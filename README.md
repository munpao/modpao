# modpao

**Generic Modbus / OT pentest console** — a SET / Metasploit-style interactive CLI for assessing Modbus TCP devices (PLCs, RTUs, ICS/SCADA gear).

Read, scan, monitor and write coils & registers; brute or replay device authentication; build raw RTU frames offline; and keep everything organised across multiple targets with resumable sessions.

```
   __  __  ___  ___  ___  ___   ___
  |  \/  |/ _ \|   \| _ \/ _ \ / _ \    m o d p a o
  | |\/| | (_) | |) |  _/ (_) | (_) |   modbus pentest console
  |_|  |_|\___/|___/|_|  \___/ \___/    multi-session . resume . tab
```

---

## Disclaimer — read this first

**modpao is for AUTHORIZED security testing and research ONLY.**

Modbus has no built-in authentication or encryption. Writing to a live PLC can move physical equipment, change process setpoints, disable safety interlocks, or damage machinery and endanger people. Scanning or flooding an ICS network can disrupt operations.

- Use it **only** on systems you own or have **explicit, written permission** to test.
- Never point it at production OT/ICS you are not authorised to touch.
- The authors accept **no liability** for misuse or for any damage, downtime, injury, or loss resulting from the use of this tool.
- Using this software against systems without authorisation may be **illegal** in your jurisdiction.

By using modpao you agree that you are solely responsible for your actions. See [`DISCLAIMER.md`](DISCLAIMER.md).

---

## Features

- **Interactive console** with modes you enter by number (`1` = enum, `4` = write, ...), per-mode `help`, and `b` to go back.
- **Read / scan** coils, discrete inputs, holding & input registers — block reads, threads, decode (`f32`, `ascii`, `hex`, `int`, `time`), zero-filter.
- **Flood read** — hammer the same address(es) at max speed and report throughput (reads/s), error %, latency (min/avg/max), and the value range seen (throughput / stress / liveness test; the read-side twin of `persist --flood`).
- **recon** — one-shot device recon and a **full sweep** of all types (0-65535) with auto-chunking, **early-stop**, and optional threading.
- **Write** coils / registers via FC05/06 (single), FC15/16 (multi/block), or **FC23** (read+write, bypasses firewalls that blacklist FC6/16).
- **Authentication** for password-locked PLCs, three schemes:
  - contiguous password packed at one register,
  - sequential/range (write the password across an address range),
  - **scattered** `reg:value` pairs (randomized-address auth).
- **`unlock`** — hold one connection and authenticate **once**, so repeated reads/writes don't re-trigger lockouts (matches how manual exploit scripts work).
- **Monitor** live values as a table (columns or transposed rows) and **watch** for deltas / threshold alerts.
- **RTU frame builder** — generate raw Modbus-RTU hex frames (with/without CRC) to pipe over `nc` or a serial gateway.
- **Discover** Modbus hosts across an IP range/CIDR (built-in TCP probe or `nmap` + `modbus-discover`).
- **Multi-session** with autosave/resume, per-session **findings log** and **audit trail**, custom register **tags**, tab-completion & history.

---

## Requirements

- Python 3.8+
- [`pymodbus`](https://pypi.org/project/pymodbus/) >= 3.8

```bash
pip install -r requirements.txt
# or
pip install "pymodbus>=3.8"
```

Tab-completion uses the standard `readline` (built-in on Linux/macOS). On Windows: `pip install pyreadline3`.

---

## Quick start

```bash
python3 modpao.py                 # resumes your last session
python3 modpao.py --ip 172.19.5.3 # start pointed at a target
python3 modpao.py --new lab1 --ip 172.19.5.3
```

Inside the console:

```
help          # main menu
guide         # step-by-step walkthrough
misc          # every flag + how authentication works
S             # show current target/settings
8             # list & switch saved targets (use N)
exit          # save + quit (resumes next time)
```

Type a number to **enter a mode**, then run commands without the number. Type `b` to go back.

---

## Usage

### Read / scan (mode `1` enum)

```
1
read h 1027                 # one holding register
read c 1-16 -F              # 16 coils, hide the False ones
read h 2048-2053 -d f32     # decode register pairs as 32-bit floats
read h 1-200 --multi        # block read (one request for the range)
scan h 0-4096               # sweep, show non-zero only
scan -u 0-32                # find responding unit/slave IDs
flood h 1027                # hammer reads at max speed for 10s (live rate/err)
flood h 1027 30             # ...for 30s
flood h 1024-1030 -t 8      # 8 threads, read the whole range each loop
flood c 1 -D 0              # run until Ctrl-C
flood h 1027 --count 5000   # stop after 5000 reads
b
```

Chain commands with `|`:  `read c 1-8 | scan h 1-50`

**flood read** hammers the *same* address(es) over and over as fast as it can and prints a live `reads / err / rate / latency` line, then a summary with **reads/s, error %, latency min/avg/max (ms)**, and the **value range** seen during the run (so you can tell if the value was moving or pinned). Handy as a throughput benchmark, a liveness probe, or a read-side stress test. Unlike **monitor** (paced table poll) and **watch** (change/threshold alert), it does no pacing. Duration is `10s` by default; give seconds as a word (`flood h 1027 30`), via `-D sec`, or `-D 0` / `--count N` to control how long it runs. Add `-d f32` to decode register pairs (e.g. `flood h 40050 -d f32`).

### Recon (mode `7` auto)

```
7
recon                # quick device info + hreg 0-63
recon full           # sweep ALL types 0-65535 (chunked + early-stop)
recon full 0-5000    # bounded range
recon full -t 6      # parallel (faster); --deep disables early-stop
writable h 1024-2100 # probe which registers actually accept writes (restores)
writable c 1-20      # same for coils (spots PLC-driven outputs)
slave                # enumerate unit IDs 0-32
b
```

### Write (mode `4`)

```
4
h 1027 100              # single (FC06)
h 1024-1030 0 --multi   # block write (FC16)
h 1027 100 --fc23       # via FC23 (firewall bypass)
c 5 1                   # coil (FC05)
h 1027 100 -a -v        # authenticate first, verbose before/after
b
```

Writes ask `y/N` first (skip with `-y`).

### Authentication

Pick the scheme that matches your target:

```
# 1) contiguous password packed at one register
auth setpw 3890 OmniPLC123#4

# 2) sequential / unknown address — write to every reg in a range
auth setpw 3890-4096 OmniPLC123#4

# 3) scattered reg:value pairs (randomized-address auth)
auth setmap 3964:56,3919:90,3916:65,3893:110,4090:51,...

auth fc fc23        # choose the write FC used to replay (fc06|fc16|fc23)
auth test 1027      # verify: does a write to 1027 stick after unlock?
auth                # show current auth config
```

**For repeated reads/writes on a locked PLC, use `unlock`** — it opens one connection, authenticates **once**, and holds it (so you don't re-auth every command and trip a lockout):

```
auth setmap 3964:56,3919:90,...
unlock
1
read h 1034,1035,1046,1047,1059,1068,1075,1076
b
lock
```

Add `-a` to a single write/read to authenticate for just that command.

### Monitor / watch (modes `2` / `3`)

```
2
h 16,1027,2048 2       # live table, new row every 2s
h 1024-1035 1 -T       # transposed (rows = addresses, refreshes)
b

3
h 1027 2 thr 1027 > 90 # alert when reg 1027 exceeds 90
b
```

### RTU frame builder (mode `6`)

Build raw Modbus-RTU frames offline (no connection needed) to send over `nc` or a serial gateway:

```
6
build read h 33               # FC03 read frame (+CRC)
build write c 5 1 -s 82       # FC05 coil write, slave 82
build write h 33 100 --no-crc # gateway that appends CRC itself
b
```

Send with:  `echo <HEX> | xxd -r -p | nc <host> <port>`

### Discover (mode `9`)

```
9
172.19.5.0/24            # scan a subnet for Modbus on tcp/502
172.19.5.1-254 --add     # save every hit as a session
172.19.5.0/24 --nmap     # deep scan via nmap + modbus-discover
b
```

### Tags (mode `00`)

Give registers/coils your own names (shown in every scan):

```
00
add h 1027 sp_heater
add c 5 master
list
b
```

---

## Global flags

| flag | meaning |
|------|---------|
| `-a` | authenticate first (replay `auth_map`) |
| `-d MODE` | decode registers: `f32` `ascii` `hex` `int` `time` |
| `-u N` | unit / slave id |
| `-F` | hide values that are `0` / `False` |
| `--multi` | block read/write (one request for a range) |
| `--fc23` | write via FC23 (bypass FC6/16 firewall) |
| `-t N` | use N parallel connections (big scans/writes) |
| `-T` | monitor: rows = addresses |
| `-v` | verbose (show real errors + before/after) |
| `-y` | skip the write confirmation |

Address format: `5` / `1-20` / `1-20,100,150-160,200`

---

## Sessions & files

- `modpao_sessions.json` — all saved targets (autosaved; resumes on start).
- `modpao_<name>.audit.log` — timestamped command log per session.
- `.modpao_history` — command history for the shell.

Each session keeps its own IP/port/unit, `auth_map`, findings, and tags.

---

## License

MIT — see [`LICENSE`](LICENSE). Provided **as-is, without warranty**. Authorized testing only.
