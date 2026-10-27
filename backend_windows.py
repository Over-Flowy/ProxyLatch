"""
Windows backend: WinDivert captures the selected apps' packets.

* WinDivert (kernel packet filter driver) intercepts outbound TCP packets.
* When a SYN is seen, the owning process is looked up (GetExtendedTcpTable).
  If its executable is in the list, the flow is NAT-ed ("reflected") to the
  local relay: the packet is rewritten to look like it arrives from the
  remote server and is re-injected inbound to the relay port.
* Replies from the relay are rewritten back so the app believes it is talking
  directly to the original server.

Requires Administrator rights (WinDivert driver).
"""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.wintypes as wt
import ipaddress
import os
import socket
import struct
import subprocess
import sys
import threading
import time

from core import APP_NAME, AppMatcher, Config, RelayBase, Target, dns_fit_udp, udp_reply_packet

FIREWALL_RULE = f"{APP_NAME} relay"
KILL_SWITCH_RULE = f"{APP_NAME} kill switch"

# --------------------------------------------------------------------------- #
# WinDivert ctypes binding (WinDivert 2.x)
# --------------------------------------------------------------------------- #

class WINDIVERT_ADDRESS(ctypes.Structure):
    _fields_ = [
        ("Timestamp", ctypes.c_int64),
        ("Flags", ctypes.c_uint32),     # Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 ...
        ("Reserved2", ctypes.c_uint32),
        ("Data", ctypes.c_uint8 * 64),
    ]


ADDR_OUTBOUND_BIT = 1 << 17
WINDIVERT_LAYER_NETWORK = 0
WINDIVERT_PARAM_QUEUE_LENGTH = 0
WINDIVERT_PARAM_QUEUE_TIME = 1
WINDIVERT_SHUTDOWN_BOTH = 3
INVALID_HANDLE = ctypes.c_void_p(-1).value


def _app_dirs() -> list[str]:
    dirs = []
    if getattr(sys, "frozen", False):
        dirs.append(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)))
        dirs.append(os.path.dirname(sys.executable))
    else:
        dirs.append(os.path.dirname(os.path.abspath(__file__)))
    return dirs


def find_windivert_dll() -> str:
    candidates = []
    for d in _app_dirs():
        candidates += [os.path.join(d, "windivert"), d]
    try:  # fall back to the binaries shipped with the pydivert package
        import importlib.util
        spec = importlib.util.find_spec("pydivert")
        if spec and spec.origin:
            candidates.append(os.path.join(os.path.dirname(spec.origin), "windivert_dll"))
    except Exception:
        pass
    for d in candidates:
        for name in ("WinDivert.dll", "WinDivert64.dll"):
            p = os.path.join(d, name)
            if os.path.isfile(p) and os.path.isfile(os.path.join(d, "WinDivert64.sys")):
                return p
    raise FileNotFoundError(
        "WinDivert.dll / WinDivert64.sys not found. Put them in a 'windivert' folder next to "
        "the program, or run 'pip install pydivert'."
    )


class WinDivert:
    _dll = None

    @classmethod
    def dll(cls):
        if cls._dll is None:
            d = ctypes.WinDLL(find_windivert_dll(), use_last_error=True)
            d.WinDivertOpen.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int16, ctypes.c_uint64]
            d.WinDivertOpen.restype = ctypes.c_void_p
            d.WinDivertRecv.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
                                        ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(WINDIVERT_ADDRESS)]
            d.WinDivertRecv.restype = wt.BOOL
            d.WinDivertSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
                                        ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(WINDIVERT_ADDRESS)]
            d.WinDivertSend.restype = wt.BOOL
            d.WinDivertShutdown.argtypes = [ctypes.c_void_p, ctypes.c_int]
            d.WinDivertShutdown.restype = wt.BOOL
            d.WinDivertClose.argtypes = [ctypes.c_void_p]
            d.WinDivertClose.restype = wt.BOOL
            d.WinDivertSetParam.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint64]
            d.WinDivertSetParam.restype = wt.BOOL
            d.WinDivertHelperCalcChecksums.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                                       ctypes.POINTER(WINDIVERT_ADDRESS), ctypes.c_uint64]
            d.WinDivertHelperCalcChecksums.restype = wt.BOOL
            d.WinDivertHelperCompileFilter.argtypes = [
                ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
                ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_uint)]
            d.WinDivertHelperCompileFilter.restype = wt.BOOL
            cls._dll = d
        return cls._dll

    @classmethod
    def check_filter(cls, flt: str) -> str:
        """Empty string if the filter compiles, else the error."""
        err, pos = ctypes.c_char_p(), ctypes.c_uint()
        ok = cls.dll().WinDivertHelperCompileFilter(flt.encode(), WINDIVERT_LAYER_NETWORK, None, 0,
                                                    ctypes.byref(err), ctypes.byref(pos))
        return "" if ok else f"{(err.value or b'').decode()} at {pos.value}"

    def __init__(self, flt: str, priority: int = 0):
        d = self.dll()
        h = d.WinDivertOpen(flt.encode(), WINDIVERT_LAYER_NETWORK, priority, 0)
        if h is None or h == INVALID_HANDLE:
            err = ctypes.get_last_error()
            hint = " (run as Administrator)" if err == 5 else ""
            raise OSError(err, f"WinDivertOpen failed: {ctypes.FormatError(err)}{hint}")
        self.h = h
        d.WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_LENGTH, 16384)
        d.WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_TIME, 2000)
        self.buf = bytearray(0xFFFF)
        self.cbuf = (ctypes.c_char * len(self.buf)).from_buffer(self.buf)
        self.addr = WINDIVERT_ADDRESS()
        self.rlen = ctypes.c_uint()

    def recv(self) -> int:
        """Receive one packet into self.buf / self.addr; returns its length (0 on shutdown)."""
        if not self._dll.WinDivertRecv(self.h, self.cbuf, len(self.buf), ctypes.byref(self.rlen),
                                       ctypes.byref(self.addr)):
            return 0
        return self.rlen.value

    def send(self, length: int, recalc: bool = False) -> None:
        if recalc:
            self._dll.WinDivertHelperCalcChecksums(self.cbuf, length, ctypes.byref(self.addr), 0)
        self._dll.WinDivertSend(self.h, self.cbuf, length, None, ctypes.byref(self.addr))

    def send_packet(self, packet: bytearray, addr: WINDIVERT_ADDRESS) -> None:
        """Inject a packet we built ourselves (safe to call from another thread)."""
        cbuf = (ctypes.c_char * len(packet)).from_buffer(packet)
        self._dll.WinDivertHelperCalcChecksums(cbuf, len(packet), ctypes.byref(addr), 0)
        self._dll.WinDivertSend(self.h, cbuf, len(packet), None, ctypes.byref(addr))

    def shutdown(self) -> None:
        self._dll.WinDivertShutdown(self.h, WINDIVERT_SHUTDOWN_BOTH)

    def close(self) -> None:
        self._dll.WinDivertClose(self.h)


# --------------------------------------------------------------------------- #
# Process lookup helpers (iphlpapi / kernel32)
# --------------------------------------------------------------------------- #

_iphlp = ctypes.WinDLL("iphlpapi")
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_iphlp.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL,
                                       wt.ULONG, ctypes.c_int, wt.ULONG]
_iphlp.GetExtendedUdpTable.argtypes = _iphlp.GetExtendedTcpTable.argtypes
_k32.OpenProcess.restype = wt.HANDLE
_k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_k32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
_k32.CloseHandle.argtypes = [wt.HANDLE]

AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

ERROR_INSUFFICIENT_BUFFER = 122

# row struct format, index of local port, index of remote port (TCP only), index of pid
_TCP_ROW = {AF_INET: ("<6I", 2, 4, 5), AF_INET6: ("<16sII16sIIII", 2, 5, 7)}
_UDP_ROW = {AF_INET: ("<3I", 1, None, 2), AF_INET6: ("<16sIII", 2, None, 3)}
_table_bufs = threading.local()  # per thread: (func name, family) -> buffer reused between calls


def _ntohs_dw(v: int) -> int:
    return ((v & 0xFF) << 8) | ((v >> 8) & 0xFF)


def _owner_rows(func, family: int, table_class: int, fmt: str):
    """Rows of an iphlpapi owner table, unpacked lazily from a reused buffer."""
    cache = _table_bufs.__dict__
    key = (func.__name__, family)
    buf = cache.get(key) or ctypes.create_string_buffer(64 * 1024)
    for _ in range(5):
        size = wt.DWORD(len(buf))
        rc = func(buf, ctypes.byref(size), False, family, table_class, 0)
        if rc == 0:
            break
        if rc != ERROR_INSUFFICIENT_BUFFER:
            return
        buf = ctypes.create_string_buffer(size.value + 16 * 1024)
    else:
        return
    cache[key] = buf
    n = struct.unpack_from("<I", buf, 0)[0]
    yield from struct.iter_unpack(fmt, memoryview(buf)[4:4 + n * struct.calcsize(fmt)])


def tcp_owner_pid(family: int, local_port: int, remote_port: int) -> int | None:
    fmt, lp_i, rp_i, pid_i = _TCP_ROW[family]
    for row in _owner_rows(_iphlp.GetExtendedTcpTable, family, TCP_TABLE_OWNER_PID_ALL, fmt):
        if _ntohs_dw(row[lp_i]) == local_port and _ntohs_dw(row[rp_i]) == remote_port:
            return row[pid_i]
    return None


def udp_owner_pid(family: int, local_port: int) -> int | None:
    fmt, lp_i, _, pid_i = _UDP_ROW[family]
    for row in _owner_rows(_iphlp.GetExtendedUdpTable, family, UDP_TABLE_OWNER_PID, fmt):
        if _ntohs_dw(row[lp_i]) == local_port:
            return row[pid_i]
    return None


MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_DELETE_TCB = 5, 12
_iphlp.SetTcpEntry.argtypes = [ctypes.c_char_p]


def kill_tcp_connections(want) -> int:
    """Reset the open IPv4 TCP connections of processes for which want(pid) is true."""
    killed = 0
    for state, laddr, lport, raddr, rport, pid in list(_owner_rows(
            _iphlp.GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_ALL, _TCP_ROW[AF_INET][0])):
        if state >= MIB_TCP_STATE_ESTAB and raddr and want(pid):
            row = struct.pack("<5I", MIB_TCP_STATE_DELETE_TCB, laddr, lport, raddr, rport)
            if _iphlp.SetTcpEntry(row) == 0:
                killed += 1
    return killed


class _PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("ExitStatus", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_void_p), ("BasePriority", ctypes.c_void_p),
                ("UniqueProcessId", ctypes.c_void_p), ("InheritedFromUniqueProcessId", ctypes.c_void_p)]


_ntdll = ctypes.WinDLL("ntdll")
_ntdll.NtQueryInformationProcess.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.ULONG,
                                             ctypes.POINTER(wt.ULONG)]
_k32.GetProcessTimes.argtypes = [wt.HANDLE] + [ctypes.POINTER(wt.FILETIME)] * 4


def process_info(pid: int) -> tuple[str, int, int]:
    """(exe path, parent pid, creation time) of a process; ("", 0, 0) if it can't be opened."""
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return "", 0, 0
    try:
        buf = ctypes.create_unicode_buffer(32768)
        n = wt.DWORD(len(buf))
        path = buf.value if _k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else ""
        pbi = _PROCESS_BASIC_INFORMATION()
        ok = _ntdll.NtQueryInformationProcess(h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None) == 0
        parent = (pbi.InheritedFromUniqueProcessId or 0) if ok else 0
        t = [wt.FILETIME() for _ in range(4)]
        created = 0
        if _k32.GetProcessTimes(h, *[ctypes.byref(x) for x in t]):
            created = (t[0].dwHighDateTime << 32) | t[0].dwLowDateTime
        return path, parent, created
    finally:
        _k32.CloseHandle(h)



# --------------------------------------------------------------------------- #
# Redirect engine
# --------------------------------------------------------------------------- #

class NatEntry:
    __slots__ = ("dst_port", "exe", "dns", "created", "active", "closed_at")

    def __init__(self, dst_port: int, exe: str, dns: bool = False):
        self.dst_port = dst_port
        self.exe = exe
        self.dns = dns  # a DNS-over-TCP connection: answer it via DoH
        self.created = time.monotonic()
        self.active = False
        self.closed_at = 0.0


class Engine(RelayBase):
    relay_host = "0.0.0.0"  # reflected packets arrive with the remote server's address

    def __init__(self, cfg: Config, log):
        super().__init__(cfg, log)
        self.running = False
        self.matches = AppMatcher(self.apps)
        # key: (remote ip bytes, client local port) -> NatEntry
        self.nat: dict[tuple[bytes, int], NatEntry] = {}
        # pid -> (matched exe or None, process creation time, lookup time)
        self.pid_cache: dict[int, tuple[str | None, int, float]] = {}
        self.udp_cache: dict[int, tuple[bool, float]] = {}
        self.divert: WinDivert | None = None

    # ---- matching -------------------------------------------------------- #

    def target_path(self, pid: int | None, depth: int = 0) -> str | None:
        """Return the exe path if pid is one of the selected apps or was started by one
        (e.g. an IDE's language server or terminal), like the cgroup does on Linux."""
        if not pid or pid == os.getpid():
            return None
        now = time.monotonic()
        cached = self.pid_cache.get(pid)
        if cached and now - cached[2] < 10:
            return cached[0]
        path, parent, created = process_info(pid)
        hit = path if self.matches(path) else None
        if hit is None and parent and depth < 8 and self.target_path(parent, depth + 1):
            p_created = self.pid_cache[parent][1]
            if p_created and created and p_created <= created:  # not a reused parent pid
                hit = path or "?"
        self.pid_cache[pid] = (hit, created, now)
        return hit

    def udp_targeted(self, family: int, port: int) -> bool:
        now = time.monotonic()
        c = self.udp_cache.get(port)
        if c and now - c[1] < 5:
            return c[0]
        hit = self.target_path(udp_owner_pid(family, port)) is not None
        self.udp_cache[port] = (hit, now)
        return hit

    # ---- lifecycle ------------------------------------------------------- #

    def build_filter(self, proxy_ips: list[str]) -> str:
        parts = ["(ip and tcp)"]
        if self.block_udp and self.dns:
            parts.append("udp")
        elif self.block_udp:
            parts.append("(udp and udp.DstPort != 53)")
        elif self.dns:
            parts.append("(udp and udp.DstPort == 53)")
        if self.block_ipv6:
            parts.append("(ipv6 and tcp.Syn and !tcp.Ack)")
        flt = f"outbound and !loopback and ({' or '.join(parts)})"
        # keep the relay's own traffic to the proxy server out of the queue
        for ip in proxy_ips:
            addr = ipaddress.ip_address(ip)
            if addr.version == 4 and not addr.is_loopback:
                # WinDivert can't negate a group, so: !(ip and tcp and addr==X and port==P)
                flt += f" and (!ip or !tcp or ip.DstAddr != {ip} or tcp.DstPort != {self.proxy.port})"
        return flt

    def _start_capture(self) -> None:
        # Resolve the proxy host now: once DNS is captured, our own lookups would need the proxy.
        try:
            infos = socket.getaddrinfo(self.proxy.host, self.proxy.port, 0, socket.SOCK_STREAM)
        except OSError as e:
            raise RuntimeError(f"Cannot resolve proxy host {self.proxy.host}: {e}") from None
        proxy_ips = sorted({i[4][0] for i in infos}, key=lambda a: ":" in a)  # IPv4 first
        self.proxy.host = proxy_ips[0]
        flt = self.build_filter(proxy_ips)
        err = WinDivert.check_filter(flt)
        if err:
            raise RuntimeError(f"Bad filter: {err}\n{flt}")
        add_firewall_rule(self.relay_port)
        kill_switch_unblock()  # the apps must be able to connect so we can redirect them
        if self.dns:
            flush_dns_cache()  # so apps can't use answers cached before we started
        self.start_relay()
        self.divert = WinDivert(flt)
        self.running = True
        t = threading.Thread(target=self._divert_thread, daemon=True)
        t.start()
        self.threads.append(t)
        if self.kill_switch:
            # connections opened before Start would bypass the proxy: reset them so the apps reconnect
            n = kill_tcp_connections(lambda pid: self.target_path(pid) is not None)
            if n:
                self.log(f"Reset {n} connection(s) opened before Start")

    def _stop_capture(self, restarting: bool) -> None:
        self.running = False
        if self.divert:
            self.divert.shutdown()
        self.stop_relay()
        if self.divert:
            self.divert.close()
            self.divert = None
        self.nat.clear()
        if not restarting:
            arm_kill_switch(self.cfg, self.log)

    # ---- packet loop ----------------------------------------------------- #

    def _divert_thread(self) -> None:
        wd = self.divert
        buf = wd.buf
        addr = wd.addr
        nat = self.nat
        relay = self.relay_port
        relay_hi, relay_lo = relay >> 8, relay & 0xFF
        while self.running:
            n = wd.recv()
            if n == 0:
                continue  # shutdown (the loop condition ends it) or a failed receive
            try:
                ver = buf[0] >> 4
                if ver == 4:
                    ihl = (buf[0] & 0x0F) * 4
                    proto = buf[9]
                    sport = (buf[ihl] << 8) | buf[ihl + 1]  # same place in TCP and UDP
                    dport = (buf[ihl + 2] << 8) | buf[ihl + 3]
                    if proto == 6:
                        if sport == relay:
                            # relay -> app: src=(L,relay) dst=(R,cport) => src=(R,orig) dst=(L,cport)
                            ent = nat.get((bytes(buf[16:20]), dport))
                            if ent is None:
                                continue  # stray, drop
                            src = bytes(buf[12:16])
                            buf[12:16] = buf[16:20]
                            buf[16:20] = src
                            buf[ihl] = ent.dst_port >> 8
                            buf[ihl + 1] = ent.dst_port & 0xFF
                            addr.Flags &= ~ADDR_OUTBOUND_BIT
                            wd.send(n, recalc=True)
                            continue
                        key = (bytes(buf[16:20]), sport)
                        flags = buf[ihl + 13]
                        if flags & 0x12 == 0x02:  # SYN without ACK: new connection
                            ent = None
                            if self.dns and dport == 53:  # DNS over TCP (any process)
                                ent = NatEntry(dport, "DNS", dns=True)
                            else:
                                path = self.target_path(tcp_owner_pid(AF_INET, sport, dport))
                                if path:
                                    ent = NatEntry(dport, path)
                            if ent:
                                nat[key] = ent
                            else:
                                nat.pop(key, None)
                        else:
                            ent = nat.get(key)
                        if ent is not None and ent.dst_port == dport:
                            # app -> server: src=(L,cport) dst=(R,dport) => src=(R,cport) dst=(L,relay)
                            dst = bytes(buf[16:20])
                            buf[16:20] = buf[12:16]
                            buf[12:16] = dst
                            buf[ihl + 2] = relay_hi
                            buf[ihl + 3] = relay_lo
                            addr.Flags &= ~ADDR_OUTBOUND_BIT
                            wd.send(n, recalc=True)
                            continue
                    elif proto == 17:
                        if self.dns and dport == 53:
                            self._queue_dns(bytes(buf[:n]), ihl + 8)
                            continue  # answered via the proxy instead
                        if self.block_udp and self.udp_targeted(AF_INET, sport):
                            continue  # drop (e.g. QUIC) so the app falls back to TCP
                elif ver == 6:
                    nh = buf[6]
                    sport = (buf[40] << 8) | buf[41]
                    dport = (buf[42] << 8) | buf[43]
                    if nh == 6:
                        if self.target_path(tcp_owner_pid(AF_INET6, sport, dport)):
                            continue  # drop IPv6 SYN -> app falls back to IPv4 (proxied)
                    elif nh == 17:
                        if self.dns and dport == 53:
                            self._queue_dns(bytes(buf[:n]), 48)
                            continue
                        if self.block_udp and self.udp_targeted(AF_INET6, sport):
                            continue
                wd.send(n)
            except Exception as e:  # never let one bad packet kill the loop
                self.log(f"[packet error] {e!r}")
                if self.kill_switch:
                    continue  # drop: never let a packet we couldn't check go out directly
                try:
                    wd.send(n)
                except Exception:
                    pass

    # ---- relay hooks ----------------------------------------------------- #

    def destination(self, writer) -> Target | None:
        ip, port = writer.get_extra_info("peername")[:2]
        try:
            ent = self.nat.get((socket.inet_aton(ip), port))
        except OSError:
            return None
        if ent is None:
            return None
        return Target(ip, ent.dst_port, ent.exe, ent.dns, ent)

    def opened(self, t: Target) -> None:
        t.entry.active = True

    def closed(self, t: Target) -> None:
        t.entry.active = False
        t.entry.closed_at = time.monotonic()

    def cleanup(self) -> None:
        now = time.monotonic()
        for k, e in list(self.nat.items()):
            if (e.closed_at and now - e.closed_at > 60) or (not e.active and not e.closed_at
                                                            and now - e.created > 120):
                if self.nat.get(k) is e:
                    del self.nat[k]
        if len(self.pid_cache) > 4096:
            self.pid_cache.clear()
        if len(self.udp_cache) > 4096:
            self.udp_cache.clear()

    # ---- DNS ------------------------------------------------------------- #

    def _queue_dns(self, pkt: bytes, offset: int) -> None:
        """Called from the packet thread for each captured DNS query."""
        addr = WINDIVERT_ADDRESS.from_buffer_copy(self.divert.addr)
        asyncio.run_coroutine_threadsafe(self._answer_dns(pkt, offset, addr), self.loop)

    async def _answer_dns(self, pkt: bytes, offset: int, addr: WINDIVERT_ADDRESS) -> None:
        query = pkt[offset:]
        if len(query) < 12 or not self.doh:
            return
        resp = await self._resolve(query)
        if resp is None or not self.divert:
            return
        resp = dns_fit_udp(query, resp)
        addr.Flags &= ~ADDR_OUTBOUND_BIT
        self.divert.send_packet(udp_reply_packet(pkt, resp), addr)


# --------------------------------------------------------------------------- #
# Windows helpers
# --------------------------------------------------------------------------- #

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, subprocess.list2cmdline(sys.argv[1:])
    else:
        exe = sys.executable
        pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(pyw):
            exe = pyw
        params = subprocess.list2cmdline([os.path.abspath(sys.argv[0])] + sys.argv[1:])
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    return rc > 32


def _run(*cmd: str) -> None:
    """Run a console tool without flashing a window."""
    subprocess.run(cmd, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)


def _netsh_rule(action: str, name: str, *opts: str) -> list[str]:
    return ["netsh", "advfirewall", "firewall", action, "rule", f"name={name}", *opts]


def add_firewall_rule(port: int) -> None:
    """Injected connections to the relay look like they come from the internet,
    so Windows Firewall must allow inbound TCP to our program."""
    _run(*_netsh_rule("delete", FIREWALL_RULE))
    _run(*_netsh_rule("add", FIREWALL_RULE, "dir=in", "action=allow", "protocol=TCP",
                      f"localport={port}", f"program={sys.executable}", "enable=yes"))


def kill_switch_block(apps: list[str]) -> list[str]:
    """Block the apps in Windows Firewall while ProxyLatch is not redirecting them.
    Returns the entries that can't be blocked (bare exe names have no path)."""
    kill_switch_unblock()
    paths = [a for a in apps if os.path.isabs(a)]
    procs = [subprocess.Popen(_netsh_rule("add", KILL_SWITCH_RULE, "dir=out", "action=block",
                                          f"program={a}", "enable=yes"),
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              creationflags=subprocess.CREATE_NO_WINDOW) for a in paths]
    for p in procs:  # started together, so N rules take about as long as one
        p.wait()
    return [a for a in apps if not os.path.isabs(a)]


def kill_switch_unblock() -> None:
    _run(*_netsh_rule("delete", KILL_SWITCH_RULE))


def flush_dns_cache() -> None:
    _run("ipconfig", "/flushdns")


def style_window(win) -> None:
    """Dark title bar to match the theme."""
    try:
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        on = ctypes.c_int(1)
        for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (new / old builds)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(on),
                                                          ctypes.sizeof(on)) == 0:
                break
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Interface used by the GUI
# --------------------------------------------------------------------------- #

DNS_SCOPE = "all DNS on this PC"
APP_DIALOG = {"filetypes": [("Programs", "*.exe"), ("All files", "*.*")]}


def on_startup(cfg: Config, log) -> None:
    if not is_admin():
        log("[error] Not running as Administrator — capturing will fail.")
    arm_kill_switch(cfg, log)  # re-arm, e.g. after a crash while running


def arm_kill_switch(cfg: Config, log) -> None:
    """While stopped, keep the apps blocked by Windows Firewall (if the kill switch is on)."""
    if not cfg.kill_switch or not cfg.apps:
        kill_switch_unblock()
        return
    skipped = kill_switch_block(cfg.apps)
    blocked = len(cfg.apps) - len(skipped)
    if blocked:
        log(f"Kill switch: {blocked} app(s) blocked from the internet until you click Start")
    for app in skipped:
        log(f'[warn] Kill switch can\'t block "{app}" while stopped — add it by full path')


def shutdown() -> None:
    pass


def prepare_main() -> bool:
    """Elevate if needed. Returns False when this process should exit."""
    if not is_admin() and "--no-elevate" not in sys.argv:
        if relaunch_as_admin():
            return False
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    return True
