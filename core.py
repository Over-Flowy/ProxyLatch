"""
Platform-independent parts of ProxyLatch: config, proxy handshakes, DNS over
the proxy (DoH) and the relay that every captured connection is handed to.

The OS backends (backend_windows / backend_linux) only decide *how* app
traffic reaches the relay and tell it where each connection was going.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
from dataclasses import asdict, dataclass, field

APP_NAME = "ProxyLatch"
IS_WINDOWS = sys.platform == "win32"
if IS_WINDOWS:
    CONFIG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), APP_NAME)
else:
    CONFIG_DIR = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
                              APP_NAME)
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

PROXY_TYPES = ("SOCKS5", "HTTP")
DOH_SERVERS = {  # DNS-over-HTTPS servers used when "Resolve DNS through proxy" is on
    "Cloudflare": "cloudflare-dns.com",
    "Google": "dns.google",
    "Quad9": "dns.quad9.net",
}


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

@dataclass
class Proxy:
    proxy_type: str = "SOCKS5"
    host: str = "127.0.0.1"
    port: int = 1080
    username: str = ""
    password: str = ""

    def label(self) -> str:
        return f"{self.proxy_type.lower()}://{self.host}:{self.port}"


class AppMatcher:
    """Matches program paths against the app list. An entry is a full path, or just a
    file name ("chrome.exe", "firefox") to match it in any folder. normcase makes the
    comparison case-insensitive on Windows only. Patterns are normalised once."""

    def __init__(self, patterns: list[str]):
        self.paths: set[str] = set()
        self.names: set[str] = set()
        for p in patterns:
            p = p.strip()
            if "\\" in p or "/" in p:
                self.paths.add(self._norm(p))
            elif p:
                self.names.add(os.path.normcase(p))

    @staticmethod
    def _norm(path: str) -> str:
        return os.path.normcase(os.path.normpath(path))

    def __call__(self, exe_path: str) -> bool:
        if not exe_path:
            return False
        exe = self._norm(exe_path)
        return exe in self.paths or os.path.basename(exe) in self.names


@dataclass
class Config:
    proxy: Proxy = field(default_factory=Proxy)
    apps: list[str] = field(default_factory=list)
    relay_port: int = 34010
    block_udp: bool = True
    block_ipv6: bool = True
    dns_over_proxy: bool = False
    dns_server: str = "Cloudflare"
    kill_switch: bool = True

    @staticmethod
    def load() -> "Config":
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return Config()
        cfg = Config()
        try:
            cfg.proxy = Proxy(**data.get("proxy", {}))
            cfg.apps = list(data.get("apps", []))
            if cfg.proxy.proxy_type not in PROXY_TYPES:  # a hand-edited / invalid file
                cfg.proxy.proxy_type = "SOCKS5"
            cfg.relay_port = int(data.get("relay_port", cfg.relay_port))
            for key in ("block_udp", "block_ipv6", "dns_over_proxy", "kill_switch"):
                setattr(cfg, key, bool(data.get(key, getattr(cfg, key))))
            if data.get("dns_server") in DOH_SERVERS:
                cfg.dns_server = data["dns_server"]
        except Exception:
            pass
        return cfg

    def save(self) -> None:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        # the file holds the proxy password: readable by this user only (on Linux)
        fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)
        if not IS_WINDOWS:
            os.chmod(CONFIG_FILE, 0o600)  # also for files saved by older versions


# --------------------------------------------------------------------------- #
# Proxy client handshakes
# --------------------------------------------------------------------------- #

class ProxyError(Exception):
    pass


async def open_via_proxy(proxy: Proxy, dst_host: str, dst_port: int, timeout: float = 15.0):
    """Open a TCP stream to dst through the proxy. Returns (reader, writer)."""
    async def _do():
        reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
        try:
            sock = writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if proxy.proxy_type == "SOCKS5":
                await _socks5(reader, writer, proxy, dst_host, dst_port)
            else:
                await _http_connect(reader, writer, proxy, dst_host, dst_port)
        except BaseException:
            writer.close()
            raise
        return reader, writer
    return await asyncio.wait_for(_do(), timeout)


async def _socks5(reader, writer, proxy: Proxy, host: str, port: int):
    methods = b"\x00\x02" if proxy.username else b"\x00"
    writer.write(b"\x05" + bytes([len(methods)]) + methods)
    ver, method = await reader.readexactly(2)
    if ver != 5:
        raise ProxyError("not a SOCKS5 proxy")
    if method == 0x02:
        u, p = proxy.username.encode(), proxy.password.encode()
        writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        _, status = await reader.readexactly(2)
        if status != 0:
            raise ProxyError("SOCKS5 authentication failed")
    elif method != 0x00:
        raise ProxyError("SOCKS5 proxy requires an unsupported auth method" if method != 0xFF
                         else "SOCKS5 proxy rejected auth methods (credentials needed?)")
    try:
        ip = ipaddress.ip_address(host)
        atyp = b"\x01" if ip.version == 4 else b"\x04"
        addr = atyp + ip.packed
    except ValueError:
        h = host.encode("idna")
        addr = b"\x03" + bytes([len(h)]) + h
    writer.write(b"\x05\x01\x00" + addr + struct.pack(">H", port))
    ver, rep, _, atyp = await reader.readexactly(4)
    if rep != 0:
        reasons = {1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable",
                   4: "host unreachable", 5: "connection refused", 6: "TTL expired",
                   7: "command not supported", 8: "address type not supported"}
        raise ProxyError(f"SOCKS5 connect failed: {reasons.get(rep, rep)}")
    if atyp == 1:
        await reader.readexactly(4 + 2)
    elif atyp == 4:
        await reader.readexactly(16 + 2)
    else:
        n = (await reader.readexactly(1))[0]
        await reader.readexactly(n + 2)


async def _http_connect(reader, writer, proxy: Proxy, host: str, port: int):
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
    if proxy.username:
        tok = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
        req += f"Proxy-Authorization: Basic {tok}\r\n"
    writer.write((req + "\r\n").encode())
    head = await reader.readuntil(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = status.split()
    if len(parts) < 2 or parts[1] != "200":
        raise ProxyError(f"HTTP proxy: {status}")


# --------------------------------------------------------------------------- #
# DNS over the proxy (DNS-over-HTTPS, RFC 8484)
# --------------------------------------------------------------------------- #

class DohClient:
    """Sends raw DNS queries to a DoH server through the proxy, reusing
    keep-alive TLS connections. The DoH host name is resolved by the proxy."""

    def __init__(self, proxy: Proxy, host: str, max_idle: int = 4):
        self.proxy = proxy
        self.host = host
        self.max_idle = max_idle
        self.idle: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        self.ctx = ssl.create_default_context()

    async def _open(self):
        reader, writer = await open_via_proxy(self.proxy, self.host, 443, timeout=10)
        await writer.start_tls(self.ctx, server_hostname=self.host)
        return reader, writer

    async def _exchange(self, conn, q: bytes) -> tuple[bytes, bool]:
        reader, writer = conn
        writer.write(f"POST /dns-query HTTP/1.1\r\nHost: {self.host}\r\n"
                     f"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n"
                     f"Content-Length: {len(q)}\r\n\r\n".encode() + q)
        await writer.drain()
        head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
        lines = head.split("\r\n")
        status = lines[0].split()
        headers = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:] if ln)}
        if headers.get("transfer-encoding", "").lower() == "chunked":
            body = b""
            while True:
                size = int((await reader.readline()).split(b";")[0], 16)
                chunk = await reader.readexactly(size + 2)
                if size == 0:
                    break
                body += chunk[:-2]
        else:
            body = await reader.readexactly(int(headers.get("content-length", "0")))
        if len(status) < 2 or status[1] != "200":
            raise ProxyError(f"DoH server answered {' '.join(status[1:])}")
        return body, headers.get("connection", "").lower() != "close"

    async def query(self, q: bytes) -> bytes:
        for attempt in range(2):
            conn = self.idle.pop() if self.idle else await self._open()
            try:
                resp, keep = await asyncio.wait_for(self._exchange(conn, q), 8)
            except Exception:
                conn[1].close()
                if attempt:
                    raise
                continue  # a stale keep-alive connection: retry on a fresh one
            if keep and len(self.idle) < self.max_idle:
                self.idle.append(conn)
            else:
                conn[1].close()
            return resp
        raise ProxyError("DoH query failed")

    def close(self) -> None:
        for _, w in self.idle:
            w.close()
        self.idle.clear()


def dns_question_end(msg: bytes) -> int:
    i = 12
    while msg[i]:
        i += msg[i] + 1
    return i + 1 + 4


def dns_answers(msg: bytes) -> tuple[str, list[str]]:
    """Return (question name, [A/AAAA addresses]) from a DNS response."""
    qd, an = struct.unpack_from("!HH", msg, 4)
    if qd != 1:
        return "", []
    labels, i = [], 12
    while msg[i]:
        labels.append(msg[i + 1:i + 1 + msg[i]].decode("ascii", "replace"))
        i += msg[i] + 1
    i = dns_question_end(msg)
    ips = []
    for _ in range(an):
        while True:  # skip owner name
            if msg[i] == 0:
                i += 1
                break
            if msg[i] & 0xC0 == 0xC0:
                i += 2
                break
            i += msg[i] + 1
        rtype, _, _, rdlen = struct.unpack_from("!HHIH", msg, i)
        i += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(msg[i:i + 4]))
        elif rtype == 28 and rdlen == 16:
            ips.append(socket.inet_ntop(socket.AF_INET6, msg[i:i + 16]))
        i += rdlen
    return ".".join(labels).lower(), ips


def dns_build_query(name: str, qtype: int = 1) -> bytes:
    q = struct.pack("!HHHHHH", int.from_bytes(os.urandom(2), "big"), 0x0100, 1, 0, 0, 0)
    for label in name.strip(".").split("."):
        q += bytes([len(label)]) + label.encode("idna")
    return q + b"\x00" + struct.pack("!HH", qtype, 1)


def dns_truncated(query: bytes, resp: bytes) -> bytes:
    """Header + question with the TC bit set: tells the client to retry over TCP."""
    hdr = bytearray(resp[:12])
    hdr[2] |= 0x02
    hdr[6:12] = bytes(6)
    return bytes(hdr) + query[12:dns_question_end(query)]


def dns_fit_udp(query: bytes, resp: bytes) -> bytes:
    """Answers that don't fit in one UDP datagram are replaced by a truncated reply,
    so the client retries over TCP (which we also proxy)."""
    limit = 1232 if query[10] or query[11] else 512  # EDNS (additional record) or classic size
    return dns_truncated(query, resp) if len(resp) > limit else resp


def udp_reply_packet(query_pkt: bytes, payload: bytes) -> bytearray:
    """Build the IP/UDP packet answering query_pkt (addresses and ports swapped)."""
    if query_pkt[0] >> 4 == 4:
        ihl = (query_pkt[0] & 0x0F) * 4
        src, dst, ports = query_pkt[12:16], query_pkt[16:20], query_pkt[ihl:ihl + 4]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), 0, 0, 64, 17, 0, dst, src)
    else:
        src, dst, ports = query_pkt[8:24], query_pkt[24:40], query_pkt[40:44]
        ip = struct.pack("!IHBB16s16s", 0x60000000, 8 + len(payload), 17, 64, dst, src)
    udp = ports[2:4] + ports[0:2] + struct.pack("!HH", 8 + len(payload), 0)
    return bytearray(ip + udp + payload)


# --------------------------------------------------------------------------- #
# Sniffing the host name from a connection's first bytes (like v2ray's "sniffing")
# --------------------------------------------------------------------------- #

SNIFF_TIMEOUT = 0.3  # protocols where the server talks first (SSH, SMTP, ...) wait this long
_HOST_CHARS = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")


def _valid_host(name: bytes) -> str | None:
    if 0 < len(name) <= 253 and set(name) <= _HOST_CHARS and b"." in name:
        return name.decode().lower().rstrip(".")
    return None


def tls_sni(data: bytes) -> str | None:
    """Server name from a TLS ClientHello (None if data isn't one / has no SNI)."""
    try:
        if data[0] != 0x16 or data[5] != 0x01:  # handshake record, ClientHello
            return None
        i = 5 + 4 + 2 + 32  # handshake header, client version, random
        i += 1 + data[i]  # session id
        i += 2 + int.from_bytes(data[i:i + 2], "big")  # cipher suites
        i += 1 + data[i]  # compression methods
        end = min(len(data), i + 2 + int.from_bytes(data[i:i + 2], "big"))
        i += 2
        while i + 4 <= end:
            ext, size = int.from_bytes(data[i:i + 2], "big"), int.from_bytes(data[i + 2:i + 4], "big")
            i += 4
            if ext == 0:  # server_name: list length (2), type (1) = host_name, length (2), name
                if data[i + 2] == 0:
                    n = int.from_bytes(data[i + 3:i + 5], "big")
                    return _valid_host(data[i + 5:i + 5 + n])
                return None
            i += size
    except IndexError:
        pass
    return None


def http_host(data: bytes) -> str | None:
    """Host header of a plain HTTP request."""
    if not data[:8].split(b" ", 1)[0].isalpha():
        return None
    for line in data.split(b"\r\n")[1:]:
        if not line:
            break
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"host":
            v = v.strip()
            if v.startswith(b"["):
                return None  # IPv6 literal: nothing to learn
            return _valid_host(v.rsplit(b":", 1)[0] if v.count(b":") == 1 else v)
    return None


def tls_record_incomplete(data: bytes) -> bool:
    """A ClientHello split over several reads (e.g. big post-quantum key shares)."""
    return len(data) >= 5 and data[0] == 0x16 and len(data) < 5 + int.from_bytes(data[3:5], "big")


def http_headers_incomplete(data: bytes) -> bool:
    """An HTTP request whose headers (and so the Host line) haven't all arrived yet."""
    method = data[:8].split(b" ", 1)[0]
    return (method.isalpha() and method.isupper() and b" " in data[:8]
            and b"\r\n\r\n" not in data and len(data) < 16384)


def first_bytes_incomplete(data: bytes) -> bool:
    return tls_record_incomplete(data) or http_headers_incomplete(data)


async def sniff_first_bytes(reader) -> bytes:
    """What the client sends first, if it sends anything within SNIFF_TIMEOUT."""
    data = b""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + SNIFF_TIMEOUT
    while True:
        left = deadline - loop.time()
        if left <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(65536), left)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        data += chunk
        if not first_bytes_incomplete(data):
            break
    return data


async def test_proxy(proxy: Proxy, doh_host: str | None = None) -> str:
    t0 = time.perf_counter()
    reader, writer = await open_via_proxy(proxy, "1.1.1.1", 80, timeout=10)
    try:
        writer.write(b"HEAD / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n")
        await asyncio.wait_for(reader.readline(), 10)
    finally:
        writer.close()
    msg = f"Proxy works  ·  {(time.perf_counter() - t0) * 1000:.0f} ms"
    if doh_host:
        doh = DohClient(proxy, doh_host)
        try:
            _, ips = dns_answers(await doh.query(dns_build_query("example.com")))
        except Exception as e:
            raise ProxyError(f"{msg}, but DNS via proxy failed: {e or type(e).__name__}") from None
        finally:
            doh.close()
        msg += f"  ·  DNS works (example.com → {ips[0] if ips else 'no answer'})"
    return msg


async def _pipe(reader, writer) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError, asyncio.CancelledError):
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except (OSError, RuntimeError):
            writer.close()


# --------------------------------------------------------------------------- #
# Relay (shared by all backends)
# --------------------------------------------------------------------------- #

class Target:
    """Where a captured connection was originally going."""
    __slots__ = ("ip", "port", "exe", "dns", "entry")

    def __init__(self, ip: str, port: int, exe: str, dns: bool = False, entry=None):
        self.ip = ip
        self.port = port
        self.exe = exe
        self.dns = dns  # a DNS-over-TCP connection: answer it via DoH
        self.entry = entry  # backend bookkeeping


class RelayBase:
    """Accepts the captured connections and opens each one through the proxy.

    Backends subclass this and provide _start_capture()/_stop_capture() and destination().
    Stopping (also after a failed start) leaves the apps in the configured stopped state:
    blocked when the kill switch is on."""

    relay_host = "127.0.0.1"  # Linux: nftables "redirect" delivers here

    def __init__(self, cfg: Config, log):
        self.cfg = cfg
        self.proxy = Proxy(**asdict(cfg.proxy))
        self.proxy_label = cfg.proxy.label()
        self.apps = list(cfg.apps)
        self.dns = cfg.dns_over_proxy
        # the kill switch implies blocking everything that could bypass the proxy
        self.kill_switch = cfg.kill_switch
        self.block_udp = cfg.block_udp or cfg.kill_switch
        self.block_ipv6 = cfg.block_ipv6 or cfg.kill_switch
        self.proxy_up = True
        self.doh: DohClient | None = None
        self.ip_names: dict[str, str] = {}  # learned from DNS answers: ip -> host name
        self.dns_fail_logged = 0.0
        self.log = log
        self.relay_port = cfg.relay_port
        self.loop: asyncio.AbstractEventLoop | None = None
        self.threads: list[threading.Thread] = []
        self.active_conns = 0
        self.total_conns = 0

    # ---- backend hooks ---------------------------------------------------- #

    def _start_capture(self) -> None:
        """Start the relay (start_relay) and send the apps' traffic to it."""
        raise NotImplementedError

    def _stop_capture(self, restarting: bool) -> None:
        """Undo _start_capture (also a partial one). Unless restarting, leave the apps in
        the stopped state the config asks for."""
        raise NotImplementedError

    def destination(self, writer) -> Target | None:
        """Original destination of an accepted connection (None = not ours, close it)."""
        raise NotImplementedError

    async def resolve_exe(self, t: Target) -> str:
        """Program that opened the connection (for the log)."""
        return t.exe

    def opened(self, t: Target) -> None:
        pass

    def closed(self, t: Target) -> None:
        pass

    async def extra_servers(self) -> list:
        """More listeners to run in the relay loop; returned objects must have close()."""
        return []

    def cleanup(self) -> None:
        """Called every 30 s from the relay loop."""

    # ---- lifecycle --------------------------------------------------------- #

    def start(self) -> None:
        if not self.apps:
            raise RuntimeError("Add at least one application.")
        try:
            self._start_capture()
        except Exception:
            self._stop_capture(restarting=False)
            raise
        self.log(f"Started — {len(self.apps)} app(s) via {self.proxy_label}" +
                 (f", DNS via {self.cfg.dns_server}" if self.dns else "") +
                 (", kill switch on" if self.kill_switch else ""))

    def stop(self, restarting: bool = False) -> None:
        self._stop_capture(restarting)
        self.log("Stopped.")

    def start_relay(self) -> None:
        if self.dns:
            self.doh = DohClient(self.proxy, DOH_SERVERS[self.cfg.dns_server])
        started = threading.Event()
        errors: list[BaseException] = []
        t = threading.Thread(target=self._relay_thread, args=(started, errors), daemon=True)
        self.threads = [t]
        t.start()
        if not started.wait(10):
            errors.append(OSError("The relay did not start in time"))
        if errors:
            self.stop_relay()
            raise errors[0]

    def stop_relay(self) -> None:
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        for t in self.threads:
            if t is not threading.current_thread():
                t.join(3)
        if self.doh:
            self.doh.close()
            self.doh = None

    def _relay_thread(self, started: threading.Event, errors: list) -> None:
        loop = asyncio.new_event_loop()
        self.loop = loop
        asyncio.set_event_loop(loop)
        servers = []
        try:
            servers.append(loop.run_until_complete(
                asyncio.start_server(self._handle, self.relay_host, self.relay_port, backlog=512)))
            servers += loop.run_until_complete(self.extra_servers())
        except BaseException as e:
            for s in servers:
                s.close()
            errors.append(OSError(f"Cannot listen on relay port: {e}"))
            started.set()
            loop.close()
            return
        started.set()
        loop.create_task(self._janitor())
        loop.create_task(self._watch_proxy())
        try:
            loop.run_forever()
        finally:
            for s in servers:
                s.close()
            for task in asyncio.all_tasks(loop):
                task.cancel()
            loop.run_until_complete(asyncio.sleep(0))
            loop.close()

    async def _janitor(self) -> None:
        while True:
            await asyncio.sleep(30)
            self.cleanup()
            if len(self.ip_names) > 50000:
                self.ip_names.clear()

    async def _watch_proxy(self) -> None:
        """Check every few seconds that the proxy accepts connections and log changes."""
        while True:
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(self.proxy.host, self.proxy.port), 5)
                w.close()
                up = True
            except (OSError, asyncio.TimeoutError):
                up = False
            if up != self.proxy_up:
                self.proxy_up = up
                if up:
                    self.log("Proxy is reachable again")
                else:
                    self.log("[fail] Proxy is unreachable — app connections are being dropped"
                             if self.kill_switch else "[fail] Proxy is unreachable")
            await asyncio.sleep(5)

    # ---- DNS --------------------------------------------------------------- #

    async def _resolve(self, query: bytes) -> bytes | None:
        try:
            resp = await self.doh.query(query)
        except Exception as e:
            if time.monotonic() - self.dns_fail_logged > 5:  # don't flood the log
                self.dns_fail_logged = time.monotonic()
                self.log(f"[fail] DNS via proxy: {e or type(e).__name__}")
            return None
        resp = query[:2] + resp[2:]  # keep the client's query ID
        try:
            name, ips = dns_answers(resp)
            for ip in ips:
                self.ip_names[ip] = name
        except (IndexError, struct.error):
            pass
        return resp

    async def _dns_over_tcp(self, reader, writer) -> None:
        """Serves one DNS-over-TCP client (length-prefixed messages) and closes it."""
        try:
            while True:
                size = struct.unpack("!H", await reader.readexactly(2))[0]
                resp = await self._resolve(await reader.readexactly(size))
                if resp is None:
                    return
                writer.write(struct.pack("!H", len(resp)) + resp)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    # ---- connections ------------------------------------------------------- #

    async def _handle(self, c_reader, c_writer) -> None:
        try:
            t = self.destination(c_writer)
        except Exception as e:
            self.log(f"[error] {e!r}")
            t = None
        if t is None:
            c_writer.close()
            return
        self.opened(t)
        if t.dns:
            try:
                await self._dns_over_tcp(c_reader, c_writer)
            finally:
                self.closed(t)
            return
        self.active_conns += 1
        self.total_conns += 1
        try:
            # Send the proxy a host name, not an IP, whenever we can: the name the app put in
            # its first bytes (TLS SNI / HTTP Host), else the one learned from DNS. The proxy
            # then resolves it itself, so wrong local DNS answers don't matter.
            first = await sniff_first_bytes(c_reader)
            host = tls_sni(first) or http_host(first) or self.ip_names.get(t.ip, t.ip)
            dst = f"{host}:{t.port}"
            name = os.path.basename(await self.resolve_exe(t)) or "?"
            self.log(f"{name}  →  {dst}")
            sock = c_writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                s_reader, s_writer = await open_via_proxy(self.proxy, host, t.port)
            except Exception as e:
                self.log(f"[fail] {name}  →  {dst}: {e or type(e).__name__}")
                return
            if first:
                s_writer.write(first)
            try:
                await asyncio.gather(_pipe(c_reader, s_writer), _pipe(s_reader, c_writer))
            finally:
                s_writer.close()
        finally:
            self.active_conns -= 1
            self.closed(t)
            c_writer.close()
