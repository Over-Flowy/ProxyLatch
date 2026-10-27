"""Platform-independent parts: config, app matching, DNS helpers, sniffing, proxy handshakes, relay."""
import asyncio
import socket
import ssl
import struct

import pytest

import core
from conftest import MiniProxy


def client_hello(host: str) -> bytes:
    """A real TLS ClientHello, as Python's ssl module sends it."""
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ssl.create_default_context().wrap_bio(inc, out, server_hostname=host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


# --------------------------------------------------------------------------- #
# config and app matching
# --------------------------------------------------------------------------- #

def test_config_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(core, "CONFIG_FILE", str(tmp_path / "config.json"))
    assert core.Config.load() == core.Config()  # nothing saved yet

    cfg = core.Config(apps=["a"], kill_switch=False, dns_server="Quad9")
    cfg.save()
    assert core.Config.load() == cfg

    (tmp_path / "config.json").write_text('{"proxy": {"proxy_type": "SOCKS4", "port": 8080}, "dns_server": "x"}')
    bad = core.Config.load()  # invalid values fall back to defaults
    assert bad.proxy.proxy_type == "SOCKS5" and bad.proxy.port == 8080 and bad.dns_server == "Cloudflare"


def test_app_matcher():
    m = core.AppMatcher(["/opt/App/Chrome", "firefox", "  "])
    assert m("/opt/App/Chrome") and m("/usr/lib/firefox") and not m("/opt/App/Chromex") and not m("")
    if core.IS_WINDOWS:
        assert core.AppMatcher(["C:/Apps/Chrome.EXE"])("c:\\apps\\chrome.exe")
    else:
        assert not m("/opt/app/chrome")  # case-sensitive outside Windows


# --------------------------------------------------------------------------- #
# DNS helpers
# --------------------------------------------------------------------------- #

def _answer(query: bytes, ip: str, extra: int = 0) -> bytes:
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    pad = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, 200) + b"\xc7" + b"x" * 199
                   for _ in range(extra))
    return (query[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1 + extra, 0, 0)
            + query[12:core.dns_question_end(query)] + rr + pad)


def test_dns_answers_and_truncation():
    q = core.dns_build_query("Example.COM")
    assert core.dns_answers(_answer(q, "93.184.215.14")) == ("example.com", ["93.184.215.14"])
    small, big = _answer(q, "1.2.3.4"), _answer(q, "1.2.3.4", extra=8)
    assert core.dns_fit_udp(q, small) == small
    cut = core.dns_fit_udp(q, big)
    assert cut[2] & 0x02 and len(cut) < 512 and cut[:2] == q[:2]  # TC bit: retry over TCP


# --------------------------------------------------------------------------- #
# sniffing the host name
# --------------------------------------------------------------------------- #

def test_tls_sni_and_http_host():
    ch = client_hello("cloudcode-pa.googleapis.com")
    assert core.tls_sni(ch) == "cloudcode-pa.googleapis.com"
    assert core.tls_sni(client_hello("1.2.3.4")) is None  # no SNI for IP addresses
    assert core.tls_sni(b"\x16\x03") is None and core.tls_sni(b"") is None
    assert core.tls_record_incomplete(ch[:100]) and not core.tls_record_incomplete(ch)
    assert core.http_headers_incomplete(b"GET / HTTP/1.1\r\nUser-Agent: x\r\n")
    assert not core.http_headers_incomplete(b"GET / HTTP/1.1\r\nHost: a.b\r\n\r\n")
    assert not core.http_headers_incomplete(b"SSH-2.0-OpenSSH\r\n")
    assert core.http_host(b"GET / HTTP/1.1\r\nHost: Example.COM:8080\r\n\r\n") == "example.com"
    assert core.http_host(b"POST /x HTTP/1.1\r\nhost: a.b\r\n\r\n") == "a.b"
    assert core.http_host(b"SSH-2.0-OpenSSH\r\n") is None
    assert core._valid_host(b"evil\r\nX") is None and core._valid_host(b"localhost") is None


# --------------------------------------------------------------------------- #
# proxy handshakes
# --------------------------------------------------------------------------- #

async def _web_server():
    async def handle(r, w):
        await r.readuntil(b"\r\n\r\n")
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        await w.drain()
        w.close()
    return await asyncio.start_server(handle, "127.0.0.1", 0)


@pytest.mark.parametrize("ptype,user,password", [("SOCKS5", "", ""), ("SOCKS5", "bob", "pw"), ("HTTP", "", "")])
def test_test_proxy(run, ptype, user, password):
    async def main():
        web = await _web_server()
        proxy = await MiniProxy({"1.1.1.1": ("127.0.0.1", web.sockets[0].getsockname()[1])}).start()
        try:
            return await core.test_proxy(core.Proxy(ptype, "127.0.0.1", proxy.port, user, password))
        finally:
            proxy.close()
            web.close()
    assert run(main()).startswith("Proxy works")


def test_socks5_wrong_password(run):
    async def main():
        proxy = await MiniProxy().start()
        try:
            await core.test_proxy(core.Proxy("SOCKS5", "127.0.0.1", proxy.port, "bob", "bad"))
        finally:
            proxy.close()
    with pytest.raises(core.ProxyError, match="authentication"):
        run(main())


# --------------------------------------------------------------------------- #
# relay end to end
# --------------------------------------------------------------------------- #

class FakeEngine(core.RelayBase):
    """A backend that says every connection was going to a (wrong) IP, like poisoned DNS."""

    def destination(self, writer):
        return core.Target("10.10.34.35", 80, "/usr/bin/app")


@pytest.mark.parametrize("ptype", ["SOCKS5", "HTTP"])
def test_relay_sends_sniffed_name_to_proxy(run, ptype):
    async def main():
        web = await _web_server()
        proxy = await MiniProxy({"example.org": ("127.0.0.1", web.sockets[0].getsockname()[1])}).start()
        logs = []
        eng = FakeEngine(core.Config(proxy=core.Proxy(ptype, "127.0.0.1", proxy.port), apps=["app"]),
                         logs.append)
        eng.relay_port = _free_port()
        eng.start_relay()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", eng.relay_port)
            w.write(b"GET / HTTP/1.1\r\n")  # split request: the sniffer must still find Host
            await w.drain()
            await asyncio.sleep(0.05)
            w.write(b"Host: example.org\r\n\r\n")
            body = await asyncio.wait_for(r.read(), 5)
            w.close()
        finally:
            eng.stop_relay()
            proxy.close()
            web.close()
        return body, proxy.seen, logs
    body, seen, logs = run(main())
    assert body.endswith(b"hello") and seen == ["example.org"] and "app  →  example.org:80" in logs


def test_relay_server_first_protocol_falls_back_to_ip(run):
    async def main():
        got = []

        async def echo(r, w):  # stands in for the destination, reached via the proxy
            got.append(await r.read(5))
            w.write(b"ok")
            await w.drain()
            w.close()
        target = await asyncio.start_server(echo, "127.0.0.1", 0)
        proxy = await MiniProxy({"10.10.34.35": ("127.0.0.1", target.sockets[0].getsockname()[1])}).start()
        eng = FakeEngine(core.Config(proxy=core.Proxy("SOCKS5", "127.0.0.1", proxy.port), apps=["x"]),
                         lambda m: None)
        eng.relay_port = _free_port()
        eng.start_relay()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", eng.relay_port)
            await asyncio.sleep(core.SNIFF_TIMEOUT + 0.2)  # the client waits, like SSH
            w.write(b"hello")
            await w.drain()
            reply = await asyncio.wait_for(r.read(), 5)
            w.close()
        finally:
            eng.stop_relay()
            proxy.close()
            target.close()
        return reply, proxy.seen, got
    reply, seen, got = run(main())
    assert reply == b"ok" and seen == ["10.10.34.35"] and got == [b"hello"]


def test_start_requires_apps():
    with pytest.raises(RuntimeError, match="at least one"):
        FakeEngine(core.Config(apps=[]), print).start()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
