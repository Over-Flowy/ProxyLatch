import asyncio
import os
import socket
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class MiniProxy:
    """A small SOCKS5 (with optional user/password) + HTTP CONNECT proxy for tests.
    `routes` maps a requested host to the real (host, port) to connect to; `seen` records
    the hosts clients asked for."""

    def __init__(self, routes=None, user=b"bob", password=b"pw"):
        self.routes = routes or {}
        self.seen: list[str] = []
        self.user, self.password = user, password
        self.server = None
        self.port = 0

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    def close(self):
        self.server.close()

    async def _handle(self, r, w):
        try:
            first = await r.readexactly(1)
            if first == b"\x05":
                methods = await r.readexactly((await r.readexactly(1))[0])
                if 2 in methods:
                    w.write(b"\x05\x02")
                    await r.readexactly(1)
                    u = await r.readexactly((await r.readexactly(1))[0])
                    p = await r.readexactly((await r.readexactly(1))[0])
                    ok = (u, p) == (self.user, self.password)
                    w.write(b"\x01\x00" if ok else b"\x01\x01")
                    if not ok:
                        return
                else:
                    w.write(b"\x05\x00")
                _, _, _, atyp = await r.readexactly(4)
                if atyp == 1:
                    host = socket.inet_ntoa(await r.readexactly(4))
                else:
                    host = (await r.readexactly((await r.readexactly(1))[0])).decode()
                port = struct.unpack(">H", await r.readexactly(2))[0]
                w.write(b"\x05\x00\x00\x01" + bytes(6))
            else:
                head = first + await r.readuntil(b"\r\n\r\n")
                host, port = head.split()[1].decode().rsplit(":", 1)
                port = int(port)
                w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            self.seen.append(host)
            host, port = self.routes.get(host, (host, port))
            ur, uw = await asyncio.open_connection(host, port)

            async def pipe(a, b):
                while data := await a.read(65536):
                    b.write(data)
                    await b.drain()
                b.close()
            await asyncio.gather(pipe(r, uw), pipe(ur, w), return_exceptions=True)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            w.close()


@pytest.fixture
def run():
    """Run a coroutine in a fresh event loop."""
    return asyncio.run
