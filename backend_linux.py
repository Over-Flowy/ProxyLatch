"""
Linux backend: nftables + a cgroup instead of a packet driver.

The root helper (linux_helper.py, started once via pkexec) moves the selected
apps' processes into the cgroup "proxylatch" and installs nftables rules that
redirect that cgroup's TCP connections to the relay on 127.0.0.1. The relay
runs here, as the normal user, and reads each connection's original destination
with SO_ORIGINAL_DST. DNS from those apps is redirected to a small DNS server
in the relay that answers via DNS-over-HTTPS through the proxy.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

from core import Config, RelayBase, Target, dns_fit_udp
from linux_helper import cgroup_pids, cgroup_v2_available, exe_of, socket_inodes, tcp_rows

DNS_PORT = 34053
SO_ORIGINAL_DST = 80
DNS_SCOPE = "for these apps"
APP_DIALOG = {"initialdir": "/usr/bin"}


# --------------------------------------------------------------------------- #
# Root helper client
# --------------------------------------------------------------------------- #

class HelperClient:
    """Talks to the root helper over its stdin/stdout (JSON lines)."""

    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.lock = threading.Lock()
        self.log = print  # set once by on_startup()
        self.next_id = 0
        self.waiting: dict[int, tuple[threading.Event, list]] = {}

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def _ensure(self) -> None:
        if self.running():
            return
        if getattr(sys, "frozen", False):
            cmd = [sys.executable, "--helper"]
        else:
            cmd = [sys.executable, os.path.abspath(sys.argv[0]), "--helper"]
        if os.geteuid() != 0:
            pkexec = shutil.which("pkexec")
            if not pkexec:
                raise RuntimeError("pkexec not found. Install it (sudo apt install pkexec) "
                                   "or start ProxyLatch with sudo.")
            cmd = [pkexec] + cmd
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     text=True, bufsize=1)
        threading.Thread(target=self._reader, args=(self.proc,), daemon=True).start()

    def _reader(self, proc: subprocess.Popen) -> None:
        for line in proc.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if "log" in msg:
                self.log(msg["log"])
            elif msg.get("id") in self.waiting:
                ev, box = self.waiting[msg["id"]]
                box.append(msg)
                ev.set()
        for ev, _ in list(self.waiting.values()):  # helper exited: wake everyone up
            ev.set()

    def request(self, cmd: str, timeout: float = 180, **args) -> dict:
        with self.lock:
            self._ensure()
            self.next_id += 1
            rid = self.next_id
            ev, box = threading.Event(), []
            self.waiting[rid] = (ev, box)
            try:
                self.proc.stdin.write(json.dumps({"id": rid, "cmd": cmd, **args}) + "\n")
                self.proc.stdin.flush()
            except (OSError, ValueError):  # helper already gone / pipe closed
                pass
        deadline = time.monotonic() + timeout  # the first request waits for the password prompt
        try:
            while not ev.wait(0.5):
                if self.proc.poll() is not None:  # helper exited (e.g. password prompt cancelled)
                    ev.wait(0.5)  # let the reader deliver a reply it may already have
                    break
                if time.monotonic() > deadline:
                    break
        finally:
            self.waiting.pop(rid, None)
        if not box:
            try:
                code = self.proc.wait(2)  # the reader saw EOF: let the exit code arrive
            except subprocess.TimeoutExpired:
                code = None
            if code in (126, 127):
                raise RuntimeError("Administrator authorization was cancelled or denied.")
            raise RuntimeError("The root helper stopped unexpectedly." if code is not None
                               else "The root helper did not answer.")
        if "error" in box[0]:
            raise RuntimeError(box[0]["error"])
        return box[0]

    def close(self) -> None:
        if self.running():
            try:
                self.proc.stdin.close()  # the helper applies the stopped state and exits
                self.proc.wait(5)
            except (OSError, subprocess.TimeoutExpired):
                pass


helper = HelperClient()


# --------------------------------------------------------------------------- #
# Finding which program opened a connection (for the log)
# --------------------------------------------------------------------------- #

def socket_inode(rows, lport: int, rport: int) -> int | None:
    """Inode of the socket with these ports among /proc/net/tcp rows."""
    lp, rp = f":{lport:04X}", f":{rport:04X}"
    return next((int(f[9]) for f in rows if f[1].endswith(lp) and f[2].endswith(rp)), None)


def owner_pid(lport: int, rport: int, hint: int | None = None) -> int | None:
    """Captured process owning the connection; checks hint (the last owner) first."""
    inode = socket_inode(tcp_rows(), lport, rport)
    if inode is None:
        return None
    pids = cgroup_pids()  # only the captured processes; they belong to us, so readable
    if hint in pids:
        pids.remove(hint)
        pids.insert(0, hint)
    return next((pid for pid in pids if inode in socket_inodes(pid)), None)


def original_destination(sock: socket.socket) -> tuple[str, int]:
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)  # struct sockaddr_in
    port = struct.unpack_from("!H", raw, 2)[0]
    return socket.inet_ntoa(raw[4:8]), port


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

class _DnsUdp(asyncio.DatagramProtocol):
    def __init__(self, engine: "Engine"):
        self.engine = engine
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if len(data) >= 12:
            asyncio.ensure_future(self._answer(data, addr))

    async def _answer(self, query: bytes, addr) -> None:
        resp = await self.engine._resolve(query)
        if resp is not None and self.transport:
            # conntrack makes the reply come from the address the app asked (e.g. 127.0.0.53)
            self.transport.sendto(dns_fit_udp(query, resp), addr)


class Engine(RelayBase):
    last_owner: int | None = None

    def _start_capture(self) -> None:
        self.start_relay()
        res = helper.request("start", apps=self.apps, relay_port=self.relay_port,
                             dns_port=DNS_PORT, dns=self.dns, block_udp=self.block_udp,
                             block_ipv6=self.block_ipv6, kill_switch=self.kill_switch,
                             exclude=[os.getpid()])  # e.g. if "python3" is in the list
        if not res.get("captured"):
            self.log("None of the apps is running yet; they are captured as soon as they start")

    def _stop_capture(self, restarting: bool) -> None:
        # when restarting, the next "start" replaces the rules; without a helper there is
        # nothing to undo (and asking would show a password prompt)
        if not restarting and helper.running():
            try:
                helper.request("stop", kill_switch=self.kill_switch, timeout=30)
            except Exception as e:
                self.log(f"[error] {e}")
        self.stop_relay()

    def destination(self, writer) -> Target | None:
        try:
            ip, port = original_destination(writer.get_extra_info("socket"))
        except OSError:  # no NAT entry
            return None
        if (ip, port) == writer.get_extra_info("sockname")[:2]:
            return None  # not redirected: someone connected to the relay directly
        return Target(ip, port, "", entry=writer.get_extra_info("peername")[1])

    async def resolve_exe(self, t: Target) -> str:
        """Walks /proc, so it runs off the event loop."""
        loop = asyncio.get_running_loop()
        pid = await loop.run_in_executor(None, owner_pid, t.entry, t.port, self.last_owner)
        if pid is None:
            return ""
        self.last_owner = pid
        return exe_of(pid)

    async def extra_servers(self) -> list:
        if not self.dns:
            return []
        loop = asyncio.get_running_loop()
        tcp = await asyncio.start_server(self._dns_over_tcp, "127.0.0.1", DNS_PORT)
        udp, _ = await loop.create_datagram_endpoint(lambda: _DnsUdp(self),
                                                     local_addr=("127.0.0.1", DNS_PORT))
        return [tcp, udp]


# --------------------------------------------------------------------------- #
# Interface used by the GUI
# --------------------------------------------------------------------------- #

def on_startup(cfg: Config, log) -> None:
    """Checks only: the nftables state of the last session survives on its own."""
    helper.log = log
    if not cgroup_v2_available():
        log("[error] cgroup v2 not found: ProxyLatch needs Ubuntu 21.10 or newer.")
    elif not shutil.which("nft") and not os.path.exists("/usr/sbin/nft"):
        log("[error] nftables is not installed: sudo apt install nftables")
    elif cgroup_pids():
        log("Kill switch is active from the last session: captured apps are offline until Start")


def arm_kill_switch(cfg: Config, log) -> None:
    """After a settings change while stopped: keep captured apps offline (kill switch on)
    or release them (off)."""
    if not helper.running() and (cfg.kill_switch or not cgroup_pids()):
        return  # nothing to change, so don't ask for the password
    helper.request("stop", kill_switch=cfg.kill_switch, timeout=180)


def launch(app: str) -> None:
    """Start an app already inside the proxied cgroup (no capture race; needed for quick
    command-line tools, which connect before a started process can be captured)."""
    path = app if os.path.isabs(app) else shutil.which(app)
    if not path:
        raise RuntimeError(f"{app} not found")
    helper.request("launch", argv=[path], env=dict(os.environ), timeout=30)


def style_window(win) -> None:
    pass


def shutdown() -> None:
    helper.close()


def prepare_main() -> bool:
    return True
