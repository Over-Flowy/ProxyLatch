"""Windows backend: needs Windows (and WinDivert.dll from pydivert for the filter tests).
Nothing here needs Administrator rights."""
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

if sys.platform != "win32":
    pytest.skip("Windows only", allow_module_level=True)

import backend_windows as bw  # noqa: E402
import core  # noqa: E402


@pytest.mark.parametrize("kill_switch,block", [(True, True), (True, False), (False, True), (False, False)])
def test_filter_compiles(kill_switch, block):
    eng = bw.Engine(core.Config(apps=["x.exe"], block_udp=block, block_ipv6=block, kill_switch=kill_switch,
                                dns_over_proxy=not block), print)
    assert bw.WinDivert.check_filter(eng.build_filter(["8.8.8.8", "::1"])) == ""


def test_dns_reply_injected(run):
    class FakeDoh:
        async def query(self, q):
            rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.215.14")
            return q[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1, 0, 0) + q[12:core.dns_question_end(q)] + rr

    class FakeDivert:
        sent = []

        def send_packet(self, packet, addr):
            self.sent.append((bytes(packet), addr.Flags))
    eng = bw.Engine(core.Config(apps=["x.exe"], dns_over_proxy=True), print)
    eng.doh, eng.divert = FakeDoh(), FakeDivert()
    q = core.dns_build_query("example.com")
    pkt = (struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(q), 1, 0, 128, 17, 0,
                       socket.inet_aton("192.168.1.5"), socket.inet_aton("192.168.1.1"))
           + struct.pack("!HHHH", 55555, 53, 8 + len(q), 0) + q)
    addr = bw.WINDIVERT_ADDRESS()
    addr.Flags = bw.ADDR_OUTBOUND_BIT
    run(eng._answer_dns(pkt, 28, addr))
    reply, flags = eng.divert.sent[-1]
    assert reply[12:16] == socket.inet_aton("192.168.1.1") and reply[28:30] == q[:2]  # swapped, same ID
    assert not flags & bw.ADDR_OUTBOUND_BIT and eng.ip_names["93.184.215.14"] == "example.com"


def test_owner_lookups_from_several_threads():
    with socket.create_connection(("1.1.1.1", 80), timeout=5) as c:
        port = c.getsockname()[1]
        results = []
        threads = [threading.Thread(target=lambda: results.append(
            {bw.tcp_owner_pid(bw.AF_INET, port, 80) for _ in range(30)})) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert results == [{os.getpid()}] * 3
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
        u.bind(("0.0.0.0", 0))
        assert bw.udp_owner_pid(bw.AF_INET, u.getsockname()[1]) == os.getpid()


def test_children_of_a_selected_app_are_targeted():
    code = ("import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(8)']);"
            "print(p.pid, flush=True); time.sleep(8)")
    cmd = subprocess.Popen(["cmd.exe", "/c", sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(8)"])
    try:
        grandchild = int(cmd.stdout.readline())
        eng = bw.Engine(core.Config(apps=[os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")]), print)
        assert eng.target_path(cmd.pid).lower().endswith("cmd.exe")
        assert eng.target_path(grandchild)  # cmd.exe -> python -> python
        assert eng.target_path(unrelated.pid) is None
        assert eng.target_path(os.getpid()) is None  # never ProxyLatch itself
    finally:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(cmd.pid)], capture_output=True)
        unrelated.kill()


def test_reused_parent_pid_is_not_inherited(monkeypatch):
    info = {77: ("C:\\x\\tool.exe", 4242, 100), 4242: ("C:\\Windows\\System32\\cmd.exe", 0, 500)}
    monkeypatch.setattr(bw, "process_info", lambda pid: info[pid])
    eng = bw.Engine(core.Config(apps=["cmd.exe"]), print)
    assert eng.target_path(77) is None  # the "parent" started after the child: a reused pid


def test_failed_start_restores_kill_switch(monkeypatch):
    armed = []
    monkeypatch.setattr(bw, "arm_kill_switch", lambda cfg, log: armed.append(cfg.kill_switch))
    for name in ("add_firewall_rule", "kill_switch_unblock", "flush_dns_cache"):
        monkeypatch.setattr(bw, name, lambda *a: None)

    class Boom:
        check_filter = staticmethod(bw.WinDivert.check_filter)

        def __init__(self, flt):
            raise OSError(5, "Access is denied")
    monkeypatch.setattr(bw, "WinDivert", Boom)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    eng = bw.Engine(core.Config(proxy=core.Proxy("SOCKS5", "127.0.0.1", 1080), apps=["x.exe"], relay_port=free), print)
    with pytest.raises(OSError):
        eng.start()
    time.sleep(0.2)
    assert armed == [True] and not eng.threads[0].is_alive()
    armed.clear()
    eng.stop(restarting=True)
    assert armed == []  # a restart does not block the apps in between
