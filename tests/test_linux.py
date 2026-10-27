"""Linux backend logic. Runs on any OS: everything that needs root or /proc is faked."""
import asyncio
import io
import json
import socket
import struct
import subprocess
import sys
import textwrap
import time
import types

import pytest

import backend_linux as bl
import core
import linux_helper as lh


# --------------------------------------------------------------------------- #
# nftables rules
# --------------------------------------------------------------------------- #

def test_ruleset_running():
    rs = lh.build_ruleset(34010, 34053, dns=True, block_udp=True, block_ipv6=True)
    assert rs.startswith("add table inet proxylatch\ndelete table inet proxylatch\n")  # atomic replace
    assert "redirect to :34010" in rs and "redirect to :34053" in rs
    assert "udp dport != 53 reject with icmpx type admin-prohibited" in rs
    assert "meta l4proto tcp reject with tcp reset" in rs and "drop" not in rs
    assert "priority -150" in rs  # filter runs before NAT, so it sees the original ports
    minimal = lh.build_ruleset(34010, 34053, dns=False, block_udp=False, block_ipv6=False)
    assert "34053" not in minimal and "reject" not in minimal


def test_kill_switch_ruleset():
    ks = lh.kill_switch_ruleset()
    assert "nat_out" not in ks and 'oifname != "lo"' in ks and "reject with tcp reset" in ks


# --------------------------------------------------------------------------- #
# /proc parsing and connection resets
# --------------------------------------------------------------------------- #

PROC_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0500A8C0:D431 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 424242 1
   1: 0100007F:84DA 0100007F:84DB 01 00000000:00000000 00:00000000 00000000  1000        0 555 1
   2: 0500A8C0:D432 22D8B85D:01BB 06 00000000:00000000 00:00000000 00000000  1000        0 0 1
"""
ROWS = [line.split() for line in PROC_TCP.splitlines()[1:]]


def test_proc_tcp_parsing():
    assert lh._hex_addr("0500A8C0:D431") == ("192.168.0.5", 54321)
    assert lh._hex_addr("0000000000000000FFFF00000100007F:0050") == ("::ffff:127.0.0.1", 80)
    assert lh.tcp_sockets(ROWS, {424242, 555, 0}) == {424242: ("192.168.0.5", 54321, "93.184.216.34", 443)}
    assert lh.tcp_sockets(ROWS, {555}) == {}  # loopback is never reset
    assert bl.socket_inode(ROWS, 54321, 443) == 424242 and bl.socket_inode(ROWS, 1, 2) is None
    assert lh.is_loopback("::ffff:127.0.0.1") and lh.is_loopback("::1") and not lh.is_loopback("8.8.8.8")


def test_reset_connections_one_ss_call(monkeypatch):
    calls = []
    monkeypatch.setattr(lh, "socket_inodes", lambda pid: {424242})
    monkeypatch.setattr(lh, "tcp_rows", lambda: iter(ROWS))
    monkeypatch.setattr(lh.subprocess, "run", lambda cmd, **kw: (
        calls.append(cmd), subprocess.CompletedProcess(cmd, 0, "ESTAB 0 0 a b\n", ""))[1])
    assert lh.reset_connections([1, 2]) == 1
    assert len(calls) == 1 and calls[0][:4] == ["ss", "-K", "-H", "-tn"]
    f = lh.ss_kill_filter([("1.2.3.4", 443, 5555), ("2001:db8::1", 80, 6666)])
    assert " ".join(f) == ("( dst 1.2.3.4 and dport = :443 and sport = :5555 ) or "
                           "( dst [2001:db8::1] and dport = :80 and sport = :6666 )")


def _exec_event(pid: int, tgid: int) -> bytes:
    ev = struct.pack("=IIQ", lh.PROC_EVENT_EXEC, 0, 123) + struct.pack("=II", pid, tgid)
    cn = struct.pack("=IIIIHH", 1, 1, 0, 0, len(ev), 0) + ev
    return struct.pack("=IHHII", 16 + len(cn), 3, 0, 0, 0) + cn


def test_exec_pids():
    fork = struct.pack("=IIQ", 1, 0, 0) + bytes(16)
    fork_msg = struct.pack("=IHHII", 16 + 20 + len(fork), 3, 0, 0, 0) + struct.pack("=IIIIHH", 1, 1, 0, 0, len(fork), 0) + fork
    assert lh.exec_pids(_exec_event(4321, 4321) + fork_msg + _exec_event(77, 76)) == [4321, 76]


# --------------------------------------------------------------------------- #
# which processes are captured
# --------------------------------------------------------------------------- #

@pytest.fixture
def fake_system(monkeypatch):
    """Fake /proc and file system: procs maps pid -> (exe, argv[:2], cgroup)."""
    links = {"/usr/bin/cursor": "/usr/share/cursor/bin/cursor",
             "/usr/bin/google-chrome": "/opt/google/chrome/google-chrome",
             "/usr/bin/firefox": "/usr/bin/firefox"}
    scripts = {"/usr/share/cursor/bin/cursor", "/opt/google/chrome/google-chrome", "/usr/bin/firefox",
               "/usr/bin/myscript"}
    procs = {}
    monkeypatch.setattr(lh.os.path, "realpath", lambda p: links.get(p, p))
    monkeypatch.setattr(lh.os.path, "exists", lambda p: p == "/snap/bin/firefox")
    monkeypatch.setattr(lh, "is_script", lambda p: p in scripts)
    monkeypatch.setattr(lh, "exe_of", lambda pid: procs[pid][0])
    monkeypatch.setattr(lh, "script_args", lambda pid: procs[pid][1])
    monkeypatch.setattr(lh, "cgroup_of", lambda pid: procs[pid][2])
    return procs


def test_matching_programs_scripts_snaps_and_app_folders(fake_system):
    fake_system.update({
        1: ("/usr/share/cursor/cursor", ["/usr/share/cursor/cursor"], "/u/a.scope"),  # Cursor from the menu
        2: ("/usr/bin/bash", ["/usr/bin/bash", "/usr/share/cursor/bin/cursor"], "/u/a.scope"),  # its launcher
        3: ("/opt/google/chrome/chrome", ["/opt/google/chrome/chrome"], "/u/a.scope"),
        4: ("/snap/firefox/1/usr/lib/firefox/firefox", ["x"], "/u/snap.firefox.firefox-9.scope"),
        5: ("/usr/bin/curl", ["/usr/bin/curl"], "/u/a.scope"),
        6: ("/usr/share/code/code", ["/usr/share/code/code"], "/u/a.scope"),  # not selected
        7: ("/usr/bin/python3", ["/usr/bin/python3", "/usr/bin/other"], "/u/a.scope"),
        8: ("/usr/bin/curl", ["/usr/bin/curl"], "/u/gui.scope"),  # ProxyLatch itself (excluded)
    })
    logs = []
    helper = types.SimpleNamespace(log=logs.append)
    w = lh.Watcher(helper, ["/usr/bin/cursor", "/usr/bin/google-chrome", "/usr/bin/firefox",
                            "/usr/bin/curl", "/usr/bin/myscript"], reset=False, exclude=[8])
    got = {pid: bool(w.matches(pid)) for pid in fake_system}
    assert got == {1: True, 2: True, 3: True, 4: True, 5: True, 6: False, 7: False, 8: False}
    assert any("plus programs in /usr/share/cursor/" in line for line in logs)
    assert lh.app_folder("/usr/bin/myscript") is None and lh.app_folder("/home/u/tool.sh") is None


def test_launch_command(monkeypatch):
    monkeypatch.setitem(sys.modules, "pwd", types.SimpleNamespace(
        getpwuid=lambda uid: types.SimpleNamespace(pw_gid=1000, pw_dir="/home/u")))
    cmd, home = lh.launch_command(["/usr/bin/curl", "-s"], 1000)
    assert cmd[:4] == ["sh", "-c", 'cg="$1"; shift; echo $$ > "$cg" && exec "$@"', "sh"]
    assert cmd[4].replace("\\", "/").endswith("proxylatch/cgroup.procs") and home == "/home/u"
    assert cmd[5:] == ["setpriv", "--reuid=1000", "--regid=1000", "--init-groups", "--", "/usr/bin/curl", "-s"]
    assert lh.launch_command(["/usr/bin/curl"], 0)[0][5:] == ["/usr/bin/curl"]  # root: no setpriv


# --------------------------------------------------------------------------- #
# the helper's start / stop / kill switch states
# --------------------------------------------------------------------------- #

@pytest.fixture
def helper(tmp_path, monkeypatch):
    calls, pids = [], []
    monkeypatch.setattr(lh, "CGROUP_ROOT", str(tmp_path))
    monkeypatch.setattr(lh, "CGROUP", str(tmp_path / "proxylatch"))
    monkeypatch.setattr(lh, "ORIGINS_FILE", str(tmp_path / "origins.json"))
    (tmp_path / "cgroup.controllers").touch()
    monkeypatch.setattr(lh, "nft_load", lambda text: calls.append("running" if "nat_out" in text else "blocked"))
    monkeypatch.setattr(lh, "nft_delete", lambda: calls.append("delete"))
    monkeypatch.setattr(lh, "cgroup_pids", lambda: list(pids))
    monkeypatch.setattr(lh, "cgroup_of", lambda pid: "/user.slice/gui.scope")
    monkeypatch.setattr(lh, "move", lambda pid, d: calls.append(("move", pid)) or True)
    monkeypatch.setattr(lh, "reset_connections", lambda p: 0)
    monkeypatch.setattr(lh.Watcher, "start", lambda self: None)  # no background thread
    monkeypatch.setattr(lh.Watcher, "join", lambda self, timeout=None: None)

    def scan(self, reset=None):
        pids.append(100)
        self.helper.origins[100] = "/user.slice/app.scope"
        return 1
    monkeypatch.setattr(lh.Watcher, "scan", scan)
    monkeypatch.setattr(lh.Watcher, "matches", lambda self, pid: "/usr/bin/curl" if pid == 100 else "")
    out = io.StringIO()
    h = lh.Helper(out)

    def call(req):
        calls.clear()
        out.truncate(0)
        out.seek(0)
        h.handle(req)
        lines = [json.loads(line) for line in out.getvalue().splitlines()]
        return calls[:], [m["log"] for m in lines if "log" in m], [m for m in lines if "id" in m][0]
    h.call, h.pids = call, pids
    return h


START = {"cmd": "start", "apps": ["/usr/bin/curl"], "relay_port": 34010, "dns_port": 34053,
         "dns": True, "block_udp": True, "block_ipv6": True, "exclude": [1]}


def test_helper_kill_switch_states(helper):
    helper.pids.append(999)  # left over from an earlier session, no longer selected
    calls, _, reply = helper.call({**START, "id": 1, "kill_switch": True})
    assert calls == [("move", 999), "running"] and reply == {"id": 1, "ok": True, "captured": 1}
    helper.pids.remove(999)

    calls, logs, _ = helper.call({"id": 2, "cmd": "stop", "kill_switch": True})
    assert calls == ["blocked"] and logs == ["Kill switch: 1 process(es) of these apps stay offline until you click Start"]
    calls, logs, _ = helper.call({"id": 3, "cmd": "stop", "kill_switch": True})
    assert calls == ["blocked"] and logs == []  # no duplicate message

    calls, logs, _ = helper.call({"id": 4, "cmd": "stop", "kill_switch": False})
    assert calls == ["delete", ("move", 100)] and logs == ["Kill switch off: the apps can reach the internet directly again"]


def test_helper_launch(helper, monkeypatch):
    _, _, reply = helper.call({"id": 1, "cmd": "launch", "argv": ["/usr/bin/curl"], "env": {}})
    assert "Start first" in reply["error"]

    started = []

    class FakePopen:
        pid = 777

        def __init__(self, cmd, **kw):
            started.append((cmd, kw))

        def poll(self):
            return None
    monkeypatch.setattr(lh.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(lh, "launch_command", lambda argv, uid: (["run", *argv], "/home/u"))
    monkeypatch.setenv("PKEXEC_UID", "1000")
    helper.call({**START, "id": 2, "kill_switch": False})
    _, logs, reply = helper.call({"id": 3, "cmd": "launch", "argv": ["/usr/bin/curl"], "env": {"DISPLAY": ":0"}})
    assert reply["pid"] == 777 and helper.origins[777] == "/user.slice/gui.scope"
    assert started[0][1]["env"] == {"DISPLAY": ":0"} and started[0][1]["cwd"] == "/home/u"


# --------------------------------------------------------------------------- #
# GUI side: talking to the helper, finding the original destination
# --------------------------------------------------------------------------- #

FAKE_HELPER = textwrap.dedent("""
    import json, sys
    for line in sys.stdin:
        req = json.loads(line)
        if req["cmd"] == "exit":
            sys.exit(126)  # what pkexec returns when the password prompt is cancelled
        print(json.dumps({"log": "got " + req["cmd"]}), flush=True)
        if req["cmd"] == "start":
            print(json.dumps({"id": req["id"], "ok": True, "captured": len(req["apps"])}), flush=True)
        else:
            print(json.dumps({"id": req["id"], "error": "boom"}), flush=True)
""")


def test_helper_client_protocol(tmp_path):
    script = tmp_path / "fake_helper.py"
    script.write_text(FAKE_HELPER)
    client = bl.HelperClient()
    logs = []
    client.log = logs.append

    def ensure():
        if not client.running():
            client.proc = subprocess.Popen([sys.executable, str(script)], stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, text=True, bufsize=1)
            bl.threading.Thread(target=client._reader, args=(client.proc,), daemon=True).start()
    client._ensure = ensure
    assert client.request("start", apps=["a", "b"], timeout=10)["captured"] == 2
    with pytest.raises(RuntimeError, match="boom"):
        client.request("stop", timeout=10)
    t0 = time.monotonic()
    with pytest.raises(RuntimeError, match="cancelled"):
        client.request("exit", timeout=180)
    assert time.monotonic() - t0 < 5  # fails at once, not after the timeout
    assert logs[:2] == ["got start", "got stop"]
    client.close()


class _Sock:
    def __init__(self, raw):
        self.raw = raw

    def getsockopt(self, *args):
        if self.raw is None:
            raise OSError(2, "no NAT entry")
        return self.raw


class _Writer:
    def __init__(self, raw):
        self.info = {"socket": _Sock(raw), "sockname": ("127.0.0.1", 34010), "peername": ("192.168.1.5", 40000)}

    def get_extra_info(self, key):
        return self.info[key]


def test_destination_and_owner(monkeypatch):
    eng = bl.Engine(core.Config(apps=["curl"]), print)
    redirected = struct.pack("!HH4s8x", socket.AF_INET, 443, socket.inet_aton("93.184.216.34"))
    direct = struct.pack("!HH4s8x", socket.AF_INET, 34010, socket.inet_aton("127.0.0.1"))
    t = eng.destination(_Writer(redirected))
    assert (t.ip, t.port, t.entry) == ("93.184.216.34", 443, 40000)
    assert eng.destination(_Writer(direct)) is None and eng.destination(_Writer(None)) is None

    monkeypatch.setattr(bl, "owner_pid", lambda lport, rport, hint: 4242 if (lport, rport) == (40000, 443) else None)
    monkeypatch.setattr(bl, "exe_of", lambda pid: "/usr/bin/curl")
    assert asyncio.run(eng.resolve_exe(t)) == "/usr/bin/curl" and eng.last_owner == 4242
