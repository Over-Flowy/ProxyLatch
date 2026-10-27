"""
Root helper for the Linux backend, started by the GUI as "pkexec proxylatch --helper".

It owns everything that needs root:
* the cgroup /sys/fs/cgroup/proxylatch. Processes of the selected apps are moved
  into it (children they start later inherit it automatically);
* the nftables table "inet proxylatch", which redirects that cgroup's TCP to the
  relay (and DNS to the relay's DNS server) and drops what could leak.

Protocol: JSON lines. Requests on stdin {"id": n, "cmd": ...}, replies on stdout
{"id": n, "ok": true, ...} or {"id": n, "error": "..."}, events {"log": "..."}.
When stdin closes (GUI quit or crashed) the stopped state is applied and we exit.
"""

from __future__ import annotations

import ipaddress
import json
import os
import select
import socket
import struct
import subprocess
import sys
import threading
import time

from core import AppMatcher

CGROUP_ROOT = "/sys/fs/cgroup"
CG_NAME = "proxylatch"
CGROUP = os.path.join(CGROUP_ROOT, CG_NAME)
TABLE = "inet proxylatch"
ORIGINS_FILE = "/run/proxylatch-origins.json"  # pid -> cgroup it came from

# --------------------------------------------------------------------------- #
# nftables
# --------------------------------------------------------------------------- #

def build_ruleset(relay_port: int, dns_port: int, dns: bool, block_udp: bool, block_ipv6: bool) -> str:
    """Rules while running. The filter chain runs before NAT, so it sees the original ports."""
    m = f'socket cgroupv2 level 1 "{CG_NAME}"'
    nat = []
    if dns:
        nat += [f"{m} meta nfproto ipv4 udp dport 53 redirect to :{dns_port}",
                f"{m} meta nfproto ipv4 tcp dport 53 redirect to :{dns_port}"]
    nat.append(f"{m} ip daddr != 127.0.0.0/8 meta l4proto tcp redirect to :{relay_port}")
    # "reject" instead of "drop": the app gets an error at once and falls back right away,
    # instead of waiting for a timeout (browsers and curl try IPv6 / QUIC first)
    flt = []
    if dns:  # IPv6 DNS can't be redirected to our IPv4 server: make the app use IPv4
        flt += [f'{m} meta nfproto ipv6 oifname != "lo" udp dport 53 {REJECT}',
                f'{m} meta nfproto ipv6 oifname != "lo" tcp dport 53 {REJECT_TCP}']
    if block_udp:  # QUIC etc. -> the app falls back to TCP
        flt.append(f'{m} oifname != "lo" udp dport != 53 {REJECT}')
    if block_ipv6:  # -> the app falls back to IPv4, which is proxied
        flt.append(f'{m} oifname != "lo" meta nfproto ipv6 meta l4proto tcp {REJECT_TCP}')
    return _table(nat, flt)


REJECT = "reject with icmpx type admin-prohibited"
REJECT_TCP = "reject with tcp reset"


def kill_switch_ruleset() -> str:
    """Rules while stopped with the kill switch on: the captured apps get no network."""
    m = f'socket cgroupv2 level 1 "{CG_NAME}" oifname != "lo"'
    return _table([], [f"{m} meta l4proto tcp {REJECT_TCP}", f"{m} {REJECT}"])


def _table(nat: list[str], flt: list[str]) -> str:
    def chain(name, kind, prio, rules):
        body = "".join(f"\n    {r}" for r in rules)
        return f"  chain {name} {{\n    type {kind} hook output priority {prio}; policy accept;{body}\n  }}\n"
    text = f"add table {TABLE}\ndelete table {TABLE}\ntable {TABLE} {{\n"  # atomic replace
    if nat:
        text += chain("nat_out", "nat", -100, nat)
    text += chain("filter_out", "filter", -150, flt)
    return text + "}\n"


def nft_load(text: str) -> None:
    r = subprocess.run(["nft", "-f", "-"], input=text, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"nft: {r.stderr.strip() or r.returncode}")


def nft_delete() -> None:
    subprocess.run(["nft", "delete", "table", *TABLE.split()], capture_output=True)


# --------------------------------------------------------------------------- #
# cgroup
# --------------------------------------------------------------------------- #

def cgroup_pids() -> list[int]:
    try:
        with open(os.path.join(CGROUP, "cgroup.procs")) as f:
            return [int(x) for x in f.read().split()]
    except OSError:
        return []


def cgroup_of(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            for line in f:
                if line.startswith("0::"):
                    return line[3:].strip()
    except OSError:
        pass
    return None


def move(pid: int, cg_dir: str) -> bool:
    try:
        with open(os.path.join(cg_dir, "cgroup.procs"), "w") as f:
            f.write(str(pid))
        return True
    except OSError:
        return False


def exe_of(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)")
    except OSError:
        return ""


def load_origins() -> dict[int, str]:
    try:
        with open(ORIGINS_FILE) as f:
            return {int(k): v for k, v in json.load(f).items()}
    except (OSError, ValueError):
        return {}


def save_origins(origins: dict[int, str]) -> None:
    try:
        with open(ORIGINS_FILE, "w") as f:
            json.dump(origins, f)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Sockets (/proc/net/tcp) - also used by the GUI side for log lines
# --------------------------------------------------------------------------- #

def tcp_rows():
    """Split lines of /proc/net/tcp and /proc/net/tcp6 (headers skipped)."""
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                lines = f.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) > 9:
                yield f


def socket_inodes(pid: int) -> set[int]:
    """Inodes of the sockets a process has open."""
    inodes = set()
    fd_dir = f"/proc/{pid}/fd"
    try:
        fds = os.listdir(fd_dir)
    except OSError:
        return inodes
    for fd in fds:
        try:
            link = os.readlink(f"{fd_dir}/{fd}")
        except OSError:
            continue
        if link.startswith("socket:["):
            inodes.add(int(link[8:-1]))
    return inodes


def _hex_addr(h: str) -> tuple[str, int]:
    """'0100007F:1F90' (from /proc/net/tcp) -> ('127.0.0.1', 8080)."""
    a, p = h.split(":")
    raw = bytes.fromhex(a)
    if len(raw) == 4:
        ip = socket.inet_ntop(socket.AF_INET, raw[::-1])
    else:  # four little-endian 32-bit words
        ip = socket.inet_ntop(socket.AF_INET6, b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    return ip, int(p, 16)


def is_loopback(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_loopback or bool(getattr(addr, "ipv4_mapped", None) and addr.ipv4_mapped.is_loopback)


def tcp_sockets(rows, inodes: set[int]) -> dict[int, tuple[str, int, str, int]]:
    """Established, non-loopback sockets among inodes: inode -> (lip, lport, rip, rport)."""
    out = {}
    for f in rows:
        inode = int(f[9])
        if f[3] == "01" and inode in inodes:  # 01 = TCP_ESTABLISHED
            (lip, lport), (rip, rport) = _hex_addr(f[1]), _hex_addr(f[2])
            if not is_loopback(rip):
                out[inode] = (lip, lport, rip, rport)
    return out


def ss_kill_filter(conns) -> list[str]:
    """One ss filter expression matching all (rip, rport, lport) connections."""
    expr = []
    for rip, rport, lport in conns:
        if expr:
            expr.append("or")
        expr += ["(", "dst", f"[{rip}]" if ":" in rip else rip, "and", "dport", "=", f":{rport}",
                 "and", "sport", "=", f":{lport}", ")"]
    return expr


def reset_connections(pids) -> int:
    """Close the established TCP connections of these processes; returns how many."""
    inodes = set().union(*(socket_inodes(p) for p in pids)) if pids else set()
    if not inodes:
        return 0
    conns = [(rip, rport, lport) for _, lport, rip, rport in tcp_sockets(tcp_rows(), inodes).values()]
    n = 0
    for i in range(0, len(conns), 64):  # one ss call per batch instead of per socket
        r = subprocess.run(["ss", "-K", "-H", "-tn", *ss_kill_filter(conns[i:i + 64])],
                           capture_output=True, text=True)
        if r.returncode == 0:  # ss -K prints one line per socket it closed
            n += len(r.stdout.strip().splitlines())
    return n


# --------------------------------------------------------------------------- #
# Process watcher
# --------------------------------------------------------------------------- #

NETLINK_CONNECTOR = 11
CN_IDX_PROC = CN_VAL_PROC = 1
PROC_CN_MCAST_LISTEN = 1
PROC_EVENT_EXEC = 2


def proc_connector() -> socket.socket | None:
    """Netlink socket that reports every exec() at once (None if unavailable)."""
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        s.bind((0, CN_IDX_PROC))
        op = struct.pack("=I", PROC_CN_MCAST_LISTEN)
        cn = struct.pack("=IIIIHH", CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(op), 0) + op
        s.send(struct.pack("=IHHII", 16 + len(cn), 3, 0, 0, os.getpid()) + cn)  # 3 = NLMSG_DONE
        return s
    except (OSError, AttributeError):
        return None


def exec_pids(data: bytes) -> list[int]:
    """PIDs from the PROC_EVENT_EXEC messages in a netlink datagram."""
    pids, off = [], 0
    while off + 16 <= len(data):
        length = struct.unpack_from("=I", data, off)[0]
        if length < 16:
            break
        msg = data[off + 16:off + length]  # cn_msg (20 bytes) + proc_event
        if len(msg) >= 20 + 16 + 8 and struct.unpack_from("=I", msg, 20)[0] == PROC_EVENT_EXEC:
            pids.append(struct.unpack_from("=II", msg, 20 + 16)[1])  # tgid
        off += (length + 3) & ~3
    return pids


def is_script(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        return False


def script_args(pid: int) -> list[str]:
    """Absolute, resolved paths of argv[0] and argv[1] (an interpreter runs a script as argv[1])."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            argv = f.read().split(b"\0")[:2]
        cwd = os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        return []
    out = []
    for a in argv:
        a = os.fsdecode(a)
        if a and ("/" in a):
            out.append(os.path.realpath(os.path.join(cwd, a)))
    return out


# folders shared by many programs: never used as an "app folder" (see app_folder)
SHARED_DIRS = {"/", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/usr/local", "/usr/local/bin",
               "/usr/local/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/share", "/usr/games",
               "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/opt", "/snap", "/home", "/root",
               "/tmp", "/var", "/etc"}


def app_folder(script: str) -> str | None:
    """The install folder of the app a launcher script belongs to, e.g.
    /usr/share/cursor/bin/cursor -> /usr/share/cursor, /opt/google/chrome/google-chrome ->
    /opt/google/chrome. Such scripts often start the real program detached (VS Code, Cursor)
    or the desktop menu runs it directly, so programs from that folder must match too."""
    d = os.path.dirname(script)
    if os.path.basename(d) == "bin":
        d = os.path.dirname(d)
    if d in SHARED_DIRS or os.path.dirname(d) == "/home":
        return None
    return d


def build_matchers(apps: list[str], log=None) -> list:
    """One predicate (pid, exe) -> bool per kind of app entry."""
    programs, scripts, snaps, folders = [], set(), set(), set()
    for a in apps:
        real = os.path.realpath(a) if os.path.isabs(a) else a  # /usr/bin entries are often symlinks
        name = os.path.basename(a)
        if a.startswith("/snap/bin/") or os.path.exists(f"/snap/bin/{name}"):
            # /snap/bin/firefox (-> /usr/bin/snap) or a wrapper like Ubuntu's /usr/bin/firefox:
            # snap moves the app into its own cgroup, so match that cgroup too
            snaps.add(name)
            if a.startswith("/snap/bin/"):
                continue
        if os.path.isabs(a) and is_script(real):
            scripts.add(real)  # e.g. /usr/bin/google-chrome: match the command line running it
            folder = app_folder(real)
            if folder:
                folders.add(folder)
            if log:
                log(f"{name}: launcher script {real}" + (f", plus programs in {folder}/" if folder else ""))
        else:
            programs.append(real)
    matchers = []
    if programs:
        exe_matches = AppMatcher(programs)
        matchers.append(lambda pid, exe: exe_matches(exe))
    if scripts:
        matchers.append(lambda pid, exe: any(a in scripts for a in script_args(pid)))
    if snaps:
        matchers.append(lambda pid, exe: any(f"/snap.{n}." in (cgroup_of(pid) or "") for n in snaps))
    if folders:
        prefixes = tuple(f + "/" for f in folders)
        matchers.append(lambda pid, exe: exe.startswith(prefixes))
    return matchers


class Watcher(threading.Thread):
    """Moves processes of the selected apps into our cgroup as soon as they start."""

    def __init__(self, helper: "Helper", apps: list[str], reset: bool, exclude=()):
        super().__init__(daemon=True)
        self.matchers = build_matchers(apps, helper.log if helper else None)
        # never capture ProxyLatch itself (the GUI sends its pid: under PyInstaller it
        # is not our parent process)
        self.exclude = set(exclude) | {os.getpid()}
        self.helper = helper
        self.reset = reset
        self.stop_flag = threading.Event()

    def matches(self, pid: int) -> str:
        if pid in self.exclude:
            return ""
        exe = exe_of(pid)
        return exe if exe and any(m(pid, exe) for m in self.matchers) else ""

    def capture(self, pid: int) -> bool:
        exe = self.matches(pid)
        if not exe:
            return False
        origin = cgroup_of(pid)
        if origin is None or origin == f"/{CG_NAME}" or not move(pid, CGROUP):
            return False
        self.helper.origins[pid] = origin
        self.helper.log(f"Captured {os.path.basename(exe)} (pid {pid})")
        return True

    def capture_all(self, pids, reset: bool) -> list[int]:
        captured = [p for p in pids if self.capture(p)]
        if captured:
            save_origins(self.helper.origins)
            if reset:  # sockets opened before the move keep bypassing the proxy
                n = reset_connections(captured)
                if n:
                    self.helper.log(f"Reset {n} connection(s) opened before capture")
        return captured

    def scan(self, reset: bool | None = None) -> int:
        inside = set(cgroup_pids())
        pids = (int(n) for n in os.listdir("/proc") if n.isdigit() and int(n) not in inside)
        return len(self.capture_all(pids, self.reset if reset is None else reset))

    def run(self) -> None:
        sock = proc_connector()
        last_scan = time.monotonic()
        while not self.stop_flag.is_set():
            if sock:
                ready, _, _ = select.select([sock], [], [], 1.0)
                if ready:
                    try:
                        self.capture_all(exec_pids(sock.recv(65536)), self.reset)
                    except OSError:
                        pass
            else:
                self.stop_flag.wait(1.0)
            if time.monotonic() - last_scan >= 2:  # catch anything the events missed
                self.scan()
                last_scan = time.monotonic()
        if sock:
            sock.close()


# --------------------------------------------------------------------------- #
# Helper main loop
# --------------------------------------------------------------------------- #

def launch_command(argv: list[str], uid: int) -> tuple[list[str], str]:
    """Command that moves itself into the cgroup, drops root and runs argv; and the user's home.
    The shell writes its own pid ($$) to cgroup.procs, then exec keeps that pid for the app."""
    import pwd  # Linux only
    user = pwd.getpwuid(uid)
    script = 'cg="$1"; shift; echo $$ > "$cg" && exec "$@"'
    run = argv if uid == 0 else ["setpriv", f"--reuid={uid}", f"--regid={user.pw_gid}",
                                 "--init-groups", "--", *argv]
    return ["sh", "-c", script, "sh", os.path.join(CGROUP, "cgroup.procs"), *run], user.pw_dir


def cgroup_v2_available() -> bool:
    return os.path.exists(os.path.join(CGROUP_ROOT, "cgroup.controllers"))


class Helper:
    def __init__(self, out=None):
        self.out = out or sys.stdout  # where replies and log events go (the GUI reads them)
        self.out_lock = threading.Lock()
        self.watcher: Watcher | None = None
        self.origins = load_origins()
        self.state = "blocked" if cgroup_pids() else "off"  # what the table currently does
        self.kill_switch: bool | None = None  # last setting the GUI sent
        self.home_cgroup = "/"  # the GUI's cgroup: where launched apps go when released
        self.launched: list[subprocess.Popen] = []

    def send(self, msg: dict) -> None:
        with self.out_lock:
            self.out.write(json.dumps(msg) + "\n")
            self.out.flush()

    def log(self, text: str) -> None:
        self.send({"log": text})

    def release(self, pids: list[int]) -> None:
        """Move processes back to the cgroup they came from."""
        if not pids:
            return
        for pid in pids:
            origin = self.origins.pop(pid, self.home_cgroup)
            if not move(pid, CGROUP_ROOT + origin):
                move(pid, CGROUP_ROOT)
        save_origins(self.origins)

    def start(self, apps: list[str], relay_port: int, dns_port: int, dns: bool,
              block_udp: bool, block_ipv6: bool, kill_switch: bool, exclude=()) -> dict:
        """block_udp / block_ipv6 arrive with the kill switch already applied."""
        if not cgroup_v2_available():
            raise RuntimeError("cgroup v2 is not mounted at /sys/fs/cgroup (Ubuntu 21.10 or newer needed)")
        self.stop_watcher()
        self.kill_switch = kill_switch
        if exclude:
            self.home_cgroup = cgroup_of(exclude[0]) or "/"
        os.makedirs(CGROUP, exist_ok=True)
        watcher = Watcher(self, apps, reset=kill_switch, exclude=exclude)
        # left over from an earlier session but no longer selected (or ProxyLatch itself)
        self.release([p for p in cgroup_pids() if not watcher.matches(p)])
        nft_load(build_ruleset(relay_port, dns_port, dns, block_udp, block_ipv6))
        self.state = "running"
        captured = watcher.scan(reset=False)
        if kill_switch:  # one batch for everything in the cgroup, old and new
            n = reset_connections(cgroup_pids())
            if n:
                self.log(f"Reset {n} connection(s) opened before Start")
        self.watcher = watcher
        watcher.start()
        return {"captured": captured}

    def stop_watcher(self) -> None:
        if self.watcher:
            self.watcher.stop_flag.set()
            self.watcher.join(3)
            self.watcher = None

    def stop(self, kill_switch: bool) -> dict:
        self.stop_watcher()
        self.kill_switch = kill_switch
        pids = cgroup_pids()
        if kill_switch and pids:
            nft_load(kill_switch_ruleset())
            if self.state != "blocked":
                self.log(f"Kill switch: {len(pids)} process(es) of these apps stay offline "
                         f"until you click Start")
            self.state = "blocked"
        else:
            nft_delete()
            self.release(pids)
            try:
                os.rmdir(CGROUP)
            except OSError:
                pass
            if self.state == "blocked":
                self.log("Kill switch off: the apps can reach the internet directly again")
            self.state = "off"
        return {}

    def launch(self, argv: list[str], env: dict[str, str]) -> dict:
        """Start a program already inside the cgroup, as the user who ran ProxyLatch.
        Unlike capturing after exec, nothing can connect before the move."""
        if self.state != "running":
            raise RuntimeError("Click Start first")
        self.launched = [p for p in self.launched if p.poll() is None]  # reap finished ones
        uid = int(os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID") or os.getuid())
        cmd, home = launch_command(argv, uid)
        p = subprocess.Popen(cmd, env=env, cwd=home, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
        self.launched.append(p)
        self.origins[p.pid] = self.home_cgroup
        save_origins(self.origins)
        self.log(f"Launched {os.path.basename(argv[0])} (pid {p.pid})")
        return {"pid": p.pid}

    def handle(self, req: dict) -> None:
        rid = req.get("id")
        try:
            args = {k: v for k, v in req.items() if k not in ("id", "cmd")}
            if req.get("cmd") == "start":
                res = self.start(**args)
            elif req.get("cmd") == "stop":
                res = self.stop(**args)
            elif req.get("cmd") == "launch":
                res = self.launch(**args)
            else:
                raise RuntimeError(f"unknown command {req.get('cmd')!r}")
            self.send({"id": rid, "ok": True, **res})
        except Exception as e:
            self.send({"id": rid, "error": str(e) or type(e).__name__})

    def run(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if line:
                try:
                    self.handle(json.loads(line))
                except ValueError:
                    pass
        # the GUI is gone: apply the stopped state
        if self.kill_switch is not None:
            try:
                self.stop(self.kill_switch)
            except Exception:
                pass


def main() -> None:
    if os.geteuid() != 0:
        sys.exit("proxylatch --helper must run as root (the GUI starts it with pkexec).")
    Helper().run()
