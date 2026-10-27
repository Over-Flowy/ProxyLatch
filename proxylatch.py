"""
ProxyLatch - send chosen apps through a SOCKS5 or HTTP proxy (Windows and Linux).

Pick one proxy (SOCKS5 or HTTP CONNECT) and a list of applications; every
outbound TCP connection made by those applications is transparently
redirected through the proxy.

  core.py             config, proxy handshakes, DNS over the proxy, relay
  backend_windows.py  capture with the WinDivert driver (needs Administrator)
  backend_linux.py    capture with nftables + a cgroup (root helper via pkexec)
  linux_helper.py     the root helper itself (runs as "proxylatch --helper")
  gui.py              the window
"""

import sys


def main():
    if sys.platform == "win32":
        import backend_windows as backend
    elif sys.platform.startswith("linux"):
        if "--helper" in sys.argv:
            import linux_helper
            linux_helper.main()
            return
        import backend_linux as backend
    else:
        sys.exit("ProxyLatch runs on Windows and Linux only.")
    if not backend.prepare_main():
        return
    from gui import App
    App(backend).mainloop()


if __name__ == "__main__":
    main()
