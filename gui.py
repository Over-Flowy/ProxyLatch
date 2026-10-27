"""ProxyLatch GUI (tkinter, dark theme). The OS specifics come from the backend module
(backend_windows / backend_linux) that proxylatch.py passes to App."""

from __future__ import annotations

import asyncio
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

from core import APP_NAME, DOH_SERVERS, IS_WINDOWS, PROXY_TYPES, Config, Proxy, test_proxy

# --------------------------------------------------------------------------- #
# GUI (dark theme)
# --------------------------------------------------------------------------- #

BG = "#17181c"
CARD = "#212228"
FIELD = "#2b2d35"
BORDER = "#363844"
FG = "#e8e9ed"
MUTED = "#8b8fa0"
ACCENT = "#5b8cff"
ACCENT_HI = "#7aa2ff"
GREEN = "#3ecf8e"
RED = "#f2555a"
STOP = "#e5484d"
STOP_HI = "#f06a6e"
# Windows fonts; apply_dark_theme() swaps in the best available ones elsewhere
FONT = ("Segoe UI", 10)
FONT_B = ("Segoe UI Semibold", 10)
FONT_TITLE = ("Segoe UI Semibold", 11)
FONT_SMALL = ("Segoe UI", 9)
FONT_MONO = ("Cascadia Mono", 9)


def pick_fonts(root: tk.Tk) -> None:
    global FONT, FONT_B, FONT_TITLE, FONT_SMALL, FONT_MONO
    if IS_WINDOWS:
        return
    have = set(tkfont.families(root))
    ui = next((f for f in ("Ubuntu", "Cantarell", "Noto Sans", "DejaVu Sans") if f in have), "TkDefaultFont")
    mono = next((f for f in ("Ubuntu Mono", "DejaVu Sans Mono", "Noto Mono") if f in have), "TkFixedFont")
    FONT, FONT_B = (ui, 10), (ui, 10, "bold")
    FONT_TITLE, FONT_SMALL, FONT_MONO = (ui, 11, "bold"), (ui, 9), (mono, 9)


def apply_dark_theme(root: tk.Tk) -> None:
    pick_fonts(root)
    root.configure(bg=BG)
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=BG, foreground=FG, fieldbackground=FIELD, bordercolor=BORDER,
                lightcolor=BORDER, darkcolor=BORDER, troughcolor=CARD, focuscolor=ACCENT,
                selectbackground=ACCENT, selectforeground="#ffffff", insertcolor=FG, font=FONT)
    s.configure("Card.TFrame", background=CARD)
    s.configure("Card.TLabel", background=CARD, foreground=FG)
    s.configure("Muted.TLabel", background=CARD, foreground=MUTED)
    s.configure("Title.TLabel", background=CARD, foreground=FG, font=FONT_TITLE)
    s.configure("Status.TLabel", background=BG, foreground=MUTED)
    s.configure("TEntry", fieldbackground=FIELD, foreground=FG, padding=6, insertcolor=FG)
    s.map("TEntry", bordercolor=[("focus", ACCENT)], lightcolor=[("focus", ACCENT)],
          fieldbackground=[("disabled", CARD)], foreground=[("disabled", MUTED)])
    s.configure("TCombobox", fieldbackground=FIELD, background=FIELD, foreground=FG,
                arrowcolor=FG, padding=5)
    s.map("TCombobox", fieldbackground=[("readonly", FIELD), ("disabled", CARD)],
          foreground=[("readonly", FG), ("disabled", MUTED)], selectbackground=[("readonly", FIELD)],
          selectforeground=[("readonly", FG)], bordercolor=[("focus", ACCENT)],
          arrowcolor=[("disabled", MUTED)])
    root.option_add("*TCombobox*Listbox.background", FIELD)
    root.option_add("*TCombobox*Listbox.foreground", FG)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
    root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
    root.option_add("*TCombobox*Listbox.font", FONT)
    s.configure("TButton", background=FIELD, foreground=FG, borderwidth=0, padding=(12, 6))
    s.map("TButton", background=[("disabled", CARD), ("pressed", BORDER), ("active", "#353845")],
          foreground=[("disabled", MUTED)])
    s.configure("Accent.TButton", background=ACCENT, foreground="#ffffff", font=FONT_B, padding=(18, 8))
    s.map("Accent.TButton", background=[("pressed", ACCENT), ("active", ACCENT_HI)])
    s.configure("Stop.TButton", background=STOP, foreground="#ffffff", font=FONT_B, padding=(18, 8))
    s.map("Stop.TButton", background=[("pressed", STOP), ("active", STOP_HI)])
    s.configure("TCheckbutton", background=CARD, foreground=FG, indicatorbackground=FIELD,
                indicatorforeground="#ffffff", focuscolor=CARD)
    s.map("TCheckbutton", background=[("active", CARD)],
          indicatorbackground=[("selected", ACCENT), ("active", BORDER)])
    s.configure("Vertical.TScrollbar", background=FIELD, troughcolor=CARD, arrowcolor=MUTED,
                bordercolor=CARD, lightcolor=FIELD, darkcolor=FIELD)
    s.map("Vertical.TScrollbar", background=[("active", BORDER)])


class App(tk.Tk):
    def __init__(self, backend):
        super().__init__()
        self.backend = backend
        self.title(APP_NAME)
        self.geometry("720x740")
        self.minsize(600, 560)
        apply_dark_theme(self)
        self.cfg = Config.load()
        self.engine = None  # backend.Engine while running
        self.logq: queue.Queue[str] = queue.Queue()

        root = ttk.Frame(self, padding=14)
        root.pack(fill="both", expand=True)

        # ---- proxy card ---------------------------------------------------- #
        p = self.cfg.proxy
        self.v_type = tk.StringVar(value=p.proxy_type)
        self.v_host = tk.StringVar(value=p.host)
        self.v_port = tk.StringVar(value=str(p.port))
        self.v_user = tk.StringVar(value=p.username)
        self.v_pass = tk.StringVar(value=p.password)

        card = self._card(root, "Proxy server")
        g = ttk.Frame(card, style="Card.TFrame")
        g.pack(fill="x")
        g.columnconfigure(1, weight=1)
        ttk.Label(g, text="Type", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(g, text="Address", style="Muted.TLabel").grid(row=0, column=1, sticky="w", padx=8)
        ttk.Label(g, text="Port", style="Muted.TLabel").grid(row=0, column=2, sticky="w")
        self.proxy_inputs = [
            ttk.Combobox(g, textvariable=self.v_type, values=PROXY_TYPES, state="readonly", width=9),
            ttk.Entry(g, textvariable=self.v_host),
            ttk.Entry(g, textvariable=self.v_port, width=8),
        ]
        self.proxy_inputs[0].grid(row=1, column=0, sticky="we", pady=(2, 8))
        self.proxy_inputs[1].grid(row=1, column=1, sticky="we", padx=8, pady=(2, 8))
        self.proxy_inputs[2].grid(row=1, column=2, sticky="we", pady=(2, 8))

        g2 = ttk.Frame(card, style="Card.TFrame")
        g2.pack(fill="x")
        g2.columnconfigure(0, weight=1)
        g2.columnconfigure(1, weight=1)
        ttk.Label(g2, text="Username (optional)", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(g2, text="Password", style="Muted.TLabel").grid(row=0, column=1, sticky="w", padx=8)
        user_e = ttk.Entry(g2, textvariable=self.v_user)
        pass_e = ttk.Entry(g2, textvariable=self.v_pass, show="•")
        user_e.grid(row=1, column=0, sticky="we", pady=(2, 0))
        pass_e.grid(row=1, column=1, sticky="we", padx=8, pady=(2, 0))
        self.test_btn = ttk.Button(g2, text="Test", command=self.test_proxy)
        self.test_btn.grid(row=1, column=2, sticky="e", pady=(2, 0))
        self.proxy_inputs += [user_e, pass_e]
        self.test_lbl = ttk.Label(card, text="", style="Muted.TLabel", wraplength=640)
        self.test_lbl.pack(anchor="w", pady=(6, 0))

        # ---- apps card ----------------------------------------------------- #
        card = self._card(root, "Applications to proxy", expand=True)
        body = ttk.Frame(card, style="Card.TFrame")
        body.pack(fill="both", expand=True)
        lf = tk.Frame(body, bg=BORDER, padx=1, pady=1)
        lf.pack(side="left", fill="both", expand=True)
        self.app_list = tk.Listbox(lf, bg=FIELD, fg=FG, selectbackground=ACCENT,
                                   selectforeground="#ffffff", highlightthickness=0, bd=0,
                                   activestyle="none", font=FONT, selectmode="extended", height=6)
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.app_list.yview)
        self.app_list.configure(yscrollcommand=sb.set)
        self.app_list.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=4)
        sb.pack(side="right", fill="y")
        self.app_list.bind("<Delete>", lambda e: self.remove_apps())
        side = ttk.Frame(body, style="Card.TFrame")
        side.pack(side="left", fill="y", padx=(10, 0))
        ttk.Button(side, text="Add app…", command=self.add_apps).pack(fill="x")
        ttk.Button(side, text="Remove", command=self.remove_apps).pack(fill="x", pady=6)
        self.launch_btn = None
        if hasattr(backend, "launch"):  # Linux: start an app already inside the proxy
            self.launch_btn = ttk.Button(side, text="Launch", command=self.launch_apps)
            self.launch_btn.pack(fill="x")
            self.launch_btn.state(["disabled"])

        self.v_udp = tk.BooleanVar(value=self.cfg.block_udp)
        self.v_v6 = tk.BooleanVar(value=self.cfg.block_ipv6)
        opts = ttk.Frame(card, style="Card.TFrame")
        opts.pack(fill="x", pady=(10, 0))
        self.opt_checks = [
            ttk.Checkbutton(opts, text="Block UDP / QUIC (prevents leaks)", variable=self.v_udp),
            ttk.Checkbutton(opts, text="Block IPv6 (forces IPv4 via proxy)", variable=self.v_v6),
        ]
        self.opt_checks[0].pack(side="left")
        self.opt_checks[1].pack(side="left", padx=(16, 0))

        self.v_dns = tk.BooleanVar(value=self.cfg.dns_over_proxy)
        self.v_dns_server = tk.StringVar(value=self.cfg.dns_server)
        dns = ttk.Frame(card, style="Card.TFrame")
        dns.pack(fill="x", pady=(8, 0))
        dns_check = ttk.Checkbutton(dns, text=f"Resolve DNS through proxy ({backend.DNS_SCOPE}) using",
                                    variable=self.v_dns)
        dns_check.pack(side="left")
        self.dns_combo = ttk.Combobox(dns, textvariable=self.v_dns_server, values=list(DOH_SERVERS),
                                      state="readonly", width=11)
        self.dns_combo.pack(side="left", padx=(6, 0))
        self.opt_checks.append(dns_check)

        self.v_kill = tk.BooleanVar(value=self.cfg.kill_switch)
        kill_check = ttk.Checkbutton(card, variable=self.v_kill, command=self.kill_switch_changed,
                                     text="Kill switch — no direct internet for these apps if the proxy "
                                          "is down or ProxyLatch is stopped")
        kill_check.pack(anchor="w", pady=(8, 0))
        self.opt_checks.append(kill_check)

        # ---- start / status ------------------------------------------------ #
        ctl = ttk.Frame(root)
        ctl.pack(fill="x", pady=(2, 10))
        self.start_btn = ttk.Button(ctl, text="▶   Start", style="Accent.TButton", command=self.toggle_engine)
        self.start_btn.pack(side="left")
        self.dot = tk.Canvas(ctl, width=12, height=12, bg=BG, highlightthickness=0)
        self.dot.pack(side="left", padx=(16, 6))
        self.dot_id = self.dot.create_oval(1, 1, 11, 11, fill=MUTED, outline="")
        self.status = ttk.Label(ctl, text="Stopped", style="Status.TLabel")
        self.status.pack(side="left")

        # ---- log ----------------------------------------------------------- #
        card = self._card(root, "Activity", expand=True)
        head = card.winfo_children()[0]
        clr = tk.Label(head, text="Clear", bg=CARD, fg=MUTED, cursor="hand2", font=FONT_SMALL)
        clr.pack(side="right")
        clr.bind("<Button-1>", lambda e: self._clear_log())
        lf = tk.Frame(card, bg=BORDER, padx=1, pady=1)
        lf.pack(fill="both", expand=True)
        self.logbox = tk.Text(lf, bg="#121317", fg="#c9ccd6", insertbackground=FG, bd=0,
                              highlightthickness=0, font=FONT_MONO, wrap="none",
                              height=8, padx=8, pady=6, state="disabled")
        lsb = ttk.Scrollbar(lf, orient="vertical", command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=lsb.set)
        self.logbox.pack(side="left", fill="both", expand=True)
        lsb.pack(side="right", fill="y")
        self.logbox.tag_configure("time", foreground="#5d6170")
        self.logbox.tag_configure("err", foreground=RED)
        self.logbox.tag_configure("ok", foreground=GREEN)

        self.refresh_apps()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.protocol("WM_SAVE_YOURSELF", self.on_close)  # Windows shutdown / sign-out
        self.after(100, self.pump_log)
        self.after(1000, self.update_status)
        self.after(10, lambda: backend.style_window(self))
        backend.on_startup(self.cfg, self.log)

    def _card(self, parent, title: str, expand: bool = False) -> ttk.Frame:
        card = ttk.Frame(parent, style="Card.TFrame", padding=14)
        card.pack(fill="both" if expand else "x", expand=expand, pady=(0, 12))
        head = ttk.Frame(card, style="Card.TFrame")
        head.pack(fill="x", pady=(0, 8))
        ttk.Label(head, text=title, style="Title.TLabel").pack(side="left")
        return card

    # ---- apps ------------------------------------------------------------ #

    def refresh_apps(self):
        self.app_list.delete(0, "end")
        for a in self.cfg.apps:
            self.app_list.insert("end", f"  {os.path.basename(a)}    —    {a}" if os.sep in a else f"  {a}")
        if not self.cfg.apps:
            self.app_list.insert("end", "  No apps yet — click “Add app…”")
            self.app_list.itemconfig(0, fg=MUTED)

    def add_apps(self):
        paths = filedialog.askopenfilenames(parent=self, title="Select applications",
                                            **self.backend.APP_DIALOG)
        new = [os.path.normpath(p) for p in paths
               if os.path.normcase(os.path.normpath(p)) not in map(os.path.normcase, self.cfg.apps)]
        if new:
            self.cfg.apps += new
            self.apps_changed()

    def remove_apps(self):
        if not self.cfg.apps:
            return
        for i in sorted(self.app_list.curselection(), reverse=True):
            del self.cfg.apps[i]
        self.apps_changed()

    def launch_apps(self):
        if not self.engine or not self.cfg.apps:
            return
        picked = self.app_list.curselection()
        if not picked:
            messagebox.showinfo(APP_NAME, "Select the app(s) to launch in the list.")
            return
        for i in picked:
            try:
                self.backend.launch(self.cfg.apps[i])
            except Exception as e:
                self.log(f"[error] Launch {os.path.basename(self.cfg.apps[i])}: {e}")

    def apps_changed(self):
        self.cfg.save()
        self.refresh_apps()
        if self.engine:
            restart = bool(self.cfg.apps)
            self.stop_engine(restarting=restart)
            if restart:
                self.start_engine()
        else:
            self.arm_kill_switch()

    # ---- kill switch ----------------------------------------------------- #

    def kill_switch_changed(self):
        self.cfg.kill_switch = self.v_kill.get()
        self.cfg.save()
        self.arm_kill_switch()

    def arm_kill_switch(self):
        """Apply a settings change made while stopped (the engine handles Start/Stop)."""
        try:
            self.backend.arm_kill_switch(self.cfg, self.log)
        except Exception as e:
            self.log(f"[error] Kill switch: {e}")

    # ---- proxy ----------------------------------------------------------- #

    def read_proxy(self) -> Proxy | None:
        host = self.v_host.get().strip()
        try:
            port = int(self.v_port.get())
            assert 0 < port < 65536
        except Exception:
            messagebox.showerror(APP_NAME, "Port must be a number 1-65535.")
            return None
        if not host:
            messagebox.showerror(APP_NAME, "Enter the proxy address.")
            return None
        return Proxy(self.v_type.get(), host, port, self.v_user.get(), self.v_pass.get())

    def test_proxy(self):
        proxy = self.read_proxy()
        if not proxy:
            return
        self.test_lbl.config(text="Testing…", foreground=MUTED)
        self.test_btn.state(["disabled"])
        doh_host = DOH_SERVERS[self.v_dns_server.get()] if self.v_dns.get() else None

        def run():
            try:
                msg, color = "✓  " + asyncio.run(test_proxy(proxy, doh_host)), GREEN
            except Exception as e:
                msg, color = f"✗  {e or type(e).__name__}", RED

            def done():
                self.test_lbl.config(text=msg, foreground=color)
                self.test_btn.state(["!disabled"])
            self.after(0, done)
        threading.Thread(target=run, daemon=True).start()

    # ---- engine ---------------------------------------------------------- #

    def toggle_engine(self):
        if self.engine:
            self.stop_engine()
            return
        proxy = self.read_proxy()
        if not proxy:
            return
        if not self.cfg.apps:
            messagebox.showinfo(APP_NAME, "Add at least one application first.")
            return
        self.cfg.proxy = proxy
        self.cfg.block_udp = self.v_udp.get()
        self.cfg.block_ipv6 = self.v_v6.get()
        self.cfg.dns_over_proxy = self.v_dns.get()
        self.cfg.dns_server = self.v_dns_server.get()
        self.cfg.kill_switch = self.v_kill.get()
        self.cfg.save()
        self.start_engine()

    def start_engine(self):
        eng = self.backend.Engine(self.cfg, self.log)
        try:
            eng.start()  # on failure it restores the stopped state itself
        except Exception as e:
            self.log(f"[error] {e}")
            messagebox.showerror(APP_NAME, f"Could not start:\n{e}")
            return
        self.engine = eng
        self.start_btn.config(text="■   Stop", style="Stop.TButton")
        for w in self.proxy_inputs + self.opt_checks + [self.dns_combo]:
            w.state(["disabled"])
        if self.launch_btn:
            self.launch_btn.state(["!disabled"])

    def stop_engine(self, restarting: bool = False):
        if self.engine:
            self.engine.stop(restarting)
            self.engine = None
        self.start_btn.config(text="▶   Start", style="Accent.TButton")
        if self.launch_btn:
            self.launch_btn.state(["disabled"])
        for w in (self.proxy_inputs[0], self.dns_combo):
            w.state(["!disabled", "readonly"])
        for w in self.proxy_inputs[1:] + self.opt_checks:
            w.state(["!disabled"])

    def update_status(self):
        if self.engine and not self.engine.proxy_up:
            self.status.config(text=f"Proxy unreachable  ·  {self.engine.proxy_label}" +
                                    ("  ·  traffic blocked" if self.engine.kill_switch else ""),
                               foreground=RED)
            self.dot.itemconfig(self.dot_id, fill=RED)
        elif self.engine:
            self.status.config(text=f"Running  ·  {self.engine.active_conns} active  ·  "
                                    f"{self.engine.total_conns} total  ·  {self.engine.proxy_label}",
                               foreground=FG)
            self.dot.itemconfig(self.dot_id, fill=GREEN)
        else:
            self.status.config(text="Stopped", foreground=MUTED)
            self.dot.itemconfig(self.dot_id, fill=MUTED)
        self.after(1000, self.update_status)

    # ---- log ------------------------------------------------------------- #

    def log(self, msg: str):
        self.logq.put(msg)

    def _clear_log(self):
        self.logbox.config(state="normal")
        self.logbox.delete("1.0", "end")
        self.logbox.config(state="disabled")

    def pump_log(self):
        lines = []
        try:
            while len(lines) < 500:
                lines.append(self.logq.get_nowait())
        except queue.Empty:
            pass
        if lines:
            ts = time.strftime("%H:%M:%S")
            self.logbox.config(state="normal")
            for line in lines:
                tag = "err" if line.startswith(("[fail]", "[error]", "[warn]", "[packet")) else \
                      "ok" if line.startswith(("Started", "Proxy is reachable")) else ()
                self.logbox.insert("end", ts + "  ", "time")
                self.logbox.insert("end", line + "\n", tag)
            if int(self.logbox.index("end-1c").split(".")[0]) > 3000:
                self.logbox.delete("1.0", "1000.0")
            self.logbox.see("end")
            self.logbox.config(state="disabled")
        self.after(100, self.pump_log)

    def on_close(self):
        self.stop_engine()
        self.backend.shutdown()
        self.destroy()
