"""
MyoVIF — Universal ONVIF Camera Tool
=====================================
Desktop GUI for testing ONVIF/RTSP/RTSPS authentication,
device discovery, and video streaming.

Usage:
    python myovif.py
"""

import threading
import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont
from datetime import datetime

from core.engine import ONVIFClient, RTSPClient, discover_devices
from core.vlc_manager import launch_stream, find_player, RTSPProxy
from core.presets import PresetManager, CameraPreset


# ────────────────────────────────────────────────────────────
# Theme
# ────────────────────────────────────────────────────────────
COLORS = {
    "bg":          "#1e1e2e",
    "bg_card":     "#2a2a3d",
    "bg_input":    "#363650",
    "fg":          "#e0e0e0",
    "fg_dim":      "#8888aa",
    "accent":      "#7aa2f7",
    "success":     "#9ece6a",
    "error":       "#f7768e",
    "warning":     "#e0af68",
    "info":        "#7dcfff",
    "border":      "#444466",
    "btn_bg":      "#3d3d5c",
    "btn_hover":   "#4d4d6c",
    "btn_accent":  "#5a6fad",
}


class MyoVIF(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("MyoVIF — Universal ONVIF Camera Tool")
        self.geometry("920x720")
        self.minsize(800, 600)
        self.configure(bg=COLORS["bg"])

        # Icon (optional)
        try:
            self.iconbitmap(default="")
        except Exception:
            pass

        self.preset_mgr = PresetManager()
        self.vlc_proc = None
        self.proxy_obj = None

        self._build_fonts()
        self._build_styles()
        self._build_ui()
        self._load_presets_dropdown()

    # ──── Fonts ────
    def _build_fonts(self):
        self.font_title = tkfont.Font(family="Segoe UI", size=14, weight="bold")
        self.font_heading = tkfont.Font(family="Segoe UI", size=10, weight="bold")
        self.font_normal = tkfont.Font(family="Segoe UI", size=9)
        self.font_mono = tkfont.Font(family="Consolas", size=9)
        self.font_btn = tkfont.Font(family="Segoe UI", size=9, weight="bold")

    # ──── ttk Styles ────
    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", background=COLORS["bg"], foreground=COLORS["fg"],
                         font=self.font_normal)
        style.configure("Card.TFrame", background=COLORS["bg_card"])
        style.configure("Card.TLabelframe", background=COLORS["bg_card"],
                         foreground=COLORS["accent"])
        style.configure("Card.TLabelframe.Label", background=COLORS["bg_card"],
                         foreground=COLORS["accent"], font=self.font_heading)
        style.configure("TLabel", background=COLORS["bg_card"],
                         foreground=COLORS["fg"])
        style.configure("TEntry", fieldbackground=COLORS["bg_input"],
                         foreground=COLORS["fg"], insertcolor=COLORS["fg"])
        style.configure("TCombobox", fieldbackground=COLORS["bg_input"],
                         foreground=COLORS["fg"])
        style.configure("TCheckbutton", background=COLORS["bg_card"],
                         foreground=COLORS["fg"])
        style.configure("TRadiobutton", background=COLORS["bg_card"],
                         foreground=COLORS["fg"])
        style.configure("Action.TButton", background=COLORS["btn_accent"],
                         foreground="#ffffff", font=self.font_btn, padding=(12, 6))
        style.map("Action.TButton",
                   background=[("active", COLORS["accent"])])
        style.configure("TButton", background=COLORS["btn_bg"],
                         foreground=COLORS["fg"], font=self.font_btn, padding=(8, 4))
        style.map("TButton",
                   background=[("active", COLORS["btn_hover"])])

    # ──── Build UI ────
    def _build_ui(self):
        # Title bar
        title_frame = tk.Frame(self, bg=COLORS["bg"])
        title_frame.pack(fill="x", padx=12, pady=(10, 4))
        tk.Label(title_frame, text="🎥 MyoVIF", font=self.font_title,
                 bg=COLORS["bg"], fg=COLORS["accent"]).pack(side="left")
        tk.Label(title_frame, text="Universal ONVIF Camera Tool",
                 font=self.font_normal, bg=COLORS["bg"],
                 fg=COLORS["fg_dim"]).pack(side="left", padx=(8, 0))

        # Main container (scrollable)
        main = tk.Frame(self, bg=COLORS["bg"])
        main.pack(fill="both", expand=True, padx=12, pady=4)

        # ── Connection Card ──
        conn_frame = ttk.LabelFrame(main, text="  Connection  ",
                                     style="Card.TLabelframe")
        conn_frame.pack(fill="x", pady=(0, 6))
        conn_inner = tk.Frame(conn_frame, bg=COLORS["bg_card"])
        conn_inner.pack(fill="x", padx=10, pady=8)

        # Row 1: Host, ONVIF Port, RTSP Port
        r1 = tk.Frame(conn_inner, bg=COLORS["bg_card"])
        r1.pack(fill="x", pady=2)

        self._label(r1, "Host:").pack(side="left")
        self.var_host = tk.StringVar(value="192.168.1.1")
        self._entry(r1, self.var_host, width=18).pack(side="left", padx=(4, 12))

        self._label(r1, "ONVIF Port:").pack(side="left")
        self.var_onvif_port = tk.StringVar(value="80")
        self._entry(r1, self.var_onvif_port, width=6).pack(side="left", padx=(4, 12))

        self._label(r1, "RTSP Port:").pack(side="left")
        self.var_rtsp_port = tk.StringVar(value="554")
        self._entry(r1, self.var_rtsp_port, width=6).pack(side="left", padx=(4, 0))

        # Row 2: User, Pass, Preset
        r2 = tk.Frame(conn_inner, bg=COLORS["bg_card"])
        r2.pack(fill="x", pady=2)

        self._label(r2, "Username:").pack(side="left")
        self.var_user = tk.StringVar(value="admin")
        self._entry(r2, self.var_user, width=14).pack(side="left", padx=(4, 12))

        self._label(r2, "Password:").pack(side="left")
        self.var_pass = tk.StringVar()
        self._entry(r2, self.var_pass, width=14, show="•").pack(side="left", padx=(4, 12))

        self._label(r2, "Preset:").pack(side="left")
        self.var_preset = tk.StringVar()
        self.combo_preset = ttk.Combobox(r2, textvariable=self.var_preset,
                                          width=16, state="readonly")
        self.combo_preset.pack(side="left", padx=(4, 4))
        self.combo_preset.bind("<<ComboboxSelected>>", self._on_preset_selected)

        ttk.Button(r2, text="Save", command=self._save_preset).pack(side="left", padx=2)
        ttk.Button(r2, text="Del", command=self._delete_preset).pack(side="left", padx=2)

# ── Options Card ──
        opts_frame = ttk.LabelFrame(main, text="  Options  ",
                                     style="Card.TLabelframe")
        opts_frame.pack(fill="x", pady=(0, 6))
        opts_inner = tk.Frame(opts_frame, bg=COLORS["bg_card"])
        opts_inner.pack(fill="x", padx=10, pady=8)

        # Row 3: Protocol, RTSP Path
        r3 = tk.Frame(opts_inner, bg=COLORS["bg_card"])
        r3.pack(fill="x", pady=2)

        self._label(r3, "Protocol:").pack(side="left")
        self.var_protocol = tk.StringVar(value="rtsp")
        ttk.Radiobutton(r3, text="RTSP", variable=self.var_protocol,
                         value="rtsp").pack(side="left", padx=(4, 8))
        ttk.Radiobutton(r3, text="RTSPS", variable=self.var_protocol,
                         value="rtsps").pack(side="left", padx=(0, 16))

        self._label(r3, "RTSP Path:").pack(side="left")
        self.var_rtsp_path = tk.StringVar(value="/stream1")
        self._entry(r3, self.var_rtsp_path, width=24).pack(side="left", padx=(4, 0))

        # Row 4: Auth Mode
        r4 = tk.Frame(opts_inner, bg=COLORS["bg_card"])
        r4.pack(fill="x", pady=2)

        self._label(r4, "Auth:").pack(side="left")
        self.var_auth_mode = tk.StringVar(value="standard")
        self.var_auth_mode.trace_add("write", self._on_auth_mode_changed)
        ttk.Radiobutton(r4, text="Standard (natural)",
                         variable=self.var_auth_mode,
                         value="standard").pack(side="left", padx=(4, 8))
        ttk.Radiobutton(r4, text="Custom Digest",
                         variable=self.var_auth_mode,
                         value="custom").pack(side="left", padx=(0, 0))

        self.var_ws_auth = tk.BooleanVar(value=False)
        ttk.Checkbutton(r4, text="WS-Security",
                         variable=self.var_ws_auth).pack(side="left", padx=(10, 0))

        # Custom Digest sub-frame (hidden by default)
        self.custom_frame = tk.Frame(opts_inner, bg=COLORS["bg_card"])

        r5 = tk.Frame(self.custom_frame, bg=COLORS["bg_card"])
        r5.pack(fill="x", pady=2)

        self._label(r5, "Algorithm:").pack(side="left", padx=(20, 0))
        self.var_algo = tk.StringVar(value="Auto-detect")
        algo_combo = ttk.Combobox(r5, textvariable=self.var_algo, width=14,
                                   state="readonly",
                                   values=["Auto-detect", "MD5", "SHA-256", "SHA-512-256"])
        algo_combo.pack(side="left", padx=(4, 12))

        self.var_quote = tk.BooleanVar(value=False)
        ttk.Checkbutton(r5, text="Quote Algorithm",
                         variable=self.var_quote).pack(side="left")

        # Row 6: VLC Fixes (No HW & Tunnel)
        r6 = tk.Frame(opts_inner, bg=COLORS["bg_card"])
        r6.pack(fill="x", pady=(6, 2))

        self._label(r6, "VLC Fixes:").pack(side="left")
        
        self.var_proxy = tk.BooleanVar(value=False)
        ttk.Checkbutton(r6, text="Use Local Proxy (Fix SHA-256)", 
                         variable=self.var_proxy).pack(side="left")
                         
        self.var_tunnel = tk.BooleanVar(value=False)
        ttk.Checkbutton(r6, text="HTTP Tunnel (Port 2020)", 
                         variable=self.var_tunnel).pack(side="left")

        self.var_absolute_uri = tk.BooleanVar(value=True)
        ttk.Checkbutton(r6, text="Absolute URI", 
                         variable=self.var_absolute_uri).pack(side="left", padx=(10, 0))

        # ── Action Buttons ──
        btn_frame = tk.Frame(main, bg=COLORS["bg"])
        btn_frame.pack(fill="x", pady=(0, 6))

        ttk.Button(btn_frame, text="🔍 Discover", style="Action.TButton",
                    command=self._cmd_discover).pack(side="left", padx=(0, 6))
        ttk.Button(btn_frame, text="📋 Device Info", style="Action.TButton",
                    command=self._cmd_device_info).pack(side="left", padx=(0, 6))
        ttk.Button(btn_frame, text="🔐 Test Auth", style="Action.TButton",
                    command=self._cmd_test_auth).pack(side="left", padx=(0, 6))
        ttk.Button(btn_frame, text="▶ Stream", style="Action.TButton",
                    command=self._cmd_stream).pack(side="left", padx=(0, 6))
        ttk.Button(btn_frame, text="Clear Log",
                    command=self._clear_log).pack(side="right")

        # ── Output Log ──
        log_frame = ttk.LabelFrame(main, text="  Output Log  ",
                                    style="Card.TLabelframe")
        log_frame.pack(fill="both", expand=True, pady=(0, 6))

        self.log_text = tk.Text(log_frame, bg=COLORS["bg_input"], fg=COLORS["fg"],
                                 font=self.font_mono, wrap="word",
                                 insertbackground=COLORS["fg"],
                                 selectbackground=COLORS["accent"],
                                 relief="flat", padx=8, pady=6,
                                 state="disabled")
        log_scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        log_scroll.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)

        # Configure log tags
        self.log_text.tag_configure("success", foreground=COLORS["success"])
        self.log_text.tag_configure("error", foreground=COLORS["error"])
        self.log_text.tag_configure("warning", foreground=COLORS["warning"])
        self.log_text.tag_configure("info", foreground=COLORS["info"])
        self.log_text.tag_configure("timestamp", foreground=COLORS["fg_dim"])

        # ── Discovered Devices ──
        disc_frame = ttk.LabelFrame(main, text="  Discovered Devices  ",
                                     style="Card.TLabelframe")
        disc_frame.pack(fill="x", pady=(0, 6))

        cols = ("ip", "port", "model", "xaddrs")
        self.device_tree = ttk.Treeview(disc_frame, columns=cols,
                                         show="headings", height=4)
        self.device_tree.heading("ip", text="IP Address")
        self.device_tree.heading("port", text="Port")
        self.device_tree.heading("model", text="Model")
        self.device_tree.heading("xaddrs", text="Service URL")
        self.device_tree.column("ip", width=130)
        self.device_tree.column("port", width=60)
        self.device_tree.column("model", width=140)
        self.device_tree.column("xaddrs", width=300)
        self.device_tree.pack(fill="x", padx=4, pady=(4, 2))

        tree_btn_frame = tk.Frame(disc_frame, bg=COLORS["bg_card"])
        tree_btn_frame.pack(fill="x", padx=4, pady=(0, 4))
        ttk.Button(tree_btn_frame, text="Connect Selected",
                    command=self._connect_selected).pack(side="left")

        # Style the treeview
        style = ttk.Style()
        style.configure("Treeview",
                         background=COLORS["bg_input"],
                         foreground=COLORS["fg"],
                         fieldbackground=COLORS["bg_input"],
                         font=self.font_normal)
        style.configure("Treeview.Heading",
                         background=COLORS["btn_bg"],
                         foreground=COLORS["fg"],
                         font=self.font_heading)
        style.map("Treeview", background=[("selected", COLORS["btn_accent"])])

        # Initial log
        self.log("MyoVIF started. Ready.", "info")
        player_path, player_name = find_player()
        if player_path:
            self.log(f"Found player: {player_name.upper()} at {player_path}", "info")
        else:
            self.log("No media player found (VLC/ffplay)", "warning")

    # ──── Widget helpers ────
    def _label(self, parent, text):
        return tk.Label(parent, text=text, font=self.font_normal,
                        bg=COLORS["bg_card"], fg=COLORS["fg"])

    def _entry(self, parent, var, width=20, show=None):
        e = tk.Entry(parent, textvariable=var, width=width, font=self.font_normal,
                     bg=COLORS["bg_input"], fg=COLORS["fg"],
                     insertbackground=COLORS["fg"], relief="flat",
                     highlightthickness=1, highlightcolor=COLORS["accent"],
                     highlightbackground=COLORS["border"])
        if show:
            e.configure(show=show)
        return e

    # ──── Logging ────
    def log(self, message, level="info"):
        """Thread-safe log to output text widget."""
        def _insert():
            self.log_text.configure(state="normal")
            ts = datetime.now().strftime("%H:%M:%S")
            self.log_text.insert("end", f"[{ts}] ", "timestamp")

            tag = level if level in ("success", "error", "warning", "info") else "info"
            prefix = {"success": "✓ ", "error": "✗ ", "warning": "⚠ ", "info": ""}.get(tag, "")
            self.log_text.insert("end", f"{prefix}{message}\n", tag)
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        if threading.current_thread() is threading.main_thread():
            _insert()
        else:
            self.after(0, _insert)

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    # ──── Auth mode toggle ────
    def _on_auth_mode_changed(self, *_):
        if self.var_auth_mode.get() == "custom":
            self.custom_frame.pack(fill="x", pady=2)
        else:
            self.custom_frame.pack_forget()

    # ──── Presets ────
    def _load_presets_dropdown(self):
        names = [p.name for p in self.preset_mgr.list_presets()]
        self.combo_preset["values"] = ["-- None --"] + names
        self.combo_preset.set("-- None --")

    def _on_preset_selected(self, _event=None):
        name = self.var_preset.get()
        if name == "-- None --":
            return
        p = self.preset_mgr.get(name)
        if not p:
            return
        self.var_host.set(p.host)
        self.var_onvif_port.set(str(p.onvif_port))
        self.var_rtsp_port.set(str(p.rtsp_port))
        self.var_rtsp_path.set(p.rtsp_path)
        self.var_user.set(p.username)
        self.var_pass.set(p.password)
        self.var_auth_mode.set(p.auth_mode)
        self.var_protocol.set(p.protocol)
        self.var_ws_auth.set(p.use_ws_auth)
        self.var_absolute_uri.set(p.absolute_uri)
        if p.auth_mode == "custom":
            algo_display = "Auto-detect" if p.algorithm == "auto" else p.algorithm
            self.var_algo.set(algo_display)
            self.var_quote.set(p.quote_algo)
        self.log(f"Loaded preset: {name}", "info")

    def _save_preset(self):
        name = self.var_preset.get()
        if not name or name == "-- None --":
            name = f"{self.var_host.get()}"

        # Ask for name
        dialog = tk.Toplevel(self)
        dialog.title("Save Preset")
        dialog.geometry("300x100")
        dialog.configure(bg=COLORS["bg_card"])
        dialog.transient(self)
        dialog.grab_set()

        tk.Label(dialog, text="Preset Name:", bg=COLORS["bg_card"],
                 fg=COLORS["fg"]).pack(pady=(10, 4))
        name_var = tk.StringVar(value=name)
        name_entry = tk.Entry(dialog, textvariable=name_var, width=30,
                              bg=COLORS["bg_input"], fg=COLORS["fg"],
                              insertbackground=COLORS["fg"], relief="flat")
        name_entry.pack(pady=4)
        name_entry.focus_set()

        def do_save():
            n = name_var.get().strip()
            if not n:
                return
            algo_val = self.var_algo.get()
            algo = "auto" if algo_val == "Auto-detect" else algo_val
            preset = CameraPreset(
                name=n,
                host=self.var_host.get(),
                onvif_port=int(self.var_onvif_port.get() or 80),
                rtsp_port=int(self.var_rtsp_port.get() or 554),
                rtsp_path=self.var_rtsp_path.get(),
                username=self.var_user.get(),
                password=self.var_pass.get(),
                auth_mode=self.var_auth_mode.get(),
                algorithm=algo,
                quote_algo=self.var_quote.get(),
                protocol=self.var_protocol.get(),
                use_ws_auth=self.var_ws_auth.get(),
                absolute_uri=self.var_absolute_uri.get(),
            )
            self.preset_mgr.add(preset)
            self._load_presets_dropdown()
            self.combo_preset.set(n)
            self.log(f"Preset saved: {n}", "success")
            dialog.destroy()

        ttk.Button(dialog, text="Save", command=do_save).pack(pady=4)
        dialog.bind("<Return>", lambda e: do_save())

    def _delete_preset(self):
        name = self.var_preset.get()
        if not name or name == "-- None --":
            return
        self.preset_mgr.delete(name)
        self._load_presets_dropdown()
        self.log(f"Preset deleted: {name}", "warning")

    # ──── Get current config ────
    def _get_config(self):
        algo_val = self.var_algo.get()
        return {
            "host": self.var_host.get().strip(),
            "onvif_port": int(self.var_onvif_port.get() or 80),
            "rtsp_port": int(self.var_rtsp_port.get() or 554),
            "rtsp_path": self.var_rtsp_path.get().strip(),
            "username": self.var_user.get().strip(),
            "password": self.var_pass.get(),
            "auth_mode": self.var_auth_mode.get(),
            "algorithm": "auto" if algo_val == "Auto-detect" else algo_val,
            "quote_algo": self.var_quote.get(),
            "protocol": self.var_protocol.get(),
            "use_ws_auth": self.var_ws_auth.get(),
            "absolute_uri": self.var_absolute_uri.get(),
            "use_proxy": self.var_proxy.get(),
            "tunnel": self.var_tunnel.get(),
        }

    def _get_rtsp_url(self, cfg):
        return f"{cfg['protocol']}://{cfg['host']}:{cfg['rtsp_port']}{cfg['rtsp_path']}"

    # ──── Commands (threaded) ────
    def _run_threaded(self, func):
        threading.Thread(target=func, daemon=True).start()

    def _cmd_discover(self):
        self._run_threaded(self._do_discover)

    def _cmd_device_info(self):
        self._run_threaded(self._do_device_info)

    def _cmd_test_auth(self):
        self._run_threaded(self._do_test_auth)

    def _cmd_stream(self):
        self._run_threaded(self._do_stream)

    # ──── Discover ────
    def _do_discover(self):
        self.log("─" * 50, "info")
        self.log("Starting LAN discovery...", "info")
        devices = discover_devices(timeout=3, log_func=self.log)

        # Update treeview on main thread
        def update_tree():
            for item in self.device_tree.get_children():
                self.device_tree.delete(item)
            for d in devices:
                self.device_tree.insert("", "end", values=(
                    d["ip"], d["port"], d.get("model", ""), d.get("xaddrs", "")
                ))
        self.after(0, update_tree)

    # ──── Connect selected device ────
    def _connect_selected(self):
        sel = self.device_tree.selection()
        if not sel:
            self.log("No device selected", "warning")
            return
        vals = self.device_tree.item(sel[0], "values")
        ip, port = vals[0], vals[1]
        self.var_host.set(ip)
        self.var_onvif_port.set(str(port))
        self.log(f"Connected form to {ip}:{port}", "info")

    # ──── Device Info ────
    def _do_device_info(self):
        cfg = self._get_config()
        self.log("─" * 50, "info")

        client = ONVIFClient(
            host=cfg["host"], port=cfg["onvif_port"],
            username=cfg["username"], password=cfg["password"],
            auth_mode=cfg["auth_mode"], algorithm=cfg["algorithm"],
            quote_algo=cfg["quote_algo"], use_ws_auth=cfg["use_ws_auth"], 
            log_func=self.log
        )

        info = client.get_device_info()
        if not info:
            return

        profiles = client.get_profiles()
        if profiles:
            uri = client.get_stream_uri(profiles[0]["token"])
            if uri:
                # Auto-fill RTSP path from discovered URI
                from urllib.parse import urlparse as _up
                parsed = _up(uri)
                if parsed.path:
                    self.after(0, lambda: self.var_rtsp_path.set(parsed.path))

    # ──── Test Auth ────
    def _do_test_auth(self):
        cfg = self._get_config()
        self.log("─" * 50, "info")
        self.log("Testing authentication...", "info")

        # Test ONVIF (HTTP)
        self.log("═══ ONVIF (HTTP Digest) ═══", "info")
        onvif = ONVIFClient(
            host=cfg["host"], port=cfg["onvif_port"],
            username=cfg["username"], password=cfg["password"],
            auth_mode=cfg["auth_mode"], algorithm=cfg["algorithm"],
            quote_algo=cfg["quote_algo"], use_ws_auth=cfg["use_ws_auth"], 
            log_func=self.log
        )
        onvif.get_device_info()

        # Test RTSP/RTSPS
        rtsp_url = self._get_rtsp_url(cfg)
        proto = "RTSPS" if cfg["protocol"] == "rtsps" else "RTSP"
        self.log(f"═══ {proto} Digest ═══", "info")
        rtsp = RTSPClient(
            url=rtsp_url,
            username=cfg["username"], password=cfg["password"],
            auth_mode=cfg["auth_mode"], algorithm=cfg["algorithm"],
            quote_algo=cfg["quote_algo"], absolute_uri=cfg["absolute_uri"],
            log_func=self.log
        )
        result = rtsp.test_auth()
        self.log("─" * 50, "info")

        status = result.get("status", "UNKNOWN")
        if status == "200":
            self.log(f"AUTH TEST COMPLETE — ALL PASSED", "success")
        else:
            self.log(f"AUTH TEST COMPLETE — RTSP status: {status}", "warning")

    # ──── Stream ────
    def _do_stream(self):
        cfg = self._get_config()
        rtsp_url = self._get_rtsp_url(cfg)
        self.log("─" * 50, "info")
        self.log(f"Launching stream: {rtsp_url}", "info")

        proc = launch_stream(
            rtsp_url, cfg["username"], cfg["password"],
            player="vlc", log_func=self.log,
            use_proxy=cfg["use_proxy"], quote_algo=cfg["quote_algo"], algorithm=cfg["algorithm"],
            absolute_uri=cfg["absolute_uri"], tunnel=cfg["tunnel"]
        )

    # ──── Cleanup ────
    def destroy(self):
        if self.vlc_proc:
            self.vlc_proc.terminate()
        if self.proxy_obj:
            self.proxy_obj.stop()
        super().destroy()


# ────────────────────────────────────────────────────────────
# Entry Point
# ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = MyoVIF()
    app.mainloop()
