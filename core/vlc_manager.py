"""
VLC / ffplay manager — find player, launch stream, RTSP proxy.
"""

import os
import re
import sys
import hashlib
import socket
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, Callable

from .engine import parse_digest_challenge, compute_digest_response, build_digest_header, get_hash_func

SCRIPT_DIR = Path(__file__).parent.parent.resolve()
DEFAULT_VLC_PATH = SCRIPT_DIR / "vlc" / "vlc.exe"

VLC_DEFAULT_ARGS = [
    "--rtsp-tcp",
    "--network-caching", "300",
    "--no-video-title-show",
]


def find_vlc(custom_path=None) -> Optional[Path]:
    """Find VLC executable: custom > portable > system."""
    candidates = []
    if custom_path:
        candidates.append(Path(custom_path))
    candidates.append(DEFAULT_VLC_PATH)
    if sys.platform == "win32":
        for prog in [os.environ.get("ProgramFiles", ""),
                     os.environ.get("ProgramFiles(x86)", "")]:
            if prog:
                candidates.append(Path(prog) / "VideoLAN" / "VLC" / "vlc.exe")
    else:
        candidates.extend([Path("/usr/bin/vlc"), Path("/snap/bin/vlc")])
    for p in candidates:
        if p and p.exists():
            return p
    return None


def find_ffplay(custom_path=None) -> Optional[Path]:
    """Find ffplay executable."""
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p

    # Check PATH
    import shutil
    found = shutil.which("ffplay")
    if found:
        return Path(found)

    # Common locations on Windows
    if sys.platform == "win32":
        for prog in [os.environ.get("ProgramFiles", ""),
                     os.environ.get("ProgramFiles(x86)", ""),
                     str(SCRIPT_DIR)]:
            if prog:
                p = Path(prog) / "ffmpeg" / "bin" / "ffplay.exe"
                if p.exists():
                    return p
    return None


def find_player(prefer="vlc", custom_path=None) -> tuple[Optional[Path], str]:
    """Find preferred media player. Returns (path, player_name)."""
    if prefer == "vlc":
        p = find_vlc(custom_path)
        if p:
            return p, "vlc"
        p = find_ffplay(custom_path)
        if p:
            return p, "ffplay"
    else:
        p = find_ffplay(custom_path)
        if p:
            return p, "ffplay"
        p = find_vlc(custom_path)
        if p:
            return p, "vlc"
    return None, "none"


def build_rtsp_url_with_creds(rtsp_url, username, password) -> str:
    """Embed credentials into RTSP URL."""
    parsed = urlparse(rtsp_url)
    if parsed.username:
        return rtsp_url
    netloc = f"{username}:{password}@{parsed.hostname}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return parsed._replace(netloc=netloc).geturl()


def launch_stream(rtsp_url, username, password, player="vlc",
                  player_path=None, log_func=None, disable_hw=False, use_proxy=False) -> Optional[subprocess.Popen]:
    """Launch VLC or ffplay to stream an RTSP/RTSPS URL."""
    log = log_func or print

    exe, name = find_player(prefer=player, custom_path=player_path)
    if not exe:
        log("No media player found (VLC or ffplay)", "error")
        log(f"Expected VLC at: {DEFAULT_VLC_PATH}", "warning")
        return None

    proxy_obj = None
    if use_proxy:
        import random
        from urllib.parse import urlparse
        parsed = urlparse(rtsp_url)
        
        # Khởi tạo Local Proxy để vượt rào SHA-256 cho VLC
        proxy_port = random.randint(10000, 60000)
        proxy_obj = RTSPProxy(
            local_port=proxy_port,
            target_host=parsed.hostname,
            target_port=parsed.port or 554,
            target_path=parsed.path,
            username=username,
            password=password,
            quote_algo=True,  # Bắt buộc True cho dòng Tapo C200
            absolute_uri=True
        )
        proxy_obj.start()
        stream_url = proxy_obj.proxy_url
        log(f"Local Proxy started at {stream_url}", "info")
    else:
        stream_url = build_rtsp_url_with_creds(rtsp_url, username, password)

    if name == "vlc":
        active_vlc_args = list(VLC_DEFAULT_ARGS)
        if disable_hw:
            active_vlc_args.append('--avcodec-hw=none')

        cmd = [str(exe)] + active_vlc_args + [
            "--meta-title", "MyoVIF Stream",
            stream_url,
        ]
    else:
        cmd = [str(exe), "-rtsp_transport", "tcp", stream_url]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if proxy_obj:
            proc._proxy_obj = proxy_obj  # Gắn proxy vào proc để bên ngoài có thể tắt nó đi khi đóng VLC
        return proc
    except Exception as e:
        log(f"Error launching player: {e}", "error")
        if proxy_obj:
            proxy_obj.stop()
        return None


# ────────────────────────────────────────────────────────────
# RTSP Proxy (for cameras with quirky auth)
# ────────────────────────────────────────────────────────────
class RTSPProxy:
    """Minimal RTSP proxy to handle custom digest auth for players that can't."""

    def __init__(self, target_url, username, password, local_port=8554,
                 quote_algo=False, algorithm="auto", log_func=None):
        self.target_url = target_url
        self.username = username
        self.password = password
        self.local_port = local_port
        self.quote_algo = quote_algo
        self.algorithm = algorithm
        self.log = log_func or print
        self.target_parsed = urlparse(target_url)
        self.target_host = self.target_parsed.hostname
        self.target_port = self.target_parsed.port or 554
        self.running = False
        self.server_sock = None

    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.settimeout(1.0)
        try:
            self.server_sock.bind(("127.0.0.1", self.local_port))
            self.server_sock.listen(5)
            self.running = True
            self.log(f"Proxy listening on rtsp://127.0.0.1:{self.local_port}/live", "info")
            threading.Thread(target=self._accept_loop, daemon=True).start()
        except Exception as e:
            self.log(f"Proxy failed to start: {e}", "error")
            self.running = False

    def stop(self):
        self.running = False
        if self.server_sock:
            self.server_sock.close()

    def _accept_loop(self):
        while self.running:
            try:
                client_conn, _ = self.server_sock.accept()
                client_conn.settimeout(1.0)
                threading.Thread(target=self._handle_client,
                                 args=(client_conn,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _calculate_auth(self, method, url, challenge):
        params = {}
        for m in re.finditer(r'(\w+)="?([^",]+)"?', challenge):
            params[m.group(1)] = m.group(2)

        realm = params.get("realm", "")
        nonce = params.get("nonce", "")
        qop = params.get("qop", "")
        server_algo = params.get("algorithm", "MD5")

        algo = server_algo if self.algorithm == "auto" else self.algorithm
        _, algo_name = get_hash_func(algo)

        nc = cnonce = None
        if qop:
            nc = "00000001"
            cnonce = "0a4f113b"

        _, _, response = compute_digest_response(
            algo_name, self.username, realm, self.password,
            method, url, nonce, qop, nc, cnonce
        )

        return build_digest_header(
            self.username, realm, nonce, url, algo_name, response,
            qop, nc, cnonce, quote_algo=self.quote_algo
        )

    def _handle_client(self, client_sock):
        try:
            cam_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cam_sock.connect((self.target_host, self.target_port))

            while self.running:
                data = client_sock.recv(8192)
                if not data:
                    break

                text = data.decode(errors="ignore")
                if text.startswith(("DESCRIBE", "SETUP", "PLAY",
                                    "OPTIONS", "TEARDOWN")):
                    lines = text.split("\r\n")
                    method = lines[0].split(" ")[0]

                    # Rewrite URL: proxy → camera
                    parts = lines[0].split(" ")
                    if len(parts) >= 2:
                        client_url = parts[1]
                        suffix = ""
                        if "/live" in client_url:
                            suffix = client_url.split("/live", 1)[1]
                        base = self.target_url.rstrip("/")
                        if suffix and not suffix.startswith("/"):
                            suffix = "/" + suffix
                        parts[1] = base + suffix
                        new_target_url = parts[1]
                    else:
                        new_target_url = self.target_url
                    lines[0] = " ".join(parts)

                    modified = "\r\n".join(lines)
                    cam_sock.sendall(modified.encode())
                    cam_resp = cam_sock.recv(8192)

                    if b"401 Unauthorized" in cam_resp:
                        challenge_m = re.search(
                            r"WWW-Authenticate: Digest (.*)",
                            cam_resp.decode(errors="ignore"),
                        )
                        if challenge_m:
                            auth = self._calculate_auth(
                                method, new_target_url, challenge_m.group(1)
                            )
                            new_lines = [l for l in lines if l.strip()]
                            new_lines.append(f"Authorization: {auth}")
                            new_lines.extend(["", ""])
                            cam_sock.sendall("\r\n".join(new_lines).encode())
                            cam_resp = cam_sock.recv(8192)

                    # Rewrite response URLs
                    resp_text = cam_resp.decode(errors="ignore")
                    proxy_base = f"rtsp://127.0.0.1:{self.local_port}/live/"
                    cam_base = self.target_url
                    if not cam_base.endswith("/"):
                        cam_base += "/"
                    if cam_base in resp_text:
                        resp_text = resp_text.replace(cam_base, proxy_base)
                        cam_resp = resp_text.encode()

                    client_sock.sendall(cam_resp)

                    if method == "PLAY" and b"200 OK" in cam_resp:
                        self._relay(client_sock, cam_sock)
                        break
                else:
                    cam_sock.sendall(data)
        except Exception as e:
            self.log(f"Proxy error: {e}", "warning")
        finally:
            client_sock.close()

    def _relay(self, s1, s2):
        s1.settimeout(1.0)
        s2.settimeout(1.0)

        def forward(src, dst):
            try:
                while self.running:
                    try:
                        data = src.recv(8192)
                        if not data:
                            break
                        dst.sendall(data)
                    except socket.timeout:
                        continue
            except Exception:
                pass

        t1 = threading.Thread(target=forward, args=(s1, s2), daemon=True)
        t2 = threading.Thread(target=forward, args=(s2, s1), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
