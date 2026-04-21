"""
SHA-256 Digest Authentication Verification Tool - VLC Integration
=================================================================
Test HTTP Digest Auth (ONVIF) và RTSP Digest Auth. Hỗ trợ VLC streaming.

QUY TẮC QUOTE ALGORITHM:
  - Mặc định: KHÔNG quote (algorithm=SHA-256) - theo chuẩn RFC.
  - Flag --quote: BẮT BUỘC quote (algorithm="SHA-256") - cần cho Tapo C200.

Usage:
  # Test ONVIF + RTSP (Tapo C200 cần --quote)
  python verify_sha256.py --preset tapo --quote --stream

  # Test Hikvision (Mặc định không quote)
  python verify_sha256.py --preset hikvision --stream

  # Custom URL
  python verify_sha256.py -u admin -p pass --rtsp rtsp://192.168.1.10:554/stream1 --stream
"""

import argparse
import hashlib
import os
import re
import socket
import base64
import sys
import json
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ============================================================
# Color helper for terminal output
# ============================================================
class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def green(text): return Color.out(text, Color.GREEN)
    @staticmethod
    def red(text): return Color.out(text, Color.RED)
    @staticmethod
    def yellow(text): return Color.out(text, Color.YELLOW)
    @staticmethod
    def cyan(text): return Color.out(text, Color.CYAN)
    @staticmethod
    def bold(text): return Color.out(text, Color.BOLD)
    @staticmethod
    def out(text, color_code): return f"{color_code}{text}{Color.END}"

# ============================================================
# VLC path & config
# ============================================================
SCRIPT_DIR = Path(__file__).parent.resolve()
DEFAULT_VLC_PATH = SCRIPT_DIR / 'vlc' / 'vlc.exe'

VLC_DEFAULT_ARGS = [
    '--rtsp-tcp',  # Force RTSP over TCP for stability
    '--network-caching', '300',
    '--no-video-title-show',
]

# ============================================================
# Presets
# ============================================================
PRESETS = {
    'tapo': {
        'label': 'TP-Link Tapo C200',
        'onvif': 'http://192.168.137.246:2020/onvif/device_service',
        'rtsp': 'rtsp://192.168.137.246:554/stream2',
        'username': 'psitest135',
        'password': 'psitest135',
    },
    'hikvision': {
        'label': 'Hikvision',
        'onvif': None,
        'rtsp': 'rtsp://192.168.66.231:554/Streaming/Channels/101',
        'username': 'admin',
        'password': 'psitest135',
    },
}


# ============================================================
# Hash helpers
# ============================================================
def get_hash_func(algorithm):
    """Return hash function for algorithm name."""
    algo = algorithm.upper().replace('-', '')
    if algo in ('SHA256',):
        return hashlib.sha256, 'SHA-256'
    elif algo in ('MD5',):
        return hashlib.md5, 'MD5'
    elif algo in ('SHA512256', 'SHA512_256'):
        return lambda: hashlib.new('sha512_256'), 'SHA-512-256'
    else:
        return hashlib.md5, 'MD5'


def compute_digest(hash_func, username, realm, password, method, uri,
                   nonce, qop=None, nc=None, cnonce=None):
    """Compute HTTP/RTSP Digest response."""
    ha1 = hash_func(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hash_func(f"{method}:{uri}".encode()).hexdigest()

    if qop:
        response = hash_func(
            f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
        ).hexdigest()
    else:
        response = hash_func(
            f"{ha1}:{nonce}:{ha2}".encode()
        ).hexdigest()

    return ha1, ha2, response


def parse_digest_challenge(header_text):
    """Parse WWW-Authenticate Digest challenge into dict."""
    params = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]+)"|([^\s,]+))', header_text):
        key = m.group(1).lower()
        val = m.group(2) if m.group(2) is not None else m.group(3)
        params[key] = val
    return params


def build_auth_header(username, realm, nonce, uri, algo_name, response,
                      qop=None, nc=None, cnonce=None, opaque=None,
                      quote_algo=True):
    """Build Authorization: Digest header string.
    
    Args:
        quote_algo: If True, algorithm="SHA-256" (quoted, default).
                    If False, algorithm=SHA-256 (unquoted, RFC standard).
    """
    algo_val = f'algorithm="{algo_name}"' if quote_algo else f'algorithm={algo_name}'
    parts = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        algo_val,
        f'response="{response}"',
    ]
    if qop:
        parts.extend([
            f'qop={qop}',
            f'nc={nc}',
            f'cnonce="{cnonce}"',
        ])
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return 'Digest ' + ', '.join(parts)


# ============================================================
# VLC Streaming
# ============================================================
def find_vlc(custom_path=None):
    """Find VLC executable. Priority: custom > portable > system."""
    candidates = []

    if custom_path:
        candidates.append(Path(custom_path))

    candidates.append(DEFAULT_VLC_PATH)

    if sys.platform == 'win32':
        for prog in [os.environ.get('ProgramFiles', ''),
                     os.environ.get('ProgramFiles(x86)', '')]:
            if prog:
                candidates.append(Path(prog) / 'VideoLAN' / 'VLC' / 'vlc.exe')
    else:
        candidates.append(Path('/usr/bin/vlc'))
        candidates.append(Path('/snap/bin/vlc'))

    for p in candidates:
        if p and p.exists():
            return p

    return None


def build_rtsp_url_with_creds(rtsp_url, username, password):
    """Embed credentials into RTSP URL for VLC."""
    parsed = urlparse(rtsp_url)
    if parsed.username:
        return rtsp_url
    netloc = f"{username}:{password}@{parsed.hostname}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return parsed._replace(netloc=netloc).geturl()


def launch_vlc(rtsp_url, username, password, vlc_path=None,
               extra_args=None, title=None, tunnel=False, tunnel_port=2020,
               user_agent="Lavf/58.29.100", proxy=False, proxy_port=8554, disable_hw=False):
    """Launch VLC to stream an RTSP URL.

    Returns the subprocess.Popen object or None on failure.
    """
    vlc_exe = find_vlc(vlc_path)
    if not vlc_exe:
        print("\n  [VLC] vlc.exe not found!")
        print(f"        Expected at: {DEFAULT_VLC_PATH}")
        print("        Use --vlc-path to specify a custom path.")
        return None

    if proxy:
        auth_url = f"rtsp://127.0.0.1:{proxy_port}/live"
    else:
        auth_url = build_rtsp_url_with_creds(rtsp_url, username, password)
    
    display_url = rtsp_url if not proxy else f"rtsp://127.0.0.1:{proxy_port}/live"

    window_title = title or f"Stream - {display_url}"

    # Start with default args, but remove --rtsp-tcp if we are tunneling (HTTP uses TCP)
    active_vlc_args = list(VLC_DEFAULT_ARGS)
    if tunnel and '--rtsp-tcp' in active_vlc_args:
        active_vlc_args.remove('--rtsp-tcp')

    cmd = [str(vlc_exe)] + active_vlc_args + [
        '--meta-title', 'CameraStream',
        '--http-user-agent', user_agent,
        '-vv',  # Very verbose logging
        '--file-logging',
        '--logfile', 'vlc_debug.log'
    ]

    # Tunneling: Use global flags for consistency now that we've switched demuxers
    if tunnel:
        cmd.extend([
            '--rtsp-http',
            '--rtsp-http-port', str(tunnel_port)
        ])

    # Pass credentials both in URL AND as explicit flags for maximum compatibility
    final_url = auth_url
    
    cmd.extend([
        '--rtsp-user', username,
        '--rtsp-pwd', password,
        final_url
    ])

    if disable_hw:
        cmd.append('--avcodec-hw=none')

    if extra_args:
        cmd.extend(extra_args)

    print(f"\n  {'='*60}")
    print(f"  VLC STREAMING {'(HTTP TUNNEL)' if tunnel else ''}")
    print(f"  {'='*60}")
    print(f"  VLC:    {vlc_exe}")
    print(f"  RTSP:   {rtsp_url}")
    if tunnel:
        print(f"  Tunnel: Port {tunnel_port}")
    
    # Debug: Full command line
    cmd_str = ' '.join(f'"{a}"' if ' ' in a or ':' in a else a for a in cmd)
    print(f"  CMD:    {Color.cyan(cmd_str)}")
    print(f"  {'='*60}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"  [VLC] Launched (PID {proc.pid})")
        return proc
    except FileNotFoundError:
        print(f"  [VLC] FAIL - Cannot execute {vlc_exe}")
        return None
    except Exception as e:
        print(f"  [VLC] FAIL - {e}")
        return None


# ============================================================
# RTSP helpers
# ============================================================
def rtsp_send_recv(sock, lines):
    """Send RTSP request lines, return (code, header_text, body_text)."""
    req = "\r\n".join(lines) + "\r\n\r\n"
    sock.sendall(req.encode())

    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk

    hdr = resp.split(b"\r\n\r\n")[0].decode('utf-8', errors='replace')
    body = resp[resp.find(b"\r\n\r\n") + 4:]

    for line in hdr.split("\r\n"):
        if line.lower().startswith("content-length"):
            clen = int(line.split(":")[1].strip())
            while len(body) < clen:
                body += sock.recv(4096)

    status_line = hdr.split("\r\n")[0]
    code = status_line.split(" ")[1] if " " in status_line else "?"
    return code, hdr, body.decode('utf-8', errors='replace')


# ============================================================
# TEST: ONVIF (HTTP POST)
# ============================================================
def test_onvif(url, username, password, force_algo=None, force_qop=None,
               quote_algo=False, verbose=True):
    """Test ONVIF SHA-256 Digest Auth via HTTP POST."""
    if not HAS_REQUESTS:
        print("  [SKIP] 'requests' module not installed. pip install requests")
        return None

    parsed = urlparse(url)
    uri = parsed.path
    method = "POST"

    soap = ('<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
            '<soap:Body><tds:GetDeviceInformation /></soap:Body>'
            '</soap:Envelope>')

    hdrs = {'Content-Type': 'application/soap+xml; charset=utf-8'}

    print(f"\n  [1] POST {url} (no auth)")
    resp1 = requests.post(url, data=soap, headers=hdrs, timeout=5)
    print(f"      <- {resp1.status_code}")

    if resp1.status_code != 401:
        if resp1.status_code == 200:
            print(f"      No auth required")
        return str(resp1.status_code)

    www_auth = resp1.headers.get('WWW-Authenticate', '')
    print(f"\n  [2] Challenge: {www_auth}")

    params = parse_digest_challenge(www_auth)
    realm = params.get('realm', '')
    nonce = params.get('nonce', '')
    qop = force_qop or params.get('qop', '')
    opaque = params.get('opaque', '')
    algo = force_algo or params.get('algorithm', 'MD5')

    hash_func, algo_name = get_hash_func(algo)

    print(f"\n  [3] Parsed challenge:")
    print(f"      algorithm = {algo} -> {algo_name}")
    print(f"      realm     = {realm}")
    print(f"      nonce     = {nonce}")
    print(f"      qop       = {qop or '(none)'}")
    print(f"      opaque    = {opaque or '(none)'}")

    nc = cnonce = None
    if qop:
        nc = "00000001"
        cnonce = hashlib.sha256(os.urandom(16)).hexdigest()[:16]

    ha1, ha2, response = compute_digest(
        hash_func, username, realm, password, method, uri,
        nonce, qop, nc, cnonce)

    if verbose:
        print(f"\n  [4] Computation ({algo_name}):")
        print(f"      HA1 = {algo_name}({username}:{realm}:***) = {ha1}")
        print(f"      HA2 = {algo_name}({method}:{uri}) = {ha2}")
        if qop:
            print(f"      response = {algo_name}(HA1:{nonce}:{nc}:{cnonce}:{qop}:HA2)")
        else:
            print(f"      response = {algo_name}(HA1:{nonce}:HA2)")
        print(f"               = {response}")
        print(f"      len = {len(response)} chars")

    auth_header = build_auth_header(
        username, realm, nonce, uri, algo_name, response,
        qop, nc, cnonce, opaque, quote_algo=quote_algo)

    hdrs2 = dict(hdrs)
    hdrs2['Authorization'] = auth_header
    resp2 = requests.post(url, data=soap, headers=hdrs2, timeout=5)

    res_color = Color.GREEN if resp2.status_code == 200 else Color.RED
    print(f"\n  [5] Result: HTTP {Color.out(resp2.status_code, res_color)}")

    discovered_uri = None
    if resp2.status_code == 200:
        print(f"      {Color.green('>>> ONVIF ' + algo_name + ' AUTH: THANH CONG <<<')}")
        body = resp2.text
        for tag in ['Manufacturer', 'Model', 'FirmwareVersion',
                     'SerialNumber', 'HardwareId']:
            m = re.search(f'<[^>]*{tag}>([^<]+)<', body)
            if m:
                print(f"      {tag}: {m.group(1)}")
        
        # --- PHASE 2: GET PROFILES ---
        print(f"\n  [6] Discovery: GetProfiles")
        soap_profiles = ('<?xml version="1.0" encoding="utf-8"?>'
                        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
                        ' xmlns:trt="http://www.onvif.org/ver10/media/wsdl">'
                        '<soap:Body><trt:GetProfiles /></soap:Body>'
                        '</soap:Envelope>')
        resp_prof = requests.post(url, data=soap_profiles, headers=hdrs2, timeout=5)
        
        token = None
        if resp_prof.status_code == 200:
            tokens = re.findall(r'token="([^"]+)"', resp_prof.text)
            if tokens:
                token = tokens[0]
                print(f"      Found {len(tokens)} profiles. Using: {token}")
        
        if token:
            # --- PHASE 3: GET STREAM URI ---
            print(f"  [7] Discovery: GetStreamUri (Token: {token})")
            soap_uri = (f'<?xml version="1.0" encoding="utf-8"?>'
                       '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
                       ' xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">'
                       '<soap:Body>'
                       '<trt:GetStreamUri>'
                       '<trt:StreamSetup>'
                       '<tt:Stream>RTP-Unicast</tt:Stream>'
                       '<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>'
                       '</trt:StreamSetup>'
                       f'<trt:ProfileToken>{token}</trt:ProfileToken>'
                       '</trt:GetStreamUri>'
                       '</soap:Body>'
                       '</soap:Envelope>')
            
            resp_uri = requests.post(url, data=soap_uri, headers=hdrs2, timeout=5)
            if resp_uri.status_code == 200:
                uri_match = re.search(r'<tt:Uri>(.*?)</tt:Uri>', resp_uri.text)
                if uri_match:
                    discovered_uri = uri_match.group(1)
                    print(f"      {Color.cyan('Authoritative URI: ' + discovered_uri)}")
    else:
        print(f"      {Color.red('>>> ONVIF ' + algo_name + ' AUTH: THAT BAI <<<')}")

    return discovered_uri if discovered_uri else (resp2.status_code == 200)


# ============================================================
# TEST: RTSP
# ============================================================
def test_rtsp(url, username, password, force_algo=None, force_qop=None,
              quote_algo=False, verbose=True):
    """Test RTSP Digest Auth using socket handshake (verified for SHA-256 quoting)."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 554
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    
    if verbose:
        print(f"\n  [1] DESCRIBE {url} (no auth)")
    
    try:
        # 1. Get challenge
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        s.send(f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Lavf/58.29.100\r\n\r\n".encode())
        resp = s.recv(4096).decode()
        s.close()
    except Exception as e:
        if verbose: print(f"      {Color.RED}[ERROR] Connection failed: {e}{Color.END}")
        return None

    if "401 Unauthorized" not in resp:
        if "200 OK" in resp:
            if verbose: print(f"      {Color.GREEN}>>> RTSP NO AUTH: SUCCESS <<<{Color.END}")
            return "200"
        return "ERROR"

    # 2. Parse Challenge
    auth_match = re.search(r'WWW-Authenticate: Digest (.*)', resp)
    if not auth_match:
        return "ERROR"
    
    params = {}
    for match in re.finditer(r'(\w+)="?([^",]+)"?', auth_match.group(1)):
        params[match.group(1)] = match.group(2)
        
    realm = params.get('realm', '')
    nonce = params.get('nonce', '')
    qop = params.get('qop', '')
    algo = force_algo or params.get('algorithm', 'SHA-256')
    opaque = params.get('opaque', '')

    if verbose:
        print(f"  [2] Challenge: algorithm=\"{algo}\", qop=\"{qop}\"")

    # 3. Calculate Response
    def get_hash(data):
        if algo.upper() in ['SHA-256', 'SHA256']:
            return hashlib.sha256(data.encode()).hexdigest()
        return hashlib.md5(data.encode()).hexdigest()

    ha1 = get_hash(f"{username}:{realm}:{password}")
    ha2 = get_hash(f"DESCRIBE:{url}")
    
    if qop:
        cnonce = "0a4f113b"
        nc = "00000001"
        response = get_hash(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
        algo_str = f'"{algo}"' if quote_algo else algo
        auth_header = (f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
                       f'uri="{url}", response="{response}", algorithm={algo_str}, '
                       f'cnonce="{cnonce}", nc={nc}, qop="auth"')
    else:
        response = get_hash(f"{ha1}:{nonce}:{ha2}")
        algo_str = f'"{algo}"' if quote_algo else algo
        auth_header = (f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
                       f'uri="{url}", response="{response}", algorithm={algo_str}')

    # 4. Send AUTH DESCRIBE
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        auth_request = (f"DESCRIBE {url} RTSP/1.0\r\n"
                        f"CSeq: 2\r\n"
                        f"Authorization: {auth_header}\r\n"
                        f"User-Agent: Lavf/58.29.100\r\n\r\n")
        s.send(auth_request.encode())
        final_resp = s.recv(4096).decode()
        s.close()
        
        status_code = "???"
        if final_resp:
            m = re.match(r'RTSP/1.0 (\d+)', final_resp)
            if m: status_code = m.group(1)

        res_color = Color.GREEN if status_code == "200" else Color.RED
        if verbose:
            print(f"  [3] Result: RTSP {Color.out(status_code, res_color)}")
            if status_code == "200":
                print(f"      {Color.green('>>> RTSP ' + algo + ' AUTH: THANH CONG <<<')}")
            else:
                print(f"      {Color.red('>>> RTSP ' + algo + ' AUTH: THAT BAI <<<')}")
        
        return status_code
    except Exception as e:
        if verbose: print(f"      {Color.RED}[ERROR] Auth request failed: {e}{Color.END}")
        return None

class RTSPProxy:
    """
    A minimal RTSP Proxy to handle SHA-256 for players that fail to quote algorithm.
    It performs the handshake with the camera and provides a clean stream to VLC.
    """
    def __init__(self, target_url, username, password, local_port=8554, quote_algo=True):
        self.target_url = target_url
        self.username = username
        self.password = password
        self.local_port = local_port
        self.quote_algo = quote_algo
        self.target_parsed = urlparse(target_url)
        self.target_host = self.target_parsed.hostname
        self.target_port = self.target_parsed.port or 554
        self.running = False
        self.server_sock = None
        self.auth_headers = {} # Cache auth headers per method

    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.settimeout(1.0) # Allow interruptible accept
        try:
            self.server_sock.bind(('127.0.0.1', self.local_port))
            self.server_sock.listen(5)
            self.running = True
            print(f"  {Color.CYAN}[Proxy] Listening on rtsp://127.0.0.1:{self.local_port}/live{Color.END}")
            threading.Thread(target=self._accept_loop, daemon=True).start()
        except Exception as e:
            print(f"  {Color.RED}[Proxy] Failed to start: {e}{Color.END}")
            self.running = False

    def stop(self):
        self.running = False
        if self.server_sock:
            self.server_sock.close()

    def _accept_loop(self):
        while self.running:
            try:
                client_conn, addr = self.server_sock.accept()
                client_conn.settimeout(1.0)
                threading.Thread(target=self._handle_client, args=(client_conn,), daemon=True).start()
            except socket.timeout:
                continue
            except:
                break

    def _calculate_auth(self, method, url, challenge):
        params = {}
        for match in re.finditer(r'(\w+)="?([^",]+)"?', challenge):
            params[match.group(1)] = match.group(2)
            
        realm = params.get('realm', '')
        nonce = params.get('nonce', '')
        qop = params.get('qop', '')
        algo = params.get('algorithm', 'SHA-256')
        
        def get_hash(data):
            if algo.upper() in ['SHA-256', 'SHA256']:
                return hashlib.sha256(data.encode()).hexdigest()
            return hashlib.md5(data.encode()).hexdigest()

        ha1 = get_hash(f"{self.username}:{realm}:{self.password}")
        ha2 = get_hash(f"{method}:{url}")
        
        if qop:
            cnonce = "0a4f113b"
            nc = "00000001"
            response = get_hash(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
            algo_str = f'"{algo}"' if self.quote_algo else algo
            return (f'Digest username="{self.username}", realm="{realm}", nonce="{nonce}", '
                    f'uri="{url}", response="{response}", algorithm={algo_str}, '
                    f'cnonce="{cnonce}", nc={nc}, qop="auth"')
        else:
            response = get_hash(f"{ha1}:{nonce}:{ha2}")
            algo_str = f'"{algo}"' if self.quote_algo else algo
            return (f'Digest username="{self.username}", realm="{realm}", nonce="{nonce}", '
                    f'uri="{url}", response="{response}", algorithm={algo_str}')

    def _handle_client(self, client_sock):
        try:
            cam_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cam_sock.connect((self.target_host, self.target_port))
            
            # Relay loop for RTSP commands
            while self.running:
                data = client_sock.recv(8192)
                if not data: break
                
                # Check if it's an RTSP command
                text = data.decode(errors='ignore')
                if text.startswith(('DESCRIBE', 'SETUP', 'PLAY', 'OPTIONS', 'TEARDOWN')):
                    lines = text.split('\r\n')
                    method = lines[0].split(' ')[0]
                    
                    # --- REWRITE REQUEST FOR CAMERA ---
                    # Fix Request Line: swap localhost proxy URL with real camera URL while preserving suffix
                    parts = lines[0].split(' ')
                    if len(parts) >= 2:
                        client_url = parts[1]
                        # Map: rtsp://127.0.0.1:8554/live/track1 -> rtsp://CAM_IP:554/stream2/track1
                        suffix = ""
                        if "/live" in client_url:
                            suffix = client_url.split("/live", 1)[1]
                        
                        # Strip any trailing slash from self.target_url if suffix starts with one
                        base_url = self.target_url.rstrip('/')
                        if not suffix.startswith('/'):
                            suffix = '/' + suffix
                            
                        parts[1] = base_url + suffix
                        new_target_url = parts[1]
                    else:
                        new_target_url = self.target_url
                        
                    lines[0] = ' '.join(parts)
                    
                    # 2. Impersonate User-Agent
                    for i in range(len(lines)):
                        if lines[i].lower().startswith('user-agent:'):
                            lines[i] = "User-Agent: Lavf/58.29.100"
                    
                    modified_text = '\r\n'.join(lines)
                    
                    # --- SEND TO CAMERA ---
                    cam_sock.sendall(modified_text.encode())
                    cam_resp = cam_sock.recv(8192)
                    
                    if b"401 Unauthorized" in cam_resp:
                        # --- HANDLE DIGEST AUTH ---
                        challenge_match = re.search(r'WWW-Authenticate: Digest (.*)', cam_resp.decode(errors='ignore'))
                        if challenge_match:
                            auth_header = self._calculate_auth(method, new_target_url, challenge_match.group(1))
                            
                            # Add Authorization header
                            # Note: We must insert it BEFORE the empty line (\r\n\r\n)
                            new_lines = []
                            for line in lines:
                                if line.strip() == "": continue
                                new_lines.append(line)
                            new_lines.append(f"Authorization: {auth_header}")
                            new_lines.append("") # Empty line to end headers
                            new_lines.append("") # Final CRLF
                            
                            retry_text = '\r\n'.join(new_lines)
                            cam_sock.sendall(retry_text.encode())
                            cam_resp = cam_sock.recv(8192)
                    
                    # --- REWRITE RESPONSE FOR VLC ---
                    # Rewrite Content-Base and Location headers to point back to proxy
                    resp_text = cam_resp.decode(errors='ignore')
                    proxy_base = f"rtsp://127.0.0.1:{self.local_port}/live/"
                    
                    # Replace camera's base URL with our proxy base
                    # We look for rtsp://CAM_IP:PORT/path/
                    cam_base = self.target_url
                    if not cam_base.endswith('/'): cam_base += '/'
                    
                    if cam_base in resp_text:
                        resp_text = resp_text.replace(cam_base, proxy_base)
                        cam_resp = resp_text.encode()

                    # Forward modified camera response back to VLC
                    client_sock.sendall(cam_resp)
                    
                    # If this was PLAY and we got 200 OK, switch to pure relay
                    if method == 'PLAY' and b"200 OK" in cam_resp:
                        self._pure_relay(client_sock, cam_sock)
                        break
                else:
                    # Binary data (RTP Interleaved) or unknown
                    cam_sock.sendall(data)
        except Exception as e:
            print(f"  {Color.RED}[Proxy] Error: {e}{Color.END}")
        finally:
            client_sock.close()

    def _pure_relay(self, s1, s2):
        s1.settimeout(1.0)
        s2.settimeout(1.0)
        def forward(src, dst):
            try:
                while self.running:
                    try:
                        data = src.recv(8192)
                        if not data: break
                        dst.sendall(data)
                    except socket.timeout:
                        continue
            except: pass
        
        t1 = threading.Thread(target=forward, args=(s1, s2), daemon=True)
        t2 = threading.Thread(target=forward, args=(s2, s1), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()


# ============================================================
# Batch mode
# ============================================================
def run_batch(filepath):
    """Run tests from a batch file (JSON array or line-per-camera)."""
    print(f"\n  Loading batch file: {filepath}")

    with open(filepath, 'r') as f:
        content = f.read().strip()

    # Try JSON format
    try:
        cameras = json.loads(content)
        if isinstance(cameras, list):
            results = []
            for cam in cameras:
                label = cam.get('label', cam.get('rtsp', cam.get('onvif', '?')))
                print(f"\n{'='*70}")
                print(f"  {label}")
                print(f"{'='*70}")

                if cam.get('onvif'):
                    r = test_onvif(cam['onvif'], cam['username'],
                                   cam['password'],
                                   cam.get('algorithm'),
                                   cam.get('qop'))
                    results.append((f"{label} ONVIF", r))

                if cam.get('rtsp'):
                    r = test_rtsp(cam['rtsp'], cam['username'],
                                  cam['password'],
                                  cam.get('algorithm'),
                                  cam.get('qop'))
                    results.append((f"{label} RTSP", r))

            return results
    except json.JSONDecodeError:
        pass

    print(f"  [ERROR] Invalid batch file format. Expected JSON array.")
    print(f'  Example: [{{"label":"Cam1","rtsp":"rtsp://...","username":"admin","password":"pass"}}]')
    return []


# ============================================================
# Main
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description='SHA-256 Digest Authentication Verification Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test ONVIF + RTSP on Tapo C200
  %(prog)s -u psitest135 -p psitest135 \\
    --onvif http://192.168.137.246:2020/onvif/device_service \\
    --rtsp rtsp://192.168.137.246:554/stream2

  # Test RTSP only on Hikvision
  %(prog)s -u admin -p psitest135 \\
    --rtsp rtsp://192.168.66.231:554/Streaming/Channels/101

  # Use preset
  %(prog)s --preset tapo
  %(prog)s --preset hikvision

  # Force MD5 algorithm
  %(prog)s -u admin -p admin --rtsp rtsp://192.168.1.1:554/stream1 --algorithm MD5

  # Batch test from JSON file
  %(prog)s --batch cameras.json

  # Quiet mode (summary only)
  %(prog)s --preset tapo -q
""")

    # Connection args
    parser.add_argument('-u', '--username', help='Username')
    parser.add_argument('-p', '--password', help='Password')
    parser.add_argument('--onvif', help='ONVIF URL (e.g. http://host:2020/onvif/device_service)')
    parser.add_argument('--rtsp', help='RTSP URL (e.g. rtsp://host:554/stream1)')

    # Optional overrides
    parser.add_argument('--algorithm', choices=['SHA-256', 'MD5', 'SHA256'],
                        help='Force digest algorithm (default: auto-detect from challenge)')
    parser.add_argument('--qop', choices=['auth', 'auth-int'],
                        help='Force qop value (default: auto-detect from challenge)')
    parser.add_argument('--quote', action='store_true',
                        help='Force quoted algorithm="SHA-256" (default is unquoted for RFC compatibility)')

    # RTSP Streaming
    parser.add_argument('--stream', action='store_true',
                        help='Automatically launch VLC to stream if authentication succeeds')
    parser.add_argument('--vlc-path', help='Path to vlc.exe (overrides default/portable path)')
    parser.add_argument('--vlc-args', nargs='*', default=[],
                        help='Extra arguments to pass to VLC')
    parser.add_argument('--tunnel', action='store_true',
                        help='Use RTSP-over-HTTP tunneling (fixes SHA-256 auth on Tapo)')
    parser.add_argument('--tunnel-port', type=int, default=2020,
                        help='Port for RTSP tunneling (default: 2020 for Tapo)')
    parser.add_argument('--no-hw', action='store_true',
                        help='Tắt giải mã phần cứng VLC (Sửa lỗi treo stream)')
    parser.add_argument('--proxy', action='store_true',
                        help='Use local RTSP proxy to bypass player SHA-256 bugs')
    parser.add_argument('--proxy-port', type=int, default=8554,
                        help='Port for local proxy (default: 8554)')
    parser.add_argument('--user-agent', default='Lavf/58.29.100',
                        help='User-Agent for VLC (default: Lavf/58.29.100)')

    # Modes
    parser.add_argument('--preset', choices=list(PRESETS.keys()),
                        help='Use preset camera config')
    parser.add_argument('--batch', metavar='FILE',
                        help='Batch test from JSON file')
    parser.add_argument('--all-presets', action='store_true',
                        help='Test all presets')

    # Output
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode - less verbose output')
    parser.add_argument('--json', action='store_true',
                        help='Output results as JSON')

    args = parser.parse_args()

    # Quoting logic: Default False (unquoted), --quote sets to True
    quote_algo = args.quote

    # Header
    print(f"\n{Color.cyan('='*70)}")
    print(f"  {Color.bold('SHA-256 DIGEST AUTHENTICATION VERIFICATION TOOL')}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Auth quoting: {'QUOTED' if quote_algo else 'UNQUOTED (Default)'}")
    print(f"{Color.cyan('='*70)}")

    results = []

    # Batch mode
    if args.batch:
        results = run_batch(args.batch)

    # All presets
    elif args.all_presets:
        for name, preset in PRESETS.items():
            print(f"\n{Color.yellow('='*70)}")
            print(f"  PRESET: {Color.bold(name)} - {preset['label']}")
            print(f"{Color.yellow('='*70)}")

            if preset.get('onvif'):
                r = test_onvif(preset['onvif'], preset['username'],
                               preset['password'], args.algorithm, args.qop,
                               quote_algo=quote_algo, verbose=not args.quiet)
                results.append((f"{preset['label']} ONVIF", r))

            if preset.get('rtsp'):
                r = test_rtsp(preset['rtsp'], preset['username'],
                              preset['password'], args.algorithm, args.qop,
                              quote_algo=quote_algo, verbose=not args.quiet)
                results.append((f"{preset['label']} RTSP", r))

    # Preset mode
    elif args.preset:
        preset = PRESETS[args.preset]
        username = args.username or preset['username']
        password = args.password or preset['password']
        onvif_url = args.onvif or preset.get('onvif')
        rtsp_url = args.rtsp or preset.get('rtsp')

        print(f"\n  {Color.cyan('Preset:')} {args.preset} ({preset['label']})")
        print(f"  {Color.cyan('User:')}   {username}")

        if onvif_url:
            print(f"\n{Color.yellow('='*70)}")
            print(f"  ONVIF: {onvif_url}")
            print(f"{Color.yellow('='*70)}")
            # ONVIF can return a discovered RTSP URI
            onvif_res = test_onvif(onvif_url, username, password,
                                   args.algorithm, args.qop,
                                   quote_algo=quote_algo, verbose=not args.quiet)
            results.append((f"{preset['label']} ONVIF", onvif_res is not False))
            if isinstance(onvif_res, str) and onvif_res.startswith("rtsp://"):
                print(f"  {Color.GREEN}Using discovered RTSP URI instead of preset.{Color.END}")
                rtsp_url = onvif_res

        if rtsp_url:
            print(f"\n{Color.yellow('='*70)}")
            print(f"  RTSP: {rtsp_url}")
            print(f"{Color.yellow('='*70)}")
            r = test_rtsp(rtsp_url, username, password,
                          args.algorithm, args.qop,
                          quote_algo=quote_algo, verbose=not args.quiet)
            results.append((f"{preset['label']} RTSP", r))

    # Manual mode
    elif args.onvif or args.rtsp:
        if not args.username or not args.password:
            parser.error("--username and --password required")

        if args.onvif:
            print(f"\n{Color.yellow('='*70)}")
            print(f"  ONVIF: {args.onvif}")
            print(f"{Color.yellow('='*70)}")
            onvif_res = test_onvif(args.onvif, args.username, args.password,
                                   args.algorithm, args.qop,
                                   quote_algo=quote_algo, verbose=not args.quiet)
            results.append(("ONVIF (Custom URL)", onvif_res is not False))
            if isinstance(onvif_res, str) and onvif_res.startswith("rtsp://"):
                print(f"  {Color.GREEN}Using discovered RTSP URI.{Color.END}")
                # Update rtsp_url if it's not manually set or if we want to override
                if not args.rtsp:
                    rtsp_url = onvif_res

        if args.rtsp:
            print(f"\n{Color.yellow('='*70)}")
            print(f"  RTSP: {args.rtsp}")
            print(f"{Color.yellow('='*70)}")
            r = test_rtsp(args.rtsp, args.username, args.password,
                          args.algorithm, args.qop,
                          quote_algo=quote_algo, verbose=not args.quiet)
            results.append(("RTSP (Custom URL)", r))

    else:
        # Default: run all presets
        print(f"\n  No arguments given. Running all presets...")
        for name, preset in PRESETS.items():
            print(f"\n{'='*70}")
            print(f"  {preset['label']} (--preset {name})")
            print(f"{'='*70}")

            if preset.get('onvif'):
                r = test_onvif(preset['onvif'], preset['username'],
                               preset['password'], args.algorithm, args.qop,
                               verbose=not args.quiet)
                results.append((f"{preset['label']} ONVIF", r))

            if preset.get('rtsp'):
                r = test_rtsp(preset['rtsp'], preset['username'],
                              preset['password'], args.algorithm, args.qop,
                              verbose=not args.quiet)
                results.append((f"{preset['label']} RTSP", r))

    # Summary
    if results:
        print(f"\n{Color.cyan('='*70)}")
        print(f"  {Color.bold('SUMMARY')}")
        print(f"{Color.cyan('='*70)}")
        print(f"  +{'-'*35}+{'-'*10}+")
        print(f"  | {Color.bold('Test'):<33} | {Color.bold('Result'):<8} |")
        print(f"  +{'-'*35}+{'-'*10}+")
        for name, code in results:
            if code == "200" or code is True or (isinstance(code, str) and code.startswith("rtsp")):
                status_text = "PASS"
                status = Color.green(status_text)
            elif code is None or code is False:
                status_text = "ERROR"
                status = Color.red(status_text)
            else:
                status_text = f"FAIL {code}"
                status = Color.red(status_text)
            
            # Padded status to ensure table alignment
            padding = " " * (8 - len(status_text))
            print(f"  | {name:<33} | {status}{padding} |")
        print(f"  +{'-'*35}+{'-'*10}+")

        all_pass = all(code == "200" for _, code in results)
        if all_pass:
            print(f"\n  {Color.green('>>> TAT CA XAC THUC THANH CONG <<<')}")

        if args.json:
            json_out = [{"test": n, "status": c} for n, c in results]
            print(f"\n{json.dumps(json_out, indent=2)}")

    # ------ VLC streaming after auth ------
    rtsp_passed = any("RTSP" in name and code == "200"
                      for name, code in results)

    if args.stream and rtsp_passed:
        # Determine which RTSP URL and credentials to use
        rtsp_url_to_stream = None
        stream_user = None
        stream_pass = None

        if args.rtsp:
            rtsp_url_to_stream = args.rtsp
            stream_user = args.username
            stream_pass = args.password
        elif args.preset:
            preset = PRESETS[args.preset]
            rtsp_url_to_stream = preset.get('rtsp')
            stream_user = args.username or preset['username']
            stream_pass = args.password or preset['password']
        
        # Fallback to the first successful RTSP test if many
        if not rtsp_url_to_stream:
            for name, code in results:
                if "RTSP" in name and code == "200":
                    # Try to find url from preset if name matches
                    for p_key, p_val in PRESETS.items():
                        if p_val['label'] in name:
                            rtsp_url_to_stream = p_val['rtsp']
                            stream_user = args.username or p_val['username']
                            stream_pass = args.password or p_val['password']
                            break
                    break

        if rtsp_url_to_stream:
            proxy_obj = None
            if args.proxy:
                proxy_obj = RTSPProxy(
                    rtsp_url_to_stream,
                    stream_user,
                    stream_pass,
                    local_port=args.proxy_port,
                    quote_algo=args.quote
                )
                proxy_obj.start()
                if not proxy_obj.running:
                    print(f"  {Color.RED}[Proxy] Could not start proxy. Aborting stream.{Color.END}")
                    return

            proc = launch_vlc(
                rtsp_url_to_stream,
                stream_user,
                stream_pass,
                vlc_path=args.vlc_path,
                extra_args=args.vlc_args,
                tunnel=args.tunnel,
                tunnel_port=args.tunnel_port,
                user_agent=args.user_agent,
                proxy=args.proxy,
                proxy_port=args.proxy_port,
                disable_hw=args.no_hw
            )
            if proc:
                print(f"\n  VLC is running. Press Ctrl+C to stop.")
                try:
                    proc.wait()
                except KeyboardInterrupt:
                    print(f"\n  Stopping VLC...")
                    if proxy_obj: proxy_obj.stop()
                    proc.terminate()
                finally:
                    if proxy_obj: proxy_obj.stop()
    elif args.stream and not rtsp_passed:
        print(f"\n  {Color.yellow('[VLC]')} Authentication failed. Skipping stream.")

    print(f"\n  SHA-256 Formula (RFC 7616):")
    print(f"    HA1 = HASH(username:realm:password)")
    print(f"    HA2 = HASH(method:uri)")
    print(f"    With qop:    response = HASH(HA1:nonce:nc:cnonce:qop:HA2)")
    print(f"    Without qop: response = HASH(HA1:nonce:HA2)")
    print()


if __name__ == '__main__':
    main()
