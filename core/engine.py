"""
MyoVIF Core Engine
==================
Auth (Standard + Custom Digest), ONVIF SOAP, RTSP/RTSPS, WS-Discovery.
"""

import hashlib
import os
import re
import socket
import ssl
import struct
import uuid
from datetime import datetime
from urllib.parse import urlparse
from typing import Optional, Callable

try:
    import requests
    from requests.auth import HTTPDigestAuth
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ────────────────────────────────────────────────────────────
# Hash helpers
# ────────────────────────────────────────────────────────────
def get_hash_func(algorithm: str):
    """Return (hashlib constructor, canonical name) for an algorithm string."""
    algo = algorithm.upper().replace("-", "")
    if algo in ("SHA256",):
        return hashlib.sha256, "SHA-256"
    elif algo in ("SHA512256", "SHA512_256"):
        return lambda: hashlib.new("sha512_256"), "SHA-512-256"
    else:
        return hashlib.md5, "MD5"


def _hash(algo_name: str, data: str) -> str:
    """One-shot hash: algo_name in ('MD5','SHA-256','SHA-512-256')."""
    algo = algo_name.upper().replace("-", "")
    if algo in ("SHA256",):
        return hashlib.sha256(data.encode()).hexdigest()
    elif algo in ("SHA512256", "SHA512_256"):
        return hashlib.new("sha512_256", data.encode()).hexdigest()
    else:
        return hashlib.md5(data.encode()).hexdigest()


def parse_digest_challenge(header_text: str) -> dict:
    """Parse WWW-Authenticate Digest challenge into dict."""
    params = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]+)"|([^\s,]+))', header_text):
        key = m.group(1).lower()
        val = m.group(2) if m.group(2) is not None else m.group(3)
        params[key] = val
    return params


def build_digest_header(
    username, realm, nonce, uri, algo_name, response,
    qop=None, nc=None, cnonce=None, opaque=None, quote_algo=False
) -> str:
    """Build Authorization: Digest header string."""
    algo_val = f'algorithm="{algo_name}"' if quote_algo else f"algorithm={algo_name}"
    parts = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        algo_val,
        f'response="{response}"',
    ]
    if qop:
        parts.extend([f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"'])
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return "Digest " + ", ".join(parts)


def compute_digest_response(
    algo_name, username, realm, password, method, uri,
    nonce, qop=None, nc=None, cnonce=None
):
    """Compute HA1, HA2, response for Digest auth."""
    ha1 = _hash(algo_name, f"{username}:{realm}:{password}")
    ha2 = _hash(algo_name, f"{method}:{uri}")
    if qop:
        response = _hash(algo_name, f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    else:
        response = _hash(algo_name, f"{ha1}:{nonce}:{ha2}")
    return ha1, ha2, response


# ────────────────────────────────────────────────────────────
# ONVIF Client
# ────────────────────────────────────────────────────────────
import base64
import time

def generate_ws_security_header(username, password):
    """Generate WS-UsernameToken according to ONVIF standards"""
    nonce_bytes = os.urandom(16)
    created = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    
    digest_raw = nonce_bytes + created.encode('utf-8') + password.encode('utf-8')
    password_digest = base64.b64encode(hashlib.sha1(digest_raw).digest()).decode('utf-8')
    nonce_b64 = base64.b64encode(nonce_bytes).decode('utf-8')

    header = f"""
    <s:Header>
        <Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <UsernameToken>
                <Username>{username}</Username>
                <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password_digest}</Password>
                <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</Nonce>
                <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</Created>
            </UsernameToken>
        </Security>
    </s:Header>"""
    return header

def inject_ws_header(soap_body: str, username, password) -> str:
    """Inject WS-Security header into a SOAP envelope."""
    header = generate_ws_security_header(username, password)
    # Inject right before <soap:Body> or <s:Body>
    if "<soap:Body" in soap_body:
        return soap_body.replace("<soap:Body", header + "\n    <soap:Body", 1)
    elif "<s:Body" in soap_body:
        return soap_body.replace("<s:Body", header + "\n    <s:Body", 1)
    return soap_body

SOAP_DEVICE_INFO = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
    ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
    '<soap:Body><tds:GetDeviceInformation /></soap:Body>'
    '</soap:Envelope>'
)

SOAP_GET_PROFILES = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
    ' xmlns:trt="http://www.onvif.org/ver10/media/wsdl">'
    '<soap:Body><trt:GetProfiles /></soap:Body>'
    '</soap:Envelope>'
)

SOAP_GET_STREAM_URI = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
    ' xmlns:trt="http://www.onvif.org/ver10/media/wsdl"'
    ' xmlns:tt="http://www.onvif.org/ver10/schema">'
    '<soap:Body>'
    '<trt:GetStreamUri>'
    '<trt:StreamSetup>'
    '<tt:Stream>RTP-Unicast</tt:Stream>'
    '<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>'
    '</trt:StreamSetup>'
    '<trt:ProfileToken>{token}</trt:ProfileToken>'
    '</trt:GetStreamUri>'
    '</soap:Body>'
    '</soap:Envelope>'
)

SOAP_GET_SNAPSHOT_URI = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
    ' xmlns:trt="http://www.onvif.org/ver10/media/wsdl">'
    '<soap:Body>'
    '<trt:GetSnapshotUri>'
    '<trt:ProfileToken>{token}</trt:ProfileToken>'
    '</trt:GetSnapshotUri>'
    '</soap:Body>'
    '</soap:Envelope>'
)


class ONVIFClient:
    """ONVIF SOAP client with Standard or Custom digest auth."""

    def __init__(self, host, port=80, username="admin", password="",
                 auth_mode="standard", algorithm="auto", quote_algo=False,
                 use_ws_auth=False, log_func=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.auth_mode = auth_mode
        self.algorithm = algorithm
        self.quote_algo = quote_algo
        self.use_ws_auth = use_ws_auth
        self.log = log_func or print
        self.url = f"http://{host}:{port}/onvif/device_service"

    def _post_standard(self, soap_body: str) -> Optional[requests.Response]:
        """Standard mode — let requests handle digest."""
        if not HAS_REQUESTS:
            self.log("[ERROR] 'requests' not installed", "error")
            return None
        
        if self.use_ws_auth:
            soap_body = inject_ws_header(soap_body, self.username, self.password)
            
        hdrs = {"Content-Type": "application/soap+xml; charset=utf-8"}
        auth = HTTPDigestAuth(self.username, self.password)
        try:
            resp = requests.post(self.url, data=soap_body, headers=hdrs,
                                 auth=auth, timeout=5)
            return resp
        except Exception as e:
            self.log(f"[ERROR] {e}", "error")
            return None

    def _post_custom(self, soap_body: str) -> Optional[requests.Response]:
        """Custom mode — manual digest calculation."""
        if not HAS_REQUESTS:
            self.log("[ERROR] 'requests' not installed", "error")
            return None
        
        if self.use_ws_auth:
            soap_body = inject_ws_header(soap_body, self.username, self.password)

        hdrs = {"Content-Type": "application/soap+xml; charset=utf-8"}
        parsed = urlparse(self.url)
        uri = parsed.path
        method = "POST"

        # Step 1: send without auth to get challenge
        try:
            resp1 = requests.post(self.url, data=soap_body, headers=hdrs, timeout=5)
        except Exception as e:
            self.log(f"[ERROR] {e}", "error")
            return None

        if resp1.status_code != 401:
            return resp1

        www_auth = resp1.headers.get("WWW-Authenticate", "")
        self.log(f"Challenge: {www_auth}", "info")
        params = parse_digest_challenge(www_auth)

        realm = params.get("realm", "")
        nonce = params.get("nonce", "")
        qop = params.get("qop", "")
        opaque = params.get("opaque", "")
        server_algo = params.get("algorithm", "MD5")

        # Use forced algorithm or server's
        algo = server_algo if self.algorithm == "auto" else self.algorithm
        _, algo_name = get_hash_func(algo)

        nc = cnonce = None
        if qop:
            nc = "00000001"
            cnonce = hashlib.sha256(os.urandom(16)).hexdigest()[:16]

        _, _, response = compute_digest_response(
            algo_name, self.username, realm, self.password,
            method, uri, nonce, qop, nc, cnonce
        )

        auth_header = build_digest_header(
            self.username, realm, nonce, uri, algo_name, response,
            qop, nc, cnonce, opaque, quote_algo=self.quote_algo
        )

        hdrs2 = dict(hdrs)
        hdrs2["Authorization"] = auth_header
        try:
            resp2 = requests.post(self.url, data=soap_body, headers=hdrs2, timeout=5)
            return resp2
        except Exception as e:
            self.log(f"[ERROR] {e}", "error")
            return None

    def _post(self, soap_body: str) -> Optional[requests.Response]:
        if self.auth_mode == "custom":
            return self._post_custom(soap_body)
        return self._post_standard(soap_body)

    def get_device_info(self) -> Optional[dict]:
        """GetDeviceInformation → dict of Manufacturer, Model, etc."""
        self.log(f"ONVIF → {self.url}", "info")
        self.log(f"Mode: {self.auth_mode.upper()}", "info")

        resp = self._post(SOAP_DEVICE_INFO)
        if resp is None:
            return None

        if resp.status_code != 200:
            self.log(f"ONVIF AUTH FAILED (HTTP {resp.status_code})", "error")
            return None

        self.log("ONVIF AUTH SUCCESS (HTTP 200)", "success")
        info = {}
        for tag in ["Manufacturer", "Model", "FirmwareVersion",
                     "SerialNumber", "HardwareId"]:
            m = re.search(f"<[^>]*{tag}>([^<]+)<", resp.text)
            if m:
                info[tag] = m.group(1)
                self.log(f"  {tag}: {m.group(1)}", "info")
        return info

    def get_profiles(self) -> list[dict]:
        """GetProfiles → list of {token, name}."""
        self.log("ONVIF → GetProfiles", "info")
        resp = self._post(SOAP_GET_PROFILES)
        if resp is None or resp.status_code != 200:
            self.log("GetProfiles failed", "error")
            return []

        profiles = []
        tokens = re.findall(r'token="([^"]+)"', resp.text)
        names = re.findall(r'<[^>]*Name>([^<]+)<', resp.text)
        for i, tok in enumerate(tokens):
            name = names[i] if i < len(names) else tok
            profiles.append({"token": tok, "name": name})

        self.log(f"Found {len(profiles)} profiles", "success")
        for p in profiles:
            self.log(f"  [{p['token']}] {p['name']}", "info")
        return profiles

    def get_stream_uri(self, profile_token: str) -> Optional[str]:
        """GetStreamUri → RTSP URI string."""
        self.log(f"ONVIF → GetStreamUri (token={profile_token})", "info")
        soap = SOAP_GET_STREAM_URI.format(token=profile_token)
        resp = self._post(soap)
        if resp is None or resp.status_code != 200:
            self.log("GetStreamUri failed", "error")
            return None
        m = re.search(r"<tt:Uri>(.*?)</tt:Uri>", resp.text)
        if m:
            uri = m.group(1)
            self.log(f"Stream URI: {uri}", "success")
            return uri
        return None

    def get_snapshot_uri(self, profile_token: str) -> Optional[str]:
        """GetSnapshotUri → HTTP snapshot URL."""
        self.log(f"ONVIF → GetSnapshotUri (token={profile_token})", "info")
        soap = SOAP_GET_SNAPSHOT_URI.format(token=profile_token)
        resp = self._post(soap)
        if resp is None or resp.status_code != 200:
            return None
        m = re.search(r"<tt:Uri>(.*?)</tt:Uri>", resp.text)
        return m.group(1) if m else None


# ────────────────────────────────────────────────────────────
# RTSP / RTSPS Client
# ────────────────────────────────────────────────────────────
class RTSPClient:
    """Test RTSP/RTSPS Digest auth via socket handshake."""

    def __init__(self, url, username="admin", password="",
                 auth_mode="standard", algorithm="auto", quote_algo=False, absolute_uri=True,
                 log_func=None):
        self.url = url
        self.username = username
        self.password = password
        self.auth_mode = auth_mode
        self.algorithm = algorithm
        self.quote_algo = quote_algo
        self.absolute_uri = absolute_uri
        self.log = log_func or print

        parsed = urlparse(url)
        self.host = parsed.hostname
        self.port = parsed.port or (322 if parsed.scheme == "rtsps" else 554)
        self.path = parsed.path or "/"
        self.is_tls = parsed.scheme == "rtsps"

    def _connect(self) -> socket.socket:
        """Create socket, optionally wrapped with TLS."""
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(5)
        raw.connect((self.host, self.port))
        if self.is_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx.wrap_socket(raw, server_hostname=self.host)
        return raw

    def _send_describe(self, sock, cseq=1, auth_header=None) -> str:
        """Send DESCRIBE request, return raw response text."""
        lines = [
            f"DESCRIBE {self.url} RTSP/1.0",
            f"CSeq: {cseq}",
            "User-Agent: MyoVIF/1.0",
        ]
        if auth_header:
            lines.append(f"Authorization: {auth_header}")
        lines.append("")
        lines.append("")
        sock.sendall("\r\n".join(lines).encode())

        resp = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"\r\n\r\n" in resp:
                    break
        except socket.timeout:
            pass
        return resp.decode("utf-8", errors="replace")

    def _build_auth_from_challenge(self, challenge_line: str, method="DESCRIBE") -> str:
        """Build Authorization header from challenge (standard or custom)."""
        params = {}
        for m in re.finditer(r'(\w+)="?([^",]+)"?', challenge_line):
            params[m.group(1)] = m.group(2)

        realm = params.get("realm", "")
        nonce = params.get("nonce", "")
        qop = params.get("qop", "")
        server_algo = params.get("algorithm", "MD5")
        opaque = params.get("opaque", "")

        if self.auth_mode == "custom" and self.algorithm != "auto":
            algo = self.algorithm
        else:
            algo = server_algo

        _, algo_name = get_hash_func(algo)

        nc = cnonce = None
        if qop:
            nc = "00000001"
            cnonce = hashlib.sha256(os.urandom(16)).hexdigest()[:8]

        uri_in_digest = self.url if self.absolute_uri else self.path

        _, _, response = compute_digest_response(
            algo_name, self.username, realm, self.password,
            method, uri_in_digest, nonce, qop, nc, cnonce
        )

        use_quote = self.quote_algo if self.auth_mode == "custom" else False
        return build_digest_header(
            self.username, realm, nonce, uri_in_digest, algo_name, response,
            qop, nc, cnonce, opaque, quote_algo=use_quote
        )

    def test_auth(self) -> dict:
        """Test RTSP/RTSPS digest auth. Returns {status, details}."""
        proto = "RTSPS" if self.is_tls else "RTSP"
        self.log(f"{proto} → {self.url}", "info")
        self.log(f"Mode: {self.auth_mode.upper()}", "info")

        result = {"status": None, "challenge": None, "sdp": None}

        # Step 1: DESCRIBE without auth
        try:
            sock = self._connect()
        except Exception as e:
            self.log(f"Connection failed: {e}", "error")
            result["status"] = "CONNECTION_ERROR"
            return result

        resp1 = self._send_describe(sock, cseq=1)
        sock.close()

        if not resp1:
            self.log("No response from camera", "error")
            result["status"] = "NO_RESPONSE"
            return result

        # Check if no auth needed
        if "200 OK" in resp1:
            self.log(f"{proto} NO AUTH REQUIRED — 200 OK", "success")
            result["status"] = "200"
            return result

        if "401" not in resp1:
            status_m = re.match(r"RTSP/1\.\d (\d+)", resp1)
            code = status_m.group(1) if status_m else "UNKNOWN"
            self.log(f"{proto} unexpected response: {code}", "warning")
            result["status"] = code
            return result

        # Step 2: Parse challenge
        auth_match = re.search(r"WWW-Authenticate: Digest (.*)", resp1)
        if not auth_match:
            # Check for Basic auth
            basic_match = re.search(r"WWW-Authenticate: Basic", resp1)
            if basic_match:
                self.log("Camera uses Basic auth (not Digest)", "warning")
                result["status"] = "BASIC_AUTH"
                return result
            self.log("No Digest challenge found", "error")
            result["status"] = "NO_CHALLENGE"
            return result

        challenge = auth_match.group(1)
        result["challenge"] = challenge
        self.log(f"Challenge: {challenge[:80]}...", "info")

        # Step 3: Build auth and re-request
        auth_header = self._build_auth_from_challenge(challenge)

        try:
            sock2 = self._connect()
        except Exception as e:
            self.log(f"Reconnection failed: {e}", "error")
            result["status"] = "CONNECTION_ERROR"
            return result

        resp2 = self._send_describe(sock2, cseq=2, auth_header=auth_header)
        sock2.close()

        status_m = re.match(r"RTSP/1\.\d (\d+)", resp2)
        code = status_m.group(1) if status_m else "UNKNOWN"
        result["status"] = code

        if code == "200":
            self.log(f"{proto} AUTH SUCCESS", "success")
            # Extract SDP if present
            if "\r\n\r\n" in resp2:
                result["sdp"] = resp2.split("\r\n\r\n", 1)[1]
        else:
            self.log(f"{proto} AUTH FAILED ({code})", "error")

        return result


# ────────────────────────────────────────────────────────────
# WS-Discovery
# ────────────────────────────────────────────────────────────
WS_DISCOVERY_MULTICAST = ("239.255.255.250", 3702)

WS_DISCOVERY_PROBE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:tns="http://schemas.xmlsoap.org/ws/2005/04/discovery"
  xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <soap:Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
  </soap:Header>
  <soap:Body>
    <tns:Probe>
      <tns:Types>dn:NetworkVideoTransmitter</tns:Types>
    </tns:Probe>
  </soap:Body>
</soap:Envelope>"""


def discover_devices(timeout=3, log_func=None) -> list[dict]:
    """WS-Discovery multicast probe for ONVIF cameras on LAN.

    Returns list of dicts: {ip, port, scopes, xaddrs, raw_xml}.
    """
    log = log_func or print
    log("WS-Discovery probe → 239.255.255.250:3702", "info")

    msg_id = str(uuid.uuid4())
    probe = WS_DISCOVERY_PROBE.format(msg_id=msg_id).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)

    try:
        sock.sendto(probe, WS_DISCOVERY_MULTICAST)
    except Exception as e:
        log(f"Failed to send probe: {e}", "error")
        sock.close()
        return []

    devices = []
    seen_ips = set()

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            resp_text = data.decode("utf-8", errors="replace")
            ip = addr[0]

            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            # Extract XAddrs (ONVIF service URL)
            xaddrs_m = re.search(r"<[^>]*XAddrs[^>]*>(.*?)</", resp_text)
            xaddrs = xaddrs_m.group(1).strip() if xaddrs_m else ""

            # Extract Scopes
            scopes_m = re.search(r"<[^>]*Scopes[^>]*>(.*?)</", resp_text)
            scopes = scopes_m.group(1).strip() if scopes_m else ""

            # Parse port from xaddrs
            port = 80
            if xaddrs:
                xaddr_parsed = urlparse(xaddrs.split()[0])
                port = xaddr_parsed.port or 80

            # Try to extract model/name from scopes
            model = ""
            for scope in scopes.split():
                if "hardware" in scope.lower():
                    model = scope.rsplit("/", 1)[-1] if "/" in scope else scope
                elif "name" in scope.lower():
                    model = model or scope.rsplit("/", 1)[-1]

            device = {
                "ip": ip,
                "port": port,
                "xaddrs": xaddrs,
                "scopes": scopes,
                "model": model,
            }
            devices.append(device)
            log(f"Found: {ip}:{port} ({model or 'unknown'})", "success")

        except socket.timeout:
            break
        except Exception as e:
            log(f"Discovery error: {e}", "warning")
            break

    sock.close()
    log(f"Discovery complete — {len(devices)} device(s) found", "info")
    return devices
