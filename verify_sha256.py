#!/usr/bin/env python3
"""
SHA-256 Digest Authentication Verification Tool
=================================================
Test HTTP Digest Auth (ONVIF) va RTSP Digest Auth tren nhieu camera.

Usage:
  # Test ca ONVIF + RTSP tren Tapo C200
  python verify_sha256.py -u psitest135 -p psitest135 \
    --onvif http://192.168.137.246:2020/onvif/device_service \
    --rtsp rtsp://192.168.137.246:554/stream2

  # Chi test RTSP tren Hikvision
  python verify_sha256.py -u admin -p psitest135 \
    --rtsp rtsp://192.168.66.231:554/Streaming/Channels/101

  # Test RTSP voi MD5 (override algorithm)
  python verify_sha256.py -u admin -p admin123 \
    --rtsp rtsp://192.168.1.100:554/stream1 --algorithm MD5

  # Test voi qop bat buoc
  python verify_sha256.py -u admin -p admin \
    --rtsp rtsp://192.168.1.100:554/stream1 --qop auth

  # Test nhieu camera lien tiep
  python verify_sha256.py --batch cameras.txt

  # Presets co san
  python verify_sha256.py --preset tapo
  python verify_sha256.py --preset hikvision
"""

import argparse
import hashlib
import os
import re
import socket
import base64
import sys
import json
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

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
                      qop=None, nc=None, cnonce=None, opaque=None):
    """Build Authorization: Digest header string."""
    parts = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'algorithm={algo_name}',
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
               verbose=True):
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
        qop, nc, cnonce, opaque)

    hdrs2 = dict(hdrs)
    hdrs2['Authorization'] = auth_header
    resp2 = requests.post(url, data=soap, headers=hdrs2, timeout=5)

    print(f"\n  [5] Result: HTTP {resp2.status_code}")

    if resp2.status_code == 200:
        print(f"      >>> ONVIF {algo_name} AUTH: THANH CONG <<<")
        body = resp2.text
        for tag in ['Manufacturer', 'Model', 'FirmwareVersion',
                     'SerialNumber', 'HardwareId']:
            m = re.search(f'<[^>]*{tag}>([^<]+)<', body)
            if m:
                print(f"      {tag}: {m.group(1)}")
    else:
        print(f"      >>> ONVIF {algo_name} AUTH: THAT BAI <<<")

    return str(resp2.status_code)


# ============================================================
# TEST: RTSP
# ============================================================
def test_rtsp(url, username, password, force_algo=None, force_qop=None,
              verbose=True):
    """Test RTSP Digest Auth."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 554

    print(f"\n  [1] TCP Connect {host}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)

    try:
        sock.connect((host, port))
        print(f"      Connected")
    except Exception as e:
        print(f"      [FAIL] {e}")
        return None

    try:
        # OPTIONS
        code1, hdr1, _ = rtsp_send_recv(sock, [
            f"OPTIONS {url} RTSP/1.0",
            "CSeq: 1",
            "User-Agent: Mozilla/5.0",
        ])
        print(f"\n  [2] OPTIONS -> {code1}")
        for line in hdr1.split("\r\n"):
            if line.lower().startswith("public:"):
                print(f"      Methods: {line.split(': ', 1)[1]}")

        # DESCRIBE without auth
        code2, hdr2, _ = rtsp_send_recv(sock, [
            f"DESCRIBE {url} RTSP/1.0",
            "Accept: application/sdp",
            "CSeq: 2",
            "User-Agent: Mozilla/5.0",
        ])
        print(f"\n  [3] DESCRIBE (no auth) -> {code2}")

        if code2 != "401":
            if code2 == "200":
                print(f"      No auth required")
            return code2

        # Parse challenges
        digest_line = ""
        for line in hdr2.split("\r\n"):
            if line.lower().startswith("www-authenticate:"):
                val = line.split(": ", 1)[1]
                print(f"      {val}")
                if 'digest' in val.lower():
                    digest_line = val

        params = parse_digest_challenge(digest_line)
        realm = params.get('realm', '')
        nonce = params.get('nonce', '')
        qop = force_qop or params.get('qop', '')
        opaque = params.get('opaque', '')
        algo = force_algo or params.get('algorithm', 'MD5')

        hash_func, algo_name = get_hash_func(algo)

        print(f"\n  [4] Parsed challenge:")
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
            hash_func, username, realm, password, "DESCRIBE", url,
            nonce, qop, nc, cnonce)

        if verbose:
            print(f"\n  [5] Computation ({algo_name}):")
            print(f"      HA1 = {algo_name}({username}:{realm}:***) = {ha1}")
            print(f"      HA2 = {algo_name}(DESCRIBE:{url}) = {ha2}")
            if qop:
                print(f"      response = {algo_name}(HA1:{nonce}:{nc}:{cnonce}:{qop}:HA2)")
            else:
                print(f"      response = {algo_name}(HA1:{nonce}:HA2)")
            print(f"               = {response}")
            print(f"      len = {len(response)} chars")

        auth_header = build_auth_header(
            username, realm, nonce, url, algo_name, response,
            qop, nc, cnonce, opaque)

        # DESCRIBE with auth
        code3, hdr3, body3 = rtsp_send_recv(sock, [
            f"DESCRIBE {url} RTSP/1.0",
            "Accept: application/sdp",
            "CSeq: 3",
            "User-Agent: Mozilla/5.0",
            f"Authorization: {auth_header}",
        ])

        print(f"\n  [6] DESCRIBE (auth) -> {code3}")

        if code3 == "200":
            print(f"\n      >>> RTSP {algo_name} AUTH: THANH CONG <<<")
            print(f"\n      SDP ({len(body3)} bytes):")
            for line in body3.strip().split('\n')[:15]:
                print(f"        {line.strip()}")
            if len(body3.strip().split('\n')) > 15:
                print(f"        ... (truncated)")
        else:
            print(f"\n      >>> RTSP {algo_name} AUTH: THAT BAI ({code3}) <<<")
            for line in hdr3.split("\r\n")[:6]:
                if line.strip():
                    print(f"        {line}")

        return code3

    except Exception as e:
        print(f"      [ERROR] {e}")
        return None
    finally:
        sock.close()


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

    # Header
    print(f"\n{'='*70}")
    print(f"  SHA-256 DIGEST AUTHENTICATION VERIFICATION TOOL")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}")

    results = []

    # Batch mode
    if args.batch:
        results = run_batch(args.batch)

    # All presets
    elif args.all_presets:
        for name, preset in PRESETS.items():
            print(f"\n{'='*70}")
            print(f"  PRESET: {name} - {preset['label']}")
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

    # Preset mode
    elif args.preset:
        preset = PRESETS[args.preset]
        username = args.username or preset['username']
        password = args.password or preset['password']
        onvif_url = args.onvif or preset.get('onvif')
        rtsp_url = args.rtsp or preset.get('rtsp')

        print(f"\n  Preset: {args.preset} ({preset['label']})")
        print(f"  User:   {username}")

        if onvif_url:
            print(f"\n{'='*70}")
            print(f"  ONVIF: {onvif_url}")
            print(f"{'='*70}")
            r = test_onvif(onvif_url, username, password,
                           args.algorithm, args.qop,
                           verbose=not args.quiet)
            results.append((f"{preset['label']} ONVIF", r))

        if rtsp_url:
            print(f"\n{'='*70}")
            print(f"  RTSP: {rtsp_url}")
            print(f"{'='*70}")
            r = test_rtsp(rtsp_url, username, password,
                          args.algorithm, args.qop,
                          verbose=not args.quiet)
            results.append((f"{preset['label']} RTSP", r))

    # Manual mode
    elif args.onvif or args.rtsp:
        if not args.username or not args.password:
            parser.error("--username and --password required")

        if args.onvif:
            print(f"\n{'='*70}")
            print(f"  ONVIF: {args.onvif}")
            print(f"{'='*70}")
            r = test_onvif(args.onvif, args.username, args.password,
                           args.algorithm, args.qop,
                           verbose=not args.quiet)
            results.append(("ONVIF", r))

        if args.rtsp:
            print(f"\n{'='*70}")
            print(f"  RTSP: {args.rtsp}")
            print(f"{'='*70}")
            r = test_rtsp(args.rtsp, args.username, args.password,
                          args.algorithm, args.qop,
                          verbose=not args.quiet)
            results.append(("RTSP", r))

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
        print(f"\n{'='*70}")
        print(f"  SUMMARY")
        print(f"{'='*70}")
        print(f"  +{'-'*35}+{'-'*10}+")
        print(f"  | {'Test':<33} | {'Result':<8} |")
        print(f"  +{'-'*35}+{'-'*10}+")
        for name, code in results:
            if code == "200":
                status = "PASS"
            elif code is None:
                status = "ERROR"
            else:
                status = f"FAIL {code}"
            print(f"  | {name:<33} | {status:<8} |")
        print(f"  +{'-'*35}+{'-'*10}+")

        all_pass = all(code == "200" for _, code in results)
        if all_pass:
            print(f"\n  >>> TAT CA XAC THUC THANH CONG <<<")

        if args.json:
            json_out = [{"test": n, "status": c} for n, c in results]
            print(f"\n{json.dumps(json_out, indent=2)}")

    print(f"\n  SHA-256 Formula (RFC 7616):")
    print(f"    HA1 = HASH(username:realm:password)")
    print(f"    HA2 = HASH(method:uri)")
    print(f"    With qop:    response = HASH(HA1:nonce:nc:cnonce:qop:HA2)")
    print(f"    Without qop: response = HASH(HA1:nonce:HA2)")
    print()


if __name__ == '__main__':
    main()
