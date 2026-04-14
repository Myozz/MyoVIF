#!/usr/bin/env python3
"""
RTSP Auth Test - Hikvision vs Tapo C200
=========================================
Test SHA-256 Digest Auth tren nhieu camera.
"""
import hashlib
import os
import re
import socket
import base64

def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def rtsp_exchange(sock, lines):
    """Send RTSP, return (code, headers, body)."""
    req = "\r\n".join(lines) + "\r\n\r\n"
    sock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk: break
        resp += chunk
    hdr = resp.split(b"\r\n\r\n")[0].decode('utf-8', errors='replace')
    body = resp[resp.find(b"\r\n\r\n")+4:]
    for line in hdr.split("\r\n"):
        if line.lower().startswith("content-length"):
            clen = int(line.split(":")[1].strip())
            while len(body) < clen:
                body += sock.recv(4096)
    code = hdr.split("\r\n")[0].split(" ")[1] if " " in hdr.split("\r\n")[0] else "?"
    return code, hdr, body.decode('utf-8', errors='replace')


def test_camera(label, host, port, path, username, password):
    """Full RTSP auth test for a camera."""
    url = f"rtsp://{host}:{port}{path}"
    
    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"  URL: {url}")
    print(f"  User: {username}")
    print(f"{'='*70}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        print(f"\n  [1] TCP Connected to {host}:{port}")
    except Exception as e:
        print(f"\n  [FAIL] Cannot connect: {e}")
        return
    
    # OPTIONS
    code1, hdr1, _ = rtsp_exchange(sock, [
        f"OPTIONS {url} RTSP/1.0",
        "CSeq: 1",
        "User-Agent: Mozilla/5.0",
    ])
    print(f"\n  [2] OPTIONS -> {code1}")
    for line in hdr1.split("\r\n"):
        if line.lower().startswith("public:"):
            print(f"      Methods: {line.split(': ', 1)[1]}")
    
    # DESCRIBE without auth
    code2, hdr2, _ = rtsp_exchange(sock, [
        f"DESCRIBE {url} RTSP/1.0",
        "Accept: application/sdp",
        "CSeq: 2",
        "User-Agent: Mozilla/5.0",
    ])
    print(f"\n  [3] DESCRIBE (no auth) -> {code2}")
    
    if code2 != "401":
        if code2 == "200":
            print(f"      No auth required!")
        else:
            print(f"      Unexpected status: {code2}")
        sock.close()
        return
    
    # Parse ALL challenges
    challenges = []
    for line in hdr2.split("\r\n"):
        if line.lower().startswith("www-authenticate:"):
            val = line.split(": ", 1)[1]
            challenges.append(val)
            print(f"      {val}")
    
    # Parse Digest challenge
    digest_line = ""
    for c in challenges:
        if 'digest' in c.lower():
            digest_line = c
            break
    
    if not digest_line:
        print(f"      No Digest challenge found!")
        sock.close()
        return
    
    params = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]+)"|([^\s,]+))', digest_line):
        params[m.group(1).lower()] = m.group(2) if m.group(2) is not None else m.group(3)
    
    realm = params.get('realm', '')
    nonce = params.get('nonce', '')
    qop = params.get('qop', '')
    opaque = params.get('opaque', '')
    algo = params.get('algorithm', 'MD5')
    
    print(f"\n  [4] Digest Challenge:")
    print(f"      algorithm = {algo}")
    print(f"      realm     = {realm}")
    print(f"      nonce     = {nonce}")
    print(f"      qop       = '{qop}' {'(NONE)' if not qop else ''}")
    print(f"      opaque    = '{opaque}' {'(NONE)' if not opaque else ''}")
    
    # Determine hash function
    if 'sha-256' in algo.lower() or 'sha256' in algo.lower():
        hash_func = hashlib.sha256
        algo_name = 'SHA-256'
        print(f"      -> Using SHA-256")
    else:
        hash_func = hashlib.md5
        algo_name = 'MD5'
        print(f"      -> Using MD5")
    
    # Compute digest
    ha1 = hash_func(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hash_func(f"DESCRIBE:{url}".encode()).hexdigest()
    
    print(f"\n  [5] Digest Computation:")
    print(f"      HA1 = {algo_name}({username}:{realm}:***)")
    print(f"          = {ha1}")
    print(f"      HA2 = {algo_name}(DESCRIBE:{url})")
    print(f"          = {ha2}")
    
    if qop:
        nc = "00000001"
        cnonce = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
        response = hash_func(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
        print(f"      nc     = {nc}")
        print(f"      cnonce = {cnonce}")
        print(f"      response = {algo_name}(HA1:{nonce}:{nc}:{cnonce}:{qop}:HA2)")
        print(f"               = {response}")
        
        auth_parts = [
            f'username="{username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{url}"',
            f'algorithm="{algo_name}"',
            f'response="{response}"',
            f'qop={qop}',
            f'nc={nc}',
            f'cnonce="{cnonce}"',
        ]
    else:
        response = hash_func(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        print(f"      response = {algo_name}(HA1:{nonce}:HA2)")
        print(f"               = {response}")
        
        auth_parts = [
            f'username="{username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{url}"',
            f'algorithm="{algo_name}"',
            f'response="{response}"',
        ]
    
    if opaque:
        auth_parts.append(f'opaque="{opaque}"')
    
    auth_header = 'Digest ' + ', '.join(auth_parts)
    print(f"      len(response) = {len(response)} chars")
    
    # DESCRIBE with auth
    code3, hdr3, body3 = rtsp_exchange(sock, [
        f"DESCRIBE {url} RTSP/1.0",
        "Accept: application/sdp",
        "CSeq: 3",
        "User-Agent: Mozilla/5.0",
        f"Authorization: {auth_header}",
    ])
    
    print(f"\n  [6] DESCRIBE (auth) -> {code3}")
    
    if code3 == "200":
        print(f"\n  >>> {algo_name} DIGEST AUTH: THANH CONG <<<")
        print(f"\n  SDP ({len(body3)} bytes):")
        for line in body3.strip().split('\n')[:15]:
            print(f"      {line.strip()}")
        if len(body3.strip().split('\n')) > 15:
            print(f"      ... (truncated)")
    else:
        print(f"\n  >>> {algo_name} DIGEST AUTH: THAT BAI ({code3}) <<<")
        for line in hdr3.split("\r\n"):
            if line.strip():
                print(f"      {line}")
    
    sock.close()
    return code3


# ============================================================
# MAIN
# ============================================================
if __name__ == '__main__':
    from datetime import datetime
    
    print(f"\n{'='*70}")
    print(f"  MULTI-CAMERA RTSP AUTHENTICATION TEST")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}")
    
    results = []
    
    # Camera 1: Tapo C200
    r1 = test_camera(
        label="Camera 1: TP-Link Tapo C200",
        host="192.168.137.246",
        port=554,
        path="/stream2",
        username="psitest135",
        password="psitest135",
    )
    results.append(("Tapo C200 /stream2", r1))
    
    # Camera 2: Hikvision
    r2 = test_camera(
        label="Camera 2: Hikvision",
        host="192.168.66.231",
        port=554,
        path="/Streaming/Channels/101",
        username="admin",
        password="psitest135",
    )
    results.append(("Hikvision /101", r2))
    
    # Summary
    print(f"\n{'='*70}")
    print(f"  SUMMARY")
    print(f"{'='*70}")
    for name, code in results:
        status = "PASS" if code == "200" else f"FAIL ({code})"
        print(f"  {name:30s} : {status}")
    print()
