#!/usr/bin/env python3
"""
RTSP Client with SHA-256 Digest Authentication
================================================
ffmpeg/OpenCV chi ho tro MD5 digest cho RTSP.
Camera Tapo C200 yeu cau SHA-256.

Module nay implement RTSP handshake (DESCRIBE, SETUP, PLAY)
voi SHA-256 digest auth, roi doc RTP data va decode bang OpenCV.

Flow:
  1. DESCRIBE -> 401 -> parse challenge -> DESCRIBE voi SHA-256 auth
  2. SETUP -> tao RTP session
  3. PLAY -> nhan video frames
"""

import hashlib
import os
import re
import socket
import struct
import time
import threading
from urllib.parse import urlparse


class RTSPSha256Client:
    """RTSP client that supports SHA-256 Digest Authentication."""

    def __init__(self, url, username, password):
        """
        Args:
            url: RTSP URL (rtsp://host:port/path)
            username: Auth username
            password: Auth password
        """
        parsed = urlparse(url)
        self.host = parsed.hostname
        self.port = parsed.port or 554
        self.path = parsed.path or '/'
        self.username = username
        self.password = password
        self.url = f"rtsp://{self.host}:{self.port}{self.path}"

        self.cseq = 0
        self.session_id = None
        self.sock = None
        self.transport_port = None

        # Auth state
        self.realm = ''
        self.nonce = ''
        self.opaque = ''
        self.nc = 0

    def connect(self):
        """Connect TCP socket to RTSP server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.host, self.port))

    def close(self):
        """Close connection."""
        if self.sock:
            try:
                self._send_request("TEARDOWN", self.url)
            except Exception:
                pass
            self.sock.close()
            self.sock = None

    def _next_cseq(self):
        self.cseq += 1
        return self.cseq

    def _compute_digest(self, method, uri):
        """Compute SHA-256 digest response."""
        self.nc += 1
        nc = f"{self.nc:08x}"
        cnonce = hashlib.sha256(os.urandom(32)).hexdigest()[:16]

        ha1 = hashlib.sha256(f"{self.username}:{self.realm}:{self.password}".encode()).hexdigest()
        ha2 = hashlib.sha256(f"{method}:{uri}".encode()).hexdigest()
        response = hashlib.sha256(
            f"{ha1}:{self.nonce}:{nc}:{cnonce}:auth:{ha2}".encode()
        ).hexdigest()

        parts = [
            f'username="{self.username}"',
            f'realm="{self.realm}"',
            f'nonce="{self.nonce}"',
            f'uri="{uri}"',
            f'algorithm=SHA-256',
            f'response="{response}"',
            f'qop=auth',
            f'nc={nc}',
            f'cnonce="{cnonce}"',
        ]
        if self.opaque:
            parts.append(f'opaque="{self.opaque}"')

        return 'Digest ' + ', '.join(parts)

    def _parse_auth_challenge(self, headers):
        """Parse WWW-Authenticate header from RTSP response."""
        www_auth = headers.get('www-authenticate', '')
        if not www_auth:
            return False

        if www_auth.lower().startswith('digest '):
            www_auth = www_auth[7:]

        params = {}
        for m in re.finditer(r'(\w+)=(?:"([^"]+)"|([^\s,]+))', www_auth):
            params[m.group(1).lower()] = m.group(2) if m.group(2) is not None else m.group(3)

        self.realm = params.get('realm', '')
        self.nonce = params.get('nonce', '')
        self.opaque = params.get('opaque', '')
        self.nc = 0
        return True

    def _send_request(self, method, uri, extra_headers=None):
        """Send an RTSP request and return (status_code, headers, body)."""
        cseq = self._next_cseq()

        lines = [
            f"{method} {uri} RTSP/1.0",
            f"CSeq: {cseq}",
            f"User-Agent: PythonRTSP/1.0",
        ]

        if self.session_id:
            lines.append(f"Session: {self.session_id}")

        if self.nonce:  # We have auth challenge
            auth = self._compute_digest(method, uri)
            lines.append(f"Authorization: {auth}")

        if extra_headers:
            for k, v in extra_headers.items():
                lines.append(f"{k}: {v}")

        lines.append("")
        lines.append("")

        request = "\r\n".join(lines)
        self.sock.sendall(request.encode())

        # Read response
        return self._read_response()

    def _read_response(self):
        """Read and parse RTSP response."""
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data += chunk

        header_end = data.find(b"\r\n\r\n")
        header_data = data[:header_end].decode('utf-8', errors='replace')
        body = data[header_end + 4:]

        lines = header_data.split("\r\n")
        status_line = lines[0]
        # Parse "RTSP/1.0 200 OK"
        parts = status_line.split(" ", 2)
        status_code = int(parts[1]) if len(parts) >= 2 else 0

        headers = {}
        for line in lines[1:]:
            if ': ' in line:
                k, v = line.split(': ', 1)
                headers[k.lower()] = v

        # Read body if Content-Length present
        content_length = int(headers.get('content-length', 0))
        while len(body) < content_length:
            body += self.sock.recv(4096)

        return status_code, headers, body.decode('utf-8', errors='replace')

    def describe(self):
        """Send DESCRIBE request with SHA-256 auth."""
        # First attempt - expect 401
        status, headers, body = self._send_request("DESCRIBE", self.url,
                                                     {"Accept": "application/sdp"})

        if status == 401:
            if self._parse_auth_challenge(headers):
                # Retry with auth
                status, headers, body = self._send_request("DESCRIBE", self.url,
                                                             {"Accept": "application/sdp"})

        return status, headers, body

    def setup(self, track_url, client_port=5000):
        """Send SETUP request."""
        self.transport_port = client_port
        transport = f"RTP/AVP/TCP;unicast;interleaved=0-1"

        status, headers, body = self._send_request(
            "SETUP", track_url,
            {"Transport": transport}
        )

        if status == 401:
            if self._parse_auth_challenge(headers):
                status, headers, body = self._send_request(
                    "SETUP", track_url,
                    {"Transport": transport}
                )

        if status == 200:
            session = headers.get('session', '')
            self.session_id = session.split(';')[0].strip()

        return status, headers, body

    def play(self):
        """Send PLAY request."""
        status, headers, body = self._send_request(
            "PLAY", self.url,
            {"Range": "npt=0.000-"}
        )

        if status == 401:
            if self._parse_auth_challenge(headers):
                status, headers, body = self._send_request(
                    "PLAY", self.url,
                    {"Range": "npt=0.000-"}
                )

        return status, headers, body

    def read_rtp_frame(self):
        """Read interleaved RTP data from TCP."""
        # RTSP interleaved format: $<channel><length><data>
        header = self._recv_exact(4)
        if not header or header[0:1] != b'$':
            return None, None

        channel = header[1]
        length = struct.unpack('>H', header[2:4])[0]
        data = self._recv_exact(length)
        return channel, data

    def _recv_exact(self, n):
        """Receive exactly n bytes."""
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data


def test_rtsp_sha256(host, port, username, password, stream_path="/stream2"):
    """Test RTSP connection with SHA-256 auth."""
    url = f"rtsp://{host}:{port}{stream_path}"
    print(f"\n  Testing RTSP SHA-256: {url}")

    client = RTSPSha256Client(url, username, password)

    try:
        print("  [1] Connecting...")
        client.connect()

        print("  [2] DESCRIBE...")
        status, headers, body = client.describe()
        print(f"      Status: {status}")

        if status == 200:
            print(f"      [PASS] RTSP DESCRIBE thanh cong!")
            # Parse SDP to find track
            print(f"      SDP ({len(body)} bytes):")
            for line in body.strip().split('\n')[:15]:
                print(f"        {line.strip()}")

            # Find track URL from SDP
            track_url = None
            for line in body.split('\n'):
                line = line.strip()
                if line.startswith('a=control:'):
                    track = line.split(':', 1)[1].strip()
                    if track.startswith('rtsp://'):
                        track_url = track
                    elif track != '*':
                        track_url = f"{url}/{track}"

            if track_url:
                print(f"\n  [3] SETUP {track_url}...")
                status2, headers2, body2 = client.setup(track_url)
                print(f"      Status: {status2}")
                if status2 == 200:
                    print(f"      Session: {client.session_id}")
                    print(f"      [PASS] SETUP thanh cong!")

                    print(f"\n  [4] PLAY...")
                    status3, headers3, body3 = client.play()
                    print(f"      Status: {status3}")
                    if status3 == 200:
                        print(f"      [PASS] PLAY thanh cong! Stream dang chay.")

                        # Read a few RTP packets
                        print(f"\n  [5] Doc RTP packets...")
                        for i in range(5):
                            ch, data = client.read_rtp_frame()
                            if data:
                                print(f"      Packet {i+1}: channel={ch}, size={len(data)} bytes")
                            else:
                                print(f"      Packet {i+1}: no data")
                                break

                        return True
                    else:
                        print(f"      [FAIL] PLAY that bai")
                else:
                    print(f"      [FAIL] SETUP that bai")
            else:
                print("      [WARN] Khong tim thay track URL trong SDP")
        else:
            print(f"      [FAIL] DESCRIBE that bai: {status}")
            if body:
                print(f"      Body: {body[:200]}")

        return False

    except Exception as e:
        print(f"      [ERROR] {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()


if __name__ == '__main__':
    print("=" * 60)
    print("  RTSP SHA-256 Digest Authentication Test")
    print("=" * 60)

    results = {}
    for stream in ['/stream2', '/stream1', '/stream8']:
        ok = test_rtsp_sha256(
            "192.168.137.246", 554,
            "psitest135", "psitest135",
            stream
        )
        results[stream] = ok
        if ok:
            break  # Thanh cong 1 stream la du

    print(f"\n{'='*60}")
    print("  RTSP Results:")
    for stream, ok in results.items():
        print(f"  {stream}: {'PASS' if ok else 'FAIL'}")
    print()
