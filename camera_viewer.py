#!/usr/bin/env python3
"""
ONVIF/RTSP Camera Tester & Video Preview
==========================================
Test ket noi tren ca 2 port:
  - Port 2020: ONVIF (SOAP + SHA-256 Digest Auth)
  - Port 554:  RTSP  (Video Stream)

Features:
  - Test ONVIF device info, profiles, stream URIs
  - Test RTSP connectivity + capture snapshot
  - Web preview video stream (Flask + ffmpeg)

Usage:
  python camera_viewer.py test              # Test ca 2 port
  python camera_viewer.py snapshot           # Chup anh tu RTSP
  python camera_viewer.py preview            # Mo web preview video
  python camera_viewer.py preview --stream 2 # Preview stream2 (720p)
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
import threading
import time
import signal
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[!] Can cai requests: pip install requests")
    sys.exit(1)

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

try:
    from flask import Flask, Response
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

# Import SHA256DigestAuth
try:
    from onvif_sha256 import SHA256DigestAuth, ONVIFClient
except ImportError:
    print("[!] Can file onvif_sha256.py trong cung thu muc")
    sys.exit(1)


# ============================================================
# Configuration
# ============================================================
DEFAULT_HOST = "192.168.137.246"
DEFAULT_ONVIF_PORT = 2020
DEFAULT_RTSP_PORT = 554
DEFAULT_USERNAME = "psitest135"
DEFAULT_PASSWORD = "psitest135"

RTSP_STREAMS = {
    1: {"path": "/stream1", "name": "mainStream",  "res": "1920x1080"},
    2: {"path": "/stream2", "name": "minorStream", "res": "1280x720"},
    8: {"path": "/stream8", "name": "jpegStream",  "res": "640x360"},
}


# ============================================================
# Port Testing
# ============================================================
def test_port(host, port, timeout=3):
    """Test if a TCP port is open."""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def test_onvif(host, port, username, password):
    """Test ONVIF connection on port 2020."""
    print(f"\n{'='*60}")
    print(f"  TEST ONVIF - http://{host}:{port}/onvif/device_service")
    print(f"{'='*60}")

    # 1. Port check
    print(f"\n  [1] Kiem tra port {port}...", end=" ")
    if test_port(host, port):
        print("OPEN")
    else:
        print("CLOSED/TIMEOUT")
        return False

    # 2. ONVIF GetDeviceInformation
    print(f"  [2] ONVIF GetDeviceInformation (SHA-256 Digest)...")
    try:
        client = ONVIFClient(host, port, username, password, force_sha256=True)
        info = client.get_device_information()
        if info:
            print(f"      [PASS] Camera responded!")
            for k, v in info.items():
                print(f"        {k}: {v}")
        else:
            print(f"      [WARN] Empty response")
    except Exception as e:
        print(f"      [FAIL] {e}")
        return False

    # 3. Get Profiles
    print(f"  [3] ONVIF GetProfiles...")
    try:
        client.get_capabilities()
        profiles = client.get_profiles()
        if profiles:
            for p in profiles:
                print(f"      {p['name']} ({p['token']}) - {p['resolution']}")
        else:
            print(f"      [WARN] Khong lay duoc profiles")
    except Exception as e:
        print(f"      [FAIL] {e}")

    # 4. Get Stream URIs
    print(f"  [4] ONVIF GetStreamUri...")
    try:
        for p in profiles:
            uri = client.get_stream_uri(p['token'])
            if uri:
                print(f"      {p['name']}: {uri}")
    except Exception as e:
        print(f"      [FAIL] {e}")

    return True


def test_rtsp(host, port, username, password, stream_num=1):
    """Test RTSP connection on port 554."""
    print(f"\n{'='*60}")
    print(f"  TEST RTSP - rtsp://{host}:{port}")
    print(f"{'='*60}")

    # 1. Port check
    print(f"\n  [1] Kiem tra port {port}...", end=" ")
    if test_port(host, port):
        print("OPEN")
    else:
        print("CLOSED/TIMEOUT")
        return False

    # 2. Test each stream
    results = {}
    for snum, sinfo in RTSP_STREAMS.items():
        rtsp_url = f"rtsp://{username}:{password}@{host}:{port}{sinfo['path']}"
        rtsp_display = f"rtsp://{host}:{port}{sinfo['path']}"
        print(f"\n  [2.{snum}] Test {sinfo['name']} ({sinfo['res']}) - {rtsp_display}")

        if HAS_CV2:
            # Test with OpenCV
            cap = cv2.VideoCapture(rtsp_url, cv2.CAP_FFMPEG)
            cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 5000)
            cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, 5000)

            if cap.isOpened():
                ret, frame = cap.read()
                if ret and frame is not None:
                    h, w = frame.shape[:2]
                    print(f"        [PASS] Connected! Frame: {w}x{h}")
                    results[snum] = True
                else:
                    print(f"        [WARN] Opened but cannot read frame")
                    results[snum] = False
                cap.release()
            else:
                print(f"        [FAIL] Cannot open RTSP stream")
                results[snum] = False
        else:
            # Test with ffprobe
            try:
                cmd = [
                    "ffprobe", "-v", "quiet",
                    "-rtsp_transport", "tcp",
                    "-i", rtsp_url,
                    "-show_entries", "stream=width,height,codec_name",
                    "-of", "csv=p=0",
                    "-timeout", "5000000"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    print(f"        [PASS] {result.stdout.strip()}")
                    results[snum] = True
                else:
                    print(f"        [FAIL] ffprobe failed")
                    results[snum] = False
            except Exception as e:
                print(f"        [FAIL] {e}")
                results[snum] = False

    return any(results.values())


# ============================================================
# Snapshot
# ============================================================
def capture_snapshot(host, port, username, password, stream_num=1, output="snapshot.jpg"):
    """Capture a single frame from RTSP stream."""
    sinfo = RTSP_STREAMS.get(stream_num, RTSP_STREAMS[1])
    rtsp_url = f"rtsp://{username}:{password}@{host}:{port}{sinfo['path']}"
    rtsp_display = f"rtsp://{host}:{port}{sinfo['path']}"

    print(f"\n  Capturing snapshot from {sinfo['name']} ({sinfo['res']})")
    print(f"  URL: {rtsp_display}")

    if HAS_CV2:
        cap = cv2.VideoCapture(rtsp_url, cv2.CAP_FFMPEG)
        cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 10000)

        if not cap.isOpened():
            print("  [FAIL] Cannot open RTSP stream")
            return None

        # Skip a few frames for camera to warm up
        for _ in range(5):
            cap.read()

        ret, frame = cap.read()
        cap.release()

        if ret and frame is not None:
            cv2.imwrite(output, frame)
            h, w = frame.shape[:2]
            print(f"  [PASS] Saved {output} ({w}x{h})")
            return output
        else:
            print("  [FAIL] Cannot read frame")
            return None
    else:
        # Use ffmpeg
        try:
            cmd = [
                "ffmpeg", "-y",
                "-rtsp_transport", "tcp",
                "-i", rtsp_url,
                "-frames:v", "1",
                "-q:v", "2",
                output
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if os.path.exists(output):
                print(f"  [PASS] Saved {output}")
                return output
            else:
                print(f"  [FAIL] ffmpeg failed: {result.stderr[:200]}")
                return None
        except Exception as e:
            print(f"  [FAIL] {e}")
            return None


# ============================================================
# Web Video Preview (Flask + OpenCV)
# ============================================================
def start_web_preview(host, port, username, password, stream_num=2, web_port=8080):
    """Start a web server to preview RTSP video stream."""
    if not HAS_FLASK:
        print("[!] Can Flask: pip install flask")
        return
    if not HAS_CV2:
        print("[!] Can OpenCV: pip install opencv-python")
        return

    sinfo = RTSP_STREAMS.get(stream_num, RTSP_STREAMS[2])
    rtsp_url = f"rtsp://{username}:{password}@{host}:{port}{sinfo['path']}"
    rtsp_display = f"rtsp://{host}:{port}{sinfo['path']}"

    app = Flask(__name__)

    # Suppress Flask logs
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.WARNING)

    def gen_frames():
        """Generate MJPEG frames from RTSP."""
        cap = cv2.VideoCapture(rtsp_url, cv2.CAP_FFMPEG)
        cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 10000)
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

        if not cap.isOpened():
            print("[!] Cannot open RTSP stream")
            return

        print(f"  [STREAM] Connected to {sinfo['name']}")

        while True:
            ret, frame = cap.read()
            if not ret:
                print("[!] Stream lost, reconnecting...")
                cap.release()
                time.sleep(2)
                cap = cv2.VideoCapture(rtsp_url, cv2.CAP_FFMPEG)
                cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 10000)
                continue

            # Encode as JPEG
            _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
            frame_bytes = buffer.tobytes()

            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

    @app.route('/')
    def index():
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Camera Preview - Tapo C200</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #0a0a0f;
            color: #e0e0e0;
            font-family: 'Segoe UI', system-ui, sans-serif;
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }}
        h1 {{
            font-size: 1.5rem;
            font-weight: 300;
            margin-bottom: 8px;
            color: #7eb8ff;
            letter-spacing: 1px;
        }}
        .info {{
            font-size: 0.85rem;
            color: #888;
            margin-bottom: 20px;
        }}
        .info span {{
            color: #5aff5a;
            font-weight: 600;
        }}
        .video-container {{
            position: relative;
            border: 2px solid #1e3a5f;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 0 40px rgba(50, 100, 200, 0.15);
            max-width: 960px;
            width: 100%;
        }}
        .video-container img {{
            width: 100%;
            height: auto;
            display: block;
        }}
        .badge {{
            position: absolute;
            top: 12px;
            left: 12px;
            background: rgba(255, 50, 50, 0.9);
            color: white;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 1px;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}
        .streams {{
            display: flex;
            gap: 10px;
            margin-top: 16px;
        }}
        .streams a {{
            padding: 8px 20px;
            background: #1a2a3a;
            color: #7eb8ff;
            border: 1px solid #2a4a6a;
            border-radius: 6px;
            text-decoration: none;
            font-size: 0.85rem;
            transition: all 0.2s;
        }}
        .streams a:hover {{
            background: #2a4a6a;
            border-color: #4a8aff;
        }}
        .streams a.active {{
            background: #1a3a5a;
            border-color: #4a8aff;
            color: white;
        }}
        .footer {{
            margin-top: 20px;
            font-size: 0.75rem;
            color: #555;
        }}
    </style>
</head>
<body>
    <h1>Tapo C200 - Live Preview</h1>
    <div class="info">
        {sinfo['name']} | <span>{sinfo['res']}</span> |
        RTSP {rtsp_display} | SHA-256 Digest Auth
    </div>
    <div class="video-container">
        <div class="badge">LIVE</div>
        <img src="/video_feed" alt="Camera Stream">
    </div>
    <div class="streams">
        <a href="/?stream=1" {'class="active"' if stream_num == 1 else ''}>Stream 1 (1080p)</a>
        <a href="/?stream=2" {'class="active"' if stream_num == 2 else ''}>Stream 2 (720p)</a>
        <a href="/?stream=8" {'class="active"' if stream_num == 8 else ''}>Stream 8 (360p)</a>
    </div>
    <div class="footer">
        ONVIF Port: {DEFAULT_ONVIF_PORT} | RTSP Port: {port} | Auth: SHA-256
    </div>
</body>
</html>"""

    @app.route('/video_feed')
    def video_feed():
        return Response(gen_frames(),
                        mimetype='multipart/x-mixed-replace; boundary=frame')

    @app.route('/snapshot')
    def snapshot():
        cap = cv2.VideoCapture(rtsp_url, cv2.CAP_FFMPEG)
        if cap.isOpened():
            for _ in range(3):
                cap.read()
            ret, frame = cap.read()
            cap.release()
            if ret:
                _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 95])
                return Response(buffer.tobytes(), mimetype='image/jpeg')
        return "Cannot capture", 500

    print(f"\n{'='*60}")
    print(f"  CAMERA WEB PREVIEW")
    print(f"{'='*60}")
    print(f"  Stream:  {sinfo['name']} ({sinfo['res']})")
    print(f"  RTSP:    {rtsp_display}")
    print(f"  Web:     http://localhost:{web_port}")
    print(f"  Snapshot: http://localhost:{web_port}/snapshot")
    print(f"{'='*60}")
    print(f"  Press Ctrl+C to stop\n")

    app.run(host='0.0.0.0', port=web_port, threaded=True)


# ============================================================
# Main
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description='ONVIF/RTSP Camera Tester & Preview',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  test      Test ca ONVIF (port 2020) va RTSP (port 554)
  snapshot  Chup anh tu RTSP stream
  preview   Mo web preview video (Flask server)

Examples:
  python camera_viewer.py test
  python camera_viewer.py snapshot --stream 1
  python camera_viewer.py preview --stream 2
  python camera_viewer.py preview --stream 1 --port 9090
        """
    )
    parser.add_argument('command', choices=['test', 'snapshot', 'preview'])
    parser.add_argument('-H', '--host', default=DEFAULT_HOST)
    parser.add_argument('-u', '--username', default=DEFAULT_USERNAME)
    parser.add_argument('-p', '--password', default=DEFAULT_PASSWORD)
    parser.add_argument('--stream', type=int, default=2, choices=[1, 2, 8],
                        help='Stream number: 1=1080p, 2=720p, 8=360p (default: 2)')
    parser.add_argument('--port', type=int, default=8080,
                        help='Web preview port (default: 8080)')
    parser.add_argument('-o', '--output', default='snapshot.jpg',
                        help='Snapshot output file')

    args = parser.parse_args()

    print(f"\n  ONVIF/RTSP Camera Tool")
    print(f"  Host: {args.host} | User: {args.username}")
    print(f"  OpenCV: {'Yes' if HAS_CV2 else 'No'} | Flask: {'Yes' if HAS_FLASK else 'No'}")

    if args.command == 'test':
        onvif_ok = test_onvif(args.host, DEFAULT_ONVIF_PORT, args.username, args.password)
        rtsp_ok = test_rtsp(args.host, DEFAULT_RTSP_PORT, args.username, args.password)

        print(f"\n{'='*60}")
        print(f"  RESULTS")
        print(f"{'='*60}")
        print(f"  ONVIF (port {DEFAULT_ONVIF_PORT}): {'PASS' if onvif_ok else 'FAIL'}")
        print(f"  RTSP  (port {DEFAULT_RTSP_PORT}):  {'PASS' if rtsp_ok else 'FAIL'}")
        print()

    elif args.command == 'snapshot':
        result = capture_snapshot(
            args.host, DEFAULT_RTSP_PORT,
            args.username, args.password,
            stream_num=args.stream,
            output=args.output
        )
        if result:
            print(f"\n  Snapshot saved: {os.path.abspath(result)}")

    elif args.command == 'preview':
        start_web_preview(
            args.host, DEFAULT_RTSP_PORT,
            args.username, args.password,
            stream_num=args.stream,
            web_port=args.port
        )


if __name__ == '__main__':
    main()
