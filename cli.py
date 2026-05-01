#!/usr/bin/env python3
import argparse
import sys
import time
from urllib.parse import urlparse
from core.engine import ONVIFClient, RTSPClient
from core.vlc_manager import launch_stream
from core.presets import PresetManager, CameraPreset

def main():
    parser = argparse.ArgumentParser(description="MyoVIF CLI - Universal ONVIF/RTSP Auth Tester & Streamer")
    parser.add_argument('-u', '--username', help='Username', default='admin')
    parser.add_argument('-p', '--password', help='Password', default='')
    parser.add_argument('--host', help='Target host IP or domain')
    parser.add_argument('--onvif-port', type=int, default=80, help='ONVIF port')
    parser.add_argument('--rtsp-port', type=int, default=554, help='RTSP port')
    parser.add_argument('--rtsp-path', default='/stream1', help='RTSP stream path')
    parser.add_argument('--protocol', choices=['rtsp', 'rtsps'], default='rtsp', help='RTSP protocol')
    parser.add_argument('--auth-mode', choices=['standard', 'custom'], default='custom', help='Authentication mode')
    parser.add_argument('--algorithm', choices=['auto', 'MD5', 'SHA-256', 'SHA-512-256'], default='auto', help='Digest algorithm')
    parser.add_argument('--quote', action='store_true', help='Quote algorithm in Digest header (for Tapo C200)')
    parser.add_argument('--ws-auth', action='store_true', help='Use WS-UsernameToken for ONVIF')
    parser.add_argument('--relative-uri', action='store_true', help='Use relative URI in RTSP Digest (default is absolute)')
    
    # Streaming options
    parser.add_argument('--stream', action='store_true', help='Launch VLC/ffplay stream after auth check')
    parser.add_argument('--player', choices=['vlc', 'ffplay'], default='vlc', help='Player to use')
    parser.add_argument('--no-hw', action='store_true', help='Disable VLC hardware acceleration')
    parser.add_argument('--tunnel', action='store_true', help='Use RTSP over TCP')
    parser.add_argument('--proxy', action='store_true', help='Use local proxy to fix SHA-256 for VLC')

    args = parser.parse_args()

    if not args.host:
        print("[ERROR] Please provide --host")
        sys.exit(1)

    print("=" * 50)
    print(f"Testing MyoVIF Auth: {args.host}")
    print("=" * 50)

    # 1. Test ONVIF
    print("\n[1] Testing ONVIF (Device Info)...")
    onvif_client = ONVIFClient(
        host=args.host, port=args.onvif_port,
        username=args.username, password=args.password,
        auth_mode=args.auth_mode, algorithm=args.algorithm,
        quote_algo=args.quote, use_ws_auth=args.ws_auth
    )
    
    dev_info = onvif_client.get_device_info()
    if dev_info:
        print("[SUCCESS] ONVIF Authentication Passed")
    else:
        print("[FAILED] ONVIF Authentication Failed")

    # 2. Test RTSP
    rtsp_url = f"{args.protocol}://{args.host}:{args.rtsp_port}{args.rtsp_path}"
    print(f"\n[2] Testing {args.protocol.upper()} Auth: {rtsp_url} ...")
    rtsp_client = RTSPClient(
        url=rtsp_url, username=args.username, password=args.password,
        auth_mode=args.auth_mode, algorithm=args.algorithm,
        quote_algo=args.quote, absolute_uri=not args.relative_uri
    )
    
    rtsp_res = rtsp_client.test_auth()
    status = rtsp_res.get('status', 'UNKNOWN')
    if status == "200":
        print("[SUCCESS] RTSP Authentication Passed")
    else:
        print(f"[{'WARNING' if status == '401' else 'FAILED'}] RTSP Response: {status}")

    # 3. Stream
    if args.stream:
        print(f"\n[3] Launching stream with {args.player}...")
        proc = launch_stream(
            rtsp_url=rtsp_url, username=args.username, password=args.password,
            player=args.player, disable_hw=args.no_hw, use_proxy=args.proxy,
            quote_algo=args.quote, algorithm=args.algorithm,
            absolute_uri=not args.relative_uri, tunnel=args.tunnel
        )
        if proc:
            print("[INFO] Stream launched. Press Ctrl+C to stop.")
            try:
                proc.wait()
            except KeyboardInterrupt:
                proc.terminate()
                print("\n[INFO] Stream stopped.")

if __name__ == "__main__":
    main()
