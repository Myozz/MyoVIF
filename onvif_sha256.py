#!/usr/bin/env python3
"""
ONVIF Camera Client with SHA-256 HTTP Digest Authentication
============================================================
Tool kết nối ONVIF/RTSP cho camera Tapo C200.
Sử dụng SHA-256 thay cho MD5 trong HTTP Digest Authentication.

HTTP Digest Auth Formula (RFC 7616):
  HA1 = HASH(username : realm : password)
  HA2 = HASH(method : uri)
  response = HASH(HA1 : nonce : nc : cnonce : qop : HA2)

Với: HASH = SHA-256 (thay vì MD5)
"""

import hashlib
import os
import re
import sys
import time
import argparse
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[!] Cần cài thư viện requests: pip install requests")
    sys.exit(1)

# ============================================================
# SHA-256 HTTP Digest Authentication
# ============================================================

class SHA256DigestAuth:
    """
    Custom HTTP Digest Authentication using SHA-256.
    
    Công thức RFC 7616:
      HA1 = SHA256(username : realm : password)
      HA2 = SHA256(method : digestURI)
      response = SHA256(HA1 : nonce : nc : cnonce : qop : HA2)
    """

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.nc = 0  # nonce count

    @staticmethod
    def _sha256(data: str) -> str:
        """Compute SHA-256 hash and return lowercase hex string."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def _md5(data: str) -> str:
        """Compute MD5 hash and return lowercase hex string (fallback)."""
        return hashlib.md5(data.encode('utf-8')).hexdigest()

    @staticmethod
    def _generate_cnonce() -> str:
        """Generate a random client nonce (16 hex chars)."""
        return hashlib.sha256(os.urandom(32)).hexdigest()[:16]

    @staticmethod
    def _parse_www_authenticate(header: str) -> dict:
        """Parse the WWW-Authenticate header into a dict of key-value pairs."""
        params = {}
        # Remove the "Digest " prefix
        header = header.strip()
        if header.lower().startswith('digest '):
            header = header[7:]

        # Parse key=value or key="value" pairs
        pattern = r'(\w+)=(?:"([^"]+)"|([^\s,]+))'
        for match in re.finditer(pattern, header):
            key = match.group(1).lower()
            value = match.group(2) if match.group(2) is not None else match.group(3)
            params[key] = value

        return params

    def _compute_digest_response(self, method: str, uri: str, params: dict, 
                                  algorithm: str = 'SHA-256') -> dict:
        """
        Compute the digest response hash.
        
        Returns a dict with all fields needed for the Authorization header.
        """
        # Select hash function
        if algorithm.upper() in ('SHA-256', 'SHA256'):
            hash_func = self._sha256
            algo_name = 'SHA-256'
        else:
            hash_func = self._md5
            algo_name = 'MD5'

        realm = params.get('realm', '')
        nonce = params.get('nonce', '')
        qop = params.get('qop', 'auth')
        opaque = params.get('opaque', '')

        # Increment nonce count
        self.nc += 1
        nc = f'{self.nc:08x}'

        # Generate client nonce
        cnonce = self._generate_cnonce()

        # Step 1: HA1 = HASH(username : realm : password)
        ha1 = hash_func(f'{self.username}:{realm}:{self.password}')

        # Step 2: HA2 = HASH(method : uri)
        ha2 = hash_func(f'{method}:{uri}')

        # Step 3: response = HASH(HA1 : nonce : nc : cnonce : qop : HA2)
        if qop:
            response = hash_func(f'{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}')
        else:
            # Without qop (legacy): response = HASH(HA1 : nonce : HA2)
            response = hash_func(f'{ha1}:{nonce}:{ha2}')

        result = {
            'username': self.username,
            'realm': realm,
            'nonce': nonce,
            'uri': uri,
            'algorithm': algo_name,
            'qop': qop,
            'nc': nc,
            'cnonce': cnonce,
            'response': response,
        }
        if opaque:
            result['opaque'] = opaque

        return result

    def _build_auth_header(self, digest_parts: dict) -> str:
        """Build the Authorization header string from digest parts."""
        parts = []
        for key in ('username', 'realm', 'nonce', 'uri', 'algorithm',
                     'qop', 'nc', 'cnonce', 'response', 'opaque'):
            if key in digest_parts:
                val = digest_parts[key]
                if key in ('nc', 'qop'):
                    parts.append(f'{key}={val}')
                else:
                    parts.append(f'{key}="{val}"')
        return 'Digest ' + ', '.join(parts)

    def send_request(self, method: str, url: str, data: str = None,
                     headers: dict = None, force_algorithm: str = 'SHA-256',
                     max_retries: int = 3) -> requests.Response:
        """
        Send an HTTP request with SHA-256 Digest Authentication.
        
        Flow:
        1. Send initial request → get 401 + WWW-Authenticate
        2. Parse challenge, compute SHA-256 digest
        3. Re-send with Authorization header
        4. If still 401 (nonce changed), retry with new nonce
        
        Uses requests.Session for connection keep-alive.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            data: Request body
            headers: Additional headers
            force_algorithm: Force this algorithm instead of server-provided one
            max_retries: Max retry attempts on nonce re-challenge
        
        Returns:
            requests.Response
        """
        if headers is None:
            headers = {}

        session = requests.Session()

        # Step 1: Send initial unauthenticated request
        clean_headers = {k: v for k, v in headers.items() if k != 'Authorization'}
        if method.upper() == 'POST':
            resp = session.post(url, data=data, headers=clean_headers)
        else:
            resp = session.get(url, headers=clean_headers)

        # If not 401, return as-is
        if resp.status_code != 401:
            return resp

        # Step 2-4: Challenge-response with retry on nonce re-challenge
        for attempt in range(max_retries):
            # Parse the WWW-Authenticate challenge
            www_auth = resp.headers.get('WWW-Authenticate', '')
            if not www_auth:
                print("[!] Server returned 401 but no WWW-Authenticate header")
                return resp

            params = self._parse_www_authenticate(www_auth)
            
            # Determine algorithm
            server_algo = params.get('algorithm', 'MD5')
            algorithm = force_algorithm if force_algorithm else server_algo

            if attempt == 0:
                print(f"[*] Server challenge received:")
                print(f"    Realm:     {params.get('realm', 'N/A')}")
                print(f"    Nonce:     {params.get('nonce', 'N/A')}")
                print(f"    Qop:       {params.get('qop', 'N/A')}")
                print(f"    Opaque:    {params.get('opaque', 'N/A')}")
                print(f"    Server algo: {server_algo}")
                print(f"    Using algo:  {algorithm}")

            # Parse URI from the URL
            parsed = urlparse(url)
            uri = parsed.path
            if parsed.query:
                uri += '?' + parsed.query

            # Compute the digest
            digest_parts = self._compute_digest_response(
                method=method.upper(),
                uri=uri,
                params=params,
                algorithm=algorithm
            )

            print(f"[*] Digest computed (attempt {attempt + 1}):")
            print(f"    NC:       {digest_parts['nc']}")
            print(f"    CNonce:   {digest_parts['cnonce']}")
            print(f"    Response: {digest_parts['response']}")

            # Re-send with Authorization
            auth_header = self._build_auth_header(digest_parts)
            auth_headers = dict(clean_headers)
            auth_headers['Authorization'] = auth_header

            if method.upper() == 'POST':
                resp = session.post(url, data=data, headers=auth_headers)
            else:
                resp = session.get(url, headers=auth_headers)

            # Success or non-auth error → return
            if resp.status_code != 401:
                return resp

            # Still 401 → check if nonce changed (re-challenge)
            new_auth = resp.headers.get('WWW-Authenticate', '')
            if new_auth:
                new_params = self._parse_www_authenticate(new_auth)
                new_nonce = new_params.get('nonce', '')
                old_nonce = params.get('nonce', '')
                if new_nonce != old_nonce:
                    print(f"[*] Nonce re-challenge (attempt {attempt + 1}): {old_nonce[:16]}... -> {new_nonce[:16]}...")
                    # Reset nc for new nonce
                    self.nc = 0
                    continue
            
            # Same nonce but still 401 → auth truly failed
            print(f"[!] Authentication failed (wrong credentials?)")
            break

        return resp


# ============================================================
# ONVIF SOAP Client
# ============================================================

class ONVIFClient:
    """
    ONVIF Camera Client using SHA-256 HTTP Digest Auth.
    Supports: GetDeviceInformation, GetCapabilities, GetProfiles, GetStreamUri
    """

    SOAP_ENVELOPE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:tt="http://www.onvif.org/ver10/schema">
  <soap:Body>
    {body}
  </soap:Body>
</soap:Envelope>"""

    SOAP_HEADERS = {
        'Content-Type': 'application/soap+xml; charset=utf-8',
    }

    def __init__(self, host: str, port: int, username: str, password: str, force_sha256: bool = True):
        self.host = host
        self.port = port
        self.base_url = f'http://{host}:{port}'
        self.device_url = f'{self.base_url}/onvif/device_service'
        self.media_url = None  # Will be discovered via GetCapabilities
        self.auth = SHA256DigestAuth(username, password)
        self.force_algo = 'SHA-256' if force_sha256 else None

    def _send_soap(self, url: str, body_xml: str) -> str:
        """Send a SOAP request and return the response body."""
        soap = self.SOAP_ENVELOPE.format(body=body_xml)
        
        print(f"\n{'='*60}")
        print(f"[>] Sending SOAP request to: {url}")
        print(f"{'='*60}")

        resp = self.auth.send_request(
            method='POST',
            url=url,
            data=soap,
            headers=dict(self.SOAP_HEADERS),
            force_algorithm=self.force_algo
        )

        print(f"[<] Response status: {resp.status_code}")
        
        if resp.status_code == 200:
            return resp.text
        else:
            print(f"[!] Error response:")
            print(resp.text[:500])
            return resp.text

    def get_device_information(self) -> dict:
        """Get device information (manufacturer, model, firmware, serial, hardware)."""
        body = '<tds:GetDeviceInformation />'
        response = self._send_soap(self.device_url, body)
        
        info = {}
        try:
            # Parse XML response
            root = ET.fromstring(response)
            ns = {
                'soap': 'http://www.w3.org/2003/05/soap-envelope',
                'tds': 'http://www.onvif.org/ver10/device/wsdl',
            }
            body_elem = root.find('.//tds:GetDeviceInformationResponse', ns)
            if body_elem is not None:
                for child in body_elem:
                    tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                    info[tag] = child.text
        except ET.ParseError as e:
            print(f"[!] XML Parse Error: {e}")
            info['raw'] = response[:500]

        return info

    def get_capabilities(self) -> dict:
        """Get device capabilities and discover service URLs."""
        body = '<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>'
        response = self._send_soap(self.device_url, body)
        
        caps = {}
        try:
            root = ET.fromstring(response)
            # Try to find the Media XAddr (service URL)
            # Look for any element containing 'XAddr'
            for elem in root.iter():
                tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                if tag == 'XAddr' and elem.text:
                    parent_tag = ''
                    # Find the parent's tag name for context
                    for parent in root.iter():
                        for child in parent:
                            if child is elem:
                                parent_tag = parent.tag.split('}')[-1] if '}' in parent.tag else parent.tag
                                break
                    caps[parent_tag] = elem.text
                    if 'media' in parent_tag.lower() or 'Media' in parent_tag:
                        self.media_url = elem.text
                        
        except ET.ParseError as e:
            print(f"[!] XML Parse Error: {e}")
            caps['raw'] = response[:500]

        # If no media URL found, try default
        if not self.media_url:
            self.media_url = f'{self.base_url}/onvif/media_service'

        return caps

    def get_profiles(self) -> list:
        """Get media profiles (needed for stream URI)."""
        # Use media URL if discovered, otherwise try device URL
        url = self.media_url or self.device_url
        body = '<trt:GetProfiles />'
        response = self._send_soap(url, body)
        
        profiles = []
        try:
            root = ET.fromstring(response)
            ns = {
                'soap': 'http://www.w3.org/2003/05/soap-envelope',
                'trt': 'http://www.onvif.org/ver10/media/wsdl',
                'tt': 'http://www.onvif.org/ver10/schema',
            }
            for profile in root.iter():
                tag = profile.tag.split('}')[-1] if '}' in profile.tag else profile.tag
                if tag == 'Profiles':
                    token = profile.attrib.get('token', '')
                    name_elem = profile.find('.//{http://www.onvif.org/ver10/schema}Name')
                    name = name_elem.text if name_elem is not None else token
                    
                    # Try to get resolution
                    width_elem = profile.find('.//{http://www.onvif.org/ver10/schema}Width')
                    height_elem = profile.find('.//{http://www.onvif.org/ver10/schema}Height')
                    width = width_elem.text if width_elem is not None else '?'
                    height = height_elem.text if height_elem is not None else '?'
                    
                    profiles.append({
                        'token': token,
                        'name': name,
                        'resolution': f'{width}x{height}'
                    })
        except ET.ParseError as e:
            print(f"[!] XML Parse Error: {e}")

        return profiles

    def get_stream_uri(self, profile_token: str) -> str:
        """Get the RTSP stream URI for a given profile."""
        url = self.media_url or self.device_url
        body = f"""<trt:GetStreamUri>
      <trt:StreamSetup>
        <tt:Stream>RTP-Unicast</tt:Stream>
        <tt:Transport>
          <tt:Protocol>RTSP</tt:Protocol>
        </tt:Transport>
      </trt:StreamSetup>
      <trt:ProfileToken>{profile_token}</trt:ProfileToken>
    </trt:GetStreamUri>"""
        
        response = self._send_soap(url, body)
        
        stream_uri = None
        try:
            root = ET.fromstring(response)
            for elem in root.iter():
                tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                if tag == 'Uri' and elem.text:
                    stream_uri = elem.text
                    break
        except ET.ParseError as e:
            print(f"[!] XML Parse Error: {e}")

        return stream_uri

    def get_snapshot_uri(self, profile_token: str) -> str:
        """Get the snapshot URI for a given profile."""
        url = self.media_url or self.device_url
        body = f"""<trt:GetSnapshotUri>
      <trt:ProfileToken>{profile_token}</trt:ProfileToken>
    </trt:GetSnapshotUri>"""
        
        response = self._send_soap(url, body)
        
        snapshot_uri = None
        try:
            root = ET.fromstring(response)
            for elem in root.iter():
                tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                if tag == 'Uri' and elem.text:
                    snapshot_uri = elem.text
                    break
        except ET.ParseError as e:
            print(f"[!] XML Parse Error: {e}")

        return snapshot_uri


# ============================================================
# Main CLI
# ============================================================

def print_banner():
    print(r"""
  ____  _   _    _    ____  ____   __    ___  _   ___     _____ _____ 
 / ___|| | | |  / \  |___ \| ___| / /_  / _ \| \ | \ \   / /_ _|  ___|
 \___ \| |_| | / _ \   __) |___ \| '_ \| | | |  \| |\ \ / / | || |_   
  ___) |  _  |/ ___ \ / __/ ___) | (_) | |_| | |\  | \ V /  | ||  _|  
 |____/|_| |_/_/   \_\_____|____/ \___/ \___/|_| \_|  \_/  |___|_|    
                                                                       
 ONVIF Camera Tool with SHA-256 Digest Authentication
 For TP-Link Tapo C200 and compatible cameras
""")


def main():
    parser = argparse.ArgumentParser(
        description='ONVIF Camera Client with SHA-256 HTTP Digest Auth',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Get device info
  python onvif_sha256.py -H 192.168.137.246 -P 2020 -u psitest135 -p psitest135 info

  # Get all profiles
  python onvif_sha256.py -H 192.168.137.246 -P 2020 -u psitest135 -p psitest135 profiles

  # Get RTSP stream URI
  python onvif_sha256.py -H 192.168.137.246 -P 2020 -u psitest135 -p psitest135 stream

  # Full discovery (all info + profiles + stream URIs)
  python onvif_sha256.py -H 192.168.137.246 -P 2020 -u psitest135 -p psitest135 discover

  # Use MD5 instead of SHA-256
  python onvif_sha256.py -H 192.168.137.246 -P 2020 -u psitest135 -p psitest135 --md5 discover
        """
    )
    parser.add_argument('-H', '--host', required=True, help='Camera IP address')
    parser.add_argument('-P', '--port', type=int, default=2020, help='ONVIF port (default: 2020)')
    parser.add_argument('-u', '--username', required=True, help='Camera username')
    parser.add_argument('-p', '--password', required=True, help='Camera password')
    parser.add_argument('--md5', action='store_true', help='Use MD5 instead of SHA-256')
    parser.add_argument('--profile', default=None, help='Specific profile token to use')
    parser.add_argument('command', choices=['info', 'caps', 'profiles', 'stream', 'snapshot', 'discover'],
                        help='Command to execute')

    args = parser.parse_args()

    print_banner()

    client = ONVIFClient(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        force_sha256=not args.md5
    )

    if args.command == 'info':
        info = client.get_device_information()
        print(f"\n{'='*60}")
        print("[CAMERA] Device Information:")
        print(f"{'='*60}")
        for k, v in info.items():
            print(f"  {k}: {v}")

    elif args.command == 'caps':
        caps = client.get_capabilities()
        print(f"\n{'='*60}")
        print("[CAPS] Device Capabilities:")
        print(f"{'='*60}")
        for k, v in caps.items():
            print(f"  {k}: {v}")

    elif args.command == 'profiles':
        # Need capabilities first to find media URL
        client.get_capabilities()
        profiles = client.get_profiles()
        print(f"\n{'='*60}")
        print("[PROFILES] Media Profiles:")
        print(f"{'='*60}")
        for i, p in enumerate(profiles):
            print(f"  [{i}] Token: {p['token']}")
            print(f"      Name: {p['name']}")
            print(f"      Resolution: {p['resolution']}")
            print()

    elif args.command == 'stream':
        # Get capabilities + profiles + stream URI
        client.get_capabilities()
        profiles = client.get_profiles()
        
        if args.profile:
            tokens = [args.profile]
        else:
            tokens = [p['token'] for p in profiles]

        print(f"\n{'='*60}")
        print("[STREAM] RTSP Stream URIs:")
        print(f"{'='*60}")
        for token in tokens:
            uri = client.get_stream_uri(token)
            print(f"  Profile: {token}")
            print(f"  URI:     {uri}")
            print()

    elif args.command == 'snapshot':
        client.get_capabilities()
        profiles = client.get_profiles()
        
        if args.profile:
            tokens = [args.profile]
        else:
            tokens = [p['token'] for p in profiles]

        print(f"\n{'='*60}")
        print("[SNAP] Snapshot URIs:")
        print(f"{'='*60}")
        for token in tokens:
            uri = client.get_snapshot_uri(token)
            print(f"  Profile: {token}")
            print(f"  URI:     {uri}")
            print()

    elif args.command == 'discover':
        # Full discovery
        print("\n" + "="*60)
        print("[*] FULL CAMERA DISCOVERY")
        print("="*60)
        
        # 1. Device Info
        info = client.get_device_information()
        print(f"\n[CAMERA] Device Information:")
        for k, v in info.items():
            print(f"    {k}: {v}")
        
        # 2. Capabilities
        caps = client.get_capabilities()
        print(f"\n[CAPS] Capabilities (XAddr URLs):")
        for k, v in caps.items():
            print(f"    {k}: {v}")
        
        # 3. Profiles
        profiles = client.get_profiles()
        print(f"\n[PROFILES] Media Profiles:")
        for i, p in enumerate(profiles):
            print(f"    [{i}] {p['name']} ({p['token']}) - {p['resolution']}")
        
        # 4. Stream URIs for each profile
        print(f"\n[STREAM] RTSP Stream URIs:")
        for p in profiles:
            uri = client.get_stream_uri(p['token'])
            print(f"    {p['name']}: {uri}")
        
        # 5. Snapshot URIs
        print(f"\n[SNAP] Snapshot URIs:")
        for p in profiles:
            uri = client.get_snapshot_uri(p['token'])
            print(f"    {p['name']}: {uri}")
        
        print(f"\n{'='*60}")
        print("[OK] Discovery complete!")
        print(f"{'='*60}")


if __name__ == '__main__':
    main()
