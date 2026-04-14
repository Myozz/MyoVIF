#!/usr/bin/env python3
"""
Test SHA-256 HTTP Digest Authentication
========================================
TEST 1: Verify cong thuc MD5 voi du lieu da biet (tu screenshot)  
TEST 2: Verify cong thuc SHA-256 (cung cong thuc, thay hash)
TEST 3: Test ket noi thuc te toi camera Tapo C200

Usage:
    python test_sha256_digest.py                # Chay tat ca test
    python test_sha256_digest.py --skip-camera  # Chi test cong thuc, khong ket noi camera
"""

import hashlib
import os
import sys
import argparse


# ============================================================
# TEST 1: Verify MD5 formula voi du lieu tu screenshot
# ============================================================
def test_md5_formula():
    """
    Verify cong thuc MD5 Digest Auth khop voi gia tri trong screenshot.

    RFC 2617 formula:
      HA1 = MD5(username : realm : password)
      HA2 = MD5(method : uri)
      response = MD5(HA1 : nonce : nc : cnonce : qop : HA2)
    """
    print("=" * 60)
    print("TEST 1: Verify MD5 Digest Auth Formula")
    print("=" * 60)

    # Du lieu lay tu screenshot
    username = "psitest135"
    realm = "TP-Link IP-Camera"
    password = "psitest135"
    nonce = "ed28d7327d4718ec30777f27738acc73"
    uri = "/onvif/service"
    method = "POST"
    qop = "auth"
    nc = "00000001"
    cnonce = "acd46f10462bdad8"
    expected_response = "dfdf93e696b3192304cc728457694a05"

    # Step 1: HA1
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    print(f"  HA1 = MD5('{username}:{realm}:{password}')")
    print(f"      = {ha1}")

    # Step 2: HA2
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    print(f"  HA2 = MD5('{method}:{uri}')")
    print(f"      = {ha2}")

    # Step 3: response
    response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
    print(f"  response = MD5(HA1 : nonce : nc : cnonce : qop : HA2)")
    print(f"           = {response}")
    print(f"  expected = {expected_response}")

    match = response == expected_response
    status = "PASS" if match else "FAIL"
    msg = "MD5 response khop!" if match else "MD5 response KHONG khop!"
    print(f"\n  [{status}] {msg}")
    return match


# ============================================================
# TEST 2: Verify SHA-256 formula
# ============================================================
def test_sha256_formula():
    """
    Verify cong thuc SHA-256 Digest Auth.
    
    RFC 7616 formula (giong MD5, chi thay ham hash):
      HA1 = SHA256(username : realm : password)
      HA2 = SHA256(method : uri)
      response = SHA256(HA1 : nonce : nc : cnonce : qop : HA2)
    """
    print("\n" + "=" * 60)
    print("TEST 2: Verify SHA-256 Digest Auth Formula")
    print("=" * 60)

    username = "psitest135"
    realm = "TP-Link IP-Camera"
    password = "psitest135"
    nonce = "test_nonce_12345"
    uri = "/onvif/device_service"
    method = "POST"
    qop = "auth"
    nc = "00000001"
    cnonce = "abcdef1234567890"

    # Step 1: HA1
    ha1 = hashlib.sha256(f"{username}:{realm}:{password}".encode()).hexdigest()
    print(f"  HA1 = SHA256('{username}:{realm}:{password}')")
    print(f"      = {ha1}")
    print(f"      length = {len(ha1)} (expected 64)")

    # Step 2: HA2
    ha2 = hashlib.sha256(f"{method}:{uri}".encode()).hexdigest()
    print(f"  HA2 = SHA256('{method}:{uri}')")
    print(f"      = {ha2}")

    # Step 3: response
    response = hashlib.sha256(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
    print(f"  response = SHA256(HA1 : nonce : nc : cnonce : qop : HA2)")
    print(f"           = {response}")

    # Verify: SHA-256 = 64 hex chars
    is_64 = len(response) == 64
    is_hex = all(c in '0123456789abcdef' for c in response)

    # Verify: khac voi MD5
    md5_ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    md5_ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    md5_resp = hashlib.md5(f"{md5_ha1}:{nonce}:{nc}:{cnonce}:{qop}:{md5_ha2}".encode()).hexdigest()
    diff = response != md5_resp

    print(f"\n  [{'PASS' if is_64 and is_hex else 'FAIL'}] Output = 64 hex chars")
    print(f"  [{'PASS' if diff else 'FAIL'}] SHA-256 != MD5")
    print(f"    MD5:    {md5_resp} ({len(md5_resp)} chars)")
    print(f"    SHA256: {response} ({len(response)} chars)")

    return is_64 and is_hex and diff


# ============================================================
# TEST 3: Test ket noi thuc te toi camera
# ============================================================
def test_camera_connection():
    """Test ket noi SHA-256 Digest Auth toi camera Tapo C200."""
    print("\n" + "=" * 60)
    print("TEST 3: Test ket noi camera Tapo C200")
    print("=" * 60)

    try:
        import requests
    except ImportError:
        print("  [SKIP] Thu vien 'requests' chua cai: pip install requests")
        return None

    try:
        from onvif_sha256 import SHA256DigestAuth
    except ImportError:
        print("  [SKIP] Khong import duoc onvif_sha256.py")
        return None

    camera_url = "http://192.168.137.246:2020/onvif/device_service"
    username = "psitest135"
    password = "psitest135"

    soap_body = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:tt="http://www.onvif.org/ver10/schema">
  <soap:Body>
    <tds:GetDeviceInformation />
  </soap:Body>
</soap:Envelope>"""

    headers = {'Content-Type': 'application/soap+xml; charset=utf-8'}
    auth = SHA256DigestAuth(username, password)

    print(f"  Camera: {camera_url}")
    print(f"  User:   {username}")
    print(f"  Algo:   SHA-256")

    print(f"\n  [1] Gui SOAP GetDeviceInformation...")
    try:
        resp = auth.send_request(
            method='POST',
            url=camera_url,
            data=soap_body,
            headers=dict(headers),
            force_algorithm='SHA-256'
        )
    except Exception as e:
        print(f"  [SKIP] Loi ket noi: {e}")
        return None

    print(f"  [2] Status: {resp.status_code}")

    if resp.status_code == 200:
        print(f"  [PASS] Camera chap nhan SHA-256 digest!")
        if 'Manufacturer' in resp.text:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(resp.text)
            for elem in root.iter():
                tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                if tag in ('Manufacturer', 'Model', 'FirmwareVersion', 'SerialNumber'):
                    print(f"       {tag}: {elem.text}")
        return True
    else:
        print(f"  [FAIL] Camera tu choi! Status={resp.status_code}")
        print(f"       Co the camera bi rate-limit hoac sai password.")
        print(f"       Thu: restart camera hoac kiem tra Camera Account trong app Tapo.")
        return False


# ============================================================
# Main
# ============================================================
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test SHA-256 Digest Auth')
    parser.add_argument('--skip-camera', action='store_true', 
                        help='Chi test cong thuc, khong ket noi camera')
    args = parser.parse_args()

    print()
    print("  SHA-256 HTTP Digest Authentication - Test Suite")
    print("  Camera: TP-Link Tapo C200")
    print("  " + "=" * 56)
    print()

    results = {}
    results['MD5 Formula'] = test_md5_formula()
    results['SHA-256 Formula'] = test_sha256_formula()

    if not args.skip_camera:
        results['Camera Connection'] = test_camera_connection()

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for name, result in results.items():
        status = "SKIP" if result is None else ("PASS" if result else "FAIL")
        print(f"  [{status}] {name}")

    failures = sum(1 for r in results.values() if r is False)
    passes = sum(1 for r in results.values() if r is True)
    skips = sum(1 for r in results.values() if r is None)
    print(f"\n  Total: {passes} passed, {failures} failed, {skips} skipped")
    sys.exit(1 if failures > 0 else 0)
