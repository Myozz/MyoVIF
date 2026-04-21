import socket
import hashlib
import re

def get_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def test_rtsp_auth(host, port, path, user, password, quote_algo=False, absolute_uri=True):
    url = f"rtsp://{host}:{port}{path}"
    uri_in_digest = url if absolute_uri else path
    
    print(f"\n--- Testing: AlgoQuoted={quote_algo}, AbsoluteURI={absolute_uri} ---")
    
    # 1. Send initial DESCRIBE to get challenge
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        s.send(f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Lavf/58.29.100\r\n\r\n".encode())
        resp = s.recv(4096).decode()
        s.close()
    except Exception as e:
        print(f"Connection failed: {e}")
        return False

    if "401 Unauthorized" not in resp:
        print("Camera did not challenge for auth.")
        return False

    # 2. Parse Challenge
    auth_match = re.search(r'WWW-Authenticate: Digest (.*)', resp)
    if not auth_match:
        print("No Digest challenge found.")
        return False
    
    # Simple regex to extract params
    params = {}
    for match in re.finditer(r'(\w+)="?([^",]+)"?', auth_match.group(1)):
        params[match.group(1)] = match.group(2)
        
    realm = params.get('realm')
    nonce = params.get('nonce')
    qop = params.get('qop')
    algo = params.get('algorithm', 'SHA-256')

    # 3. Calculate SHA-256 Response
    ha1 = get_sha256(f"{user}:{realm}:{password}")
    ha2 = get_sha256(f"DESCRIBE:{uri_in_digest}")
    
    if qop:
        cnonce = "0a4f113b"
        nc = "00000001"
        response = get_sha256(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
        algo_str = f'"{algo}"' if quote_algo else algo
        auth_header = (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
                       f'uri="{uri_in_digest}", response="{response}", algorithm={algo_str}, '
                       f'cnonce="{cnonce}", nc={nc}, qop="auth"')
    else:
        response = get_sha256(f"{ha1}:{nonce}:{ha2}")
        algo_str = f'"{algo}"' if quote_algo else algo
        auth_header = (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
                       f'uri="{uri_in_digest}", response="{response}", algorithm={algo_str}')

    # 4. Send AUTH DESCRIBE
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        auth_request = (f"DESCRIBE {url} RTSP/1.0\r\n"
                        f"CSeq: 2\r\n"
                        f"Authorization: {auth_header}\r\n"
                        f"User-Agent: Lavf/58.29.100\r\n\r\n")
        s.send(auth_request.encode())
        final_resp = s.recv(4096).decode()
        s.close()
        
        status_line = final_resp.splitlines()[0] if final_resp else "NO RESPONSE"
        print(f"RESULT: {status_line}")
        return "200 OK" in final_resp
    except Exception as e:
        print(f"Auth request failed: {e}")
        return False

if __name__ == "__main__":
    host = "192.168.137.246"
    port = 554
    path = "/stream1"
    user = "psitest135"
    pw = "psitest135"
    
    # Test all 4 combinations
    test_rtsp_auth(host, port, path, user, pw, quote_algo=False, absolute_uri=True)
    test_rtsp_auth(host, port, path, user, pw, quote_algo=True, absolute_uri=True)
    test_rtsp_auth(host, port, path, user, pw, quote_algo=False, absolute_uri=False)
    test_rtsp_auth(host, port, path, user, pw, quote_algo=True, absolute_uri=False)
