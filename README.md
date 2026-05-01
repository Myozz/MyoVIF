# MyoVIF - Universal ONVIF/RTSP Camera Tool

MyoVIF is a comprehensive tool designed to interact, authenticate, and stream from IP cameras using ONVIF and RTSP/RTSPs protocols. It is specifically built to handle tricky authentication setups, such as SHA-256 Digest Authentication, which many standard players (like VLC) fail to handle out of the box.

## Features
- **ONVIF Support**: Auto-discover devices, get device info, and extract stream profiles using standard or custom Digest authentication and WS-Security (WS-UsernameToken).
- **RTSP & RTSPS**: Full support for both unencrypted (RTSP) and encrypted (RTSPS) streams.
- **Custom Digest Authentication**: Manually force `MD5`, `SHA-256`, or `SHA-512-256` hashing algorithms.
- **VLC Fixes (Local Proxy)**: Includes a built-in RTSP Proxy that acts as a middleman. It computes the complex SHA-256 Digest handshakes on behalf of VLC so your streams load flawlessly (very useful for models like TP-Link Tapo C200).
- **Flexible Parameters**: Fine-tune authentication with features like "Quote Algorithm" (wrapping `algorithm="SHA-256"` in quotes) and "Absolute URI" targeting.
- **Preset Management**: Save multiple camera profiles so you don't have to re-type IPs and credentials.

---

## Requirements

Ensure you have Python 3 installed. You also need the `requests` library and a media player (VLC is recommended).

```bash
pip install requests
```

Make sure **VLC Media Player** or **FFplay** is installed on your system if you plan to view the live streams.

---

## Usage

MyoVIF provides both a fully-featured Graphical User Interface (GUI) and a Command-Line Interface (CLI).

### 1. GUI Mode (Recommended)
Run the main application for an easy-to-use graphical interface:

```bash
python myovif.py
```

**GUI Capabilities:**
- Scan network for ONVIF cameras (`🔍 Discover`).
- Select auth options: **WS-Security** for ONVIF or **Custom Digest** for RTSP.
- Use **VLC Fixes** like "Local Proxy (Fix SHA-256)" to bypass authentication limitations.
- Save and load configuration Presets.
- Test authentication and view live streams.

### 2. CLI Mode (For Automation & Terminals)
For quick testing or headless environments, use `cli.py`:

```bash
# Display all help options
python cli.py --help

# Basic test (ONVIF & RTSP Auth)
python cli.py --host 192.168.1.100 -u admin -p yourpassword

# Force SHA-256, use WS-Security for ONVIF, and Quote Algorithm
python cli.py --host 192.168.1.100 -u admin -p yourpass --algorithm SHA-256 --quote --ws-auth

# Test Auth and immediately launch VLC Stream using Local Proxy fix
python cli.py --host 192.168.1.100 -u admin -p yourpass --stream --proxy
```

## Structure
- `myovif.py`: Main GUI Application.
- `cli.py`: Command-Line interface.
- `core/`: Core engine handling HTTP/RTSP requests, proxy logic, and presets.
  - `engine.py`: ONVIF / RTSP protocol implementations.
  - `vlc_manager.py`: Player launching and Local Proxy bridging.
  - `presets.py`: Configuration and preset management.
