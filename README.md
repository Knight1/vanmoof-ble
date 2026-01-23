# VanMoof BLE Communication

A collection of tools for communicating with VanMoof S5/A5 e-bikes via Bluetooth Low Energy (BLE). This project enables direct bike communication for authentication, unlocking, and other commands.

## Features

- 🔐 **BLE Authentication** - Authenticate with your VanMoof S5/A5 or later bikes using certificates from the API
- 🔓 **Unlock Control** - unlock your bike via Bluetooth
- 🔊 **Sound Control** - Play sounds on the bike
- ⚡ **Power Level Control** - Adjust power assist levels (0-4)
- 💡 **Light Control** - Control front light mode (off, on, auto)
- 🔍 **BLE Scanning** - Discover nearby VanMoof bikes
- 🛠️ **Frida Scripts** - Android app analysis tools for protocol research

## Prerequisites

- VanMoof SA5 or later bike
- Python 3.8+
- Bluetooth Low Energy capable device (Mac, Raspberry Pi 1+, any Linux Computer with latest OS is fine, even Windows works, Android too if you install Python on it)
- VanMoof bike certificate and private key using [vanmoof-certificates](https://github.com/Knight1/vanmoof-certificates)

## Installation

```bash
git clone https://github.com/Knight1/vanmoof-ble.git
cd vanmoof-ble

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### CLI Options

| Option | Description |
| ------ | ----------- |
| `--privkey` | Base64-encoded Ed25519 private key (required unless using only `--scan`). |
| `--cert` | Base64-encoded VanMoof certificate containing CBOR payload (required unless using only `--scan`). |
| `--mac` | Bluetooth MAC address of the bike. If omitted, the client scans and picks the first match. |
| `--scan` | Scan for nearby VanMoof bikes and print their addresses. No authentication attempted. |
| `--debug` | Enable verbose debug logging. |
| `--timestamp` | Prefix TX/RX logs with timestamps in `seconds.microseconds` format (6 decimals). |

### Scanning for Bikes

```bash
python main.py --scan
```

### Connecting and Authenticating

```bash
python main.py --privkey "YOUR_BASE64_PRIVATE_KEY" --cert "YOUR_BASE64_CERTIFICATE"
```

### With a specific MAC Address

```bash
python main.py --privkey "..." --cert "..." --mac "XX:XX:XX:XX:XX:XX"
```

You need to use the MAC Address since the UUID from the Bike changes after every reboot!  

### Interactive Commands


Once connected and authenticated, you can use these commands:

| Command                | Description                | BLE Packet (hex)         |
|------------------------|----------------------------|--------------------------|
| `unlock`               | Unlock the bike            | 81 00 03 01 00 A0 01     |
| `lock`                 | Lock the bike              | 81 00 03 01 00 A0 00     |
| `arm`                  | Arm (enable) alarm         | 81 00 03 01 01 A0 01     |
| `disarm`               | Disarm (disable) alarm     | 81 00 03 01 01 A0 00     |
| `alarm`                | Trigger alarm sound        | 81 00 03 01 02 A0 01     |
| `beep`                 | Play a sound               | 81 00 03 01 00 21 01     |
| `bell`                 | Bell ding                  | 81 00 03 02 00 A0 01     |
| `bell2`                | Bell double ding           | 81 00 03 02 00 A0 02     |
| `horn`                 | Horn sound                 | 81 00 03 02 01 A0 01     |
| `power <0-4>`          | Set power level            | 81 00 03 01 00 67 <n>    |
| `poweron`              | Power on bike              | 81 00 03 03 00 A0 01     |
| `poweroff`             | Power off bike             | 81 00 03 03 00 A0 00     |
| `booston`              | Enable boost mode          | 81 00 03 03 01 A0 01     |
| `boostoff`             | Disable boost mode         | 81 00 03 03 01 A0 00     |
| `lights <off|on|auto>` | Set light mode             | 81 00 03 01 00 6B <n>    |
| `quit`                 | Exit the program           | -                        |


## Project Structure

```
vanmoof-ble/
├── main.py                 # Main BLE client application
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── LICENSE                # MIT License
├── docs/
│   └── PROTOCOL.md        # Detailed protocol documentation
└── frida/                 # Frida scripts for Android app analysis
    ├── ble_sniffer.js     # Full-duplex GATT sniffer
    ├── sniff_gatt.js      # Basic GATT write monitor
    ├── hook_dispatcher.js # Dispatcher hook for command tracing
    ├── deep_scan.js       # Deep object exploration
    ├── dump_security.js   # Security state extractor
    └── dump_security_v3.js # Low-level security extraction
```

## Protocol Overview

For detailed protocol documentation, see [docs/PROTOCOL.md](docs/PROTOCOL.md).

The VanMoof SA5 and later uses a custom BLE protocol with the following authentication flow:

1. **Init Exchange** - Bike sends initialization message, client echoes back
2. **Certificate Submission** - Client sends CA-signed certificate containing CBOR payload
3. **Challenge-Response** - Bike sends 16-byte challenge, client signs with Ed25519 private key
4. **Authentication Confirmed** - Bike confirms with `{auth: true}`

### Key UUIDs
- **Service/Characteristic**: `e3d80001-3416-4a54-b011-68d41fdcbfcf`

### Packet Structure
- Byte 0: Message type (0x80/0x81/0x82) - must match bike's initial response
- Byte 1: Reserved (0x00)
- Byte 2: Payload length (varies by certificate size)
- Byte 3: Command type
- Byte 4+: Payload (often CBOR encoded)

## Extracting Credentials for debugging

### From Android Device (requires root or developer mode)

```bash
adb root
adb shell
cat /data/data/nl.samsonit.vanmoofapp/shared_prefs/VANMOOF.xml
```

For certificate data:
```bash
cd /data/data/nl.samsonit.vanmoofapp/databases
sqlite3 rider-app-database
SELECT id, name FROM bikes;
SELECT * FROM bike_certificate;
```

> Note: The `bike_certificate` table references the app's bike ID, so you'll need to match it if you have multiple SA5 or later bikes.

## Frida Scripts

These scripts are for analyzing the VanMoof Android app to understand the BLE protocol. Requires [Frida](https://frida.re/) installed.

### Usage

```bash
frida -U -f nl.samsonit.vanmoofapp -l frida/ble_sniffer.js
```

### Available Scripts

| Script | Description |
|--------|-------------|
| `ble_sniffer.js` | Captures all BLE traffic (TX/RX) |
| `sniff_gatt.js` | Basic GATT write monitor with stack traces |
| `hook_dispatcher.js` | Hooks the command dispatcher class |
| `deep_scan.js` | Explores internal object structures |
| `dump_security.js` | Extracts encryption keys and IVs |
| `dump_security_v3.js` | Low-level security state extraction |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request ❤️