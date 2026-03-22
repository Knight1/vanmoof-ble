# VanMoof BLE Communication

A Python tool for communicating with VanMoof S5 and A5 e-bikes via Bluetooth Low Energy (BLE). Authenticate, control, and query your bike directly from any computer or device with Bluetooth.

## Features

- **Authentication** - Ed25519 certificate-based authentication over BLE
- **Lock / Unlock** - Lock and unlock the bike remotely
- **Alarm** - Arm, disarm, and trigger the alarm
- **Sound** - Bell (single/double ding), horn, and custom sounds
- **Power Control** - Power on/off bike electronics, enable/disable boost mode
- **Assist Level** - Set motor assist level (0-4)
- **Lights** - Control front light mode (off, on, auto)
- **Speed Region** - Set speed region (EU 25 km/h, US 32 km/h, JP 24 km/h)
- **Status Queries** - Query lock state, alarm, lights, power, battery, and more
- **Device Info** - Read firmware version, model, serial from BLE GATT
- **BLE Scanning** - Discover nearby VanMoof bikes
- **Raw Commands** - Send arbitrary hex commands for protocol exploration
- **Debug Mode** - Full packet logging with optional timestamps

## Prerequisites

- VanMoof S5 or A5 bike
- Python 3.8+
- Bluetooth Low Energy capable device
- Bike certificate and private key (see [vanmoof-certificates](https://github.com/Knight1/vanmoof-certificates))

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

| Option           | Description                                                |
|------------------|------------------------------------------------------------|
| `--privkey`      | Base64-encoded Ed25519 private key                         |
| `--cert`         | Base64-encoded certificate (CA signature + CBOR payload)   |
| `--mac`          | Bluetooth MAC address of the bike                          |
| `--scan`         | Scan for nearby VanMoof bikes                              |
| `--debug`        | Enable verbose packet logging                              |
| `--timestamp`    | Add timestamps to TX/RX logs                               |
| `--ignore-expiry`| Continue even if the certificate is expired                |

### Scanning for Bikes

```bash
python main.py --scan
```

### Connecting and Authenticating

```bash
python main.py --privkey "YOUR_BASE64_PRIVATE_KEY" --cert "YOUR_BASE64_CERTIFICATE"
```

### With a Specific MAC Address

```bash
python main.py --privkey "..." --cert "..." --mac "XX:XX:XX:XX:XX:XX"
```

The bike's BLE address changes after every reboot. Use `--scan` to find it, or specify `--mac` if you already know it.

### Debug Mode

```bash
python main.py --privkey "..." --cert "..." --debug --timestamp
```

## Interactive Commands

Once connected and authenticated, the following commands are available:

### Lock / Security

| Command   | Description              | BLE Packet (hex)        |
|-----------|--------------------------|-------------------------|
| `unlock`  | Unlock the bike          | `81 00 03 01 00 A0 01`  |
| `lock`    | Lock the bike            | `81 00 03 01 00 A0 00`  |
| `arm`     | Arm (enable) alarm       | `81 00 03 01 01 A0 01`  |
| `disarm`  | Disarm (disable) alarm   | `81 00 03 01 01 A0 00`  |
| `alarm`   | Trigger alarm sound      | `81 00 03 01 02 A0 01`  |

### Sound

| Command       | Description              | BLE Packet (hex)        |
|---------------|--------------------------|-------------------------|
| `bell`        | Single bell ding         | `81 00 03 02 00 A0 01`  |
| `bell2`       | Double bell ding         | `81 00 03 02 00 A0 02`  |
| `horn`        | Horn sound               | `81 00 03 02 01 A0 01`  |
| `beep`        | Play default sound       | `81 00 03 01 00 21 01`  |
| `sound <N>`   | Play sound by ID         | `81 00 03 01 00 21 <N>` |

### Ride Control

| Command    | Description              | BLE Packet (hex)        |
|------------|--------------------------|-------------------------|
| `poweron`  | Power on electronics     | `81 00 03 03 00 A0 01`  |
| `poweroff` | Power off electronics    | `81 00 03 03 00 A0 00`  |
| `booston`  | Enable boost mode        | `81 00 03 03 01 A0 01`  |
| `boostoff` | Disable boost mode       | `81 00 03 03 01 A0 00`  |

### Power & Configuration

| Command                 | Description              | BLE Packet (hex)        |
|-------------------------|--------------------------|-------------------------|
| `power <0-4>`           | Set assist level         | `81 00 04 30 00 A0 <N>` |
| `lights <off\|on\|auto>` | Set light mode           | `81 00 03 01 00 6B <N>` |
| `region <eu\|us\|jp>`    | Set speed region         | `81 00 04 30 01 A0 <N>` |

### Telemetry (Real-time Sensor Data)

The bike streams real-time telemetry via BLE notifications when powered on. Available sensors vary by model and firmware version.

| Command       | Description                                        |
|---------------|----------------------------------------------------|
| `monitor`     | Start live telemetry display (Ctrl+C to stop)      |
| `sensors`     | Show last known sensor readings                    |
| `subscribe`   | Activate telemetry stream (powers on bike)         |

Available sensor readings:

| Sensor         | Description                      | Unit   |
|----------------|----------------------------------|--------|
| Speed          | Current bike speed               | km/h   |
| Pedal RPM      | Pedal cadence                    | RPM    |
| Pedal Torque   | Pedal torque                     | Nm     |
| Boost Button   | Boost button pressed             | -      |
| Battery        | Battery charge level             | %      |
| Assist Level   | Current motor assist level       | 0-4    |
| Motor Temp     | Motor temperature                | C      |
| Driver Temp    | Motor driver/controller temp     | C      |
| Module Temp    | Main module temperature          | C      |
| Light Sensor   | Ambient light level              | -      |
| Humidity       | Humidity sensor                  | %      |
| Air Quality    | Air quality index (S6)           | AQI    |

### Information

| Command            | Description                                   |
|--------------------|-----------------------------------------------|
| `status`           | Show last received CBOR status                |
| `info`             | Show bike info (credentials, GATT device info)|
| `battery`          | Query battery level                           |
| `services`         | List all BLE GATT services and characteristics|
| `query <target>`   | Query specific state (see below)              |

Query targets: `lock`, `alarm`, `lights`, `power`, `boost`, `level`, `region`, `battery`, `all`

### Utility

| Command            | Description                                   |
|--------------------|-----------------------------------------------|
| `raw <hex>`        | Send raw hex bytes (e.g., `raw 81 00 03 01 00 A0 01`) |
| `help`             | Show all available commands                   |
| `quit`             | Disconnect and exit                           |

## Project Structure

```
vanmoof-ble/
├── main.py                    # Main BLE client application
├── requirements.txt           # Python dependencies
├── README.md                  # This file
├── commands/                  # BLE command modules
│   ├── alarm.py               # Alarm arm/disarm/trigger
│   ├── info.py                # Status queries, device info, GATT services
│   ├── lights.py              # Light mode control
│   ├── lock.py                # Lock/unlock
│   ├── power.py               # Assist level control
│   ├── region.py              # Speed region control (EU/US/JP)
│   ├── ride.py                # Power on/off, boost
│   ├── sound.py               # Bell, horn, sounds
│   └── telemetry.py           # Real-time sensor data streaming
├── utils/                     # Utility modules
│   ├── credentials_utils.py   # Certificate parsing & key validation
│   ├── crypto_utils.py        # Ed25519 signing & key loading
│   └── protocol_utils.py      # Packet builders (read/write/config/auth)
└── docs/
    └── PROTOCOL.md            # Complete BLE protocol reference
```

## Protocol Overview

For the full protocol specification, see [docs/PROTOCOL.md](docs/PROTOCOL.md).

The VanMoof S5/A5 uses a custom BLE protocol over a single GATT characteristic (`e3d80001-3416-4a54-b011-68d41fdcbfcf`):

1. **Init Exchange** - Bike sends `{enc: false, auth: false}`, client echoes back
2. **Certificate** - Client sends CA-signed certificate (64-byte signature + CBOR payload)
3. **Challenge-Response** - Bike sends 16-byte nonce, client signs with Ed25519 key
4. **Confirmation** - Bike confirms with `{auth: true}`

### Packet Format

```
[frame_byte] [0x00] [module/length] [subtype] [payload...]

Modules:  0x02 = Read    0x03 = Write    0x04 = Configure
```

### Command Groups

| Group | Hex    | Commands                                 |
|-------|--------|------------------------------------------|
| Security | `0x01` | Lock, alarm, lights, sounds           |
| Sound    | `0x02` | Bell, horn                            |
| Ride     | `0x03` | Power on/off, boost                   |
| Config   | `0x30` | Assist level, speed region            |

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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request ❤️