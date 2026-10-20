# VanMoof BLE

A Python tool for communicating with VanMoof S5, A5, and S6 e-bikes via Bluetooth Low Energy (BLE). Authenticate, control, and query your bike directly from any computer or device with Bluetooth.

## Features

- **Authentication** - Ed25519 certificate-based authentication over BLE
- **Unlock** - Unlock the bike remotely
- **Alarm** - Enable and disable the alarm
- **Bell Tone** - Select the bell sound (tones differ between S5/A5 and S6)
- **Assist Level** - Set motor assist level (0-4)
- **Lights** - Control light mode (off, on, auto)
- **Speed Region** - Set speed region (EU 25 km/h, US 32 km/h, JP 24 km/h, offroad; S5/A5)
- **Status Queries** - Query lock state, power state, alarm, lights, assist level, region, battery
- **Telemetry** - Live ride, battery and sensor readings
- **Module Status** - Per-module status derived from the bike's CAN-bus heartbeats
- **Device Info** - Read firmware version, model, serial from BLE GATT
- **BLE Scanning** - Discover nearby VanMoof bikes
- **Protocol Tools** - Write any topic, decode captured packets, send raw hex
- **Debug Mode** - Full packet logging with optional timestamps

Both the S5/A5 and the S6 are supported. They use different BLE protocols; the client detects the model and speaks the right one. The S5/A5-only commands (region, telemetry streaming and module status) are noted below.

## Prerequisites

- VanMoof S5, A5, or S6 bike
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

Once connected and authenticated, the client reads the bike's state (lock, battery, settings) and the following commands are available. `unlock`, `arm`/`disarm`, `power`, `lights`, `bellsound`, `battery`, `query`, `read`, `write` and `topics` work on both models; `region`, `subscribe`/`unsubscribe`, `sensors`, `monitor` and `modules` are S5/A5 only. The topic/packet columns below show the S5/A5 wire form (see [docs/PROTOCOL.md](docs/PROTOCOL.md) for the S6 equivalents).

### Lock / Security

| Command   | Description              | Topic                         | BLE Packet (hex)        |
|-----------|--------------------------|-------------------------------|-------------------------|
| `unlock`  | Unlock the bike          | `0x00A0` ux/lock/unlock = 1   | `81 00 03 01 00 A0 01`  |
| `lock`    | Explains how the S5/A5 locks (there is no BLE lock command) | - | - |
| `arm`     | Enable the alarm         | `0x006F` settings/alarm/set   | `81 00 03 01 00 6F F5`  |
| `disarm`  | Disable the alarm        | `0x006F` settings/alarm/set   | `81 00 03 01 00 6F F4`  |

### Settings

| Command                         | Description         | Topic                               | BLE Packet (hex)        |
|---------------------------------|---------------------|-------------------------------------|-------------------------|
| `power <0-4>`                   | Set assist level    | `0x0067` settings/assist_level/set  | `81 00 03 01 00 67 <N>` |
| `lights <off\|on\|auto>`         | Set light mode      | `0x006B` settings/light_mode/set    | `81 00 03 01 00 6B <N>` |
| `region <eu\|us\|jp\|offroad>`    | Set speed region (S5/A5) | `0x0062` settings/region/set   | `81 00 03 01 00 62 <N>` |
| `bellsound [tone]`              | Select bell tone    | `0x0073` settings/bell_sound/set    | `81 00 03 01 00 73 <N>` |

Values: lights `1` on, `2` off, `3` auto; region `0` EU, `1` US, `2` JP, `3` offroad; bell `0` ding_dong, `1` party_horn, `2` ping, `3` vanmoof, `4` ship_horn. The bike confirms each change by re-publishing the setting, which the client prints.

### Telemetry (Real-time Sensor Data, S5/A5)

| Command                         | Description                                          |
|---------------------------------|------------------------------------------------------|
| `subscribe [group\|topic ...]`   | Subscribe to topics (default: telemetry; groups: `status`, `telemetry`, `modules`, `all`) |
| `unsubscribe <group\|topic ...>` | Stop topics                                         |
| `sensors`                       | Show last known readings                             |
| `monitor`                       | Live display of changing readings (Ctrl+C to stop)   |
| `modules`                       | Show the status of each module (CAN-bus heartbeats)  |

Available readings:

| Group        | Topics                                                                 |
|--------------|------------------------------------------------------------------------|
| Ride         | speed, pedal RPM, torque, motor speed, motor current, motor temperature, brake level, boost, calories, ride distance |
| Battery      | battery % (as shown in the app), raw state of charge, power state      |
| Environment  | light, humidity, temperature, air quality sensors                      |
| Modules      | status of ble, battery, charger, e-lock, e-shifter, lights, modem, motor, power control, power pedal, user ECU |

Ride readings mostly update while riding. Values are shown as the bike sends them unless the unit is known.

### Information

| Command            | Description                                   |
|--------------------|-----------------------------------------------|
| `status`           | Show link status (auth, encryption, connection parameters) |
| `info`             | Show bike info (credentials, GATT device info, bike state) |
| `battery`          | Query battery level                           |
| `services`         | List all BLE GATT services and characteristics|
| `query <target>`   | Query specific state (see below)              |
| `topics`           | Show all last decoded topic values            |

Query targets (S5/A5): `lock`, `power`, `alarm`, `lights`, `level`, `region`, `boost`, `battery`, `all`. On the S6: `lock`, `alarm`, `lights`, `level`, `battery`, `all`.

### Protocol Tools

| Command                 | Description                                   |
|-------------------------|-----------------------------------------------|
| `read <topic ...>`      | Read one or more topic values (e.g., `read 0x022a`) |
| `write <topic> <value>` | Write a topic value (e.g., `write 0x006b 2`)  |
| `decode <hex>`          | Decode a captured S5/A5 or S6 message or fragment offline |
| `raw <hex>`             | Send raw hex bytes (e.g., `raw 81 00 03 01 00 A0 01`) |
| `errors`                | Explain how errors are reported               |
| `error <code>`          | Format an error number or S6 DTC (e.g. `error 0x9050`) |
| `help`                  | Show all available commands                   |
| `quit`                  | Disconnect and exit                           |

## Project Structure

```
vanmoof-ble/
|-- main.py                    # Main BLE client application
|-- requirements.txt           # Python dependencies
|-- README.md                  # This file
|-- commands/                  # BLE command modules
|   |-- alarm.py               # Alarm enable/disable
|   |-- info.py                # Status queries, device info, GATT services
|   |-- lights.py              # Light mode control
|   |-- lock.py                # Unlock
|   |-- power.py               # Assist level control
|   |-- region.py              # Speed region control (EU/US/JP/offroad)
|   |-- sound.py               # Bell tone selection
|   +-- telemetry.py           # Telemetry and module status
|-- utils/                     # Utility modules
|   |-- credentials_utils.py   # Certificate parsing & key validation
|   |-- error_codes.py         # Faithful error / DTC formatting
|   |-- protocol_codes.py      # S5/A5 topic protocol: framing, topics, values
|   +-- s6_protocol.py         # S6 message protocol: framing, topics, values
|-- tests/                     # unittest suite + seeded fuzzers (tests/test_fuzz.py)
+-- docs/
    |-- BLEUUID.md             # BLE services and characteristics
    +-- PROTOCOL.md            # Complete BLE protocol reference
```

## Protocol Overview

For the full protocol specification, see [docs/PROTOCOL.md](docs/PROTOCOL.md).

The VanMoof S5/A5 speaks a small publish/subscribe protocol over a single GATT characteristic (`e3d80001-3416-4a54-b011-68d41fdcbfcf`). Each 16-bit topic id maps to a topic on the bike's internal MQTT bus. The S6 uses a related message format on its own characteristic (`df286101-...`); see [docs/PROTOCOL.md](docs/PROTOCOL.md). The S5/A5 flow:

1. **Certificate** - Client sends its CA-signed certificate (64-byte signature + CBOR payload)
2. **Challenge-Response** - Bike sends a 16-byte nonce, client signs it with its Ed25519 key
3. **Confirmation** - Bike confirms with `{auth: true}` (a rejected certificate makes the bike disconnect)
4. **Subscribe** - Client subscribes to the topics it wants; state topics arrive immediately

### Packet Format

```
[fragment header: 0x81 first / 0x01 continuation] [remaining: 2 bytes BE] [PayloadType] [body...]

PayloadType: 1 = topic value   2 = subscribe   3 = certificate   4 = challenge
             5 = auth details  6 = data length 7 = connection params
```

A topic value is `[topic: 2 bytes BE][CBOR value]`; settings are written to their `.../set` topic and the bike re-publishes the value topic.

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

Contributions are welcome! Please feel free to submit a Pull Request
