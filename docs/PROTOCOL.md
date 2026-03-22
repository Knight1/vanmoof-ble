# VanMoof S5/A5 BLE Protocol Reference

---

## Table of Contents

1. [Overview](#overview)
2. [BLE Service Information](#ble-service-information)
3. [Packet Structure](#packet-structure)
4. [Authentication](#authentication)
5. [Certificate Format](#certificate-format)
6. [Command Reference](#command-reference)
7. [Read Commands (Queries)](#read-commands-queries)
8. [Status Messages](#status-messages)
9. [Encryption (Optional)](#encryption-optional)
10. [Response Parsing](#response-parsing)
11. [Troubleshooting](#troubleshooting)
12. [Security Notes](#security-notes)

---

## Overview

The VanMoof S5 and A5 e-bikes use Bluetooth Low Energy (BLE) for communication. All commands and responses flow through a single custom GATT characteristic using a binary protocol with CBOR-encoded status payloads.

### Key Properties

- **Authentication**: Ed25519 digital signatures with certificate-based trust
- **Certificates**: Issued by a Certificate Authority, containing CBOR-encoded metadata
- **Challenge-Response**: Bike sends a 16-byte nonce, client signs it with Ed25519 private key
- **Protocol**: Binary frames with CBOR for structured data
- **Encryption**: Optional AES-128-CBC encrypted sessions (used in some firmware versions)

### Required Credentials

1. **Ed25519 Private Key** (32 or 64 bytes, base64 encoded)
2. **Certificate** (base64 encoded, contains CA signature + CBOR payload)

---

## BLE Service Information

| Property             | Value                                        |
|----------------------|----------------------------------------------|
| Service UUID         | `e3d80000-3416-4a54-b011-68d41fdcbfcf`       |
| Characteristic UUID  | `e3d80001-3416-4a54-b011-68d41fdcbfcf`       |
| Properties           | Write, Notify                                |

All communication happens through this single characteristic. The client writes commands and receives responses via notifications.

---

## Packet Structure

### Frame Format

Every packet starts with a 2-byte header followed by a type/length byte and a subtype byte:

```
Byte 0: Frame byte (direction indicator)
Byte 1: Reserved (always 0x00)
Byte 2: Module/Length (context-dependent)
Byte 3: Command/Subtype
Byte 4+: Payload
```

### Frame Bytes (Byte 0)

| Value  | Direction       | Description                              |
|--------|-----------------|------------------------------------------|
| `0x80` | Bike -> Client  | Standard bike response                   |
| `0x81` | Client -> Bike  | Standard client command                  |
| `0x82` | Bike -> Client  | Alternate response (some firmware)       |

The client must match the frame byte used by the bike. During authentication, echo the exact frame byte received in the init message.

### Byte 2: Module vs Length

Byte 2 serves different purposes depending on the message type:

**For commands (write/read/config):**

| Value  | Module     | Purpose                        |
|--------|------------|--------------------------------|
| `0x02` | Read       | Query current value            |
| `0x03` | Write      | Set a value                    |
| `0x04` | Configure  | Set persistent configuration   |

**For protocol messages (auth, status):**

Byte 2 is the payload length (number of bytes after byte 3):

| Example          | Byte 2 | Meaning                       |
|------------------|--------|-------------------------------|
| Challenge        | `0x10` | 16 bytes of challenge data    |
| Challenge resp.  | `0x40` | 64 bytes of signature         |
| Certificate      | varies | Certificate data length       |
| Status           | varies | CBOR payload length           |

### Message Types (Byte 2 + Byte 3 combinations)

| Byte 2 | Byte 3 | Direction     | Description                    |
|--------|--------|---------------|--------------------------------|
| `0x0D` | `0x05` | Both          | Status message (CBOR)          |
| `0x10` | `0x04` | Bike->Client  | Authentication challenge       |
| `0x40` | `0x04` | Client->Bike  | Challenge response (signature) |
| length | `0x03` | Client->Bike  | Certificate submission         |
| `0x02` | varies | Client->Bike  | Read command (query)           |
| `0x03` | varies | Client->Bike  | Write command (set value)      |
| `0x04` | varies | Client->Bike  | Configuration command          |
| `0x07` | `0x01` | Bike->Client  | Command response               |
| `0x1F` | `0x07` | Bike->Client  | Connection parameters          |

---

## Authentication

### Flow Overview

```
Client                                          Bike
  |                                               |
  |            1. Connect (BLE GATT)              |
  |<--------------------------------------------->|
  |                                               |
  |         2. Init {enc: false, auth: false}      |
  |<----------------------------------------------|
  |                                               |
  |         3. Echo init back                      |
  |---------------------------------------------->|
  |                                               |
  |         4. Certificate [CA_sig + CBOR]         |
  |---------------------------------------------->|
  |                                               |
  |         5. Challenge (16-byte nonce)           |
  |<----------------------------------------------|
  |                                               |
  |         6. Signed challenge (64-byte sig)      |
  |---------------------------------------------->|
  |                                               |
  |         7. Confirm {enc: false, auth: true}    |
  |<----------------------------------------------|
```

### Step 1: Connect and Subscribe

```python
from bleak import BleakClient

CHAR_UUID = "e3d80001-3416-4a54-b011-68d41fdcbfcf"

client = BleakClient(mac_address)
await client.connect()
await client.start_notify(CHAR_UUID, notification_handler)
```

### Step 2: Receive and Echo Init

The bike sends an init status message:

```
RX: 81 00 0D 05 BF 63 65 6E 63 F4 64 61 75 74 68 F4 FF
                      └── CBOR: {"enc": false, "auth": false}
```

Echo it back exactly (preserve the frame byte):

```
TX: 81 00 0D 05 BF 63 65 6E 63 F4 64 61 75 74 68 F4 FF
```

### Step 3: Send Certificate

Build the certificate packet with the full certificate (CA signature + CBOR payload):

```
TX: [frame_byte] 00 [cert_length] 03 [64-byte CA signature] [CBOR payload]
```

- `cert_length`: Length of the certificate data (CA signature + CBOR)
- `0x03`: Certificate subtype identifier
- The CA signature is the original signature from the certificate, not recomputed

```python
def build_auth_packet(ca_signature, cert_cbor, first_byte=0x81):
    cert_data = ca_signature + cert_cbor
    packet = bytearray([first_byte, 0x00, len(cert_data), 0x03])
    packet.extend(cert_data)
    return bytes(packet)
```

### Step 4: Receive Challenge

The bike sends a 16-byte random challenge nonce:

```
RX: 81 00 10 04 [16 random bytes]
         |  |    └── Challenge nonce
         |  └── Subtype 0x04 (challenge)
         └── Length 0x10 (16 bytes)
```

### Step 5: Sign and Send Response

Sign the 16-byte challenge with the Ed25519 private key to produce a 64-byte signature:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def build_challenge_response(private_key, challenge, first_byte=0x81):
    signature = private_key.sign(challenge)  # 64-byte Ed25519 signature
    packet = bytearray([first_byte, 0x00, 0x40, 0x04])
    packet.extend(signature)
    return bytes(packet)
```

```
TX: [frame_byte] 00 40 04 [64-byte Ed25519 signature]
                  |  |
                  |  └── Subtype 0x04 (challenge response)
                  └── Length 0x40 (64 bytes)
```

### Step 6: Receive Confirmation

The bike confirms successful authentication:

```
RX: 81 00 0D 05 BF 63 65 6E 63 F4 64 61 75 74 68 F5 FF
                                                   |
                                            F5 = true (authenticated!)
```

CBOR decoded: `{"enc": false, "auth": true}`

---

## Certificate Format

### Structure

The certificate is a binary blob structured as:

```
┌────────────────────────────────────┐
│ Bytes 0-63:   CA Signature         │  Ed25519 signature from the CA
│ Bytes 64+:    CBOR Payload         │  Certificate metadata
└────────────────────────────────────┘
```

### CBOR Payload Fields

The CBOR payload is a map with 7 fields:

| Key | Type    | Description                              |
|-----|---------|------------------------------------------|
| `i` | uint32  | Certificate ID                           |
| `f` | string  | Frame number (e.g., "SVTBKLxxxxxOA")     |
| `b` | string  | Bike serial (typically same as frame)    |
| `e` | uint32  | Expiry timestamp (Unix epoch, seconds)   |
| `r` | uint8   | Access role                              |
| `u` | bytes   | User UUID (16 bytes)                     |
| `p` | bytes   | Ed25519 public key (32 bytes)            |

### Role Values

| Value | Role   | Permissions                              |
|-------|--------|------------------------------------------|
| 7     | Owner  | Full control of all bike functions       |
| 3     | User   | Limited access (ride, basic controls)    |

### Example CBOR (Annotated Hex)

```
A7                          # map(7)
   61 69                    # key: "i"
   1A 00 01 1F 2F           # value: 73519 (cert ID)
   61 66                    # key: "f"
   6D 535654424B4C...       # value: "SVTBKLxxxxxOA" (frame)
   61 62                    # key: "b"
   6D 535654424B4C...       # value: "SVTBKLxxxxxOA" (serial)
   61 65                    # key: "e"
   1A 69 6F 67 03           # value: 1768908547 (expiry)
   61 72                    # key: "r"
   07                       # value: 7 (owner)
   61 75                    # key: "u"
   50 [16 bytes]            # value: user UUID
   61 70                    # key: "p"
   58 20 [32 bytes]         # value: Ed25519 public key
```

---

## Command Reference

### Command Packet Format

Write commands (module `0x03`):

```
[frame_byte] 00 03 [group] [sub] [param] [value]
```

Configuration commands (module `0x04`):

```
[frame_byte] 00 04 [group] [sub] [param] [value]
```

### Command Groups

| Group  | Hex    | Description                              |
|--------|--------|------------------------------------------|
| Security | `0x01` | Lock, alarm, lights, sounds            |
| Sound    | `0x02` | Bell, horn                             |
| Ride     | `0x03` | Power on/off, boost                    |
| Config   | `0x30` | Assist level, speed region             |

### Sub-commands

| Group  | Sub    | Target                                   |
|--------|--------|------------------------------------------|
| `0x01` | `0x00` | Lock/Unlock                              |
| `0x01` | `0x01` | Alarm arm/disarm                         |
| `0x01` | `0x02` | Alarm trigger                            |
| `0x02` | `0x00` | Bell                                     |
| `0x02` | `0x01` | Horn                                     |
| `0x03` | `0x00` | Power on/off                             |
| `0x03` | `0x01` | Boost on/off                             |
| `0x30` | `0x00` | Assist level                             |
| `0x30` | `0x01` | Speed region                             |

### Parameter Types

| Param  | Hex    | Purpose                                  |
|--------|--------|------------------------------------------|
| State  | `0xA0` | On/off toggle, level values              |
| Light  | `0x6B` | Light mode control                       |
| Sound  | `0x21` | Sound ID selection                       |

### Lock / Unlock

| Command         | Packet (hex)            | Description              |
|-----------------|-------------------------|--------------------------|
| Unlock          | `81 00 03 01 00 A0 01`  | Unlock the bike          |
| Lock            | `81 00 03 01 00 A0 00`  | Lock the bike            |

### Alarm

| Command           | Packet (hex)            | Description            |
|-------------------|-------------------------|------------------------|
| Arm alarm         | `81 00 03 01 01 A0 01`  | Enable alarm           |
| Disarm alarm      | `81 00 03 01 01 A0 00`  | Disable alarm          |
| Trigger alarm     | `81 00 03 01 02 A0 01`  | Trigger alarm sound    |

### Sound / Bell

| Command           | Packet (hex)            | Description            |
|-------------------|-------------------------|------------------------|
| Bell (single)     | `81 00 03 02 00 A0 01`  | Single bell ding       |
| Bell (double)     | `81 00 03 02 00 A0 02`  | Double bell ding       |
| Horn              | `81 00 03 02 01 A0 01`  | Horn sound             |
| Play sound        | `81 00 03 01 00 21 XX`  | Play sound by ID       |

### Lights

| Command           | Packet (hex)            | Description            |
|-------------------|-------------------------|------------------------|
| Lights off        | `81 00 03 01 00 6B 00`  | Turn lights off        |
| Lights on         | `81 00 03 01 00 6B 01`  | Always on              |
| Lights auto       | `81 00 03 01 00 6B 03`  | Automatic / sensor     |

Light mode values:

| Value | Mode                                            |
|-------|-------------------------------------------------|
| `0x00` | Off                                            |
| `0x01` | Always on                                      |
| `0x03` | Auto (sensor-triggered)                        |

### Ride Control

| Command           | Packet (hex)            | Description            |
|-------------------|-------------------------|------------------------|
| Power on          | `81 00 03 03 00 A0 01`  | Power on electronics   |
| Power off         | `81 00 03 03 00 A0 00`  | Power off electronics  |
| Enable boost      | `81 00 03 03 01 A0 01`  | Enable boost mode      |
| Disable boost     | `81 00 03 03 01 A0 00`  | Disable boost mode     |

### Power Assist Level

Uses configuration module `0x04`:

| Level   | Packet (hex)            | Description            |
|---------|-------------------------|------------------------|
| Off     | `81 00 04 30 00 A0 00`  | No motor assist        |
| Level 1 | `81 00 04 30 00 A0 01`  | Lowest assist          |
| Level 2 | `81 00 04 30 00 A0 02`  | Medium-low assist      |
| Level 3 | `81 00 04 30 00 A0 03`  | Medium-high assist     |
| Level 4 | `81 00 04 30 00 A0 04`  | Maximum assist         |

Note: Changing the power level requires the bike to be unlocked and powered on.

### Speed Region

Uses configuration module `0x04`, config group `0x30`, subcommand `0x01`:

| Region  | Packet (hex)            | Max Speed              |
|---------|-------------------------|------------------------|
| EU      | `81 00 04 30 01 A0 00`  | 25 km/h                |
| US      | `81 00 04 30 01 A0 01`  | 32 km/h                |
| JP      | `81 00 04 30 01 A0 02`  | 24 km/h                |

---

## Read Commands (Queries)

Read commands use module `0x02` to query the current value of any settable parameter. They follow the same group/sub/param structure as write commands but without a value byte:

```
[frame_byte] 00 02 [group] [sub] [param]
```

The bike responds via a command response message (`07 01`) or a CBOR status update (`0D 05`).

### Available Read Commands

| Query            | Packet (hex)       | Description               |
|------------------|--------------------|---------------------------|
| Lock state       | `81 00 02 01 00 A0` | Is the bike locked?      |
| Alarm state      | `81 00 02 01 01 A0` | Is the alarm armed?      |
| Light mode       | `81 00 02 01 00 6B` | Current light setting    |
| Power state      | `81 00 02 03 00 A0` | Is the bike powered on?  |
| Boost state      | `81 00 02 03 01 A0` | Is boost enabled?        |
| Assist level     | `81 00 02 30 00 A0` | Current assist level     |
| Speed region     | `81 00 02 30 01 A0` | Current speed region     |

### Response Format

Command responses arrive as notifications with bytes 2-3 = `07 01`:

```
RX: 80 00 07 01 [group] [sub] [param] [value...]
```

---

## Status Messages

The bike sends CBOR-encoded status messages automatically during authentication and after state changes. These use message type `0x0D 0x05`.

### Format

```
[frame_byte] 00 [length] 05 [CBOR data]
```

The CBOR data uses an indefinite-length map (starts with `0xBF`, ends with `0xFF`).

### Known Status / Telemetry Fields

The bike streams CBOR telemetry data via notifications when powered on. The set of fields varies by model and firmware version. All known fields:

**Connection State:**

| Key         | Type    | Description                              |
|-------------|---------|------------------------------------------|
| `enc`       | bool    | Encryption enabled                       |
| `auth`      | bool    | Authentication status                    |
| `enabled`   | bool    | Bike electronics powered on              |
| `ready`     | bool    | Bike ready for commands                  |

**Bike State:**

| Key         | Type    | Description                              |
|-------------|---------|------------------------------------------|
| `locked`    | bool    | Lock state                               |
| `alarm`     | bool    | Alarm armed                              |
| `boost`     | bool    | Boost mode active                        |
| `boost_btn` | bool    | Boost button currently pressed           |
| `pwr`       | int     | Assist level (0-4)                       |
| `light`     | int     | Light mode (0=off, 1=on, 3=auto)         |
| `gear`      | int     | Current gear                             |
| `region`    | int     | Speed region setting                     |
| `err`       | int     | Error code (0 = no error)                |

**Motion Sensors:**

| Key         | Type    | Description                              |
|-------------|---------|------------------------------------------|
| `spd`       | float   | Current speed (km/h)                     |
| `cad`       | int     | Pedal cadence / RPM                      |
| `torque`    | float   | Pedal torque (Nm)                        |

**Battery & Power:**

| Key         | Type    | Description                              |
|-------------|---------|------------------------------------------|
| `bat`       | int     | Battery level (percentage)               |
| `charging`  | bool    | Battery currently charging               |

**Temperature Sensors:**

| Key           | Type  | Description                              |
|---------------|-------|------------------------------------------|
| `motor_temp`  | int   | Motor temperature (C)                    |
| `driver_temp` | int   | Motor driver/controller temperature (C)  |
| `module_temp` | int   | Main module temperature (C)              |
| `temp`        | int   | General temperature (C)                  |

**Environment Sensors:**

| Key           | Type  | Description                              |
|---------------|-------|------------------------------------------|
| `light`       | int   | Ambient light sensor value               |
| `humidity`    | int   | Humidity (%)                             |
| `air_quality` | int   | Air quality index (S6)                   |

**Distance:**

| Key         | Type    | Description                              |
|-------------|---------|------------------------------------------|
| `dst`       | float   | Trip distance (km)                       |
| `odo`       | float   | Odometer total (km)                      |

**Device Info:**

| Key         | Type    | Description                              |
|-------------|---------|------------------------------------------|
| `fw`        | string  | Firmware version                         |
| `hw`        | string  | Hardware revision                        |

### Init Status Example

```
BF 63 65 6E 63 F4 64 61 75 74 68 F4 FF
   └─ "enc"  └─false └─ "auth"  └─false └─ end map
```

Decoded: `{"enc": false, "auth": false}`

### Authenticated Status Example

```
BF 63 65 6E 63 F4 64 61 75 74 68 F5 FF
```

Decoded: `{"enc": false, "auth": true}`

---

## Encryption (Optional)

Some firmware versions support (or require) an AES-128-CBC encrypted session after authentication. When encryption is active, the init status shows `{"enc": true, "auth": false}`.

### Encryption Handshake

After successful authentication:

#### Step 1: Client Sends Encryption Init

```
TX: A0 [16-byte random nonce]
```

The client generates a random 16-byte nonce and sends it with the `0xA0` prefix.

#### Step 2: Bike Responds with Nonce

```
RX: A1 [16-byte bike nonce]
```

The bike responds with its own 16-byte nonce prefixed with `0xA1`.

#### Step 3: Derive Encryption IVs

IVs are derived asymmetrically from the bike's nonce:

```python
# TX IV (Client -> Bike): bitwise NOT of bike nonce
iv_encrypt = bytes(b ^ 0xFF for b in bike_nonce)

# RX IV (Bike -> Client): bike nonce as-is
iv_decrypt = bike_nonce
```

### Encrypted Frame Format

After the handshake, all subsequent frames are encrypted:

```
Plaintext:  [length] [0x01] [payload bytes] [zero-pad to 16-byte boundary]
Ciphertext: AES-128-CBC(plaintext, key, iv)
```

### IV Chaining

After each encryption/decryption operation, the IV is updated to the last 16 bytes of the ciphertext:

```python
iv_encrypt = ciphertext[-16:]  # After encrypting
iv_decrypt = ciphertext[-16:]  # After decrypting
```

### Encryption Parameters

| Parameter   | Value                                        |
|-------------|----------------------------------------------|
| Cipher      | AES-128                                      |
| Mode        | CBC                                          |
| Key Size    | 16 bytes (128 bits)                          |
| IV Size     | 16 bytes (128 bits)                          |
| Padding     | Zero-pad to 16-byte boundary                 |
| IV Update   | Chained (last 16 bytes of previous ciphertext) |

---

## Response Parsing

### Command Responses

After sending a write or read command, the bike responds with a command response message:

```
RX: 80 00 07 01 [group] [sub] [param] [value...]
              |  |
              |  └── Mirrors the command's group/sub/param
              └── Subtype 0x01 (command response)
```

### CBOR Status Updates

After state changes, the bike also sends CBOR status updates:

```
RX: 80 00 0D 05 BF [key-value pairs...] FF
```

Parse using any CBOR library. Look for the `0xBF` marker (indefinite-length map start) to find the CBOR data within the packet.

### Connection Parameters

Some firmware versions send connection parameter messages:

```
RX: 80 00 1F 07 [CBOR data]
```

These contain BLE connection timing parameters and can generally be ignored.

---

## Troubleshooting

### Bike Disconnects After Certificate

| Symptom                    | Solution                                     |
|----------------------------|----------------------------------------------|
| Immediate disconnect       | Check that the length byte (byte 2) matches the actual certificate data size |
| Disconnect after cert sent | Use the original CA signature from the certificate, not a recomputed one |
| Key mismatch error         | Ensure the private key matches the public key embedded in the certificate |
| Certificate expired        | Request a new certificate (typically valid for 7 days) |
| Wrong frame byte           | Use the same frame byte (0x81/0x82) as the bike's init message |

### No Challenge Received

| Symptom                    | Solution                                     |
|----------------------------|----------------------------------------------|
| No response after cert     | Make sure to echo the init message back before sending the certificate |
| Timeout waiting            | Verify the certificate packet structure: `[frame] 00 [len] 03 [cert]` |
| Wrong response type        | Check that notifications are enabled on the characteristic |

### Auth Rejected After Challenge

| Symptom                    | Solution                                     |
|----------------------------|----------------------------------------------|
| Auth false after response  | Use the same private key that was used to generate the certificate |
| Signature invalid          | Sign exactly the 16-byte challenge, nothing more, nothing less |
| Wrong signature length     | Ed25519 signatures are always 64 bytes |

### Commands Not Working

| Symptom                    | Solution                                     |
|----------------------------|----------------------------------------------|
| No response to commands    | Verify authentication succeeded (`auth: true` in status) |
| Power level won't change   | Unlock the bike and power on electronics first |
| Lock won't respond         | Some operations need specific bike states (e.g., stationary) |

---

## Security Notes

- **Certificate expiry**: Certificates are typically valid for 7 days. Request new ones as needed.
- **CA signature validation**: The bike verifies that the certificate was signed by the trusted Certificate Authority. The CA signature proves the certificate is authorized for the specific bike.
- **Challenge-response**: The 16-byte random challenge prevents replay attacks. Each authentication session uses a unique challenge.
- **Key binding**: The Ed25519 public key in the certificate must match the private key used to sign the challenge. This binds the authentication to the specific keypair.
- **Role-based access**: The certificate's role field (owner=7, user=3) determines which commands are available.

---
