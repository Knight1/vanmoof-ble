# VanMoof S5/A5 BLE Authentication Protocol

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Protocol Summary](#protocol-summary)
4. [Detailed Protocol Analysis](#detailed-protocol-analysis)
5. [Certificate Structure](#certificate-structure)
6. [Authentication Flow](#authentication-flow)
7. [Command Reference](#command-reference)
8. [Implementation](#implementation)
9. [Troubleshooting](#troubleshooting)

---

## Overview

The VanMoof SA5 and later bikes uses Bluetooth Low Energy (BLE) for communication with the official app. This document describes the complete authentication protocol, allowing third-party tools to connect to and control the bike.

### Key Discoveries

- Authentication uses **Ed25519** digital signatures
- Certificates are issued by VanMoof's API and signed by their Certificate Authority (CA)
- The protocol uses a **challenge-response** mechanism
- Each user/device has a unique Ed25519 keypair
- The bike accepts multiple valid certificates

### Credentials Required
1. **Ed25519 Private Key** (32 or 64 bytes, base64 encoded)
2. **Certificate** from VanMoof API (base64 encoded)

---

## Protocol Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    VANMOOF S5 BLE AUTHENTICATION                            │
├───────────────────────────────────────────────────────────────────────────��─┤
│                                                                             │
│  1.  CONNECT                                                                 │
│     └── Connect to bike's BLE GATT service                                  │
│                                                                             │
│  2. INIT                                                                    │
│     ├── Bike → Client: {enc: false, auth: false}                            │
│     └── Client → Bike: {enc: false, auth: false}  (echo)                    │
│                                                                             │
│  3. CERTIFICATE                                                             │
│     └── Client → Bike: [CA Signature] + [Certificate CBOR]                  │
│                                                                             │
│  4. CHALLENGE                                                               │
│     └── Bike → Client: 16-byte random nonce                                 │
│                                                                             │
│  5. RESPONSE                                                                │
│     └── Client → Bike:  Ed25519 signature of the challenge                   │
│                                                                             │
��  6. CONFIRMATION                                                            │
│     └── Bike → Client: {enc: false, auth: true}                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Protocol Analysis

### BLE Service Information

| Property | Value |
|----------|-------|
| Service UUID | `e3d80000-3416-4a54-b011-68d41fdcbfcf` |
| Characteristic UUID | `e3d80001-3416-4a54-b011-68d41fdcbfcf` |
| Properties | Write, Notify |

### Packet Frame Structure

All packets use a variable-length header:

```
┌────────┬────────┬────────┬─────────────────┐
│ Byte 0 │ Byte 1 │ Byte 2 │ Payload         │
├────────┼────────┼────────┼─────────────────┤
│ 0x80   │ 0x00   │ Length │ Bike → Client   │
│ 0x81   │ 0x00   │ Length │ Client → Bike   │
│ 0x82   │ 0x00   │ Length │ Bike → Client * │
└────────┴────────┴────────┴─────────────────┘
* 0x82 observed in some protocol versions
* Length must match actual payload size
```

### Message Types

| Cmd | Sub | Direction | Description |
|-----|-----|-----------|-------------|
| 0x0D | 0x05 | Both | Status message (CBOR) |
| 0x10 | 0x04 | Bike→Client | Challenge (16 bytes) |
| 0x40 | 0x04 | Client→Bike | Challenge response (64 bytes) |
| Length | 0x03 | Client→Bike | Certificate packet (length varies) |
| 0x1F | 0x07 | Bike→Client | Connection parameters |
| 0x03 | 0x01 | Client→Bike | Command (lock/unlock/etc) |
| 0x07 | 0x01 | Bike→Client | Command response |

---

## Certificate Structure

### API Certificate Format

The certificate from VanMoof's API is structured as: 

```
┌─────────────────────────────────────────────────────────────┐
│                    API Certificate                          │
├─────────────────────────────────────────────────────────────┤
│ Bytes 0-63:    Ed25519 Signature (CA signed)                 │
│ Bytes 64+:    CBOR Payload                                  │
└─────────────────────────────────────────────────────────────┘
```

### CBOR Payload Structure

The CBOR payload is a map with 7 fields:

```cbor
{
  "i": <cert_id>,        // uint32 - Certificate ID
  "f": <frame_number>,   // string - Frame number (e.g., "SVTBKLxxxxxOA")
  "b": <bike_serial>,    // string - Bike serial (same as frame)
  "e": <expiry>,         // uint32 - Unix timestamp expiry
  "r": <role>,           // uint8  - Access role (7 = owner)
  "u": <user_id>,        // bytes  - 16-byte UUID
  "p": <public_key>      // bytes  - 32-byte Ed25519 public key
}
```

### Example Certificate (Hex)

```
CA Signature (64 bytes):
d4b323b3bd2a7760141be6ebfb26d9423050d3078589f690f1528018d5be7e2f
5e068e39012cfeda5fca58fdf197e3364d7ee8d969e35932249442524be33a00

CBOR Payload (decoded):
A7                          # map(7)
   61 69                    # "i"
   1A 00 01 1F 2F           # 73519 (cert ID)
   61 66                    # "f"
   6D 535654424B4C...        # "SVTBKLxxxxxOA"
   61 62                    # "b"
   6D 535654424B4C...       # "SVTBKLxxxxxOA"
   61 65                    # "e"
   1A 69 6F 67 03           # 1768908547 (expiry)
   61 72                    # "r"
   07                       # 7 (owner role)
   61 75                    # "u"
   50 1E08DEBC1ON73G344...   # 16-byte user UUID
   61 70                    # "p"
   58 20 9F2751608BE6...    # 32-byte public key
```

### Role Values

| Value | Role | Permissions |
|-------|------|-------------|
| 7 | Owner | Full control |
| 3 | User | Limited access |

---

## Authentication Flow

### Step 1: Connect and Subscribe

```python
from bleak import BleakClient

CHAR_UUID = "e3d80001-3416-4a54-b011-68d41fdcbfcf"

client = BleakClient(mac_address)
await client.connect()
await client.start_notify(CHAR_UUID, notification_handler)
```

### Step 2:  Receive and Echo Init

The bike sends an init message: 
```
RX: 81 00 0D 05 BF 63 65 6E 63 F4 64 61 75 74 68 F4 FF
              │  └─────────────────────────────────────┘
              │            CBOR:  {enc: false, auth: false}
              └── Command 0x0D, Subtype 0x05
```

Echo it back (keep `81 00` header):
```
TX: 81 00 0D 05 BF 63 65 6E 63 F4 64 61 75 74 68 F4 FF
```

### Step 3: Send Certificate

Build the certificate packet: 
```
TX: 81 00 [LENGTH] 03 [64-byte CA signature] [CBOR payload]
```

**Important:** 
- The LENGTH byte must match the actual certificate size
- The CA signature is the ORIGINAL signature from the API certificate, NOT a freshly computed signature!

```python
def build_auth_packet(ca_signature: bytes, cert_cbor: bytes) -> bytes:
    cert_data = ca_signature + cert_cbor  # Combine signature and CBOR
    packet = bytearray([0x81, 0x00, len(cert_data), 0x03])
    packet.extend(cert_data)
    return bytes(packet)
```

### Step 4: Receive Challenge

The bike sends a 16-byte random challenge:
```
RX: 81 00 10 04 [16 random bytes]
              │  └── Challenge nonce
              └── Command 0x10, Subtype 0x04

Example: 
RX: 81 00 10 04 2A 8D 7A 09 66 A0 FB BF EB 67 E2 64 B5 99 C9 4F
```

### Step 5: Sign and Send Response

Sign the 16-byte challenge with your Ed25519 private key: 

```python
from cryptography.hazmat.primitives.asymmetric. ed25519 import Ed25519PrivateKey

def build_challenge_response(private_key: Ed25519PrivateKey, challenge: bytes) -> bytes:
    signature = private_key. sign(challenge)  # 64-byte Ed25519 signature
    packet = bytearray([0x81, 0x00, 0x40, 0x04])
    packet.extend(signature)
    return bytes(packet)
```

```
TX: 81 00 40 04 [64-byte Ed25519 signature]
```

### Step 6: Receive Confirmation

The bike confirms authentication:
```
RX: 81 00 0D 05 BF 63 65 6E 63 F4 64 61 75 74 68 F5 FF
                                              │
                                              └── F5 = true (authenticated!)
```

---

## Command Reference

### Packet Format for Commands

```
┌────────┬────────┬────────┬────────┬────────┬────────┬────────┐
│ Header │ Header │ Module │ Command│ Subtype│ Param  │ Value  │
│ 0x81   │ 0x00   │ 0x03   │ 0x01   │ 0x00   │ varies │ varies │
└────────┴────────┴────────┴────────┴────────┴────────┴────────┘
```



### Lock/Unlock/Alarm Commands

| Function            | Command (hex)          | Meaning              |
|---------------------|-----------------------|----------------------|
| Unlock bike         | 81 00 03 01 00 A0 01  | Unlock main lock     |
| Lock bike           | 81 00 03 01 00 A0 00  | Lock main lock       |
| Arm alarm           | 81 00 03 01 01 A0 01  | Enable alarm         |
| Disarm alarm        | 81 00 03 01 01 A0 00  | Disable alarm        |
| Trigger alarm sound | 81 00 03 01 02 A0 01  | Immediate alarm      |


### Sound/Feedback Commands

See also: [sound.py](../sound.py)

| Function           | Command (hex)          | Description         |
|--------------------|-----------------------|---------------------|
| Bell ding          | 81 00 03 02 00 A0 01  | Bell ding (single)  |
| Bell double ding   | 81 00 03 02 00 A0 02  | Bell double ding    |
| Horn sound         | 81 00 03 02 01 A0 01  | Horn sound          |

Command group `0x02` = sound/feedback

### Ride/Power Control Commands

See also: [ride.py](../ride.py)

| Function         | Command (hex)          | Description         |
|------------------|-----------------------|---------------------|
| Power on bike    | 81 00 03 03 00 A0 01  | Power on bike       |
| Power off bike   | 81 00 03 03 00 A0 00  | Power off bike      |
| Enable boost     | 81 00 03 03 01 A0 01  | Enable boost mode   |
| Disable boost    | 81 00 03 03 01 A0 00  | Disable boost mode  |

Command group `0x03` = ride/power control

### Power Level Commands

| Power Level | Packet |
|-------------|--------|
| Off | `81 00 03 01 00 67 00` |
| Level 1 | `81 00 03 01 00 67 01` |
| Level 2 | `81 00 03 01 00 67 02` |
| Level 3 | `81 00 03 01 00 67 03` |
| Level 4 | `81 00 03 01 00 67 04` |

### Light Commands

| Light Mode | Packet |
|------------|--------|
| Off | `81 00 03 01 00 6B 00` |
| Always On | `81 00 03 01 00 6B 01` |
| Auto/Pulse | `81 00 03 01 00 6B 03` |

### Sound Commands

| Command | Packet |
|---------|--------|
| Play sound 1 | `81 00 03 01 00 21 01` |
| Play sound 2 | `81 00 03 01 00 21 02` |

---


## Troubleshooting

### Bike Disconnects After Certificate

| Cause | Solution |
|-------|----------|
| Wrong packet length | Ensure length byte matches actual certificate size |
| Wrong CA signature | Use the original signature from the API certificate, don't compute a new one |
| Key mismatch | Ensure your private key matches the public key in the certificate |
| Certificate expired | Request a new certificate from the API |
| Wrong packet header | Use same first byte (0x81/0x82) as bike's initial response |

### No Challenge Received

| Cause | Solution |
|-------|----------|
| Didn't echo init | Make sure to echo the init message back with `0x81` header |
| Wrong packet format | Verify the certificate packet structure |

### Auth Rejected After Challenge

| Cause | Solution |
|-------|----------|
| Wrong private key | Use the same key that was sent to the API |
| Signing wrong data | Sign exactly the 16-byte challenge, nothing more |

---

## Security Considerations

- **Certificates expire** - 7 days, request new ones as needed
- **The CA signature validates the certificate** - it proves VanMoof authorized this keypair for this specific bike
- **The challenge-response proves key ownership** - it prevents replay attacks

---