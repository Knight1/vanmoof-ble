# VanMoof S5/A5/S6 BLE Protocol Reference

The S5, A5 and S6 all authenticate the same way (an Ed25519 certificate and a
signed challenge) and carry CBOR values over one GATT characteristic, but they
frame those values differently. Sections 1-12 cover the S5/A5; section 13
covers the S6; the error codes and notes after it are shared.

---

## Table of Contents

1. [Overview](#overview)
2. [Transport](#transport)
3. [Message and Fragment Format](#message-and-fragment-format)
4. [Authentication](#authentication)
5. [Certificate Format](#certificate-format)
6. [Subscribing (Reading)](#subscribing-reading)
7. [Topics](#topics)
8. [Writing Settings](#writing-settings)
9. [Module Status (CAN Heartbeats)](#module-status-can-heartbeats)
10. [Status Messages](#status-messages)
11. [Legacy `81 00 ..` Command Tables](#legacy-81-00--command-tables)
12. [S6 Protocol](#s6-protocol)
13. [Error Codes](#error-codes)
14. [Troubleshooting](#troubleshooting)
15. [Security Notes](#security-notes)

---

## Overview

The VanMoof S5 and A5 speak a small MQTT-like publish/subscribe protocol over
one GATT characteristic. Behind the BLE chip, the bike's `spi-mqtt-bridge`
maps every 16-bit **topic id** to a topic on the bike's internal MQTT bus.
Writing a topic publishes on that bus; subscribing asks the bridge to forward
topics back as notifications. The S6 uses a related but distinct message
format on its own characteristic - see [S6 Protocol](#s6-protocol). This
document's first half covers the S5/A5.

### Key Properties

- **Authentication**: Ed25519 challenge-response with a CA-signed certificate
- **Messages**: `[PayloadType][body]`, fragmented to the BLE MTU
- **Values**: CBOR (integers, booleans, strings, maps)
- **Permissions**: the certificate's role decides which topics may be read or
  written (enforced by the bike's MQTT ACL)
- **Encryption**: none at the application layer; the `enc` flag the bike
  reports is BLE link-layer encryption

### Sources

Ground truth, in order of authority:

1. **Bike firmware v1.5.0**: the `spi-mqtt-bridge` topic-id registry (300
   entries), the nRF52 `ble` image (authentication, AUTH_DETAILS) and the
   mosquitto ACL per certificate role.
2. **Official app** (`nl.samsonit.vanmoofapp` 24.3): the S5/A5 topic table,
   value encoders and fragmenter.

Implemented in `utils/protocol_codes.py`; run `python -m utils.protocol_codes`
for its self-test.

### Required Credentials

1. **Ed25519 Private Key** (32 or 64 bytes, base64 encoded)
2. **Certificate** (base64 encoded, contains CA signature + CBOR payload)

---

## Transport

| Role                        | UUID                                         |
|-----------------------------|----------------------------------------------|
| Service                     | `e3d80000-3416-4a54-b011-68d41fdcbfcf`       |
| App (notify + write)        | `e3d80001-3416-4a54-b011-68d41fdcbfcf`       |

The official app enables notifications on `e3d80001` and writes everything to
it. Some community clients write to `e3d80002` when the bike exposes it; the
app never does.

The bike's BLE address is randomised on every reboot: scan for the service
UUID (or the name) rather than pinning a MAC.

---

## Message and Fragment Format

Every logical message is `[PayloadType:1] [body...]`, split into fragments of at
most `MTU - 3` payload bytes:

```
[ (0x80 if first else 0x00) | 0x01 ] [ remaining : 2 bytes BIG-endian ] [ chunk ]
```

- The low seven bits of the first byte are always `1`; the app never
  increments them. So a first fragment starts with `0x81`, a continuation
  with `0x01`.
- First fragment: `remaining` = message length - 1 (the body bytes after the
  PayloadType).
- Fragment *n* (n >= 1): `remaining` = message length - n x (MTU - 3).
- A message is complete once `remaining + 1` bytes have been reassembled.

### PayloadType

| Type             | Value | Direction      | Body                                              |
|------------------|-------|----------------|---------------------------------------------------|
| `TOPIC_CBOR`     | 1     | both           | `topic:2BE` + CBOR value                          |
| `SUBSCRIBE`      | 2     | client -> bike  | `0xE001` (subscribe) / `0xE002` (unsubscribe) + `topic:2BE` list |
| `AUTH_CERT`      | 3     | client -> bike  | certificate (64-byte CA signature + CBOR)         |
| `AUTH_CHALLENGE` | 4     | both           | bike: 16-byte nonce / client: 64-byte signature   |
| `AUTH_DETAILS`   | 5     | bike -> client  | CBOR `{enc, auth}`                                |
| `MTU_UPDATE`     | 6     | bike -> client  | CBOR `{tx_max_len, tx_max_time, rx_max_len, rx_max_time}` |
| `PARAM_UPDATE`   | 7     | bike -> client  | CBOR `{latency, timeout, interval}`               |

Example: battery level notification (single fragment):

```
81 00 04 01 00 18 18 26
|  +--+ |  +--+ +--+
|   |   |   |    +-- CBOR 0x1826 -> 38
|   |   |   +-- topic 0x0018 -> power/battery/primary/info/soc_app
|   |   +-- PayloadType 1 (TOPIC_CBOR)
|   +-- remaining = 4 (message length 5 - 1)
+-- first fragment
```

---

## Authentication

### Flow Overview

```
Client                                          Bike
  |                                               |
  |   1. Connect, enable notifications (e3d80001) |
  |<--------------------------------------------->|
  |                                               |
  |   2. AUTH_DETAILS {enc: false, auth: false}   |
  |<----------------------------------------------|
  |                                               |
  |   3. AUTH_CERT [CA_sig + CBOR]                |
  |---------------------------------------------->|
  |                                               |
  |   4. AUTH_CHALLENGE (16-byte nonce)           |
  |<----------------------------------------------|
  |                                               |
  |   5. AUTH_CHALLENGE (64-byte Ed25519 sig)     |
  |---------------------------------------------->|
  |                                               |
  |   6. AUTH_DETAILS {enc: false, auth: true}    |
  |<----------------------------------------------|
```

The bike also sends PARAM_UPDATE / MTU_UPDATE messages whenever the link
parameters change. The official app does **not** echo the initial
AUTH_DETAILS; it sends its certificate as soon as notifications are on.

### Certificate

```
TX: 81 00 A9 03 [64-byte CA signature] [CBOR payload]
       +--+ +-- PayloadType 3 (AUTH_CERT)
         +-- remaining = certificate length (here 169 bytes)
```

With a small MTU the certificate is split over several fragments like any
other message.

### Challenge

```
RX: 81 00 10 04 [16-byte nonce]
```

### Response

Sign exactly the 16 nonce bytes with the Ed25519 private key:

```
TX: 81 00 40 04 [64-byte Ed25519 signature]
```

### Confirmation

```
RX: 81 00 0D 05 BF 63 65 6E 63 F4 64 61 75 74 68 F5 FF
                                                  +-- auth: true
```

### Rejection

The bike doesn't answer a bad certificate or signature with `{auth: false}`; it
logs a reason and drops the connection. Reasons from the firmware:
`invalid certificate/parsing error`, `server signature invalid`,
`bike id invalid`, `certificate expired`, `certificate blacklisted`,
`challenge return invalid`, `authentication timeout`.

An AUTH_CERT body of 64 bytes or less is rejected as `server signature
invalid` **even on an authenticated connection**, and any topic write before
authentication also causes a disconnect.

---

## Certificate Format

### Structure

The certificate is a binary blob structured as:

```
+------------------------------------+
| Bytes 0-63:   CA Signature         |  Ed25519 signature from the CA
| Bytes 64+:    CBOR Payload         |  Certificate metadata
+------------------------------------+
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

The role becomes the bike's MQTT user `ble-role-N`, and the bike's ACL decides
what that user may read and write.

| Value | Role          | Permissions                                       |
|-------|---------------|---------------------------------------------------|
| 7     | Owner         | Read/write `settings/#`, unlock, read ride / battery / power state / lock state / module status / errors |
| 11    | Shared bike   | Like Owner, but only selected settings            |
| 17    | Bike doctor   | Full read/write                                   |
| 22    | Bike hunter   | Full read/write                                   |
| 55    | QA engineer   | Full read/write                                   |
| 66    | R&D engineer  | Full read/write                                   |

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

## Subscribing (Reading)

There are no read commands. To read a value, subscribe to its topic:

```
02  E0 01  <topic:2BE> <topic:2BE> ...
|   |      +-- one entry per topic
|   +-- control topic 0xE001 (bridge/subscribe); 0xE002 unsubscribes
+-- PayloadType 2 (SUBSCRIBE)
```

State and setting topics are **retained** on the bike, so their current
values arrive immediately; afterwards every change is pushed. Telemetry
topics only arrive when they change. Topics the certificate's role may not
read are silently ignored. Subscribing twice to the same topic doesn't
re-send its value.

After login the official app subscribes to: power state, battery, lock state,
touch-unlock request, backup code, speed, assist level, light mode, bell
sound, alarm, shift levels, region, brake/turning lights, ride animation,
odometer, Find My, BLE firmware version, errors, calories and its update /
proxy topics.

---

## Topics

Topic ids are 2 bytes, big-endian. A setting has a value topic (read) and a
`.../set` topic (write). "Owner" is what an owner certificate may do.

| ID       | MQTT topic                              | Owner | Value                                     |
|----------|-----------------------------------------|-------|-------------------------------------------|
| `0x0001` | `power/state`                           | R     | power state, see below                    |
| `0x0002` | `power/state/set`                       | -     |                                           |
| `0x0010` | `power/battery/primary/info/soc`        | R     | raw state of charge, %                    |
| `0x0018` | `power/battery/primary/info/soc_app`    | R     | state of charge shown in the app, %       |
| `0x0030`-`0x003E` | `device/<module>/status`       | R     | module status, see [below](#module-status-can-heartbeats) |
| `0x0049` | `ride/info/calories`                    | R     | float                                     |
| `0x0050` | `ride/info/speed`                       | R     | int                                       |
| `0x0051` | `ride/info/distance`                    | R     | trip distance                             |
| `0x0052` | `ride/info/pedal_rpm`                   | R     |                                           |
| `0x0053` | `ride/info/motor_temperature`           | R     |                                           |
| `0x0054` | `ride/info/torque`                      | R     |                                           |
| `0x0055` | `ride/info/motor_speed`                 | R     |                                           |
| `0x0056` | `ride/info/motor_current`               | R     |                                           |
| `0x0057` | `ride/brake_level`                      | R     | 0-255                                     |
| `0x0060` | `ride/boost`                            | R     |                                           |
| `0x0061` / `0x0062` | `settings/region` (`/set`)   | R/W   | 0 EU (25 km/h), 1 US (32 km/h), 2 JP (24 km/h), 3 offroad |
| `0x0065` / `0x0067` | `settings/assist_level` (`/set`) | R/W | 0 off, 1-4 (`0x0066` is unused)        |
| `0x0068` / `0x0069` | `settings/shift_levels` (`/set`) | R/W |                                        |
| `0x006A` / `0x006B` | `settings/light_mode` (`/set`) | R/W | 1 on, 2 off, 3 auto                      |
| `0x006E` / `0x006F` | `settings/alarm` (`/set`)    | R/W   | bool (alarm enabled)                      |
| `0x0072` / `0x0073` | `settings/bell_sound` (`/set`) | R/W | 0 ding_dong, 1 party_horn, 2 ping, 3 vanmoof, 4 ship_horn |
| `0x0074` / `0x0075` | `settings/backup_unlock_code` (`/set`) | R/W | 3-symbol backup code              |
| `0x007B` / `0x007C` | `settings/brake_lights` (`/set`) | R/W |                                        |
| `0x007D` / `0x007E` | `settings/turning_lights` (`/set`) | R/W |                                      |
| `0x0076` | `ux/sound/play`                         | -     |                                           |
| `0x0078` | `ux/alarm/state`                        | -     | 1 alarm stage 2, 2 alarm stage 3, 3 theft |
| `0x0081`-`0x0084` | `ux/sensor/{light,humidity,temperature,air}` | R |                           |
| `0x00A0` | `ux/lock/unlock`                        | W     | write `1` to unlock                       |
| `0x00A1` | `ux/lock/info/state`                    | R     | 1 locked, 3 unlocked (or unlocking), 5 unlocked |
| `0x00A5` | `ux/info/distance`                      | R     | odometer (community clients divide by 100 for km; unverified) |
| `0x00A8` / `0x00A9` | `eshifter/gear` (`/set`)     | R/W   |                                           |
| `0x00C0` | `ble/system/version_info`               | R     | BLE firmware version string               |
| `0x00E1` | `ble/findmy/report`                     | R     | bytes                                     |
| `0x00FF` | (errors)                                | R     | subscribed by the app; not in the 1.5.0 registry |
| `0xE001` / `0xE002` | `bridge/subscribe` / `unsubscribe` | - | SUBSCRIBE control topics               |

**Power state** (`0x0001`): 0 invalid, 1 shipping, 2 standby, 3 operational,
4 charging, 5 updating, 6 alarm, 7 maintenance.

> Note: corrections to the community clients: topic `0x0001` is the power state,
> not the lock state (the real lock state is `0x00A1`); topic `0x0010` is the
> raw state of charge, not a "module battery"; topic `0x0061` is the region,
> not the gear. Light modes are `1` on, `2` off, `3` auto (taken from the
> app's encoder), not `0` off / `2` halo. Bell tones on the wire are not the
> app's `BellSound` enum ordinals, and the app's tring, laser, quack, meow
> and epic tones aren't supported on S5/A5.

---

## Writing Settings

Write the CBOR value to the `.../set` topic as a TOPIC_CBOR message. The
owning service validates it, applies it and re-publishes the value topic,
which arrives as a notification if you are subscribed to it:

```
TX: 81 00 03 01 00 6B 02      settings/light_mode/set = 2 (off)
RX: 81 00 03 01 00 6A 02      settings/light_mode = 2
```

| Action          | Packet (hex)              |
|-----------------|---------------------------|
| Unlock          | `81 00 03 01 00 A0 01`    |
| Alarm on / off  | `81 00 03 01 00 6F F5` / `81 00 03 01 00 6F F4` |
| Lights on / off / auto | `81 00 03 01 00 6B 01` / `... 02` / `... 03` |
| Assist level N  | `81 00 03 01 00 67 0N`    |
| Region N        | `81 00 03 01 00 62 0N`    |
| Bell tone N     | `81 00 03 01 00 73 0N`    |

The official app never writes `0` to `ux/lock/unlock`: the S5/A5 has no BLE
lock command. An owner certificate can't change the power state, toggle
boost, or play a sound (`power/state/set`, `ride/boost`, `ux/sound/play`); the
bike ignores those writes.

---

## Module Status (CAN Heartbeats)

The bike's `monitor` service tracks every sub-module through its CANopen
heartbeat (every 2 s) and publishes the result as `device/<module>/status`.
These topics are readable with an owner certificate, which makes the CAN-bus
heartbeat view available over BLE:

| ID       | Module             | ID       | Module             |
|----------|--------------------|----------|--------------------|
| `0x0030` | ble                | `0x0038` | modem              |
| `0x0031` | battery_primary    | `0x0039` | motor_control      |
| `0x0032` | battery_secondary  | `0x003A` | motor_sensor       |
| `0x0033` | charger            | `0x003B` | power_control      |
| `0x0034` | elock              | `0x003C` | power_pedal        |
| `0x0035` | eshifter           | `0x003D` | rearlight          |
| `0x0036` | frontlight         | `0x003E` | user_ecu           |
| `0x0037` | imx8_bridge        |          |                    |

```
02 E0 01 00 30 00 31 ... 00 3E      subscribe to all module statuses
```

Use the `modules` command to read them.

---

## Status Messages

**AUTH_DETAILS** (PayloadType 5) is sent when the connection is set up, when
the link becomes encrypted and after authentication:

```
BF 63 65 6E 63 F4 64 61 75 74 68 F4 FF      {"enc": false, "auth": false}
BF 63 65 6E 63 F4 64 61 75 74 68 F5 FF      {"enc": false, "auth": true}
```

`enc` means the BLE link is encrypted (security level 2 or 3); there is no
application-layer encryption, and topic values are always plain CBOR.

**PARAM_UPDATE** (PayloadType 7) reports the connection parameters, e.g.
`{"latency": 0, "timeout": 25, "interval": 12}`. **MTU_UPDATE** (PayloadType
6) reports the data length parameters (`tx_max_len`, `tx_max_time`,
`rx_max_len`, `rx_max_time`), or `{"err": ...}`.

---

## Legacy `81 00 ..` Command Tables

Earlier versions of this tool and document described an
`[frame byte][0x00][module][group][sub][param][value]` command model. Those
bytes are really the fragment header plus a PayloadType, which is why some of
them worked and most didn't:

| Old command           | Packet (hex)              | What the bike actually received                |
|-----------------------|---------------------------|------------------------------------------------|
| Unlock                | `81 00 03 01 00 A0 01`    | `ux/lock/unlock = 1`: correct                  |
| Lock                  | `81 00 03 01 00 A0 00`    | `ux/lock/unlock = 0`: never sent by the app    |
| Arm / disarm alarm    | `81 00 03 01 01 A0 0x`    | topic `0x01A0`, which doesn't exist            |
| Trigger alarm         | `81 00 03 01 02 A0 01`    | topic `0x02A0`, which doesn't exist            |
| Lights on / auto      | `81 00 03 01 00 6B 01/03` | `settings/light_mode/set`: correct             |
| Lights off            | `81 00 03 01 00 6B 00`    | invalid light mode (off is `02`)               |
| Play sound            | `81 00 03 01 00 21 xx`    | `power/battery/lipo/info/voltage` (denied)     |
| Bell / horn           | `81 00 03 02 0x A0 0x`    | malformed SUBSCRIBE                            |
| Power on/off, boost   | `81 00 03 03 0x A0 0x`    | 3-byte AUTH_CERT: the bike disconnects         |
| Assist level, region  | `81 00 04 30 0x A0 xx`    | invalid PayloadType `0x30`, one byte short     |
| Read commands         | `81 00 02 ..`             | empty publishes / invalid PayloadTypes         |

The old status-field tables (`spd`, `bat`, `cad`, ...) and the AES
"encryption handshake" do not exist on the S5/A5.

---

## S6 Protocol

The S6 uses a single characteristic like the S5/A5, but its own message
format. Implemented in `utils/s6_protocol.py`; run `python -m utils.s6_protocol`
for its self-test.

Sources, in order of authority: field captures of the official app talking to 
the official app 24.3 (S6 profile `xl/l0`, builder `mm.o`, fragmenter `cg.r.c`,
CRC `ck.a`), and the S6 `ble` firmware v1.8.8.4974.

### Transport

| Role                        | UUID                                         |
|-----------------------------|----------------------------------------------|
| Service                     | `df286100-1440-48a1-88f1-247d7f7d274d`       |
| App (notify + write)        | `df286101-1440-48a1-88f1-247d7f7d274d`       |

The app enables notifications on `df286101` and writes everything to it. Some
retail bikes advertise the same service with a different 128-bit base
(`df286100-6003-11e5-9260-0002a5d5c51b`); this tool matches the `df286101`
prefix either way.

### Message format

Each message is:

```
[id:1][flags:1][topic:2 LE][length:2 LE][payload][crc:2 LE]
```

- `id` is a per-connection counter (0..255, wrapping).
- `flags` = `type | (qos << 3) | (retain << 4)`. Types: 0 ACK, 1 PUBLISH,
  2 SUBSCRIBE, 3 UNSUBSCRIBE, 4 GET, 5 SET, 6 OWN, 7 SYNC. The app's QoS is
  `AT_MOST_ONCE` = 1, so a SET is `0x0D` and a GET is `0x0C`.
- `topic` and `length` are **little-endian**.
- `crc` is CRC-16/MODBUS over every byte before it, appended little-endian.

The client reads with GET (empty payload), writes with SET, and the bike
answers with PUBLISH. Auth also uses SET. Unlike the S5/A5, the bike doesn't
push values unasked; this tool reads each topic with a GET.

### Fragment format

Fragments are different from the message's own fields - `remaining` is
**big-endian**:

```
[(0x80 if first else 0x00) | frag_id][remaining:2 BE][chunk]
```

`frag_id` is a second counter (0..127, then 1..127), shared by a message's
fragments. `remaining` counts the bytes still to come including this chunk, so
the first fragment carries the full message length. A chunk is at most one
GATT write (ATT MTU - 3). At MTU 247 most messages are a single fragment.

### Authentication

Both auth messages are a SET on the AUTH topic `0xFF00`; the bike answers with
a PUBLISH on the same topic.

```
client -> bike   SET 0xFF00   certificate, wrapped (see below)
bike -> client   PUBLISH 0xFF00   [status, challenge]  (status >= 0, 16-byte challenge)
client -> bike   SET 0xFF00   Ed25519 signature of the challenge, wrapped
bike -> client   PUBLISH 0xFF00   [status]             (status >= 0, no challenge = success)
```

A negative status is a rejection; a bad signature also drops the connection.

### Payload wrapping

A request payload wraps its CBOR in a byte string inside a one-element array
(`81 <bstr>`), as the app's kotlinx-serialization does - there is no map and
no "value" key. The certificate and signature are wrapped once more:

```
certificate:  81 58AB 58A9 <169-byte certificate>
signature:    81 5842 5840 <64-byte signature>
```

A settable value is encoded as its data-class fields in a CBOR array, then
wrapped: `SET 0x0110 [3]` (assist level 3) is `81 42 8103`. The bike's
PUBLISH replies wrap the same way with indefinite-length arrays.

### Topics

Topic ids are 2 bytes (little-endian on the wire). Verified against the field
captures ("captured") or the app's S6 code.

| ID       | Name            | R/W | Value                                         |
|----------|-----------------|-----|-----------------------------------------------|
| `0x0031` | frame_number    | R   | frame number string                           |
| `0x010C` | wake            | W   | SET [1] wakes the bike, which unlocks it (captured) |
| `0x0110` | assist_level    | R/W | 0 off, 1-4                                    |
| `0x0112` | lock_state      | R   | 0 unlocked, 1 locked; published by the bike (captured) |
| `0x0113` | distance        | R   | odometer                                      |
| `0x0131` | light_mode      | R/W | `[mode, 1]`: 0 off, 2 on, 3 auto (1 is not on) |
| `0x0142` | bell_sound      | W   | selecting a tone plays it; SET [1] rings the bell (captured) |
| `0x0164` | speed           | R   | current speed (captured)                      |
| `0x0171` | alarm_sensitivity | R/W | 1 high, 2 medium, 4 low                     |
| `0x0172` | alarm           | R/W | 0 off, 1 on                                   |
| `0x011F` | errors          | R   | error code (captured)                         |
| `0x01B1` | firmware        | R   | firmware version                              |
| `0x022A` | battery_level   | R   | % (captured)                                  |
| `0x022D` | charge_limit    | R/W | % charge limit, e.g. 80/85/90/95/100 (captured) |
| `0xFF00` | auth            | -   | certificate / challenge exchange              |

> There is no BLE lock command: the S6 is locked on its kicklock. Unlock is a
> wake (`0x010C`); the bike then publishes `lock_state` = 0. SET `0x0142` rings
> the bell, it does **not** unlock. Light mode value 1 is not "on" (use 2).

---

## Error Codes

There is no public table mapping a VanMoof error number to a description for
the S5/A5/S6. The official app shows the bare number ("Error N was detected");
the worded descriptions riders see come from VanMoof's support material.

- **S5/A5** report errors on the MQTT `error/#` subtree (per service); the
  errors topic the app subscribes to (id `0x00FF`) carries a list. The S5
  firmware decomp (v1.5.0) was reviewed to try to recover a numbered table and
  does not contain one: errors surface as `service/{power,ux,monitor,update}/error`
  (ids `0x0200`-`0x0203`, JSON/string); the battery has a generic-fault bit and
  a UVP (under-voltage / empty-pack) fault, but the detailed battery
  status/warning bit names are runtime strings not in the static image, and the
  charger's 8-entry fault table is in off-image flash.
- **S6** reports Diagnostic Trouble Codes (DTCs): 16-bit hex codes in the
  `0x9000`-`0x95FF` range (e.g. `0x9050`-`0x9053` around battery charging),
  read on topic `0x011F`. The firmware decodes each DTC to a
  `<device> <name>` string via a large internal table that hasn't been
  recovered.
- The old numbered scheme (motor 1-8, BMS 9-20, SIM 54-58, ...) is the
  **S3/X3** generation's and does **not** apply to these bikes, so it isn't
  reproduced here.

A value of `0` means no error. `format_error` in `utils/error_codes.py` renders
whatever the bike reports - the bare number, or the DTC in hex. Use the
`error <code>` REPL command to format one (`error 0x9050`).

## Troubleshooting

### Bike Disconnects During Authentication

| Symptom                    | Solution                                     |
|----------------------------|----------------------------------------------|
| Disconnect after cert sent | Use the original certificate bytes (CA signature + CBOR) unchanged |
| Key mismatch error         | Ensure the private key matches the public key embedded in the certificate |
| Certificate expired        | Request a new certificate (typically valid for 7 days) |
| Disconnect after signature | Sign exactly the 16-byte challenge with the certificate's key |

### No Challenge Received

| Symptom                    | Solution                                     |
|----------------------------|----------------------------------------------|
| Timeout waiting            | Check that notifications are enabled on `e3d80001` before sending the certificate |
| Large certificate          | Fragment it to the negotiated MTU (first fragment `0x81`, continuations `0x01`) |

### Commands Not Working

| Symptom                    | Solution                                     |
|----------------------------|----------------------------------------------|
| No confirmation after a write | Subscribe to the value topic; check that the certificate's role may write it |
| Value doesn't change       | Check the value encoding in [Topics](#topics) (e.g. lights off is `2`) |
| Disconnect after a command | Never send AUTH_CERT after login or any topic write before it |

---

## Security Notes

- **Certificate expiry**: Certificates are typically valid for 7 days. Request new ones as needed.
- **CA signature validation**: The bike verifies that the certificate was signed by the trusted Certificate Authority, and that it was issued for this bike's id.
- **Challenge-response**: The 16-byte random challenge prevents replay attacks. Each authentication session uses a unique challenge.
- **Key binding**: The Ed25519 public key in the certificate must match the private key used to sign the challenge. This binds the authentication to the specific keypair.
- **Role-based access**: The certificate's role selects the bike's ACL (owner=7, shared bike=11, service roles 17/22/55/66 with full access), which decides which topics may be read or written.

---
