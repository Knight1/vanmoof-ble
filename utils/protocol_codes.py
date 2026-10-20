"""
VanMoof S5/A5 BLE Topic / PayloadType protocol.

The S5/A5 speak a small MQTT-like publish/subscribe protocol over the ``e3d8``
GATT service. Behind the BLE chip, the bike's ``spi-mqtt-bridge`` maps every
16-bit topic id to a topic on the bike's internal MQTT bus: writing a topic is
a publish on that bus, and a SUBSCRIBE asks the bridge to forward topics back
as notifications. Settings are written to their ``.../set`` topic; the owning
service applies them and re-publishes the value topic.

Ground truth, in order of authority:

  - the bike firmware (v1.5.0): the ``spi-mqtt-bridge`` topic-id registry, the
    nRF52 ``ble`` image and the mosquitto ACL that limits what each
    certificate role may read or write (see ``ROLE_NAMES``);
  - the official VanMoof app (``nl.samsonit.vanmoofapp`` 24.3): the S5/A5
    topic table (class ``xl/g0``), its value encoders and its BLE fragmenter;
  - the community clients victorlagerfors/vanmoof-s5-homey and its Python port
    TimTheBeastNL/VanMoof-SA5-HomeAssistant. Their framing matches the app
    byte-for-byte, but several of their value tables do not (topic 1 is the
    power state, not the lock state, and their light-mode values are wrong).

    GATT service : e3d80000-3416-4a54-b011-68d41fdcbfcf
    App char     : e3d80001-...   (bike notifies on it and the app writes to it)

Wire format
-----------
Every logical message is::

    [PayloadType:1] [body ...]

and is split into BLE fragments of at most one GATT write (ATT MTU - 3)::

    [ (0x80 if first else 0x00) | 0x01 ] [ remaining : 2 BIG-endian ] [ chunk ]

  * the low seven bits are always 1; the app never increments them;
  * on the first fragment ``remaining`` is the message length minus one (the
    body bytes after the PayloadType); on fragment ``n`` it is
    ``len - n * (max_write - 3)``;
  * a message is complete once ``remaining + 1`` bytes have been reassembled.

This explains the ``81 00 0D 05 ..`` bytes seen on the wire: ``81 00 0D`` is
the fragment header (first fragment, remaining = 13) and ``05`` is the
PayloadType (AUTH_DETAILS), followed by a 13-byte CBOR body. Topic ids and the
``remaining`` field are big-endian; values are CBOR.
"""

from __future__ import annotations

import base64
import math
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Iterable, List, Optional, Union

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# --------------------------------------------------------------------------- #
# BLE UUIDs
# --------------------------------------------------------------------------- #

SERVICE_UUID    = "e3d80000-3416-4a54-b011-68d41fdcbfcf"
APP_CHAR_UUID   = "e3d80001-3416-4a54-b011-68d41fdcbfcf"  # notify + write
# Community clients prefer e3d80002 for writes when it is exposed. The official
# app never uses it: its S5/A5 profile declares only e3d80001 and writes there.
WRITE_CHAR_UUID = "e3d80002-3416-4a54-b011-68d41fdcbfcf"


# --------------------------------------------------------------------------- #
# PayloadType -- first byte of every reassembled message
# --------------------------------------------------------------------------- #

class PayloadType(IntEnum):
    """First byte of a reassembled VanMoof message."""

    TOPIC_CBOR     = 1   # topic:2BE + CBOR value (bike publishes / client writes)
    SUBSCRIBE      = 2   # control topic (0xE001 / 0xE002) + list of topic:2BE
    AUTH_CERT      = 3   # client sends certificate (CA sig + CBOR payload)
    AUTH_CHALLENGE = 4   # bike sends 16-byte nonce / client sends 64-byte signature
    AUTH_DETAILS   = 5   # bike reports {enc, auth}; enc = BLE link-layer encryption
    MTU_UPDATE     = 6   # bike reports data-length params {tx_max_len, ...}
    PARAM_UPDATE   = 7   # bike reports connection params {latency, timeout, interval}


# --------------------------------------------------------------------------- #
# Topics -- the firmware's spi-mqtt-bridge registry (v1.5.0)
# --------------------------------------------------------------------------- #

class Topic(IntEnum):
    """Topic ids. Write a ``*_SET`` topic; read (subscribe to) the value topic."""

    # power / battery (power service)
    POWER_STATE          = 0x0001  # see POWER_STATES
    POWER_STATE_SET      = 0x0002  # not writable with owner/shared certificates
    BATTERY_SOC          = 0x0010  # raw state of charge, %
    BATTERY_LEVEL        = 0x0018  # state of charge shown in the app, %

    # ride telemetry (ride service)
    CALORIES             = 0x0049
    SPEED                = 0x0050
    RIDE_DISTANCE        = 0x0051
    PEDAL_RPM            = 0x0052
    MOTOR_TEMPERATURE    = 0x0053
    TORQUE               = 0x0054
    MOTOR_SPEED          = 0x0055
    MOTOR_CURRENT        = 0x0056
    BRAKE_LEVEL          = 0x0057
    BOOST                = 0x0060  # read-only with owner/shared certificates

    # settings: value topic + .../set topic
    REGION               = 0x0061  # see REGIONS
    REGION_SET           = 0x0062
    ASSIST_LEVEL         = 0x0065  # 0 = off, 1-4
    ASSIST_LEVEL_SET     = 0x0067  # (0x0066 is unused)
    SHIFT_LEVELS         = 0x0068
    SHIFT_LEVELS_SET     = 0x0069
    LIGHT_MODE           = 0x006A  # see LIGHT_MODES
    LIGHT_MODE_SET       = 0x006B
    ALARM                = 0x006E  # alarm enabled (bool)
    ALARM_SET            = 0x006F
    BELL_SOUND           = 0x0072  # see BELL_SOUNDS
    BELL_SOUND_SET       = 0x0073
    BACKUP_UNLOCK_CODE   = 0x0074
    BRAKE_LIGHTS         = 0x007B
    BRAKE_LIGHTS_SET     = 0x007C
    TURNING_LIGHTS       = 0x007D
    TURNING_LIGHTS_SET   = 0x007E

    # ux service
    SOUND_PLAY           = 0x0076  # not writable with owner/shared certificates
    ALARM_STATE          = 0x0078  # see ALARM_STATES
    SENSOR_LIGHT         = 0x0081
    SENSOR_HUMIDITY      = 0x0082
    SENSOR_TEMPERATURE   = 0x0083
    SENSOR_AIR           = 0x0084
    UNLOCK               = 0x00A0  # write 1 to unlock
    LOCK_STATE           = 0x00A1  # see LOCK_STATES
    DISTANCE             = 0x00A5  # odometer
    ESHIFTER_GEAR        = 0x00A8
    ESHIFTER_GEAR_SET    = 0x00A9

    # BLE module
    FW_INFO              = 0x00C0  # BLE firmware version string
    FIND_MY              = 0x00E1  # Apple Find My report
    ERRORS               = 0x00FF  # subscribed by the app; not in the v1.5.0 registry

    # bridge control topics (first word of a SUBSCRIBE body)
    SUBSCRIBE_CONTROL    = 0xE001
    UNSUBSCRIBE_CONTROL  = 0xE002


# MQTT topic on the bike's bus for each id (from the firmware registry).
TOPIC_NAMES = {
    Topic.POWER_STATE:         "power/state",
    Topic.POWER_STATE_SET:     "power/state/set",
    Topic.BATTERY_SOC:         "power/battery/primary/info/soc",
    Topic.BATTERY_LEVEL:       "power/battery/primary/info/soc_app",
    Topic.CALORIES:            "ride/info/calories",
    Topic.SPEED:               "ride/info/speed",
    Topic.RIDE_DISTANCE:       "ride/info/distance",
    Topic.PEDAL_RPM:           "ride/info/pedal_rpm",
    Topic.MOTOR_TEMPERATURE:   "ride/info/motor_temperature",
    Topic.TORQUE:              "ride/info/torque",
    Topic.MOTOR_SPEED:         "ride/info/motor_speed",
    Topic.MOTOR_CURRENT:       "ride/info/motor_current",
    Topic.BRAKE_LEVEL:         "ride/brake_level",
    Topic.BOOST:               "ride/boost",
    Topic.REGION:              "settings/region",
    Topic.REGION_SET:          "settings/region/set",
    Topic.ASSIST_LEVEL:        "settings/assist_level",
    Topic.ASSIST_LEVEL_SET:    "settings/assist_level/set",
    Topic.SHIFT_LEVELS:        "settings/shift_levels",
    Topic.SHIFT_LEVELS_SET:    "settings/shift_levels/set",
    Topic.LIGHT_MODE:          "settings/light_mode",
    Topic.LIGHT_MODE_SET:      "settings/light_mode/set",
    Topic.ALARM:               "settings/alarm",
    Topic.ALARM_SET:           "settings/alarm/set",
    Topic.BELL_SOUND:          "settings/bell_sound",
    Topic.BELL_SOUND_SET:      "settings/bell_sound/set",
    Topic.BACKUP_UNLOCK_CODE:  "settings/backup_unlock_code",
    Topic.BRAKE_LIGHTS:        "settings/brake_lights",
    Topic.BRAKE_LIGHTS_SET:    "settings/brake_lights/set",
    Topic.TURNING_LIGHTS:      "settings/turning_lights",
    Topic.TURNING_LIGHTS_SET:  "settings/turning_lights/set",
    Topic.SOUND_PLAY:          "ux/sound/play",
    Topic.ALARM_STATE:         "ux/alarm/state",
    Topic.SENSOR_LIGHT:        "ux/sensor/light",
    Topic.SENSOR_HUMIDITY:     "ux/sensor/humidity",
    Topic.SENSOR_TEMPERATURE:  "ux/sensor/temperature",
    Topic.SENSOR_AIR:          "ux/sensor/air",
    Topic.UNLOCK:              "ux/lock/unlock",
    Topic.LOCK_STATE:          "ux/lock/info/state",
    Topic.DISTANCE:            "ux/info/distance",
    Topic.ESHIFTER_GEAR:       "eshifter/gear",
    Topic.ESHIFTER_GEAR_SET:   "eshifter/gear/set",
    Topic.FW_INFO:             "ble/system/version_info",
    Topic.FIND_MY:             "ble/findmy/report",
    Topic.ERRORS:              "errors",
    Topic.SUBSCRIBE_CONTROL:   "bridge/subscribe",
    Topic.UNSUBSCRIBE_CONTROL: "bridge/unsubscribe",
}

# Per-module presence, published by the bike's monitor service from each
# sub-ECU's CANopen heartbeat: the CAN-bus heartbeat view over BLE. Readable
# with an owner certificate (topic ids 0x0030-0x003E, one per module).
ECU_NAMES = (
    "ble", "battery_primary", "battery_secondary", "charger", "elock",
    "eshifter", "frontlight", "imx8_bridge", "modem", "motor_control",
    "motor_sensor", "power_control", "power_pedal", "rearlight", "user_ecu",
)
DEVICE_STATUS_TOPICS = {0x0030 + i: name for i, name in enumerate(ECU_NAMES)}
TOPIC_NAMES.update({topic: "device/{0}/status".format(name)
                    for topic, name in DEVICE_STATUS_TOPICS.items()})

# Subscribed after login: what the official app subscribes to, minus its
# update/proxy plumbing, plus the raw SoC.
STATUS_TOPICS = [
    Topic.POWER_STATE, Topic.BATTERY_LEVEL, Topic.BATTERY_SOC,
    Topic.LOCK_STATE, Topic.DISTANCE, Topic.ASSIST_LEVEL, Topic.LIGHT_MODE,
    Topic.REGION, Topic.ALARM, Topic.BELL_SOUND, Topic.ESHIFTER_GEAR,
    Topic.FW_INFO, Topic.ERRORS,
]

TELEMETRY_TOPICS = [
    Topic.SPEED, Topic.CALORIES, Topic.RIDE_DISTANCE, Topic.PEDAL_RPM,
    Topic.TORQUE, Topic.MOTOR_SPEED, Topic.MOTOR_CURRENT,
    Topic.MOTOR_TEMPERATURE, Topic.BRAKE_LEVEL, Topic.BOOST,
    Topic.SENSOR_LIGHT, Topic.SENSOR_HUMIDITY, Topic.SENSOR_TEMPERATURE,
    Topic.SENSOR_AIR,
]

HEARTBEAT_TOPICS = list(DEVICE_STATUS_TOPICS)

ALL_TOPICS = STATUS_TOPICS + TELEMETRY_TOPICS + HEARTBEAT_TOPICS


def topic_name(topic: int) -> str:
    """MQTT name of a topic id, or a hex placeholder for unknown ids."""
    return TOPIC_NAMES.get(topic, "topic_0x{0:04X}".format(topic))


# --------------------------------------------------------------------------- #
# Value enumerations / decoders
# --------------------------------------------------------------------------- #

# Certificate role (`r`) -> mosquitto ACL user `ble-role-N` on the bike.
ROLE_NAMES = {
    7:  "Owner",
    11: "Shared bike",
    17: "Bike doctor",
    22: "Bike hunter",
    55: "QA engineer",
    66: "R&D engineer",
}

# power/state, from the power service's StateManager.
POWER_STATES = {
    0: "invalid",
    1: "shipping",
    2: "standby",
    3: "operational",
    4: "charging",
    5: "updating",
    6: "alarm",
    7: "maintenance",
}

# ux/lock/info/state, from the ux service's e-lock handler.
LOCK_STATES = {
    1: "locked",
    3: "unlocked",   # also published while the unlock is in progress
    5: "unlocked",   # default after boot
}

# settings/light_mode values, from the app's encoder.
LIGHT_MODES = {
    1: "on",
    2: "off",
    3: "auto",
}

# settings/region values, from the app's encoder.
REGIONS = {
    0: "EU (25 km/h)",
    1: "US (32 km/h)",
    2: "JP (24 km/h)",
    3: "offroad",
}

# settings/bell_sound values, from the app's encoder. The app's other bell
# tones (tring, laser, quack, meow, epic) are not supported on S5/A5.
BELL_SOUNDS = {
    0: "ding_dong",
    1: "party_horn",
    2: "ping",
    3: "vanmoof",
    4: "ship_horn",
}

# ux/alarm/state escalation level.
ALARM_STATES = {
    1: "alarm stage 2",
    2: "alarm stage 3",
    3: "theft",
}

LIGHT_MODE_VALUES = {name: value for value, name in LIGHT_MODES.items()}
REGION_VALUES = {"eu": 0, "us": 1, "jp": 2, "offroad": 3}
BELL_SOUND_VALUES = {name: value for value, name in BELL_SOUNDS.items()}


def _lookup(table: dict, value: Any) -> Optional[str]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return table.get(value)


def _finite_number(value: Any) -> Optional[Union[int, float]]:
    """`value` if it is an int or a finite float (bools excluded), else None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def power_state_name(value: Any) -> Optional[str]:
    """Map a POWER_STATE value to its name."""
    return _lookup(POWER_STATES, value)


def lock_state_name(value: Any) -> Optional[str]:
    """Map a LOCK_STATE value to its name."""
    return _lookup(LOCK_STATES, value)


def is_locked(value: Any) -> Optional[bool]:
    """True if a LOCK_STATE value means locked, None if unknown."""
    name = lock_state_name(value)
    return None if name is None else name == "locked"


def decode_light_mode(value: Any) -> Optional[str]:
    """Map a LIGHT_MODE value to its name."""
    return _lookup(LIGHT_MODES, value)


def decode_region(value: Any) -> Optional[str]:
    """Map a REGION value to its label."""
    return _lookup(REGIONS, value)


def bell_name(value: Any) -> Optional[str]:
    """Map a BELL_SOUND value to its name."""
    return _lookup(BELL_SOUNDS, value)


def decode_distance_km(value: Any) -> Optional[float]:
    """
    Convert a DISTANCE value to kilometres.

    Both community clients divide by 100 (and the app does the same for the
    S6 odometer); the firmware docs suggest metres. Unverified for S5/A5.
    """
    number = _finite_number(value)
    if number is None:
        return None
    try:
        km = round(float(number) / 100.0, 1)
    except OverflowError:  # a CBOR bignum
        return None
    return km if math.isfinite(km) else None


def describe_topic_value(topic: int, value: Any) -> str:
    """Return a human-readable rendering of a decoded topic value."""
    name = None
    if topic == Topic.POWER_STATE:
        name = power_state_name(value)
    elif topic == Topic.LOCK_STATE:
        name = lock_state_name(value)
    elif topic in (Topic.LIGHT_MODE, Topic.LIGHT_MODE_SET):
        name = decode_light_mode(value)
    elif topic in (Topic.REGION, Topic.REGION_SET):
        name = decode_region(value)
    elif topic in (Topic.BELL_SOUND, Topic.BELL_SOUND_SET):
        if bell_name(value) is not None:
            name = "{0} ({1})".format(value, bell_name(value))
    elif topic == Topic.ALARM_STATE:
        name = _lookup(ALARM_STATES, value)
    elif topic in (Topic.ALARM, Topic.ALARM_SET) and isinstance(value, bool):
        name = "enabled" if value else "disabled"
    elif topic in (Topic.ASSIST_LEVEL, Topic.ASSIST_LEVEL_SET) and value == 0:
        name = "0 (off)"
    elif topic == Topic.DISTANCE:
        km = decode_distance_km(value)
        if km is not None:
            name = "{0} km".format(km)
    elif topic in (Topic.BATTERY_LEVEL, Topic.BATTERY_SOC):
        if _finite_number(value) is not None:
            name = "{0}%".format(int(value))
    if name is not None:
        return name
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return str(value)


# --------------------------------------------------------------------------- #
# Decoded message types
# --------------------------------------------------------------------------- #

@dataclass
class TopicMessage:
    """A published topic value (PayloadType.TOPIC_CBOR)."""

    topic: int
    topic_name: str
    value: Any


@dataclass
class AuthMessage:
    """The bike's {enc, auth} status (PayloadType.AUTH_DETAILS)."""

    authenticated: bool
    encrypted: bool


@dataclass
class ChallengeMessage:
    """A 16-byte challenge nonce (PayloadType.AUTH_CHALLENGE, bike -> client)."""

    nonce: bytes


@dataclass
class ParamMessage:
    """Connection parameters (PayloadType.PARAM_UPDATE)."""

    data: Any


@dataclass
class MtuMessage:
    """Data-length parameters (PayloadType.MTU_UPDATE)."""

    data: Any


S5Message = Union[TopicMessage, AuthMessage, ChallengeMessage, ParamMessage,
                  MtuMessage]


# --------------------------------------------------------------------------- #
# Fragment layer
# --------------------------------------------------------------------------- #

def build_fragments(payload: bytes, max_write: int = 244) -> List[bytes]:
    """
    Split a full message (``[PayloadType] + body``) into BLE fragments of at
    most ``max_write`` bytes, the payload of one GATT write (ATT MTU - 3; the
    app passes the same value, so 244 matches its MTU of 247).

    Same layout as the official app: the first fragment carries
    ``remaining = len(payload) - 1``; continuation fragments carry
    ``len(payload)`` minus the chunk bytes already sent.
    """
    chunk_size = max_write - 3
    fragments = []  # type: List[bytes]
    offset = 0
    index = 0

    while offset < len(payload):
        chunk = payload[offset:offset + chunk_size]
        if index == 0:
            remaining = len(payload) - 1
        else:
            remaining = len(payload) - (chunk_size * index)
        header = bytes([
            (0x80 if index == 0 else 0x00) | 1,
            (remaining >> 8) & 0xFF,
            remaining & 0xFF,
        ])
        fragments.append(header + chunk)
        offset += chunk_size
        index += 1

    return fragments


@dataclass
class ParsedFragment:
    """A single decoded BLE fragment header + payload."""

    is_first: bool
    seq_id: int
    total_len: int
    payload: bytes


def parse_fragment(data: bytes) -> ParsedFragment:
    """Decode one fragment's 3-byte header."""
    b0 = data[0]
    total_len = (data[1] << 8) | data[2]
    return ParsedFragment(
        is_first=bool(b0 & 0x80),
        seq_id=b0 & 0x7F,
        total_len=total_len,
        payload=data[3:],
    )


class FragmentReassembler:
    """Reassembles fragmented notifications and parses complete messages."""

    def __init__(self) -> None:
        self._buf = b""
        self._total_len = 0
        self._active = False

    def reset(self) -> None:
        self._buf = b""
        self._total_len = 0
        self._active = False

    def feed(self, data: bytes) -> Optional[S5Message]:
        """
        Feed one raw notification. Returns a parsed message once the underlying
        logical message is complete, otherwise ``None``.
        """
        if len(data) < 3:
            return None
        frag = parse_fragment(data)

        if frag.is_first:
            self._buf = bytes(frag.payload)
            self._total_len = frag.total_len
            self._active = True
        elif not self._active:
            return None  # continuation without a first fragment
        else:
            self._buf += frag.payload

        # total_len is the body length (excl. PayloadType), so a message is
        # complete once we have total_len + 1 bytes.
        if len(self._buf) >= self._total_len + 1:
            message = self._buf[:self._total_len + 1]
            self.reset()
            return parse_message(message)

        return None


# --------------------------------------------------------------------------- #
# Message parsing
# --------------------------------------------------------------------------- #

def parse_message(data: bytes) -> Optional[S5Message]:
    """Parse a fully reassembled ``[PayloadType] + body`` message."""
    if not data:
        return None

    payload_type = data[0]
    rest = data[1:]

    if payload_type == PayloadType.AUTH_DETAILS:
        info = _safe_cbor(rest)
        if isinstance(info, dict):
            return AuthMessage(
                authenticated=bool(info.get("auth", False)),
                encrypted=bool(info.get("enc", False)),
            )
        return AuthMessage(authenticated=False, encrypted=False)

    if payload_type == PayloadType.AUTH_CHALLENGE:
        return ChallengeMessage(nonce=bytes(rest))

    if payload_type == PayloadType.PARAM_UPDATE:
        return ParamMessage(data=_safe_cbor(rest))

    if payload_type == PayloadType.MTU_UPDATE:
        return MtuMessage(data=_safe_cbor(rest))

    if payload_type == PayloadType.TOPIC_CBOR:
        if len(rest) < 2:
            return None
        topic = (rest[0] << 8) | rest[1]
        value = _safe_cbor(rest[2:]) if len(rest) > 2 else None
        return TopicMessage(topic=topic, topic_name=topic_name(topic),
                            value=value)

    return None


def _safe_cbor(data: bytes) -> Any:
    """Decode CBOR, tolerating trailing bytes and decode errors."""
    if not data:
        return None
    try:
        return cbor2.loads(data)
    except Exception:
        try:
            # cbor2 raises on trailing data in some versions; fall back to a
            # streaming decode of just the first item.
            decoder = cbor2.CBORDecoder(_BytesReader(data))
            return decoder.decode()
        except Exception:
            return None


class _BytesReader:
    """Minimal file-like wrapper so CBORDecoder can read from bytes."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read(self, n: int) -> bytes:
        chunk = self._data[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk


# --------------------------------------------------------------------------- #
# Message builders (client -> bike)
# --------------------------------------------------------------------------- #

def build_certificate_message(cert_data: bytes) -> bytes:
    """Build an AUTH_CERT message body (PayloadType + raw certificate)."""
    return bytes([PayloadType.AUTH_CERT]) + bytes(cert_data)


def sign_challenge(nonce: bytes,
                   private_key: Union[Ed25519PrivateKey, bytes]) -> bytes:
    """
    Build an AUTH_CHALLENGE response: PayloadType + 64-byte Ed25519 signature
    over the raw 16-byte nonce.

    ``private_key`` may be an :class:`Ed25519PrivateKey` or raw key bytes
    (32-byte seed or 64-byte expanded form).
    """
    if isinstance(private_key, (bytes, bytearray)):
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(private_key[:32]))
    signature = private_key.sign(nonce)
    return bytes([PayloadType.AUTH_CHALLENGE]) + signature


def _control_message(control: int, topics: Iterable[int]) -> bytes:
    out = bytearray([PayloadType.SUBSCRIBE])
    out += int(control).to_bytes(2, "big")
    for topic in topics:
        out += int(topic).to_bytes(2, "big")
    return bytes(out)


def build_subscribe_message(topics: Iterable[int]) -> bytes:
    """
    Build a SUBSCRIBE message: PayloadType, the SUBSCRIBE_CONTROL topic, then
    each requested topic as a big-endian uint16. Retained topics (states and
    settings) are delivered immediately.
    """
    return _control_message(Topic.SUBSCRIBE_CONTROL, topics)


def build_unsubscribe_message(topics: Iterable[int]) -> bytes:
    """Build an unsubscribe message (SUBSCRIBE with UNSUBSCRIBE_CONTROL)."""
    return _control_message(Topic.UNSUBSCRIBE_CONTROL, topics)


def build_topic_write(topic: int, value: Any) -> bytes:
    """
    Build a TOPIC_CBOR write message: PayloadType, topic (uint16 big-endian),
    then the CBOR-encoded value.
    """
    return (bytes([PayloadType.TOPIC_CBOR])
            + int(topic).to_bytes(2, "big")
            + cbor2.dumps(value))


def b64_certificate_message(certificate_b64: str) -> bytes:
    """Convenience: build an AUTH_CERT message from a base64 certificate."""
    return build_certificate_message(base64.b64decode(certificate_b64))


# --------------------------------------------------------------------------- #
# Self-test (run: python -m utils.protocol_codes)
#
# Wire vectors come from the community clients' unit tests and from the
# official app's encoders, so this doubles as a regression check that the
# messages we build are the ones the app sends.
# --------------------------------------------------------------------------- #

def _selftest() -> None:
    # TOPIC_CBOR: battery level 38 on topic 24.
    m = parse_message(bytes.fromhex("0100181826"))
    assert isinstance(m, TopicMessage) and m.topic == 24 and m.value == 38, m
    assert describe_topic_value(m.topic, m.value) == "38%"

    # TOPIC_CBOR: distance 1013514 on topic 165.
    m = parse_message(bytes.fromhex("0100a51a000f770a"))
    assert isinstance(m, TopicMessage) and m.topic == 165 and m.value == 1013514, m

    # TOPIC_CBOR: topic 1 is the power state; 3 == operational.
    m = parse_message(bytes.fromhex("01000103"))
    assert isinstance(m, TopicMessage) and m.topic == Topic.POWER_STATE and m.value == 3
    assert power_state_name(m.value) == "operational"

    # Lock state lives on 161: 1 locked, 3/5 unlocked.
    assert is_locked(1) is True and is_locked(3) is False and is_locked(5) is False
    assert is_locked(4) is None and is_locked(True) is None

    # AUTH_DETAILS: {enc: true, auth: true}.
    m = parse_message(bytes.fromhex("05bf63656e63f56461757468f5ff"))
    assert isinstance(m, AuthMessage) and m.authenticated and m.encrypted, m

    # AUTH_CHALLENGE nonce passthrough.
    nonce = bytes.fromhex("4ad328f79cdc0011203c84968822597f")
    m = parse_message(bytes([PayloadType.AUTH_CHALLENGE]) + nonce)
    assert isinstance(m, ChallengeMessage) and m.nonce == nonce

    # PARAM_UPDATE and MTU_UPDATE carry CBOR maps.
    m = parse_message(bytes.fromhex(
        "07bf676c6174656e6379006774696d656f7574181968696e74657276616c0cff"))
    assert isinstance(m, ParamMessage) and m.data == {
        "latency": 0, "timeout": 25, "interval": 12}, m
    m = parse_message(bytes([PayloadType.MTU_UPDATE]) + cbor2.dumps({"tx_max_len": 251}))
    assert isinstance(m, MtuMessage) and m.data == {"tx_max_len": 251}, m

    # Reassembler: single-fragment battery message (fragment header 81 00 04).
    r = FragmentReassembler()
    m = r.feed(bytes.fromhex("8100040100181826"))
    assert isinstance(m, TopicMessage) and m.topic == 24 and m.value == 38, m

    # Reassembler: single-fragment AUTH_DETAILS, not authenticated.
    r = FragmentReassembler()
    m = r.feed(bytes.fromhex("81000d05bf63656e63f46461757468f4ff"))
    assert isinstance(m, AuthMessage) and not m.authenticated, m

    # Reassembler: a continuation fragment without a first fragment is dropped.
    assert FragmentReassembler().feed(bytes.fromhex("0100040100181826")) is None

    # build_subscribe_message layout: 02 E001 0018 00A1.
    sub = build_subscribe_message([Topic.BATTERY_LEVEL, Topic.LOCK_STATE])
    assert sub == bytes.fromhex("02e001001800a1"), sub.hex()
    assert build_unsubscribe_message([0x35]) == bytes.fromhex("02e0020035")

    # build_fragments: single fragment, header 0x81, remaining == len - 1.
    payload = bytes([PayloadType.TOPIC_CBOR, 0x00, 0x18, 0x18, 0x26])
    frags = build_fragments(payload)
    assert frags == [bytes.fromhex("810004") + payload]

    # build_fragments: multi-fragment layout of the app's fragmenter.
    big = bytes([PayloadType.AUTH_CERT]) + b"\xAA" * 49
    frags = build_fragments(big, max_write=20)
    assert [f[:3].hex() for f in frags] == ["810031", "010021", "010010"]
    r = FragmentReassembler()
    frags = build_fragments(build_topic_write(Topic.FW_INFO, "v" * 40), max_write=20)
    got = [r.feed(f) for f in frags]
    assert len(frags) == 3 and got[:2] == [None, None], got
    assert isinstance(got[2], TopicMessage) and got[2].value == "v" * 40, got

    # Writes, byte-for-byte as the official app builds them.
    assert (build_fragments(build_topic_write(Topic.UNLOCK, 1))
            == [bytes.fromhex("8100030100a001")])
    assert build_topic_write(Topic.LIGHT_MODE_SET, LIGHT_MODE_VALUES["off"]) == bytes.fromhex("01006b02")
    assert build_topic_write(Topic.ASSIST_LEVEL_SET, 3) == bytes.fromhex("01006703")
    assert build_topic_write(Topic.ALARM_SET, True) == bytes.fromhex("01006ff5")
    assert build_topic_write(Topic.REGION_SET, REGION_VALUES["offroad"]) == bytes.fromhex("01006203")
    assert build_topic_write(Topic.BELL_SOUND_SET, BELL_SOUND_VALUES["ping"]) == bytes.fromhex("01007302")

    # Round-trip a topic write through fragments + reassembler.
    r = FragmentReassembler()
    for frag in build_fragments(build_topic_write(Topic.LIGHT_MODE, 2)):
        m = r.feed(frag)
    assert isinstance(m, TopicMessage) and m.topic == Topic.LIGHT_MODE and m.value == 2
    assert describe_topic_value(m.topic, m.value) == "off"

    # Names: firmware registry entries and the CAN heartbeat topics.
    assert topic_name(Topic.LOCK_STATE) == "ux/lock/info/state"
    assert topic_name(0x0035) == "device/eshifter/status"
    assert topic_name(0x1234) == "topic_0x1234"
    assert len(HEARTBEAT_TOPICS) == 15 and HEARTBEAT_TOPICS[-1] == 0x003E
    assert all(t in TOPIC_NAMES for t in ALL_TOPICS)
    assert bell_name(4) == "ship_horn" and decode_region(3) == "offroad"

    print("protocol_codes self-test: OK")


if __name__ == "__main__":
    _selftest()
