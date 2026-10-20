"""
VanMoof S6 BLE protocol.

The S6 talks to the app over a single GATT characteristic, like the S5/A5, but
uses its own message format: an MQTT-style message with a type, a 16-bit topic
(an id in the bike's object dictionary), a CBOR payload and a CRC.

Sources, in order of authority:

  - captures of the official app talking to an S6 in the field (app v26,
    documented in Nefilim78/vanmoof-s6-ble-protocol): what the bike accepts
    today, including the topic meanings marked "captured" below;
  - the official app 24.3 (S6 profile `xl/l0`, message builder `mm.o`,
    fragmenter `cg.r.c`, CRC `ck.a`, payload wrapper `yd.e0.c`): the exact
    encodings;
  - the S6 `ble` firmware v1.8.8.4974, which registers the GATT UUIDs below
    and dispatches topics through its object dictionary.

    GATT service : df286100-1440-48a1-88f1-247d7f7d274d
    App char     : df286101-1440-48a1-88f1-247d7f7d274d   (notify + write)

Wire format
-----------
Message::

    [id:1][type | qos << 3 | retain << 4][topic:2 LE][length:2 LE][payload][crc:2 LE]

  * `id` comes from a per-connection counter (0..255, wrapping);
  * `crc` is CRC-16/MODBUS over every byte before it.

Messages are split into fragments of at most one GATT write (ATT MTU - 3)::

    [(0x80 if first else 0x00) | frag_id][remaining:2 BE][chunk]

  * `frag_id` comes from a second counter (0..127, then 1..127) and is shared
    by all fragments of a message;
  * `remaining` counts the bytes still to come *including* this chunk, so the
    first fragment carries the full message length.

Payloads are CBOR. A value is a small data class encoded as a CBOR array of
its fields (`[value]`, `[mode, offAutoMode]`, ...). Requests wrap that
encoding in a byte string inside a one-element array; the bike answers the
same way, with indefinite-length arrays.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, List, Optional, Union

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SERVICE_UUID  = "df286100-1440-48a1-88f1-247d7f7d274d"
APP_CHAR_UUID = "df286101-1440-48a1-88f1-247d7f7d274d"
# Match the characteristic by this prefix: published notes also give a
# df286101 UUID with a different base.
APP_CHAR_PREFIX = "df286101-"


class MessageType(IntEnum):
    ACK         = 0
    PUBLISH     = 1   # bike -> client: a topic value
    SUBSCRIBE   = 2
    UNSUBSCRIBE = 3
    GET         = 4   # client -> bike: read a topic (empty payload)
    SET         = 5   # client -> bike: write a topic, also used for auth
    OWN         = 6
    SYNC        = 7


QOS_AT_LEAST_ONCE = 0
QOS_AT_MOST_ONCE  = 1   # the app's default


class Topic(IntEnum):
    """Topic ids (object-dictionary ids of the S6 `ble` controller)."""

    FRAME_NUMBER      = 0x0031  # frame number string
    WAKE              = 0x010C  # write [1] to wake the bike, which unlocks it (captured)
    ASSIST_LEVEL      = 0x0110  # 0 = off, 1-4
    LOCK_STATE        = 0x0112  # 0 unlocked, 1 locked (captured; app 24.3 read speed here)
    DISTANCE          = 0x0113  # odometer
    WALK_ASSIST       = 0x0118  # 0 / 1
    ERRORS            = 0x011F  # error code (captured)
    LIGHT_MODE        = 0x0131  # [mode, offAutoMode], see LIGHT_MODES
    BELL_SOUND        = 0x0142  # bell tone; selecting one plays it
    MUTE_MODE         = 0x0144
    SPEED             = 0x0164  # (captured)
    ALARM_SENSITIVITY = 0x0171  # see ALARM_SENSITIVITIES
    ALARM             = 0x0172  # 0 off, 1 on
    FIRMWARE          = 0x01B1  # firmware version
    BATTERY_LEVEL     = 0x022A  # %
    CHARGE_LIMIT      = 0x022D  # % (captured)
    AUTH              = 0xFF00  # certificate / challenge exchange


TOPIC_NAMES = {topic: topic.name.lower() for topic in Topic}


def topic_name(topic: int) -> str:
    """Name of a topic id, or a hex placeholder for unknown ids."""
    return TOPIC_NAMES.get(topic, "topic_0x{0:04X}".format(topic))


# Status topics read after login.
STATUS_TOPICS = [
    Topic.LOCK_STATE, Topic.BATTERY_LEVEL, Topic.ASSIST_LEVEL,
    Topic.LIGHT_MODE, Topic.ALARM, Topic.BELL_SOUND, Topic.DISTANCE,
    Topic.FIRMWARE,
]


# --------------------------------------------------------------------------- #
# Value tables (from the app's S6 encoders unless noted)
# --------------------------------------------------------------------------- #

LOCK_STATES = {0: "unlocked", 1: "locked"}
LIGHT_MODES = {0: "off", 1: "DRL", 2: "on", 3: "auto"}
LIGHT_MODE_VALUES = {"off": 0, "on": 2, "auto": 3}
ALARM_STATES = {0: "off", 1: "on"}
ALARM_SENSITIVITIES = {1: "high", 2: "medium", 4: "low"}
# The S6 has its own tone set; the S5's vanmoof, party_horn and ship_horn
# tones aren't offered.
BELL_SOUNDS = {0: "ping", 1: "tring", 2: "ding_dong", 3: "laser",
               4: "quack", 5: "meow", 6: "epic"}
BELL_SOUND_VALUES = {name: value for value, name in BELL_SOUNDS.items()}

# The app's light mode carries a second field; the captured app sends 1.
LIGHT_OFF_AUTO_MODE = 1


def _int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def first_field(value: Any) -> Any:
    """The first field of a decoded value (its only field for most topics)."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def describe_value(topic: int, value: Any) -> str:
    """Human-readable rendering of a decoded topic value."""
    field = first_field(value)
    tables = {
        Topic.LOCK_STATE: LOCK_STATES,
        Topic.LIGHT_MODE: LIGHT_MODES,
        Topic.ALARM: ALARM_STATES,
        Topic.ALARM_SENSITIVITY: ALARM_SENSITIVITIES,
        Topic.BELL_SOUND: BELL_SOUNDS,
    }
    if topic in tables and _int(field) is not None and field in tables[topic]:
        return tables[topic][field]
    if topic in (Topic.BATTERY_LEVEL, Topic.CHARGE_LIMIT) and _int(field) is not None:
        return "{0}%".format(field)
    if topic == Topic.ASSIST_LEVEL and field == 0 and _int(field) is not None:
        return "0 (off)"
    if isinstance(field, float) and not math.isfinite(field):
        return str(field)
    if isinstance(field, (bytes, bytearray)):
        return bytes(field).hex()
    if isinstance(value, list) and len(value) > 1:
        return str(value)
    return str(field)


# --------------------------------------------------------------------------- #
# CRC, messages and counters
# --------------------------------------------------------------------------- #

def crc16_modbus(data: bytes) -> int:
    """CRC-16/MODBUS (reflected polynomial 0xA001, initial value 0xFFFF)."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


@dataclass
class Message:
    """One S6 message."""

    type: int
    topic: int
    payload: bytes = b""
    id: int = 0
    qos: int = QOS_AT_MOST_ONCE
    retain: int = 0


def build_message(message: Message) -> bytes:
    """Serialize a message, including its CRC."""
    flags = (message.type & 0x07) | ((message.qos & 0x01) << 3) | ((message.retain & 0x03) << 4)
    body = (bytes([message.id & 0xFF, flags])
            + (message.topic & 0xFFFF).to_bytes(2, "little")
            + len(message.payload).to_bytes(2, "little")
            + bytes(message.payload))
    return body + crc16_modbus(body).to_bytes(2, "little")


def parse_message(data: bytes) -> Optional[Message]:
    """Parse one complete message; None if it is truncated or the CRC is wrong."""
    if len(data) < 8:
        return None
    length = int.from_bytes(data[4:6], "little")
    if len(data) < 8 + length:
        return None
    body, crc = data[:6 + length], data[6 + length:8 + length]
    if crc16_modbus(body) != int.from_bytes(crc, "little"):
        return None
    flags = data[1]
    return Message(type=flags & 0x07, topic=int.from_bytes(data[2:4], "little"),
                   payload=bytes(data[6:6 + length]), id=data[0],
                   qos=(flags >> 3) & 0x01, retain=(flags >> 4) & 0x03)


class Counter:
    """The app's id counters: message ids wrap 255 -> 0, fragment ids 127 -> 1."""

    def __init__(self, limit: int, restart: int):
        self._next = 0
        self._limit = limit
        self._restart = restart

    def next(self) -> int:
        value = self._next
        self._next = self._restart if value >= self._limit else value + 1
        return value


def message_counter() -> Counter:
    return Counter(255, 0)


def fragment_counter() -> Counter:
    return Counter(127, 1)


# --------------------------------------------------------------------------- #
# Fragment layer
# --------------------------------------------------------------------------- #

def build_fragments(message: bytes, max_write: int, frag_id: int) -> List[bytes]:
    """
    Split a serialized message into fragments of at most `max_write` bytes
    (the ATT MTU - 3), as the app does.
    """
    chunk_size = max_write - 3
    fragments = []  # type: List[bytes]
    for index, start in enumerate(range(0, len(message), chunk_size)):
        remaining = (len(message) - index * chunk_size) & 0xFFFF
        header = bytes([(0x80 if index == 0 else 0x00) | (frag_id & 0x7F)])
        fragments.append(header + remaining.to_bytes(2, "big")
                         + message[start:start + chunk_size])
    return fragments


class FragmentReassembler:
    """
    Reassembles fragmented notifications into complete serialized messages.

    A fragment continues the message in progress when its `remaining` matches
    the bytes still expected, whether or not it has the first-fragment bit
    set: the captures only show single-fragment messages from the bike, all
    with that bit set.
    """

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._buf = b""
        self._total = 0

    def feed(self, data: bytes) -> Optional[bytes]:
        """Feed one notification; returns the message bytes once complete."""
        if len(data) < 3:
            return None
        remaining = int.from_bytes(data[1:3], "big")
        chunk = bytes(data[3:])
        expected = self._total - len(self._buf)
        if self._buf and remaining == expected:
            self._buf += chunk
        elif data[0] & 0x80:
            self._buf, self._total = chunk, remaining
        else:
            self.reset()
            return None
        if len(self._buf) >= self._total:
            message = self._buf[:self._total]
            self.reset()
            return message
        return None


# --------------------------------------------------------------------------- #
# Payloads
# --------------------------------------------------------------------------- #

def wrap_payload(inner: bytes) -> bytes:
    """A request payload: a one-element CBOR array holding `inner` as bytes."""
    return cbor2.dumps([bytes(inner)])


def encode_value(fields: List[Any]) -> bytes:
    """Request payload for a SET: the data-class fields, wrapped."""
    return wrap_payload(cbor2.dumps(list(fields)))


def decode_payload(payload: bytes) -> Any:
    """
    The fields of a payload from the bike: unwraps the one-element array of
    bytes the bike sends and decodes the data class inside. Returns a list of
    fields, a bare value for other encodings, or None if it isn't CBOR.
    """
    if not payload:
        return None
    try:
        outer = cbor2.loads(payload)
        if (isinstance(outer, list) and len(outer) == 1
                and isinstance(outer[0], (bytes, bytearray))):
            return cbor2.loads(bytes(outer[0]))
        return outer
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #

def build_certificate_payload(certificate: bytes) -> bytes:
    """AUTH payload carrying the certificate (64-byte CA signature + CBOR)."""
    return wrap_payload(cbor2.dumps(bytes(certificate)))


def build_signature_payload(signature: bytes) -> bytes:
    """AUTH payload carrying the 64-byte Ed25519 signature of the challenge."""
    return wrap_payload(cbor2.dumps(bytes(signature)))


def sign_challenge(challenge: bytes,
                   private_key: Union[Ed25519PrivateKey, bytes]) -> bytes:
    """AUTH payload answering a challenge with the certificate's key."""
    if isinstance(private_key, (bytes, bytearray)):
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(private_key[:32]))
    return build_signature_payload(private_key.sign(bytes(challenge)))


@dataclass
class AuthReply:
    """
    The bike's answer on the AUTH topic: `status` >= 0 with a 16-byte
    `challenge` after the certificate, `status` 2 without one once
    authenticated, and a negative `status` on a rejection.
    """

    status: int
    challenge: Optional[bytes] = None

    @property
    def rejected(self) -> bool:
        return self.status < 0

    @property
    def authenticated(self) -> bool:
        return self.status >= 0 and self.challenge is None


def parse_auth_reply(payload: bytes) -> Optional[AuthReply]:
    """Parse an AUTH payload from the bike; None if it isn't one."""
    fields = decode_payload(payload)
    if not isinstance(fields, list) or not fields or _int(fields[0]) is None:
        return None
    challenge = fields[1] if len(fields) > 1 else None
    if challenge is not None and not (isinstance(challenge, (bytes, bytearray))
                                      and len(challenge) == 16):
        return None
    return AuthReply(status=fields[0],
                     challenge=bytes(challenge) if challenge is not None else None)


# --------------------------------------------------------------------------- #
# Self-test (run: python -m utils.s6_protocol)
# --------------------------------------------------------------------------- #

def _selftest() -> None:
    assert crc16_modbus(b"123456789") == 0x4B37  # the CRC-16/MODBUS check value

    # Certificate message as captured: 71 0D 00FF AE00 81 58AB 58A9 <cert> <crc>.
    certificate = bytes(range(169))
    payload = build_certificate_payload(certificate)
    assert payload[:5] == bytes.fromhex("8158ab58a9") and len(payload) == 174
    message = build_message(Message(MessageType.SET, Topic.AUTH, payload, id=0x71))
    assert message[:6] == bytes.fromhex("710d00ffae00") and len(message) == 182
    assert parse_message(message) == Message(MessageType.SET, Topic.AUTH, payload, id=0x71)
    assert parse_message(message[:-1] + bytes([message[-1] ^ 1])) is None

    # Fragments: the captured single fragment "85 00B6", and a split message.
    assert build_fragments(message, 244, 5)[0][:3] == bytes.fromhex("8500b6")
    frags = build_fragments(message, 20, 7)
    assert [f[0] for f in frags[:2]] == [0x87, 0x07]
    assert int.from_bytes(frags[1][1:3], "big") == len(message) - 17
    r = FragmentReassembler()
    assert [r.feed(f) for f in frags][-1] == message

    # Bike replies: challenge, success and rejection, as captured.
    challenge = bytes(range(16))
    inner = bytes.fromhex("9f0150") + challenge + b"\xff"
    reply = parse_auth_reply(b"\x9f\x54" + inner + b"\xff")
    assert reply == AuthReply(1, challenge) and not reply.authenticated
    assert parse_auth_reply(bytes.fromhex("9f439f02ffff")).authenticated
    assert parse_auth_reply(bytes.fromhex("9f439f20ffff")).rejected

    # Values: SET payload and a published value.
    assert encode_value([1]) == bytes.fromhex("81428101")
    assert decode_payload(bytes.fromhex("9f439f00ffff")) == [0]
    assert describe_value(Topic.LOCK_STATE, [0]) == "unlocked"
    assert describe_value(Topic.LIGHT_MODE, [2, 1]) == "on"

    # Counters wrap like the app's.
    c = fragment_counter()
    assert [c.next() for _ in range(129)][-2:] == [127, 1]
    c = message_counter()
    assert [c.next() for _ in range(257)][-2:] == [255, 0]

    print("s6_protocol self-test: OK")


if __name__ == "__main__":
    _selftest()
