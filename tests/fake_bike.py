"""
A simulated VanMoof S5/A5 for tests: a fake BleakClient plus a bike model that
behaves the way the firmware (v1.5.0) and the official app show.

The bike reassembles client fragments with the app's layout and records every
complete message. Like the firmware it

  - answers AUTH_CERT with a challenge and checks the signature against the
    certificate's public key, disconnecting on a bad one;
  - disconnects on an AUTH_CERT body of 0x40 bytes or less, and on topic
    writes before authentication;
  - applies .../set writes the owner role may make and re-publishes the value
    topic to subscribers, ignoring every other write;
  - delivers retained values when a topic is first subscribed.

Anything a correct client should never send is recorded in `violations`.
"""

import asyncio
import base64
import contextlib
import io
import os
import time

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)

from utils import protocol_codes as proto
from utils import s6_protocol as s6
from utils.credentials_utils import load_credentials
from utils.protocol_codes import Topic
from utils.s6_protocol import Topic as S6Topic


# .../set topic -> (value topic, validator), as the owner ACL allows.
SETTINGS = {
    Topic.ASSIST_LEVEL_SET: (Topic.ASSIST_LEVEL, lambda v: v in range(5)),
    Topic.LIGHT_MODE_SET:   (Topic.LIGHT_MODE, lambda v: v in (1, 2, 3)),
    Topic.ALARM_SET:        (Topic.ALARM, lambda v: isinstance(v, bool)),
    Topic.REGION_SET:       (Topic.REGION, lambda v: v in range(4)),
    Topic.BELL_SOUND_SET:   (Topic.BELL_SOUND, lambda v: v in range(5)),
}


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def initial_state():
    """Retained values for every topic the client may ask for."""
    state = {
        Topic.POWER_STATE: 2, Topic.BATTERY_LEVEL: 38, Topic.BATTERY_SOC: 40,
        Topic.LOCK_STATE: 1, Topic.DISTANCE: 1013514, Topic.ASSIST_LEVEL: 2,
        Topic.LIGHT_MODE: 3, Topic.REGION: 0, Topic.ALARM: False,
        Topic.BELL_SOUND: 3, Topic.ESHIFTER_GEAR: 2, Topic.FW_INFO: "1.5.0",
        Topic.ERRORS: 0, Topic.CALORIES: 12.5, Topic.BOOST: False,
    }
    for topic in proto.TELEMETRY_TOPICS:
        state.setdefault(topic, 0)
    for topic in proto.HEARTBEAT_TOPICS:
        state[topic] = "ok"
    return state


class FakeBike:
    """The bike side of the link."""

    def __init__(self, mtu=247, reject_signature=False, state=None):
        self.mtu = mtu
        self.reject_signature = reject_signature
        self.state = initial_state() if state is None else state
        # GATT table the fake BleakClient reports (None: the S5/A5 service).
        self.services = None
        self.link = None            # FakeBleakClient, set when it is created
        self.authenticated = False
        self.subscribed = set()
        self.fragments = []         # raw client -> bike writes
        self.messages = []          # complete client -> bike messages
        self.violations = []
        self.disconnect_reason = None
        self._cert_key = None
        self._nonce = None
        self._buf = b""
        self._expected = 0
        self._active = False

    # -- bike -> client ---------------------------------------------------- #

    def send(self, message):
        for frag in proto.build_fragments(message, self.mtu - 3):
            self.link.notify(frag)

    def publish(self, topic, value):
        """Change a value and push it to the client if it is subscribed."""
        self.state[topic] = value
        if topic in self.subscribed:
            self.send(proto.build_topic_write(topic, value))

    def on_connect(self):
        self.send(bytes([proto.PayloadType.AUTH_DETAILS])
                  + cbor2.dumps({"enc": False, "auth": False}))
        self.send(bytes([proto.PayloadType.PARAM_UPDATE])
                  + cbor2.dumps({"latency": 0, "timeout": 25, "interval": 12}))

    def drop(self, reason):
        self.disconnect_reason = reason
        self.link.drop()

    # -- client -> bike ---------------------------------------------------- #

    def on_write(self, data):
        self.fragments.append(data)
        if len(data) < 3:
            self.violations.append("write of %d bytes (no fragment header)" % len(data))
            return
        if len(data) > self.link.mtu_size - 3:
            self.violations.append("fragment of %d bytes" % len(data))
        frag = proto.parse_fragment(data)
        if frag.seq_id != 1:
            self.violations.append("fragment seq id %d" % frag.seq_id)
        if frag.is_first:
            self._buf, self._active = bytes(frag.payload), True
            self._expected = frag.total_len + 1
        elif not self._active:
            self.violations.append("continuation without a first fragment")
            return
        else:
            if frag.total_len != self._expected - len(self._buf):
                self.violations.append("continuation remaining %d, expected %d"
                                       % (frag.total_len, self._expected - len(self._buf)))
            self._buf += frag.payload
        if len(self._buf) >= self._expected:
            message, self._active = self._buf[:self._expected], False
            self.messages.append(message)
            self.on_message(message)

    def on_message(self, message):
        payload_type, body = message[0], message[1:]
        if payload_type == proto.PayloadType.AUTH_CERT:
            self._on_certificate(body)
        elif payload_type == proto.PayloadType.AUTH_CHALLENGE:
            self._on_signature(body)
        elif payload_type == proto.PayloadType.SUBSCRIBE:
            self._on_subscribe(body)
        elif payload_type == proto.PayloadType.TOPIC_CBOR:
            self._on_topic_write(body)
        else:
            self.violations.append("PayloadType 0x%02X" % payload_type)

    def _on_certificate(self, body):
        if len(body) <= 0x40:
            self.violations.append("AUTH_CERT body of %d bytes" % len(body))
            return self.drop("server signature invalid")
        if self.authenticated:
            return
        try:
            self._cert_key = Ed25519PublicKey.from_public_bytes(
                cbor2.loads(body[64:])["p"])
        except Exception:
            return self.drop("invalid certificate/parsing error")
        self._nonce = os.urandom(16)
        self.send(bytes([proto.PayloadType.AUTH_CHALLENGE]) + self._nonce)

    def _on_signature(self, signature):
        try:
            if self.reject_signature or self._nonce is None:
                raise ValueError("rejected")
            self._cert_key.verify(signature, self._nonce)
        except Exception:
            return self.drop("challenge return invalid")
        self.authenticated = True
        self.send(bytes([proto.PayloadType.AUTH_DETAILS])
                  + cbor2.dumps({"enc": False, "auth": True}))

    def _on_subscribe(self, body):
        control = int.from_bytes(body[:2], "big")
        topics = [int.from_bytes(body[i:i + 2], "big")
                  for i in range(2, len(body) - 1, 2)]
        if len(body) % 2:
            self.violations.append("SUBSCRIBE body of odd length")
        if control == Topic.SUBSCRIBE_CONTROL:
            for topic in topics:
                if topic not in self.subscribed:
                    self.subscribed.add(topic)
                    if topic in self.state:
                        self.send(proto.build_topic_write(topic, self.state[topic]))
        elif control == Topic.UNSUBSCRIBE_CONTROL:
            self.subscribed.difference_update(topics)
        else:
            self.violations.append("SUBSCRIBE control topic 0x%04X" % control)

    def _on_topic_write(self, body):
        if not self.authenticated:
            self.violations.append("topic write before authentication")
            return self.drop("not authenticated")
        topic = int.from_bytes(body[:2], "big")
        if len(body) <= 2:
            self.violations.append("empty publish to 0x%04X" % topic)
            return
        value = cbor2.loads(body[2:])
        if topic in SETTINGS:
            value_topic, valid = SETTINGS[topic]
            if (topic == Topic.ALARM_SET or _is_int(value)) and valid(value):
                self.publish(value_topic, value)
        elif topic == Topic.UNLOCK:
            if value == 1 and _is_int(value):
                self.publish(Topic.LOCK_STATE, 3)
        else:
            self.violations.append("write outside the owner ACL: 0x%04X" % topic)


def s6_initial_state():
    """Values (as field lists) for the S6 topics the client may ask for."""
    return {
        S6Topic.LOCK_STATE: [1], S6Topic.BATTERY_LEVEL: [64],
        S6Topic.ASSIST_LEVEL: [2], S6Topic.LIGHT_MODE: [3, 1], S6Topic.ALARM: [0],
        S6Topic.BELL_SOUND: [2], S6Topic.DISTANCE: [123456],
        S6Topic.FIRMWARE: ["1.8.8.4974"], S6Topic.FRAME_NUMBER: ["TVDEG200260ZA"],
    }


# S6 settings the fake bike accepts: topic -> validator of the field list.
S6_SETTINGS = {
    S6Topic.ASSIST_LEVEL: lambda f: len(f) == 1 and f[0] in range(5),
    S6Topic.LIGHT_MODE:   lambda f: len(f) == 2 and f[0] in range(4),
    S6Topic.ALARM:        lambda f: len(f) == 1 and f[0] in (0, 1),
    S6Topic.BELL_SOUND:   lambda f: len(f) == 1 and f[0] in range(7),
}


class FakeS6Bike:
    """
    The bike side of an S6 link: the app's fragment layout, CRC-checked
    messages, the certificate / challenge exchange on the AUTH topic, GET and
    SET on the known topics. Replies use the bike's indefinite-length
    wrapping; `bit7_on_all` sets the first-fragment bit on every fragment.
    """

    def __init__(self, mtu=247, reject_certificate=False, reject_signature=False,
                 publish_on_set=True, bit7_on_all=False, state=None):
        self.mtu = mtu
        self.reject_certificate = reject_certificate
        self.reject_signature = reject_signature
        self.publish_on_set = publish_on_set
        self.bit7_on_all = bit7_on_all
        self.state = s6_initial_state() if state is None else state
        self.services = [FakeService(s6.SERVICE_UUID, [
            FakeCharacteristic(s6.APP_CHAR_UUID, ["write", "notify"])])]
        self.link = None
        self.authenticated = False
        self.fragments = []
        self.messages = []          # parsed client -> bike messages
        self.violations = []
        self.disconnect_reason = None
        self._key = None
        self._challenge = None
        self._last_id = None
        self._buf = b""
        self._total = 0
        self._frag_id = None
        self._message_ids = s6.message_counter()
        self._fragment_ids = s6.fragment_counter()

    # -- bike -> client ---------------------------------------------------- #

    @staticmethod
    def wrap(fields):
        """The bike's payload: [_ bstr([_ fields... ]) ] (indefinite arrays)."""
        inner = b"\x9f" + b"".join(cbor2.dumps(f) for f in fields) + b"\xff"
        return b"\x9f" + cbor2.dumps(inner) + b"\xff"

    def send(self, topic, fields):
        message = s6.build_message(s6.Message(
            s6.MessageType.PUBLISH, topic, self.wrap(fields),
            id=self._message_ids.next()))
        for i, frag in enumerate(s6.build_fragments(message, self.mtu - 3,
                                                    self._fragment_ids.next())):
            if self.bit7_on_all:
                frag = bytes([frag[0] | 0x80]) + frag[1:]
            self.link.notify(frag)

    def publish(self, topic, fields):
        self.state[topic] = list(fields)
        self.send(topic, fields)

    def on_connect(self):
        pass  # the S6 waits for the certificate

    def drop(self, reason):
        self.disconnect_reason = reason
        self.link.drop()

    # -- client -> bike ---------------------------------------------------- #

    def on_write(self, data):
        self.fragments.append(data)
        if len(data) > self.link.mtu_size - 3:
            self.violations.append("fragment of %d bytes" % len(data))
        if len(data) < 3:
            self.violations.append("write of %d bytes" % len(data))
            return
        remaining = int.from_bytes(data[1:3], "big")
        if data[0] & 0x80:
            if self._buf:
                self.violations.append("new message before the last one completed")
            self._buf, self._total, self._frag_id = bytes(data[3:]), remaining, data[0] & 0x7F
        elif self._buf and (data[0] & 0x7F) == self._frag_id \
                and remaining == self._total - len(self._buf):
            self._buf += bytes(data[3:])
        else:
            self.violations.append("unexpected continuation fragment %s" % data[:3].hex())
            self._buf = b""
            return
        if len(self._buf) >= self._total:
            raw, self._buf = self._buf[:self._total], b""
            message = s6.parse_message(raw)
            if message is None:
                self.violations.append("message with a bad length or CRC")
                return
            self.messages.append(message)
            self.on_message(message)

    def _fields(self, message):
        """The field list of a client SET payload: [bstr(cbor(fields))]."""
        try:
            outer = cbor2.loads(message.payload)
            fields = cbor2.loads(outer[0])
        except Exception:
            fields = None
        if not (isinstance(outer, list) and len(outer) == 1 and isinstance(fields, list)):
            self.violations.append("SET payload not wrapped like the app's")
            return None
        return fields

    def on_message(self, message):
        expected_id = 0 if self._last_id is None else (self._last_id + 1) & 0xFF
        if message.id != expected_id:
            self.violations.append("message id %d, expected %d" % (message.id, expected_id))
        self._last_id = message.id
        if message.qos != s6.QOS_AT_MOST_ONCE:
            self.violations.append("qos %d" % message.qos)
        if message.topic == S6Topic.AUTH:
            return self._on_auth(message)
        if not self.authenticated:
            self.violations.append("request before authentication")
            return
        if message.type == s6.MessageType.GET:
            if message.payload:
                self.violations.append("GET with a payload")
            if message.topic in self.state:
                self.send(message.topic, self.state[message.topic])
        elif message.type == s6.MessageType.SET:
            fields = self._fields(message)
            if fields is None:
                return
            if message.topic == S6Topic.WAKE:
                if fields == [1]:
                    self.publish(S6Topic.LOCK_STATE, [0])
            elif message.topic in S6_SETTINGS:
                if S6_SETTINGS[message.topic](fields):
                    self.state[message.topic] = fields
                    if self.publish_on_set:
                        self.send(message.topic, fields)
            else:
                self.violations.append("SET on topic 0x%04X" % message.topic)
        else:
            self.violations.append("message type %d" % message.type)

    def _on_auth(self, message):
        if message.type != s6.MessageType.SET:
            self.violations.append("auth message of type %d" % message.type)
            return
        try:
            outer = cbor2.loads(message.payload)
            data = cbor2.loads(outer[0])
            assert isinstance(outer, list) and len(outer) == 1 and isinstance(data, bytes)
        except Exception:
            self.violations.append("auth payload not wrapped like the app's")
            return
        if self._challenge is None:
            try:
                self._key = Ed25519PublicKey.from_public_bytes(cbor2.loads(data[64:])["p"])
            except Exception:
                return self.send(S6Topic.AUTH, [-1])
            if self.reject_certificate:
                return self.send(S6Topic.AUTH, [-1])
            self._challenge = os.urandom(16)
            return self.send(S6Topic.AUTH, [1, self._challenge])
        try:
            if self.reject_signature:
                raise ValueError("rejected")
            self._key.verify(data, self._challenge)
        except Exception:
            self.send(S6Topic.AUTH, [-1])
            return self.drop("challenge return invalid")
        self.authenticated = True
        self.send(S6Topic.AUTH, [2])


class FakeCharacteristic:
    def __init__(self, uuid, properties):
        self.uuid = uuid
        self.properties = properties
        self.description = ""


class FakeService:
    def __init__(self, uuid, characteristics):
        self.uuid = uuid
        self.characteristics = characteristics
        self.description = ""


class _Backend:
    """Stands in for bleak's BlueZ backend, which reports the MTU on demand."""

    def __init__(self, link):
        self.link = link

    async def _acquire_mtu(self):
        self.link.mtu = self.link.bike.mtu


class FakeBleakClient:
    """Drop-in for bleak.BleakClient, wired to `FakeBleakClient.bike`."""

    bike = None  # set by the test before main.VanMoofClient.connect()

    def __init__(self, address, disconnected_callback=None):
        self.address = address
        self.bike = FakeBleakClient.bike
        self.bike.link = self
        self.mtu = 23
        self.is_connected = False
        self._backend = _Backend(self)
        self._disconnected_callback = disconnected_callback
        self._notify_callback = None
        self._loop = asyncio.get_event_loop()
        self.services = self.bike.services or [FakeService(proto.SERVICE_UUID, [
            FakeCharacteristic(proto.APP_CHAR_UUID,
                               ["write-without-response", "write", "notify"])])]

    @property
    def mtu_size(self):
        return self.mtu

    async def connect(self):
        self.is_connected = True

    async def disconnect(self):
        self.is_connected = False

    async def start_notify(self, char, callback):
        self._notify_callback = callback
        self._loop.call_soon(self.bike.on_connect)

    async def write_gatt_char(self, char, data, response=False):
        if not self.is_connected:
            raise RuntimeError("not connected")
        self._loop.call_soon(self.bike.on_write, bytes(data))

    async def read_gatt_char(self, char):
        return b""

    def notify(self, fragment):
        if self.is_connected and self._notify_callback:
            self._loop.call_soon(self._notify_callback, None, bytearray(fragment))

    def drop(self):
        if self.is_connected:
            self.is_connected = False
            if self._disconnected_callback:
                self._loop.call_soon(self._disconnected_callback, self)


def fail_on_loop_errors(test):
    """
    Make `test` fail if an event-loop callback raises. asyncio only logs those,
    and the fake link delivers every notification and write via call_soon.
    Call from asyncSetUp.
    """
    errors = []
    asyncio.get_running_loop().set_exception_handler(
        lambda loop, context: errors.append(context))

    def check():
        if errors:
            context = errors[0]
            test.fail("exception in an event-loop callback: %r (%s)"
                      % (context.get("exception"), context.get("message")))
    test.addCleanup(check)


def make_credentials(role=7):
    """Credentials with a fresh key and a matching (unsigned) certificate."""
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload = cbor2.dumps({
        "i": 73519, "f": "SVTBKLTEST001", "b": "SVTBKLTEST001",
        "e": int(time.time()) + 7 * 86400, "r": role,
        "u": os.urandom(16), "p": public,
    })
    certificate = os.urandom(64) + payload
    with contextlib.redirect_stdout(io.StringIO()):
        return load_credentials(base64.b64encode(seed + public).decode(),
                                base64.b64encode(certificate).decode())
