"""
Seeded fuzz tests for the protocol layer, the client and the REPL.

Every run is reproducible: FUZZ_SEED picks the seed and FUZZ_ITERATIONS the
number of cases per target. The defaults keep CI fast; for a longer campaign
run e.g.

    FUZZ_ITERATIONS=100000 python -m unittest tests.test_fuzz

A failure reports the seed and the offending input so it can be replayed.
"""

import asyncio
import contextlib
import datetime
import decimal
import io
import math
import os
import random
import unittest
from unittest import mock

import cbor2

import main
from tests.fake_bike import (FakeBike, FakeS6Bike, FakeBleakClient,
                             fail_on_loop_errors, make_credentials)
from utils import protocol_codes as proto
from utils import s6_protocol as s6
from utils.protocol_codes import Topic

SEED = int(os.environ.get("FUZZ_SEED", "20261019"), 0)
ITERATIONS = int(os.environ.get("FUZZ_ITERATIONS", "500"))

MESSAGE_TYPES = (proto.TopicMessage, proto.AuthMessage, proto.ChallengeMessage,
                 proto.ParamMessage, proto.MtuMessage)
KNOWN_TOPICS = sorted(set(proto.TOPIC_NAMES))

_real_sleep = asyncio.sleep


async def _fast_sleep(delay, *args, **kwargs):
    await _real_sleep(min(delay, 0.002), *args, **kwargs)


# --------------------------------------------------------------------------- #
# Generators
# --------------------------------------------------------------------------- #

def random_bytes(rng, max_len=64):
    return bytes(rng.getrandbits(8) for _ in range(rng.randint(0, max_len)))


def random_text(rng, max_len=12):
    alphabet = "abcxyz_019 /-.?é²٣🚲\t"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, max_len)))


def random_value(rng, depth=0, exotic=False):
    """A random CBOR-encodable value (finite floats unless exotic)."""
    kinds = ["int", "bigint", "neg", "bool", "none", "float", "text", "bytes"]
    if depth < 3:
        kinds += ["list", "dict"]
    if exotic:
        kinds += ["special_float", "tag", "datetime", "decimal"]
    kind = rng.choice(kinds)
    if kind == "int":
        return rng.choice([0, 1, 2, 3, 4, 5, 23, 24, 255, 256, 65535, 65536, 2 ** 32 - 1])
    if kind == "bigint":
        return rng.randint(2 ** 64, 2 ** 1100) * rng.choice([1, -1])
    if kind == "neg":
        return -rng.randint(1, 2 ** 40)
    if kind == "bool":
        return rng.random() < 0.5
    if kind == "none":
        return None
    if kind == "float":
        return rng.uniform(-1e6, 1e6)
    if kind == "text":
        return random_text(rng)
    if kind == "bytes":
        return random_bytes(rng, 16)
    if kind == "list":
        return [random_value(rng, depth + 1, exotic) for _ in range(rng.randint(0, 4))]
    if kind == "dict":
        return {random_text(rng, 6): random_value(rng, depth + 1, exotic)
                for _ in range(rng.randint(0, 4))}
    if kind == "special_float":
        return rng.choice([math.inf, -math.inf, math.nan, 1e308, -0.0, 5e-324])
    if kind == "tag":
        return cbor2.CBORTag(rng.randint(6, 30000), random_value(rng, depth + 1))
    if kind == "datetime":
        return datetime.datetime(2024, 1, 29, 14, 52, 22, tzinfo=datetime.timezone.utc)
    return decimal.Decimal("3.14")


def corpus():
    """Valid messages to mutate: the vectors from the tests and the builders."""
    seeds = [
        bytes.fromhex("0100181826"), bytes.fromhex("0100a51a000f770a"),
        bytes.fromhex("01000103"), bytes.fromhex("05bf63656e63f56461757468f5ff"),
        bytes.fromhex("07bf676c6174656e6379006774696d656f7574181968696e74657276616c0cff"),
        b"\x04" + bytes(range(16)), b"\x06" + cbor2.dumps({"tx_max_len": 251}),
    ]
    for topic in KNOWN_TOPICS:
        seeds.append(proto.build_topic_write(topic, 3))
    seeds.append(proto.build_topic_write(Topic.FW_INFO, "1.5.0"))
    return seeds


def mutate(rng, data):
    data = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(6)
        if op == 0 and data:      # flip a bit
            i = rng.randrange(len(data))
            data[i] ^= 1 << rng.randrange(8)
        elif op == 1 and data:    # replace a byte with an interesting value
            data[rng.randrange(len(data))] = rng.choice([0x00, 0x01, 0x18, 0x19, 0x1A, 0x1B,
                                                         0x5B, 0x7B, 0x9F, 0xBF, 0xFF])
        elif op == 2:             # insert random bytes
            i = rng.randrange(len(data) + 1)
            data[i:i] = random_bytes(rng, 8)
        elif op == 3 and data:    # truncate
            del data[rng.randrange(len(data)):]
        elif op == 4 and data:    # duplicate a slice
            i = rng.randrange(len(data))
            data[i:i] = data[i:i + rng.randint(1, 8)]
        else:                     # splice another seed
            data += rng.choice(corpus())[:rng.randint(0, 8)]
    return bytes(data)


def random_message(rng):
    if rng.random() < 0.6:
        return mutate(rng, rng.choice(corpus()))
    return bytes([rng.randrange(256)]) + random_bytes(rng, 40)


def app_fragments(mtu, payload):
    """Transliteration of the official app's fragmenter (y3.a, Java `short` math)."""
    chunk = mtu - 3
    out = []
    for index, start in enumerate(range(0, len(payload), chunk)):
        remaining = (len(payload) - chunk * index - (1 if index == 0 else 0)) & 0xFFFF
        header = bytes([(0x80 if index == 0 else 0x00) | 1]) + remaining.to_bytes(2, "big")
        out.append(header + payload[start:start + chunk])
    return out


def values_equal(a, b):
    if isinstance(a, float) and isinstance(b, float):
        return a == b or (math.isnan(a) and math.isnan(b))
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(values_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(values_equal(a[k], b[k]) for k in a)
    return type(a) == type(b) and a == b


# --------------------------------------------------------------------------- #
# Protocol layer
# --------------------------------------------------------------------------- #

class ProtocolFuzzTests(unittest.TestCase):

    def setUp(self):
        self.rng = random.Random(SEED)

    def fail_case(self, data):
        self.fail("seed=%#x input=%r" % (SEED, data))

    def test_parse_message_never_raises(self):
        for _ in range(ITERATIONS * 4):
            data = random_message(self.rng)
            try:
                message = proto.parse_message(data)
                if message is not None:
                    self.assertIsInstance(message, MESSAGE_TYPES)
                if isinstance(message, proto.TopicMessage):
                    self.assertIsInstance(
                        proto.describe_topic_value(message.topic, message.value), str)
            except Exception:
                self.fail_case(data)

    def test_reassembler_never_raises(self):
        for _ in range(ITERATIONS):
            reassembler = proto.FragmentReassembler()
            stream = []
            for _ in range(self.rng.randint(1, 12)):
                if self.rng.random() < 0.5:
                    stream += proto.build_fragments(random_message(self.rng),
                                                    self.rng.randint(4, 64))
                else:
                    stream.append(random_bytes(self.rng, 30))
            self.rng.shuffle(stream) if self.rng.random() < 0.3 else None
            try:
                for fragment in stream:
                    message = reassembler.feed(fragment)
                    if message is not None:
                        self.assertIsInstance(message, MESSAGE_TYPES)
            except Exception:
                self.fail_case(stream)

    def test_fragmenter_matches_app(self):
        for _ in range(ITERATIONS):
            length = self.rng.choice([self.rng.randint(1, 600), self.rng.randint(1, 4000)])
            if self.rng.random() < 0.01:
                length = self.rng.randint(65530, 70000)  # 16-bit wrap of `remaining`
            payload = random_bytes(self.rng, 0) + bytes(self.rng.getrandbits(8)
                                                        for _ in range(length))
            mtu = self.rng.randint(4, 600)
            fragments = proto.build_fragments(payload, mtu)
            if fragments != app_fragments(mtu, payload):
                self.fail_case((mtu, payload))
            self.assertTrue(all(len(f) <= mtu for f in fragments))
            self.assertEqual(b"".join(f[3:] for f in fragments), payload)

    def test_topic_roundtrip_through_fragments(self):
        for _ in range(ITERATIONS):
            topic = self.rng.choice([self.rng.randrange(0x10000), self.rng.choice(KNOWN_TOPICS)])
            value = random_value(self.rng)
            mtu = self.rng.randint(4, 300)
            reassembler = proto.FragmentReassembler()
            results = [reassembler.feed(f) for f in
                       proto.build_fragments(proto.build_topic_write(topic, value), mtu)]
            message = results[-1]
            if (any(r is not None for r in results[:-1])
                    or not isinstance(message, proto.TopicMessage)
                    or message.topic != topic or not values_equal(message.value, value)):
                self.fail_case((topic, value, mtu))

    def test_describe_never_raises(self):
        topics = KNOWN_TOPICS + [0, 0xFFFF, 0x1234]
        for _ in range(ITERATIONS * 2):
            topic = self.rng.choice(topics)
            value = random_value(self.rng, exotic=True)
            try:
                self.assertIsInstance(proto.describe_topic_value(topic, value), str)
                proto.is_locked(value)
                proto.decode_distance_km(value)
            except Exception:
                self.fail_case((topic, value))

    def test_subscribe_roundtrip(self):
        for _ in range(ITERATIONS):
            topics = [self.rng.randrange(0x10000) for _ in range(self.rng.randint(0, 120))]
            for build, control in ((proto.build_subscribe_message, 0xE001),
                                   (proto.build_unsubscribe_message, 0xE002)):
                message = build(topics)
                self.assertEqual(message[0], proto.PayloadType.SUBSCRIBE)
                self.assertEqual(int.from_bytes(message[1:3], "big"), control)
                parsed = [int.from_bytes(message[i:i + 2], "big")
                          for i in range(3, len(message), 2)]
                self.assertEqual(parsed, topics)


def app_s6_fragments(message, max_write, frag_id):
    """Transliteration of the official app's S6 fragmenter (cg.r.c)."""
    chunk = max_write - 3
    out = []
    for index, start in enumerate(range(0, len(message), chunk)):
        remaining = (len(message) - index * chunk) & 0xFFFF
        out.append(bytes([(0x80 if index == 0 else 0) | frag_id])
                   + bytes([(remaining >> 8) & 0xFF, remaining & 0xFF])
                   + message[start:start + chunk])
    return out


class S6ProtocolFuzzTests(unittest.TestCase):

    def setUp(self):
        self.rng = random.Random(SEED)

    def fail_case(self, data):
        self.fail("seed=%#x input=%r" % (SEED, data))

    def test_parse_message_never_raises(self):
        topics = list(s6.Topic) + [0, 0xFFFF]
        for _ in range(ITERATIONS * 2):
            if self.rng.random() < 0.5:
                topic = self.rng.choice(topics)
                payload = s6.encode_value([random_value(self.rng, exotic=True)])
                data = s6.build_message(s6.Message(
                    self.rng.randrange(8), topic, payload,
                    id=self.rng.randrange(256)))
                if self.rng.random() < 0.3:  # corrupt it
                    data = mutate(self.rng, data)
            else:
                data = random_bytes(self.rng, 64)
            try:
                message = s6.parse_message(data)
                if message is not None:
                    s6.decode_payload(message.payload)
                    s6.describe_value(message.topic, s6.decode_payload(message.payload))
                    s6.parse_auth_reply(message.payload)
            except Exception:
                self.fail_case(data)

    def test_fragmenter_matches_app(self):
        for _ in range(ITERATIONS):
            length = self.rng.randint(1, 4000)
            message = bytes(self.rng.getrandbits(8) for _ in range(length))
            max_write = self.rng.randint(4, 300)
            frag_id = self.rng.randint(1, 127)
            frags = s6.build_fragments(message, max_write, frag_id)
            if frags != app_s6_fragments(message, max_write, frag_id):
                self.fail_case((max_write, frag_id, length))
            self.assertTrue(all(len(f) <= max_write for f in frags))
            self.assertEqual(b"".join(f[3:] for f in frags), message)

    def test_message_roundtrip(self):
        for _ in range(ITERATIONS):
            original = s6.Message(
                self.rng.randrange(8), self.rng.randrange(0x10000),
                random_bytes(self.rng, 300), id=self.rng.randrange(256),
                qos=self.rng.randrange(2), retain=self.rng.randrange(4))
            data = s6.build_message(original)
            if s6.parse_message(data) != original:
                self.fail_case(original)
            # and through the fragment layer
            r = s6.FragmentReassembler()
            raw = [r.feed(f) for f in
                   s6.build_fragments(data, self.rng.randint(4, 300),
                                      self.rng.randint(1, 127))][-1]
            if raw != data:
                self.fail_case(original)

    def test_reassembler_never_raises(self):
        for _ in range(ITERATIONS):
            r = s6.FragmentReassembler()
            stream = []
            for _ in range(self.rng.randint(1, 10)):
                if self.rng.random() < 0.5:
                    msg = s6.build_message(s6.Message(
                        1, self.rng.randrange(0x10000), random_bytes(self.rng, 40)))
                    stream += s6.build_fragments(msg, self.rng.randint(4, 64),
                                                 self.rng.randint(1, 127))
                else:
                    stream.append(random_bytes(self.rng, 30))
            try:
                for fragment in stream:
                    raw = r.feed(fragment)
                    if raw is not None:
                        s6.parse_message(raw)
            except Exception:
                self.fail_case(stream)


class CredentialsFuzzTests(unittest.TestCase):
    """--privkey / --cert are user input: bad values must exit cleanly."""

    def test_load_credentials_never_crashes(self):
        import base64
        from utils.credentials_utils import Credentials, load_credentials
        rng = random.Random(SEED)
        good = make_credentials()
        good_key = base64.b64encode(good.private_key.private_bytes_raw()
                                    if hasattr(good.private_key, "private_bytes_raw")
                                    else bytes(32)).decode()
        for _ in range(ITERATIONS):
            certificate = mutate(rng, good.cert_data) if rng.random() < 0.7 \
                else random_bytes(rng, 200)
            cert_b64 = base64.b64encode(certificate).decode()
            key_b64 = good_key if rng.random() < 0.7 else base64.b64encode(
                random_bytes(rng, 70)).decode()
            if rng.random() < 0.1:
                cert_b64 = cert_b64[:rng.randrange(len(cert_b64) + 1)] + rng.choice("!=@ ")
            if rng.random() < 0.1:
                payload = dict(cbor2.loads(good.cert_cbor_only))
                payload[rng.choice("iferpu")] = random_value(rng, exotic=True)
                cert_b64 = base64.b64encode(good.ca_signature + cbor2.dumps(payload)).decode()
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    creds = load_credentials(key_b64, cert_b64)
                self.assertIsInstance(creds, Credentials)
            except SystemExit:
                pass
            except Exception:
                self.fail("seed=%#x key=%r cert=%r" % (SEED, key_b64, cert_b64))


# --------------------------------------------------------------------------- #
# Client and REPL against the simulated bike
# --------------------------------------------------------------------------- #

COMMANDS = ["unlock", "lock", "arm", "disarm", "power", "lights", "region",
            "bellsound", "subscribe", "s5sub", "unsubscribe", "sensors",
            "modules", "status", "info", "battery", "services", "query",
            "topics", "decode", "errors", "error", "help", "quit", "q"]
ARGUMENTS = ["0", "1", "2", "3", "4", "5", "9", "-1", "0x6b", "0x006b", "107",
             "0x10000", "65535", "true", "false", "on", "off", "auto", "halo",
             "eu", "us", "jp", "offroad", "de", "ping", "vanmoof", "ding_dong",
             "ship_horn", "all", "status", "telemetry", "modules", "lock",
             "power", "level", "lights", "region", "boost", "battery", "nope",
             "²", "٣", "0x", "🚲", "8100040100181826", "81 00 04", "zz", "1e3",
             "1_0", "0b101", "0o17"]


def random_command(rng, commands):
    if rng.random() < 0.1:
        return random_text(rng, 30)
    words = [rng.choice(commands)]
    for _ in range(rng.choice([0, 1, 1, 1, 2, 3])):
        words.append(rng.choice(ARGUMENTS) if rng.random() < 0.8 else random_text(rng, 8))
    return " ".join(words).strip().lower()


class ClientFuzzTests(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.rng = random.Random(SEED)
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        for patch in (mock.patch.object(main, "BleakClient", FakeBleakClient),
                      mock.patch("asyncio.sleep", _fast_sleep)):
            patch.start()
            self.addCleanup(patch.stop)
        fail_on_loop_errors(self)
        self.creds = make_credentials()

    is_s6 = False

    async def connect(self, authenticate=True):
        if self.is_s6:
            self.bike = FakeS6Bike(mtu=self.rng.choice([32, 64, 247]))
        else:
            self.bike = FakeBike(mtu=self.rng.choice([23, 64, 247]))
        FakeBleakClient.bike = self.bike
        client = main.VanMoofClient(self.creds)
        client.REPLY_TIMEOUT = 0.05
        client.AUTH_TIMEOUT = 0.2
        self.assertTrue(await client.connect("AA:BB:CC:DD:EE:FF"))
        if authenticate:
            self.assertTrue(await client.authenticate())
            if not self.is_s6:
                await client.subscribe(proto.STATUS_TOPICS)
        return client

    async def test_notifications_never_raise(self):
        client = await self.connect()
        for i in range(ITERATIONS * 2):
            if i % 50 == 0:
                await _real_sleep(0)  # let the loop breathe between bursts
            if self.rng.random() < 0.5 and not self.is_s6:
                fragments = proto.build_fragments(random_message(self.rng),
                                                  self.rng.randint(4, 64))
            elif self.rng.random() < 0.5:
                msg = s6.build_message(s6.Message(
                    self.rng.randrange(8), self.rng.randrange(0x10000),
                    s6.encode_value([random_value(self.rng, exotic=True)]),
                    id=self.rng.randrange(256)))
                fragments = s6.build_fragments(msg, self.rng.randint(4, 64),
                                               self.rng.randint(1, 127))
            else:
                fragments = [random_bytes(self.rng, 40)]
            try:
                for fragment in fragments:
                    client._on_notify(None, bytearray(fragment))
            except Exception:
                self.fail("seed=%#x s6=%s fragments=%r" % (SEED, self.is_s6, fragments))
        # The client still works afterwards.
        client.reassembler.reset()
        client.s6_reassembler.reset()
        await main.handle_command("lights off", client)
        topic = s6.Topic.LIGHT_MODE if self.is_s6 else Topic.LIGHT_MODE
        self.assertEqual(s6.first_field(self.bike.state[topic]), 0 if self.is_s6 else 2)

    async def test_authentication_with_noise(self):
        for _ in range(max(10, ITERATIONS // 25)):
            client = await self.connect(authenticate=False)
            send = self.bike.send

            def noisy_send(*args, send=send):
                if self.rng.random() < 0.3:
                    client._on_notify(None, bytearray(random_bytes(self.rng, 30)))
                send(*args)
            self.bike.send = noisy_send
            result = await client.authenticate()
            self.assertIsInstance(result, bool)

    async def _run_commands(self, commands, iterations):
        client = await self.connect()
        for _ in range(iterations):
            cmd = random_command(self.rng, commands)
            if cmd.split()[:1] == ["monitor"]:
                continue
            try:
                result = await main.handle_command(cmd, client)
            except Exception:
                self.fail("seed=%#x command=%r" % (SEED, cmd))
            self.assertIsInstance(result, bool)
        return client

    async def test_repl_commands(self):
        client = await self._run_commands(COMMANDS, ITERATIONS)
        # Without raw/write, nothing the REPL sends may violate the protocol.
        self.assertEqual(self.bike.violations, [])
        self.assertTrue(client.connected)

    async def test_repl_raw_and_write(self):
        await self._run_commands(COMMANDS + ["raw", "write", "write", "raw"],
                                 ITERATIONS // 2)


class S6ClientFuzzTests(ClientFuzzTests):
    """Run the client / REPL fuzzers against a simulated S6."""

    is_s6 = True

    async def test_repl_commands(self):
        client = await self._run_commands(COMMANDS, ITERATIONS)
        self.assertEqual(self.bike.violations, [])
        self.assertTrue(client.connected)


if __name__ == "__main__":
    unittest.main()
