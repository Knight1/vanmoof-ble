"""Unit tests for utils.protocol_codes: framing, parsing, builders, tables."""

import unittest

import cbor2

from utils import protocol_codes as proto
from utils.protocol_codes import PayloadType, Topic


class FragmentTests(unittest.TestCase):

    def test_single_fragment_header(self):
        payload = bytes.fromhex("0100181826")
        self.assertEqual(proto.build_fragments(payload),
                         [bytes.fromhex("810004") + payload])

    def test_multi_fragment_layout_matches_app(self):
        # The app's fragmenter: chunk = mtu - 3, header (first?0x80:0)|1,
        # remaining = len - chunk*idx - (1 if first else 0).
        payload = bytes(range(50))
        frags = proto.build_fragments(payload, max_write=20)
        self.assertEqual([f[:3].hex() for f in frags], ["810031", "010021", "010010"])
        self.assertEqual(b"".join(f[3:] for f in frags), payload)
        self.assertTrue(all(len(f) <= 20 for f in frags))

    def test_exact_chunk_boundary(self):
        payload = bytes(34)  # exactly two chunks at mtu 20
        frags = proto.build_fragments(payload, max_write=20)
        self.assertEqual(len(frags), 2)
        self.assertEqual(frags[1][:3], bytes([0x01, 0x00, 34 - 17]))

    def test_empty_payload_has_no_fragments(self):
        self.assertEqual(proto.build_fragments(b""), [])

    def test_parse_fragment(self):
        frag = proto.parse_fragment(bytes.fromhex("81000d05bf63656e63f46461757468f4ff"))
        self.assertTrue(frag.is_first)
        self.assertEqual((frag.seq_id, frag.total_len), (1, 13))
        self.assertEqual(frag.payload[0], PayloadType.AUTH_DETAILS)


class ReassemblerTests(unittest.TestCase):

    def test_single_fragment_message(self):
        msg = proto.FragmentReassembler().feed(bytes.fromhex("8100040100181826"))
        self.assertEqual(msg, proto.TopicMessage(24, "power/battery/primary/info/soc_app", 38))

    def test_multi_fragment_message(self):
        value = {"version": "1.5.0", "build": "x" * 60}
        frags = proto.build_fragments(proto.build_topic_write(Topic.FW_INFO, value), max_write=20)
        r = proto.FragmentReassembler()
        results = [r.feed(f) for f in frags]
        self.assertGreater(len(frags), 3)
        self.assertTrue(all(m is None for m in results[:-1]))
        self.assertEqual(results[-1].value, value)

    def test_new_first_fragment_restarts(self):
        r = proto.FragmentReassembler()
        partial = proto.build_fragments(proto.build_topic_write(1, "y" * 40), max_write=20)[0]
        self.assertIsNone(r.feed(partial))
        self.assertEqual(r.feed(bytes.fromhex("8100040100181826")).value, 38)

    def test_continuation_without_first_is_dropped(self):
        r = proto.FragmentReassembler()
        self.assertIsNone(r.feed(bytes.fromhex("0100040100181826")))
        self.assertEqual(r.feed(bytes.fromhex("8100040100181826")).value, 38)

    def test_short_notification_is_ignored(self):
        self.assertIsNone(proto.FragmentReassembler().feed(b"\x81\x00"))


class ParseMessageTests(unittest.TestCase):
    """Vectors from the community clients' unit tests."""

    def test_battery(self):
        m = proto.parse_message(bytes.fromhex("0100181826"))
        self.assertEqual((m.topic, m.value), (24, 38))

    def test_distance(self):
        m = proto.parse_message(bytes.fromhex("0100a51a000f770a"))
        self.assertEqual((m.topic, m.value), (165, 1013514))

    def test_topic_without_value(self):
        m = proto.parse_message(bytes.fromhex("0100a5"))
        self.assertEqual((m.topic, m.value), (165, None))

    def test_truncated_topic(self):
        self.assertIsNone(proto.parse_message(bytes.fromhex("0100")))

    def test_auth_details(self):
        m = proto.parse_message(bytes.fromhex("05bf63656e63f56461757468f4ff"))
        self.assertEqual(m, proto.AuthMessage(authenticated=False, encrypted=True))
        m = proto.parse_message(bytes.fromhex("05bf63656e63f56461757468f5ff"))
        self.assertTrue(m.authenticated)

    def test_auth_details_garbage(self):
        self.assertEqual(proto.parse_message(b"\x05\xff\xff"),
                         proto.AuthMessage(authenticated=False, encrypted=False))

    def test_challenge(self):
        nonce = bytes.fromhex("4ad328f79cdc0011203c84968822597f")
        self.assertEqual(proto.parse_message(b"\x04" + nonce), proto.ChallengeMessage(nonce))

    def test_param_update(self):
        m = proto.parse_message(bytes.fromhex(
            "07bf676c6174656e6379006774696d656f7574181968696e74657276616c0cff"))
        self.assertEqual(m.data, {"latency": 0, "timeout": 25, "interval": 12})

    def test_mtu_update(self):
        m = proto.parse_message(b"\x06" + cbor2.dumps({"tx_max_len": 251}))
        self.assertIsInstance(m, proto.MtuMessage)
        self.assertEqual(m.data, {"tx_max_len": 251})

    def test_client_only_and_unknown_types(self):
        for payload_type in (PayloadType.SUBSCRIBE, PayloadType.AUTH_CERT, 0, 8, 0x30, 0xFF):
            self.assertIsNone(proto.parse_message(bytes([payload_type, 0xE0, 0x01])))
        self.assertIsNone(proto.parse_message(b""))

    def test_trailing_bytes_after_cbor(self):
        m = proto.parse_message(bytes.fromhex("010018182600ff"))
        self.assertEqual(m.value, 38)


class BuilderTests(unittest.TestCase):
    """Messages byte-for-byte as the official app builds them."""

    def test_unlock(self):
        self.assertEqual(proto.build_fragments(proto.build_topic_write(Topic.UNLOCK, 1)),
                         [bytes.fromhex("8100030100a001")])

    def test_settings(self):
        cases = [
            (Topic.LIGHT_MODE_SET, proto.LIGHT_MODE_VALUES["on"], "01006b01"),
            (Topic.LIGHT_MODE_SET, proto.LIGHT_MODE_VALUES["off"], "01006b02"),
            (Topic.LIGHT_MODE_SET, proto.LIGHT_MODE_VALUES["auto"], "01006b03"),
            (Topic.ASSIST_LEVEL_SET, 4, "01006704"),
            (Topic.ALARM_SET, True, "01006ff5"),
            (Topic.ALARM_SET, False, "01006ff4"),
            (Topic.REGION_SET, proto.REGION_VALUES["jp"], "01006202"),
            (Topic.REGION_SET, proto.REGION_VALUES["offroad"], "01006203"),
            (Topic.BELL_SOUND_SET, proto.BELL_SOUND_VALUES["vanmoof"], "01007303"),
        ]
        for topic, value, expected in cases:
            with self.subTest(topic=topic, value=value):
                self.assertEqual(proto.build_topic_write(topic, value).hex(), expected)

    def test_subscribe_and_unsubscribe(self):
        self.assertEqual(proto.build_subscribe_message([Topic.BATTERY_LEVEL, Topic.LOCK_STATE]),
                         bytes.fromhex("02e001001800a1"))
        self.assertEqual(proto.build_unsubscribe_message([0x35, 0x3E]),
                         bytes.fromhex("02e0020035003e"))
        self.assertEqual(proto.build_subscribe_message([]), bytes.fromhex("02e001"))

    def test_certificate_message(self):
        self.assertEqual(proto.build_certificate_message(b"\xde\xad"), b"\x03\xde\xad")
        self.assertEqual(proto.b64_certificate_message("3q0="), b"\x03\xde\xad")

    def test_sign_challenge(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat)
        key = Ed25519PrivateKey.generate()
        seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        nonce = bytes(range(16))
        for private in (key, seed, seed + public):
            message = proto.sign_challenge(nonce, private)
            self.assertEqual((message[0], len(message)), (PayloadType.AUTH_CHALLENGE, 65))
            key.public_key().verify(message[1:], nonce)


class TableTests(unittest.TestCase):

    def test_power_states(self):
        self.assertEqual(proto.power_state_name(3), "operational")
        self.assertEqual(proto.power_state_name(4), "charging")
        self.assertIsNone(proto.power_state_name(99))

    def test_lock_states(self):
        self.assertIs(proto.is_locked(1), True)
        for unlocked in (3, 5):
            self.assertIs(proto.is_locked(unlocked), False)
        for unknown in (0, 2, 4, True, None, "1", 1.0):
            self.assertIsNone(proto.is_locked(unknown))

    def test_light_modes_match_app_encoder(self):
        # hm.p ordinals AUTO=0, ALWAYS_ON=1, OFF=2 are sent as 3, 1, 2.
        self.assertEqual(proto.LIGHT_MODE_VALUES, {"on": 1, "off": 2, "auto": 3})

    def test_regions_and_bells(self):
        self.assertEqual(proto.decode_region(3), "offroad")
        self.assertEqual(proto.bell_name(0), "ding_dong")
        self.assertEqual(proto.bell_name(4), "ship_horn")
        self.assertIsNone(proto.bell_name(5))

    def test_distance(self):
        self.assertEqual(proto.decode_distance_km(1013514), 10135.1)
        self.assertIsNone(proto.decode_distance_km("12"))
        self.assertIsNone(proto.decode_distance_km(True))

    def test_describe(self):
        cases = [
            (Topic.POWER_STATE, 2, "standby"),
            (Topic.LOCK_STATE, 1, "locked"),
            (Topic.LIGHT_MODE, 2, "off"),
            (Topic.LIGHT_MODE_SET, 3, "auto"),
            (Topic.REGION, 1, "US (32 km/h)"),
            (Topic.BELL_SOUND, 2, "2 (ping)"),
            (Topic.ALARM, True, "enabled"),
            (Topic.ASSIST_LEVEL, 0, "0 (off)"),
            (Topic.ASSIST_LEVEL, 3, "3"),
            (Topic.DISTANCE, 1013514, "10135.1 km"),
            (Topic.BATTERY_LEVEL, 38, "38%"),
            (Topic.ALARM_STATE, 3, "theft"),
            (Topic.FIND_MY, b"\x01\x02", "0102"),
            (0x0035, "ok", "ok"),
            (0x1234, [1, 2], "[1, 2]"),
            (Topic.LIGHT_MODE, 0, "0"),
        ]
        for topic, value, expected in cases:
            with self.subTest(topic=topic, value=value):
                self.assertEqual(proto.describe_topic_value(topic, value), expected)

    def test_topic_names(self):
        self.assertEqual(proto.topic_name(Topic.BATTERY_LEVEL), "power/battery/primary/info/soc_app")
        self.assertEqual(proto.topic_name(0x003E), "device/user_ecu/status")
        self.assertEqual(proto.topic_name(0xBEEF), "topic_0xBEEF")
        for topic in Topic:
            self.assertIn(topic, proto.TOPIC_NAMES)

    def test_topic_sets(self):
        self.assertEqual(proto.HEARTBEAT_TOPICS, list(range(0x30, 0x3F)))
        self.assertEqual(len(set(proto.ALL_TOPICS)), len(proto.ALL_TOPICS))
        self.assertNotIn(Topic.UNLOCK, proto.ALL_TOPICS)
        self.assertTrue(all(0 <= t <= 0xFFFF for t in proto.ALL_TOPICS))

    def test_selftest(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            proto._selftest()


if __name__ == "__main__":
    unittest.main()
