"""Unit tests for utils.s6_protocol: CRC, messages, fragments, auth, values."""

import unittest

import cbor2

from utils import s6_protocol as s6
from utils.s6_protocol import MessageType, Topic


class CrcTests(unittest.TestCase):

    def test_check_value(self):
        self.assertEqual(s6.crc16_modbus(b"123456789"), 0x4B37)

    def test_empty(self):
        self.assertEqual(s6.crc16_modbus(b""), 0xFFFF)


class MessageTests(unittest.TestCase):

    def test_build_header_and_crc(self):
        # Captured certificate message: 71 0D 00FF AE00 <payload> <crc>.
        payload = s6.build_certificate_payload(bytes(range(169)))
        message = s6.build_message(s6.Message(MessageType.SET, Topic.AUTH, payload, id=0x71))
        self.assertEqual(message[:6], bytes.fromhex("710d00ffae00"))
        self.assertEqual(message[-2:],
                         s6.crc16_modbus(message[:-2]).to_bytes(2, "little"))

    def test_type_flags(self):
        for mtype, flags in ((MessageType.SET, 0x0D), (MessageType.GET, 0x0C),
                             (MessageType.PUBLISH, 0x09), (MessageType.SUBSCRIBE, 0x0A)):
            message = s6.build_message(s6.Message(mtype, 0x0110))
            self.assertEqual(message[1], flags)

    def test_topic_and_length_little_endian(self):
        message = s6.build_message(s6.Message(MessageType.SET, 0x022D, b"\xaa\xbb"))
        self.assertEqual(message[2:4], bytes.fromhex("2d02"))
        self.assertEqual(message[4:6], bytes.fromhex("0200"))

    def test_roundtrip(self):
        original = s6.Message(MessageType.SET, 0x0131, b"\x81\x43\x82\x02\x01",
                              id=42, qos=1, retain=0)
        self.assertEqual(s6.parse_message(s6.build_message(original)), original)

    def test_parse_rejects_bad_crc(self):
        message = bytearray(s6.build_message(s6.Message(MessageType.GET, 0x0110)))
        message[-1] ^= 0xFF
        self.assertIsNone(s6.parse_message(bytes(message)))

    def test_parse_rejects_truncated(self):
        message = s6.build_message(s6.Message(MessageType.SET, 0x0110, b"\x01\x02\x03"))
        self.assertIsNone(s6.parse_message(message[:-1]))
        self.assertIsNone(s6.parse_message(message[:7]))
        self.assertIsNone(s6.parse_message(b""))

    def test_counters_wrap(self):
        msg = s6.message_counter()
        values = [msg.next() for _ in range(258)]
        self.assertEqual(values[:3], [0, 1, 2])
        self.assertEqual(values[255:258], [255, 0, 1])
        frag = s6.fragment_counter()
        values = [frag.next() for _ in range(130)]
        self.assertEqual(values[:3], [0, 1, 2])
        self.assertEqual(values[127:130], [127, 1, 2])


class FragmentTests(unittest.TestCase):

    def test_single_fragment(self):
        payload = s6.build_certificate_payload(bytes(range(169)))
        message = s6.build_message(s6.Message(MessageType.SET, Topic.AUTH, payload, id=5))
        frags = s6.build_fragments(message, 244, 5)
        self.assertEqual(len(frags), 1)
        self.assertEqual(frags[0][:3], bytes([0x85]) + len(message).to_bytes(2, "big"))

    def test_multi_fragment_big_endian_remaining(self):
        message = bytes(range(80))
        frags = s6.build_fragments(message, 20, 3)
        self.assertEqual([f[0] for f in frags], [0x83, 0x03, 0x03, 0x03, 0x03])
        self.assertEqual(int.from_bytes(frags[0][1:3], "big"), 80)
        self.assertEqual(int.from_bytes(frags[1][1:3], "big"), 80 - 17)
        self.assertEqual(b"".join(f[3:] for f in frags), message)
        self.assertTrue(all(len(f) <= 20 for f in frags))

    def test_reassemble(self):
        message = s6.build_message(s6.Message(MessageType.SET, Topic.AUTH,
                                              s6.build_certificate_payload(bytes(169))))
        frags = s6.build_fragments(message, 20, 7)
        r = s6.FragmentReassembler()
        results = [r.feed(f) for f in frags]
        self.assertTrue(all(x is None for x in results[:-1]))
        self.assertEqual(results[-1], message)

    def test_reassemble_single(self):
        message = s6.build_message(s6.Message(MessageType.PUBLISH, Topic.LOCK_STATE,
                                              s6.wrap_payload(cbor2.dumps(0))))
        frag = s6.build_fragments(message, 244, 1)[0]
        self.assertEqual(s6.FragmentReassembler().feed(frag), message)

    def test_reassemble_ignores_short(self):
        self.assertIsNone(s6.FragmentReassembler().feed(b"\x80\x00"))

    def test_reassemble_continuation_without_first(self):
        self.assertIsNone(s6.FragmentReassembler().feed(bytes([0x01, 0x00, 0x05, 1, 2])))


class AuthTests(unittest.TestCase):

    def test_certificate_wrapping(self):
        # 81 58AB 58A9 <169-byte cert>.
        payload = s6.build_certificate_payload(bytes(range(169)))
        self.assertEqual(payload[:5], bytes.fromhex("8158ab58a9"))
        self.assertEqual(len(payload), 174)

    def test_signature_wrapping(self):
        # 81 5842 5840 <64-byte sig>.
        payload = s6.build_signature_payload(bytes(64))
        self.assertEqual(payload[:5], bytes.fromhex("8158425840"))
        self.assertEqual(len(payload), 69)

    def test_sign_challenge(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat)
        key = Ed25519PrivateKey.generate()
        seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        challenge = bytes(range(16))
        for private in (key, seed, seed + public):
            payload = s6.sign_challenge(challenge, private)
            outer = cbor2.loads(payload)
            signature = cbor2.loads(outer[0])
            key.public_key().verify(signature, challenge)

    def test_parse_challenge(self):
        # Captured: 9F 54 [9F 01 50 <16> FF] FF.
        challenge = bytes(range(16))
        inner = b"\x9f\x01\x50" + challenge + b"\xff"
        reply = s6.parse_auth_reply(b"\x9f\x54" + inner + b"\xff")
        self.assertEqual(reply.status, 1)
        self.assertEqual(reply.challenge, challenge)
        self.assertFalse(reply.authenticated)
        self.assertFalse(reply.rejected)

    def test_parse_success(self):
        reply = s6.parse_auth_reply(bytes.fromhex("9f439f02ffff"))
        self.assertTrue(reply.authenticated)
        self.assertFalse(reply.rejected)

    def test_parse_rejection(self):
        reply = s6.parse_auth_reply(bytes.fromhex("9f439f20ffff"))  # int -1
        self.assertTrue(reply.rejected)
        self.assertFalse(reply.authenticated)

    def test_parse_non_auth(self):
        self.assertIsNone(s6.parse_auth_reply(s6.wrap_payload(cbor2.dumps("x"))))
        self.assertIsNone(s6.parse_auth_reply(b""))
        # a bad challenge length is not a valid reply
        inner = b"\x9f\x01\x43abc\xff"
        self.assertIsNone(s6.parse_auth_reply(b"\x9f\x43" + inner + b"\xff"))


class ValueTests(unittest.TestCase):

    def test_encode_value(self):
        self.assertEqual(s6.encode_value([1]), bytes.fromhex("81428101"))
        self.assertEqual(s6.encode_value([2, 1]), bytes.fromhex("8143820201"))

    def test_decode_payload(self):
        self.assertEqual(s6.decode_payload(bytes.fromhex("9f439f00ffff")), [0])
        self.assertEqual(s6.decode_payload(s6.encode_value([2, 1])), [2, 1])
        self.assertIsNone(s6.decode_payload(b""))
        self.assertIsNone(s6.decode_payload(b"\x58\xff"))  # bytestring says 255 bytes, none follow

    def test_first_field(self):
        self.assertEqual(s6.first_field([5]), 5)
        self.assertEqual(s6.first_field([2, 1]), 2)
        self.assertIsNone(s6.first_field([]))
        self.assertEqual(s6.first_field(7), 7)

    def test_describe(self):
        cases = [
            (Topic.LOCK_STATE, [0], "unlocked"),
            (Topic.LOCK_STATE, [1], "locked"),
            (Topic.LIGHT_MODE, [2, 1], "on"),
            (Topic.LIGHT_MODE, [0, 1], "off"),
            (Topic.ALARM, [1], "on"),
            (Topic.ALARM_SENSITIVITY, [4], "low"),
            (Topic.BELL_SOUND, [2], "ding_dong"),
            (Topic.BATTERY_LEVEL, [64], "64%"),
            (Topic.CHARGE_LIMIT, [90], "90%"),
            (Topic.ASSIST_LEVEL, [0], "0 (off)"),
            (Topic.ASSIST_LEVEL, [3], "3"),
            (Topic.FIRMWARE, ["1.8.8"], "1.8.8"),
            (Topic.DISTANCE, [123456], "123456"),
            (0x9999, [1, 2, 3], "[1, 2, 3]"),
        ]
        for topic, value, expected in cases:
            with self.subTest(topic=topic, value=value):
                self.assertEqual(s6.describe_value(topic, value), expected)

    def test_dtc_detection(self):
        self.assertTrue(s6.is_dtc(0x9053))   # class 0x90
        self.assertTrue(s6.is_dtc(0xA4FF))   # class 0xA4 battery
        self.assertTrue(s6.is_dtc(0xC100))   # class 0xC1 elock
        for not_dtc in (0, 22, 0x0016, 0x0100, 0xB000, True, "0x9053", None, 1.0):
            self.assertFalse(s6.is_dtc(not_dtc))

    def test_dtc_describe(self):
        self.assertEqual(
            s6.describe_dtc(0x9053),
            "power/battery supervisor DTC 0x9053: "
            "low-battery shutdown (RSOC < 11% or VBAT < 3401 mV)")
        self.assertEqual(s6.describe_dtc(0x9050),
                         "power/battery supervisor DTC 0x9050: "
                         "lipo RSOC (fuel-gauge state-of-charge) read failed")
        self.assertEqual(s6.describe_dtc(0xA4FF), "battery DTC 0xA4FF")
        self.assertEqual(s6.describe_dtc(0xC100), "elock DTC 0xC100")
        self.assertIsNone(s6.describe_dtc(0x1234))
        self.assertIsNone(s6.describe_dtc(22))

    def test_dtc_on_errors_topic(self):
        self.assertEqual(s6.describe_value(Topic.ERRORS, [0x9052]),
                         "power/battery supervisor DTC 0x9052: "
                         "lipo VBAT (pack voltage) read failed")
        self.assertEqual(s6.describe_value(Topic.ERRORS, [0xA701]), "charger DTC 0xA701")

    def test_topic_names(self):
        self.assertEqual(s6.topic_name(Topic.LOCK_STATE), "lock_state")
        self.assertEqual(s6.topic_name(0x1234), "topic_0x1234")

    def test_light_mode_values_match_app(self):
        self.assertEqual(s6.LIGHT_MODE_VALUES, {"off": 0, "on": 2, "auto": 3})

    def test_selftest(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            s6._selftest()


if __name__ == "__main__":
    unittest.main()
