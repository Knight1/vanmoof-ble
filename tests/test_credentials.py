"""Tests for utils.credentials_utils.load_credentials."""

import base64
import contextlib
import io
import os
import unittest

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)

from utils.credentials_utils import load_credentials


def _key():
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return seed, public


def _certificate(public, role=7):
    payload = {"i": 73519, "f": "SVTBKLTEST001", "b": "SVTBKLTEST001",
               "e": 1768908547, "r": role, "u": bytes(16), "p": public}
    return os.urandom(64) + cbor2.dumps(payload)


def _load(private, certificate):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        creds = load_credentials(base64.b64encode(private).decode(),
                                 base64.b64encode(certificate).decode())
    return creds, out.getvalue()


class CredentialsTests(unittest.TestCase):

    def test_fields(self):
        seed, public = _key()
        certificate = _certificate(public)
        creds, out = _load(seed, certificate)
        self.assertEqual(creds.cert_data, certificate)
        self.assertEqual(creds.ca_signature, certificate[:64])
        self.assertEqual(creds.cert_cbor_only, certificate[64:])
        self.assertEqual((creds.cert_id, creds.frame, creds.expiry, creds.role),
                         (73519, "SVTBKLTEST001", 1768908547, 7))
        self.assertEqual(creds.public_key, public)
        self.assertIn("Role:    7 (Owner)", out)
        self.assertIn("Keys match", out)

    def test_expanded_private_key(self):
        seed, public = _key()
        creds, _ = _load(seed + public, _certificate(public))
        self.assertEqual(creds.public_key, public)

    def test_role_names(self):
        seed, public = _key()
        for role, name in ((11, "Shared bike"), (66, "R&D engineer"), (3, "unknown role")):
            with self.subTest(role=role):
                _, out = _load(seed, _certificate(public, role))
                self.assertIn("(%s)" % name, out)

    def test_key_mismatch_exits(self):
        seed, _ = _key()
        _, other_public = _key()
        with self.assertRaises(SystemExit):
            _load(seed, _certificate(other_public))

    def test_malformed_input_exits_cleanly(self):
        seed, public = _key()
        good = _certificate(public)
        payload = cbor2.loads(good[64:])
        cases = {
            "short key": (seed[:12], good),
            "64-byte certificate": (seed, good[:64]),
            "CBOR is not a map": (seed, good[:64] + cbor2.dumps([1, 2])),
            "invalid CBOR": (seed, good[:64] + b"\xff\xff"),
            "expiry not an int": (seed, good[:64] + cbor2.dumps(dict(payload, e="soon"))),
            "expiry out of range": (seed, good[:64] + cbor2.dumps(dict(payload, e=10 ** 30))),
            "role not an int": (seed, good[:64] + cbor2.dumps(dict(payload, r=[7]))),
        }
        for name, (private, certificate) in cases.items():
            with self.subTest(name):
                with self.assertRaises(SystemExit):
                    _load(private, certificate)
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(io.StringIO()):
                load_credentials("not base64!", base64.b64encode(good).decode())


if __name__ == "__main__":
    unittest.main()
