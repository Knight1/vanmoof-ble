"""
VanMoof S5/A5 BLE credentials utilities

Provides function to load credentials from base64 strings.

Functions:
    load_credentials(privkey_b64, cert_b64): Load credentials
"""
import base64
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dataclasses import dataclass
import sys

@dataclass
class Credentials:
    private_key: Ed25519PrivateKey
    public_key: bytes
    ca_signature: bytes
    cert_cbor: bytes
    cert_id: int = None
    frame: str = None
    expiry: int = None
    role: int = None

def load_credentials(privkey_b64: str, cert_b64: str) -> Credentials:
    """Load credentials from base64 strings"""
    private_key = base64.b64decode(privkey_b64)
    private_key = Ed25519PrivateKey.from_private_bytes(private_key[:32])
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    cert_raw = base64.b64decode(cert_b64)
    ca_sig = cert_raw[:64]
    cert_cbor = cert_raw[64:]
    parsed = cbor2.loads(cert_cbor)
    cert_pubkey = parsed.get("p")
    creds = Credentials(
        private_key=private_key,
        public_key=public_key,
        ca_signature=ca_sig,
        cert_cbor=cert_cbor,
        cert_id=parsed.get("i"),
        frame=parsed.get("f"),
        expiry=parsed.get("e"),
        role=parsed.get("r"),
    )
    print("📋 Credentials Loaded:")
    print(f"   Cert ID: {creds.cert_id}")
    print(f"   Frame:   {creds.frame}")
    print(f"   Role:    {creds.role} ({'Owner' if creds.role == 7 else 'User'})")
    if cert_pubkey == public_key:
        print("   ✅ Keys match!")
    else:
        print("   ❌ KEY MISMATCH - wrong private key!")
        sys.exit(1)
    return creds
