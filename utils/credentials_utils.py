"""
VanMoof S5/A5/S6 BLE credentials utilities

Loads and validates credentials from base64-encoded strings.

The certificate from the API is structured as:
    [64-byte CA Signature] [CBOR Payload]

The CBOR payload contains:
    i  - Certificate ID (uint32)
    f  - Frame number (string)
    b  - Bike serial (string)
    e  - Expiry timestamp (uint32, Unix epoch)
    r  - Role (uint8, 7=owner, 11=shared bike; see protocol_codes.ROLE_NAMES)
    u  - User UUID (16 bytes)
    p  - Ed25519 public key (32 bytes)

Functions:
    load_credentials(privkey_b64, cert_b64): Load and validate credentials
"""

import base64
import binascii
import sys
import datetime

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dataclasses import dataclass

from utils.protocol_codes import ROLE_NAMES


@dataclass
class Credentials:
    """Holds all credentials needed for BLE authentication."""
    private_key: Ed25519PrivateKey
    public_key: bytes       # 32-byte Ed25519 public key
    ca_signature: bytes     # 64-byte CA signature from certificate
    cert_data: bytes        # Full certificate (CA signature + CBOR payload)
    cert_cbor_only: bytes   # CBOR payload only (without CA signature)
    cert_id: int = None
    frame: str = None
    expiry: int = None
    role: int = None
    user_id: bytes = None


def load_credentials(privkey_b64: str, cert_b64: str) -> Credentials:
    """
    Load credentials from base64 strings.

    Args:
        privkey_b64: Base64-encoded Ed25519 private key (32 or 64 bytes)
        cert_b64:    Base64-encoded certificate (CA signature + CBOR)

    Returns:
        Credentials dataclass with all parsed fields

    Raises:
        SystemExit: If the key or certificate is malformed, or the keys don't
            match (wrong private key for certificate)
    """
    # Load private key (handle both 32-byte seed and 64-byte expanded formats)
    try:
        raw_key = base64.b64decode(privkey_b64)
        private_key = Ed25519PrivateKey.from_private_bytes(raw_key[:32])
    except (binascii.Error, ValueError) as e:
        sys.exit(f"Invalid private key: {e}")
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Parse certificate: first 64 bytes = CA signature, rest = CBOR
    try:
        cert_raw = base64.b64decode(cert_b64)
        parsed = cbor2.loads(cert_raw[64:]) if len(cert_raw) > 64 else None
    except Exception as e:  # bad base64 or any CBOR decode error
        sys.exit(f"Invalid certificate: {e}")
    if not isinstance(parsed, dict):
        sys.exit("Invalid certificate: expected a 64-byte CA signature "
                 "followed by a CBOR map")
    for field in ("i", "e", "r"):
        value = parsed.get(field)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            sys.exit(f"Invalid certificate: field '{field}' is not an integer")
    try:
        if parsed.get("e"):
            datetime.datetime.fromtimestamp(parsed["e"], tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        sys.exit("Invalid certificate: expiry is out of range")
    ca_sig = cert_raw[:64]
    cbor_only = cert_raw[64:]

    creds = Credentials(
        private_key=private_key,
        public_key=public_key,
        ca_signature=ca_sig,
        cert_data=cert_raw,
        cert_cbor_only=cbor_only,
        cert_id=parsed.get("i"),
        frame=parsed.get("f"),
        expiry=parsed.get("e"),
        role=parsed.get("r"),
        user_id=parsed.get("u"),
    )

    # Display loaded credentials
    print("Credentials Loaded:")
    print(f"   Cert ID: {creds.cert_id}")
    print(f"   Frame:   {creds.frame}")
    print(f"   Role:    {creds.role} ({ROLE_NAMES.get(creds.role, 'unknown role')})")
    if creds.expiry:
        dt = datetime.datetime.fromtimestamp(creds.expiry, tz=datetime.timezone.utc)
        print(f"   Expiry:  {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    else:
        print("   Expiry:  (not present)")

    # Validate key consistency
    cert_pubkey = parsed.get("p")
    if cert_pubkey == public_key:
        print("   Keys match")
    else:
        print("   KEY MISMATCH - wrong private key for this certificate!")
        sys.exit(1)

    return creds
