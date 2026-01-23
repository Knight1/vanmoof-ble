"""
VanMoof S5/A5 BLE cryptographic utilities

Provides functions for key loading and challenge signing.

Functions:
    load_private_key(privkey_b64): Load Ed25519 private key
    build_challenge_response(creds, challenge): Sign challenge
"""
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def load_private_key(privkey_b64: str) -> Ed25519PrivateKey:
    """Load Ed25519 private key (handles 32 or 64 byte formats)"""
    raw = base64.b64decode(privkey_b64)
    seed = raw[:32]  # First 32 bytes is the seed
    return Ed25519PrivateKey.from_private_bytes(seed)

def build_challenge_response(creds, challenge: bytes, first_byte: int = 0x81) -> bytes:
    """Sign the challenge with our private key"""
    signature = creds.private_key.sign(challenge)
    packet = bytearray([first_byte, 0x00, 0x40, 0x04])
    packet.extend(signature)
    return bytes(packet)
