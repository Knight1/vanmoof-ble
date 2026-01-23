"""
VanMoof S5/A5 BLE protocol utilities

Provides functions for building protocol headers and authentication packets.

Functions:
    build_tx_header(rx_header=None): Build TX header
    build_auth_packet(creds):        Build certificate authentication packet
"""

def build_tx_header(rx_header: bytes = None) -> bytes:
    """
    Build TX header based on RX header.
    Bike sends 80/81/82, we respond with 81.
    """
    return bytes([0x81, 0x00])

def build_auth_packet(creds) -> bytes:
    """
    Build the certificate authentication packet
    """
    packet = bytearray([0x81, 0x00, 0xA9, 0x03])
    packet.extend(creds.ca_signature)
    packet.extend(creds.cert_cbor)
    return bytes(packet)
