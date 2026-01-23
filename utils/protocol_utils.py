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
    Use same first byte as received (80/81/82).
    """
    if rx_header and len(rx_header) > 0:
        return bytes([rx_header[0], 0x00])
    return bytes([0x81, 0x00])

def build_auth_packet(creds, first_byte: int = 0x81) -> bytes:
    """
    Build the certificate authentication packet
    
    The packet structure is:
    - Header: [first_byte] 00 [length] 03
    - Certificate data (signature + CBOR)
    """
    cert_len = len(creds.cert_cbor)
    packet = bytearray([first_byte, 0x00, cert_len, 0x03])
    packet.extend(creds.cert_cbor)
    return bytes(packet)
