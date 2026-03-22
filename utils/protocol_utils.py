"""
VanMoof S5/A5/S6 BLE protocol utilities

Provides functions for building protocol packets: headers, authentication,
read commands, write commands, and configuration commands.

Packet Structure
----------------
All packets follow this format:

    [frame_byte] [0x00] [module] [command] [payload...]

Frame bytes:
    0x80 = Bike -> Client
    0x81 = Client -> Bike
    0x82 = Bike -> Client (alternate, some firmware versions)

Modules (byte 2):
    0x02 = Read (query current value)
    0x03 = Write (set value)
    0x04 = Configure (set configuration parameter)

For authentication packets, byte 2 is the payload length instead.

Functions:
    build_tx_header(rx_header):     Build TX header matching RX frame byte
    build_auth_packet(creds):       Build certificate authentication packet
    build_read_command(group, sub, param):           Query a value
    build_write_command(group, sub, param, value):   Set a value
    build_config_command(group, sub, param, value):  Set a config value
"""


def build_tx_header(rx_header: bytes = None) -> bytes:
    """
    Build TX header based on RX header.
    Use same first byte as received (0x80/0x81/0x82).
    """
    if rx_header and len(rx_header) > 0:
        return bytes([rx_header[0], 0x00])
    return bytes([0x81, 0x00])


def build_auth_packet(creds, first_byte: int = 0x81) -> bytes:
    """
    Build the certificate authentication packet.

    Format: [frame_byte] 00 [cert_length] 03 [CA_signature + CBOR_payload]

    The cert_data field contains the full certificate: the 64-byte CA
    signature concatenated with the CBOR-encoded certificate payload.
    The length byte represents the size of the certificate data that
    follows the 0x03 subtype byte.
    """
    cert_data = creds.cert_data
    packet = bytearray([first_byte, 0x00, len(cert_data), 0x03])
    packet.extend(cert_data)
    return bytes(packet)


def build_read_command(group: int, sub: int, param: int,
                       first_byte: int = 0x81) -> bytes:
    """
    Build a read (query) command packet.

    Format: [frame_byte] 00 02 [group] [sub] [param]

    Module 0x02 = Read. No value byte; the bike responds with the
    current value for the specified group/sub/param.

    Args:
        group: Command group (0x01=security, 0x02=sound, 0x03=ride, 0x30=config)
        sub:   Sub-command within the group
        param: Parameter type (0xA0=state, 0x6B=light, 0x21=sound)
    """
    return bytes([first_byte, 0x00, 0x02, group, sub, param])


def build_write_command(group: int, sub: int, param: int, value: int,
                        first_byte: int = 0x81) -> bytes:
    """
    Build a write (set) command packet.

    Format: [frame_byte] 00 03 [group] [sub] [param] [value]

    Module 0x03 = Write. Sets the specified parameter to the given value.

    Args:
        group: Command group (0x01=security, 0x02=sound, 0x03=ride)
        sub:   Sub-command within the group
        param: Parameter type (0xA0=state, 0x6B=light, 0x21=sound)
        value: Value to set
    """
    return bytes([first_byte, 0x00, 0x03, group, sub, param, value])


def build_config_command(group: int, sub: int, param: int, value: int,
                         first_byte: int = 0x81) -> bytes:
    """
    Build a configuration command packet.

    Format: [frame_byte] 00 04 [group] [sub] [param] [value]

    Module 0x04 = Configure. Used for settings like power assist level
    and speed region that persist across power cycles.

    Args:
        group: Command group (0x30=configuration)
        sub:   Sub-command (0x00=assist level, 0x01=region)
        param: Parameter type (0xA0=state)
        value: Configuration value
    """
    return bytes([first_byte, 0x00, 0x04, group, sub, param, value])
