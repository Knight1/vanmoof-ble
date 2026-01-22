"""
VanMoof S5/A5 BLE Sound/Feedback Commands

Provides functions to trigger bell, horn, and generic sounds on VanMoof bikes via BLE.

Functions:
    play_sound(client, sound_id=1):   Play a generic sound
    bell_ding(client):                Bell ding (single)
    bell_double_ding(client):         Bell double ding
    horn_sound(client):               Horn sound

Each function expects an authenticated VanMoofClient instance.

Command group: 0x02 (sound/feedback)

| Function           | Command (hex)          | Description         |
|--------------------|-----------------------|---------------------|
| play_sound         | 81 00 03 01 00 21 <n> | Play sound <n>      |
| bell_ding          | 81 00 03 02 00 A0 01  | Bell ding (single)  |
| bell_double_ding   | 81 00 03 02 00 A0 02  | Bell double ding    |
| horn_sound         | 81 00 03 02 01 A0 01  | Horn sound          |
"""
import asyncio

async def play_sound(client, sound_id: int = 1):
    """
    Play a sound on the bike (default sound_id=1)
    BLE Packet: 81 00 03 01 00 21 <sound_id>
    """
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print(f"\n🔊 Playing sound {sound_id}...")
    cmd = bytes([0x81, 0x00, 0x03, 0x01, 0x00, 0x21, sound_id])
    await client.send(cmd, "sound")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break

async def bell_ding(client):
    """
    Play a single bell ding sound.
    BLE Packet: 81 00 03 02 00 A0 01
    """
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print("\n🔔 Bell ding...")
    cmd = bytes([0x81, 0x00, 0x03, 0x02, 0x00, 0xA0, 0x01])
    await client.send(cmd, "bell ding")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break

async def bell_double_ding(client):
    """
    Play a double bell ding sound.
    BLE Packet: 81 00 03 02 00 A0 02
    """
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print("\n🔔🔔 Bell double ding...")
    cmd = bytes([0x81, 0x00, 0x03, 0x02, 0x00, 0xA0, 0x02])
    await client.send(cmd, "bell double ding")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break

async def horn_sound(client):
    """
    Play the horn sound.
    BLE Packet: 81 00 03 02 01 A0 01
    """
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print("\n📢 Horn sound...")
    cmd = bytes([0x81, 0x00, 0x03, 0x02, 0x01, 0xA0, 0x01])
    await client.send(cmd, "horn sound")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break
