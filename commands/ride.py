"""
ride.py - VanMoof S5/A5 BLE ride/power control commands

Provides functions to control power and boost features on the bike.

Functions:
    power_on_bike(client):    Power on the bike
    power_off_bike(client):   Power off the bike
    enable_boost(client):     Enable boost mode
    disable_boost(client):    Disable boost mode

Each function expects an authenticated VanMoofClient instance.
"""

import asyncio

async def power_on_bike(client):
    """
    Power on the bike.
    BLE Packet: 81 00 03 03 00 A0 01
    """
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print("\n⚡ Powering on bike...")
    cmd = bytes([0x81, 0x00, 0x03, 0x03, 0x00, 0xA0, 0x01])
    await client.send(cmd, "power on")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break

async def power_off_bike(client):
    """
    Power off the bike.
    BLE Packet: 81 00 03 03 00 A0 00
    """
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print("\n🔌 Powering off bike...")
    cmd = bytes([0x81, 0x00, 0x03, 0x03, 0x00, 0xA0, 0x00])
    await client.send(cmd, "power off")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break

async def enable_boost(client):
    """
    Enable boost mode.
    BLE Packet: 81 00 03 03 01 A0 01
    """
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print("\n🚀 Enabling boost mode...")
    cmd = bytes([0x81, 0x00, 0x03, 0x03, 0x01, 0xA0, 0x01])
    await client.send(cmd, "enable boost")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break

async def disable_boost(client):
    """
    Disable boost mode.
    BLE Packet: 81 00 03 03 01 A0 00
    """
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print("\n🛑 Disabling boost mode...")
    cmd = bytes([0x81, 0x00, 0x03, 0x03, 0x01, 0xA0, 0x00])
    await client.send(cmd, "disable boost")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break
