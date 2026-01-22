"""
VanMoof S5/A5 BLE Lock/Unlock Commands

Provides functions to lock and unlock the bike via BLE.

Functions:
    unlock(client): Unlock the bike
    lock(client):   Lock the bike

Each function expects an authenticated VanMoofClient instance.

Command group: 0x01 (lock)

| Function | Command (hex)          | Description      |
|----------|-----------------------|------------------|
| unlock   | 81 00 03 01 00 A0 01  | Unlock main lock |
| lock     | 81 00 03 01 00 A0 00  | Lock main lock   |
"""
import asyncio

async def unlock(client):
    """Unlock the bike (BLE: 81 00 03 01 00 A0 01)"""
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print("\n🔓 Unlocking...")
    cmd = bytes([0x81, 0x00, 0x03, 0x01, 0x00, 0xA0, 0x01])
    await client.send(cmd, "unlock")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break

async def lock(client):
    """Lock the bike (BLE: 81 00 03 01 00 A0 00)"""
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print("\n🔒 Locking...")
    cmd = bytes([0x81, 0x00, 0x03, 0x01, 0x00, 0xA0, 0x00])
    await client.send(cmd, "lock")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break
