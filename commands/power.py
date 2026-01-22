"""
VanMoof S5/A5 BLE Power Level Commands

Provides function to set the bike's power assist level via BLE.

Functions:
    set_power_level(client, level): Set power assist level (0-4)

Each function expects an authenticated VanMoofClient instance.

Command group: 0x01 (power)

| Function         | Command (hex)          | Description         |
|------------------|-----------------------|---------------------|
| set_power_level  | 81 00 03 01 00 67 <n> | Set power level     |
"""
import asyncio

async def set_power_level(client, level: int):
    """Set the power assist level (0=off, 1-4)"""
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    if level < 0 or level > 4:
        print("   ❌ Power level must be 0-4")
        return
    level_names = ["Off", "Level 1", "Level 2", "Level 3", "Level 4"]
    print(f"\n⚡ Setting power level to {level_names[level]}...")
    cmd = bytes([0x81, 0x00, 0x03, 0x01, 0x00, 0x67, level])
    await client.send(cmd, f"power {level}")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break
