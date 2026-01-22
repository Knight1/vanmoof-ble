"""
VanMoof S5/A5 BLE Light Commands

Provides function to set the bike's light mode via BLE.

Functions:
    set_lights(client, mode): Set light mode (off, on, auto)

Each function expects an authenticated VanMoofClient instance.

Command group: 0x01 (lights)

| Function   | Command (hex)          | Description         |
|------------|-----------------------|---------------------|
| set_lights | 81 00 03 01 00 6B <n> | Set light mode      |
"""
import asyncio

async def set_lights(client, mode: str):
    """Set the light mode (off, on, auto)"""
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    modes = {"off": 0x00, "on": 0x01, "auto": 0x03}
    mode = mode.lower()
    if mode not in modes:
        print("   ❌ Light mode must be: off, on, or auto")
        return
    mode_names = {"off": "Off", "on": "Always On", "auto": "Auto/Pulse"}
    print(f"\n💡 Setting lights to {mode_names[mode]}...")
    cmd = bytes([0x81, 0x00, 0x03, 0x01, 0x00, 0x6B, modes[mode]])
    await client.send(cmd, f"lights {mode}")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break
