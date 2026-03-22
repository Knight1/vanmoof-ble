"""
VanMoof S5/A5 BLE Power Level Commands

Provides function to set the bike's power assist level via BLE.

Functions:
    set_power_level(client, level): Set power assist level (0-4)

Each function expects an authenticated VanMoofClient instance.

Command group: 0x30 (configuration)

Note: Power level changes require the bike to be unlocked, powered on,
and in ready state. The function handles this automatically.

| Function         | Command (hex)          | Description         |
|------------------|-----------------------|---------------------|
| set_power_level  | 81 00 04 30 00 A0 <n> | Set power level     |
"""
import asyncio
import cbor2
from commands.lock import unlock
from commands.ride import power_on_bike

async def _wait_for_ready(client, timeout: float = 3.0) -> bool:
    """Wait for bike to be enabled and ready"""
    start = asyncio.get_event_loop().time()
    while asyncio.get_event_loop().time() - start < timeout:
        resp = await client.recv(0.2)
        if resp and len(resp) > 4:
            # Look for CBOR state frames
            for i in range(len(resp)):
                if resp[i] == 0xBF:
                    try:
                        state = cbor2.loads(resp[i:])
                        if state.get('enabled') and state.get('ready'):
                            return True
                    except:
                        pass
        await asyncio.sleep(0.1)
    return False

async def set_power_level(client, level: int):
    """Set the power assist level (0=off, 1-4)"""
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    if not client.connected:
        print("   ❌ Not connected")
        return
    if level < 0 or level > 4:
        print("   ❌ Power level must be 0-4")
        return
    
    level_names = ["Off", "Level 1", "Level 2", "Level 3", "Level 4"]
    print(f"\n⚡ Setting power level to {level_names[level]}...")
    
    # Step 1: Unlock bike first (required before power-on)
    print("   🔓 Unlocking bike...")
    await unlock(client)
    await asyncio.sleep(0.3)
    
    # Step 2: Power on bike
    print("   🔌 Powering on bike...")
    await power_on_bike(client)
    await asyncio.sleep(0.3)
    
    # Step 3: Wait for bike to be ready (enabled and ready state)
    print("   ⏳ Waiting for bike to be ready...")
    if not await _wait_for_ready(client, timeout=2.0):
        print("   ⚠️  Bike not ready, attempting anyway...")
    else:
        print("   ✅ Bike ready")
    
    # Minimum quiet time after power-on
    await asyncio.sleep(0.3)
    
    # Step 4: Set assist level (group 0x30 configuration)
    cmd = bytes([0x81, 0x00, 0x04, 0x30, 0x00, 0xA0, level])
    await client.send(cmd, f"power {level}")
    
    # Wait for state convergence
    await asyncio.sleep(0.3)
