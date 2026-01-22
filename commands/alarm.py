"""
VanMoof S5/A5 BLE Alarm Commands

Provides functions to arm, disarm, and trigger the alarm via BLE.

Functions:
    arm_alarm(client):           Arm (enable) alarm
    disarm_alarm(client):        Disarm (disable) alarm
    trigger_alarm_sound(client): Trigger alarm sound

Each function expects an authenticated VanMoofClient instance.

Command group: 0x01 (alarm)

| Function             | Command (hex)          | Description         |
|----------------------|-----------------------|---------------------|
| arm_alarm            | 81 00 03 01 01 A0 01  | Enable alarm        |
| disarm_alarm         | 81 00 03 01 01 A0 00  | Disable alarm       |
| trigger_alarm_sound  | 81 00 03 01 02 A0 01  | Immediate alarm     |
"""
import asyncio

async def arm_alarm(client):
    """Arm (enable) the bike alarm (BLE: 81 00 03 01 01 A0 01)"""
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print("\n🚨 Arming alarm...")
    cmd = bytes([0x81, 0x00, 0x03, 0x01, 0x01, 0xA0, 0x01])
    await client.send(cmd, "arm alarm")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break

async def disarm_alarm(client):
    """Disarm (disable) the bike alarm (BLE: 81 00 03 01 01 A0 00)"""
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print("\n🔕 Disarming alarm...")
    cmd = bytes([0x81, 0x00, 0x03, 0x01, 0x01, 0xA0, 0x00])
    await client.send(cmd, "disarm alarm")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break

async def trigger_alarm_sound(client):
    """Trigger the immediate alarm sound (BLE: 81 00 03 01 02 A0 01)"""
    if not client.authenticated:
        print("   ❌ Not authenticated")
        return
    print("\n🔔 Triggering alarm sound...")
    cmd = bytes([0x81, 0x00, 0x03, 0x01, 0x02, 0xA0, 0x01])
    await client.send(cmd, "trigger alarm")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break
