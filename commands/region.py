"""
VanMoof S5/A5 BLE Region Commands

Control the speed region setting which determines the maximum motor
assist speed.

Regions:
    EU:   25 km/h  (European standard)
    US:   32 km/h  (US standard)
    JP:   24 km/h  (Japanese standard)

Uses configuration group 0x30, subcommand 0x01.

Functions:
    set_region(client, region):    Set speed region
    query_region(client):          Query current region

| Function     | Command (hex)          | Description              |
|--------------|------------------------|--------------------------|
| set_region   | 81 00 04 30 01 A0 <n>  | Set speed region         |
| query_region | 81 00 02 30 01 A0      | Read current region      |

Region values:
    | Value | Region | Max Assist Speed |
    |-------|--------|------------------|
    | 0x00  | EU     | 25 km/h          |
    | 0x01  | US     | 32 km/h          |
    | 0x02  | JP     | 24 km/h          |
"""

import asyncio

REGIONS = {
    "eu": (0x00, "EU (25 km/h)"),
    "us": (0x01, "US (32 km/h)"),
    "jp": (0x02, "JP (24 km/h)"),
}

REGION_BY_VALUE = {v: name for (_, (v, name)) in
                   [(k, REGIONS[k]) for k in REGIONS]}


async def set_region(client, region: str):
    """
    Set the speed region/limit.

    Args:
        client: Authenticated VanMoofClient
        region: Region code - "eu", "us", or "jp"

    BLE Packet: 81 00 04 30 01 A0 <region_value>
    """
    if not client.authenticated:
        print("   Not authenticated")
        return

    region = region.lower()
    if region not in REGIONS:
        valid = ", ".join(REGIONS.keys())
        print(f"   Unknown region. Valid: {valid}")
        return

    value, name = REGIONS[region]
    print(f"\nSetting region to {name}...")
    cmd = bytes([0x81, 0x00, 0x04, 0x30, 0x01, 0xA0, value])
    await client.send(cmd, f"region {region}")
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break


async def query_region(client):
    """
    Query the current speed region setting.

    BLE Packet: 81 00 02 30 01 A0
    """
    if not client.authenticated:
        print("   Not authenticated")
        return

    print("\nQuerying region...")
    cmd = bytes([0x81, 0x00, 0x02, 0x30, 0x01, 0xA0])
    await client.send(cmd, "read region")
    await asyncio.sleep(0.3)
    for _ in range(3):
        resp = await client.recv(0.3)
        if not resp:
            break
