"""
VanMoof S5/A5 BLE Region Commands

Control the speed region setting which determines the maximum motor
assist speed.

Regions:
    EU:      25 km/h  (European standard)
    US:      32 km/h  (US standard)
    JP:      24 km/h  (Japanese standard)
    Offroad: as offered by the official app

Functions:
    set_region(client, region):    Set speed region

| Function     | Topic                          | Message (hex)          |
|--------------|--------------------------------|------------------------|
| set_region   | 0x0062 settings/region/set     | 81 00 03 01 00 62 <n>  |

Region values, as the official app encodes them:
    | Value | Region  | Max Assist Speed |
    |-------|---------|------------------|
    | 0x00  | EU      | 25 km/h          |
    | 0x01  | US      | 32 km/h          |
    | 0x02  | JP      | 24 km/h          |
    | 0x03  | Offroad | -                |

The bike confirms on 0x0061 settings/region; read it with 'query region'.
"""

from utils import protocol_codes as proto
from utils.protocol_codes import Topic


async def set_region(client, region: str):
    """
    Set the speed region/limit.

    Args:
        client: Authenticated VanMoofClient
        region: Region code - "eu", "us", "jp", or "offroad"
    """
    if not client.require_s5():
        return

    region = region.lower()
    value = proto.REGION_VALUES.get(region)
    if value is None:
        valid = ", ".join(proto.REGION_VALUES)
        print(f"   Unknown region. Valid: {valid}")
        return

    print(f"\nSetting region to {proto.REGIONS[value]}...")
    await client.apply_setting("Region", Topic.REGION_SET, value, Topic.REGION,
                               f"region {region}")
