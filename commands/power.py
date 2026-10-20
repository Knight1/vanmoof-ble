"""
VanMoof S5/A5 BLE Power Level Commands

Provides function to set the bike's power assist level via BLE.

Functions:
    set_power_level(client, level): Set power assist level (0-4)

Each function expects an authenticated VanMoofClient instance.

| Model | Topic                              | Value  |
|-------|------------------------------------|--------|
| S5/A5 | 0x0067 settings/assist_level/set   | 0-4    |
| S6    | 0x0110 assist_level (SET)          | [0-4]  |

The S5/A5 ride service picks the level up from 0x0065 settings/assist_level,
which the bike re-publishes as confirmation; no unlock or power-on is needed.
"""
from utils import s6_protocol as s6
from utils.protocol_codes import Topic


async def set_power_level(client, level: int):
    """Set the power assist level (0=off, 1-4)"""
    if not client.require_auth():
        return
    if level < 0 or level > 4:
        print("   ❌ Power level must be 0-4")
        return

    level_names = ["Off", "Level 1", "Level 2", "Level 3", "Level 4"]
    print(f"\n⚡ Setting power level to {level_names[level]}...")
    if client.bike_model == "S6":
        await client.s6_apply_setting("Assist level", s6.Topic.ASSIST_LEVEL, [level])
        return
    await client.apply_setting("Assist level", Topic.ASSIST_LEVEL_SET, level,
                               Topic.ASSIST_LEVEL, f"power {level}")
