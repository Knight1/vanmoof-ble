"""
VanMoof S5/A5 BLE Light Commands

Provides function to set the bike's light mode via BLE.

Functions:
    set_lights(client, mode): Set light mode (off, on, auto)

Each function expects an authenticated VanMoofClient instance.

| Model | Topic                            | Values                        |
|-------|----------------------------------|-------------------------------|
| S5/A5 | 0x006B settings/light_mode/set   | 1 on, 2 off, 3 auto           |
| S6    | 0x0131 light_mode (SET)          | [mode, 1]: 0 off, 2 on, 3 auto|

Values as the official app encodes them. The S5/A5 confirm on 0x006A
settings/light_mode; the S6 value is published back or read with GET.
"""
from utils import protocol_codes as proto
from utils import s6_protocol as s6
from utils.protocol_codes import Topic


async def set_lights(client, mode: str):
    """Set the light mode (off, on, auto)"""
    if not client.require_auth():
        return
    mode = mode.lower()
    values = s6.LIGHT_MODE_VALUES if client.bike_model == "S6" else proto.LIGHT_MODE_VALUES
    value = values.get(mode)
    if value is None:
        print("   Light mode must be: off, on, or auto")
        return
    mode_names = {"off": "Off", "on": "Always On", "auto": "Auto"}
    print(f"\nSetting lights to {mode_names[mode]}...")
    if client.bike_model == "S6":
        await client.s6_apply_setting("Light mode", s6.Topic.LIGHT_MODE,
                                      [value, s6.LIGHT_OFF_AUTO_MODE])
        return
    await client.apply_setting("Light mode", Topic.LIGHT_MODE_SET, value,
                               Topic.LIGHT_MODE, f"lights {mode}")
