"""
VanMoof S5/A5 BLE Alarm Commands

Provides functions to enable and disable the alarm via BLE.

Functions:
    arm_alarm(client):    Enable the alarm
    disarm_alarm(client): Disable the alarm

Each function expects an authenticated VanMoofClient instance.

| Model | Topic                           | arm / disarm   |
|-------|---------------------------------|----------------|
| S5/A5 | 0x006F settings/alarm/set       | true / false   |
| S6    | 0x0172 alarm (SET)              | [1] / [0]      |

Values as the official app writes them. The S5/A5 confirm on 0x006E
settings/alarm. There is no BLE command to trigger the alarm.
"""
from utils import s6_protocol as s6
from utils.protocol_codes import Topic


async def arm_alarm(client):
    """Enable the bike alarm (topic 0x006F settings/alarm/set = true)"""
    if not client.require_auth():
        return
    print("\nArming alarm...")
    if client.bike_model == "S6":
        await client.s6_apply_setting("Alarm", s6.Topic.ALARM, [1])
        return
    await client.apply_setting("Alarm", Topic.ALARM_SET, True, Topic.ALARM,
                               "arm alarm")


async def disarm_alarm(client):
    """Disable the bike alarm (topic 0x006F settings/alarm/set = false)"""
    if not client.require_auth():
        return
    print("\nDisarming alarm...")
    if client.bike_model == "S6":
        await client.s6_apply_setting("Alarm", s6.Topic.ALARM, [0])
        return
    await client.apply_setting("Alarm", Topic.ALARM_SET, False, Topic.ALARM,
                               "disarm alarm")
