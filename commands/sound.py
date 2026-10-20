"""
VanMoof S5/A5 BLE Bell Sound Commands

The S5/A5 bell plays one of a few built-in tones; the app selects it through
settings/bell_sound/set. Sounds can't be played on demand with an owner or
shared-bike certificate: the bike's ACL doesn't let those roles write
ux/sound/play.

Functions:
    set_bell_sound(client, tone): Select the bell tone (no tone: list them)

Each function expects an authenticated VanMoofClient instance.

| Model | Topic                            | Values                        |
|-------|----------------------------------|-------------------------------|
| S5/A5 | 0x0073 settings/bell_sound/set   | protocol_codes.BELL_SOUNDS    |
| S6    | 0x0142 bell_sound (SET)          | s6_protocol.BELL_SOUNDS       |

The two models offer different tones. The S5/A5 confirm on 0x0072
settings/bell_sound; the S6 plays the tone it selects.
"""
from utils import protocol_codes as proto
from utils import s6_protocol as s6
from utils.protocol_codes import Topic


async def set_bell_sound(client, tone: str = None):
    """Select the bell tone, or list the tones when none is given."""
    if not client.require_auth():
        return
    is_s6 = client.bike_model == "S6"
    tones = s6.BELL_SOUNDS if is_s6 else proto.BELL_SOUNDS
    if tone is None:
        current = client.topics.get(s6.Topic.BELL_SOUND if is_s6 else Topic.BELL_SOUND)
        current = s6.first_field(current) if is_s6 else current
        print("\n   Bell tones:")
        for value, name in tones.items():
            marker = "   <- current" if value == current else ""
            print(f"      {name}{marker}")
        print("   Usage: bellsound <tone>")
        return

    values = s6.BELL_SOUND_VALUES if is_s6 else proto.BELL_SOUND_VALUES
    value = values.get(tone.lower())
    if value is None:
        print(f"   ❌ Unknown tone. Valid: {', '.join(values)}")
        return
    print(f"\n🔔 Setting bell sound to {tone}...")
    if is_s6:
        await client.s6_apply_setting("Bell sound", s6.Topic.BELL_SOUND, [value])
        return
    await client.apply_setting("Bell sound", Topic.BELL_SOUND_SET, value,
                               Topic.BELL_SOUND, f"bell sound {tone}")
