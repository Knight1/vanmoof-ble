"""
VanMoof S5/A5 BLE Telemetry - Real-time Sensor Data

The S5/A5 publish ride, battery and sensor data as topics. Nothing is sent
until the client subscribes: 'subscribe' asks for the telemetry topics, after
which the bike pushes each value when it changes (ride data mostly while
riding).

Available readings (topic ids, see utils/protocol_codes.py):
    Ride         speed 0x0050, pedal_rpm 0x0052, torque 0x0054,
                 motor_speed 0x0055, motor_current 0x0056,
                 motor_temperature 0x0053, brake_level 0x0057, boost 0x0060,
                 calories 0x0049, ride distance 0x0051
    Battery      soc_app 0x0018, soc 0x0010, power state 0x0001
    Environment  ux/sensor/light 0x0081, humidity 0x0082,
                 temperature 0x0083, air 0x0084
    Modules      device/<module>/status 0x0030-0x003E, derived by the bike
                 from each sub-module's CAN-bus heartbeat

Values are shown as the bike sends them unless the unit is known.

Functions:
    subscribe_telemetry(client): Subscribe to the telemetry topics
    show_telemetry(client):      Show last known readings, grouped
    start_monitor(client):       Live display of changing readings (Ctrl+C to stop)
    show_modules(client):        Show the status of each module (CAN heartbeats)
"""

import asyncio
import time

from utils import protocol_codes as proto
from utils.protocol_codes import Topic


GROUPS = (
    ("Ride", (Topic.SPEED, Topic.PEDAL_RPM, Topic.TORQUE, Topic.MOTOR_SPEED,
              Topic.MOTOR_CURRENT, Topic.MOTOR_TEMPERATURE, Topic.BRAKE_LEVEL,
              Topic.BOOST, Topic.CALORIES, Topic.RIDE_DISTANCE)),
    ("Battery", (Topic.BATTERY_LEVEL, Topic.BATTERY_SOC, Topic.POWER_STATE)),
    ("Environment", (Topic.SENSOR_LIGHT, Topic.SENSOR_HUMIDITY,
                     Topic.SENSOR_TEMPERATURE, Topic.SENSOR_AIR)),
    ("Bike", (Topic.LOCK_STATE, Topic.DISTANCE, Topic.ASSIST_LEVEL,
              Topic.LIGHT_MODE, Topic.REGION, Topic.ESHIFTER_GEAR)),
)

_MISSING = object()


def _short_name(topic: int) -> str:
    """Compact label for a topic: its last path element, or the last two
    joined when that alone is ambiguous (power/state, device/<ecu>/status)."""
    parts = proto.topic_name(topic).split("/")
    if parts[-1] in ("state", "status") and len(parts) > 1:
        owner = parts[-3] if parts[-2] == "info" and len(parts) > 2 else parts[-2]
        return f"{owner}_{parts[-1]}"
    return parts[-1]


async def subscribe_telemetry(client):
    """Subscribe to the telemetry topics."""
    if not client.require_s5():
        return

    print("\nSubscribing to telemetry topics...")
    await client.subscribe(proto.TELEMETRY_TOPICS, "subscribe (telemetry)")
    print("   Ride readings update while riding. Use 'sensors' or 'monitor'.")


def show_telemetry(client):
    """Display the last known readings, grouped by category."""
    if client.bike_model == "S6":
        print("   Not available on the S6 (use 'query all' or 'topics')")
        return
    if not client.topics:
        print("\n   No telemetry data received yet.")
        print("   Use 'subscribe' to start receiving it.")
        return

    print("\n" + "=" * 45)
    print("   Sensor Readings")
    print("=" * 45)

    for group, topics in GROUPS:
        known = [t for t in topics if t in client.topics]
        if not known:
            continue
        print(f"\n   {group}:")
        for topic in known:
            pretty = proto.describe_topic_value(topic, client.topics[topic])
            print(f"      {_short_name(topic):20s} {pretty}")

    if not all(t in client.subscribed for t in proto.TELEMETRY_TOPICS):
        print("\n   (Ride and sensor topics need 'subscribe' first.)")
    print()


async def start_monitor(client):
    """
    Start live telemetry monitoring.

    Prints every reading that changes as it arrives. Press Ctrl+C to stop
    monitoring and return to the command prompt.
    """
    if not client.require_s5():
        return

    if not all(t in client.subscribed for t in proto.TELEMETRY_TOPICS):
        await client.subscribe(proto.TELEMETRY_TOPICS, "subscribe (telemetry)")

    print("\n" + "=" * 45)
    print("   Live Telemetry Monitor")
    print("   Press Ctrl+C to stop")
    print("=" * 45 + "\n")

    last_snapshot = {}
    update_count = 0
    client.quiet = True

    try:
        while client.connected:
            changed = {t: v for t, v in client.topics.items()
                       if last_snapshot.get(t, _MISSING) != v}
            if changed:
                update_count += 1
                last_snapshot.update(changed)
                ts = time.strftime("%H:%M:%S")
                parts = [f"{_short_name(t)}={proto.describe_topic_value(t, v)}"
                         for t, v in changed.items()]
                print(f"[{ts}] #{update_count}  " + "  |  ".join(parts))

            await asyncio.sleep(0.2)

    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        client.quiet = False

    print("\n   Monitor stopped.")


async def show_modules(client):
    """Show each module's status, derived by the bike from its CAN heartbeat."""
    if not client.require_s5():
        return

    print("\nReading module status (CAN heartbeats)...")
    await client.read_topics(proto.HEARTBEAT_TOPICS, timeout=3.0)
    for topic, name in proto.DEVICE_STATUS_TOPICS.items():
        if topic in client.topics:
            shown = proto.describe_topic_value(topic, client.topics[topic])
        else:
            shown = "(no report)"
        print(f"   {name:18s} {shown}")
