"""
VanMoof S5/A5 BLE Telemetry - Real-time Sensor Data

The bike streams real-time telemetry data via BLE notifications while
riding. This module provides a live monitor that captures, parses, and
displays sensor readings as they arrive.

Available sensors (varies by model/firmware):
    speed          Current speed (km/h)
    pedal_rpm      Pedal cadence (RPM)
    pedal_torque   Pedal torque (Nm)
    assist_level   Current motor assist level
    boost_button   Boost button pressed
    battery        Battery level (%)
    motor_temp     Motor temperature (C)
    driver_temp    Motor driver/controller temperature (C)
    module_temp    Main module temperature (C)
    light_sensor   Ambient light sensor value
    humidity       Humidity sensor (%)
    air_quality    Air quality index (S6)
    distance       Trip distance (km)
    locked         Lock state

Functions:
    start_monitor(client):    Start live telemetry display (Ctrl+C to stop)
    show_telemetry(client):   Show last known sensor readings
    subscribe_telemetry(client): Send subscription command for telemetry stream
"""

import asyncio
import cbor2
import time


# All known telemetry field names mapped to human-readable labels and units
SENSOR_FIELDS = {
    # Motion
    "spd":          ("Speed",              "km/h"),
    "speed":        ("Speed",              "km/h"),
    "cad":          ("Pedal RPM",          "RPM"),
    "rpm":          ("Pedal RPM",          "RPM"),
    "pedal_rpm":    ("Pedal RPM",          "RPM"),
    "torque":       ("Pedal Torque",       "Nm"),
    "trq":          ("Pedal Torque",       "Nm"),
    "pedal_torque": ("Pedal Torque",       "Nm"),

    # Assist
    "pwr":          ("Assist Level",       ""),
    "assist":       ("Assist Level",       ""),
    "boost":        ("Boost Active",       ""),
    "boost_btn":    ("Boost Button",       ""),
    "boost_button": ("Boost Button",       ""),

    # Battery & Power
    "bat":          ("Battery",            "%"),
    "battery":      ("Battery",            "%"),
    "charging":     ("Charging",           ""),

    # Temperatures
    "motor_temp":   ("Motor Temp",         "C"),
    "mt":           ("Motor Temp",         "C"),
    "driver_temp":  ("Driver Temp",        "C"),
    "dt":           ("Driver Temp",        "C"),
    "module_temp":  ("Module Temp",        "C"),
    "temp":         ("Temperature",        "C"),

    # Environment (S6 and later)
    "light":        ("Light Sensor",       ""),
    "lux":          ("Light Sensor",       "lux"),
    "light_sensor": ("Light Sensor",       ""),
    "humidity":     ("Humidity",           "%"),
    "hum":          ("Humidity",           "%"),
    "air_quality":  ("Air Quality",        "AQI"),
    "aq":           ("Air Quality",        "AQI"),

    # State
    "locked":       ("Locked",             ""),
    "alarm":        ("Alarm Armed",        ""),
    "enabled":      ("Enabled",            ""),
    "ready":        ("Ready",              ""),
    "err":          ("Error Code",         ""),
    "error":        ("Error Code",         ""),

    # Distance
    "dst":          ("Trip Distance",      "km"),
    "odo":          ("Odometer",           "km"),
    "trip":         ("Trip",               "km"),

    # Auth/Enc (internal, but captured)
    "enc":          ("Encryption",         ""),
    "auth":         ("Authenticated",      ""),

    # Region/Config
    "region":       ("Region",             ""),
    "gear":         ("Gear",               ""),
    "fw":           ("Firmware",           ""),
    "hw":           ("Hardware",           ""),
}


def _format_value(key: str, value) -> str:
    """Format a sensor value for display."""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, bytes):
        return value.hex()

    label, unit = SENSOR_FIELDS.get(key, (key, ""))

    if isinstance(value, float):
        formatted = f"{value:.1f}"
    else:
        formatted = str(value)

    if unit:
        return f"{formatted} {unit}"
    return formatted


def show_telemetry(client):
    """
    Display last known telemetry/sensor readings.

    Shows all values from the accumulated last_status dict,
    organized by category.
    """
    if not client.last_status:
        print("\n   No telemetry data received yet.")
        print("   Telemetry streams when the bike is powered on.")
        print("   Use 'monitor' for live display or 'poweron' first.")
        return

    print("\n" + "=" * 45)
    print("   Sensor Readings")
    print("=" * 45)

    # Group by category
    categories = {
        "Motion":      ["spd", "speed", "cad", "rpm", "pedal_rpm",
                        "torque", "trq", "pedal_torque"],
        "Assist":      ["pwr", "assist", "boost", "boost_btn", "boost_button"],
        "Battery":     ["bat", "battery", "charging"],
        "Temperature": ["motor_temp", "mt", "driver_temp", "dt",
                        "module_temp", "temp"],
        "Environment": ["light", "lux", "light_sensor", "humidity", "hum",
                        "air_quality", "aq"],
        "Distance":    ["dst", "odo", "trip"],
        "State":       ["locked", "alarm", "enabled", "ready",
                        "enc", "auth", "err", "error"],
        "Config":      ["region", "gear", "fw", "hw"],
    }

    shown_keys = set()
    for cat_name, cat_keys in categories.items():
        cat_values = {}
        for k in cat_keys:
            if k in client.last_status:
                label, _ = SENSOR_FIELDS.get(k, (k, ""))
                cat_values[label] = _format_value(k, client.last_status[k])
                shown_keys.add(k)

        if cat_values:
            print(f"\n   {cat_name}:")
            for label, val in cat_values.items():
                print(f"      {label:20s} {val}")

    # Show any unknown keys
    unknown = {k: v for k, v in client.last_status.items()
               if k not in shown_keys}
    if unknown:
        print(f"\n   Other:")
        for k, v in unknown.items():
            print(f"      {k:20s} {_format_value(k, v)}")

    print()


async def subscribe_telemetry(client):
    """
    Request the bike to start streaming telemetry data.

    The bike normally sends status updates after state changes.
    Powering on the bike electronics activates the telemetry stream
    which includes speed, cadence, temperatures, and other sensor data.
    """
    if not client.authenticated:
        print("   Not authenticated")
        return

    # Power on bike to activate sensors and telemetry stream
    print("\nActivating telemetry stream...")
    print("   Sending power-on to activate sensors...")
    cmd = bytes([0x81, 0x00, 0x03, 0x03, 0x00, 0xA0, 0x01])
    await client.send(cmd, "power on (telemetry)")
    await asyncio.sleep(0.5)

    # Drain any immediate responses
    for _ in range(5):
        resp = await client.recv(0.3)
        if not resp:
            break

    print("   Telemetry active. Sensor data will appear as the bike sends it.")


async def start_monitor(client):
    """
    Start live telemetry monitoring.

    Displays real-time sensor readings as they arrive from the bike.
    The notification handler (_on_notify) already captures CBOR status
    updates into client.last_status. This function periodically
    refreshes a formatted display.

    Press Ctrl+C to stop monitoring and return to the command prompt.
    """
    if not client.authenticated:
        print("   Not authenticated")
        return

    print("\n" + "=" * 45)
    print("   Live Telemetry Monitor")
    print("   Press Ctrl+C to stop")
    print("=" * 45)

    # Activate telemetry if not already active
    if not client.last_status.get("enabled"):
        await subscribe_telemetry(client)

    last_snapshot = {}
    update_count = 0

    try:
        while client.connected:
            # Check for new data
            current = dict(client.last_status)
            if current != last_snapshot:
                update_count += 1
                last_snapshot = current

                # Build compact live display
                ts = time.strftime("%H:%M:%S")
                parts = []

                # Priority readings (most useful while riding)
                display_order = [
                    ("spd", "speed"),
                    ("speed", None),
                    ("bat", "battery"),
                    ("battery", None),
                    ("pwr", "assist"),
                    ("assist", None),
                    ("cad", "cadence"),
                    ("rpm", None),
                    ("pedal_rpm", None),
                    ("torque", "torque"),
                    ("trq", None),
                    ("pedal_torque", None),
                    ("motor_temp", "motor"),
                    ("mt", None),
                    ("driver_temp", "driver"),
                    ("dt", None),
                    ("module_temp", "module"),
                    ("boost", "boost"),
                    ("boost_btn", "boost_btn"),
                    ("boost_button", None),
                    ("light", "light"),
                    ("lux", None),
                    ("light_sensor", None),
                    ("humidity", "humid"),
                    ("hum", None),
                    ("air_quality", "air"),
                    ("aq", None),
                    ("locked", "lock"),
                    ("err", "err"),
                    ("error", None),
                ]

                seen_labels = set()
                for key, label in display_order:
                    if key in current and label and label not in seen_labels:
                        val = _format_value(key, current[key])
                        parts.append(f"{label}={val}")
                        seen_labels.add(label)

                if parts:
                    line = f"[{ts}] #{update_count}  " + "  |  ".join(parts)
                    print(f"\r{line}")

            # Small delay before checking again
            await asyncio.sleep(0.2)

    except (KeyboardInterrupt, asyncio.CancelledError):
        pass

    print("\n   Monitor stopped.")
