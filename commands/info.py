"""
VanMoof S5/A5 BLE Information & Status Commands

Query bike state, read device information, and display status.

Read commands use module 0x02:  81 00 02 [group] [sub] [param]
The bike responds with the current value via a command response (07 01)
or a CBOR status update (0D 05).

Functions:
    query_lock_state(client):   Query lock state
    query_alarm_state(client):  Query alarm state
    query_light_mode(client):   Query light mode
    query_power_state(client):  Query power on/off state
    query_boost_state(client):  Query boost mode state
    query_power_level(client):  Query assist level
    query_battery(client):      Query battery level
    query_all(client):          Query all known states
    read_device_info(client):   Read GATT device information (firmware, model, etc.)
    list_services(client):      List all GATT services and characteristics
    show_bike_info(client):     Display comprehensive bike information
    show_last_status(client):   Display last received CBOR status

Command group reference:
    | Query            | Packet (hex)      | Description           |
    |------------------|-------------------|-----------------------|
    | Lock state       | 81 00 02 01 00 A0 | Read lock state       |
    | Alarm state      | 81 00 02 01 01 A0 | Read alarm state      |
    | Light mode       | 81 00 02 01 00 6B | Read light mode       |
    | Power state      | 81 00 02 03 00 A0 | Read power on/off     |
    | Boost state      | 81 00 02 03 01 A0 | Read boost mode       |
    | Assist level     | 81 00 02 30 00 A0 | Read assist level     |
    | Region           | 81 00 02 30 01 A0 | Read speed region     |
"""

import asyncio
import datetime


# Standard BLE Device Information Service characteristic UUIDs
DIS_CHARS = {
    "00002a29": "Manufacturer",
    "00002a24": "Model",
    "00002a25": "Serial Number",
    "00002a26": "Firmware",
    "00002a27": "Hardware Rev",
    "00002a28": "Software Rev",
}


async def _send_read(client, group: int, sub: int, param: int,
                     label: str = "") -> list:
    """Send a read command and collect responses."""
    cmd = bytes([0x81, 0x00, 0x02, group, sub, param])
    await client.send(cmd, label or "read")
    await asyncio.sleep(0.3)
    responses = []
    for _ in range(3):
        resp = await client.recv(0.3)
        if resp:
            responses.append(resp)
        else:
            break
    return responses


async def query_lock_state(client):
    """Query current lock state (81 00 02 01 00 A0)"""
    if not client.authenticated:
        print("   Not authenticated")
        return
    print("\nQuerying lock state...")
    await _send_read(client, 0x01, 0x00, 0xA0, "read lock")


async def query_alarm_state(client):
    """Query current alarm state (81 00 02 01 01 A0)"""
    if not client.authenticated:
        print("   Not authenticated")
        return
    print("\nQuerying alarm state...")
    await _send_read(client, 0x01, 0x01, 0xA0, "read alarm")


async def query_light_mode(client):
    """Query current light mode (81 00 02 01 00 6B)"""
    if not client.authenticated:
        print("   Not authenticated")
        return
    print("\nQuerying light mode...")
    await _send_read(client, 0x01, 0x00, 0x6B, "read lights")


async def query_power_state(client):
    """Query current power state (81 00 02 03 00 A0)"""
    if not client.authenticated:
        print("   Not authenticated")
        return
    print("\nQuerying power state...")
    await _send_read(client, 0x03, 0x00, 0xA0, "read power")


async def query_boost_state(client):
    """Query current boost state (81 00 02 03 01 A0)"""
    if not client.authenticated:
        print("   Not authenticated")
        return
    print("\nQuerying boost state...")
    await _send_read(client, 0x03, 0x01, 0xA0, "read boost")


async def query_power_level(client):
    """Query current power assist level (81 00 02 30 00 A0)"""
    if not client.authenticated:
        print("   Not authenticated")
        return
    print("\nQuerying assist level...")
    await _send_read(client, 0x30, 0x00, 0xA0, "read level")


async def query_battery(client):
    """
    Query battery level.

    Tries the standard BLE Battery Service characteristic (0x2A19) first.
    Falls back to a protocol read command if not available.
    """
    if not client.authenticated:
        print("   Not authenticated")
        return

    print("\nQuerying battery...")

    # Try standard BLE Battery Service
    if client.client:
        for svc in client.client.services:
            for char in svc.characteristics:
                if "2a19" in char.uuid.lower():
                    try:
                        data = await client.client.read_gatt_char(char.uuid)
                        if data:
                            level = data[0]
                            print(f"   Battery: {level}%")
                            return level
                    except Exception as e:
                        client.log(f"Battery service read failed: {e}")

    # Fallback: protocol read command
    await _send_read(client, 0x0E, 0x00, 0xA0, "read battery")


async def query_all(client):
    """Query all known states sequentially."""
    if not client.authenticated:
        print("   Not authenticated")
        return

    print("\n" + "=" * 40)
    print("   Querying All States")
    print("=" * 40)

    queries = [
        query_lock_state,
        query_alarm_state,
        query_light_mode,
        query_power_state,
        query_boost_state,
        query_power_level,
        query_battery,
    ]
    for q in queries:
        await q(client)
        await asyncio.sleep(0.2)

    print("\n" + "=" * 40)


async def read_device_info(client):
    """
    Read device information from standard BLE GATT services.

    Reads from the Device Information Service (0x180A) and Battery
    Service (0x180F) if available. Returns a dict of discovered info.
    """
    if not client.client:
        print("   Not connected")
        return {}

    info = {}
    found_any = False

    for svc in client.client.services:
        for char in svc.characteristics:
            uuid_lower = char.uuid.lower()

            # Device Information Service characteristics
            for dis_prefix, name in DIS_CHARS.items():
                if dis_prefix in uuid_lower:
                    try:
                        data = await client.client.read_gatt_char(char.uuid)
                        value = data.decode("utf-8", errors="replace").strip('\x00')
                        if value:
                            info[name] = value
                            found_any = True
                    except Exception as e:
                        client.log(f"Failed to read {name}: {e}")

            # Battery Level
            if "2a19" in uuid_lower:
                try:
                    data = await client.client.read_gatt_char(char.uuid)
                    if data:
                        info["Battery"] = f"{data[0]}%"
                        found_any = True
                except Exception as e:
                    client.log(f"Failed to read battery: {e}")

    return info


async def list_services(client):
    """List all GATT services and characteristics on the connected device."""
    if not client.client:
        print("   Not connected")
        return

    print("\nGATT Services:")
    for svc in client.client.services:
        desc = f" ({svc.description})" if svc.description else ""
        print(f"\n   Service: {svc.uuid}{desc}")
        for char in svc.characteristics:
            props = ", ".join(char.properties)
            cdesc = f" - {char.description}" if char.description else ""
            print(f"      {char.uuid} [{props}]{cdesc}")
    print()


async def show_bike_info(client):
    """Display comprehensive bike information from credentials and GATT."""
    print("\n" + "=" * 50)
    print("   Bike Information")
    print("=" * 50)

    # Credential info
    if client.creds:
        print(f"\n   Frame:         {client.creds.frame or 'Unknown'}")
        print(f"   Cert ID:       {client.creds.cert_id or 'Unknown'}")
        role_name = "Owner" if client.creds.role == 7 else f"User (role={client.creds.role})"
        print(f"   Role:          {role_name}")
        if client.creds.expiry:
            dt = datetime.datetime.fromtimestamp(
                client.creds.expiry, tz=datetime.timezone.utc
            )
            print(f"   Cert Expiry:   {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # Connection state
    print(f"\n   Connected:     {client.connected}")
    print(f"   Authenticated: {client.authenticated}")

    # GATT device info
    gatt_info = await read_device_info(client)
    if gatt_info:
        print("\n   Device Info (GATT):")
        for name, value in gatt_info.items():
            print(f"      {name}: {value}")

    # Last known status
    if client.last_status:
        print("\n   Last Status:")
        print(format_status(client.last_status))

    print()


def show_last_status(client):
    """Display the last received CBOR status in a readable format."""
    if not client.last_status:
        print("\n   No status received yet.")
        print("   The bike sends status updates automatically after commands.")
        return

    print("\n" + "=" * 40)
    print("   Current Status")
    print("=" * 40)
    print(format_status(client.last_status))
    print()


def format_status(status: dict) -> str:
    """Format a CBOR status dict for human-readable display."""
    key_names = {
        # Auth/connection
        "enc": "Encryption",
        "auth": "Authenticated",
        "enabled": "Enabled",
        "ready": "Ready",
        # State
        "locked": "Locked",
        "alarm": "Alarm Armed",
        "boost": "Boost",
        "boost_btn": "Boost Button",
        "boost_button": "Boost Button",
        # Motion
        "spd": "Speed",
        "speed": "Speed",
        "cad": "Pedal RPM",
        "rpm": "Pedal RPM",
        "pedal_rpm": "Pedal RPM",
        "torque": "Pedal Torque",
        "trq": "Pedal Torque",
        "pedal_torque": "Pedal Torque",
        # Power
        "bat": "Battery",
        "battery": "Battery",
        "pwr": "Assist Level",
        "assist": "Assist Level",
        "charging": "Charging",
        # Temperature
        "motor_temp": "Motor Temp",
        "mt": "Motor Temp",
        "driver_temp": "Driver Temp",
        "dt": "Driver Temp",
        "module_temp": "Module Temp",
        "temp": "Temperature",
        # Environment
        "light": "Light Sensor",
        "lux": "Light Sensor",
        "light_sensor": "Light Sensor",
        "humidity": "Humidity",
        "hum": "Humidity",
        "air_quality": "Air Quality",
        "aq": "Air Quality",
        # Distance
        "dst": "Trip Distance",
        "odo": "Odometer",
        "trip": "Trip",
        # Config
        "gear": "Gear",
        "region": "Region",
        "fw": "Firmware",
        "hw": "Hardware",
        "err": "Error Code",
        "error": "Error Code",
        "motor": "Motor State",
        "speed_limit": "Speed Limit",
    }

    # Keys with units for formatting
    unit_keys = {
        "spd": "km/h", "speed": "km/h",
        "bat": "%", "battery": "%",
        "cad": "RPM", "rpm": "RPM", "pedal_rpm": "RPM",
        "torque": "Nm", "trq": "Nm", "pedal_torque": "Nm",
        "dst": "km", "odo": "km", "trip": "km",
        "motor_temp": "C", "mt": "C",
        "driver_temp": "C", "dt": "C",
        "module_temp": "C", "temp": "C",
        "humidity": "%", "hum": "%",
        "lux": "lux",
    }

    light_names = {0: "Off", 1: "On", 2: "On", 3: "Auto"}
    level_names = {0: "Off", 1: "1", 2: "2", 3: "3", 4: "4"}

    lines = []
    for key, value in status.items():
        name = key_names.get(key, key)

        if isinstance(value, bool):
            value_str = "Yes" if value else "No"
        elif key in ("light", "light_sensor") and isinstance(value, int) and value in light_names:
            value_str = light_names[value]
        elif key in ("pwr", "assist") and isinstance(value, int):
            value_str = level_names.get(value, str(value))
        elif isinstance(value, bytes):
            value_str = value.hex()
        elif key in unit_keys:
            if isinstance(value, float):
                value_str = f"{value:.1f} {unit_keys[key]}"
            else:
                value_str = f"{value} {unit_keys[key]}"
        else:
            value_str = str(value)

        lines.append(f"      {name}: {value_str}")

    return "\n".join(lines)
