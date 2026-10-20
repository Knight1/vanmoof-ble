"""
VanMoof S5/A5/S6 BLE Information & Status Commands

Query bike state, read device information, and display status.

Reading a value on the S5/A5 means subscribing to its topic: states and
settings are retained on the bike, so the current value is delivered as soon
as the subscription is made. The S6 is read with a GET per topic (see
VanMoofClient.read_topics).

Functions:
    query(client, target):      Query one state (see QUERIES) or 'all'
    query_battery(client):      Query battery level
    read_device_info(client):   Read GATT device information (firmware, model, etc.)
    list_services(client):      List all GATT services and characteristics
    show_bike_info(client):     Display comprehensive bike information
    show_last_status(client):   Display the link-level status the bike reported

Query reference:
    | Query    | Topic                                              |
    |----------|----------------------------------------------------|
    | lock     | 0x00A1 ux/lock/info/state                          |
    | power    | 0x0001 power/state                                 |
    | alarm    | 0x006E settings/alarm                              |
    | lights   | 0x006A settings/light_mode                         |
    | level    | 0x0065 settings/assist_level                       |
    | region   | 0x0061 settings/region                             |
    | boost    | 0x0060 ride/boost                                  |
    | battery  | 0x0018 .../soc_app (app %), 0x0010 .../soc (raw %) |

    On the S6: lock 0x0112, alarm 0x0172, lights 0x0131, level 0x0110,
    battery 0x022A (see S6_QUERIES).
"""

import datetime

from utils import protocol_codes as proto
from utils import s6_protocol as s6
from utils.protocol_codes import Topic


# Standard BLE Device Information Service characteristic UUIDs
DIS_CHARS = {
    "00002a29": "Manufacturer",
    "00002a24": "Model",
    "00002a25": "Serial Number",
    "00002a26": "Firmware",
    "00002a27": "Hardware Rev",
    "00002a28": "Software Rev",
}

QUERIES = {
    "lock":    [Topic.LOCK_STATE],
    "power":   [Topic.POWER_STATE],
    "alarm":   [Topic.ALARM],
    "lights":  [Topic.LIGHT_MODE],
    "level":   [Topic.ASSIST_LEVEL],
    "region":  [Topic.REGION],
    "boost":   [Topic.BOOST],
    "battery": [Topic.BATTERY_LEVEL, Topic.BATTERY_SOC],
    "all":     proto.STATUS_TOPICS,
}

S6_QUERIES = {
    "lock":    [s6.Topic.LOCK_STATE],
    "alarm":   [s6.Topic.ALARM],
    "lights":  [s6.Topic.LIGHT_MODE],
    "level":   [s6.Topic.ASSIST_LEVEL],
    "battery": [s6.Topic.BATTERY_LEVEL],
    "all":     s6.STATUS_TOPICS,
}


def print_topics(client, topics):
    """Print the last known value of each topic."""
    for topic in topics:
        if topic in client.topics:
            shown = client.describe(topic, client.topics[topic])
        else:
            shown = "(no report)"
        print(f"   {client.topic_name(topic):36s} {shown}")


async def query(client, target: str):
    """Query a state by name (see QUERIES and S6_QUERIES)."""
    queries = S6_QUERIES if client.bike_model == "S6" else QUERIES
    topics = queries.get(target)
    if topics is None:
        print(f"Unknown query target. Valid: {', '.join(queries)}")
        return
    if not client.require_auth():
        return
    print(f"\nQuerying {target}...")
    await client.read_topics(topics)
    print_topics(client, topics)


async def _read_gatt_battery(client):
    """Battery level from the standard BLE Battery Service, if exposed."""
    for svc in client.client.services:
        for char in svc.characteristics:
            if "2a19" in char.uuid.lower():
                try:
                    data = await client.client.read_gatt_char(char.uuid)
                    if data:
                        return data[0]
                except Exception as e:
                    client.log(f"Battery service read failed: {e}")
    return None


async def query_battery(client):
    """
    Query battery level.

    On the S5/A5 this reads the battery topics (the percentage the app shows,
    plus the raw state of charge). Falls back to the standard BLE Battery
    Service characteristic (0x2A19) if the bike exposes one.
    """
    if not client.authenticated:
        print("   Not authenticated")
        return

    print("\nQuerying battery...")

    if client.bike_model == "S6":
        level = s6.first_field(
            (await client.read_topics([s6.Topic.BATTERY_LEVEL]))[s6.Topic.BATTERY_LEVEL])
        if level is not None:
            print(f"   Battery: {level}%")
            return level

    if client.bike_model == "S5A5":
        values = await client.read_topics(QUERIES["battery"])
        level = values[Topic.BATTERY_LEVEL]
        soc = values[Topic.BATTERY_SOC]
        if level is not None:
            extra = f" (raw SoC {soc}%)" if soc is not None else ""
            print(f"   Battery: {level}%{extra}")
            return level
        if soc is not None:
            print(f"   Battery (raw SoC): {soc}%")
            return soc

    if client.client and client.connected:
        level = await _read_gatt_battery(client)
        if level is not None:
            print(f"   Battery: {level}% (BLE Battery Service)")
            return level

    print("   No battery data available.")


async def read_device_info(client):
    """
    Read device information from standard BLE GATT services.

    Reads from the Device Information Service (0x180A) and Battery
    Service (0x180F) if available. Returns a dict of discovered info.
    """
    if not client.client or not client.connected:
        print("   Not connected")
        return {}

    info = {}

    try:
        services = client.client.services
    except Exception:
        return info

    for svc in services:
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
                    except Exception as e:
                        client.log(f"Failed to read {name}: {e}")

            # Battery Level
            if "2a19" in uuid_lower:
                try:
                    data = await client.client.read_gatt_char(char.uuid)
                    if data:
                        info["Battery"] = f"{data[0]}%"
                except Exception as e:
                    client.log(f"Failed to read battery: {e}")

    return info


async def list_services(client):
    """List all GATT services and characteristics on the connected device."""
    if not client.client or not client.connected:
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
        role_name = proto.ROLE_NAMES.get(client.creds.role, "unknown role")
        print(f"   Role:          {role_name} (role={client.creds.role})")
        if client.creds.expiry:
            dt = datetime.datetime.fromtimestamp(
                client.creds.expiry, tz=datetime.timezone.utc
            )
            print(f"   Cert Expiry:   {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # Connection state
    print(f"\n   Model:         {client.bike_model or 'Unknown'}")
    print(f"   Connected:     {client.connected}")
    print(f"   Authenticated: {client.authenticated}")
    print(f"   ATT MTU:       {client.mtu}")

    # GATT device info
    gatt_info = await read_device_info(client)
    if gatt_info:
        print("\n   Device Info (GATT):")
        for name, value in gatt_info.items():
            print(f"      {name}: {value}")

    # Last known bike state
    state_topics = s6.STATUS_TOPICS if client.bike_model == "S6" else proto.STATUS_TOPICS
    known = [t for t in state_topics if t in client.topics]
    if known:
        print("\n   Bike State:")
        print_topics(client, known)

    print()


def show_last_status(client):
    """Display the link-level status the bike reported."""
    if not client.last_status:
        print("\n   No status received yet.")
        return

    print("\n" + "=" * 40)
    print("   Link Status")
    print("=" * 40)
    print(format_status(client.last_status))
    print(f"      Subscribed Topics: {len(client.subscribed)}")
    print()


def format_status(status: dict) -> str:
    """Format the AUTH_DETAILS / PARAM_UPDATE / MTU_UPDATE maps for display."""
    key_names = {
        # AUTH_DETAILS
        "auth": "Authenticated",
        "enc": "Link Encrypted",
        # PARAM_UPDATE (connection parameters)
        "interval": "Conn Interval",
        "latency": "Peripheral Latency",
        "timeout": "Supervision Timeout",
        # MTU_UPDATE (data length parameters)
        "tx_max_len": "TX Max Length",
        "tx_max_time": "TX Max Time",
        "rx_max_len": "RX Max Length",
        "rx_max_time": "RX Max Time",
        "err": "Error",
    }

    lines = []
    for key, value in status.items():
        name = key_names.get(key, key)
        if isinstance(value, bool):
            value_str = "Yes" if value else "No"
        elif isinstance(value, bytes):
            value_str = value.hex()
        else:
            value_str = str(value)
        lines.append(f"      {name}: {value_str}")

    return "\n".join(lines)
