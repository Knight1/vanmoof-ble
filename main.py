#!/usr/bin/env python3
"""
VanMoof S5/A5 BLE Client

Communicates with VanMoof S5 and A5 bikes over Bluetooth Low Energy.
Supports authentication, bike control, status queries, and more.

Authentication flow:
    1. Bike sends init: {enc: false, auth: false}
    2. Client echoes init back
    3. Client sends certificate: [frame_byte] 00 [len] 03 [CA_sig] [CBOR]
    4. Bike sends 16-byte challenge
    5. Client signs challenge with Ed25519 private key
    6. Bike confirms: {auth: true}
"""

import asyncio
import argparse
import sys
import time
import datetime
from typing import Optional

from utils.crypto_utils import build_challenge_response
from utils.protocol_utils import build_auth_packet
from utils.credentials_utils import load_credentials, Credentials
from commands import lock, alarm, sound, power, lights, ride, info, region
from commands import telemetry

try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.characteristic import BleakGATTCharacteristic
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
except ImportError:
    sys.exit("pip install bleak")

try:
    import cbor2
except ImportError:
    sys.exit("pip install cbor2")

try:
    import cryptography  # noqa: F401
except ImportError:
    sys.exit("pip install cryptography")


VANMOOF_CHAR_UUID = "e3d80001-3416-4a54-b011-68d41fdcbfcf"


class VanMoofClient:
    """BLE client for VanMoof S5/A5 bikes."""

    def __init__(self, creds: Credentials, debug: bool = False,
                 timestamp: bool = False):
        self.creds = creds
        self.debug = debug
        self.timestamp = timestamp
        self.client: BleakClient = None
        self.char_uuid = VANMOOF_CHAR_UUID
        self.responses: asyncio.Queue = asyncio.Queue()
        self.connected = False
        self.authenticated = False
        self.last_status = {}

    def _timestamp(self) -> str:
        if self.timestamp:
            return f"[{time.time():.6f}] "
        return ""

    def log(self, msg: str):
        if self.debug:
            print(f"{self._timestamp()}[DEBUG] {msg}")

    async def scan(self, timeout: float = 10.0) -> Optional[str]:
        """Scan for VanMoof bikes until first one is found or timeout."""
        print(f"Scanning for VanMoof bikes (max {timeout}s)...")
        found_device = None
        found_event = asyncio.Event()

        def cb(dev: BLEDevice, adv: AdvertisementData):
            nonlocal found_device
            if found_device:
                return
            name = dev.name or adv.local_name or ""
            if any(x in name.upper() for x in ["VANMOOF", "SVTB"]):
                found_device = dev
                found_event.set()
            elif adv.service_uuids and any("e3d8" in u for u in adv.service_uuids):
                found_device = dev
                found_event.set()

        scanner = BleakScanner(detection_callback=cb)
        await scanner.start()
        try:
            await asyncio.wait_for(found_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass
        await scanner.stop()

        if found_device:
            print(f"   Found: {found_device.name or 'VanMoof'} - {found_device.address}")
            return found_device.address
        return None

    def _on_disconnect(self, client: BleakClient):
        self.connected = False
        print("\n   Disconnected")

    def _on_notify(self, sender: BleakGATTCharacteristic, data: bytearray):
        """Handle BLE notifications from the bike."""
        data_bytes = bytes(data)
        hex_str = ' '.join(f'{b:02X}' for b in data_bytes)
        if self.debug:
            display = hex_str
        else:
            display = hex_str[:80] + ('...' if len(hex_str) > 80 else '')
        print(f"\n{self._timestamp()}RX: {display}")

        if len(data_bytes) >= 4:
            msg_type, msg_sub = data_bytes[2], data_bytes[3]

            if msg_type == 0x0D and msg_sub == 0x05:
                # Status message (CBOR encoded)
                for i in range(4, len(data_bytes)):
                    if data_bytes[i] == 0xBF:
                        try:
                            status = cbor2.loads(data_bytes[i:])
                            self.last_status.update(status)
                            print(f"   Status: {status}")
                        except Exception:
                            pass
                        break

            elif msg_type == 0x10 and msg_sub == 0x04:
                print(f"   Challenge ({len(data_bytes) - 4} bytes)")

            elif msg_type == 0x07 and msg_sub == 0x01:
                # Command response - parse payload
                if len(data_bytes) > 4:
                    payload = data_bytes[4:]
                    # Try to decode payload as meaningful data
                    if len(payload) >= 3:
                        group, sub, param = payload[0], payload[1], payload[2]
                        if len(payload) > 3:
                            values = payload[3:]
                            val_hex = ' '.join(f'{b:02X}' for b in values)
                            print(f"   Response: group=0x{group:02X} "
                                  f"sub=0x{sub:02X} param=0x{param:02X} "
                                  f"value={val_hex}")
                        else:
                            print(f"   Response: group=0x{group:02X} "
                                  f"sub=0x{sub:02X} param=0x{param:02X}")
                    else:
                        print(f"   Response")
                else:
                    print(f"   Response (ack)")

            elif msg_type == 0x1F and msg_sub == 0x07:
                # Connection parameters
                for i in range(4, len(data_bytes)):
                    if data_bytes[i] == 0xBF:
                        try:
                            params = cbor2.loads(data_bytes[i:])
                            print(f"   Params: {params}")
                        except Exception:
                            pass
                        break

        self.responses.put_nowait(data_bytes)

    async def connect(self, address: str) -> bool:
        """Connect to a bike by Bluetooth address."""
        print(f"\nConnecting to {address}...")
        self.client = BleakClient(
            address, disconnected_callback=self._on_disconnect
        )

        try:
            await self.client.connect()
            self.connected = True
            print("   Connected")

            # Find the VanMoof characteristic
            for svc in self.client.services:
                for char in svc.characteristics:
                    if "e3d80001" in char.uuid.lower():
                        self.char_uuid = char.uuid

            await self.client.start_notify(self.char_uuid, self._on_notify)
            print("   Notifications enabled")
            return True
        except Exception as e:
            print(f"   Connection failed: {e}")
            return False

    async def disconnect(self):
        """Disconnect from the bike."""
        if self.client and self.client.is_connected:
            await self.client.disconnect()
        print("Disconnected")

    async def send(self, data: bytes, label: str = "") -> bool:
        """Send data to the bike characteristic."""
        if not self.connected:
            print("   Not connected")
            return False

        hex_str = ' '.join(f'{b:02X}' for b in data)
        if self.debug:
            display = hex_str
        else:
            display = hex_str[:80] + ('...' if len(hex_str) > 80 else '')
        print(f"\n{self._timestamp()}TX: {display}"
              + (f" [{label}]" if label else ""))

        try:
            await self.client.write_gatt_char(
                self.char_uuid, data, response=False
            )
            return True
        except Exception as e:
            print(f"   Write failed: {e}")
            return False

    async def recv(self, timeout: float = 3.0) -> Optional[bytes]:
        """Receive a response from the notification queue."""
        try:
            return await asyncio.wait_for(self.responses.get(), timeout)
        except asyncio.TimeoutError:
            return None

    def parse_challenge(self, data: bytes) -> Optional[bytes]:
        """Extract 16-byte challenge from response."""
        if len(data) >= 20 and data[2] == 0x10 and data[3] == 0x04:
            return data[4:20]
        return None

    def parse_auth_status(self, data: bytes) -> Optional[bool]:
        """Extract auth status from CBOR response."""
        for i in range(len(data)):
            if data[i] == 0xBF:
                try:
                    parsed = cbor2.loads(data[i:])
                    return parsed.get("auth")
                except Exception:
                    pass
        return None

    async def authenticate(self) -> bool:
        """
        Authenticate with the bike using certificate + challenge-response.

        Flow:
            1. Wait for init message from bike
            2. Echo init back
            3. Send certificate (CA signature + CBOR payload)
            4. Receive 16-byte challenge
            5. Sign challenge with Ed25519 private key, send signature
            6. Receive auth confirmation
        """
        print("\nAuthenticating...")

        # Wait for init message
        await asyncio.sleep(0.3)
        init = None
        while True:
            msg = await self.recv(0.5)
            if msg:
                init = msg
            else:
                break

        if not self.connected:
            return False

        # Echo init back (preserve the frame byte 0x81 or 0x82)
        if init:
            echo = bytearray(init)
            await self.send(bytes(echo), "echo init")
            await asyncio.sleep(0.1)

        # Send certificate
        first_byte = init[0] if init else 0x81
        cert_pkt = build_auth_packet(self.creds, first_byte)
        await self.send(cert_pkt, "certificate")

        # Wait for challenge
        challenge = None
        for _ in range(10):
            if not self.connected:
                return False
            resp = await self.recv(1.0)
            if not resp:
                continue

            challenge = self.parse_challenge(resp)
            if challenge:
                self.log(f"Challenge: {challenge.hex()}")
                break

            if self.parse_auth_status(resp) is True:
                self.authenticated = True
                return True

        if not challenge:
            print("   No challenge received")
            return False

        # Sign and send challenge response
        response_pkt = build_challenge_response(
            self.creds, challenge, first_byte
        )
        await self.send(response_pkt, "challenge response")

        # Wait for confirmation
        for _ in range(5):
            resp = await self.recv(1.0)
            if resp:
                status = self.parse_auth_status(resp)
                if status is True:
                    print("\n   AUTHENTICATED")
                    self.authenticated = True
                    return True
                elif status is False:
                    print("\n   Auth rejected")
                    return False

        return False


HELP_TEXT = """
Commands:
   Lock / Security:
      unlock               Unlock the bike
      lock                 Lock the bike
      arm                  Arm (enable) alarm
      disarm               Disarm (disable) alarm
      alarm                Trigger alarm sound

   Sound:
      bell                 Bell ding (single)
      bell2                Bell double ding
      horn                 Horn sound
      beep                 Play default sound
      sound <1-N>          Play sound by ID

   Ride Control:
      poweron              Power on bike electronics
      poweroff             Power off bike electronics
      booston              Enable boost mode
      boostoff             Disable boost mode

   Power & Configuration:
      power <0-4>          Set assist level (0=off, 1-4)
      lights <off|on|auto> Set light mode
      region <eu|us|jp>    Set speed region

   Telemetry (real-time sensor data):
      monitor              Start live telemetry display (Ctrl+C to stop)
      sensors              Show last known sensor readings
      subscribe            Activate telemetry stream (powers on bike)

   Information:
      status               Show last received status
      info                 Show bike information
      battery              Query battery level
      services             List BLE GATT services
      query <target>       Query state (lock/alarm/lights/power/boost/level/all)

   Utility:
      raw <hex bytes>      Send raw hex (e.g. raw 81 00 03 01 00 A0 01)
      help                 Show this help
      quit                 Exit

   Telemetry sensors (when streaming):
      speed, pedal RPM, pedal torque, boost button, battery,
      motor temp, driver temp, module temp, light sensor,
      humidity, air quality (S6), assist level, lock state
"""


def print_help():
    print(HELP_TEXT)


async def handle_command(cmd: str, client: VanMoofClient):
    """Dispatch an interactive command."""
    parts = cmd.split()
    if not parts:
        return True

    command = parts[0]

    # Lock / Security
    if command == "unlock":
        await lock.unlock(client)
    elif command == "lock":
        await lock.lock(client)
    elif command in ("arm", "arm_alarm"):
        await alarm.arm_alarm(client)
    elif command in ("disarm", "disarm_alarm"):
        await alarm.disarm_alarm(client)
    elif command in ("alarm", "trigger_alarm"):
        await alarm.trigger_alarm_sound(client)

    # Sound
    elif command == "bell":
        await sound.bell_ding(client)
    elif command == "bell2":
        await sound.bell_double_ding(client)
    elif command == "horn":
        await sound.horn_sound(client)
    elif command in ("beep", "sound"):
        sound_id = 1
        if len(parts) == 2 and parts[1].isdigit():
            sound_id = int(parts[1])
        await sound.play_sound(client, sound_id)

    # Ride control
    elif command == "poweron":
        await ride.power_on_bike(client)
    elif command == "poweroff":
        await ride.power_off_bike(client)
    elif command == "booston":
        await ride.enable_boost(client)
    elif command == "boostoff":
        await ride.disable_boost(client)

    # Power & Configuration
    elif command == "power":
        if len(parts) == 2 and parts[1].isdigit():
            level = int(parts[1])
            await power.set_power_level(client, level)
        else:
            print("Usage: power <0-4>")
    elif command == "lights":
        if len(parts) == 2 and parts[1] in ("off", "on", "auto"):
            await lights.set_lights(client, parts[1])
        else:
            print("Usage: lights <off|on|auto>")
    elif command == "region":
        if len(parts) == 2:
            await region.set_region(client, parts[1])
        else:
            print("Usage: region <eu|us|jp>")

    # Telemetry
    elif command == "monitor":
        await telemetry.start_monitor(client)
    elif command == "sensors":
        telemetry.show_telemetry(client)
    elif command == "subscribe":
        await telemetry.subscribe_telemetry(client)

    # Information
    elif command == "status":
        info.show_last_status(client)
    elif command == "info":
        await info.show_bike_info(client)
    elif command == "battery":
        await info.query_battery(client)
    elif command == "services":
        await info.list_services(client)
    elif command == "query":
        if len(parts) < 2:
            print("Usage: query <lock|alarm|lights|power|boost|level|region|battery|all>")
        else:
            target = parts[1]
            query_map = {
                "lock": info.query_lock_state,
                "alarm": info.query_alarm_state,
                "lights": info.query_light_mode,
                "power": info.query_power_state,
                "boost": info.query_boost_state,
                "level": info.query_power_level,
                "battery": info.query_battery,
                "region": region.query_region,
                "all": info.query_all,
            }
            if target in query_map:
                await query_map[target](client)
            else:
                valid = ", ".join(query_map.keys())
                print(f"Unknown query target. Valid: {valid}")

    # Utility
    elif command == "raw":
        if len(parts) < 2:
            print("Usage: raw <hex bytes>  (e.g. raw 81 00 03 01 00 A0 01)")
        else:
            hex_str = ''.join(parts[1:])
            try:
                data = bytes.fromhex(hex_str)
                await client.send(data, "raw")
                await asyncio.sleep(0.5)
                for _ in range(3):
                    resp = await client.recv(0.5)
                    if not resp:
                        break
            except ValueError:
                print("   Invalid hex string")
    elif command == "help":
        print_help()
    elif command in ("q", "quit", "exit"):
        return False
    else:
        print(f"Unknown command: {cmd}  (type 'help' for commands)")

    return True


async def main():
    parser = argparse.ArgumentParser(
        description="VanMoof S5/A5 BLE Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    Scan for bikes:
        python main.py --scan

    Connect and authenticate:
        python main.py --privkey "BASE64_KEY" --cert "BASE64_CERT"

    With specific MAC address:
        python main.py --privkey "..." --cert "..." --mac "XX:XX:XX:XX:XX:XX"

    With debug output:
        python main.py --privkey "..." --cert "..." --debug --timestamp
"""
    )

    parser.add_argument("--privkey", help="Base64 Ed25519 private key")
    parser.add_argument("--cert", help="Base64 certificate")
    parser.add_argument("--mac", help="Bike Bluetooth address")
    parser.add_argument("--scan", action="store_true",
                        help="Scan for bikes")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug output")
    parser.add_argument("--timestamp", action="store_true",
                        help="Show timestamps")
    parser.add_argument("--ignore-expiry", action="store_true",
                        help="Ignore certificate expiry check")
    args = parser.parse_args()

    if args.scan:
        client = VanMoofClient(None, args.debug, args.timestamp)
        await client.scan(10.0)
        return

    if not args.privkey or not args.cert:
        parser.error("--privkey and --cert are required")

    creds = load_credentials(args.privkey, args.cert)

    # Check certificate expiry
    if creds.expiry:
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        if now > creds.expiry:
            if args.ignore_expiry:
                print("Certificate is expired, but --ignore-expiry is set.")
            else:
                print("Certificate is expired. Use --ignore-expiry to override.")
                return

    client = VanMoofClient(creds, args.debug, args.timestamp)

    mac = args.mac or await client.scan()
    if not mac:
        print("No bike found")
        return

    try:
        if not await client.connect(mac):
            return

        if not await client.authenticate():
            print("Authentication failed")
            return

        print("\n" + "=" * 50)
        print("   VanMoof Bike Connected")
        print("=" * 50)
        print("   Type 'help' for available commands.\n")

        while client.connected:
            try:
                cmd = input("> ").strip().lower()
                if not cmd:
                    continue
                if not await handle_command(cmd, client):
                    break
            except (EOFError, KeyboardInterrupt):
                print()
                break

    finally:
        await client.disconnect()

    print("\nGoodbye!")


if __name__ == "__main__":
    asyncio.run(main())
