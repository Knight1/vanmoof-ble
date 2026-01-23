#!/usr/bin/env python3
"""
VanMoof S5 BLE Client

Successfully authenticates with VanMoof S5 bikes using: 
1. Certificate from VanMoof API (contains CA signature + CBOR payload)
2. Ed25519 private key (to sign the challenge)

Protocol: 
1. Bike sends init: {enc: false, auth:  false}
2. We echo init back
3. We send certificate: 81 00 A9 03 [CA_sig] [CBOR]
4. Bike sends 16-byte challenge
5. We sign challenge with our private key
6. Bike confirms: {auth: true}
"""

import asyncio
import argparse
import base64

import sys
import time
from typing import Optional
from dataclasses import dataclass

# Utility modules
from utils.crypto_utils import load_private_key, build_challenge_response
from utils.protocol_utils import build_tx_header, build_auth_packet
from utils.credentials_utils import load_credentials, Credentials
# Command group modules
from commands import lock, alarm, sound, power, lights, ride

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
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    sys.exit("pip install cryptography")


VANMOOF_CHAR_UUID = "e3d80001-3416-4a54-b011-68d41fdcbfcf"


@dataclass
class Credentials:
    private_key: Ed25519PrivateKey
    public_key: bytes
    ca_signature: bytes
    cert_cbor: bytes
    cert_id: int = None
    frame: str = None
    expiry: int = None
    role: int = None


class VanMoofClient:
    def __init__(self, creds: Credentials, debug: bool = False, timestamp: bool = False):
        self.creds = creds
        self.debug = debug
        self.timestamp = timestamp
        self.client: BleakClient = None
        self.char_uuid = VANMOOF_CHAR_UUID
        self.responses: asyncio.Queue = asyncio.Queue()
        self.connected = False
        self.authenticated = False

    def _timestamp(self) -> str:
        """Get current timestamp with microsecond precision"""
        if self.timestamp:
            return f"[{time.time():.6f}] "
        return ""

    def log(self, msg: str):
        if self.debug:
            print(f"{self._timestamp()}[DEBUG] {msg}")

    async def scan(self, timeout: float = 1.0) -> Optional[str]:
        print(f"🔍 Scanning for VanMoof bikes ({timeout}s)...")
        found = []

        def cb(dev: BLEDevice, adv: AdvertisementData):
            name = dev.name or adv.local_name or ""
            if any(x in name.upper() for x in ["VANMOOF", "SVTB"]):
                found.append(dev)
            elif adv.service_uuids and any("e3d8" in u for u in adv.service_uuids):
                found.append(dev)

        scanner = BleakScanner(detection_callback=cb)
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()

        for d in found:
            print(f"  📍 {d.name or 'VanMoof'} - {d.address}")
        return found[0].address if found else None

    def _on_disconnect(self, client: BleakClient):
        self.connected = False
        print("\n⚠️  Disconnected")

    def _on_notify(self, sender: BleakGATTCharacteristic, data: bytearray):
        data_bytes = bytes(data)
        hex_str = ' '.join(f'{b:02X}' for b in data_bytes)
        if self.debug:
            display = hex_str
        else:
            display = hex_str[:80] + ('...' if len(hex_str) > 80 else '')
        print(f"\n{self._timestamp()}📥 RX: {display}")
        
        # Decode packet
        if len(data_bytes) >= 4:
            cmd, sub = data_bytes[2], data_bytes[3]
            
            if cmd == 0x0D and sub == 0x05:
                # Status message
                for i in range(4, len(data_bytes)):
                    if data_bytes[i] == 0xBF:
                        try:
                            status = cbor2.loads(data_bytes[i: ])
                            print(f"   Status: {status}")
                        except: 
                            pass
                        break
            elif cmd == 0x10 and sub == 0x04:
                print(f"   🎲 Challenge")
            elif cmd == 0x07 and sub == 0x01:
                print(f"   📍 Command response")
            elif cmd == 0x1F and sub == 0x07:
                for i in range(4, len(data_bytes)):
                    if data_bytes[i] == 0xBF:
                        try:
                            params = cbor2.loads(data_bytes[i:])
                            print(f"   ⚙️  Params: {params}")
                        except:
                            pass
                        break

        self.responses.put_nowait(data_bytes)

    async def connect(self, address: str) -> bool:
        print(f"\n🔗 Connecting to {address}...")
        self.client = BleakClient(address, disconnected_callback=self._on_disconnect)
        
        try:
            await self.client.connect()
            self.connected = True
            print("   ✅ Connected")

            # Find characteristic
            for svc in self.client.services:
                for char in svc.characteristics:
                    if "e3d80001" in char.uuid.lower():
                        self.char_uuid = char.uuid

            await self.client.start_notify(self.char_uuid, self._on_notify)
            print("   🔔 Notifications enabled")
            return True
        except Exception as e:
            print(f"   ❌ Connection failed: {e}")
            return False

    async def disconnect(self):
        if self.client and self.client.is_connected:
            await self.client.disconnect()
        print("🔌 Disconnected")

    async def send(self, data: bytes, label: str = "") -> bool:
        if not self.connected:
            print("   ❌ Not connected")
            return False
        
        hex_str = ' '.join(f'{b:02X}' for b in data)
        if self.debug:
            display = hex_str
        else:
            display = hex_str[:80] + ('...' if len(hex_str) > 80 else '')
        print(f"\n{self._timestamp()}📤 TX: {display}" + (f" [{label}]" if label else ""))

        try:
            await self.client.write_gatt_char(self.char_uuid, data, response=False)
            return True
        except Exception as e:
            print(f"   ❌ Write failed: {e}")
            return False

    async def recv(self, timeout: float = 3.0) -> Optional[bytes]:
        try:
            return await asyncio.wait_for(self.responses.get(), timeout)
        except asyncio.TimeoutError:
            return None

    def parse_challenge(self, data: bytes) -> Optional[bytes]:
        """Extract 16-byte challenge from response"""
        if len(data) >= 20 and data[2] == 0x10 and data[3] == 0x04:
            return data[4:20]
        return None

    def parse_auth_status(self, data: bytes) -> Optional[bool]:
        """Extract auth status from response"""
        for i in range(len(data)):
            if data[i] == 0xBF:
                try:
                    parsed = cbor2.loads(data[i:])
                    return parsed.get("auth")
                except:
                    pass
        return None

    async def authenticate(self) -> bool:
        print("\n🔐 Authenticating...")
        
        # Wait for init
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
        
        # Echo init
        # The received packet might begin with 0x81 or 0x82 (see protocol details).
        # The bike expects an exact echo of the first byte (0x81 or 0x82).
        if init:
            echo = bytearray(init)
            # Echo the first byte as received (0x81 or 0x82)
            await self.send(bytes(echo), "echo")
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

            if self.parse_auth_status(resp) == True:
                self.authenticated = True
                return True
        
        if not challenge:
            print("   ❌ No challenge received")
            return False
        
        # Send challenge response
        response_pkt = build_challenge_response(self.creds, challenge, first_byte)
        await self.send(response_pkt, "response")
        
        # Wait for confirmation
        for _ in range(5):
            resp = await self.recv(1.0)
            if resp:
                status = self.parse_auth_status(resp)
                if status == True:
                    print("\n✅ AUTHENTICATED!")
                    self.authenticated = True
                    return True
                elif status == False: 
                    print("\n❌ Auth rejected")
                    return False
        
        return False





async def main():
    parser = argparse.ArgumentParser(
            description="VanMoof S5 BLE Client",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
    Scan for bikes:
        python main.py --scan

    Connect and authenticate:
        python main.py --privkey "BASE64_KEY" --cert "BASE64_CERT"

    With specific MAC address:
        python main.py --privkey "..." --cert "..." --mac "XX:XX:XX:XX:XX:XX"

Commands (interactive):
    unlock            - Unlock the bike
    lock              - Lock the bike
    arm               - Arm alarm
    disarm            - Disarm alarm
    alarm             - Trigger alarm sound
    beep              - Play a sound (default)
    bell              - Bell ding
    bell2             - Bell double ding
    horn              - Horn sound
    power <0-4>       - Set power level (0=off, 1-4)
    poweron           - Power on bike
    poweroff          - Power off bike
    booston           - Enable boost mode
    boostoff          - Disable boost mode
    lights <off|on|auto> - Set light mode
    quit              - Exit
"""
    )
        

    parser.add_argument("--privkey", help="Base64 Ed25519 private key")
    parser.add_argument("--cert", help="Base64 certificate from VanMoof API")
    parser.add_argument("--mac", help="Bike Bluetooth address")
    parser.add_argument("--scan", action="store_true", help="Scan for bikes")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--timestamp", action="store_true", help="Show timestamps with microsecond precision")
    parser.add_argument("--ignore-expiry", action="store_true", help="Ignore certificate expiry check")
    args = parser.parse_args()

    if args.scan:
        client = VanMoofClient(None, args.debug, args.timestamp)
        await client.scan(1.0)
        return

    if not args.privkey or not args.cert:
        parser.error("--privkey and --cert are required")


    creds = load_credentials(args.privkey, args.cert)

    # Check certificate expiry
    import datetime
    expiry = creds.expiry
    if expiry:
        # expiry is expected to be a UNIX timestamp (seconds)
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        if now > expiry:
            if args.ignore_expiry:
                print("⚠️ Certificate is expired, but --ignore-expiry is set. Continuing...")
            else:
                print("❌ Certificate is expired. Aborting.")
                return

    client = VanMoofClient(creds, args.debug, args.timestamp)

    mac = args.mac or await client.scan()
    if not mac:
        print("❌ No bike found")
        return

    try:
        if not await client.connect(mac):
            return

        if not await client.authenticate():
            print("❌ Authentication failed")
            return

        print("\n" + "="*50)
        print("📱 VanMoof Bike Connected!")
        print("="*50)
        print("\nCommands:")
        print("   unlock            - Unlock the bike")
        print("   lock              - Lock the bike")
        print("   arm               - Arm alarm")
        print("   disarm            - Disarm alarm")
        print("   alarm             - Trigger alarm sound")
        print("   beep              - Play a sound (default)")
        print("   bell              - Bell ding")
        print("   bell2             - Bell double ding")
        print("   horn              - Horn sound")
        print("   power <0-4>       - Set power level (0=off, 1-4)")
        print("   poweron           - Power on bike")
        print("   poweroff          - Power off bike")
        print("   booston           - Enable boost mode")
        print("   boostoff          - Disable boost mode")
        print("   lights <off|on|auto> - Set light mode")
        print("   quit              - Exit")
        print()
        
        while client.connected:
            try:
                cmd = input("> ").strip().lower()

                if cmd in ("q", "quit", "exit"):
                    break
                elif cmd == "unlock":
                    await lock.unlock(client)
                elif cmd == "lock":
                    await lock.lock(client)
                elif cmd in ("arm", "arm_alarm"):
                    await alarm.arm_alarm(client)
                elif cmd in ("disarm", "disarm_alarm"):
                    await alarm.disarm_alarm(client)
                elif cmd in ("alarm", "trigger_alarm"):
                    await alarm.trigger_alarm_sound(client)
                elif cmd in ("beep", "sound"):
                    await sound.play_sound(client, 1)
                elif cmd == "bell":
                    await sound.bell_ding(client)
                elif cmd == "bell2":
                    await sound.bell_double_ding(client)
                elif cmd == "horn":
                    await sound.horn_sound(client)
                elif cmd.startswith("power"):
                    parts = cmd.split()
                    if len(parts) == 2 and parts[1].isdigit():
                        await power.set_power_level(client, int(parts[1]))
                    else:
                        print("Usage: power <0-4>")
                elif cmd == "poweron":
                    await ride.power_on_bike(client)
                elif cmd == "poweroff":
                    await ride.power_off_bike(client)
                elif cmd == "booston":
                    await ride.enable_boost(client)
                elif cmd == "boostoff":
                    await ride.disable_boost(client)
                elif cmd.startswith("lights"):
                    parts = cmd.split()
                    if len(parts) == 2 and parts[1] in ("off", "on", "auto"):
                        await lights.set_lights(client, parts[1])
                    else:
                        print("Usage: lights <off|on|auto>")
                elif cmd == "":
                    pass
                else:
                    print(f"Unknown command: {cmd}")
                    
            except (EOFError, KeyboardInterrupt):
                print()
                break
                
    finally:
        await client.disconnect()

    print("\n👋 Goodbye!")


if __name__ == "__main__":
    asyncio.run(main())
