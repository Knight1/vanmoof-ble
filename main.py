#!/usr/bin/env python3
"""
VanMoof S5/A5/S6 BLE Client

Communicates with VanMoof S5, A5 and S6 bikes over Bluetooth Low Energy: the
S5/A5 Topic/PayloadType protocol (utils/protocol_codes.py) and the S6 message
protocol (utils/s6_protocol.py); see docs/PROTOCOL.md. Supports
authentication, bike control, status queries, and more.

Authentication flow on the S5/A5 (as the official app does it):
    1. Enable notifications on e3d80001; the bike reports AUTH_DETAILS
       {enc: false, auth: false}
    2. Client sends AUTH_CERT: 64-byte CA signature + CBOR payload
    3. Bike sends AUTH_CHALLENGE with a 16-byte nonce
    4. Client sends AUTH_CHALLENGE with its Ed25519 signature of the nonce
    5. Bike reports AUTH_DETAILS {auth: true}; it disconnects on a rejection
    6. Client subscribes to the topics it wants (retained values arrive at once)

On the S6 the same certificate and signature travel as SET messages on the
AUTH topic, and the bike answers with a challenge, then a status.
"""

import asyncio
import argparse
import sys
import time
import warnings
import datetime
from typing import Any, Callable, Iterable, List, Optional

from utils.credentials_utils import load_credentials, Credentials
from utils.error_codes import format_error, list_all_errors
from utils import protocol_codes as proto
from utils import s6_protocol as s6
from utils.protocol_codes import Topic
from commands import lock, alarm, sound, power, lights, info, region
from commands import telemetry

try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.characteristic import BleakGATTCharacteristic
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
except ImportError:
    sys.exit("pip install bleak")

try:
    import cbor2  # noqa: F401
except ImportError:
    sys.exit("pip install cbor2")

try:
    import cryptography  # noqa: F401
except ImportError:
    sys.exit("pip install cryptography")


# S5/A5: Topic protocol. The official app enables notifications on, and writes
# to, the single e3d80001 characteristic.
S5A5_SERVICE_UUID     = proto.SERVICE_UUID
S5A5_CHAR_UUID        = proto.APP_CHAR_UUID

# S6: one df286101 characteristic as well, with its own message protocol.
S6_SERVICE_UUID       = s6.SERVICE_UUID
S6_CHAR_UUID          = s6.APP_CHAR_UUID

# Earlier bike generations (SmartBike, S2/X2 and S3/X3 eras) use the 6acb55xx,
# 6acc55xx and 8e7f1a5x services and other protocols; they are not supported.
LEGACY_SERVICE_PREFIXES = ["8e7f1a5", "6acb55", "6acc55"]

# Known service UUID prefixes for BLE scanning
KNOWN_SERVICE_PREFIXES = ["e3d8", "df2861"]

# Named topic sets for 'subscribe' / 'unsubscribe'.
TOPIC_GROUPS = {
    "status":    proto.STATUS_TOPICS,
    "telemetry": proto.TELEMETRY_TOPICS,
    "modules":   proto.HEARTBEAT_TOPICS,
    "all":       proto.ALL_TOPICS,
}


class VanMoofClient:
    """BLE client for VanMoof S5/A5/S6 bikes."""

    AUTH_TIMEOUT = 10.0   # seconds to wait for each authentication reply
    REPLY_TIMEOUT = 3.0   # seconds to wait for the bike to confirm a write

    def __init__(self, creds: Credentials, debug: bool = False,
                 timestamp: bool = False):
        self.creds = creds
        self.debug = debug
        self.timestamp = timestamp
        self.client: BleakClient = None
        self.char_uuid = None
        self.bike_model = None  # "S5A5", "S6", or None
        self.mtu = 23
        self.connected = False
        self.authenticated = False
        # Link-level CBOR maps from AUTH_DETAILS, PARAM_UPDATE and MTU_UPDATE.
        self.last_status = {}
        self.reassembler = proto.FragmentReassembler()
        self.topics = {}         # topic id -> last decoded value
        self.subscribed = set()  # topic ids the bike was asked to publish
        self.quiet = False       # suppress per-message output (live monitor)
        self._waiters = []       # (match, future) pairs, see _expect()
        # S6 transport state.
        self.s6_reassembler = s6.FragmentReassembler()
        self.s6_message_ids = s6.message_counter()
        self.s6_fragment_ids = s6.fragment_counter()

    def _timestamp(self) -> str:
        if self.timestamp:
            return f"[{time.time():.6f}] "
        return ""

    def log(self, msg: str):
        if self.debug:
            print(f"{self._timestamp()}[DEBUG] {msg}")

    def _format_hex(self, data: bytes) -> str:
        hex_str = ' '.join(f'{b:02X}' for b in data)
        if self.debug:
            return hex_str
        return hex_str[:80] + ('...' if len(hex_str) > 80 else '')

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
            elif adv.service_uuids:
                for u in adv.service_uuids:
                    if any(p in u.lower() for p in KNOWN_SERVICE_PREFIXES):
                        found_device = dev
                        found_event.set()
                        break

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
        # Wake up anything still waiting for a reply that will never come.
        for _, future in self._waiters:
            if not future.done():
                future.set_result(None)

    def _on_notify(self, sender: BleakGATTCharacteristic, data: bytearray):
        """Handle BLE notifications from the bike."""
        data_bytes = bytes(data)
        if self.debug or not self.quiet:
            print(f"\n{self._timestamp()}RX: {self._format_hex(data_bytes)}")

        try:
            if self.bike_model == "S6":
                raw = self.s6_reassembler.feed(data_bytes)
                msg = s6.parse_message(raw) if raw is not None else None
                if raw is not None and msg is None:
                    self.log("S6 message with a bad length or CRC")
            else:
                msg = self.reassembler.feed(data_bytes)
        except Exception as e:
            self.log(f"Undecodable notification: {e}")
            return
        if msg is None:
            return

        if isinstance(msg, s6.Message):
            self._show_s6(msg)
        else:
            self._show(msg)
        for match, future in list(self._waiters):
            if not future.done() and match(msg):
                future.set_result(msg)

    def _show_s6(self, msg: s6.Message):
        """Print a decoded S6 message and record a published value."""
        if msg.topic == s6.Topic.AUTH:
            reply = s6.parse_auth_reply(msg.payload)
            if reply is None:
                print(f"   Auth message ({len(msg.payload)} bytes)")
            elif reply.challenge is not None:
                print(f"   Challenge ({len(reply.challenge)} bytes)")
            else:
                print(f"   Auth status: {reply.status}")
            return
        if msg.type != s6.MessageType.PUBLISH:
            self.log(f"S6 {s6.MessageType(msg.type).name} on {s6.topic_name(msg.topic)}")
            return
        value = s6.decode_payload(msg.payload)
        self.topics[msg.topic] = value
        if not self.quiet:
            pretty = s6.describe_value(msg.topic, value)
            print(f"   {s6.topic_name(msg.topic)} = {pretty}")
        error = s6.first_field(value)
        if (msg.topic == s6.Topic.ERRORS and isinstance(error, int)
                and not isinstance(error, bool) and error != 0):
            print(f"   ERROR: {format_error(error)}")

    def _show(self, msg: proto.S5Message):
        """Print a decoded message and record what it tells us."""
        if isinstance(msg, proto.TopicMessage):
            self.topics[msg.topic] = msg.value
            if not self.quiet:
                pretty = proto.describe_topic_value(msg.topic, msg.value)
                print(f"   {msg.topic_name} = {pretty}")
            if msg.topic == Topic.ERRORS and msg.value not in (None, 0, "", [], {}):
                if isinstance(msg.value, int):
                    print(f"   ERROR: {format_error(msg.value)}")
                else:
                    print(f"   ERROR topic: {msg.value}")
        elif isinstance(msg, proto.AuthMessage):
            self.last_status.update({"auth": msg.authenticated,
                                     "enc": msg.encrypted})
            print(f"   Auth details: auth={msg.authenticated}, "
                  f"link encrypted={msg.encrypted}")
        elif isinstance(msg, proto.ChallengeMessage):
            print(f"   Challenge ({len(msg.nonce)} bytes)")
        elif isinstance(msg, (proto.ParamMessage, proto.MtuMessage)):
            if isinstance(msg.data, dict):
                self.last_status.update(msg.data)
            if not self.quiet:
                label = ("Connection params" if isinstance(msg, proto.ParamMessage)
                         else "Data length")
                print(f"   {label}: {msg.data}")

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

            # Auto-detect bike model from available GATT services
            self.char_uuid = None
            self.bike_model = None
            for svc in self.client.services:
                for char in svc.characteristics:
                    char_lower = char.uuid.lower()
                    if char_lower == S5A5_CHAR_UUID:
                        self.char_uuid = char.uuid
                        self.bike_model = "S5A5"
                    elif char_lower.startswith(s6.APP_CHAR_PREFIX):
                        self.char_uuid = char.uuid
                        self.bike_model = "S6"

            if not self.char_uuid:
                print("   No supported VanMoof service found "
                      "(S5/A5: e3d80000, S6: df286100)")
                if any(prefix in s.uuid.lower() for s in self.client.services
                       for prefix in LEGACY_SERVICE_PREFIXES):
                    print("   This looks like an earlier VanMoof generation "
                          "(pre-S5), which is not supported")
                return False

            self.mtu = await self._negotiated_mtu()
            self.log(f"Using characteristic: {self.char_uuid} "
                     f"({self.bike_model}), MTU {self.mtu}")

            await self.client.start_notify(self.char_uuid, self._on_notify)
            print(f"   Notifications enabled ({self.bike_model})")
            return True
        except Exception as e:
            print(f"   Connection failed: {e}")
            return False

    async def _negotiated_mtu(self) -> int:
        """ATT MTU of the link, so messages are fragmented like the app does."""
        backend = getattr(self.client, "_backend", None)
        if hasattr(backend, "_acquire_mtu"):
            # BlueZ only knows the MTU after acquiring it (see bleak's MTU example).
            try:
                await backend._acquire_mtu()
            except Exception as e:
                self.log(f"Could not acquire MTU: {e}")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                return int(self.client.mtu_size)
            except Exception:
                return 23

    async def disconnect(self):
        """Disconnect from the bike."""
        if self.client and self.client.is_connected:
            await self.client.disconnect()
        print("Disconnected")

    async def send(self, data: bytes, label: str = "") -> bool:
        """Write raw bytes (one BLE fragment) to the bike."""
        if not self.connected:
            print("   Not connected")
            return False

        print(f"\n{self._timestamp()}TX: {self._format_hex(data)}"
              + (f" [{label}]" if label else ""))

        try:
            await self.client.write_gatt_char(self.char_uuid, data, response=False)
            return True
        except Exception as e:
            print(f"   Write failed: {e}")
            return False

    async def send_message(self, payload: bytes, label: str = "") -> bool:
        """Fragment a full [PayloadType][body] message and write it to the bike."""
        for frag in proto.build_fragments(payload, self.mtu - 3):
            if not await self.send(frag, label):
                return False
            label = ""  # only label the first fragment
        return True

    def _expect(self, match: Callable[[Any], bool]):
        """Register interest in the next message satisfying `match`."""
        entry = (match, asyncio.get_running_loop().create_future())
        self._waiters.append(entry)
        return entry

    async def _wait(self, entry, timeout: float):
        """Wait for an _expect() entry; None on timeout or disconnect."""
        try:
            return await asyncio.wait_for(entry[1], timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            self._waiters.remove(entry)

    async def request(self, payload: bytes, match: Callable[[Any], bool],
                      timeout: float, label: str = ""):
        """Send a message and wait for the first reply satisfying `match`."""
        entry = self._expect(match)
        if not await self.send_message(payload, label):
            self._waiters.remove(entry)
            return None
        return await self._wait(entry, timeout)

    def require_auth(self) -> bool:
        """Check that commands can be sent: connected and authenticated."""
        if not self.connected:
            print("   Not connected")
            return False
        if not self.authenticated:
            print("   Not authenticated")
            return False
        return True

    def require_s5(self) -> bool:
        """Check for an authenticated S5/A5, for features only it has."""
        if not self.require_auth():
            return False
        if self.bike_model != "S5A5":
            print("   Not available on the S6")
            return False
        return True

    def topic_name(self, topic: int) -> str:
        """Name of a topic id for the connected model."""
        if self.bike_model == "S6":
            return s6.topic_name(topic)
        return proto.topic_name(topic)

    def describe(self, topic: int, value: Any) -> str:
        """Human-readable value of a topic for the connected model."""
        if self.bike_model == "S6":
            return s6.describe_value(topic, value)
        return proto.describe_topic_value(topic, value)

    # -- S6 transport ------------------------------------------------------ #

    async def send_s6(self, message_type: int, topic: int, payload: bytes = b"",
                      label: str = "") -> bool:
        """Build an S6 message, fragment it and write it to the bike."""
        message = s6.build_message(s6.Message(
            message_type, topic, payload, id=self.s6_message_ids.next()))
        frag_id = self.s6_fragment_ids.next()
        for frag in s6.build_fragments(message, self.mtu - 3, frag_id):
            if not await self.send(frag, label):
                return False
            label = ""  # only label the first fragment
        return True

    async def s6_request(self, message_type: int, topic: int, payload: bytes,
                         match: Callable[[Any], bool], timeout: float,
                         label: str = ""):
        """Send an S6 message and wait for the first reply satisfying `match`."""
        entry = self._expect(match)
        if not await self.send_s6(message_type, topic, payload, label):
            self._waiters.remove(entry)
            return None
        return await self._wait(entry, timeout)

    @staticmethod
    def _s6_publish_of(topic: int) -> Callable[[Any], bool]:
        return lambda m: (isinstance(m, s6.Message) and m.topic == topic
                          and m.type == s6.MessageType.PUBLISH)

    async def s6_get(self, topic: int, timeout: Optional[float] = None) -> Any:
        """Read an S6 topic with GET; the decoded value, or None."""
        reply = await self.s6_request(
            s6.MessageType.GET, topic, b"", self._s6_publish_of(topic),
            self.REPLY_TIMEOUT if timeout is None else timeout,
            f"get {s6.topic_name(topic)}")
        return s6.decode_payload(reply.payload) if reply is not None else None

    async def s6_set(self, topic: int, fields: List[Any],
                     confirm: Optional[int] = None,
                     timeout: Optional[float] = None) -> Any:
        """
        Write an S6 topic with SET. Waits for the bike to publish `confirm`
        (default: the topic itself) and returns that value, or None.
        """
        reply = await self.s6_request(
            s6.MessageType.SET, topic, s6.encode_value(fields),
            self._s6_publish_of(topic if confirm is None else confirm),
            self.REPLY_TIMEOUT if timeout is None else timeout,
            f"set {s6.topic_name(topic)}")
        return s6.decode_payload(reply.payload) if reply is not None else None

    async def s6_apply_setting(self, name: str, topic: int,
                               fields: List[Any]) -> bool:
        """
        Write an S6 setting and report what the bike holds afterwards: the
        value it publishes back, or else the value read back with GET.
        """
        value = await self.s6_set(topic, fields)
        if value is None:
            value = await self.s6_get(topic)
        wanted = s6.describe_value(topic, fields)
        if value is not None and s6.first_field(value) == fields[0]:
            print(f"   [OK] {name}: {wanted}")
            return True
        if value is not None:
            got = s6.describe_value(topic, value)
            print(f"   Bike reports {name.lower()} {got} (requested {wanted})")
            return False
        print(f"   No reply from the bike ({name.lower()} not confirmed)")
        return False

    async def subscribe(self, topics: Iterable[int], label: str = "subscribe",
                        settle: float = 1.0) -> bool:
        """
        Ask the bike to publish `topics`.

        State and setting topics are retained on the bike, so their current
        values arrive right away; `settle` gives them time to come in.
        """
        topics = list(topics)
        if not topics:
            return True
        if not await self.send_message(proto.build_subscribe_message(topics), label):
            return False
        self.subscribed.update(topics)
        if settle:
            await asyncio.sleep(settle)
        return True

    async def unsubscribe(self, topics: Iterable[int],
                          label: str = "unsubscribe") -> bool:
        """Stop the bike from publishing `topics`."""
        topics = list(topics)
        if not await self.send_message(proto.build_unsubscribe_message(topics), label):
            return False
        self.subscribed.difference_update(topics)
        return True

    async def read_topics(self, topics: Iterable[int], timeout: float = 2.0,
                          quiet: bool = True) -> dict:
        """
        Current values of `topics` (None where the bike sent nothing).

        On the S5/A5 reading means subscribing: the retained value is
        delivered on subscribe and later changes keep arriving, so a
        subscribed topic is always up to date. On the S6 every topic is read
        with a GET, like the app does.
        """
        topics = list(topics)
        if self.bike_model == "S6":
            return await self._s6_read_topics(topics, timeout, quiet)
        previous, self.quiet = self.quiet, quiet
        try:
            new = [t for t in topics if t not in self.subscribed]
            if new:
                await self.subscribe(new, "subscribe (read)", settle=0)
            loop = asyncio.get_running_loop()
            deadline = loop.time() + (timeout if new else 0.2)
            while (self.connected and loop.time() < deadline
                   and any(t not in self.topics for t in topics)):
                await asyncio.sleep(0.1)
        finally:
            self.quiet = previous
        return {t: self.topics.get(t) for t in topics}

    async def _s6_read_topics(self, topics: List[int], timeout: float,
                              quiet: bool) -> dict:
        """Send a GET for every topic, then collect the answers."""
        previous, self.quiet = self.quiet, quiet
        try:
            for topic in topics:
                self.topics.pop(topic, None)
                if not await self.send_s6(s6.MessageType.GET, topic, b"",
                                          f"get {s6.topic_name(topic)}"):
                    break
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout
            while (self.connected and loop.time() < deadline
                   and any(t not in self.topics for t in topics)):
                await asyncio.sleep(0.1)
        finally:
            self.quiet = previous
        return {t: self.topics.get(t) for t in topics}

    async def write_topic(self, topic: int, value: Any, label: str = "",
                          confirm: Optional[int] = None,
                          timeout: Optional[float] = None):
        """
        Write `value` to `topic` (normally a .../set topic).

        With `confirm`, wait for the bike to publish that topic and return the
        TopicMessage (None after `timeout`, default REPLY_TIMEOUT). The bike
        only forwards subscribed topics, so `confirm` is subscribed to first if
        needed.
        """
        if timeout is None:
            timeout = self.REPLY_TIMEOUT
        if confirm is not None and confirm not in self.subscribed:
            await self.subscribe([confirm], f"subscribe ({proto.topic_name(confirm)})")
        payload = proto.build_topic_write(topic, value)
        if confirm is None:
            await self.send_message(payload, label)
            return None
        return await self.request(
            payload,
            lambda m: isinstance(m, proto.TopicMessage) and m.topic == confirm,
            timeout, label)

    async def apply_setting(self, name: str, set_topic: int, value: Any,
                            value_topic: int, label: str = "") -> bool:
        """
        Write a setting to its .../set topic and report what the bike applied.

        The owning service on the bike validates the value and re-publishes
        `value_topic`; no reply usually means the certificate's role isn't
        allowed to change this setting.
        """
        reply = await self.write_topic(set_topic, value, label, confirm=value_topic)
        wanted = proto.describe_topic_value(value_topic, value)
        if reply is not None and reply.value == value:
            print(f"   [OK] {name}: {wanted}")
            return True
        if reply is not None:
            got = proto.describe_topic_value(value_topic, reply.value)
            print(f"   Bike reports {name.lower()} {got} (requested {wanted})")
            return False
        if self.topics.get(value_topic) == value:
            print(f"   {name} is already {wanted}")
            return True
        print(f"   No confirmation from the bike ({name.lower()} not changed)")
        return False

    async def authenticate(self) -> bool:
        """
        Authenticate with the bike using certificate + challenge-response.

        Flow:
            1. Send certificate (CA signature + CBOR payload)
            2. Receive 16-byte challenge
            3. Sign challenge with Ed25519 private key, send signature
            4. Receive auth confirmation
        """
        print("\nAuthenticating...")

        # The bike reports AUTH_DETAILS {auth: false} once notifications are
        # on. The official app doesn't echo it; it just sends its certificate.
        await asyncio.sleep(0.3)
        if not self.connected:
            return False
        if self.bike_model == "S6":
            return await self._authenticate_s6()

        reply = await self.request(
            proto.build_certificate_message(self.creds.cert_data),
            lambda m: isinstance(m, proto.ChallengeMessage)
            or (isinstance(m, proto.AuthMessage) and m.authenticated),
            timeout=self.AUTH_TIMEOUT, label="certificate")
        if reply is None:
            if self.connected:
                print("   No challenge received")
            else:
                print("   Bike closed the connection (certificate rejected?)")
            return False

        if isinstance(reply, proto.ChallengeMessage):
            self.log(f"Challenge: {reply.nonce.hex()}")
            reply = await self.request(
                proto.sign_challenge(reply.nonce, self.creds.private_key),
                lambda m: isinstance(m, proto.AuthMessage) and m.authenticated,
                timeout=self.AUTH_TIMEOUT, label="challenge response")
            if reply is None:
                if self.connected:
                    print("   No auth confirmation received")
                else:
                    print("   Auth rejected: bike closed the connection")
                return False

        print("\n   AUTHENTICATED")
        self.authenticated = True
        return True

    async def _authenticate_s6(self) -> bool:
        """
        S6 authentication: SET the certificate on the AUTH topic, sign the
        16-byte challenge the bike answers with, SET the signature, and wait
        for a non-negative status without a challenge.
        """
        def auth_reply(m):
            return (isinstance(m, s6.Message) and m.topic == s6.Topic.AUTH
                    and m.type == s6.MessageType.PUBLISH
                    and s6.parse_auth_reply(m.payload) is not None)

        reply = await self.s6_request(
            s6.MessageType.SET, s6.Topic.AUTH,
            s6.build_certificate_payload(self.creds.cert_data), auth_reply,
            self.AUTH_TIMEOUT, "certificate")
        if reply is None:
            print("   No challenge received" if self.connected
                  else "   Bike closed the connection (certificate rejected?)")
            return False
        answer = s6.parse_auth_reply(reply.payload)
        if answer.rejected:
            print(f"   Certificate rejected (status {answer.status})")
            return False

        if answer.challenge is not None:
            self.log(f"Challenge: {answer.challenge.hex()}")
            reply = await self.s6_request(
                s6.MessageType.SET, s6.Topic.AUTH,
                s6.sign_challenge(answer.challenge, self.creds.private_key),
                auth_reply, self.AUTH_TIMEOUT, "challenge response")
            if reply is None:
                print("   No auth confirmation received" if self.connected
                      else "   Auth rejected: bike closed the connection")
                return False
            answer = s6.parse_auth_reply(reply.payload)
            if not answer.authenticated:
                print(f"   Auth rejected (status {answer.status})")
                return False

        print("\n   AUTHENTICATED")
        self.authenticated = True
        return True


HELP_TEXT = """
Commands:
   Lock / Security:
      unlock               Unlock the bike
      lock                 Explain how the bike locks (no BLE lock command)
      arm                  Enable the alarm
      disarm               Disable the alarm

   Settings:
      power <0-4>          Set assist level (0=off, 1-4)
      lights <off|on|auto> Set light mode
      region <eu|us|jp|offroad>  Set speed region (S5/A5)
      bellsound [tone]     Select the bell tone (no tone: list tones)

   Telemetry (real-time sensor data, S5/A5):
      subscribe [group|topic ...]  Subscribe to topics (default: telemetry;
                           groups: status, telemetry, modules, all)
      unsubscribe <group|topic ...>  Stop topics
      sensors              Show last known readings
      monitor              Live display of changing readings (Ctrl+C to stop)
      modules              Show module status (CAN heartbeats)

   Information:
      status               Show link status (auth, encryption, params)
      info                 Show bike information
      battery              Query battery level
      services             List BLE GATT services
      query <target>       Query state (lock/power/alarm/lights/level/region/boost/battery/all)
      topics               Show all last decoded topic values

   Protocol tools:
      read <topic ...>     Read topic values (e.g. read 0x022a)
      write <topic> <value>  Write a topic value (e.g. write 0x006b 2)
      decode <hex>         Decode an S5/A5 or S6 message or fragment offline
      raw <hex bytes>      Send raw hex (e.g. raw 81 00 03 01 00 A0 01)
      errors               Explain how errors are reported
      error <code>         Format an error number or S6 DTC (e.g. error 0x9050)
      help                 Show this help
      quit                 Exit
"""


def print_help():
    print(HELP_TEXT)


def _parse_topic(text: str) -> Optional[int]:
    """A topic id given as decimal or 0x-prefixed hex."""
    try:
        topic = int(text, 0)
    except ValueError:
        return None
    return topic if 0 <= topic <= 0xFFFF else None


def _parse_topics(args: List[str]) -> Optional[List[int]]:
    """Topic ids from group names (see TOPIC_GROUPS) and/or numbers."""
    topics = []
    for arg in args:
        if arg in TOPIC_GROUPS:
            topics.extend(TOPIC_GROUPS[arg])
            continue
        topic = _parse_topic(arg)
        if topic is None:
            return None
        topics.append(topic)
    return topics


def _parse_value(text: str) -> Any:
    """A CBOR value for 'write': true/false, an integer, or a string."""
    if text in ("true", "false"):
        return text == "true"
    try:
        return int(text, 0)
    except ValueError:
        return text


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

    # Settings
    elif command == "power":
        if len(parts) == 2 and parts[1].isdecimal():
            level = int(parts[1])
            await power.set_power_level(client, level)
        else:
            print("Usage: power <0-4>")
    elif command == "lights":
        if len(parts) == 2 and parts[1] in proto.LIGHT_MODE_VALUES:
            await lights.set_lights(client, parts[1])
        else:
            print("Usage: lights <off|on|auto>")
    elif command == "region":
        if len(parts) == 2:
            await region.set_region(client, parts[1])
        else:
            print("Usage: region <eu|us|jp|offroad>")
    elif command == "bellsound":
        await sound.set_bell_sound(client, parts[1] if len(parts) == 2 else None)

    # Telemetry
    elif command in ("subscribe", "s5sub", "unsubscribe"):
        args = parts[1:]
        if not args and command != "unsubscribe":
            args = ["all"] if command == "s5sub" else ["telemetry"]
        topics = _parse_topics(args)
        if not topics:
            print(f"Usage: {command} [{'|'.join(TOPIC_GROUPS)}|<topic id> ...]")
        elif command == "unsubscribe":
            if client.require_s5():
                await client.unsubscribe(topics)
        elif args == ["telemetry"]:
            await telemetry.subscribe_telemetry(client)
        elif client.require_s5():
            await client.subscribe(topics, f"subscribe ({' '.join(args)})")
    elif command == "monitor":
        await telemetry.start_monitor(client)
    elif command == "sensors":
        telemetry.show_telemetry(client)
    elif command == "modules":
        await telemetry.show_modules(client)

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
            print(f"Usage: query <{'|'.join(info.QUERIES)}>")
        else:
            await info.query(client, parts[1])
    elif command == "topics":
        if not client.topics:
            print("   No topics decoded yet (try 'query all')")
        else:
            for topic in sorted(client.topics):
                pretty = client.describe(topic, client.topics[topic])
                print(f"   0x{topic:04X} {client.topic_name(topic):36s} {pretty}")

    # Protocol tools
    elif command == "read":
        topics = [_parse_topic(arg) for arg in parts[1:]]
        if not topics or None in topics:
            print("Usage: read <topic> [<topic> ...]  (e.g. read 0x022a)")
        elif client.require_auth():
            await client.read_topics(topics)
            info.print_topics(client, topics)
    elif command == "write":
        topic = _parse_topic(parts[1]) if len(parts) == 3 else None
        if topic is None:
            print("Usage: write <topic> <value>  (e.g. write 0x006b 2)")
        elif client.require_auth() and client.bike_model == "S6":
            value = await client.s6_set(topic, [_parse_value(parts[2])])
            if value is not None:
                print(f"   {client.topic_name(topic)} = {client.describe(topic, value)}")
        elif client.authenticated:
            await client.write_topic(topic, _parse_value(parts[2]),
                                     f"write {proto.topic_name(topic)}")
            await asyncio.sleep(1.0)
    elif command == "decode":
        if len(parts) < 2:
            print("Usage: decode <hex bytes>  (a full message or one fragment)")
        else:
            try:
                data = bytes.fromhex(''.join(parts[1:]))
            except ValueError:
                print("   Invalid hex string")
                return True
            # An S6 message is recognised by its CRC, as a single fragment or
            # on its own.
            raw = s6.FragmentReassembler().feed(data) if data[:1] >= b"\x80" else None
            message = s6.parse_message(raw) if raw else None
            message = message or s6.parse_message(data)
            if message is not None:
                value = s6.decode_payload(message.payload)
                print(f"   S6 {s6.MessageType(message.type).name} "
                      f"0x{message.topic:04X} ({s6.topic_name(message.topic)}) "
                      f"id={message.id} = {value!r}  -> "
                      f"{s6.describe_value(message.topic, value)}")
                return True
            # Treat input as a fragment if it has a plausible fragment header,
            # otherwise as an already-reassembled [PayloadType] message.
            decoded = None
            if len(data) >= 3 and (data[0] & 0x80):
                decoded = proto.FragmentReassembler().feed(data)
            if decoded is None:
                decoded = proto.parse_message(data)
            if decoded is None:
                print("   Could not decode (incomplete fragment or unknown type)")
            elif isinstance(decoded, proto.TopicMessage):
                pretty = proto.describe_topic_value(decoded.topic, decoded.value)
                print(f"   Topic 0x{decoded.topic:04X} ({decoded.topic_name}) = "
                      f"{decoded.value!r}  -> {pretty}")
            else:
                print(f"   {decoded}")
    elif command == "raw":
        if len(parts) < 2:
            print("Usage: raw <hex bytes>  (e.g. raw 81 00 03 01 00 A0 01)")
        else:
            hex_str = ''.join(parts[1:])
            try:
                data = bytes.fromhex(hex_str)
            except ValueError:
                print("   Invalid hex string")
                return True
            await client.send(data, "raw")
            await asyncio.sleep(1.0)
    elif command == "errors":
        print(list_all_errors())
    elif command == "error":
        code = None
        if len(parts) == 2:
            try:
                code = int(parts[1], 0)  # decimal, or 0x.. for an S6 DTC
            except ValueError:
                code = None
        if code is None:
            print("Usage: error <code>  (e.g. error 22 or error 0x9050)")
        else:
            print(f"   {format_error(code)}")
    elif command == "help":
        print_help()
    elif command in ("q", "quit", "exit"):
        return False
    else:
        print(f"Unknown command: {cmd}  (type 'help' for commands)")

    return True


async def main():
    parser = argparse.ArgumentParser(
        description="VanMoof S5/A5/S6 BLE Client",
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

        # Like the app: subscribe to (S5/A5) or read (S6) the bike's state
        # right after login.
        if client.bike_model == "S5A5":
            await client.subscribe(proto.STATUS_TOPICS, "subscribe (status)")
        else:
            await client.read_topics(s6.STATUS_TOPICS, quiet=False)

        print("\n   Type 'help' for available commands.\n")

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
