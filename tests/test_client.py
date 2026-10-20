"""End-to-end tests of main.VanMoofClient and the REPL commands against a
simulated S5/A5 (see tests/fake_bike.py)."""

import asyncio
import contextlib
import io
import time
import unittest
from unittest import mock

import main
from tests.fake_bike import (FakeBike, FakeBleakClient, FakeService,
                             fail_on_loop_errors, make_credentials)
from utils import protocol_codes as proto
from utils.protocol_codes import PayloadType, Topic

_real_sleep = asyncio.sleep


async def _fast_sleep(delay, *args, **kwargs):
    """asyncio.sleep without the settle times meant for a real bike."""
    await _real_sleep(min(delay, 0.01), *args, **kwargs)


class BikeTestCase(unittest.IsolatedAsyncioTestCase):
    """A VanMoofClient wired to a FakeBike; stdout is captured in self.output."""

    mtu = 247

    async def asyncSetUp(self):
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        for patch in (mock.patch.object(main, "BleakClient", FakeBleakClient),
                      mock.patch("asyncio.sleep", _fast_sleep)):
            patch.start()
            self.addCleanup(patch.stop)
        fail_on_loop_errors(self)
        self.bike = FakeBike(mtu=self.mtu)
        FakeBleakClient.bike = self.bike
        self.creds = make_credentials()
        self.client = main.VanMoofClient(self.creds)
        self.client.REPLY_TIMEOUT = 0.3
        self.client.AUTH_TIMEOUT = 0.5

    async def login(self):
        self.assertTrue(await self.client.connect("AA:BB:CC:DD:EE:FF"))
        self.assertTrue(await self.client.authenticate())
        await self.client.subscribe(proto.STATUS_TOPICS, "subscribe (status)")

    async def run_command(self, cmd):
        self.assertTrue(await main.handle_command(cmd, self.client))

    def assert_clean(self):
        self.assertEqual(self.bike.violations, [])
        self.assertTrue(self.client.connected)


class AuthenticationTests(BikeTestCase):

    async def test_login(self):
        await self.login()
        self.assert_clean()
        # Like the app: the certificate is the first message, with no echo.
        first = self.bike.messages[0]
        self.assertEqual(first, proto.build_certificate_message(self.creds.cert_data))
        self.assertEqual(self.bike.messages[1][0], PayloadType.AUTH_CHALLENGE)
        self.assertTrue(self.bike.authenticated)
        self.assertEqual(self.client.mtu, 247)
        self.assertEqual(self.client.topics[Topic.BATTERY_LEVEL], 38)
        self.assertEqual(self.client.last_status["auth"], True)
        self.assertEqual(self.client.last_status["interval"], 12)

    async def test_rejected_signature_fails_fast(self):
        self.bike.reject_signature = True
        self.assertTrue(await self.client.connect("AA:BB:CC:DD:EE:FF"))
        self.client.AUTH_TIMEOUT = 10.0  # the disconnect must end the wait
        start = time.monotonic()
        self.assertFalse(await self.client.authenticate())
        self.assertLess(time.monotonic() - start, 2.0)
        self.assertIn("Auth rejected", self.output.getvalue())
        self.assertFalse(self.client.authenticated)

    async def test_no_challenge(self):
        self.bike._on_certificate = lambda body: None  # bike stays silent
        self.assertTrue(await self.client.connect("AA:BB:CC:DD:EE:FF"))
        self.assertFalse(await self.client.authenticate())
        self.assertIn("No challenge received", self.output.getvalue())

    async def test_unsupported_bike(self):
        self.bike.services = [FakeService("8e7f1a50-087a-44c9-b292-a2c628fdd9aa", [])]
        self.assertFalse(await self.client.connect("AA:BB:CC:DD:EE:FF"))
        self.assertIn("earlier VanMoof generation", self.output.getvalue())


class SmallMtuTests(BikeTestCase):

    mtu = 23

    async def test_login_fragments_to_mtu(self):
        await self.login()
        self.assert_clean()
        self.assertEqual(self.client.mtu, 23)
        self.assertTrue(all(len(f) <= 20 for f in self.bike.fragments))
        certificate_fragments = [f for f in self.bike.fragments if f[0] == 0x81][0]
        self.assertEqual(certificate_fragments[3], PayloadType.AUTH_CERT)
        self.assertGreater(len(self.bike.fragments), 10)
        self.assertEqual(self.bike.messages[0],
                         proto.build_certificate_message(self.creds.cert_data))

    async def test_commands_with_small_mtu(self):
        await self.login()
        await self.run_command("subscribe all")
        await self.run_command("lights off")
        self.assertEqual(self.bike.state[Topic.LIGHT_MODE], 2)
        self.assert_clean()


class CommandTests(BikeTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.login()

    async def test_settings(self):
        cases = [
            ("lights off", Topic.LIGHT_MODE, 2),
            ("lights on", Topic.LIGHT_MODE, 1),
            ("lights auto", Topic.LIGHT_MODE, 3),
            ("power 0", Topic.ASSIST_LEVEL, 0),
            ("power 4", Topic.ASSIST_LEVEL, 4),
            ("region us", Topic.REGION, 1),
            ("region jp", Topic.REGION, 2),
            ("region offroad", Topic.REGION, 3),
            ("region eu", Topic.REGION, 0),
            ("arm", Topic.ALARM, True),
            ("disarm", Topic.ALARM, False),
            ("bellsound ding_dong", Topic.BELL_SOUND, 0),
            ("bellsound ship_horn", Topic.BELL_SOUND, 4),
        ]
        for cmd, topic, expected in cases:
            with self.subTest(cmd=cmd):
                await self.run_command(cmd)
                self.assertEqual(self.bike.state[topic], expected)
                self.assertEqual(self.client.topics[topic], expected)
        self.assertEqual(self.output.getvalue().count("[OK]"), len(cases))
        self.assert_clean()

    async def test_setting_already_applied(self):
        self.bike._on_topic_write = lambda body: None  # no confirmation
        await self.run_command("power 2")
        self.assertIn("Assist level is already 2", self.output.getvalue())
        await self.run_command("power 1")
        self.assertIn("No confirmation from the bike", self.output.getvalue())

    async def test_setting_changed_to_other_value(self):
        def clamp(body):
            self.bike.publish(Topic.ASSIST_LEVEL, 1)
        self.bike._on_topic_write = clamp
        await self.run_command("power 4")
        self.assertIn("Bike reports assist level 1 (requested 4)", self.output.getvalue())

    async def test_unlock(self):
        await self.run_command("unlock")
        self.assertEqual(self.bike.messages[-1], bytes.fromhex("0100a001"))
        self.assertEqual(self.bike.state[Topic.LOCK_STATE], 3)
        self.assertIn("Lock state: unlocked", self.output.getvalue())
        self.assert_clean()

    async def test_lock_sends_nothing(self):
        before = len(self.bike.messages)
        await self.run_command("lock")
        self.assertEqual(len(self.bike.messages), before)
        self.assertIn("can't be locked over BLE", self.output.getvalue())

    async def test_queries(self):
        for target, expected in (("lock", "locked"), ("power", "standby"),
                                 ("lights", "auto"), ("level", "2"),
                                 ("region", "EU (25 km/h)"), ("alarm", "disabled"),
                                 ("boost", "False")):
            with self.subTest(target=target):
                self.output.seek(0)
                self.output.truncate(0)
                await self.run_command("query " + target)
                self.assertIn(expected, self.output.getvalue())
        await self.run_command("query all")
        await self.run_command("battery")
        self.assertIn("Battery: 38% (raw SoC 40%)", self.output.getvalue())
        self.assert_clean()

    async def test_read_topics_subscribes_once(self):
        await self.client.read_topics([Topic.BOOST])
        await self.client.read_topics([Topic.BOOST])
        subscribes = [m for m in self.bike.messages
                      if m[0] == PayloadType.SUBSCRIBE and m[3:5] == b"\x00\x60"]
        self.assertEqual(len(subscribes), 1)

    async def test_modules(self):
        await self.run_command("modules")
        out = self.output.getvalue()
        for name in proto.ECU_NAMES:
            self.assertRegex(out, r"%s\s+ok" % name)
        self.assertTrue(set(proto.HEARTBEAT_TOPICS) <= self.bike.subscribed)

    async def test_telemetry(self):
        await self.run_command("subscribe")
        self.assertTrue(set(proto.TELEMETRY_TOPICS) <= self.bike.subscribed)
        self.bike.publish(Topic.SPEED, 18)
        await _real_sleep(0.05)
        self.assertEqual(self.client.topics[Topic.SPEED], 18)
        await self.run_command("sensors")
        self.assertRegex(self.output.getvalue(), r"speed\s+18")

    async def test_monitor(self):
        task = asyncio.ensure_future(main.telemetry.start_monitor(self.client))
        await _real_sleep(0.1)
        self.bike.publish(Topic.SPEED, 7)
        await _real_sleep(0.3)
        task.cancel()
        await task
        out = self.output.getvalue()
        self.assertIn("speed=7", out)
        self.assertIn("Monitor stopped", out)
        self.assertFalse(self.client.quiet)

    async def test_unsubscribe(self):
        await self.run_command("subscribe modules")
        await self.run_command("unsubscribe modules")
        await _real_sleep(0.05)  # let the bike process the write
        self.assertFalse(set(proto.HEARTBEAT_TOPICS) & self.bike.subscribed)
        self.assertFalse(set(proto.HEARTBEAT_TOPICS) & self.client.subscribed)

    async def test_write_and_raw(self):
        await self.run_command("write 0x006b 2")
        self.assertEqual(self.bike.state[Topic.LIGHT_MODE], 2)
        await self.run_command("write 111 true")
        self.assertIs(self.bike.state[Topic.ALARM], True)
        await self.run_command("raw 81 00 03 01 00 a0 01")
        self.assertEqual(self.bike.state[Topic.LOCK_STATE], 3)
        self.assert_clean()

    async def test_info_and_status(self):
        await self.run_command("info")
        await self.run_command("status")
        await self.run_command("services")
        await self.run_command("topics")
        out = self.output.getvalue()
        self.assertIn("Role:          Owner (role=7)", out)
        self.assertIn("Authenticated: Yes", out)
        self.assertIn("0x00A1 ux/lock/info/state", out)

    async def test_decode(self):
        await self.run_command("decode 8100040100181826")
        self.assertIn("soc_app) = 38  -> 38%", self.output.getvalue())

    async def test_errors_topic(self):
        await self.client.subscribe([Topic.ERRORS])
        self.bike.publish(Topic.ERRORS, 22)
        await _real_sleep(0.05)
        self.assertIn("ERROR: Error 22 was detected", self.output.getvalue())

    async def test_usage_errors_send_nothing(self):
        before = len(self.bike.messages)
        for cmd in ("power", "power x", "power 9", "power \u00b2", "error \u00b2",
                    "lights halo", "region mars",
                    "bellsound nope", "bellsound", "query", "query nope", "write",
                    "write zz 1", "write 0x10000 1", "subscribe nope",
                    "unsubscribe", "error", "error x", "decode zz", "decode",
                    "raw zz", "raw", "foo", "help", "errors", "error 22"):
            with self.subTest(cmd=cmd):
                await self.run_command(cmd)
        self.assertEqual(len(self.bike.messages), before)
        self.assertFalse(await main.handle_command("quit", self.client))
        self.assert_clean()

    async def test_s5_only_commands_refused_on_s6(self):
        self.client.bike_model = "S6"
        before = len(self.bike.fragments)
        for cmd in ("region eu", "subscribe", "subscribe all", "unsubscribe modules",
                    "modules", "sensors"):
            await self.run_command(cmd)
        self.assertEqual(len(self.bike.fragments), before)
        self.assertIn("Not available on the S6", self.output.getvalue())

    async def test_disconnect_releases_waiters(self):
        waiter = self.client._expect(lambda m: False)
        asyncio.get_running_loop().call_later(0.05, self.bike.drop, "test")
        start = time.monotonic()
        self.assertIsNone(await self.client._wait(waiter, 10.0))
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertFalse(self.client.connected)
        await self.run_command("unlock")
        self.assertIn("Not connected", self.output.getvalue())


class UnauthenticatedTests(BikeTestCase):

    async def test_commands_need_authentication(self):
        self.assertTrue(await self.client.connect("AA:BB:CC:DD:EE:FF"))
        for cmd in ("unlock", "lights off", "subscribe", "write 0x006b 2"):
            await main.handle_command(cmd, self.client)
        self.assertNotIn(PayloadType.TOPIC_CBOR, [m[0] for m in self.bike.messages])
        self.assertIn("Not authenticated", self.output.getvalue())
        self.assert_clean()


class ParserTests(unittest.TestCase):

    def test_parse_topic(self):
        self.assertEqual(main._parse_topic("0x006b"), 0x6B)
        self.assertEqual(main._parse_topic("107"), 107)
        self.assertEqual(main._parse_topic("65535"), 0xFFFF)
        for bad in ("0x10000", "-1", "x", "", "0x"):
            self.assertIsNone(main._parse_topic(bad))

    def test_parse_topics(self):
        self.assertEqual(main._parse_topics(["modules"]), proto.HEARTBEAT_TOPICS)
        self.assertEqual(main._parse_topics(["0x30", "49"]), [0x30, 49])
        self.assertIsNone(main._parse_topics(["status", "nope"]))
        self.assertEqual(main._parse_topics([]), [])

    def test_parse_value(self):
        self.assertIs(main._parse_value("true"), True)
        self.assertIs(main._parse_value("false"), False)
        self.assertEqual(main._parse_value("0x10"), 16)
        self.assertEqual(main._parse_value("-3"), -3)
        self.assertEqual(main._parse_value("abc"), "abc")


if __name__ == "__main__":
    unittest.main()
