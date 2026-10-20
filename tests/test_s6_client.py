"""End-to-end tests of main.VanMoofClient and the REPL against a simulated S6."""

import asyncio
import contextlib
import io
import time
import unittest
from unittest import mock

import main
from tests.fake_bike import (FakeS6Bike, FakeBleakClient, fail_on_loop_errors,
                             make_credentials)
from utils import s6_protocol as s6
from utils.s6_protocol import MessageType, Topic

_real_sleep = asyncio.sleep


async def _fast_sleep(delay, *args, **kwargs):
    await _real_sleep(min(delay, 0.01), *args, **kwargs)


class S6TestCase(unittest.IsolatedAsyncioTestCase):

    mtu = 247
    bike_kwargs = {}

    async def asyncSetUp(self):
        fail_on_loop_errors(self)
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        for patch in (mock.patch.object(main, "BleakClient", FakeBleakClient),
                      mock.patch("asyncio.sleep", _fast_sleep)):
            patch.start()
            self.addCleanup(patch.stop)
        self.bike = FakeS6Bike(mtu=self.mtu, **self.bike_kwargs)
        FakeBleakClient.bike = self.bike
        self.client = main.VanMoofClient(make_credentials())
        self.client.REPLY_TIMEOUT = 0.3
        self.client.AUTH_TIMEOUT = 0.5

    async def login(self):
        self.assertTrue(await self.client.connect("AA:BB:CC:DD:EE:FF"))
        self.assertEqual(self.client.bike_model, "S6")
        self.assertTrue(await self.client.authenticate())

    async def run_command(self, cmd):
        self.assertTrue(await main.handle_command(cmd, self.client))

    def assert_clean(self):
        self.assertEqual(self.bike.violations, [])
        self.assertTrue(self.client.connected)


class AuthenticationTests(S6TestCase):

    async def test_login(self):
        await self.login()
        self.assert_clean()
        self.assertTrue(self.bike.authenticated)
        # First message is the certificate as a SET on the AUTH topic.
        first = self.bike.messages[0]
        self.assertEqual((first.type, first.topic), (MessageType.SET, Topic.AUTH))
        self.assertEqual(first.payload, s6.build_certificate_payload(self.client.creds.cert_data))
        # Second is the signature, also a SET on AUTH.
        self.assertEqual((self.bike.messages[1].type, self.bike.messages[1].topic),
                         (MessageType.SET, Topic.AUTH))

    async def test_rejected_certificate(self):
        self.bike.reject_certificate = True
        self.assertTrue(await self.client.connect("AA:BB:CC:DD:EE:FF"))
        self.assertFalse(await self.client.authenticate())
        self.assertIn("Certificate rejected", self.output.getvalue())
        self.assertFalse(self.client.authenticated)

    async def test_rejected_signature_fails_fast(self):
        self.bike.reject_signature = True
        self.assertTrue(await self.client.connect("AA:BB:CC:DD:EE:FF"))
        self.client.AUTH_TIMEOUT = 10.0
        start = time.monotonic()
        self.assertFalse(await self.client.authenticate())
        self.assertLess(time.monotonic() - start, 2.0)
        self.assertIn("rejected", self.output.getvalue().lower())

    async def test_no_reply(self):
        self.bike._on_auth = lambda message: None  # bike stays silent
        self.assertTrue(await self.client.connect("AA:BB:CC:DD:EE:FF"))
        self.assertFalse(await self.client.authenticate())
        self.assertIn("No challenge received", self.output.getvalue())


class SmallMtuTests(S6TestCase):

    mtu = 32

    async def test_login_fragments_certificate(self):
        await self.login()
        self.assert_clean()
        self.assertTrue(all(len(f) <= 29 for f in self.bike.fragments))
        # The certificate (~174 B payload) spans several fragments at this MTU.
        self.assertGreater(len(self.bike.fragments), 6)

    async def test_commands_with_small_mtu(self):
        await self.login()
        await self.run_command("power 3")
        self.assertEqual(self.bike.state[Topic.ASSIST_LEVEL], [3])
        self.assert_clean()


class ReassemblyBitTests(S6TestCase):
    # Some firmwares set the first-fragment bit on every fragment.
    bike_kwargs = {"bit7_on_all": True}

    async def test_login_and_read(self):
        await self.login()
        await self.run_command("query battery")
        self.assertIn("64%", self.output.getvalue())
        self.assert_clean()


class CommandTests(S6TestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.login()

    async def test_status_read_after_login(self):
        # main() reads the status topics; here we do it explicitly.
        await self.client.read_topics(s6.STATUS_TOPICS)
        self.assertEqual(s6.first_field(self.client.topics[Topic.BATTERY_LEVEL]), 64)
        self.assertEqual(s6.first_field(self.client.topics[Topic.LOCK_STATE]), 1)

    async def test_settings(self):
        cases = [
            ("power 0", Topic.ASSIST_LEVEL, [0]),
            ("power 4", Topic.ASSIST_LEVEL, [4]),
            ("lights off", Topic.LIGHT_MODE, [0, 1]),
            ("lights on", Topic.LIGHT_MODE, [2, 1]),
            ("lights auto", Topic.LIGHT_MODE, [3, 1]),
            ("arm", Topic.ALARM, [1]),
            ("disarm", Topic.ALARM, [0]),
            ("bellsound ding_dong", Topic.BELL_SOUND, [2]),
            ("bellsound epic", Topic.BELL_SOUND, [6]),
        ]
        for cmd, topic, expected in cases:
            with self.subTest(cmd=cmd):
                await self.run_command(cmd)
                self.assertEqual(self.bike.state[topic], expected)
        self.assertEqual(self.output.getvalue().count("✅"), len(cases))
        self.assert_clean()

    async def test_setting_confirmed_by_get(self):
        # A bike that applies settings but doesn't publish them back: the
        # client reads the value with GET to confirm.
        self.bike.publish_on_set = False
        await self.run_command("power 3")
        self.assertEqual(self.bike.state[Topic.ASSIST_LEVEL], [3])
        self.assertIn("✅ Assist level: 3", self.output.getvalue())

    async def test_unlock(self):
        await self.run_command("unlock")
        last = self.bike.messages[-1]
        self.assertEqual((last.type, last.topic), (MessageType.SET, Topic.WAKE))
        self.assertEqual(self.bike.state[Topic.LOCK_STATE], [0])
        self.assertIn("Lock state: unlocked", self.output.getvalue())
        self.assert_clean()

    async def test_lock_sends_nothing(self):
        before = len(self.bike.messages)
        await self.run_command("lock")
        self.assertEqual(len(self.bike.messages), before)
        self.assertIn("can't be locked over BLE", self.output.getvalue())

    async def test_queries(self):
        for target, expected in (("lock", "locked"), ("alarm", "off"),
                                 ("lights", "auto"), ("level", "2"),
                                 ("battery", "64%")):
            with self.subTest(target=target):
                self.output.seek(0)
                self.output.truncate(0)
                await self.run_command("query " + target)
                self.assertIn(expected, self.output.getvalue())
        await self.run_command("query all")
        await self.run_command("battery")
        self.assertIn("Battery: 64%", self.output.getvalue())
        self.assert_clean()

    async def test_read_and_write(self):
        await self.run_command("read 0x022a")
        self.assertIn("64%", self.output.getvalue())
        await self.run_command("write 0x0110 3")
        self.assertEqual(self.bike.state[Topic.ASSIST_LEVEL], [3])
        self.assert_clean()

    async def test_bellsound_list(self):
        await self.run_command("bellsound")
        out = self.output.getvalue()
        self.assertIn("ding_dong", out)
        self.assertIn("epic", out)

    async def test_info_and_topics(self):
        await self.client.read_topics(s6.STATUS_TOPICS)
        await self.run_command("info")
        await self.run_command("topics")
        out = self.output.getvalue()
        self.assertIn("Model:         S6", out)
        self.assertIn("lock_state", out)

    async def test_decode(self):
        message = s6.build_message(s6.Message(
            MessageType.PUBLISH, Topic.BATTERY_LEVEL,
            self.bike.wrap([64]), id=3))
        await self.run_command("decode " + message.hex())
        self.assertIn("battery_level", self.output.getvalue())
        self.assertIn("64", self.output.getvalue())

    async def test_telemetry_commands_refused(self):
        before = len(self.bike.fragments)
        for cmd in ("subscribe", "sensors", "modules", "region eu"):
            await self.run_command(cmd)
        self.assertEqual(len(self.bike.fragments), before)
        self.assertIn("Not available on the S6", self.output.getvalue())

    async def test_usage_errors_send_nothing(self):
        before = len(self.bike.messages)
        for cmd in ("power 9", "lights halo", "bellsound nope", "write 0x10000 1",
                    "read", "read zz", "query nope"):
            await self.run_command(cmd)
        self.assertEqual(len(self.bike.messages), before)
        self.assert_clean()

    async def test_errors_topic(self):
        self.bike.state[Topic.ERRORS] = [22]
        await self.run_command("read 0x011f")
        self.assertIn("ERROR: Error 22 was detected", self.output.getvalue())


class UnauthenticatedTests(S6TestCase):

    async def test_commands_need_authentication(self):
        self.assertTrue(await self.client.connect("AA:BB:CC:DD:EE:FF"))
        for cmd in ("unlock", "lights off", "power 2", "query battery"):
            await main.handle_command(cmd, self.client)
        self.assertEqual(self.bike.messages, [])
        self.assertIn("Not authenticated", self.output.getvalue())
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
