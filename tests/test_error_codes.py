"""Tests for utils.error_codes: faithful formatting, no invented S3 table."""

import unittest

from utils import error_codes as ec


class ErrorCodeTests(unittest.TestCase):

    def test_no_error(self):
        self.assertEqual(ec.format_error(0), "No error")

    def test_bare_number(self):
        # The app's own wording; no S3-style description is attached.
        self.assertEqual(ec.format_error(22), "Error 22 was detected")
        self.assertEqual(ec.format_error(54), "Error 54 was detected")
        self.assertNotIn("Motor", ec.format_error(1))
        self.assertNotIn("SIM", ec.format_error(54))

    def test_s6_dtc_hex(self):
        self.assertEqual(ec.format_error(0x9050), "DTC 0x9050")
        self.assertEqual(ec.format_error(0x9000), "DTC 0x9000")
        self.assertEqual(ec.format_error(0x95FF), "DTC 0x95FF")

    def test_is_dtc(self):
        self.assertTrue(ec.is_dtc(0x9000))
        self.assertTrue(ec.is_dtc(0x9FFF))
        for not_dtc in (0, 22, 0x8FFF, 0xA000, True, "0x9050", None, 1.0):
            self.assertFalse(ec.is_dtc(not_dtc))

    def test_non_integer(self):
        # A structured S5/A5 error list is shown as-is, not crashed on.
        self.assertEqual(ec.format_error([1, 2]), "Error: [1, 2]")
        self.assertEqual(ec.format_error(True), "Error: True")

    def test_no_s3_table_remains(self):
        # The module must not carry the old S3 numbered table / visible list.
        for gone in ("ERROR_CODES", "VISIBLE_ERRORS_SX3", "ERROR_CATEGORIES"):
            self.assertFalse(hasattr(ec, gone), f"{gone} should be removed")

    def test_list_all_errors_explains(self):
        text = ec.list_all_errors()
        self.assertIn("S3/X3", text)
        self.assertIn("DTC", text)
        self.assertNotIn("Motor Stalled", text)


if __name__ == "__main__":
    unittest.main()
