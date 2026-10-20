"""
VanMoof S5/A5/S6 error reporting.

There is no public table that maps a VanMoof error number to a description for
these bikes:

  - The official app does not name them. It shows the raw number
    ("Error %1d was detected", string ``notification_bike_error_title``); the
    descriptions users see come from VanMoof's support material, not the app.
  - The S5/A5 report errors on the MQTT ``error/#`` subtree (per service), and
    the errors topic the app subscribes to (id ``0x00FF``) carries a list.
    Going over the S5 firmware decomp (v1.5.0) confirms there is no numbered
    error->meaning table in it: errors surface as the per-service channels
    ``service/{power,ux,monitor,update}/error`` (ids 0x0200-0x0203, JSON/string,
    not a numbered code); the battery exposes a generic-fault bit and a UVP
    (under-voltage / empty-pack) fault that gate reset/charging, but the full
    ~33 status + ~20 warning bit names are runtime-initialised strings absent
    from the static image; and the charger's 8-entry fault table lives in flash
    off the decompiled slice (``CHG_FAULT_TABLE`` 0x80b0), so its codes aren't
    recoverable either.
  - The S6 reports Diagnostic Trouble Codes (DTCs) — 16-bit hex codes in the
    ``0x9000``–``0x95ff`` range (e.g. ``0x9050``–``0x9053`` around battery
    charging). Its firmware decodes each DTC to a ``<device> <name>`` string
    through a large internal table that has not been recovered.

The older numbered scheme (motor 1–8, BMS 9–20, …) belongs to the S3/X3
generation, not these bikes, so it is deliberately not reproduced here: showing
an S3 description for an S5/A5/S6 error number would be misleading. This module
therefore reports errors faithfully — the bare number, or the DTC in hex — the
way the bike and the app present them.

Functions:
    format_error(code):  One-line rendering of an error value from the bike
    list_all_errors():    Explanation of the error model (no invented table)
"""

# S6 DTCs are 16-bit hex codes; everything observed falls in this range.
DTC_MIN = 0x9000
DTC_MAX = 0x9FFF


def is_dtc(code) -> bool:
    """True if `code` looks like an S6 Diagnostic Trouble Code."""
    return isinstance(code, int) and not isinstance(code, bool) and DTC_MIN <= code <= DTC_MAX


def format_error(code) -> str:
    """
    Render an error value from the bike as the bike/app present it:
    ``No error`` for 0, a hex ``DTC`` for an S6 trouble code, otherwise the
    app's bare ``Error N``. Non-integers (e.g. a structured S5/A5 error list)
    are shown as-is.
    """
    if code == 0:
        return "No error"
    if is_dtc(code):
        return f"DTC 0x{code:04X}"
    if isinstance(code, bool) or not isinstance(code, int):
        return f"Error: {code}"
    return f"Error {code} was detected"


def list_all_errors() -> str:
    """Explain how errors are reported (there is no public code->name table)."""
    return (
        "VanMoof does not publish a code->description table for the S5/A5/S6.\n"
        "\n"
        "   - The app shows the bare number: \"Error N was detected\".\n"
        "   - S5/A5 report errors on the MQTT 'error/#' subtree (topic 0x00FF\n"
        "     carries a list); S6 reports hex DTCs (0x9000-0x95FF, e.g.\n"
        "     0x9050-0x9053 around battery charging).\n"
        "   - The old numbered list (motor 1-8, BMS 9-20, ...) is the S3/X3\n"
        "     scheme and does not apply to these bikes.\n"
        "\n"
        "   This tool shows whatever the bike reports. Look the number up in\n"
        "   VanMoof's support material for its meaning."
    )
