## BLE Service Information

### S5 / A5

The S5/A5 uses a single custom service. All messages flow through one
characteristic: the client enables notifications on it and writes to it (see
[PROTOCOL.md](PROTOCOL.md) for the Topic / PayloadType protocol it carries).

| Property               | UUID                                         |
|------------------------|----------------------------------------------|
| **Service**            | `e3d80000-3416-4a54-b011-68d41fdcbfcf`       |
| App (notify + write)   | `e3d80001-3416-4a54-b011-68d41fdcbfcf`       |

The official app scans for this service UUID, enables notifications on
`e3d80001` and writes every message there. Some community clients prefer
`e3d80002` for writes when it is exposed; the app never uses it.

Firmware updates don't use a separate GATT service on the S5/A5: the app
transfers images over the same characteristic using FTP topics.

> **Note:** The `8e7f1a5x` service (Challenge `8e7f1a51`, New Private Key
> `8e7f1a52`, Functions `8e7f1a53`, Parameters `8e7f1a54`) and the TI OAD
> service (`f000ffc0`) belong to the earlier bike generations (S3/X3 era),
> which the official app handles with separate profiles. They are not part of
> the S5/A5 and are not supported by this tool.

### S6

The S6 uses the same single-characteristic design as the S5/A5, with its own
service UUID and its own message protocol (see [PROTOCOL.md](PROTOCOL.md)).

| Property               | UUID                                         |
|------------------------|----------------------------------------------|
| **Service**            | `df286100-1440-48a1-88f1-247d7f7d274d`       |
| App (notify + write)   | `df286101-1440-48a1-88f1-247d7f7d274d`       |

The official app scans for this service UUID, enables notifications on the
`df286101` characteristic and writes every message there. Field captures of a
retail S6 report the same service with a different 128-bit base
(`df286100-6003-11e5-9260-0002a5d5c51b`); this tool matches the characteristic
by its `df286101` prefix so either base works. The app also exposes a
read-only data service (`87290102-3c51-43b1-a1a9-11b9dc38478b`) and standard TX
Power, which this tool doesn't use.

> **Note:** The `6acb55xx` and `6acc55xx` services (and the `8e7f1a5x` service)
> belong to earlier VanMoof generations (SmartBike, S2/X2 and S3/X3 eras), not
> the S6. They are not supported by this tool. Earlier revisions of this
> document listed a granular `6acb`/`6acc` characteristic map for the "S6"; that
> was a misattribution.

---