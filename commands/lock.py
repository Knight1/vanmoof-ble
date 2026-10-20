"""
VanMoof S5/A5/S6 BLE Lock/Unlock Commands

Provides functions to unlock the bike via BLE.

Functions:
    unlock(client): Unlock the bike
    lock(client):   Explain how the bike locks (there is no BLE lock command)

Each function expects an authenticated VanMoofClient instance.

| Model | Function | Topic                          | Value  |
|-------|----------|--------------------------------|--------|
| S5/A5 | unlock   | 0x00A0 ux/lock/unlock          | 1      |
| S6    | unlock   | 0x010C wake (SET)              | [1]    |

The official app unlocks with exactly these writes and has no lock command:
the e-lock is engaged on the bike itself. The bike reports the result on
0x00A1 ux/lock/info/state (S5/A5) or 0x0112 lock_state (S6).
"""
from utils import protocol_codes as proto
from utils import s6_protocol as s6
from utils.protocol_codes import Topic


async def unlock(client):
    """Unlock the bike (S5/A5: 0x00A0 ux/lock/unlock = 1, S6: wake)"""
    if not client.require_auth():
        return
    print("\n🔓 Unlocking...")
    if client.bike_model == "S6":
        # The app unlocks the S6 by waking it; the bike then publishes its
        # lock state.
        state = await client.s6_set(s6.Topic.WAKE, [1], confirm=s6.Topic.LOCK_STATE,
                                    timeout=5.0)
        if state is None:
            state = await client.s6_get(s6.Topic.LOCK_STATE)
        if state is not None:
            print(f"   Lock state: {s6.describe_value(s6.Topic.LOCK_STATE, state)}")
        else:
            print("   No lock-state update from the bike")
        return
    reply = await client.write_topic(Topic.UNLOCK, 1, "unlock",
                                     confirm=Topic.LOCK_STATE, timeout=5.0)
    if reply is not None:
        state = proto.describe_topic_value(Topic.LOCK_STATE, reply.value)
        print(f"   Lock state: {state}")
    elif proto.is_locked(client.topics.get(Topic.LOCK_STATE)) is False:
        print("   Already unlocked")
    else:
        print("   No lock-state update from the bike")


async def lock(client):
    """There is no BLE lock command; explain instead of sending one."""
    print("\n   The bike can't be locked over BLE: the official app has no lock")
    print("   command and the bike is locked on the e-lock itself. Use 'query lock'")
    print("   to see the current state.")
