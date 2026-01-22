sound.py - VanMoof S5/A5 BLE sound/feedback commands
## This file has been merged into commands/sound.py and is now deprecated.
    await asyncio.sleep(0.5)
    for _ in range(3):
        resp = await client.recv(0.5)
        if not resp:
            break
