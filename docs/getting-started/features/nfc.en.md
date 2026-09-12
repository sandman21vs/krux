# NFC Card Storage

!!! danger "Proof of concept. Do not put real seeds on these cards."
    Not reviewed, not audited, no security review by anyone. Anything built for
    real use should start from the established practice for this problem — NFC
    tag security, key diversification instead of factory keys, replay and
    cloning resistance, and the physical threat model of a backup that answers
    any reader that comes near it. None of that is settled here.

Keeps [KEF-encrypted](encryption/encryption.md) seed backups on NFC cards, read
and written through an external reader module. The card is a third destination
alongside flash and SD: same envelope, same password prompt, different medium.

Two readers are supported, chosen under **Settings → Hardware → NFC → Reader**:
a **WS1850S** on I2C and a **PN5180** on SPI. Which chip is in use is decided in
one place; the tag and record layers above it are the same code either way.

**Off by default.** Nothing happens until **Settings → Hardware → NFC →
Enabled** is switched on.

## The air-gap question

Krux is an air-gapped signer and NFC is a radio, so the exposure is kept as
small as it can be made:

- The RF field is energized only inside the "hold a card to the reader" page,
  and drops on every exit path.
- The reader is attached to its bus lazily, in that same page. With the toggle
  off the bus is never opened, so a module left plugged in is untouched rather
  than merely unused.
- Only the KEF envelope crosses the antenna. The mnemonic is turned into BIP39
  entropy and sealed before the reader is attached, and the reader is detached
  again before the decryption password is asked for.
- The module is external. Unplugged, the feature reports "NFC reader not found".

## Wiring

Supply is **3.3 V** for both modules, not the 5 V a Grove connector is nominally
rated for — if a card reads unreliably, suspect the supply first. Every pin is a
setting, so no board file has to change.

### WS1850S (I2C, two wires)

An [M5Stack RFID Unit 2 (WS1850S)](https://shop.m5stack.com/products/rfid-unit-2-ws1850s)
at I2C address `0x28`.

`SDA Pin` and `SCL Pin` are settings, so no board file has to change. They
default to the board's TX and RX header pins (8 and 6 on Yahboom), which are
also the [thermal printer](printing/printing.md) pins — **a printer and a
reader cannot share them.** On those pins the reader gets its own I2C
controller; wired instead to the board's own `I2C_SDA`/`I2C_SCL`, it reuses the
existing bus, where `0x28` does not collide with the touch controller or PMU.

### PN5180 (SPI, six wires)

`SCK Pin`, `MOSI Pin`, `MISO Pin`, `NSS Pin`, `BUSY Pin` and `RST Pin`. Six
lines is the cost of an SPI reader, and it is the reason this is a pin list
rather than a bus selection: on some boards, notably the Yahboom, the GPIOs are
not on an external header at all and reaching them means soldering to the
connector that holds the K210 module. On the Amigo the defaults put five of the
six on one expansion connector — which also carries GND and 3V3 — and send only
RESET to the other, it being the one line with no timing to lose.

`BUSY` is not optional. The PN5180 gates every transaction on it, and clocking a
command in while it is high returns stale bytes with no error.

Neither SPI controller on a K210 is free — SPI0 drives the LCD and SPI1 the SD
card — so the PN5180 is driven in software at 1 MHz. It is slower than the I2C
reader and that is expected.

Check the wiring with **Tools → Device Tests → NFC Reader**, which probes the
bus and detaches again without energizing the antenna.

## Supported tags

| Family | SAK | Usable bytes |
|--------|-----|--------------|
| MIFARE Classic 1K | `0x08`, `0x88` | 752, capped at 720 |

A KEF-wrapped 24-word seed is under 100 bytes, so every supported tag has room
to spare. Any other SAK reads as an empty field.

Classic sectors use the factory key A (`FF FF FF FF FF FF`). The protection is
the KEF password, not the sector key — the card stays readable by any reader,
and what a reader finds is ciphertext. A tag that has been **NDEF-formatted no
longer uses the factory key** and will read as if it held no backup; erasing it
with any tag tool restores it, destroying whatever NDEF content it shipped with.

## Interoperability with Kern

The record magic tags the format, not the device, so a card written by Krux
reads on the [Kern](https://github.com/sandman21vs/Kern) NFC branch and vice
versa. Every layer that matters is shared: the 16-byte record header, the tag
addressing, the KEF envelope and its version numbers, and a plaintext of raw
BIP39 entropy. `tests/test_nfc.py` pins the header bytes with a golden vector —
without it a refactor could split the two firmwares silently, since both would
stay self-consistent and only a card handed between devices would show it.

## The card is treated as hostile

Every byte comes from whoever handed the user the card, so parsing is an
allowlist and nothing is allocated before the header passes. The reader refuses
a reply that does not fit rather than truncating it (the classic MFRC522
overflow); selection allowlists SAK and checks BCC, and capacity comes from that
allowlist rather than from anything the card claims; writes to block 0 and
sector trailers are refused, because a corrupted trailer bricks its sector
permanently. After decryption the payload
passes one narrow gate: raw BIP39 entropy, 16 or 32 bytes.

**What this does not protect against:** a planted card the user accepts, with a
password they get right, loads the attacker's seed. That is the same exposure as
a malicious QR code, and the same defence applies — the fingerprint confirmation
screen before the key is used.
