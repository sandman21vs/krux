# NFC Card Storage

!!! danger "Proof of concept. Do not put real seeds on these cards."
    Not reviewed, not audited, no security review by anyone. Anything built for
    real use should start from the established practice for this problem — NFC
    tag security, key diversification instead of factory keys, replay and
    cloning resistance, and the physical threat model of a backup that answers
    any reader that comes near it. None of that is settled here.

Keeps [KEF-encrypted](encryption/encryption.md) seed backups and wallet output
descriptors on NFC cards, read and written through an external reader module.
The card is a third destination alongside flash and SD: same envelope, same
password prompt, different medium.

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
- Only the KEF envelope crosses the antenna. The payload is sealed before the
  reader is attached, and the reader is detached again before the decryption
  password is asked for.
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

## What a card can hold

| Record | Written from | Read from |
|--------|--------------|-----------|
| Encrypted mnemonic | Backup → Encrypted → Store on NFC Card | Load Mnemonic → From NFC Card |
| Wallet output descriptor | Wallet Descriptor → Encrypted | Wallet Descriptor → Load from NFC card |

Each record carries a type byte, and a reader asks for the type it can parse, so
a descriptor card offered to the mnemonic loader — or a seed card offered to the
wallet — reads as an empty card. Overwriting still warns for either, because the
question "is something already here" is asked without a type.

### Why descriptors are encrypted only

The plaintext/encrypted choice the descriptor export offers for QR codes and SD
files does not extend to cards. Three reasons, in order of weight:

- **No integrity check.** The on-card format carries no checksum on purpose: the
  KEF envelope authenticates itself, so a half-written or decaying card fails to
  decrypt instead of returning damaged bytes. A descriptor string has no
  checksum of its own to fall back on — Krux writes the descriptor as embit
  serializes it, without the BIP-380 trailer — so a plaintext record on a
  block-addressed, zero-padded medium would have nothing checking it at all.
- **Size.** Sealing deflates before it encrypts. A 2-of-3 is about 450 bytes
  plaintext and a taproot miniscript can pass 880, against a payload ceiling of
  704; compressed they are roughly 345 and 470. Encrypted descriptors fit where
  plaintext ones would not.
- **Privacy.** A descriptor holds every xpub in the wallet, which is its whole
  history. Plaintext means any reader brought near the card gets it.

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
permanently.

Decryption is not acceptance. A KEF version with a 16-bit hidden auth lets a
wrong password through about once in 65536 tries, and a planted card can carry
a password its author chose, so what comes out still has to get past a gate —
and it is the same gate the same data faces arriving by QR code or SD card. For
a mnemonic that is raw BIP39 entropy, 16 or 32 bytes. For a descriptor it is the
descriptor parser, which also decides whether the loaded key is a cosigner. NFC
adds a medium, never a parser and never a shortcut past one.

**What this does not protect against:** a planted card the user accepts, with a
password they get right, loads the attacker's seed. That is the same exposure as
a malicious QR code, and the same defence applies — the fingerprint confirmation
screen before the key is used.
