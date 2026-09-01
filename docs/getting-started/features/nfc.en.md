# NFC Card Storage

!!! danger "Proof of concept. Do not put real seeds on these cards."
    This is an experiment in a fork, written to find out whether the idea works
    at all — not a reviewed, audited or finished feature. It has been exercised
    on one board with one card type and has had no security review by anyone.

    Anything built for real use should start from the established practice for
    this problem rather than from this code: NFC tag security, key
    diversification instead of factory keys, replay and cloning resistance, and
    the physical threat model of a backup that answers any reader that comes
    near it. None of that is settled here.

Keeps [KEF-encrypted](encryption/encryption.md) seed backups on NFC cards, read
and written through an external WS1850S module (M5Stack RFID Unit 2) on an I2C
bus. The card is a third destination alongside flash and SD: same envelope, same
password prompt, different medium.

**Off by default.** The driver ships with the firmware, but nothing happens
until the toggle under **Settings → Hardware → NFC → Enabled** is switched on.

---

## The air-gap question

Krux is an air-gapped signer, and NFC is a radio. This feature sits in tension
with that and is deliberately narrow:

- The RF field is energized only inside the "hold a card to the reader" page,
  and dropped when it closes — including when the user cancels or an error is
  shown.
- The reader is attached to the I2C bus lazily, inside that same page. With the
  toggle off, the bus is never even opened, so a module left plugged in is
  untouched rather than merely unused.
- Only the KEF envelope crosses the antenna. The mnemonic is turned into BIP39
  entropy and sealed before the reader is attached, and the reader is detached
  again before the decryption password is asked for.
- The module is external. Unplugged, the feature reports "NFC reader not found"
  and stops.

What it is not: a network interface. There is no routing, no pairing and no
session — the far side is a memory tag a couple of centimetres away.

---

## Wiring

The reader is an [M5Stack RFID Unit 2
(WS1850S)](https://shop.m5stack.com/products/rfid-unit-2-ws1850s) at I2C address
`0x28`. Its Grove HY2.0-4P lead carries SDA (yellow), SCL (white), VCC (red) and
GND (black).

Supply is **3.3 V**, not the 5 V the Grove connector is nominally rated for. The
WS1850S is a 3.3 V part and the K210's logic is 3.3 V, so the whole link runs at
one level. Read range at the lower supply has not been measured — if a card
reads unreliably, suspect the supply first.

Which pins the reader hangs off is a setting, so no board file has to change:

| Setting | Default | Meaning |
|---------|---------|---------|
| `SDA Pin` | the board's TX pin (8 on Yahboom) | data line |
| `SCL Pin` | the board's RX pin (6 on Yahboom) | clock line |

The defaults are the same two pins the [thermal
printer](printing/printing.md) uses, because on most boards they are the only
GPIOs brought out to a header. **A printer and an NFC reader cannot share them.**

Wired to those pins the reader gets its own I2C controller (`I2C1`). Wired
instead to the board's own I2C pins — `I2C_SDA` / `I2C_SCL`, 25 and 24 on
Yahboom — Krux reuses the existing bus, the one the touch controller and PMU are
already on; the WS1850S at `0x28` does not collide with either.

!!! note "Yahboom"
    The pins this was developed against: **SCL to the RX pin (GPIO 6)** and
    **SDA to the TX pin (GPIO 8)**, which is what the settings default to.

---

## Supported tags

| Family | SAK | Usable bytes | Notes |
|--------|-----|--------------|-------|
| MIFARE Classic 1K | `0x08`, `0x88` | 752, capped at 720 | Ships with the RFID2 kit |
| MIFARE Classic 4K | `0x18` | as 1K | Upper sectors have a different layout and are not used |
| Ultralight / NTAG21x | `0x00` | 48–888, capped at 720 | NTAG213 is 144, NTAG215 is 504 |

A KEF-wrapped 24-word seed is well under 100 bytes, so every supported tag has
room to spare. Any other SAK is treated as an empty field.

Classic sectors are authenticated with the factory key A (`FF FF FF FF FF FF`).
The protection is the KEF password, not the sector key — the card stays readable
by any reader, and what a reader finds is ciphertext.

### An NDEF-formatted tag has to be wiped first

A tag that has been NDEF-formatted no longer uses the factory key: the NFC Forum
mapping puts `A0 A1 A2 A3 A4 A5` on the MAD sector and `D3 F7 D3 F7 D3 F7` on
the data sectors, so authentication fails and the tag reads as if it held no
backup. Erasing it with any tag tool (NFC Tools' format/erase, for one) restores
the factory keys. Note that this destroys whatever NDEF content the tag shipped
with.

---

## Card format

A 16-byte header at linear offset 0, payload immediately after:

```
0..3    magic "KRN1"
4       record type (1 = KEF envelope)
5       reserved, must be zero
6..7    payload length, big endian
8..15   reserved, must be zero
```

There is no checksum: the KEF envelope is authenticated, so a half-written or
decaying card fails to decrypt.

### Interoperability with Kern

The magic tags the format, not the device. A card written by Krux reads on the
[Kern](https://github.com/sandman21vs/Kern) NFC branch and vice versa, because
every layer that matters is the same on both sides:

| Layer | Shared |
|-------|--------|
| Record header | 16 bytes, same magic, same field offsets, same 704-byte ceiling |
| Tag addressing | block 0 and sector trailers skipped; Ultralight/NTAG from page 4 |
| Envelope | KEF — `[len_id][id][version][iterations:3 BE][iv][ciphertext][auth]` |
| KEF versions | 0, 1, 5, 6, 7, 10, 11, 12, 15, 16, 20, 21 |
| Plaintext | raw BIP39 entropy, 16 or 32 bytes |

The KEF label is carried inside the envelope and used as the PBKDF2 salt, so
the password prompt behaves identically whichever firmware wrote the card.

`tests/test_nfc_record.py` pins the header bytes with a golden vector. If a
refactor changes what lands on the card, that test fails rather than letting
the two firmwares drift apart silently — both would still be self-consistent,
and only a card handed between devices would reveal the break.

On MIFARE Classic the linear offset skips block 0 and every sector trailer; on
Ultralight/NTAG it starts at page 4. Nothing above the tag layer knows which
kind of card is present.

---

## The card is treated as hostile

A card is input where an attacker picked every byte, and it only has to be held
near the device. Every layer refuses anything that is not exactly what Krux
writes:

- **Reader FIFO** — the reply length is chosen by the tag. Reading `FIFOLevelReg`
  into a smaller buffer is the classic MFRC522 overflow, so a reply that does not
  fit is rejected rather than truncated. Every wait is bounded three times over:
  by the reader's own 25 ms timer, by a wall-clock deadline, and by a poll count.
- **Selection** — SAK is an allowlist, the cascade is capped at two levels, BCC
  is checked. On NTAG the capacity byte is attacker-written, so it is clamped at
  both ends. Writes to block 0 and sector trailers are refused; a corrupted
  trailer bricks its sector permanently.
- **Record header** — validated before anything is allocated, stopping at the
  first divergence: magic, type, reserved bytes (must be zero, denying the field
  as a covert channel), then length against both a compile-time ceiling and the
  tag's real capacity.
- **After decryption** — decrypting does not make the bytes ours. KEF versions
  with a 16-bit hidden auth let a wrong password through roughly once in 65536
  tries, and a planted card could have been encrypted with a password its author
  chose. So the payload passes one narrow gate: raw BIP39 entropy, 16 or 32
  bytes, the single format Krux ever writes to a card.

**What this does not protect against:** a planted card the user accepts, with a
password they get right, loads the attacker's seed. That is the same exposure as
a malicious QR code and the same defence applies — the fingerprint confirmation
screen before the key is used. The filtering above is about the path to that
screen being free of memory corruption, not about deciding whose seed it is.

---

## Using it

**Enable it:** Settings → Hardware → NFC → Enabled. Check the wiring with
Tools → Device Tests → NFC Reader, which probes the bus and detaches again
without ever energizing the antenna.

**Save a backup:** load a mnemonic, then Backup → Encrypted → Store on NFC Card.
The usual KEF prompts run first (password, ID); the card is only asked for once
there is an envelope to write. A card that already holds a backup asks before
being overwritten.

**Load a backup:** Load Mnemonic → From NFC Card. The card is read, the reader
is dropped, and the password is then asked for. The fingerprint confirmation
screen follows as it does for every other load path.

**Erase a card:** Tools → Erase NFC Card. This blanks the record header so the
tag stops presenting a backup. The ciphertext itself stays on the card until
something overwrites it, so treat an erased card the way you would treat a
deleted file on an SD card.
