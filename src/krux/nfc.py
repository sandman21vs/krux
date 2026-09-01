# The MIT License (MIT)

# Copyright (c) 2021-2024 Krux contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""NFC card storage - KEF envelopes on ISO14443A tags.

Reader: WS1850S (M5Stack RFID Unit 2) on an I2C bus opened from the pins
configured under Settings > Hardware > NFC. Tags: MIFARE Classic 1K/4K and
Ultralight/NTAG21x, presented to callers as one flat byte array.

A card is input where an attacker picked every byte, and it only has to be held
near the device. Every layer here refuses anything that is not exactly what
Krux writes.

Record layout - 16 byte header at linear offset 0, payload right after:

    0..3    magic "KRN1"
    4       record type (RECORD_KEF)
    5       reserved, must be zero
    6..7    payload length, big endian
    8..15   reserved, must be zero

The magic tags the format, not the device. It is shared with the Kern NFC
branch, which originated this layout, so a card written by either firmware
reads on the other. There is no checksum: the KEF envelope is authenticated, so
a half-written or decaying card fails to decrypt.
"""

import time
import board

WS1850S_ADDR = 0x28
I2C_FREQ = 400000

HEADER_LEN = 16
RECORD_MAGIC = b"KRN1"
RECORD_KEF = 1

# Largest payload Krux will read off a card, whatever the card claims to hold.
# A KEF-wrapped 24 word seed is under 100 bytes; the ceiling stops a hostile tag
# from driving a large allocation on a device with about 1 MB of heap.
MAX_PAYLOAD = 704

# The reader's FIFO is 64 bytes; no frame can exceed it. A CRC_A is two bytes,
# and receive buffers must have room for it: the CRC arrives with the frame.
FIFO_SIZE = 64
CRC_LEN = 2

# PICC commands
CMD_WUPA = 0x52
CMD_HALT = 0x50
CMD_SEL_CL1 = 0x93
CMD_SEL_CL2 = 0x95
CMD_AUTH_KEY_A = 0x60
CMD_READ = 0x30
CMD_MF_WRITE = 0xA0
CMD_UL_WRITE = 0xA2

# Registers (MFRC522 compatible)
REG_COMMAND = 0x01
REG_COM_IRQ = 0x04
REG_DIV_IRQ = 0x05
REG_ERROR = 0x06
REG_STATUS2 = 0x08
REG_FIFO_DATA = 0x09
REG_FIFO_LEVEL = 0x0A
REG_CONTROL = 0x0C
REG_BIT_FRAMING = 0x0D
REG_MODE = 0x11
REG_TX_CONTROL = 0x14
REG_TX_ASK = 0x15
REG_CRC_RESULT_H = 0x21
REG_CRC_RESULT_L = 0x22
REG_T_MODE = 0x2A
REG_T_PRESCALER = 0x2B
REG_T_RELOAD_H = 0x2C
REG_T_RELOAD_L = 0x2D

# Reader commands
PCD_IDLE = 0x00
PCD_CALC_CRC = 0x03
PCD_TRANSCEIVE = 0x0C
PCD_AUTHENT = 0x0E
PCD_RESET = 0x0F

# Any fatal ErrorReg bit means the frame is garbage. CRCErr is excluded because
# framing without a CRC legitimately leaves it set.
ERR_FATAL_MASK = 0x1B  # BufferOvfl | Coll | Parity | Protocol

IRQ_TIMER = 0x01
IRQ_IDLE = 0x10
IRQ_RX = 0x20

# An exchange is bounded three times over: the reader's own 25 ms timer, a wall
# clock deadline in case the reader stops answering, and a poll cap so a clock
# that never advances still cannot spin forever.
EXCHANGE_TIMEOUT_MS = 60
CRC_TIMEOUT_MS = 20
MAX_POLLS = 4000

# SAK values Krux accepts. Anything else reads as an empty field: the point is
# to talk only to what we know how to talk to.
SAK_ULTRALIGHT = 0x00
SAK_CLASSIC = (0x08, 0x18, 0x88)
SAK_CASCADE_BIT = 0x04
CASCADE_TAG = 0x88

TAG_CLASSIC = 1
TAG_ULTRALIGHT = 2

# MIFARE Classic geometry. 4K tags are addressed as 1K: their upper sectors hold
# 16 blocks instead of 4, and a seed needs a fraction of the first 16 anyway.
MF_BLOCK_SIZE = 16
MF_DATA_BLOCKS = 47  # 64 blocks less block 0 and 16 sector trailers
MF_DEFAULT_KEY = b"\xff\xff\xff\xff\xff\xff"

# Ultralight / NTAG geometry. A READ answers with four pages.
READ_LEN = 16
UL_PAGE_SIZE = 4
UL_DATA_FIRST_PAGE = 4
UL_CC_PAGE = 3
UL_MIN_CAPACITY = 48  # plain Ultralight, pages 4..15
UL_MAX_CAPACITY = 888  # NTAG216 user memory

# Nothing larger than one record is ever addressable, whatever a tag claims.
MAX_CAPACITY = MAX_PAYLOAD + HEADER_LEN


class NFCError(Exception):
    """Any NFC failure. The pages turn it into one short message, because the
    exact reason a hostile card was refused is not for the screen."""


class NFCNotFound(NFCError):
    """No reader on the bus, no acceptable tag, or no record on the tag"""


class NFCSizeError(NFCError):
    """A reply did not fit its buffer, or a payload does not fit the tag"""


def parse_header(header, capacity):
    """Validates a header read off a tag, returns the payload length.

    capacity is the tag's usable linear byte count including the header, so the
    declared length is checked against what the card can physically hold as well
    as against the ceiling.
    """
    if len(header) < HEADER_LEN or bytes(header[:4]) != RECORD_MAGIC:
        raise NFCNotFound("Not a Krux record")

    # One known type, and reserved bytes that must be zero: it denies the field
    # as a covert channel and stops stale bytes from silently acquiring meaning
    # in a later format version.
    if header[4] != RECORD_KEF or header[5] != 0 or any(header[8:HEADER_LEN]):
        raise NFCNotFound("Not a Krux record")

    # A number a stranger picked. Bound it before it sizes an allocation.
    length = (header[6] << 8) | header[7]
    if not 0 < length <= min(MAX_PAYLOAD, capacity - HEADER_LEN):
        raise NFCSizeError("Invalid record length")
    return length


def build_header(length, capacity):
    """Serializes the header for a payload about to be written"""
    if not 0 < length <= min(MAX_PAYLOAD, capacity - HEADER_LEN):
        raise NFCSizeError("Invalid record length")
    header = bytearray(HEADER_LEN)
    header[0:4] = RECORD_MAGIC
    header[4] = RECORD_KEF
    header[6] = length >> 8
    header[7] = length & 0xFF
    return header


class NFC:
    """Reader, tag layer and record I/O.

    The WS1850S is register compatible with the MFRC522 but does not report its
    VersionReg values, so presence is probed by writing a register and reading
    it back.
    """

    def __init__(self, scl=None, sda=None, addr=WS1850S_ADDR):
        from .krux_settings import Settings

        settings = Settings().hardware.nfc
        self.scl = settings.scl_pin if scl is None else scl
        self.sda = settings.sda_pin if sda is None else sda
        self.addr = addr
        self.i2c = None
        self.ready = False
        self.crypto_on = False
        self.authed_sector = None
        self.tag = None

    # ---------- Register access ----------

    def _write(self, reg, val):
        """Writes one register"""
        self._raw(bytes([reg, val]))

    def _raw(self, payload):
        """Writes a register byte followed by data.

        Both must travel in one transaction: the MFRC522 does not auto
        increment, so every byte after the address lands in the same register.
        """
        try:
            self.i2c.writeto(self.addr, payload)
        except Exception as exc:
            raise NFCError("I2C write failed") from exc

    def _read(self, reg, length=1):
        """Reads from a register. Reading FIFODataReg repeatedly drains it."""
        try:
            self.i2c.writeto(self.addr, bytes([reg]))
            data = self.i2c.readfrom(self.addr, length)
        except Exception as exc:
            raise NFCError("I2C read failed") from exc
        if data is None or len(data) != length:
            raise NFCError("I2C short read")
        return data

    def _byte(self, reg):
        """Reads a single register"""
        return self._read(reg)[0]

    def _mask(self, reg, mask, on):
        """Sets or clears the masked bits of a register"""
        val = self._byte(reg)
        self._write(reg, val | mask if on else val & (~mask & 0xFF))

    # ---------- Lifecycle ----------

    def _open_bus(self):
        """Opens, or borrows, the I2C bus the reader sits on.

        Wired to the board's own I2C pins the reader shares the existing bus
        with the touch controller and PMU. Wired anywhere else - the UART
        header, where an external module usually ends up - it gets a controller
        of its own.
        """
        pins = board.config["krux"]["pins"]
        if pins.get("I2C_SCL") == self.scl and pins.get("I2C_SDA") == self.sda:
            from .i2c import i2c_bus

            if i2c_bus is None:
                raise NFCNotFound("No I2C bus")
            return i2c_bus

        from machine import I2C

        try:
            return I2C(I2C.I2C1, freq=I2C_FREQ, scl=self.scl, sda=self.sda)
        except Exception as exc:
            raise NFCNotFound("No I2C bus") from exc

    def init(self):
        """Brings the reader up with the field off. Idempotent."""
        if self.ready:
            return
        self.i2c = self._open_bus()

        # VersionReg is useless here, so write two patterns to a harmless
        # register and read them back. A missing module fails the transfer.
        for pattern in (0x55, 0xAA):
            try:
                self._write(REG_T_RELOAD_L, pattern)
                if self._byte(REG_T_RELOAD_L) != pattern:
                    raise NFCNotFound("No NFC reader")
            except NFCError as exc:
                raise NFCNotFound("No NFC reader") from exc

        self._write(REG_COMMAND, PCD_RESET)
        for _ in range(10):
            time.sleep_ms(5)
            try:
                if not self._byte(REG_COMMAND) & 0x10:
                    break
            except NFCError:
                pass
        else:
            raise NFCError("Reader reset timed out")

        # Timer: TAuto, prescaler 0xA9 -> 40 kHz, reload 1000 -> 25 ms per
        # exchange. This is what stops a silent tag from hanging a read.
        for reg, val in (
            (REG_T_MODE, 0x80),
            (REG_T_PRESCALER, 0xA9),
            (REG_T_RELOAD_H, 0x03),
            (REG_T_RELOAD_L, 0xE8),
            (REG_TX_ASK, 0x40),  # force 100% ASK
            (REG_MODE, 0x3D),  # CRC preset 0x6363
        ):
            self._write(reg, val)

        self.ready = True
        self.crypto_on = False
        self.field(False)  # callers energize the antenna deliberately

    def deinit(self):
        """Releases the tag and the reader, field off first"""
        if self.ready:
            try:
                self.release()
                self._mask(REG_TX_CONTROL, 0x03, False)
            except NFCError:
                pass
        self.ready = False
        self.crypto_on = False
        self.i2c = None

    def field(self, on):
        """Energizes or drops the RF antenna"""
        if not self.ready:
            raise NFCError("Reader not ready")
        if not on:
            self.release()
        self._mask(REG_TX_CONTROL, 0x03, on)

    # ---------- Frame exchange ----------

    def _wait_irq(self, mask, timeout_ms):
        """Waits for a masked IRQ bit, the reader's timer, or the deadline"""
        deadline = time.ticks_ms() + timeout_ms
        for _ in range(MAX_POLLS):
            irq = self._byte(REG_COM_IRQ)
            if irq & mask:
                return
            if irq & IRQ_TIMER or time.ticks_ms() > deadline:
                break
        raise NFCError("No answer from tag")

    def transceive(self, send, tx_last_bits=0, recv_size=0):
        """Exchanges one frame, returning (reply, rx_last_bits).

        recv_size is the largest reply accepted; a longer one is refused rather
        than truncated, because truncating it would let the tag desynchronize
        us. 0 means no reply is expected.
        """
        if not self.ready or not send or len(send) > FIFO_SIZE or tx_last_bits > 7:
            raise NFCSizeError("Bad frame")

        self._write(REG_COMMAND, PCD_IDLE)
        self._write(REG_COM_IRQ, 0x7F)  # clear IRQs
        self._write(REG_FIFO_LEVEL, 0x80)  # flush FIFO
        self._raw(bytes([REG_FIFO_DATA]) + bytes(send))
        self._write(REG_BIT_FRAMING, tx_last_bits)
        self._write(REG_COMMAND, PCD_TRANSCEIVE)
        self._mask(REG_BIT_FRAMING, 0x80, True)  # StartSend
        try:
            self._wait_irq(IRQ_RX | IRQ_IDLE, EXCHANGE_TIMEOUT_MS)
        finally:
            self._mask(REG_BIT_FRAMING, 0x80, False)

        # A collision only happens with more than one card in the field; Krux
        # asks for a single card rather than resolving it.
        if self._byte(REG_ERROR) & ERR_FATAL_MASK:
            raise NFCError("Reader error")

        if not recv_size:
            self._write(REG_COMMAND, PCD_IDLE)
            return b"", 0

        # The tag decides this number. Copying it into a smaller buffer is the
        # classic MFRC522 overflow, so refuse rather than truncate.
        level = self._byte(REG_FIFO_LEVEL)
        if level > FIFO_SIZE:
            raise NFCError("Oversized reply")
        if level > recv_size:
            raise NFCSizeError("Reply does not fit")

        data = self._read(REG_FIFO_DATA, level) if level else b""
        # RxLastBits is three bits wide; mask before it becomes shift arithmetic
        return bytes(data), self._byte(REG_CONTROL) & 0x07

    def transceive_crc(self, send, recv_size):
        """Appends a CRC_A and verifies the one on the reply, stripping it.

        recv_size must cover the payload plus CRC_LEN - the CRC arrives as part
        of the frame, and an undersized buffer reads as an oversized reply.
        """
        if not send or len(send) + CRC_LEN > FIFO_SIZE or recv_size < CRC_LEN:
            raise NFCSizeError("Bad frame")

        reply, _ = self.transceive(bytes(send) + self.calc_crc(send), 0, recv_size)
        # A reply carrying a CRC_A is at least three bytes
        if len(reply) < 3:
            raise NFCError("Malformed reply")
        if self.calc_crc(reply[:-2]) != reply[-2:]:
            raise NFCError("Bad CRC")
        return reply[:-2]

    def calc_crc(self, data):
        """Computes a CRC_A with the reader's own coprocessor"""
        if not self.ready or not data or len(data) > FIFO_SIZE:
            raise NFCSizeError("Bad CRC input")

        self._write(REG_COMMAND, PCD_IDLE)
        self._write(REG_DIV_IRQ, 0x04)  # clear CRCIRq
        self._write(REG_FIFO_LEVEL, 0x80)
        self._raw(bytes([REG_FIFO_DATA]) + bytes(data))
        self._write(REG_COMMAND, PCD_CALC_CRC)

        deadline = time.ticks_ms() + CRC_TIMEOUT_MS
        for _ in range(MAX_POLLS):
            if self._byte(REG_DIV_IRQ) & 0x04:
                self._write(REG_COMMAND, PCD_IDLE)
                return bytes(
                    [self._byte(REG_CRC_RESULT_L), self._byte(REG_CRC_RESULT_H)]
                )
            if time.ticks_ms() > deadline:
                break
        self._write(REG_COMMAND, PCD_IDLE)
        raise NFCError("CRC timed out")

    # ---------- Selection ----------

    def _cascade(self, sel_cmd):
        """One cascade level: anticollision to learn four UID bytes, then select"""
        reply, _ = self.transceive(bytes([sel_cmd, 0x20]), 0, 5)
        if len(reply) != 5:
            raise NFCError("Bad anticollision")
        # BCC is a plain XOR check. A mismatch means a malformed frame, so stop
        # rather than build a UID out of it.
        if reply[0] ^ reply[1] ^ reply[2] ^ reply[3] != reply[4]:
            raise NFCError("Bad BCC")

        sak = self.transceive_crc(bytes([sel_cmd, 0x70]) + reply, 1 + CRC_LEN)
        if len(sak) != 1:
            raise NFCError("Bad SAK")
        return reply[:4], sak[0]

    def _ul_capacity(self):
        """Derives a usable size from the NTAG compatibility container"""
        pages = self.transceive_crc(bytes([CMD_READ, UL_CC_PAGE]), READ_LEN + CRC_LEN)
        if len(pages) != READ_LEN:
            raise NFCError("Bad CC read")

        # pages[2] was written by whoever held the tag last, and `size * 8` is
        # exactly the kind of number that overflows if believed. Take it only
        # behind the NFC Forum magic byte, and clamp it at both ends regardless.
        capacity = pages[2] * 8 if pages[0] == 0xE1 and pages[2] else UL_MIN_CAPACITY
        return min(max(capacity, UL_MIN_CAPACITY), UL_MAX_CAPACITY)

    def poll(self):
        """Wakes, identifies and selects one tag.

        Raises NFCNotFound when the field is empty, holds more than one tag, or
        holds a family Krux does not accept.
        """
        if not self.ready:
            raise NFCError("Reader not ready")
        self.release()

        try:
            # WUPA rather than REQA, as a 7 bit frame: release() just halted
            # whatever was there, and a halted tag answers WUPA but ignores
            # REQA, which would make the card unselectable while it stays in
            # the field.
            atqa, _ = self.transceive(bytes([CMD_WUPA]), 7, 2)
            if len(atqa) != 2:
                raise NFCError("Bad ATQA")

            uid, sak = self._cascade(CMD_SEL_CL1)
            if sak & SAK_CASCADE_BIT:
                # Double size UID: the first byte of level 1 is the cascade tag,
                # not UID data. Ten byte UIDs are not supported, not guessed at.
                if uid[0] != CASCADE_TAG:
                    raise NFCError("Unsupported UID")
                head = uid[1:4]
                uid, sak = self._cascade(CMD_SEL_CL2)
                if sak & SAK_CASCADE_BIT:
                    raise NFCError("Unsupported UID")
                uid = head + uid
        except NFCError as exc:
            raise NFCNotFound("No card") from exc

        if sak in SAK_CLASSIC:
            self.tag = (
                TAG_CLASSIC,
                uid,
                min(MF_DATA_BLOCKS * MF_BLOCK_SIZE, MAX_CAPACITY),
            )
        elif sak == SAK_ULTRALIGHT:
            try:
                capacity = self._ul_capacity()
            except NFCError as exc:
                self.release()
                raise NFCNotFound("Unreadable card") from exc
            self.tag = (TAG_ULTRALIGHT, uid, min(capacity, MAX_CAPACITY))
        else:
            self.release()
            raise NFCNotFound("Unsupported card")
        return self.tag

    def release(self):
        """Halts the tag and drops any crypto1 session. Safe to call always."""
        self.authed_sector = None
        self.tag = None
        if not self.ready:
            return
        # HALT goes out before crypto is dropped: while a sector is
        # authenticated the reader enciphers the frame, and a plaintext HALT
        # would be ignored, leaving the tag awake in a state it thinks is still
        # authenticated. HALT draws no reply, so a timeout is the success case.
        try:
            halt = bytes([CMD_HALT, 0x00])
            self.transceive(halt + self.calc_crc(halt))
        except NFCError:
            pass
        if self.crypto_on:
            try:
                self._mask(REG_STATUS2, 0x08, False)
            except NFCError:
                pass
            self.crypto_on = False

    # ---------- Linear addressing ----------

    @staticmethod
    def _block(index):
        """Maps a data block index onto a physical MIFARE Classic block.

        Skips the manufacturer block and every sector trailer: sector 0
        contributes two data blocks, every later sector three. A corrupted
        trailer bricks its sector permanently, so the result is re-checked - it
        catches a future edit to the arithmetic before it destroys a card.
        """
        if index >= MF_DATA_BLOCKS:
            raise NFCSizeError("Block out of range")
        rest = index - 2
        block = index + 1 if index < 2 else (rest // 3 + 1) * 4 + rest % 3
        if block == 0 or block % 4 == 3:
            raise NFCError("Refusing to touch a sector trailer")
        return block

    def _authenticate(self, uid, block):
        """Authenticates a sector with the factory key A.

        The protection is the KEF password, not the sector key: the card stays
        readable by any reader, and what a reader finds is ciphertext.
        """
        sector = block // 4
        if sector == self.authed_sector:
            return
        self.authed_sector = None

        self._write(REG_COMMAND, PCD_IDLE)
        self._write(REG_COM_IRQ, 0x7F)
        self._write(REG_FIFO_LEVEL, 0x80)
        # Classic authenticates on the last four UID bytes, the whole UID for
        # single size tags and the tail for double size ones.
        self._raw(
            bytes([REG_FIFO_DATA, CMD_AUTH_KEY_A, block])
            + MF_DEFAULT_KEY
            + bytes(uid[-4:])
        )
        self._write(REG_COMMAND, PCD_AUTHENT)
        try:
            self._wait_irq(IRQ_IDLE, EXCHANGE_TIMEOUT_MS)
        except NFCError:
            self._write(REG_COMMAND, PCD_IDLE)
            self.crypto_on = False
            raise

        # Crypto1On is the only reliable success signal
        if not self._byte(REG_STATUS2) & 0x08:
            self.crypto_on = False
            raise NFCError("Authentication failed")
        self.crypto_on = True
        self.authed_sector = sector

    def _ack(self, data):
        """Sends one frame and requires a 4 bit ACK back.

        A MIFARE write is two such frames. An ACK is exactly one nibble holding
        0x0A; anything else - a NAK, a full byte, a longer frame - is a failed
        write, not a partial success.
        """
        if len(data) + CRC_LEN > FIFO_SIZE:
            raise NFCSizeError("Frame too long")
        reply, valid_bits = self.transceive(bytes(data) + self.calc_crc(data), 0, 1)
        if len(reply) != 1 or valid_bits != 4 or reply[0] & 0x0F != 0x0A:
            raise NFCError("Write not acknowledged")

    def _check_range(self, offset, length):
        """Refuses a range that falls outside the selected tag"""
        if self.tag is None:
            raise NFCError("No tag selected")
        capacity = self.tag[2]
        if not length or offset > capacity or length > capacity - offset:
            raise NFCSizeError("Range outside tag")

    def read(self, offset, length):
        """Reads bytes at a linear offset, spanning blocks and pages as needed"""
        self._check_range(offset, length)
        kind, uid, _ = self.tag

        out = bytearray()
        while len(out) < length:
            pos = offset + len(out)
            aligned = pos - pos % READ_LEN
            skip = pos - aligned
            take = min(READ_LEN - skip, length - len(out))

            if kind == TAG_CLASSIC:
                block = self._block(aligned // MF_BLOCK_SIZE)
                self._authenticate(uid, block)
            else:
                block = UL_DATA_FIRST_PAGE + aligned // UL_PAGE_SIZE

            # The block arrives with its CRC_A attached; the buffer has to hold
            # both or the reply reads as oversized.
            data = self.transceive_crc(bytes([CMD_READ, block]), READ_LEN + CRC_LEN)
            if len(data) != READ_LEN:
                raise NFCError("Bad block read")
            out += data[skip : skip + take]
        return bytes(out)

    def write(self, offset, data):
        """Writes data at a block aligned linear offset, zero padding the tail"""
        self._check_range(offset, len(data))
        kind, uid, _ = self.tag
        unit = MF_BLOCK_SIZE if kind == TAG_CLASSIC else UL_PAGE_SIZE
        if offset % unit:
            raise NFCSizeError("Unaligned write")

        done = 0
        while done < len(data):
            # Pad the tail so a short final block still writes a full unit; the
            # record header carries the real length.
            chunk = bytearray(unit)
            chunk[0 : min(unit, len(data) - done)] = data[done : done + unit]

            pos = offset + done
            if kind == TAG_CLASSIC:
                block = self._block(pos // MF_BLOCK_SIZE)
                self._authenticate(uid, block)
                self._ack(bytes([CMD_MF_WRITE, block]))
                self._ack(chunk)
            else:
                page = UL_DATA_FIRST_PAGE + pos // UL_PAGE_SIZE
                self._ack(bytes([CMD_UL_WRITE, page]) + chunk)
            done += unit

    # ---------- Records ----------

    def has_record(self):
        """True when the selected tag already carries a Krux record.

        Absent or unreadable records report False, so callers can warn before
        overwriting without a card fault looking like a refusal.
        """
        try:
            parse_header(self.read(0, HEADER_LEN), self.tag[2])
            return True
        except NFCError:
            return False

    def read_record(self):
        """Reads the record off the selected tag, validating it throughout"""
        length = parse_header(self.read(0, HEADER_LEN), self.tag[2])
        # length is already bounded by the ceiling and by this tag's capacity
        return self.read(HEADER_LEN, length)

    def write_record(self, data):
        """Writes a record, replacing whatever was there.

        Header and payload go out as one contiguous image so the write stays
        block aligned from offset zero and never touches a block it does not
        fully own.
        """
        header = build_header(len(data), self.tag[2])
        self.write(0, bytes(header) + bytes(data))
