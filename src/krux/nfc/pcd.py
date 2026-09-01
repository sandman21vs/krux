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
"""WS1850S reader (PCD) - register access and ISO14443A framing.

The WS1850S is register compatible with the NXP MFRC522 but is not the same
part: notably it does not report the MFRC522's VersionReg values, so presence
is probed by writing a register and reading it back rather than by matching a
version byte.

Everything here is bounded. Frame length, wait loops and FIFO reads all have
hard limits, because the far side of the antenna is a device someone else
built.
"""

import time
from .errors import (
    NFCError,
    NFCTimeout,
    NFCSizeError,
    NFCCRCError,
    NFCResponseError,
    NFCNotFound,
)

# 7 bit address. 0x28 is the M5Stack RFID Unit 2 factory default.
WS1850S_ADDR = 0x28

# The reader's FIFO is 64 bytes; no frame can exceed it.
FIFO_SIZE = 64

# A CRC_A is two bytes. Receive buffers must have room for it even when the
# caller only wants the payload: the CRC arrives with the frame and is verified
# before being stripped.
CRC_LEN = 2

# PICC commands used by the tag layer
PICC_CMD_WUPA = 0x52
PICC_CMD_HALT = 0x50
PICC_CMD_SEL_CL1 = 0x93
PICC_CMD_SEL_CL2 = 0x95
PICC_CMD_MF_AUTH_KEY_A = 0x60
PICC_CMD_MF_AUTH_KEY_B = 0x61
PICC_CMD_MF_READ = 0x30
PICC_CMD_MF_WRITE = 0xA0
PICC_CMD_UL_WRITE = 0xA2

# Register map (MFRC522 compatible)
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
CMD_IDLE = 0x00
CMD_CALC_CRC = 0x03
CMD_TRANSCEIVE = 0x0C
CMD_MF_AUTHENT = 0x0E
CMD_SOFT_RESET = 0x0F

# ErrorReg bits. Any of the fatal ones means the frame is garbage; CRCErr is
# excluded because framing without a CRC legitimately leaves it set.
ERR_PROTOCOL = 0x01
ERR_PARITY = 0x02
ERR_COLL = 0x08
ERR_BUFFER_OVFL = 0x10
ERR_FATAL_MASK = ERR_BUFFER_OVFL | ERR_COLL | ERR_PARITY | ERR_PROTOCOL

IRQ_TIMER = 0x01
IRQ_IDLE = 0x10
IRQ_RX = 0x20

# An exchange is bounded three times over: the reader's own 25 ms timer, a wall
# clock deadline in case the reader itself stops answering, and an iteration
# cap so a clock that never advances still cannot spin forever.
EXCHANGE_TIMEOUT_MS = 60
CRC_TIMEOUT_MS = 20
MAX_POLLS = 4000


class WS1850S:
    """Register level driver for the WS1850S / MFRC522 over I2C"""

    def __init__(self, i2c, addr=WS1850S_ADDR):
        self.i2c = i2c
        self.addr = addr
        self.ready = False
        self.crypto_on = False

    # ---------- Register access ----------

    def _write_reg(self, reg, val):
        """Writes one register"""
        try:
            self.i2c.writeto(self.addr, bytes([reg, val]))
        except Exception as exc:
            raise NFCError("I2C write failed") from exc

    def _write_fifo(self, data):
        """Pushes a payload into the FIFO.

        The register byte and the payload have to travel in one transaction:
        the MFRC522 does not auto increment, so every byte after the address
        lands in FIFODataReg.
        """
        if len(data) > FIFO_SIZE:
            raise NFCSizeError("Frame too long")
        try:
            self.i2c.writeto(self.addr, bytes([REG_FIFO_DATA]) + bytes(data))
        except Exception as exc:
            raise NFCError("I2C write failed") from exc

    def _read_reg(self, reg, length=1):
        """Reads one or more bytes from a register.

        Reading FIFODataReg repeatedly drains the FIFO, so one burst read works.
        """
        try:
            self.i2c.writeto(self.addr, bytes([reg]))
            data = self.i2c.readfrom(self.addr, length)
        except Exception as exc:
            raise NFCError("I2C read failed") from exc
        if data is None or len(data) != length:
            raise NFCError("I2C short read")
        return data

    def _read_byte(self, reg):
        """Reads a single register"""
        return self._read_reg(reg, 1)[0]

    def _set_bits(self, reg, mask):
        """Sets the masked bits of a register"""
        self._write_reg(reg, self._read_byte(reg) | mask)

    def _clear_bits(self, reg, mask):
        """Clears the masked bits of a register"""
        self._write_reg(reg, self._read_byte(reg) & (~mask & 0xFF))

    # ---------- Bring up ----------

    def _probe(self):
        """Confirms a reader is really answering on the bus.

        VersionReg is useless here - the WS1850S does not return the MFRC522's
        0x91/0x92 - so instead write two patterns to a harmless register and
        read them back. A missing or dead module fails the transfer or returns
        something else.
        """
        for pattern in (0x55, 0xAA):
            try:
                self._write_reg(REG_T_RELOAD_L, pattern)
                back = self._read_byte(REG_T_RELOAD_L)
            except NFCError as exc:
                raise NFCNotFound("No NFC reader") from exc
            if back != pattern:
                raise NFCNotFound("No NFC reader")

    def _soft_reset(self):
        """Resets the reader and waits for it to come back"""
        self._write_reg(REG_COMMAND, CMD_SOFT_RESET)

        # The datasheet allows the reset to take a moment; poll rather than
        # guessing a delay, but give up instead of spinning.
        for _ in range(10):
            time.sleep_ms(5)
            try:
                if not self._read_byte(REG_COMMAND) & 0x10:
                    return
            except NFCError:
                pass
        raise NFCTimeout("Reader reset timed out")

    def init(self):
        """Brings the reader up with the field off. Idempotent."""
        if self.ready:
            return

        self._probe()
        self._soft_reset()

        # Timer: TAuto, prescaler 0xA9 -> 40 kHz, reload 1000 -> 25 ms per
        # exchange. This is what stops a silent tag from hanging a read.
        self._write_reg(REG_T_MODE, 0x80)
        self._write_reg(REG_T_PRESCALER, 0xA9)
        self._write_reg(REG_T_RELOAD_H, 0x03)
        self._write_reg(REG_T_RELOAD_L, 0xE8)
        self._write_reg(REG_TX_ASK, 0x40)  # force 100% ASK
        self._write_reg(REG_MODE, 0x3D)  # CRC preset 0x6363

        self.ready = True
        self.crypto_on = False

        # Come up with the antenna dark; callers energize it deliberately.
        self.antenna(False)

    def deinit(self):
        """Drops the field and forgets the reader state"""
        if self.ready:
            try:
                self.antenna(False)
            except NFCError:
                pass
        self.ready = False
        self.crypto_on = False

    def antenna(self, on):
        """Energizes or drops the RF antenna"""
        if on:
            self._set_bits(REG_TX_CONTROL, 0x03)
        else:
            self._clear_bits(REG_TX_CONTROL, 0x03)

    # ---------- Frame exchange ----------

    def _wait_irq(self, wait_mask, timeout_ms):
        """Waits for one of the masked IRQ bits, or for the reader's timer"""
        deadline = time.ticks_ms() + timeout_ms
        for _ in range(MAX_POLLS):
            irq = self._read_byte(REG_COM_IRQ)
            if irq & wait_mask:
                return
            if irq & IRQ_TIMER:
                raise NFCTimeout("No answer from tag")
            if time.ticks_ms() > deadline:
                break
        raise NFCTimeout("No answer from tag")

    def _collect_reply(self, recv_size):
        """Drains the reply the tag left in the FIFO, refusing anything oversized"""
        level = self._read_byte(REG_FIFO_LEVEL)

        # The tag decides this number. Copying it into a smaller buffer is the
        # classic MFRC522 overflow, so refuse rather than truncate: a short read
        # would also leave the protocol out of step.
        if level > FIFO_SIZE:
            raise NFCResponseError("Oversized reply")
        if level > recv_size:
            raise NFCSizeError("Reply does not fit")

        data = self._read_reg(REG_FIFO_DATA, level) if level else b""

        # RxLastBits is three bits wide; mask before it becomes shift arithmetic.
        rx_last_bits = self._read_byte(REG_CONTROL) & 0x07
        return bytes(data), rx_last_bits

    def transceive(self, send, tx_last_bits=0, recv_size=0):
        """Exchanges one frame with the tag.

        send          bytes to transmit, at most FIFO_SIZE
        tx_last_bits  bits of the final byte to send; 0 sends all 8
        recv_size     largest reply accepted. A longer one is refused outright,
                      because truncating it would let the tag desynchronize us.
                      0 means no reply is expected.

        Returns (reply_bytes, rx_last_bits).
        """
        if not self.ready:
            raise NFCError("Reader not ready")
        if not send or len(send) > FIFO_SIZE or tx_last_bits > 7:
            raise NFCSizeError("Bad frame")

        self._write_reg(REG_COMMAND, CMD_IDLE)
        self._write_reg(REG_COM_IRQ, 0x7F)  # clear IRQs
        self._write_reg(REG_FIFO_LEVEL, 0x80)  # flush FIFO
        self._write_fifo(send)
        self._write_reg(REG_BIT_FRAMING, tx_last_bits)
        self._write_reg(REG_COMMAND, CMD_TRANSCEIVE)
        self._set_bits(REG_BIT_FRAMING, 0x80)  # StartSend

        try:
            self._wait_irq(IRQ_RX | IRQ_IDLE, EXCHANGE_TIMEOUT_MS)
        finally:
            self._clear_bits(REG_BIT_FRAMING, 0x80)

        if self._read_byte(REG_ERROR) & ERR_FATAL_MASK:
            # Collisions are expected only with more than one card in the
            # field; Krux treats that as "present a single card" rather than
            # resolving it.
            raise NFCResponseError("Reader error")

        if not recv_size:
            self._write_reg(REG_COMMAND, CMD_IDLE)
            return b"", 0

        return self._collect_reply(recv_size)

    def transceive_crc(self, send, recv_size):
        """Appends a CRC_A to the frame and verifies the CRC_A on the reply.

        recv_size must cover the payload *plus* CRC_LEN - the CRC arrives as
        part of the frame, and an undersized buffer is rejected as an oversized
        reply. The CRC is stripped from the value returned.
        """
        if not send or len(send) + CRC_LEN > FIFO_SIZE:
            raise NFCSizeError("Bad frame")
        if recv_size < CRC_LEN:
            raise NFCSizeError("Bad receive size")

        frame = bytes(send) + self.calc_crc(send)
        reply, _ = self.transceive(frame, 0, recv_size)

        # A reply carrying a CRC_A is at least three bytes; anything shorter is
        # malformed regardless of what it claims to be.
        if len(reply) < 3:
            raise NFCResponseError("Malformed reply")

        if self.calc_crc(reply[:-2]) != reply[-2:]:
            raise NFCCRCError("Bad CRC")

        return reply[:-2]

    def calc_crc(self, data):
        """Computes a CRC_A using the reader's own CRC coprocessor"""
        if not self.ready:
            raise NFCError("Reader not ready")
        if not data or len(data) > FIFO_SIZE:
            raise NFCSizeError("Bad CRC input")

        self._write_reg(REG_COMMAND, CMD_IDLE)
        self._write_reg(REG_DIV_IRQ, 0x04)  # clear CRCIRq
        self._write_reg(REG_FIFO_LEVEL, 0x80)
        self._write_fifo(data)
        self._write_reg(REG_COMMAND, CMD_CALC_CRC)

        deadline = time.ticks_ms() + CRC_TIMEOUT_MS
        for _ in range(MAX_POLLS):
            if self._read_byte(REG_DIV_IRQ) & 0x04:  # CRCIRq
                self._write_reg(REG_COMMAND, CMD_IDLE)
                return bytes(
                    [
                        self._read_byte(REG_CRC_RESULT_L),
                        self._read_byte(REG_CRC_RESULT_H),
                    ]
                )
            if time.ticks_ms() > deadline:
                break

        self._write_reg(REG_COMMAND, CMD_IDLE)
        raise NFCTimeout("CRC timed out")

    # ---------- MIFARE Classic authentication ----------

    def mf_authenticate(self, cmd, block, key, uid):
        """Runs MIFARE Classic authentication for one sector.

        The crypto1 state lives in the reader; every authenticated exchange
        afterwards must be followed by stop_crypto() before the tag can be
        released.
        """
        if not self.ready:
            raise NFCError("Reader not ready")
        if cmd not in (PICC_CMD_MF_AUTH_KEY_A, PICC_CMD_MF_AUTH_KEY_B):
            raise NFCError("Bad auth command")
        if len(key) != 6 or len(uid) < 4:
            raise NFCError("Bad auth argument")

        # Classic authenticates on the last four UID bytes, which is the whole
        # UID for single size tags and the tail for double size ones.
        payload = bytes([cmd, block]) + bytes(key) + bytes(uid[-4:])

        self._write_reg(REG_COMMAND, CMD_IDLE)
        self._write_reg(REG_COM_IRQ, 0x7F)
        self._write_reg(REG_FIFO_LEVEL, 0x80)
        self._write_fifo(payload)
        self._write_reg(REG_COMMAND, CMD_MF_AUTHENT)

        try:
            self._wait_irq(IRQ_IDLE, EXCHANGE_TIMEOUT_MS)
        except NFCError:
            self._write_reg(REG_COMMAND, CMD_IDLE)
            self.crypto_on = False
            raise

        # Crypto1On in Status2Reg is the only reliable success signal.
        if not self._read_byte(REG_STATUS2) & 0x08:
            self.crypto_on = False
            raise NFCResponseError("Authentication failed")

        self.crypto_on = True

    def stop_crypto(self):
        """Clears the crypto1 state left by mf_authenticate()"""
        if not self.ready:
            self.crypto_on = False
            return
        try:
            self._clear_bits(REG_STATUS2, 0x08)
        except NFCError:
            pass
        self.crypto_on = False
