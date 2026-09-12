# The MIT License (MIT)

# Copyright (c) 2021-2026 Krux contributors

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
"""PN5180 reader over SPI.

Where the WS1850S exposes MFRC522 registers over I2C, the PN5180 speaks a
command protocol over SPI with a BUSY line for flow control, and it is the
frames rather than the registers that are comparable. Both end up behind the
same Reader interface.

Three things about this chip shape the code:

- **Every transaction is gated by BUSY.** The host waits for it low, drives NSS
  low, clocks the command out, waits for BUSY to rise and fall again, and only
  then may read the answer in a second transaction. Skipping a wait does not
  fail loudly; it returns stale bytes, which is worse.
- **It will not compute a CRC_A on demand.** The MFRC522 has a coprocessor
  command for it; the PN5180 only frames a CRC inline while transmitting. So
  hardware CRC is switched off in both directions and crc_a() from
  nfc_reader.py does the work, exactly as the frames arrive on the other chip.
- **There is no hardware SPI free on these boards.** SPI0 drives the LCD and
  SPI1 the SD card, so this runs on MaixPy's software SPI over ordinary GPIOs.
  That is slower than a peripheral, which does not matter for a few hundred
  bytes a user is holding a card still for.
"""

import time
from Maix import GPIO
from fpioa_manager import fm
from .nfc_reader import (
    Reader,
    crc_a,
    NFCError,
    NFCNotFound,
    NFCSizeError,
    FIFO_SIZE,
    EXCHANGE_TIMEOUT_MS,
    MAX_POLLS,
    MF_DEFAULT_KEY,
)

# Software SPI is bit banged, so this is a ceiling rather than a clock the
# chip has to keep up with. The PN5180 accepts up to 7 MHz.
SPI_BAUDRATE = 1000000

# GPIOHS channels for the three lines the SPI object does not drive. 0, 1, 2,
# 21 and 22 are taken by the buttons, and 3 by the light.
GPIOHS_NSS = 23
GPIOHS_BUSY = 24
GPIOHS_RST = 25

# Host commands
CMD_WRITE_REGISTER = 0x00
CMD_WRITE_REGISTER_OR_MASK = 0x01
CMD_WRITE_REGISTER_AND_MASK = 0x02
CMD_READ_REGISTER = 0x04
CMD_READ_EEPROM = 0x07
CMD_SEND_DATA = 0x09
CMD_READ_DATA = 0x0A
CMD_MIFARE_AUTHENTICATE = 0x0C
CMD_LOAD_RF_CONFIG = 0x11
CMD_RF_ON = 0x16
CMD_RF_OFF = 0x17

# Registers, all 32 bit and little endian on the wire
REG_SYSTEM_CONFIG = 0x00
REG_IRQ_ENABLE = 0x01
REG_IRQ_STATUS = 0x02
REG_IRQ_CLEAR = 0x03
REG_TRANSCEIVE_CONTROL = 0x04
REG_CRC_RX_CONFIG = 0x12
REG_RX_STATUS = 0x13
REG_CRC_TX_CONFIG = 0x19

# EEPROM: two bytes of product version. An absent or dead chip reads 0xFFFF.
EEPROM_PRODUCT_VERSION = 0x10

# SYSTEM_CONFIG command field
SYS_COMMAND_MASK = 0x00000007
SYS_COMMAND_IDLE = 0x00000000
SYS_COMMAND_TRANSCEIVE = 0x00000003

# IRQ_STATUS bits
IRQ_RX = 1 << 0
IRQ_GENERAL_ERROR = 1 << 17

# RX_STATUS layout
RX_BYTES_MASK = 0x1FF
RX_LAST_BITS_SHIFT = 9
RX_LAST_BITS_MASK = 0x0F
RX_COLLISION = 1 << 18
RX_PROTOCOL_ERROR = 1 << 19

# TRANSCEIVE_CONTROL: the state machine's own view of where it is
TRANSCEIVE_STATE_SHIFT = 24
TRANSCEIVE_STATE_MASK = 0x07
TRANSCEIVE_STATE_WAIT_TRANSMIT = 1

# ISO14443-A at 106 kbps, the only profile Krux loads
RF_TX_ISO14443A_106 = 0x00
RF_RX_ISO14443A_106 = 0x80

BUSY_TIMEOUT_MS = 20
RESET_SETTLE_MS = 5


class PN5180(Reader):
    """NXP PN5180 NFC frontend on software SPI"""

    def __init__(self, sck, mosi, miso, nss, busy, rst):
        # One tuple rather than six fields: they are read together, once, and
        # only by _open_bus.
        self.pins = (sck, mosi, miso, nss, busy, rst)
        self.spi = None
        self.nss = None
        self.busy = None
        self.rst = None
        self.ready = False
        self.crypto_on = False

    # ---------- Bus ----------

    def _open_bus(self):
        """Brings up software SPI and the three lines it does not drive.

        NSS is manual on purpose: MaixPy's software SPI does not assert a chip
        select, and the PN5180 needs NSS held across a command and released
        before its answer can be read.
        """
        from machine import SPI

        sck, mosi, miso, nss, busy, rst = self.pins
        try:
            fm.register(nss, getattr(fm.fpioa, "GPIOHS%d" % GPIOHS_NSS))
            fm.register(busy, getattr(fm.fpioa, "GPIOHS%d" % GPIOHS_BUSY))
            fm.register(rst, getattr(fm.fpioa, "GPIOHS%d" % GPIOHS_RST))
            self.nss = GPIO(getattr(GPIO, "GPIOHS%d" % GPIOHS_NSS), GPIO.OUT)
            self.busy = GPIO(getattr(GPIO, "GPIOHS%d" % GPIOHS_BUSY), GPIO.IN)
            self.rst = GPIO(getattr(GPIO, "GPIOHS%d" % GPIOHS_RST), GPIO.OUT)
            self.nss.value(1)
            self.rst.value(1)
            self.spi = SPI(
                SPI.SPI_SOFT,
                mode=SPI.MODE_MASTER,
                baudrate=SPI_BAUDRATE,
                polarity=0,
                phase=0,
                sck=sck,
                mosi=mosi,
                miso=miso,
            )
        except Exception as exc:
            raise NFCNotFound("No SPI bus") from exc

    def _wait_busy(self, level):
        """Waits for BUSY to reach a level, bounded by a deadline and a cap"""
        deadline = time.ticks_ms() + BUSY_TIMEOUT_MS
        for _ in range(MAX_POLLS):
            if self.busy.value() == level:
                return
            if time.ticks_ms() > deadline:
                break
        raise NFCError("Reader busy")

    def _command(self, cmd, payload=b"", recv_len=0):
        """Runs one host command, optionally reading its answer.

        The answer never shares a transaction with the command: NSS has to rise
        and BUSY has to settle in between, or what comes back is the previous
        command's tail.
        """
        frame = bytes([cmd]) + bytes(payload)
        try:
            self._wait_busy(0)
            self.nss.value(0)
            self.spi.write(frame)
            self._wait_busy(1)
            self.nss.value(1)
            self._wait_busy(0)

            if not recv_len:
                return b""

            self.nss.value(0)
            reply = self.spi.read(recv_len)
            self.nss.value(1)
            self._wait_busy(0)
        except NFCError:
            self.nss.value(1)
            raise
        except Exception as exc:
            self.nss.value(1)
            raise NFCError("SPI transfer failed") from exc

        if reply is None or len(reply) != recv_len:
            raise NFCError("SPI short read")
        return bytes(reply)

    # ---------- Registers ----------

    def _write_reg(self, reg, val):
        """Writes one 32 bit register"""
        self._command(
            CMD_WRITE_REGISTER,
            bytes(
                [
                    reg,
                    val & 0xFF,
                    (val >> 8) & 0xFF,
                    (val >> 16) & 0xFF,
                    (val >> 24) & 0xFF,
                ]
            ),
        )

    def _read_reg(self, reg):
        """Reads one 32 bit register"""
        data = self._command(CMD_READ_REGISTER, bytes([reg]), 4)
        return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)

    def _or_mask(self, reg, mask):
        """Sets the masked bits of a register"""
        self._command(
            CMD_WRITE_REGISTER_OR_MASK,
            bytes(
                [
                    reg,
                    mask & 0xFF,
                    (mask >> 8) & 0xFF,
                    (mask >> 16) & 0xFF,
                    (mask >> 24) & 0xFF,
                ]
            ),
        )

    def _and_mask(self, reg, mask):
        """Clears the bits absent from mask"""
        self._command(
            CMD_WRITE_REGISTER_AND_MASK,
            bytes(
                [
                    reg,
                    mask & 0xFF,
                    (mask >> 8) & 0xFF,
                    (mask >> 16) & 0xFF,
                    (mask >> 24) & 0xFF,
                ]
            ),
        )

    def _idle(self):
        """Returns the transceive state machine to idle"""
        self._and_mask(REG_SYSTEM_CONFIG, ~SYS_COMMAND_MASK & 0xFFFFFFFF)
        self._or_mask(REG_SYSTEM_CONFIG, SYS_COMMAND_IDLE)

    # ---------- Lifecycle ----------

    def init(self):
        """Brings the reader up with the field off. Idempotent."""
        if self.ready:
            return
        self._open_bus()

        # A hardware reset is the only way to know what state the chip is in;
        # it may have been left mid-transceive by a previous session.
        self.rst.value(0)
        time.sleep_ms(RESET_SETTLE_MS)
        self.rst.value(1)
        time.sleep_ms(RESET_SETTLE_MS)

        # Presence probe. An absent module reads all ones, and a module whose
        # supply is wrong tends to read all zeros; neither is a version.
        version = self._command(CMD_READ_EEPROM, bytes([EEPROM_PRODUCT_VERSION, 2]), 2)
        if version in (b"\xff\xff", b"\x00\x00"):
            raise NFCNotFound("No NFC reader")

        self._write_reg(REG_IRQ_ENABLE, 0)
        self._write_reg(REG_IRQ_CLEAR, 0xFFFFFFFF)
        self._idle()

        self.ready = True
        self.crypto_on = False
        self.field(False)  # callers energize the antenna deliberately

    def deinit(self):
        """Drops the field and releases the bus"""
        if self.ready:
            try:
                self._command(CMD_RF_OFF, b"\x00")
            except NFCError:
                pass
        self.ready = False
        self.crypto_on = False
        if self.nss is not None:
            try:
                self.nss.value(1)
            except Exception:
                pass
        self.spi = None

    def field(self, on):
        """Energizes or drops the RF antenna.

        The RF profile is loaded with the field, not at init: the chip forgets
        it across an RF_OFF, and loading it while the antenna is live is what
        produces a reader that transmits nothing.
        """
        if not self.ready:
            raise NFCError("Reader not ready")
        if on:
            self._command(
                CMD_LOAD_RF_CONFIG, bytes([RF_TX_ISO14443A_106, RF_RX_ISO14443A_106])
            )
            self._command(CMD_RF_ON, b"\x00")
            # CRC is computed and checked in software, the same as on the other
            # reader, so the chip must not add a second one.
            self._write_reg(REG_CRC_TX_CONFIG, 0)
            self._write_reg(REG_CRC_RX_CONFIG, 0)
        else:
            self._command(CMD_RF_OFF, b"\x00")
        self.crypto_on = False

    def clear_crypto(self):
        """Forgets the crypto1 session.

        The PN5180 has no command to drop one: the session lives until the
        field goes down or another authentication replaces it. Dropping the
        field is the tag layer's job on the way out, so this only clears the
        flag - and says so rather than pretending to do more.
        """
        self.crypto_on = False

    # ---------- Frame exchange ----------

    def transceive(self, send, tx_last_bits=0, recv_size=0):
        """Exchanges one frame, returning (reply, rx_last_bits).

        recv_size is the largest reply accepted; a longer one is refused rather
        than truncated. 0 means no reply is expected.
        """
        if not self.ready or not send or len(send) > FIFO_SIZE or tx_last_bits > 7:
            raise NFCSizeError("Bad frame")

        self._idle()
        self._write_reg(REG_IRQ_CLEAR, 0xFFFFFFFF)
        self._and_mask(REG_SYSTEM_CONFIG, ~SYS_COMMAND_MASK & 0xFFFFFFFF)
        self._or_mask(REG_SYSTEM_CONFIG, SYS_COMMAND_TRANSCEIVE)

        state = (
            self._read_reg(REG_TRANSCEIVE_CONTROL) >> TRANSCEIVE_STATE_SHIFT
        ) & TRANSCEIVE_STATE_MASK
        if state != TRANSCEIVE_STATE_WAIT_TRANSMIT:
            raise NFCError("Reader not ready to send")

        # SEND_DATA's first byte is how many bits of the last byte are valid;
        # zero means the whole byte, which is what a full frame wants.
        self._command(CMD_SEND_DATA, bytes([tx_last_bits]) + bytes(send))

        if not recv_size:
            self._idle()
            return b"", 0

        self._wait_irq(IRQ_RX, EXCHANGE_TIMEOUT_MS)

        status = self._read_reg(REG_RX_STATUS)
        if status & (RX_COLLISION | RX_PROTOCOL_ERROR):
            self._idle()
            raise NFCError("Reader error")

        # The tag decides this number, so it is bounded before it becomes a
        # read length - the same refusal the other reader makes.
        level = status & RX_BYTES_MASK
        if level > FIFO_SIZE:
            self._idle()
            raise NFCError("Oversized reply")
        if level > recv_size:
            self._idle()
            raise NFCSizeError("Reply does not fit")

        data = self._command(CMD_READ_DATA, b"\x00", level) if level else b""
        self._idle()
        return data, (status >> RX_LAST_BITS_SHIFT) & RX_LAST_BITS_MASK

    def _wait_irq(self, mask, timeout_ms):
        """Waits for a masked IRQ bit, a general error, or the deadline"""
        deadline = time.ticks_ms() + timeout_ms
        for _ in range(MAX_POLLS):
            status = self._read_reg(REG_IRQ_STATUS)
            if status & IRQ_GENERAL_ERROR:
                break
            if status & mask:
                return
            if time.ticks_ms() > deadline:
                break
        self._idle()
        raise NFCError("No answer from tag")

    def calc_crc(self, data):
        """Computes a CRC_A in software.

        The chip offers no command for it, so this is the same value the other
        reader's coprocessor returns - the tests pin both against one vector.
        """
        if not self.ready or not data or len(data) > FIFO_SIZE:
            raise NFCSizeError("Bad CRC input")
        return crc_a(data)

    # ---------- MIFARE ----------

    def authenticate(self, uid, block):
        """Opens a crypto1 session on the sector holding block.

        The chip runs the whole exchange and answers with one status byte, so
        unlike the MFRC522 path there is no register to read back for proof:
        zero is success and anything else is not.
        """
        status = self._command(
            CMD_MIFARE_AUTHENTICATE,
            MF_DEFAULT_KEY + bytes([0x60, block]) + bytes(uid[-4:]),
            1,
        )
        if status[0] != 0:
            self.crypto_on = False
            raise NFCError("Authentication failed")
        self.crypto_on = True
