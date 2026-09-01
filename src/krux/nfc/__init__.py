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

Reader: WS1850S (M5Stack RFID Unit 2) on an I2C bus this module opens from the
pins configured under Settings > Hardware > NFC. Nothing here runs unless the
user turned the feature on: the bus is opened by init(), which the pages call
only after checking the setting.

Tags: MIFARE Classic 1K/4K and Ultralight/NTAG21x. Callers never see the
difference - picc.py maps a linear byte offset onto whichever addressing the
tag family uses.

A card is attacker controlled input. Every routine here treats it that way: see
the validation notes in record.py.
"""

import board
from .errors import NFCError, NFCNotFound
from .record import HEADER_LEN, build_header, parse_header
from .pcd import WS1850S, WS1850S_ADDR
from .picc import PICC

I2C_FREQ = 400000


class NFC:
    """Reader lifecycle and record I/O"""

    def __init__(self, scl=None, sda=None, addr=WS1850S_ADDR):
        from ..krux_settings import Settings

        nfc_settings = Settings().hardware.nfc
        self.scl = nfc_settings.scl_pin if scl is None else scl
        self.sda = nfc_settings.sda_pin if sda is None else sda
        self.addr = addr
        self.i2c = None
        self.pcd = None
        self.picc = None

    # ---------- Lifecycle ----------

    def _open_bus(self):
        """Opens, or borrows, the I2C bus the reader sits on.

        Wired to the board's own I2C pins the reader shares the existing bus
        with the touch controller and PMU. Wired anywhere else - the UART
        header, which is where an external module usually ends up - it gets a
        second controller of its own.
        """
        pins = board.config["krux"]["pins"]
        if pins.get("I2C_SCL") == self.scl and pins.get("I2C_SDA") == self.sda:
            from ..i2c import i2c_bus

            if i2c_bus is None:
                raise NFCNotFound("No I2C bus")
            return i2c_bus

        from machine import I2C

        try:
            return I2C(I2C.I2C1, freq=I2C_FREQ, scl=self.scl, sda=self.sda)
        except Exception as exc:
            raise NFCNotFound("No I2C bus") from exc

    def init(self):
        """Binds the reader to its bus and puts it in a known state.

        Idempotent. Leaves the RF field off. Raises NFCNotFound when no
        WS1850S answers.
        """
        if self.pcd is not None and self.pcd.ready:
            return

        self.i2c = self._open_bus()
        self.pcd = WS1850S(self.i2c, self.addr)
        self.pcd.init()
        self.picc = PICC(self.pcd)

    def deinit(self):
        """Releases the reader. Turns the field off first."""
        if self.picc is not None:
            try:
                self.picc.release()
            except NFCError:
                pass
        if self.pcd is not None:
            self.pcd.deinit()
        self.picc = None
        self.pcd = None
        self.i2c = None

    def is_ready(self):
        """True once init() has succeeded"""
        return self.pcd is not None and self.pcd.ready

    def field(self, on):
        """Energizes or drops the RF antenna.

        Off after init(); callers turn it on only for as long as they are
        actively looking for a card.
        """
        if not self.is_ready():
            raise NFCError("Reader not ready")
        if not on:
            self.picc.release()
        self.pcd.antenna(on)

    def poll(self):
        """One look for a tag in the field, raising NFCNotFound when empty"""
        if not self.is_ready():
            raise NFCError("Reader not ready")
        return self.picc.select()

    # ---------- Records ----------

    def _read_header(self, tag):
        """Reads and validates the header. Nothing downstream runs until this passes."""
        header = self.picc.read(tag, 0, HEADER_LEN)
        return parse_header(header, tag.capacity)

    def has_record(self, tag):
        """True when the tag already carries a Krux record.

        Lets callers warn before overwriting. Absent or unreadable records
        report False.
        """
        try:
            self._read_header(tag)
            return True
        except NFCError:
            return False

    def read_record(self, tag):
        """Reads the record off a tag, validating it as hostile input throughout"""
        _, length = self._read_header(tag)

        # length has already been bounded by both the ceiling and this tag's
        # capacity, so it is safe to allocate against.
        return self.picc.read(tag, HEADER_LEN, length)

    def write_record(self, tag, data):
        """Writes a record, replacing whatever was there.

        Refuses payloads larger than MAX_PAYLOAD or than the tag can hold.
        """
        header = build_header(len(data), tag.capacity)

        # One contiguous image keeps the write block aligned from offset zero,
        # so picc.write never has to touch a block it does not fully own.
        self.picc.write(tag, 0, bytes(header) + bytes(data))

    def erase(self, tag):
        """Overwrites the record header so the tag no longer presents a record.

        Zeroing it is enough: the magic no longer matches and parsing stops at
        the first check.
        """
        self.picc.write(tag, 0, bytes(HEADER_LEN))
