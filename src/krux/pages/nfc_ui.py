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
"""NFC card pages - tap prompt and card I/O.

The RF field is energized in exactly one place, NFCTapPage, and comes down on
every exit path. Outside these pages the reader is inert: with NFC switched off
the I2C bus is never opened, so a module left plugged in is untouched rather
than merely unused.

Only the KEF envelope crosses the antenna. The mnemonic is turned into entropy
and sealed before the reader is attached, and the reader is detached again
before the decryption password is asked for.
"""

from ..display import BOTTOM_PROMPT_LINE
from ..krux_settings import t, Settings
from ..themes import theme
from . import Page, MENU_CONTINUE

# Also how long a cancel keypress can wait, so it stays short
POLL_INTERVAL_MS = 200


class NFCTapPage(Page):
    """Card presence prompt and RF field lifecycle"""

    def __init__(self, ctx):
        super().__init__(ctx, None)
        self.nfc = None

    def open_reader(self):
        """Attaches the reader, reporting failure on screen.

        The menu entries that lead here are already gated on the setting, but
        the check is repeated at the hardware boundary so no future caller can
        reach the bus around it.
        """
        from ..nfc import NFC, NFCError

        if not Settings().hardware.nfc.enabled:
            self.flash_error(t("NFC reader not found"))
            return False
        nfc = NFC()
        try:
            nfc.init()
        except NFCError:
            self.flash_error(t("NFC reader not found"))
            return False
        self.nfc = nfc
        return True

    def close_reader(self):
        """Drops the field and detaches the reader"""
        if self.nfc is not None:
            self.nfc.deinit()
            self.nfc = None

    def wait_for_tag(self, title):
        """Energizes the field and polls until a card shows up or the user leaves"""
        from ..nfc import NFCError

        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(
            title + "\n\n" + t("Hold a card to the reader")
        )
        self.ctx.display.draw_hcentered_text(
            t("Press PAGE to cancel."), BOTTOM_PROMPT_LINE, color=theme.highlight_color
        )
        try:
            self.nfc.field(True)
        except NFCError:
            self.flash_error(t("NFC reader not found"))
            return False

        while True:
            try:
                self.nfc.poll()
                return True
            except NFCError:
                # An empty field, two cards at once, and a family Krux does not
                # accept all look the same from here: keep waiting.
                pass
            if (
                self.ctx.input.wait_for_button(
                    block=False, wait_duration=POLL_INTERVAL_MS
                )
                is not None
            ):
                break

        try:
            self.nfc.field(False)
        except NFCError:
            pass
        return False

    def test_reader(self):
        """Probes for a reader and reports what it found, field never coming up"""
        if not self.open_reader():
            return MENU_CONTINUE
        self.close_reader()
        self.flash_success(t("Reader detected"))
        return MENU_CONTINUE


class StoreOnNFC(NFCTapPage):
    """Writes a KEF envelope to a card"""

    def write(self, kef_envelope, mnemonic_id):
        """Asks for a card and writes the envelope onto it"""
        from ..nfc import NFCError, NFCSizeError

        if not self.open_reader():
            return MENU_CONTINUE
        try:
            if not self.wait_for_tag(t("Store on NFC Card")):
                return MENU_CONTINUE
            if self.nfc.has_record():
                self.ctx.display.clear()
                if not self.prompt(t("Overwrite?"), self.ctx.display.height() // 2):
                    return MENU_CONTINUE
                # Ask for the card again rather than trusting the earlier poll:
                # the prompt was up in between, and the card only had to drift a
                # centimetre.
                if not self.wait_for_tag(t("Store on NFC Card")):
                    return MENU_CONTINUE
            try:
                self.nfc.write_record(kef_envelope)
            except NFCSizeError:
                self.flash_error(t("Card too small"))
                return MENU_CONTINUE
            except NFCError:
                self.flash_error(t("Failed to store mnemonic"))
                return MENU_CONTINUE
        finally:
            self.close_reader()

        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(
            t("Encrypted mnemonic stored with ID:") + " " + mnemonic_id,
            highlight_prefix=":",
        )
        self.ctx.input.wait_for_button()
        return MENU_CONTINUE


class LoadFromNFC(NFCTapPage):
    """Reads a KEF envelope off a card"""

    def read(self):
        """Returns the envelope bytes, or None. Detaches the reader first, so
        the password is asked for with the antenna already down."""
        from ..nfc import NFCError

        if not self.open_reader():
            return None
        try:
            if not self.wait_for_tag(t("From NFC Card")):
                return None
            try:
                return self.nfc.read_record()
            except NFCError:
                # A card with no record, an unreadable one, and one whose header
                # was refused all say the same thing here on purpose.
                self.flash_error(t("No backup on this card"))
                return None
        finally:
            self.close_reader()
