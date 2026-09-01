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
"""NFC card pages - tap prompt, store, load and erase.

The RF field is energized in exactly one place, NFCTapPage, and it comes down
with the page. Outside these pages the reader is inert: the I2C bus is not even
opened, so a device with NFC switched off never touches the module even with it
plugged in.

Only the KEF envelope crosses the antenna. The mnemonic is turned into entropy
and sealed before the reader is attached, and the reader is detached again
before the decryption password is asked for.
"""

from ..display import BOTTOM_PROMPT_LINE
from ..krux_settings import t, Settings
from ..themes import theme
from . import Page, MENU_CONTINUE

# How often the field is asked whether a card showed up. It is also how long a
# cancel keypress can wait, so it stays short.
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
        reach the bus around it. A disabled reader is untouched, not merely
        unused.
        """
        if not Settings().hardware.nfc.enabled:
            self.flash_error(t("NFC is disabled"))
            return False

        from ..nfc import NFC
        from ..nfc.errors import NFCError

        nfc = NFC()
        try:
            nfc.init()
        except NFCError:
            self.flash_error(t("NFC reader not found"))
            return False

        self.nfc = nfc
        return True

    def close_reader(self):
        """Drops the field and detaches the reader.

        Called on every exit path, so the antenna is never left live behind a
        page the user has already walked away from.
        """
        if self.nfc is not None:
            self.nfc.deinit()
            self.nfc = None

    def wait_for_tag(self, title, hint=""):
        """Energizes the field and polls until a card shows up or the user leaves.

        Returns the selected tag, or None when the user cancelled or the reader
        stopped answering.
        """
        from ..nfc.errors import NFCError

        text = title + "\n\n" + t("Hold a card to the reader")
        if hint:
            text += "\n\n" + hint
        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(text)
        self.ctx.display.draw_hcentered_text(
            t("Press any key to cancel"),
            BOTTOM_PROMPT_LINE,
            color=theme.highlight_color,
        )

        try:
            self.nfc.field(True)
        except NFCError:
            self.flash_error(t("NFC reader not found"))
            return None

        while True:
            try:
                return self.nfc.poll()
            except NFCError:
                # An empty field, two cards at once, or a family Krux does not
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
        return None

    def test_reader(self):
        """Probes for a reader and reports what it found"""
        if not self.open_reader():
            return MENU_CONTINUE

        # The probe is a one off, not a session: leave nothing attached.
        self.close_reader()
        self.flash_success(t("Reader detected"))
        return MENU_CONTINUE


class StoreOnNFC(NFCTapPage):
    """Writes a KEF envelope to a card"""

    def write(self, kef_envelope, mnemonic_id):
        """Asks for a card and writes the envelope onto it"""
        from ..nfc.errors import NFCError, NFCSizeError, InvalidRecordError

        if not self.open_reader():
            return MENU_CONTINUE

        try:
            tag = self.wait_for_tag(t("Save to NFC"), mnemonic_id)
            if tag is None:
                return MENU_CONTINUE

            if self.nfc.has_record(tag):
                self.ctx.display.clear()
                if not self.prompt(
                    t("This card already holds a backup.") + "\n\n" + t("Overwrite?"),
                    self.ctx.display.height() // 2,
                ):
                    return MENU_CONTINUE

                # Ask for the card again rather than trusting the tag from the
                # first poll: the prompt was up in between, and the card only
                # had to drift a centimetre.
                tag = self.wait_for_tag(t("Save to NFC"), mnemonic_id)
                if tag is None:
                    return MENU_CONTINUE

            try:
                self.nfc.write_record(tag, kef_envelope)
            except (NFCSizeError, InvalidRecordError):
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
        """Returns the envelope bytes, or None when nothing was read.

        The reader is detached before returning, so the decryption password is
        asked for with the antenna already down.
        """
        from ..nfc.errors import NFCError

        if not self.open_reader():
            return None

        try:
            tag = self.wait_for_tag(t("Load from NFC"))
            if tag is None:
                return None
            try:
                return self.nfc.read_record(tag)
            except NFCError:
                # A card with no record, an unreadable one, and one whose header
                # was refused all say the same thing here on purpose.
                self.flash_error(t("No backup on this card"))
                return None
        finally:
            self.close_reader()


class EraseNFCCard(NFCTapPage):
    """Blanks the record header so a card stops presenting a backup"""

    def erase(self):
        """Asks for a card, confirms, and wipes its record header"""
        from ..nfc.errors import NFCError

        if not self.open_reader():
            return MENU_CONTINUE

        try:
            tag = self.wait_for_tag(t("Erase NFC Card"))
            if tag is None:
                return MENU_CONTINUE

            if not self.nfc.has_record(tag):
                self.flash_error(t("No backup on this card"))
                return MENU_CONTINUE

            self.ctx.display.clear()
            if not self.prompt(t("Erase this card?"), self.ctx.display.height() // 2):
                return MENU_CONTINUE

            tag = self.wait_for_tag(t("Erase NFC Card"))
            if tag is None:
                return MENU_CONTINUE

            try:
                self.nfc.erase(tag)
            except NFCError:
                self.flash_error(t("Failed to erase card"))
                return MENU_CONTINUE
        finally:
            self.close_reader()

        self.flash_success(t("Card erased"))
        return MENU_CONTINUE
