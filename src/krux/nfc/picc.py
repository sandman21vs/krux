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
"""Tag layer (PICC) - selection and linear byte addressing.

Presents every supported tag family as a flat byte array so the record layer
never learns what it is talking to. MIFARE Classic offsets skip block 0 and
every sector trailer; Ultralight/NTAG offsets start at page 4.

Only tags Krux recognizes are selected at all: an unexpected SAK is reported as
an empty field rather than probed further.
"""

from .errors import NFCError, NFCCRCError, NFCSizeError, NFCResponseError, NFCNotFound
from .record import HEADER_LEN, MAX_PAYLOAD
from .pcd import (
    CRC_LEN,
    FIFO_SIZE,
    PICC_CMD_HALT,
    PICC_CMD_MF_AUTH_KEY_A,
    PICC_CMD_MF_READ,
    PICC_CMD_MF_WRITE,
    PICC_CMD_SEL_CL1,
    PICC_CMD_SEL_CL2,
    PICC_CMD_UL_WRITE,
    PICC_CMD_WUPA,
)

TAG_MIFARE_CLASSIC = 1
TAG_ULTRALIGHT = 2  # Ultralight and NTAG21x

# SAK values Krux accepts. Anything else is treated as an empty field: the point
# is to talk only to what we know how to talk to.
SAK_ULTRALIGHT = 0x00
SAK_CLASSIC_1K = 0x08
SAK_CLASSIC_4K = 0x18
SAK_CLASSIC_1K_INFINEON = 0x88
SAK_CASCADE_BIT = 0x04

CASCADE_TAG = 0x88

# MIFARE Classic geometry. 4K tags are addressed as 1K: their upper sectors hold
# 16 blocks instead of 4, and a seed needs a fraction of the first 16 sectors
# anyway.
MF_BLOCK_SIZE = 16
MF_DATA_BLOCKS = 47  # 64 blocks less block 0 and 16 sector trailers
MF_DEFAULT_KEY = b"\xff\xff\xff\xff\xff\xff"

# Ultralight / NTAG geometry
UL_PAGE_SIZE = 4
UL_DATA_FIRST_PAGE = 4
UL_CC_PAGE = 3
UL_MIN_CAPACITY = 48  # plain Ultralight, pages 4..15
UL_MAX_CAPACITY = 888  # NTAG216 user memory

# Nothing larger than one record is ever addressable, whatever a tag claims.
MAX_CAPACITY = MAX_PAYLOAD + HEADER_LEN

# A READ answers with four pages
READ_LEN = 16


class Tag:
    """One selected tag, presented as a flat byte array"""

    def __init__(self, tag_type, uid, sak, capacity):
        self.type = tag_type
        self.uid = uid
        self.sak = sak
        self.capacity = capacity


class PICC:
    """Selection and linear read/write over one reader"""

    def __init__(self, pcd):
        self.pcd = pcd
        # Sector currently authenticated, or None. Reset on every select and
        # release so a stale session can never be mistaken for a fresh one.
        self.authed_sector = None

    # ---------- Selection ----------

    def _request_tag(self):
        """Wakes whatever is in the field.

        WUPA rather than REQA, and it is a 7 bit frame. Every select starts by
        releasing whatever was held, which halts the tag - and a halted tag
        answers WUPA but ignores REQA, so REQA here would make a card
        unselectable for the rest of its time in the field.
        """
        atqa, _ = self.pcd.transceive(bytes([PICC_CMD_WUPA]), 7, 2)
        if len(atqa) != 2:
            raise NFCResponseError("Bad ATQA")

    def _cascade_level(self, sel_cmd):
        """Runs one cascade level: anticollision, then select.

        No collision resolution - Krux asks for a single card, and two cards in
        the field simply read as "nothing there" until one is taken away.
        """
        reply, _ = self.pcd.transceive(bytes([sel_cmd, 0x20]), 0, 5)
        if len(reply) != 5:
            raise NFCResponseError("Bad anticollision")

        # BCC is a plain XOR check. A mismatch means a malformed frame, so stop
        # rather than build a UID out of it.
        if reply[0] ^ reply[1] ^ reply[2] ^ reply[3] != reply[4]:
            raise NFCCRCError("Bad BCC")

        select = bytes([sel_cmd, 0x70]) + reply
        sak = self.pcd.transceive_crc(select, 1 + CRC_LEN)
        if len(sak) != 1:
            raise NFCResponseError("Bad SAK")

        return reply[:4], sak[0]

    def _ultralight_capacity(self):
        """Reads the compatibility container and derives a usable size"""
        pages = self.pcd.transceive_crc(
            bytes([PICC_CMD_MF_READ, UL_CC_PAGE]), READ_LEN + CRC_LEN
        )
        if len(pages) != READ_LEN:
            raise NFCResponseError("Bad CC read")

        # pages[2] is the size byte, and it was written by whoever held the tag
        # last - `size * 8` is exactly the kind of number that turns into an
        # overflow if believed. Take it only when the NFC Forum magic byte is
        # there, and clamp it at both ends regardless.
        capacity = UL_MIN_CAPACITY
        if pages[0] == 0xE1 and pages[2] > 0:
            capacity = pages[2] * 8

        return min(max(capacity, UL_MIN_CAPACITY), UL_MAX_CAPACITY)

    def select(self):
        """Wakes, identifies and selects one tag.

        Raises NFCNotFound when the field is empty, when more than one tag is
        present, or when the tag is not a family Krux accepts.
        """
        self.release()

        try:
            self._request_tag()
            uid_part, sak = self._cascade_level(PICC_CMD_SEL_CL1)

            if sak & SAK_CASCADE_BIT:
                # Double size UID: the first byte of level 1 is the cascade tag,
                # not UID data. Level 3 (ten byte UIDs) is not supported and is
                # not guessed at.
                if uid_part[0] != CASCADE_TAG:
                    raise NFCNotFound("Unsupported UID")
                uid = uid_part[1:4]
                uid_part, sak = self._cascade_level(PICC_CMD_SEL_CL2)
                if sak & SAK_CASCADE_BIT:
                    raise NFCNotFound("Unsupported UID")
                uid += uid_part
            else:
                uid = uid_part
        except NFCError as exc:
            raise NFCNotFound("No card") from exc

        if sak in (SAK_CLASSIC_1K, SAK_CLASSIC_4K, SAK_CLASSIC_1K_INFINEON):
            tag_type = TAG_MIFARE_CLASSIC
            capacity = MF_DATA_BLOCKS * MF_BLOCK_SIZE
        elif sak == SAK_ULTRALIGHT:
            tag_type = TAG_ULTRALIGHT
            try:
                capacity = self._ultralight_capacity()
            except NFCError as exc:
                self.release()
                raise NFCNotFound("Unreadable card") from exc
        else:
            self.release()
            raise NFCNotFound("Unsupported card")

        return Tag(tag_type, uid, sak, min(capacity, MAX_CAPACITY))

    def release(self):
        """Halts the tag and drops any crypto1 session. Safe to call always."""
        self.authed_sector = None
        if not self.pcd.ready:
            return

        # HALT goes out before crypto is dropped: while a sector is
        # authenticated the reader enciphers the frame, and a plaintext HALT
        # would be ignored, leaving the tag awake in a state it thinks is still
        # authenticated. HALT draws no reply, so a timeout here is the success
        # case.
        try:
            halt = bytes([PICC_CMD_HALT, 0x00])
            self.pcd.transceive(halt + self.pcd.calc_crc(halt), 0, 0)
        except NFCError:
            pass

        if self.pcd.crypto_on:
            self.pcd.stop_crypto()

    # ---------- MIFARE Classic ----------

    @staticmethod
    def _mf_physical_block(index):
        """Maps a data block index onto a physical block.

        Skips the manufacturer block and every sector trailer. Sector 0
        contributes two data blocks (1, 2); every later sector contributes
        three.
        """
        if index >= MF_DATA_BLOCKS:
            raise NFCSizeError("Block out of range")

        if index < 2:
            block = index + 1
        else:
            rest = index - 2
            block = (rest // 3 + 1) * 4 + (rest % 3)

        # The mapping already excludes them; this catches a future edit to the
        # arithmetic before it destroys a sector rather than after.
        if block == 0 or block % 4 == 3:
            raise NFCError("Refusing to touch a sector trailer")

        return block

    def _mf_authenticate(self, tag, block):
        """Authenticates the sector holding a block, with the factory key A"""
        sector = block // 4
        if sector == self.authed_sector:
            return
        try:
            self.pcd.mf_authenticate(
                PICC_CMD_MF_AUTH_KEY_A, block, MF_DEFAULT_KEY, tag.uid
            )
        except NFCError:
            self.authed_sector = None
            raise
        self.authed_sector = sector

    def _mf_read_block(self, tag, block):
        """Reads one 16 byte block"""
        self._mf_authenticate(tag, block)

        # The block arrives with its CRC_A attached; the buffer has to hold both
        # or the reply reads as oversized.
        data = self.pcd.transceive_crc(
            bytes([PICC_CMD_MF_READ, block]), MF_BLOCK_SIZE + CRC_LEN
        )
        if len(data) != MF_BLOCK_SIZE:
            raise NFCResponseError("Bad block read")
        return data

    def _frame_ack(self, data):
        """Sends one frame and requires a 4 bit ACK back.

        MIFARE write is two frames, each answered by a nibble.
        """
        if len(data) + CRC_LEN > FIFO_SIZE:
            raise NFCSizeError("Frame too long")

        frame = bytes(data) + self.pcd.calc_crc(data)
        reply, valid_bits = self.pcd.transceive(frame, 0, 1)

        # An ACK is exactly one nibble holding 0x0A. Anything else - a NAK, a
        # full byte, a longer frame - is a failed write, not a partial success.
        if len(reply) != 1 or valid_bits != 4 or reply[0] & 0x0F != 0x0A:
            raise NFCResponseError("Write not acknowledged")

    def _mf_write_block(self, tag, block, data):
        """Writes one 16 byte block"""
        self._mf_authenticate(tag, block)
        self._frame_ack(bytes([PICC_CMD_MF_WRITE, block]))
        self._frame_ack(data)

    # ---------- Ultralight / NTAG ----------

    def _ul_read_pages(self, page):
        """Reads the four pages starting at page"""
        data = self.pcd.transceive_crc(
            bytes([PICC_CMD_MF_READ, page]), READ_LEN + CRC_LEN
        )
        if len(data) != READ_LEN:
            raise NFCResponseError("Bad page read")
        return data

    def _ul_write_page(self, page, data):
        """Writes one 4 byte page"""
        self._frame_ack(bytes([PICC_CMD_UL_WRITE, page]) + bytes(data))

    # ---------- Linear access ----------

    @staticmethod
    def _check_range(tag, offset, length):
        """Refuses a range that falls outside the tag"""
        if not length:
            raise NFCSizeError("Empty range")
        if offset > tag.capacity or length > tag.capacity - offset:
            raise NFCSizeError("Range outside tag")

    def read(self, tag, offset, length):
        """Reads length bytes starting at a linear offset.

        Offset and length are free form; the mapping handles block and page
        boundaries.
        """
        self._check_range(tag, offset, length)

        out = bytearray()
        while len(out) < length:
            pos = offset + len(out)
            aligned = pos - (pos % READ_LEN)
            skip = pos - aligned
            take = min(READ_LEN - skip, length - len(out))

            if tag.type == TAG_MIFARE_CLASSIC:
                block = self._mf_read_block(
                    tag, self._mf_physical_block(aligned // MF_BLOCK_SIZE)
                )
            else:
                block = self._ul_read_pages(
                    UL_DATA_FIRST_PAGE + aligned // UL_PAGE_SIZE
                )

            out += block[skip : skip + take]

        return bytes(out)

    def write(self, tag, offset, data):
        """Writes data starting at a linear offset.

        offset must land on a block boundary for the tag family (16 bytes for
        Classic, 4 for Ultralight); a trailing partial block is zero padded.
        Writes that would touch block 0 or a sector trailer are refused - a
        corrupted trailer bricks its sector permanently.
        """
        self._check_range(tag, offset, len(data))

        unit = MF_BLOCK_SIZE if tag.type == TAG_MIFARE_CLASSIC else UL_PAGE_SIZE
        if offset % unit:
            raise NFCSizeError("Unaligned write")

        done = 0
        while done < len(data):
            # Pad the tail so a short final block still writes a full unit; the
            # record header carries the real length.
            chunk = bytearray(unit)
            take = min(unit, len(data) - done)
            chunk[0:take] = data[done : done + take]

            pos = offset + done
            if tag.type == TAG_MIFARE_CLASSIC:
                self._mf_write_block(
                    tag, self._mf_physical_block(pos // MF_BLOCK_SIZE), chunk
                )
            else:
                self._ul_write_page(UL_DATA_FIRST_PAGE + pos // UL_PAGE_SIZE, chunk)

            done += unit
