# NFC reader, tag layer and record I/O tests
#
# The reader and one MIFARE Classic 1K are emulated at the I2C level, so the
# whole stack - register access, ISO14443A framing, sector authentication,
# linear addressing and the record header - is exercised end to end without
# hardware.

import pytest

UID = b"\xde\xad\xbe\xef"
SAK_CLASSIC_1K = 0x08


def crc_a(data):
    """ISO14443-A CRC, the value the reader's coprocessor produces"""
    crc = 0x6363
    for byte in data:
        byte ^= crc & 0xFF
        byte = (byte ^ (byte << 4)) & 0xFF
        crc = ((crc >> 8) ^ (byte << 8) ^ (byte << 3) ^ (byte >> 4)) & 0xFFFF
    return bytes([crc & 0xFF, crc >> 8])


class FakeClassic:
    """A MIFARE Classic 1K that answers the frames Krux sends it"""

    def __init__(self, uid=UID, sak=SAK_CLASSIC_1K):
        self.uid = uid
        self.sak = sak
        self.blocks = [bytearray(16) for _ in range(64)]
        self.authed = False
        self.write_target = None
        self.refuse_write = False

    @property
    def bcc(self):
        """UID check byte"""
        return self.uid[0] ^ self.uid[1] ^ self.uid[2] ^ self.uid[3]

    def frame(self, data, tx_last_bits):
        """Returns (reply, rx_last_bits), or None for silence"""
        if tx_last_bits == 7 and data == b"\x52":  # WUPA
            return b"\x04\x00", 0

        if data == b"\x93\x20":  # anticollision
            return self.uid + bytes([self.bcc]), 0

        if data[:2] == b"\x93\x70":  # select
            return bytes([self.sak]) + crc_a(bytes([self.sak])), 0

        if data[:2] == b"\x50\x00":  # HALT draws no reply
            self.authed = False
            return None

        if self.write_target is not None:  # the data half of a write
            block, self.write_target = self.write_target, None
            if len(data) != 18 or crc_a(data[:16]) != data[16:]:
                return None
            self.blocks[block][:] = data[:16]
            return b"\x0a", 4

        if data[0] == 0x30 and len(data) == 4:  # READ
            if not self.authed:
                return None
            block = data[1]
            return bytes(self.blocks[block]) + crc_a(bytes(self.blocks[block])), 0

        if data[0] == 0xA0 and len(data) == 4:  # WRITE
            if not self.authed or self.refuse_write:
                return None
            self.write_target = data[1]
            return b"\x0a", 4

        return None


class FakeI2C:
    """Enough of a WS1850S to drive the register level code"""

    def __init__(self, tag=None, present=True):
        self.regs = bytearray(0x40)
        self.fifo = bytearray()
        self.tag = tag
        self.present = present
        self.tx_last_bits = 0
        self.commands = []
        self._pending_reg = None
        # Force a reply the tag would never send, to exercise the size guards
        self.forced_level = None

    def writeto(self, _addr, buf):
        """One byte selects a register to read; more than one writes to it"""
        if not self.present:
            raise OSError("nack")
        buf = bytes(buf)
        if len(buf) == 1:
            self._pending_reg = buf[0]
            return
        reg, data = buf[0], buf[1:]
        if reg == 0x09:  # FIFODataReg does not auto increment
            self.fifo.extend(data)
            return
        for byte in data:
            self._write_reg(reg, byte)

    def readfrom(self, _addr, length):
        """Reads back whatever register was selected"""
        if not self.present:
            raise OSError("nack")
        reg = self._pending_reg
        if reg == 0x09:  # draining the FIFO
            out = bytes(self.fifo[:length])
            self.fifo = self.fifo[length:]
            return out
        if reg == 0x0A:  # FIFOLevelReg
            level = len(self.fifo) if self.forced_level is None else self.forced_level
            return bytes([level])
        return bytes(self.regs[reg : reg + 1]) * length

    def _write_reg(self, reg, val):
        if reg == 0x01:  # CommandReg
            self.commands.append(val)
            self._run_command(val)
            return
        if reg == 0x0A and val & 0x80:  # flush FIFO
            self.fifo = bytearray()
            return
        if reg == 0x04:  # ComIrqReg, writing clears
            self.regs[0x04] = 0
            return
        if reg == 0x0D:  # BitFramingReg
            self.tx_last_bits = val & 0x07
        self.regs[reg] = val

    def _run_command(self, cmd):
        self.regs[0x01] = cmd
        if cmd == 0x0F:  # soft reset, comes back idle
            self.regs[0x01] = 0
        elif cmd == 0x03:  # CalcCRC
            result = crc_a(bytes(self.fifo))
            self.regs[0x22], self.regs[0x21] = result[0], result[1]
            self.regs[0x05] |= 0x04  # DivIrqReg CRCIRq
        elif cmd == 0x0C:  # Transceive
            self._transceive()
        elif cmd == 0x0E:  # MFAuthent
            if self.tag is not None:
                self.tag.authed = True
            self.regs[0x08] |= 0x08  # Status2Reg Crypto1On
            self.regs[0x04] = 0x10  # ComIrqReg IdleIRq

    def _transceive(self):
        sent = bytes(self.fifo)
        self.fifo = bytearray()
        reply = self.tag.frame(sent, self.tx_last_bits) if self.tag else None
        self.regs[0x06] = 0  # ErrorReg
        if reply is None:
            self.regs[0x04] = 0x01  # TimerIRq
            return
        data, last_bits = reply
        self.fifo = bytearray(data)
        self.regs[0x0C] = last_bits & 0x07  # ControlReg
        self.regs[0x04] = 0x20 | 0x10  # RxIRq | IdleIRq


def _reader(i2c):
    from krux.nfc.pcd import WS1850S

    pcd = WS1850S(i2c)
    pcd.init()
    return pcd


def _nfc(m5stickv, i2c):
    """An NFC facade wired to the fake bus instead of a real one"""
    from krux.nfc import NFC

    nfc = NFC(scl=1, sda=2)
    nfc._open_bus = lambda: i2c
    nfc.init()
    nfc.field(True)
    return nfc


# ---------- Reader bring up ----------


def test_init_probes_the_bus(m5stickv):
    pcd = _reader(FakeI2C())
    assert pcd.ready
    # Comes up with the antenna dark
    assert not pcd._read_byte(0x14) & 0x03


def test_missing_reader_is_reported(m5stickv):
    from krux.nfc.pcd import WS1850S
    from krux.nfc.errors import NFCNotFound

    with pytest.raises(NFCNotFound):
        WS1850S(FakeI2C(present=False)).init()


def test_reader_that_does_not_echo_is_refused(m5stickv):
    from krux.nfc.pcd import WS1850S
    from krux.nfc.errors import NFCNotFound

    class Deaf(FakeI2C):
        """Answers on the bus but does not behave like a WS1850S"""

        def _write_reg(self, reg, val):
            if reg == 0x2D:
                return
            super()._write_reg(reg, val)

    with pytest.raises(NFCNotFound):
        WS1850S(Deaf()).init()


def test_antenna_toggles_tx_control(m5stickv):
    pcd = _reader(FakeI2C())
    pcd.antenna(True)
    assert pcd._read_byte(0x14) & 0x03 == 0x03
    pcd.antenna(False)
    assert not pcd._read_byte(0x14) & 0x03


def test_deinit_drops_the_field(m5stickv):
    i2c = FakeI2C()
    pcd = _reader(i2c)
    pcd.antenna(True)
    pcd.deinit()
    assert not pcd.ready
    assert not i2c.regs[0x14] & 0x03


# ---------- Frame exchange guards ----------


def test_silent_tag_times_out(m5stickv):
    from krux.nfc.errors import NFCTimeout

    pcd = _reader(FakeI2C(FakeClassic()))
    with pytest.raises(NFCTimeout):
        pcd.transceive(b"\x99", 0, 4)


def test_oversized_reply_is_refused_not_truncated(m5stickv):
    from krux.nfc.errors import NFCSizeError

    i2c = FakeI2C(FakeClassic())
    pcd = _reader(i2c)
    # ATQA is two bytes; ask for a buffer that cannot hold it
    with pytest.raises(NFCSizeError):
        pcd.transceive(b"\x52", 7, 1)


def test_reply_longer_than_the_fifo_is_refused(m5stickv):
    from krux.nfc.errors import NFCResponseError

    i2c = FakeI2C(FakeClassic())
    pcd = _reader(i2c)
    i2c.forced_level = 200
    with pytest.raises(NFCResponseError):
        pcd.transceive(b"\x52", 7, 64)


def test_frame_longer_than_the_fifo_is_refused(m5stickv):
    from krux.nfc.errors import NFCSizeError

    pcd = _reader(FakeI2C(FakeClassic()))
    with pytest.raises(NFCSizeError):
        pcd.transceive(b"\x00" * 65, 0, 2)


def test_reader_error_bits_fail_the_exchange(m5stickv):
    from krux.nfc.errors import NFCResponseError

    class Colliding(FakeI2C):
        """Two cards in the field"""

        def _transceive(self):
            super()._transceive()
            self.regs[0x06] = 0x08  # CollErr

    pcd = _reader(Colliding(FakeClassic()))
    with pytest.raises(NFCResponseError):
        pcd.transceive(b"\x52", 7, 4)


def test_bad_crc_is_caught(m5stickv):
    from krux.nfc.errors import NFCCRCError

    class Lying(FakeClassic):
        """Answers a select with a corrupted CRC"""

        def frame(self, data, tx_last_bits):
            reply = super().frame(data, tx_last_bits)
            if reply and data[:2] == b"\x93\x70":
                return bytes([self.sak]) + b"\x00\x00", 0
            return reply

    pcd = _reader(FakeI2C(Lying()))
    with pytest.raises(NFCCRCError):
        pcd.transceive_crc(b"\x93\x70" + UID + bytes([Lying().bcc]), 3)


def test_calc_crc_matches_the_reference(m5stickv):
    pcd = _reader(FakeI2C())
    assert pcd.calc_crc(b"\x30\x04") == crc_a(b"\x30\x04")


# ---------- Selection ----------


def test_select_reads_a_classic(m5stickv):
    from krux.nfc.picc import PICC, TAG_MIFARE_CLASSIC

    picc = PICC(_reader(FakeI2C(FakeClassic())))
    tag = picc.select()
    assert tag.type == TAG_MIFARE_CLASSIC
    assert tag.uid == UID
    assert tag.sak == SAK_CLASSIC_1K
    # 47 data blocks of 16 bytes, clamped to one record's worth
    assert tag.capacity == 720


def test_empty_field_reports_no_card(m5stickv):
    from krux.nfc.picc import PICC
    from krux.nfc.errors import NFCNotFound

    picc = PICC(_reader(FakeI2C()))
    with pytest.raises(NFCNotFound):
        picc.select()


def test_unsupported_sak_is_refused(m5stickv):
    from krux.nfc.picc import PICC
    from krux.nfc.errors import NFCNotFound

    # 0x20 is ISO14443-4, a card Krux does not know how to address
    picc = PICC(_reader(FakeI2C(FakeClassic(sak=0x20))))
    with pytest.raises(NFCNotFound):
        picc.select()


def test_bad_bcc_is_refused(m5stickv):
    from krux.nfc.picc import PICC
    from krux.nfc.errors import NFCNotFound

    class BadBcc(FakeClassic):
        """A malformed anticollision reply"""

        def frame(self, data, tx_last_bits):
            if data == b"\x93\x20":
                return self.uid + b"\x00", 0
            return super().frame(data, tx_last_bits)

    picc = PICC(_reader(FakeI2C(BadBcc())))
    with pytest.raises(NFCNotFound):
        picc.select()


# ---------- Linear addressing ----------


def test_block_mapping_never_touches_block_zero_or_a_trailer(m5stickv):
    from krux.nfc.picc import PICC, MF_DATA_BLOCKS

    blocks = [PICC._mf_physical_block(i) for i in range(MF_DATA_BLOCKS)]
    assert 0 not in blocks
    assert not any(block % 4 == 3 for block in blocks)
    assert blocks == sorted(blocks)
    assert len(set(blocks)) == MF_DATA_BLOCKS
    assert blocks[:4] == [1, 2, 4, 5]


def test_block_past_the_last_data_block_is_refused(m5stickv):
    from krux.nfc.picc import PICC, MF_DATA_BLOCKS
    from krux.nfc.errors import NFCSizeError

    with pytest.raises(NFCSizeError):
        PICC._mf_physical_block(MF_DATA_BLOCKS)


def test_read_and_write_span_blocks(m5stickv):
    from krux.nfc.picc import PICC

    tag_model = FakeClassic()
    picc = PICC(_reader(FakeI2C(tag_model)))
    tag = picc.select()

    payload = bytes(range(48))
    picc.write(tag, 0, payload)
    assert picc.read(tag, 0, len(payload)) == payload
    # An unaligned read still lands on the right bytes
    assert picc.read(tag, 5, 20) == payload[5:25]


def test_write_outside_the_tag_is_refused(m5stickv):
    from krux.nfc.picc import PICC
    from krux.nfc.errors import NFCSizeError

    picc = PICC(_reader(FakeI2C(FakeClassic())))
    tag = picc.select()
    with pytest.raises(NFCSizeError):
        picc.write(tag, 0, bytes(tag.capacity + 1))
    with pytest.raises(NFCSizeError):
        picc.read(tag, tag.capacity - 8, 16)


def test_unaligned_write_is_refused(m5stickv):
    from krux.nfc.picc import PICC
    from krux.nfc.errors import NFCSizeError

    picc = PICC(_reader(FakeI2C(FakeClassic())))
    tag = picc.select()
    with pytest.raises(NFCSizeError):
        picc.write(tag, 8, bytes(16))


# ---------- Records ----------


def test_record_round_trip(m5stickv):
    i2c = FakeI2C(FakeClassic())
    nfc = _nfc(m5stickv, i2c)
    tag = nfc.poll()

    assert not nfc.has_record(tag)

    envelope = bytes(range(60))
    nfc.write_record(tag, envelope)

    assert nfc.has_record(tag)
    assert nfc.read_record(tag) == envelope


def test_erase_stops_the_card_presenting_a_record(m5stickv):
    from krux.nfc.errors import NoRecordError

    nfc = _nfc(m5stickv, FakeI2C(FakeClassic()))
    tag = nfc.poll()

    nfc.write_record(tag, bytes(32))
    nfc.erase(tag)

    assert not nfc.has_record(tag)
    with pytest.raises(NoRecordError):
        nfc.read_record(tag)


def test_payload_over_the_ceiling_is_refused(m5stickv):
    from krux.nfc.errors import InvalidRecordError
    from krux.nfc.record import MAX_PAYLOAD

    nfc = _nfc(m5stickv, FakeI2C(FakeClassic()))
    tag = nfc.poll()

    with pytest.raises(InvalidRecordError):
        nfc.write_record(tag, bytes(MAX_PAYLOAD + 1))


def test_blank_card_reports_no_record(m5stickv):
    from krux.nfc.errors import NoRecordError

    nfc = _nfc(m5stickv, FakeI2C(FakeClassic()))
    tag = nfc.poll()

    assert not nfc.has_record(tag)
    with pytest.raises(NoRecordError):
        nfc.read_record(tag)


def test_a_card_that_stops_answering_mid_read_fails(m5stickv):
    from krux.nfc.errors import NFCError

    tag_model = FakeClassic()
    nfc = _nfc(m5stickv, FakeI2C(tag_model))
    tag = nfc.poll()
    nfc.write_record(tag, bytes(range(40)))

    tag_model.authed = False
    tag_model.refuse_write = True

    def silent(data, tx_last_bits):
        return None

    tag_model.frame = silent
    with pytest.raises(NFCError):
        nfc.read_record(tag)


def test_deinit_releases_the_tag_and_the_field(m5stickv):
    i2c = FakeI2C(FakeClassic())
    nfc = _nfc(m5stickv, i2c)
    nfc.poll()

    nfc.deinit()
    assert not nfc.is_ready()
    assert not i2c.regs[0x14] & 0x03
    assert not i2c.regs[0x08] & 0x08  # crypto1 dropped
