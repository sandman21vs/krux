import pytest

UID = b"\xde\xad\xbe\xef"
BCC = 0xDE ^ 0xAD ^ 0xBE ^ 0xEF


def crc_a(data):
    """ISO14443-A CRC, the value that goes on the air"""
    crc = 0x6363
    for byte in data:
        byte ^= crc & 0xFF
        byte = (byte ^ (byte << 4)) & 0xFF
        crc = ((crc >> 8) ^ (byte << 8) ^ (byte << 3) ^ (byte >> 4)) & 0xFFFF
    return bytes([crc & 0xFF, crc >> 8])


class FakePin:
    """A GPIO whose writes the chip can react to"""

    def __init__(self, chip=None, name="", level=0):
        self.chip = chip
        self.name = name
        self.level = level

    def value(self, level=None):
        if level is None:
            return self.level
        self.level = level
        if self.chip is not None:
            self.chip.on_pin(self.name, level)
        return None


class FakeChip:
    """The PN5180's command protocol, its BUSY handshake and one Classic 1K.

    BUSY is the part worth modelling faithfully: it rises when a command is
    clocked in and only falls once NSS has been released. A driver that skips
    either wait reads the previous command's tail, which is why the fake
    refuses to answer while it is still busy.
    """

    def __init__(self, version=b"\x04\x03", tag=True, reply_len=None):
        self.version = version
        self.tag = tag
        self.regs = {}
        self.pending = b""
        self.busy = 0
        self.rf_on = False
        self.rf_config = None
        self.air = []  # frames that reached the antenna
        self.auth_status = 0
        self.forced_len = reply_len  # to fake a lying RX_STATUS
        self.stuck_busy = False

    # ---- pins ----

    def on_pin(self, name, level):
        if name == "nss" and level == 1 and not self.stuck_busy:
            self.busy = 0

    def busy_value(self):
        return self.busy

    # ---- SPI ----

    def write(self, frame):
        if self.busy and not self.stuck_busy:
            raise AssertionError("command clocked in while BUSY was high")
        self.busy = 1
        self._handle(bytes(frame))

    def read(self, length):
        data = self.pending[:length]
        self.pending = self.pending[length:]
        return data

    # ---- protocol ----

    def _reg(self, name):
        return self.regs.get(name, 0)

    def _handle(self, frame):
        cmd, body = frame[0], frame[1:]
        if cmd == 0x00:  # WRITE_REGISTER
            self.regs[body[0]] = int.from_bytes(body[1:5], "little")
            self._sync_state(body[0])
        elif cmd == 0x01:  # OR_MASK
            self.regs[body[0]] = self._reg(body[0]) | int.from_bytes(
                body[1:5], "little"
            )
            self._sync_state(body[0])
        elif cmd == 0x02:  # AND_MASK
            self.regs[body[0]] = self._reg(body[0]) & int.from_bytes(
                body[1:5], "little"
            )
            self._sync_state(body[0])
        elif cmd == 0x04:  # READ_REGISTER
            self.pending = self._reg(body[0]).to_bytes(4, "little")
        elif cmd == 0x07:  # READ_EEPROM
            self.pending = self.version
        elif cmd == 0x09:  # SEND_DATA
            self._on_air(body[1:])
        elif cmd == 0x0A:  # READ_DATA
            self.pending = self._rx
        elif cmd == 0x0C:  # MIFARE_AUTHENTICATE
            self.pending = bytes([self.auth_status])
        elif cmd == 0x11:  # LOAD_RF_CONFIG
            self.rf_config = (body[0], body[1])
        elif cmd == 0x16:  # RF_ON
            self.rf_on = True
        elif cmd == 0x17:  # RF_OFF
            self.rf_on = False

    def _sync_state(self, reg):
        """TRANSCEIVE_CONTROL follows SYSTEM_CONFIG's command field.

        The driver checks the state machine reached WaitTransmit before it
        sends, so a fake that leaves this at zero makes every transceive fail
        for the wrong reason.
        """
        if reg != 0x00:
            return
        command = self._reg(0x00) & 0x07
        state = 1 if command == 3 else 0  # WaitTransmit when transceiving
        self.regs[0x04] = state << 24

    def _on_air(self, data):
        self.air.append(bytes(data))
        self._rx = self._answer(bytes(data))
        length = self.forced_len if self.forced_len is not None else len(self._rx)
        # RX_STATUS: byte count in [8:0], valid bits of the last byte in [12:9]
        self.regs[0x13] = length & 0x1FF
        self.regs[0x02] = 1 if self._rx else 0  # IRQ_STATUS: RX_IRQ

    def _answer(self, data):
        if not self.tag:
            return b""
        if data[:1] == b"\x52":  # WUPA
            return b"\x04\x00"
        if data[:2] == b"\x93\x20":  # anticollision
            return UID + bytes([BCC])
        if data[:2] == b"\x93\x70":  # select
            return b"\x08" + crc_a(b"\x08")
        return b""

    _rx = b""


def make_pn5180(chip):
    """A PN5180 with its bus replaced by the fake chip"""
    from krux.nfc_pn5180 import PN5180

    reader = PN5180(sck=28, mosi=29, miso=30, nss=25, busy=22, rst=31)

    def open_bus():
        reader.spi = chip
        reader.nss = FakePin(chip, "nss", 1)
        reader.busy = FakePin(chip, "busy")
        reader.busy.value = chip.busy_value
        reader.rst = FakePin(chip, "rst", 1)

    reader._open_bus = open_bus
    return reader


# ---------- Bring-up ----------


def test_init_probes_the_chip_and_leaves_the_antenna_dark(m5stickv):
    chip = FakeChip()
    reader = make_pn5180(chip)
    reader.init()

    assert reader.ready
    assert not chip.rf_on


@pytest.mark.parametrize("version", [b"\xff\xff", b"\x00\x00"])
def test_a_missing_or_unpowered_module_is_reported(m5stickv, version):
    """All ones is an absent chip, all zeros a chip whose supply is wrong"""
    from krux.nfc import NFCNotFound

    with pytest.raises(NFCNotFound):
        make_pn5180(FakeChip(version=version)).init()


def test_a_chip_that_never_releases_busy_does_not_hang(m5stickv):
    from krux.nfc import NFCError

    chip = FakeChip()
    chip.stuck_busy = True
    chip.busy = 1
    with pytest.raises(NFCError):
        make_pn5180(chip).init()


def test_the_field_loads_a_profile_and_silences_the_hardware_crc(m5stickv):
    """The chip forgets its RF profile across an RF_OFF, and a CRC it adds
    itself would duplicate the one the driver appends."""
    chip = FakeChip()
    reader = make_pn5180(chip)
    reader.init()
    reader.field(True)

    assert chip.rf_on
    assert chip.rf_config == (0x00, 0x80)  # ISO14443-A at 106 kbps
    assert chip.regs[0x19] == 0  # CRC_TX_CONFIG
    assert chip.regs[0x12] == 0  # CRC_RX_CONFIG

    reader.field(False)
    assert not chip.rf_on


# ---------- Registers ----------


def test_registers_are_written_little_endian(m5stickv):
    chip = FakeChip()
    reader = make_pn5180(chip)
    reader.init()

    reader._write_reg(0x40, 0x12345678)
    assert chip.regs[0x40] == 0x12345678
    assert reader._read_reg(0x40) == 0x12345678


# ---------- Frames ----------


def test_calc_crc_matches_the_reference(m5stickv):
    """Computed in software here and by a coprocessor on the other reader;
    a card written by one must read on the other."""
    chip = FakeChip()
    reader = make_pn5180(chip)
    reader.init()

    assert reader.calc_crc(b"\x30\x04") == crc_a(b"\x30\x04")
    assert reader.calc_crc(b"\x50\x00") == crc_a(b"\x50\x00")


def test_oversized_reply_is_refused_not_truncated(m5stickv):
    """RX_STATUS carries a length the tag chose. Trusting it into a smaller
    buffer is the overflow this whole layer exists to refuse."""
    from krux.nfc import NFCError

    chip = FakeChip(reply_len=200)
    reader = make_pn5180(chip)
    reader.init()
    reader.field(True)

    with pytest.raises(NFCError):
        reader.transceive(b"\x52", 7, 4)


def test_a_reply_that_does_not_fit_the_buffer_is_refused(m5stickv):
    from krux.nfc import NFCSizeError

    chip = FakeChip()
    reader = make_pn5180(chip)
    reader.init()
    reader.field(True)

    with pytest.raises(NFCSizeError):
        reader.transceive(b"\x52", 7, 1)  # ATQA is two bytes


def test_frame_longer_than_the_fifo_is_refused(m5stickv):
    from krux.nfc import NFCSizeError

    reader = make_pn5180(FakeChip())
    reader.init()

    with pytest.raises(NFCSizeError):
        reader.transceive(b"\x00" * 65, 0, 2)


@pytest.mark.parametrize("flag", [1 << 18, 1 << 19])  # collision, protocol error
def test_rx_error_bits_fail_the_exchange(m5stickv, flag):
    from krux.nfc import NFCError

    chip = FakeChip()
    reader = make_pn5180(chip)
    reader.init()
    reader.field(True)

    original = chip._on_air

    def poisoned(data):
        original(data)
        chip.regs[0x13] |= flag

    chip._on_air = poisoned
    with pytest.raises(NFCError):
        reader.transceive(b"\x52", 7, 2)


def test_a_silent_tag_times_out(m5stickv):
    from krux.nfc import NFCError

    chip = FakeChip(tag=False)
    reader = make_pn5180(chip)
    reader.init()
    reader.field(True)

    with pytest.raises(NFCError):
        reader.transceive(b"\x52", 7, 2)


# ---------- MIFARE ----------


def test_authentication_failure_is_not_a_success(m5stickv):
    """The chip answers with one status byte and no register to cross-check,
    so anything but zero has to be treated as a refusal."""
    from krux.nfc import NFCError

    chip = FakeChip()
    chip.auth_status = 1
    reader = make_pn5180(chip)
    reader.init()
    reader.field(True)

    with pytest.raises(NFCError):
        reader.authenticate(UID, 4)
    assert not reader.crypto_on

    chip.auth_status = 0
    reader.authenticate(UID, 4)
    assert reader.crypto_on


# ---------- The layer above ----------


def test_the_tag_layer_selects_a_card_through_this_reader(m5stickv):
    """The point of the split: poll() is the same code that runs on the
    WS1850S, and it neither knows nor asks which chip is underneath."""
    from krux.nfc import NFC

    chip = FakeChip()
    reader = make_pn5180(chip)
    nfc = NFC(reader=reader)
    nfc.init()
    nfc.field(True)

    assert nfc.poll() == (UID, 720)
