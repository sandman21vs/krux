# NFC record parser tests
#
# The card supplies every byte of a record header, so this suite is mostly
# about what the parser refuses. Each malformed header below is something a
# hostile or half-written tag can present.

import pytest

# A 1K MIFARE Classic clamped to one record's worth of addressable bytes
CAPACITY = 720

PAYLOAD_LEN = 16

# A small NTAG213: 144 bytes total
SMALL_TAG = 144


def _record(m5stickv):
    from krux.nfc import record

    return record


def _good_header(record, length=PAYLOAD_LEN, capacity=CAPACITY):
    """A valid header for a test to then corrupt"""
    return bytearray(record.build_header(length, capacity))


def _set_len(header, length):
    header[6] = (length >> 8) & 0xFF
    header[7] = length & 0xFF


# ---------- Round trip ----------


def test_round_trip(m5stickv):
    record = _record(m5stickv)

    header = record.build_header(PAYLOAD_LEN, CAPACITY)
    assert len(header) == record.HEADER_LEN
    assert bytes(header[:4]) == record.RECORD_MAGIC

    rec_type, length = record.parse_header(header, CAPACITY)
    assert rec_type == record.RECORD_KEF
    assert length == PAYLOAD_LEN


def test_max_payload_round_trips(m5stickv):
    record = _record(m5stickv)

    header = record.build_header(record.MAX_PAYLOAD, CAPACITY)
    _, length = record.parse_header(header, CAPACITY)
    assert length == record.MAX_PAYLOAD


# ---------- Hostile headers ----------


def test_blank_card_is_not_a_record(m5stickv):
    record = _record(m5stickv)
    from krux.nfc.errors import NoRecordError

    with pytest.raises(NoRecordError):
        record.parse_header(bytearray(record.HEADER_LEN), CAPACITY)


def test_erased_card_is_not_a_record(m5stickv):
    record = _record(m5stickv)
    from krux.nfc.errors import NoRecordError

    with pytest.raises(NoRecordError):
        record.parse_header(bytearray(b"\xff" * record.HEADER_LEN), CAPACITY)


def test_near_miss_magic_is_refused(m5stickv):
    record = _record(m5stickv)
    from krux.nfc.errors import NoRecordError

    header = _good_header(record)
    header[3] = ord("2")
    with pytest.raises(NoRecordError):
        record.parse_header(header, CAPACITY)


@pytest.mark.parametrize("rec_type", [0, 2, 0xFF])
def test_unknown_record_type_is_refused(m5stickv, rec_type):
    record = _record(m5stickv)
    from krux.nfc.errors import NoRecordError

    header = _good_header(record)
    header[4] = rec_type
    with pytest.raises(NoRecordError):
        record.parse_header(header, CAPACITY)


@pytest.mark.parametrize("index", [5, 8, 9, 10, 11, 12, 13, 14, 15])
def test_reserved_bytes_must_be_zero(m5stickv, index):
    record = _record(m5stickv)
    from krux.nfc.errors import NoRecordError

    header = _good_header(record)
    header[index] = 0x01
    with pytest.raises(NoRecordError):
        record.parse_header(header, CAPACITY)


def test_zero_length_is_refused(m5stickv):
    record = _record(m5stickv)
    from krux.nfc.errors import InvalidRecordError

    header = _good_header(record)
    _set_len(header, 0)
    with pytest.raises(InvalidRecordError):
        record.parse_header(header, CAPACITY)


def test_max_uint16_length_is_refused(m5stickv):
    record = _record(m5stickv)
    from krux.nfc.errors import InvalidRecordError

    header = _good_header(record)
    _set_len(header, 0xFFFF)
    with pytest.raises(InvalidRecordError):
        record.parse_header(header, CAPACITY)


def test_length_past_the_ceiling_is_refused(m5stickv):
    record = _record(m5stickv)
    from krux.nfc.errors import InvalidRecordError

    header = _good_header(record)
    _set_len(header, record.MAX_PAYLOAD + 1)
    with pytest.raises(InvalidRecordError):
        record.parse_header(header, CAPACITY)


def test_length_past_what_the_tag_holds_is_refused(m5stickv):
    record = _record(m5stickv)
    from krux.nfc.errors import InvalidRecordError

    # Under the ceiling, but a 144 byte tag cannot be holding 200 bytes
    header = _good_header(record)
    _set_len(header, 200)
    with pytest.raises(InvalidRecordError):
        record.parse_header(header, SMALL_TAG)


def test_payload_exactly_filling_the_tag_is_accepted(m5stickv):
    record = _record(m5stickv)

    header = _good_header(record)
    _set_len(header, SMALL_TAG - record.HEADER_LEN)
    _, length = record.parse_header(header, SMALL_TAG)
    assert length == SMALL_TAG - record.HEADER_LEN


def test_one_byte_past_a_full_tag_is_refused(m5stickv):
    record = _record(m5stickv)
    from krux.nfc.errors import InvalidRecordError

    header = _good_header(record)
    _set_len(header, SMALL_TAG - record.HEADER_LEN + 1)
    with pytest.raises(InvalidRecordError):
        record.parse_header(header, SMALL_TAG)


@pytest.mark.parametrize("capacity", [0, 8, 15])
def test_capacity_below_the_header_is_refused(m5stickv, capacity):
    record = _record(m5stickv)
    from krux.nfc.errors import InvalidRecordError

    header = _good_header(record)
    with pytest.raises(InvalidRecordError):
        record.parse_header(header, capacity)


def test_short_header_is_refused(m5stickv):
    record = _record(m5stickv)
    from krux.nfc.errors import InvalidRecordError

    header = _good_header(record)
    with pytest.raises(InvalidRecordError):
        record.parse_header(header[:8], CAPACITY)
    with pytest.raises(InvalidRecordError):
        record.parse_header(b"", CAPACITY)


# ---------- Build limits ----------


def test_build_refuses_an_oversize_payload(m5stickv):
    record = _record(m5stickv)
    from krux.nfc.errors import InvalidRecordError

    with pytest.raises(InvalidRecordError):
        record.build_header(record.MAX_PAYLOAD + 1, CAPACITY)


def test_build_refuses_a_payload_the_tag_cannot_hold(m5stickv):
    record = _record(m5stickv)
    from krux.nfc.errors import InvalidRecordError

    with pytest.raises(InvalidRecordError):
        record.build_header(PAYLOAD_LEN, 20)


def test_build_refuses_an_empty_payload(m5stickv):
    record = _record(m5stickv)
    from krux.nfc.errors import InvalidRecordError

    with pytest.raises(InvalidRecordError):
        record.build_header(0, CAPACITY)
