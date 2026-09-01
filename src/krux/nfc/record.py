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
"""NFC card record - header layout and validation.

Every byte described below was chosen by whoever handed the user the card, so
parsing is an allowlist: exactly what Krux writes is accepted, anything else is
refused, and nothing is allocated or read until the header passes.

Layout - 16 byte header at linear offset 0, payload immediately after:

    0..3    magic "KRX1"
    4       record type (RECORD_KEF)
    5       reserved, must be zero
    6..7    payload length, big endian
    8..15   reserved, must be zero

There is no checksum: the KEF envelope is authenticated, so a half-written or
decaying card fails to decrypt. The payload stays untrusted regardless.

Pure: no I/O and no MicroPython, so the host test suite exercises this file
unchanged.
"""

from .errors import InvalidRecordError, NoRecordError

HEADER_LEN = 16
RECORD_MAGIC = b"KRX1"
RECORD_KEF = 1

# Largest payload Krux will read off a card, regardless of what the card claims
# to hold. A KEF-wrapped 24 word seed is under 100 bytes; the ceiling exists so
# a hostile tag cannot drive a large allocation on a device with ~1 MB of heap.
MAX_PAYLOAD = 704


def parse_header(header, capacity):
    """Validates a header read off a tag, returns (record_type, payload_len).

    capacity is the tag's usable linear byte count including the header, so the
    declared length is checked against what the card can physically hold as
    well as against the compile time ceiling.
    """

    if not header or len(header) < HEADER_LEN:
        raise InvalidRecordError("Short header")

    if bytes(header[:4]) != RECORD_MAGIC:
        raise NoRecordError("Not a Krux record")

    # One known type. A record Krux did not write is not a record to grow
    # lenient about.
    if header[4] != RECORD_KEF:
        raise NoRecordError("Unknown record type")

    # Reserved bytes mean nothing today, so zero is the only value accepted: it
    # denies the field as a covert channel and stops stale bytes from silently
    # acquiring meaning in a later format version.
    if header[5] != 0:
        raise NoRecordError("Reserved bytes not zero")
    for i in range(8, HEADER_LEN):
        if header[i] != 0:
            raise NoRecordError("Reserved bytes not zero")

    # The declared length is a number a stranger picked. Check it against the
    # ceiling and against what this tag can physically hold before it is ever
    # used to size an allocation or a read.
    length = (header[6] << 8) | header[7]
    if length == 0 or length > MAX_PAYLOAD:
        raise InvalidRecordError("Invalid record length")
    if capacity < HEADER_LEN or length > capacity - HEADER_LEN:
        raise InvalidRecordError("Invalid record length")

    return header[4], length


def build_header(length, capacity):
    """Serializes the header for a payload of length bytes about to be written"""

    if length == 0 or length > MAX_PAYLOAD:
        raise InvalidRecordError("Invalid record length")
    if capacity < HEADER_LEN or length > capacity - HEADER_LEN:
        raise InvalidRecordError("Invalid record length")

    header = bytearray(HEADER_LEN)
    header[0:4] = RECORD_MAGIC
    header[4] = RECORD_KEF
    header[6] = (length >> 8) & 0xFF
    header[7] = length & 0xFF
    return header
