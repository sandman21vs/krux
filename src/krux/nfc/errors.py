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
"""NFC failures.

Kept in their own module so the record parser stays free of hardware imports
and can be exercised on the host.

Every layer below the UI signals through these: the pages catch NFCError and
turn it into one short message, because a card is attacker-controlled input
and the exact reason it was refused is not something to spell out on screen.
"""


class NFCError(Exception):
    """Base for every NFC failure"""


class NFCTimeout(NFCError):
    """The tag or the reader said nothing before the deadline"""


class NFCSizeError(NFCError):
    """A reply did not fit its buffer, or a range fell outside the tag"""


class NFCCRCError(NFCError):
    """A frame failed its CRC_A, or a UID failed its BCC"""


class NFCResponseError(NFCError):
    """A collision, a protocol error, or a reply Krux does not accept"""


class NFCNotFound(NFCError):
    """No reader on the bus, or no acceptable tag in the field"""


class NoRecordError(NFCError):
    """The tag is readable but carries no Krux record"""


class InvalidRecordError(NFCError):
    """A Krux record header whose declared length cannot be trusted"""
