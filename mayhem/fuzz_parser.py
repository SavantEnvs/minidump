#!/usr/bin/env python3
"""Atheris libFuzzer harness for skelsec/minidump (pure Python).

Feeds the raw fuzz input directly to MinidumpFile.parse_bytes() — the full
Windows minidump parse path (header, stream directory, every stream parser).
The previous harness round-tripped the input through
ConsumeUnicodeNoSurrogates().encode('utf-8'), which destroys the binary
minidump structure (the 'MDMP' magic and all little-endian fields) — raw
bytes drive the parser properly.

Expected (non-bug) parse rejections raised by the library on malformed input
are swallowed; anything else (AttributeError, RecursionError, MemoryError...)
surfaces as a finding.
"""
import sys

import atheris

with atheris.instrument_imports(include=["minidump"]):
    from minidump.minidumpfile import MinidumpFile

from minidump.exceptions import (
    MinidumpException,
    MinidumpHeaderFlagsException,
    MinidumpHeaderSignatureMismatchException,
)

# Exceptions the parser legitimately raises on malformed input: its own
# exception hierarchy plus the struct/int conversion errors that bubble out
# of stream parsers fed truncated/garbage bytes.
EXPECTED = (
    MinidumpException,
    MinidumpHeaderFlagsException,
    MinidumpHeaderSignatureMismatchException,
    ValueError,
    OverflowError,
    EOFError,
    UnicodeDecodeError,
)


def TestOneInput(data: bytes):
    try:
        MinidumpFile.parse_bytes(data)
    except EXPECTED:
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
