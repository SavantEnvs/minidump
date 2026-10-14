#!/usr/bin/env python3
"""Atheris libFuzzer harness for skelsec/minidump (pure Python).

Feeds the raw fuzz input directly to MinidumpFile.parse_bytes() — the full
Windows minidump parse path (header, stream directory, every stream parser).
The previous harness round-tripped the input through
ConsumeUnicodeNoSurrogates().encode('utf-8'), which destroys the binary
minidump structure (the 'MDMP' magic and all little-endian fields) — raw
bytes drive the parser properly.

Parsed dumps are then read back through the buffered memory reader at their segment
boundaries (check_buffered_reader).

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


MAX_SEGMENTS = 16


def check_buffered_reader(mf):
    """Drive MinidumpBufferedReader.move() to the edges of the parsed memory segments.

    Each segment is entered at its first address (which caches it in the buffered reader) and then at
    its end address, the first byte past it. A successful move() must land in a segment that contains
    the address; the library signals "address not mapped" with a plain Exception, which is expected.
    """
    if mf.modules is None or mf.sysinfo is None:
        return
    if mf.memory_segments_64 is None and mf.memory_segments is None:
        return
    try:
        reader = mf.get_reader().get_buffered_reader()
    except Exception:
        return
    for seg in reader.reader.memory_segments[:MAX_SEGMENTS]:
        for addr in (seg.start_virtual_address, seg.end_virtual_address):
            try:
                reader.move(addr)
            except Exception:
                continue
            cur = reader.current_segment
            if not (cur.start_address <= addr < cur.end_address):
                raise AssertionError(
                    "move(0x%x) selected segment [0x%x, 0x%x) that does not contain it"
                    % (addr, cur.start_address, cur.end_address)
                )


def TestOneInput(data: bytes):
    try:
        mf = MinidumpFile.parse_bytes(data)
    except EXPECTED:
        return -1
    check_buffered_reader(mf)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
