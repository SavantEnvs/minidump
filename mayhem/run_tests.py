#!/usr/bin/python3
"""run_tests.py — RUN minidump known-answer assertions and print a parseable summary.

Invoked via the `/mayhem/minidump-tests` ELF launcher (NOT directly), so the verify-repo
sabotage oracle can neuter the launcher and prove the test oracle is behavioral.

AUTHORED ORACLE: upstream skelsec/minidump ships NO test suite (no tests/ directory, no
Makefile test target, no CI test workflow — only a pyinstaller build script), so this
known-answer suite was authored for the integration. It parses the bundled real Windows
minidump (mayhem/parse-fuzz/testsuite/appendtofile.DMP — an x64 Windows 10 dump of
appendtofile.exe) and asserts the exact decoded header, stream-directory, module, thread,
system-info and memory-descriptor values, plus the library's exception behavior on a
non-minidump input. A no-op / exit(0) / behavior-altering patch to minidump cannot pass it.

It prints one line:

    RUNTESTS tests=<n> passed=<p> failed=<f> skipped=<s>

Exit 0 iff failed == 0. mayhem/test.sh parses that line into a CTRF report.
"""
from __future__ import annotations

import sys

DMP = "/mayhem/mayhem/parse-fuzz/testsuite/appendtofile.DMP"

passed = 0
failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"PASS {name}")
    else:
        failed += 1
        print(f"FAIL {name}")


def main() -> int:
    from minidump.minidumpfile import MinidumpFile
    from minidump.exceptions import MinidumpHeaderSignatureMismatchException

    # --- parse a known real minidump and assert exact decoded values ---
    mf = MinidumpFile.parse(DMP)

    h = mf.header
    check("header signature PMDM", h.Signature == "PMDM")
    check("header version 42899", h.Version == 42899)
    check("header stream count 15", h.NumberOfStreams == 15)
    check("15 stream directories parsed", len(mf.directories) == 15)

    check("module list has 5 modules", mf.modules is not None and len(mf.modules.modules) == 5)
    m0 = mf.modules.modules[0]
    check(
        "module[0] name appendtofile.exe",
        m0.name == r"C:\Users\dallm\CLionProjects\appendtofile\cmake-build-debug\appendtofile.exe",
    )
    check("module[0] baseaddress 0x7ff7d6aa0000", m0.baseaddress == 0x7FF7D6AA0000)
    check("module[0] size 147456", m0.size == 147456)

    check("thread list has 2 threads", mf.threads is not None and len(mf.threads.threads) == 2)
    check("thread[0] id 14644", mf.threads.threads[0].ThreadId == 14644)

    check("sysinfo present", mf.sysinfo is not None)
    check("sysinfo arch AMD64", mf.sysinfo.ProcessorArchitecture.name == "AMD64")
    check("sysinfo build 19043", mf.sysinfo.BuildNumber == 19043)

    check(
        "memory64 list has 54 segments",
        mf.memory_segments_64 is not None and len(mf.memory_segments_64.memory_segments) == 54,
    )
    check("misc info present", mf.misc_info is not None)

    # --- parse_bytes API parity on the same known input ---
    with open(DMP, "rb") as f:
        mf2 = MinidumpFile.parse_bytes(f.read())
    check("parse_bytes parses same directory count", len(mf2.directories) == 15)

    # --- assert exception behavior on a non-minidump input ---
    try:
        MinidumpFile.parse_bytes(b"not a minidump at all!!")
        check("garbage raises signature-mismatch", False)
    except MinidumpHeaderSignatureMismatchException:
        check("garbage raises signature-mismatch", True)
    except Exception:
        check("garbage raises signature-mismatch", False)

    tests = passed + failed
    print(f"RUNTESTS tests={tests} passed={passed} failed={failed} skipped=0")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # import/setup failure is a hard failure, not a vacuous pass
        import traceback

        traceback.print_exc()
        print(f"RUNTESTS tests=1 passed=0 failed=1 skipped=0 (harness error: {exc})")
        sys.exit(1)
