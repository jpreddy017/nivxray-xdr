"""Feb-2026 · Anti-hallucination: fake PE detection.

User reported (via 4 screenshots) that NivXRay claimed:
    SOC VERDICT — SHELLCODE DETECTED
    PE executable (MZ header)
    arch: pe · confidence: 62/100 · magic

...on a buffer whose hex dump showed a REPEATING short-period pattern
(`MZFT..DY..L.WL..` every ~10 bytes) with entropy 4.815. That's XOR-brute
noise, not a real PE. Real PE files have:
  * exactly ONE MZ header at offset 0
  * a valid `e_lfanew` field at offset 0x3c
  * a `PE\\0\\0` signature at the offset e_lfanew points to
  * entropy > 6.0 (compiled code) and NO short-period byte repetition

These tests lock in the strict-validator guard so future refactors of the
shellcode detector cannot regress into false positives again.
"""
import struct

import pytest


class TestFakePeDetection:
    def test_repetitive_mz_prefixed_noise_rejected(self):
        """The exact pattern from the user's screenshot: `MZFT..DY..L.Wt`
        repeating every 10 bytes. Must NOT be flagged as PE / shellcode."""
        from shellcode_analyzer import (
            starts_with_known_prologue, is_shellcode, _is_valid_pe, _is_repetitive,
        )
        # Reconstruct from the screenshot hex preview
        pattern = bytes.fromhex("4d5a4654860444597474")  # MZFT..DY.tt = ~10 bytes
        buf = pattern * 200                              # 2000 bytes of pure repetition

        assert _is_repetitive(buf) is True, "repetition detector must catch period-10 noise"
        assert _is_valid_pe(buf) is False, "no valid e_lfanew → not a PE"
        assert starts_with_known_prologue(buf) is False, "false-positive PE claim"
        assert is_shellcode(buf) is False, "false-positive shellcode claim"

    def test_real_pe_dos_stub_accepted(self):
        """Minimal but valid PE: MZ header + e_lfanew at 0x40 + PE\\0\\0 signature."""
        from shellcode_analyzer import _is_valid_pe, starts_with_known_prologue
        pe = bytearray(0x80)
        pe[0:2] = b"MZ"
        pe[0x3c:0x40] = struct.pack("<I", 0x40)   # e_lfanew → 0x40
        pe[0x40:0x44] = b"PE\x00\x00"
        # Some non-repeating filler in the DOS stub
        pe[2:0x3c] = bytes(range(0x02, 0x3c))
        pe[0x44:0x80] = bytes(range(0x44, 0x80))
        assert _is_valid_pe(bytes(pe)) is True
        assert starts_with_known_prologue(bytes(pe)) is True

    def test_bare_mz_two_bytes_not_pe(self):
        """A 2-byte `MZ` isn't a PE (nowhere near enough for the header)."""
        from shellcode_analyzer import _is_valid_pe, starts_with_known_prologue
        assert _is_valid_pe(b"MZ") is False
        assert starts_with_known_prologue(b"MZ" + b"\x00" * 62) is False

    def test_mz_with_bad_e_lfanew_rejected(self):
        """A buffer that starts MZ but has bogus e_lfanew (points past end or
        into wrong bytes) is NOT a valid PE."""
        from shellcode_analyzer import _is_valid_pe
        # e_lfanew = 0x1000 → points way past our 128-byte buffer
        bad = bytearray(0x80)
        bad[0:2] = b"MZ"
        bad[0x3c:0x40] = struct.pack("<I", 0x1000)
        assert _is_valid_pe(bytes(bad)) is False

    def test_real_x86_shellcode_still_detected(self):
        """The FIX must not regress ACTUAL shellcode detection.
        MSFvenom-style x86_64 stager starts with `\\xfc\\xe8` (cld; call)."""
        from shellcode_analyzer import starts_with_known_prologue, is_shellcode
        # Non-repeating body so the repetition guard doesn't fire
        body = bytes(range(2, 62)) + bytes(range(60, 20, -1))   # varied bytes
        buf = b"\xfc\xe8" + body
        assert starts_with_known_prologue(buf) is True
        assert is_shellcode(buf) is True

    def test_repetitive_shellcode_prologue_still_rejected(self):
        """If a buffer starts with `\\xfc\\xe8` but the rest is repetitive
        noise, it's still XOR-brute garbage — reject."""
        from shellcode_analyzer import starts_with_known_prologue
        repeat = b"\xfc\xe8" + (b"\x41\x42" * 300)   # very periodic
        assert starts_with_known_prologue(repeat) is False

    def test_elf_still_accepted(self):
        """ELF header validation is prologue-only (no equivalent to e_lfanew
        in our current strict pass) — must still pass through."""
        from shellcode_analyzer import starts_with_known_prologue
        # Varied bytes after the ELF magic
        elf = b"\x7fELF" + bytes(range(0x40, 0x40 + 100))
        assert starts_with_known_prologue(elf) is True
