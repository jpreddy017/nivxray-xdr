"""
S05 · Byte-level Forensic Report.

The owner requires that any claim of "corpus-quality issue" be
verified by explicit byte-level evidence — never accepted on
assertion. This report dumps the complete decode path for S05 so a
human reviewer can determine, with zero ambiguity, whether the
failure is in the corpus payload or in our decoder.

Sections emitted (all to stdout):

  1. Original payload (verbatim).
  2. Extracted Base64 argument.
  3. Raw Base64-decoded bytes (length + hex + printable overlay).
  4. Byte-level breakdown: gzip header, compressed body, trailer.
  5. gzip.decompress() attempt and exact exception text (if any).
  6. Raw DEFLATE attempt (zlib.decompress with -MAX_WBITS on body).
  7. Full inflate attempt (zlib.decompress plain).
  8. Recovered plaintext (best-effort).
  9. Corpus-declared expected substrings.
 10. Byte-level comparison of expected vs recovered.
 11. Verdict: corpus defect, decoder defect, or ambiguous.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import json
import sys
import textwrap
import zlib
from pathlib import Path


CORPUS_PATH = Path(__file__).resolve().parent / "corpus.json"


def _hexdump(raw: bytes, width: int = 16) -> str:
    lines: list[str] = []
    for i in range(0, len(raw), width):
        chunk = raw[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def _sample() -> dict:
    with CORPUS_PATH.open("r", encoding="utf-8") as fh:
        doc = json.load(fh)
    for s in doc["categories"]["powershell"]["samples"]:
        if s["id"] == "S05_nested_b64_gzip":
            return s
    raise RuntimeError("S05 not found in corpus")


def _section(title: str) -> None:
    print()
    print("─" * 72)
    print(f" {title}")
    print("─" * 72)


def main() -> int:
    sample = _sample()

    _section("1 · Original payload (verbatim)")
    print(sample["input"])

    # Extract the Base64 argument.
    payload = sample["input"]
    b64_start = payload.index("FromBase64String('") + len("FromBase64String('")
    b64_end = payload.index("'", b64_start)
    b64 = payload[b64_start:b64_end]

    _section("2 · Extracted Base64 argument")
    print(f"  length         : {len(b64)} chars")
    print(f"  multiple of 4  : {len(b64) % 4 == 0}")
    print(f"  content        : {b64}")

    # Raw Base64 decode.
    _section("3 · Raw Base64-decoded bytes")
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        print(f"  ! base64 decode FAILED: {exc!r}")
        return 1
    print(f"  length         : {len(raw)} bytes")
    print(_hexdump(raw))

    # Byte-level gzip anatomy.
    _section("4 · Byte-level gzip anatomy")
    if len(raw) < 18 or raw[:2] != b"\x1f\x8b":
        print("  ! not a gzip container (magic bytes missing)")
    else:
        # RFC 1952: header is 10 bytes fixed + optional extras.
        header = raw[:10]
        body = raw[10:-8]
        trailer = raw[-8:]
        _GZ_MAGIC = b"\x1f\x8b"
        print(f"  header (10 B)  : {header.hex(' ')}")
        magic_ok = "OK" if header[0:2] == _GZ_MAGIC else "BAD"
        print(f"    magic        : {header[0:2].hex(' ')} ({magic_ok})")
        method_str = "DEFLATE (0x08)" if header[2] == 0x08 else "other"
        print(f"    method       : {header[2]:#04x} ({method_str})")
        print(f"    flags        : {header[3]:#04x}")
        print(f"    mtime        : {header[4:8].hex(' ')}")
        print(f"    xfl / os     : {header[8]:#04x} / {header[9]:#04x}")
        print(f"  body ({len(body)} B) : {body.hex(' ')}")
        print(f"  trailer (8 B)  : {trailer.hex(' ')}")
        declared_crc32 = int.from_bytes(trailer[:4], "little")
        declared_size = int.from_bytes(trailer[4:], "little")
        print(f"    declared CRC : {declared_crc32:#010x}")
        print(f"    declared size: {declared_size} bytes")

    # gzip.decompress attempt.
    _section("5 · gzip.decompress() attempt")
    try:
        decompressed = gzip.decompress(raw)
        print(f"  SUCCESS ({len(decompressed)} bytes)")
        try:
            print(f"  as UTF-8       : {decompressed.decode('utf-8')!r}")
        except UnicodeDecodeError:
            print("  UTF-8 decode failed")
    except Exception as exc:
        print(f"  ! FAILED: {type(exc).__name__}: {exc}")

    # Raw DEFLATE attempt (skip 10-byte gzip header).
    _section("6 · zlib.decompress(body, -MAX_WBITS) — raw DEFLATE")
    if len(raw) >= 18 and raw[:2] == b"\x1f\x8b":
        body = raw[10:-8]
        try:
            raw_deflated = zlib.decompress(body, -zlib.MAX_WBITS)
            print(f"  SUCCESS ({len(raw_deflated)} bytes)")
            print(f"  as latin-1     : {raw_deflated.decode('latin-1')!r}")
            actual_crc = zlib.crc32(raw_deflated) & 0xFFFFFFFF
            print(f"  computed CRC32 : {actual_crc:#010x}")
            print(f"  declared CRC32 : {declared_crc32:#010x}")
            print(f"  CRC match      : {actual_crc == declared_crc32}")
            print(f"  computed size  : {len(raw_deflated)} bytes")
            print(f"  declared size  : {declared_size} bytes")
            print(f"  size match     : {len(raw_deflated) == declared_size}")
        except zlib.error as exc:
            print(f"  ! FAILED: {exc}")

    # Plain zlib attempt (full stream).
    _section("7 · zlib.decompress(raw) — full stream")
    try:
        z = zlib.decompress(raw)
        print(f"  SUCCESS ({len(z)} bytes): {z[:200]!r}")
    except zlib.error as exc:
        print(f"  ! FAILED: {exc}")

    # Recovered plaintext (best effort).
    _section("8 · Recovered plaintext (best-effort)")
    recovered: bytes | None = None
    try:
        recovered = gzip.decompress(raw)
        print(f"  via gzip.decompress: {recovered!r}")
    except Exception:
        if len(raw) >= 18 and raw[:2] == b"\x1f\x8b":
            try:
                recovered = zlib.decompress(raw[10:-8], -zlib.MAX_WBITS)
                print(f"  via raw DEFLATE   : {recovered!r}")
            except zlib.error:
                pass
    if recovered is None:
        print("  ! nothing recovered")

    # Corpus expectations.
    _section("9 · Corpus-declared expectations")
    exp = sample.get("expected") or {}
    for k, v in exp.items():
        print(f"  {k:<30} : {v}")

    # Comparison.
    _section("10 · Byte-level comparison")
    contains = exp.get("final_output_contains") or []
    if recovered is not None:
        try:
            text = recovered.decode("utf-8")
        except UnicodeDecodeError:
            text = recovered.decode("latin-1")
        print(f"  recovered text : {text!r}")
        for sub in contains:
            hit = sub.lower() in text.lower()
            print(f"    substring {sub!r:<20} present={hit}")

    # Verdict.
    _section("11 · Verdict")
    print(textwrap.dedent(
        """
          If:
            * gzip.decompress FAILED, AND
            * raw DEFLATE SUCCEEDED, AND
            * the recovered text does NOT contain any expected
              substring:
          then the PAYLOAD BYTES themselves cannot produce the
          declared final output — this is a corpus-authoring defect,
          not a decoder defect. The decoder ran every recovery path
          available (gzip + raw DEFLATE) and every recovery yields a
          different plaintext than the corpus declares.

          If instead:
            * gzip.decompress SUCCEEDED, and
            * the recovered text contains "Hello" / "malicious":
          then this decoder is failing to fire and the decoder is
          defective — proceed to fix `decoder-frombase64string-fold`
          and `decoder-base64-full`.
        """
    ).strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
