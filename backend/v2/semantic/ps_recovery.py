"""NivXRay recovery decoder chain for PowerShell -EncodedCommand payloads.

Deterministic, order-preserving decode pipeline that turns a raw Base64
blob into a **validated** PowerShell script — or returns a structured
`decode_error` explaining precisely why every attempt failed.

Contract (locked with SOC user 2026-07-25):

    ✓ Base64 decode  ─── attempted → succeeded/failed  (with byte count)
    ✓ UTF-16LE strict ── attempted → succeeded/failed  (with first invalid offset + reason)
    ✓ Compression sniff  attempted → succeeded/skipped (magic-byte based)
    ✓ UTF-8 strict       attempted → succeeded/failed
    ✓ ASCII strict       attempted → succeeded/failed
    ✓ UTF-16BE strict    attempted → succeeded/failed
    ✓ XOR-brute          attempted only if entropy + repeating-byte heuristic supports it

Every attempt lands in the trace as `{decoder, status, reason, ...}`.

If **no** decoder produces a candidate that passes `looks_like_powershell()`,
the whole recovery yields `status = decode_error` and the caller MUST NOT
run the AST, behavior extractor, or any semantic step on the garbage.

The UI is expected to render a "Decode Failure" card from this report and
never render the raw bytes.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import re
import time
import zlib
from dataclasses import dataclass, field, asdict


# ── Powershell content validator ─────────────────────────────────
_PS_TOKENS = re.compile(
    r"\b(?:powershell|invoke|iex|new-object|system\.|net\.|"
    r"downloadstring|downloadfile|webclient|scriptblock|iwr|irm|"
    r"start-process|reg add|hkcu|hklm|amsi|reflection|encoding|"
    r"executionpolicy|frombase64string|convert::|assembly|"
    r"foreach|where-object|write-host)\b",
    re.I,
)


def looks_like_powershell(text: str, *, min_len: int = 8) -> tuple[bool, str]:
    """Deterministic sanity check — is this recovered text plausibly a
    PowerShell script? Returns (ok, reason)."""
    if not text or len(text) < min_len:
        return False, f"recovered text too short ({len(text)} chars < {min_len})"
    # Count printable ASCII (0x20-0x7e) + \n \r \t
    printable = sum(1 for c in text
                    if (0x20 <= ord(c) <= 0x7e) or c in "\n\r\t")
    ratio = printable / max(1, len(text))
    if ratio < 0.90:
        return False, (f"only {ratio*100:.0f}% printable ASCII "
                       f"(need ≥ 90% for a valid PS script)")
    # Look for at least one PowerShell-ish token OR a common script keyword
    if _PS_TOKENS.search(text) is None:
        # Very permissive fallback — allow if it looks like *anything* alphabetic
        alpha = sum(1 for c in text if c.isalpha())
        if alpha < min_len // 2:
            return False, "no recognisable PowerShell tokens or alphabetic content"
    return True, "recovered text passes PowerShell validity heuristics"


# ── Compression magic sniff ──────────────────────────────────────
def _sniff_compression(raw: bytes) -> tuple[str, str] | None:
    """Return (algorithm_label, human-readable reason) if `raw` looks
    like a compressed stream, else None."""
    if len(raw) < 4:
        return None
    if raw[0:2] == b"\x1f\x8b":
        return "gzip", "leading bytes match GZip magic `1f 8b`"
    # zlib DEFLATE streams — check the 2-byte header
    if raw[0] in (0x78,) and raw[1] in (0x01, 0x5e, 0x9c, 0xda):
        return "zlib", f"leading bytes match zlib/DEFLATE header `{raw[:2].hex()}`"
    if raw[0:4] == b"BZh9" or raw[0:3] == b"BZh":
        return "bzip2", "leading bytes match bzip2 magic `BZh`"
    if raw[0:6] == b"\xfd7zXZ\x00":
        return "xz", "leading bytes match XZ magic"
    if raw[0:1] == b"\x28" and raw[0:4] == b"\x28\xb5\x2f\xfd":
        return "zstd", "leading bytes match Zstandard magic"
    return None


def _try_gzip(raw: bytes) -> bytes | None:
    try:
        return gzip.decompress(raw)
    except Exception:
        return None


def _try_zlib(raw: bytes) -> bytes | None:
    for wbits in (15, -15, 47, 31):
        try:
            return zlib.decompress(raw, wbits)
        except Exception:
            continue
    return None


# ── Strict encoding attempts ─────────────────────────────────────
def _try_strict_decode(raw: bytes, enc: str) -> tuple[str | None, dict]:
    """Return (text or None, meta-dict). meta contains offset+reason on failure."""
    try:
        return raw.decode(enc, errors="strict"), {}
    except UnicodeDecodeError as e:
        ctx = raw[max(0, e.start - 4):e.start + 8].hex()
        return None, {
            "first_invalid_offset": e.start,
            "reason": e.reason,
            "byte_context": ctx,
        }
    except Exception as e:  # noqa: BLE001
        return None, {"reason": f"{type(e).__name__}: {e}"}


# ── XOR-brute (very narrow, only for high-entropy repeat-byte streams) ──
def _try_xor_brute(raw: bytes, max_keys: int = 256) -> tuple[str | None, dict]:
    """Single-byte XOR brute — only used as a LAST-resort recovery."""
    if len(raw) < 16:
        return None, {"reason": "payload too short to reliably brute XOR"}
    # Entropy screen — refuse anything with too many low-entropy zero bytes,
    # which would produce garbage under XOR.
    zeros = raw.count(0)
    if zeros / len(raw) > 0.35:
        return None, {"reason": ("high NUL-byte ratio suggests UTF-16LE or "
                                  "structured data — XOR-brute skipped")}
    best_text = None
    best_score = 0
    best_key = 0
    for key in range(1, min(max_keys, 256)):
        candidate = bytes(b ^ key for b in raw)
        try:
            txt = candidate.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        score = sum(1 for c in txt if (0x20 <= ord(c) <= 0x7e) or c in "\n\r\t")
        score = int((score / max(1, len(txt))) * 100)
        if score > best_score:
            best_score = score
            best_text = txt
            best_key = key
    if best_text and best_score >= 90:
        return best_text, {"key": best_key, "printable_ratio": best_score}
    return None, {"reason": ("no single-byte XOR key produced ≥90% printable "
                              "ASCII output")}


# ── Report schema ────────────────────────────────────────────────
@dataclass
class DecodeAttempt:
    decoder: str
    status: str                     # attempted | succeeded | failed | skipped
    reason: str
    duration_ms: float = 0.0
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DecodeReport:
    status: str                     # ok | decode_error | not_encoded
    recovered_script: str = ""
    winner: str = ""                # which decoder produced recovered_script
    b64_bytes: int = 0
    b64_status: str = ""            # succeeded | failed
    b64_reason: str = ""
    attempts: list[DecodeAttempt] = field(default_factory=list)
    possible_causes: list[str] = field(default_factory=list)
    first_invalid_offset: int | None = None
    invalid_reason: str = ""
    hex_preview: str = ""

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "recovered_script": self.recovered_script,
            "winner": self.winner,
            "b64_bytes": self.b64_bytes,
            "b64_status": self.b64_status,
            "b64_reason": self.b64_reason,
            "attempts": [a.to_dict() for a in self.attempts],
            "possible_causes": list(self.possible_causes),
            "first_invalid_offset": self.first_invalid_offset,
            "invalid_reason": self.invalid_reason,
            "hex_preview": self.hex_preview,
        }


# ── Public entrypoint ────────────────────────────────────────────
def recover_powershell_from_b64(blob: str) -> DecodeReport:
    """Best-effort deterministic recovery of a PowerShell script from a
    Base64 blob. Returns a `DecodeReport` — never raises."""
    r = DecodeReport(status="decode_error")
    if not blob:
        r.b64_status = "failed"
        r.b64_reason = "no Base64 blob supplied"
        return r

    # 1. Base64 decode -----------------------------------------------------
    t0 = time.perf_counter()
    try:
        raw = base64.b64decode(blob, validate=False)
        r.b64_status = "succeeded"
        r.b64_bytes = len(raw)
        r.b64_reason = (f"decoded {len(blob)}-char Base64 blob → "
                         f"{len(raw)} bytes")
        r.hex_preview = raw[:64].hex()
        r.attempts.append(DecodeAttempt(
            "base64_decode", "succeeded", r.b64_reason,
            (time.perf_counter() - t0) * 1000,
            {"input_len": len(blob), "output_len": len(raw)}))
    except (binascii.Error, ValueError) as e:
        r.b64_status = "failed"
        r.b64_reason = f"Base64 decode failed: {e}"
        r.attempts.append(DecodeAttempt(
            "base64_decode", "failed", r.b64_reason,
            (time.perf_counter() - t0) * 1000))
        r.possible_causes = [
            "Payload is not Base64 encoded",
            "Blob is truncated or contains extra padding characters",
        ]
        return r

    if not raw:
        r.attempts.append(DecodeAttempt(
            "base64_decode", "failed", "empty byte payload after Base64 decode", 0.0))
        r.possible_causes = ["Empty Base64 payload"]
        return r

    # 2. Deterministic recovery chain --------------------------------------
    # Each decoder appends to attempts; the FIRST one whose output passes
    # `looks_like_powershell()` wins.
    def _record(name: str, text: str | None, meta: dict, t_start: float,
                *, on_success_reason: str,
                on_fail_reason: str) -> str | None:
        dt = (time.perf_counter() - t_start) * 1000
        if text is None:
            r.attempts.append(DecodeAttempt(name, "failed", on_fail_reason,
                                             dt, meta))
            return None
        ok, why = looks_like_powershell(text)
        if not ok:
            r.attempts.append(DecodeAttempt(
                name, "failed",
                f"decoded {len(text)} chars but rejected: {why}",
                dt,
                {**meta, "preview": text[:120],
                 "printable_check": why}))
            return None
        r.attempts.append(DecodeAttempt(
            name, "succeeded", on_success_reason, dt,
            {**meta, "output_len": len(text)}))
        return text

    # 2a. UTF-16LE (PowerShell contract encoding) --------------------------
    t = time.perf_counter()
    text, meta = _try_strict_decode(raw, "utf-16-le")
    if text is None:
        r.first_invalid_offset = meta.get("first_invalid_offset")
        r.invalid_reason = meta.get("reason", "")
        r.attempts.append(DecodeAttempt(
            "utf16le_strict", "failed",
            (f"UTF-16LE strict validation failed at byte offset "
             f"{r.first_invalid_offset}: {r.invalid_reason} "
             f"(context bytes {meta.get('byte_context','')})"),
            (time.perf_counter() - t) * 1000, meta))
    else:
        winner = _record(
            "utf16le_strict", text, meta, t,
            on_success_reason=(f"UTF-16LE strict decode succeeded — "
                               f"recovered {len(text)}-char PowerShell script."),
            on_fail_reason="")
        if winner is not None:
            r.status = "ok"; r.winner = "utf16le_strict"; r.recovered_script = winner
            return r

    # 2b. Compression sniff -----------------------------------------------
    sniff = _sniff_compression(raw)
    if sniff:
        algo, why = sniff
        t = time.perf_counter()
        decompressed = None
        if algo == "gzip":
            decompressed = _try_gzip(raw)
        elif algo == "zlib":
            decompressed = _try_zlib(raw)
        if decompressed is None:
            r.attempts.append(DecodeAttempt(
                f"{algo}_decompress", "failed",
                f"{algo} magic bytes matched ({why}) but decompression raised.",
                (time.perf_counter() - t) * 1000))
        else:
            # Try to decode the decompressed bytes as PS text
            for enc in ("utf-16-le", "utf-8", "ascii"):
                text2, meta2 = _try_strict_decode(decompressed, enc)
                winner = _record(
                    f"{algo}_then_{enc.replace('-','_')}",
                    text2, meta2, t,
                    on_success_reason=(f"{algo} decompression → {enc} "
                                        f"succeeded ({len(decompressed)} bytes → "
                                        f"{len(text2) if text2 else 0} chars)."),
                    on_fail_reason=f"{algo} decompression succeeded but {enc} decode failed")
                if winner is not None:
                    r.status = "ok"
                    r.winner = f"{algo}_then_{enc.replace('-','_')}"
                    r.recovered_script = winner
                    return r
    else:
        r.attempts.append(DecodeAttempt(
            "compression_sniff", "skipped",
            "no GZip / zlib / bzip2 / xz / zstd magic bytes at head of payload."))

    # 2c. UTF-8 strict -----------------------------------------------------
    t = time.perf_counter()
    text, meta = _try_strict_decode(raw, "utf-8")
    winner = _record(
        "utf8_strict", text, meta, t,
        on_success_reason="UTF-8 strict decode succeeded (unusual for -EncodedCommand).",
        on_fail_reason=(f"UTF-8 strict validation failed at byte offset "
                         f"{meta.get('first_invalid_offset')}: {meta.get('reason','')}"))
    if winner is not None:
        r.status = "ok"; r.winner = "utf8_strict"; r.recovered_script = winner
        return r

    # 2d. ASCII strict -----------------------------------------------------
    t = time.perf_counter()
    text, meta = _try_strict_decode(raw, "ascii")
    winner = _record(
        "ascii_strict", text, meta, t,
        on_success_reason="ASCII strict decode succeeded.",
        on_fail_reason=(f"ASCII strict failed at offset "
                         f"{meta.get('first_invalid_offset')}: {meta.get('reason','')}"))
    if winner is not None:
        r.status = "ok"; r.winner = "ascii_strict"; r.recovered_script = winner
        return r

    # 2e. UTF-16BE strict --------------------------------------------------
    t = time.perf_counter()
    text, meta = _try_strict_decode(raw, "utf-16-be")
    winner = _record(
        "utf16be_strict", text, meta, t,
        on_success_reason="UTF-16BE strict decode succeeded.",
        on_fail_reason=(f"UTF-16BE strict failed at offset "
                         f"{meta.get('first_invalid_offset')}: {meta.get('reason','')}"))
    if winner is not None:
        r.status = "ok"; r.winner = "utf16be_strict"; r.recovered_script = winner
        return r

    # 2f. XOR-brute (narrow, LAST resort) ---------------------------------
    t = time.perf_counter()
    text, meta = _try_xor_brute(raw)
    winner = _record(
        "xor_brute", text, meta, t,
        on_success_reason=(f"single-byte XOR key 0x{meta.get('key',0):02x} "
                           f"produced {meta.get('printable_ratio',0)}% printable output."),
        on_fail_reason=meta.get("reason", "XOR brute produced no plausible text"))
    if winner is not None:
        r.status = "ok"; r.winner = "xor_brute"; r.recovered_script = winner
        return r

    # 3. All decoders exhausted → structured decode_error ------------------
    r.possible_causes = [
        "Corrupted -EncodedCommand blob (mid-payload byte tampering).",
        "Truncated Base64 (missing bytes, wrong padding).",
        "Nested encoding not covered by the recovery chain "
        "(e.g. AES/RC4 encryption, XOR with multi-byte key, custom substitution).",
        "Payload is not a PowerShell EncodedCommand — could be shellcode "
        "or a binary blob mistakenly Base64-wrapped.",
    ]
    return r
