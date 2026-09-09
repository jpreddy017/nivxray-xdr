"""Gate 2D-B3.0 · Snapshot #2 · Second runtime surface parity baseline.

Snapshot #1 (`capture_pre_migration_snapshot.py`) froze the behaviour
of `services.die.preprocessor.recursive_decoder.peel_recursively` —
the primary orchestration path for GZIP / Zlib / UTF-16LE / bare
base64 / from_base64_string / byte-array XOR-loop.

Snapshot #2 (this script) freezes the behaviour of the *second*
runtime surface, which peel_recursively does NOT invoke:

  · decoders.crypto_symmetric.Rc4Decoder      → RC4
  · decoders.crypto_symmetric.AesCbcDecoder   → AES-CBC / AES-ECB
  · decoders.xor_brute.XorBruteDecoder        → repeating-key XOR
  · services.pe_analyzer.analyze_pe           → PE analyzer
  · shellcode_analyzer.analyze                → shellcode analyzer

These are invoked in production either directly (`XorBruteDecoder`
through the L2 pipeline) or via UAIE plugin adapters
(`crypto_rc4`, `crypto_aes_cbc`, `pe_analyzer`, `shellcode_analyzer`).

Owner directive (2026-02, option a):
    "B3 absorbs BOTH decoder runtime surfaces."
    "Freeze this second parity snapshot before modifying those paths."

This script writes ONE artefact:

    tests/decoder_migration/pre_migration_snapshot_2.json

with a `content_signature_sha256` computed only over decode
observables (excluding timestamps and wall-clock latency) so a
re-run produces a byte-identical signature.

Execute from /app/backend:

    python -m tests.decoder_migration.capture_pre_migration_snapshot_2
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure repository root on sys.path when invoked directly.
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tests.decoder_migration.parity_harness import (  # noqa: E402
    enumerate_fixtures,
    write_json,
    _sha256_hex,
)

# ── Reference decoder / analyzer imports ─────────────────────────
# Wrapped in try/except so a missing optional dep (e.g. pefile, capstone)
# doesn't crash the whole snapshot — we record availability honestly.

_AVAIL: dict[str, bool] = {}

try:
    from decoders.crypto_symmetric import Rc4Decoder as _Rc4Decoder
    from decoders.crypto_symmetric import AesCbcDecoder as _AesCbcDecoder
    _AVAIL["crypto_symmetric"] = True
except Exception as exc:                        # pragma: no cover
    _Rc4Decoder = _AesCbcDecoder = None
    _AVAIL["crypto_symmetric"] = False
    _AVAIL["crypto_symmetric_error"] = type(exc).__name__ + ": " + str(exc)

try:
    from decoders.xor_brute import XorBruteDecoder as _XorBruteDecoder
    _AVAIL["xor_brute"] = True
except Exception as exc:                        # pragma: no cover
    _XorBruteDecoder = None
    _AVAIL["xor_brute"] = False
    _AVAIL["xor_brute_error"] = type(exc).__name__ + ": " + str(exc)

try:
    from services.pe_analyzer import analyze_pe as _pe_analyze
    from services.pe_analyzer import is_available as _pe_is_available
    _AVAIL["pe_analyzer"] = bool(_pe_is_available())
except Exception as exc:                        # pragma: no cover
    _pe_analyze = None
    _AVAIL["pe_analyzer"] = False
    _AVAIL["pe_analyzer_error"] = type(exc).__name__ + ": " + str(exc)

try:
    import shellcode_analyzer as _sca
    _AVAIL["shellcode_analyzer"] = True
except Exception as exc:                        # pragma: no cover
    _sca = None
    _AVAIL["shellcode_analyzer"] = False
    _AVAIL["shellcode_analyzer_error"] = type(exc).__name__ + ": " + str(exc)

# Contexts required by BaseDecoder-shaped plugins.  Instantiate ONCE.
try:
    from engine.models import AnalysisContext, Fingerprint
    _CTX = AnalysisContext()
except Exception as exc:                        # pragma: no cover
    AnalysisContext = None                      # type: ignore
    Fingerprint = None                          # type: ignore
    _CTX = None
    _AVAIL["engine_models"] = False
    _AVAIL["engine_models_error"] = type(exc).__name__ + ": " + str(exc)
else:
    _AVAIL["engine_models"] = True

HERE = Path(__file__).resolve().parent


def _make_fp(payload: str) -> "Fingerprint":
    """Cheap, deterministic Fingerprint for plugin invocation.

    We don't need a full L0 pass — the crypto/xor decoders only read
    `entropy` and `input_len`.  Compute them locally so the snapshot
    is decoupled from the L0 pipeline (which itself will be migrated
    at a later gate)."""
    b = payload.encode("utf-8", errors="replace")
    n = len(b)
    entropy = 0.0
    if n:
        from collections import Counter
        import math
        counts = Counter(b)
        entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return Fingerprint(
        input_len=n,
        entropy=entropy,
        printable_ratio=(printable / n) if n else 0.0,
        english_density=0.0,
        is_binary=False,
    )


def _reduce_plugin_result(result) -> dict:
    """Serialise a PluginResult into a stable, comparable dict."""
    if result is None:
        return {"present": False}
    out = result.output or ""
    tradecraft = sorted(
        [{"flag": t.flag, "severity": t.severity} for t in (result.tradecraft or [])],
        key=lambda x: (x["flag"], x["severity"]),
    )
    mitre = sorted(
        [{"id": m.id, "technique": m.technique} for m in (result.mitre_hints or [])],
        key=lambda x: (x["id"], x["technique"]),
    )
    return {
        "present": True,
        "output_len": len(out),
        "output_sha256": _sha256_hex(out) if out else None,
        "notes_count": len(result.notes or []),
        "tradecraft": tradecraft,
        "mitre_hints": mitre,
        "explanation_sha256": _sha256_hex(result.explanation) if result.explanation else None,
    }


def _snapshot_crypto(cls, kind: str, text: str) -> dict:
    """Invoke a crypto BaseDecoder plugin on `text` and reduce to a
    stable observable dict."""
    if cls is None or _CTX is None:
        return {"available": False, "kind": kind}
    fp = _make_fp(text)
    t0 = time.perf_counter()
    exception = None
    detect_dict: dict = {}
    decode_dict: dict = {"present": False}
    try:
        inst = cls()
        det = inst.detect(text, fp, _CTX)
        detect_dict = {
            "confidence": round(float(det.confidence), 4),
            "why": det.why or "",
        }
        if det.confidence >= 0.30:
            res = inst.decode(text, det.args or {}, _CTX)
            decode_dict = _reduce_plugin_result(res)
    except Exception as exc:                    # never crash the snapshot
        exception = type(exc).__name__
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "available": True,
        "kind": kind,
        "exception": exception,
        "detect": detect_dict,
        "decode": decode_dict,
        "latency_ms": elapsed_ms,
    }


def _try_base64_bytes(text: str) -> "bytes | None":
    """Extract the longest base64-decoded blob from `text`.  Used to
    surface bytes that PE/shellcode analyzers can inspect (mirrors
    the way peel_recursively surfaces bytes via `_decode_bare_base64`)."""
    import re
    m = None
    best = b""
    for cand in re.finditer(r"[A-Za-z0-9+/=]{40,}", text):
        s = cand.group(0)
        s2 = s.rstrip("=")
        pad = "=" * (-len(s2) % 4)
        try:
            b = base64.b64decode(s2 + pad, validate=False)
        except (binascii.Error, ValueError):
            continue
        if len(b) > len(best):
            best = b
            m = cand
    return best if best else None


def _snapshot_pe(text: str) -> dict:
    if _pe_analyze is None:
        return {"available": False, "kind": "pe"}
    t0 = time.perf_counter()
    exception = None
    reduced: dict = {"applicable": False}
    try:
        raw = _try_base64_bytes(text)
        if raw and len(raw) >= 64 and raw[:2] == b"MZ":
            report = _pe_analyze(raw) or {}
            overview = report.get("overview") or {}
            hashes = report.get("hashes") or {}
            reduced = {
                "applicable": True,
                "available": bool(report.get("available")),
                "error": report.get("error"),
                "size": overview.get("size"),
                "machine": overview.get("machine"),
                "subsystem": overview.get("subsystem"),
                "sha256": hashes.get("sha256"),
                "imphash": hashes.get("imphash"),
                "sections": len(report.get("sections") or []),
                "imports": len(report.get("imports") or []),
                "findings_kinds": sorted(
                    list({(f.get("kind") or "") for f in (report.get("findings") or [])})
                ),
                "packer_hints": sorted(list(report.get("packer_hints") or [])),
            }
    except Exception as exc:
        exception = type(exc).__name__
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "available": True,
        "kind": "pe",
        "exception": exception,
        "report": reduced,
        "latency_ms": elapsed_ms,
    }


def _snapshot_shellcode(text: str) -> dict:
    if _sca is None:
        return {"available": False, "kind": "shellcode"}
    t0 = time.perf_counter()
    exception = None
    reduced: dict = {"applicable": False}
    try:
        raw = _try_base64_bytes(text)
        if raw and len(raw) >= 32:
            # PE bytes are NOT shellcode — skip if MZ.
            if raw[:2] == b"MZ":
                reduced = {"applicable": False, "reason": "MZ header (PE, not shellcode)"}
            else:
                is_sc = _sca.is_shellcode(raw)
                prologue = _sca.starts_with_known_prologue(raw)
                if is_sc or prologue:
                    report = _sca.analyze(raw) or {}
                    family, family_mitre = _sca._family_recognise(raw)
                    reduced = {
                        "applicable": True,
                        "is_shellcode": bool(report.get("is_shellcode")),
                        "arch": report.get("arch"),
                        "size": report.get("size"),
                        "entropy": round(float(report.get("entropy") or 0.0), 3),
                        "family": family,
                        "family_mitre": family_mitre,
                        "disasm_count": len(report.get("disassembly") or []),
                        "iocs_kinds": sorted(list((report.get("iocs") or {}).keys())),
                    }
                else:
                    reduced = {"applicable": False, "reason": "not shellcode-shaped"}
    except Exception as exc:
        exception = type(exc).__name__
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "available": True,
        "kind": "shellcode",
        "exception": exception,
        "report": reduced,
        "latency_ms": elapsed_ms,
    }


def main() -> int:
    fixtures = enumerate_fixtures()
    fixtures_root = Path(__file__).resolve().parents[1] / "fixtures"

    # Only fixtures hinted at surface #2 capabilities need to be probed.
    # Snapshot #1 already covers gzip/zlib/utf16le/byte-array-xor-loop.
    SURFACE_2_HINTS = {"rc4", "aes_cbc", "repeating_key_xor",
                       "pe", "shellcode", "xor"}

    applicable = [f for f in fixtures if set(f.codec_hints) & SURFACE_2_HINTS]

    snapshots: list[dict] = []
    total_latency: list[float] = []
    exceptions = 0

    for f in applicable:
        text = (fixtures_root / f.path).read_text(encoding="utf-8", errors="latin-1")
        record: dict = {
            "fixture_id": f.fixture_id,
            "codec_hints": list(f.codec_hints),
            "input_sha256": f.input_sha256,
            "size_bytes": f.size_bytes,
            "results": {},
        }
        if "rc4" in f.codec_hints:
            r = _snapshot_crypto(_Rc4Decoder, "rc4", text)
            record["results"]["rc4"] = r
            total_latency.append(r.get("latency_ms", 0.0))
            if r.get("exception"):
                exceptions += 1
        if "aes_cbc" in f.codec_hints:
            r = _snapshot_crypto(_AesCbcDecoder, "aes_cbc", text)
            record["results"]["aes_cbc"] = r
            total_latency.append(r.get("latency_ms", 0.0))
            if r.get("exception"):
                exceptions += 1
        if ("repeating_key_xor" in f.codec_hints
                or "xor" in f.codec_hints):
            r = _snapshot_crypto(_XorBruteDecoder, "xor_brute", text)
            record["results"]["xor_brute"] = r
            total_latency.append(r.get("latency_ms", 0.0))
            if r.get("exception"):
                exceptions += 1
        if "pe" in f.codec_hints:
            r = _snapshot_pe(text)
            record["results"]["pe"] = r
            total_latency.append(r.get("latency_ms", 0.0))
            if r.get("exception"):
                exceptions += 1
        if "shellcode" in f.codec_hints:
            r = _snapshot_shellcode(text)
            record["results"]["shellcode"] = r
            total_latency.append(r.get("latency_ms", 0.0))
            if r.get("exception"):
                exceptions += 1
        snapshots.append(record)

    # Aggregate latency
    lat_sorted = sorted(total_latency)
    def _pct(p: float) -> float:
        if not lat_sorted:
            return 0.0
        k = max(0, min(len(lat_sorted) - 1,
                       int(round((p / 100.0) * (len(lat_sorted) - 1)))))
        return lat_sorted[k]

    # Content signature — excludes timestamps, latency, and error strings
    # (only exception CLASS names contribute).
    content_only = []
    for s in snapshots:
        res_clean: dict = {}
        for kind, r in (s["results"] or {}).items():
            if r is None:
                continue
            rc = dict(r)
            rc.pop("latency_ms", None)
            res_clean[kind] = rc
        content_only.append({
            "fixture_id": s["fixture_id"],
            "codec_hints": s["codec_hints"],
            "input_sha256": s["input_sha256"],
            "results": res_clean,
        })
    signature = hashlib.sha256(
        json.dumps(content_only, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    out = {
        "gate": "P0-1B · Phase 2 · Gate 2D-B3.0 · Snapshot #2 (surface #2)",
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "reference_impls": {
            "rc4":         "decoders.crypto_symmetric.Rc4Decoder",
            "aes_cbc":     "decoders.crypto_symmetric.AesCbcDecoder",
            "xor_brute":   "decoders.xor_brute.XorBruteDecoder",
            "pe":          "services.pe_analyzer.analyze_pe",
            "shellcode":   "shellcode_analyzer.analyze",
        },
        "availability": _AVAIL,
        "surface_2_hints": sorted(list(SURFACE_2_HINTS)),
        "total_fixtures_probed": len(applicable),
        "exception_count": exceptions,
        "content_signature_sha256": signature,
        "aggregate_latency_ms": {
            "p50": _pct(50.0),
            "p95": _pct(95.0),
            "p99": _pct(99.0),
            "mean": (sum(total_latency) / len(total_latency)) if total_latency else 0.0,
            "max": (max(total_latency) if total_latency else 0.0),
        },
        "snapshots": snapshots,
    }
    write_json(HERE / "pre_migration_snapshot_2.json", out)

    print("─" * 68)
    print("Gate 2D-B3.0 · Snapshot #2 · Surface #2 parity baseline")
    print("─" * 68)
    print(f"applicable fixtures   : {len(applicable)}")
    print(f"exceptions raised     : {exceptions}")
    print(f"latency p50/p95/p99   : {_pct(50.0):.3f} / {_pct(95.0):.3f} / "
          f"{_pct(99.0):.3f} ms")
    print(f"content signature     : {signature[:24]}…")
    print("availability          :")
    for k, v in _AVAIL.items():
        print(f"    {k:<26s} = {v}")
    print("─" * 68)
    print("Artefact written:")
    print("    tests/decoder_migration/pre_migration_snapshot_2.json")
    print("─" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
