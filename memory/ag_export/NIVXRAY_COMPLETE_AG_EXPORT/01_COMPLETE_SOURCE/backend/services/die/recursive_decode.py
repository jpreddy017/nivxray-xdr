"""Recursive base64 / -EncodedCommand decoder for the DIE analyzer.

ADR-0010e §10 item 3 · ADR-0023 §4 precondition 3 (owner sign-off 2026-08-12).

Purpose
    Extend the DIE analyzer's evidence chain by peeling nested
    base64 layers embedded in PowerShell / cmd / VBScript inputs so
    inner IOCs, commands, and MITRE evidence become visible.

    Concretely, this closes the ADR-0010e §7 Q5.2 finding: case
    `rip-08-nested-b64-ps` produces an outer T1027 + T1059.001 +
    T1564.003 envelope but no inner URL / no T1140 because the outer
    analyzer never invokes its inner sibling on the decoded payload.

Design
    * **Additive only** — this module never mutates or overwrites the
      base analyzer's decisions. It emits a list of ``DecodedLayer``
      records that callers merge into their envelope by deduplication.
    * **Deterministic** — same input always produces the same layer
      set. No randomness, no timestamps, no wall-clock latency
      dependencies. Ordering is (regex-match-order, depth).
    * **Terminates** — hard cap ``MAX_DEPTH = 3`` on nesting depth and
      ``MAX_LAYERS = 12`` on total layers per invocation. A
      SHA-256 visit set guards against cycles (a payload that decodes
      into itself, base64-of-itself, etc.).
    * **Cruise-Missile Guidance Principle** (ADR-0023 §3a) — the
      decoder pursues the evidence chain one layer deeper, but never
      manufactures verdict-level claims. The caller decides how the
      new layers combine into a verdict.
"""
from __future__ import annotations
import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Set, Tuple

# ── Hard caps (owner-locked) ────────────────────────────────────────
MAX_DEPTH: int = 3           # nested layers — 3 is enough for known malware
MAX_LAYERS: int = 12         # total layers emitted per top-level call
MIN_B64_LEN: int = 20        # ignore short accidental base64-looking tokens
MAX_B64_LEN: int = 500_000   # refuse absurdly large blobs (DoS guard)

# ── Base64 extraction patterns ──────────────────────────────────────
# Each pattern must yield the base64 payload as capture group 1.
_B64_PATTERNS: Tuple[re.Pattern, ...] = (
    # PowerShell -EncodedCommand / -Enc / -e / -ec (case-insensitive)
    re.compile(r"(?i)(?:-e(?:c|nc|ncodedcommand)?)\s+"
               r"([A-Za-z0-9+/]{20,}={0,2})"),
    # .NET: [Convert]::FromBase64String('...') or "..."
    re.compile(r"(?i)FromBase64String\s*\(\s*['\"]"
               r"([A-Za-z0-9+/]{20,}={0,2})['\"]"),
    # cmd/bash: certutil -decode / base64 -d fed inline (rare but seen)
    re.compile(r"(?i)base64\s+(?:-d|--decode)\s+"
               r"([A-Za-z0-9+/]{20,}={0,2})"),
)


@dataclass(frozen=True)
class DecodedLayer:
    """One successfully-decoded base64 payload."""
    depth: int
    pattern_index: int      # which _B64_PATTERNS pattern matched
    source_offset: int      # where in the parent this layer was found
    encoding_used: str      # "utf-8" or "utf-16le"
    b64_sha256: str         # SHA-256 of the base64 blob (visit-set key)
    decoded_sha256: str     # SHA-256 of the decoded plaintext
    decoded_text: str       # ≤ 64 KB view; callers must not exceed this


def _try_decode(b64: str) -> Tuple[str, str] | None:
    """Attempt UTF-16LE first (PowerShell -EncodedCommand default),
    then UTF-8. Return ``(text, encoding)`` on success, ``None`` on
    failure. Never raises.

    Preference order matters: PowerShell -Enc payloads are UTF-16LE
    but naive UTF-8 decoding *appears* to succeed because interleaved
    NUL bytes are technically valid UTF-8. We detect that ambiguity
    by scoring the decoded text's null-byte density and printable-
    ratio, and pick UTF-16LE when it produces cleaner text."""
    if not b64 or len(b64) < MIN_B64_LEN or len(b64) > MAX_B64_LEN:
        return None
    # Base64 length must be a multiple of 4 after stripping — pad if
    # a caller-side truncation lost the trailing "=" chars.
    pad = (-len(b64)) % 4
    b64p = b64 + ("=" * pad)
    try:
        raw = base64.b64decode(b64p, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None

    def _score(text: str) -> float:
        """Higher is cleaner. Penalises NUL density; rewards printable
        ASCII + common whitespace."""
        if not text:
            return 0.0
        nul_ratio = text.count("\x00") / len(text)
        printable = sum(1 for c in text
                        if c.isprintable() or c in "\r\n\t ")
        return (printable / len(text)) - (2 * nul_ratio)

    utf8_candidate = None
    utf16_candidate = None
    try:
        utf8_candidate = raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if len(raw) % 2 == 0:
        try:
            utf16_candidate = raw.decode("utf-16le")
        except UnicodeDecodeError:
            pass
    else:
        # Defensive: real-world -Enc payloads occasionally arrive with
        # a stray trailing byte (base64 truncation, chain concat).
        # Drop the last byte so a single lost byte does not blind the
        # analyzer to the entire inner layer.
        try:
            utf16_candidate = raw[:-1].decode("utf-16le")
        except UnicodeDecodeError:
            pass

    utf8_score = _score(utf8_candidate) if utf8_candidate else -1.0
    utf16_score = _score(utf16_candidate) if utf16_candidate else -1.0

    # Choose the higher-scoring candidate above a 0.7 acceptance floor;
    # UTF-16LE wins on ties (matches PowerShell's default).
    if utf16_candidate and utf16_score >= 0.7 and utf16_score >= utf8_score:
        return utf16_candidate, "utf-16le"
    if utf8_candidate and utf8_score >= 0.7:
        return utf8_candidate, "utf-8"
    return None


def _extract_layers(
    src: str,
    depth: int,
    visited: Set[str],
    layers_out: List[DecodedLayer],
) -> None:
    """Recursively extract base64 layers from ``src``. Populates
    ``layers_out`` in-place. Bounded by ``MAX_DEPTH`` + ``MAX_LAYERS``
    + ``visited`` cycle guard."""
    if depth >= MAX_DEPTH or len(layers_out) >= MAX_LAYERS:
        return
    for pat_idx, pat in enumerate(_B64_PATTERNS):
        for m in pat.finditer(src):
            if len(layers_out) >= MAX_LAYERS:
                return
            b64_blob = m.group(1)
            b64_sha = hashlib.sha256(b64_blob.encode()).hexdigest()
            if b64_sha in visited:
                continue  # already processed this exact base64 blob
            visited.add(b64_sha)
            decoded = _try_decode(b64_blob)
            if not decoded:
                continue
            text, enc = decoded
            # Cap the surfaced text at 64 KB to bound response size.
            surface = text[:64_000]
            layer = DecodedLayer(
                depth=depth,
                pattern_index=pat_idx,
                source_offset=m.start(),
                encoding_used=enc,
                b64_sha256=b64_sha,
                decoded_sha256=hashlib.sha256(text.encode(
                    "utf-8", errors="replace")).hexdigest(),
                decoded_text=surface,
            )
            layers_out.append(layer)
            # Recurse into the decoded content for further nested
            # base64 layers.
            _extract_layers(text, depth + 1, visited, layers_out)


def extract_decoded_layers(src: str) -> List[DecodedLayer]:
    """Public entry point.

    Deterministic — same ``src`` returns the same ``List[DecodedLayer]``
    on every call. Never raises. Bounded by ``MAX_DEPTH`` + ``MAX_LAYERS``.
    """
    if not src or not isinstance(src, str):
        return []
    visited: Set[str] = set()
    layers: List[DecodedLayer] = []
    _extract_layers(src, depth=0, visited=visited, layers_out=layers)
    return layers


def merge_evidence(
    outer: dict,
    inner_envelopes: Iterable[dict],
) -> dict:
    """Fold inner-envelope evidence into the outer envelope by
    deduplication. **Additive only** — never removes or renames outer
    signals. Returns the same dict for chaining.

    Merge rules (each dedup key documented):
      * ``techniques`` — dedup on ``id``. First occurrence wins.
      * ``lolbins`` — dedup on ``binary`` (lower-cased).
      * ``iocs`` — dedup on ``(kind, value)`` tuple.
      * When any inner envelope contributes ≥ 1 new technique or
        IOC, synthesise a ``T1140`` (Deobfuscate/Decode Files or
        Information) row on ``outer.techniques`` with an evidence
        snippet naming the recursive-decode source. T1140 is the
        MITRE-attested technique that describes exactly what the
        recursive decoder is observing.
    """
    if not outer.get("techniques"):
        outer["techniques"] = []
    if not outer.get("lolbins"):
        outer["lolbins"] = []
    if not outer.get("iocs"):
        outer["iocs"] = []

    seen_techs = {t.get("id") for t in outer["techniques"] if isinstance(t, dict)}
    seen_lolbins = {(l.get("binary") or "").lower()
                    for l in outer["lolbins"] if isinstance(l, dict)}
    seen_iocs = {(i.get("kind"), i.get("value"))
                 for i in outer["iocs"] if isinstance(i, dict)}

    inner_added = 0
    for env in inner_envelopes:
        if not isinstance(env, dict):
            continue
        for t in env.get("techniques") or []:
            if isinstance(t, dict) and t.get("id") and t["id"] not in seen_techs:
                outer["techniques"].append({**t, "source": "recursive_decode"})
                seen_techs.add(t["id"])
                inner_added += 1
        for l in env.get("lolbins") or []:
            if isinstance(l, dict):
                key = (l.get("binary") or "").lower()
                if key and key not in seen_lolbins:
                    outer["lolbins"].append({**l, "source": "recursive_decode"})
                    seen_lolbins.add(key)
                    inner_added += 1
        for i in env.get("iocs") or []:
            if isinstance(i, dict):
                key = (i.get("kind"), i.get("value"))
                if key not in seen_iocs and i.get("value"):
                    outer["iocs"].append({**i, "source": "recursive_decode"})
                    seen_iocs.add(key)
                    inner_added += 1

    if inner_added > 0 and "T1140" not in seen_techs:
        outer["techniques"].append({
            "id": "T1140",
            "name": "Deobfuscate/Decode Files or Information",
            "evidence": (f"Recursive base64 decode surfaced "
                         f"{inner_added} additional evidence element(s) "
                         f"across nested layer(s)."),
            "source": "recursive_decode",
        })

    return outer


__all__ = [
    "MAX_DEPTH", "MAX_LAYERS",
    "DecodedLayer", "extract_decoded_layers", "merge_evidence",
]
