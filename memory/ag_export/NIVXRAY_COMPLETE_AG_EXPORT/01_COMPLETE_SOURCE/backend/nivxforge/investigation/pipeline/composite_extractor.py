"""Composite Value Extractor — pre-Stage-3 enrichment.

Owner mandate (2026-02-XX): composite-value parsing is NOT semantic
mapping. It is deterministic parsing that belongs *before* Stage 3.

Composite values look like:

    Hashes:      "SHA256=abc… MD5=def… IMPHASH=ghi…"
    Algorithms:  "algo=rsa2048;bits=2048;padding=pkcs1"
    TLS suites:  "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256"
    Certs:       "subject=CN=x issuer=CN=y serial=00abcd"

They embed multiple canonical values inside one field. Vendor
normalizers historically know to crack them open with hard-coded
regex; that's exactly the vendor-branching we want to avoid.

This module cracks them open GENERICALLY:

  · A single ``key=value`` pair per line / delimiter
  · Multiple ``key=value`` pairs separated by whitespace / commas /
    semicolons
  · Multi-hash rows like ``SHA256=… MD5=…``

Cracked keys are emitted as SIBLING fields on the record, prefixed
with the origin field name for provenance (e.g.
``Hashes.SHA256``, ``Hashes.MD5``). The origin field is retained.

Contract:
  · Pure function — no I/O, no state.
  · Never raises. Never mutates the input.
  · Returns a NEW ParsedInput. If nothing was composite, returns
    an equal (but new) instance.
  · No vendor branding. No hard-coded field names.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .parser import ParsedInput


# Match ``KEY=value`` where key is short-ish uppercase-alnum. Values
# stop at whitespace / semicolon / comma unless quoted. This is
# deliberately strict to avoid false-positive expansions of prose.
_COMPOSITE_KV = re.compile(
    r"([A-Za-z][A-Za-z0-9_]{1,32})\s*=\s*"
    r"(\"[^\"]{1,512}\"|'[^']{1,512}'|[^\s;,]{1,512})"
)

# Minimum number of KV pairs required before treating a value as
# composite. Prevents "foo=bar" (a single genuine assignment inside
# analyst prose) from being expanded.
_MIN_KV_PAIRS = 2

# Fields whose values NEVER get composite-expanded even if they
# structurally look composite (e.g. URLs contain ``?a=1&b=2`` fragments).
_SKIP_FIELDS = frozenset({
    "url", "uri", "request_url", "requesturl",
    "http.url", "http.request.url",
    "commandline", "command_line", "cmdline",
    "processcommandline",
})


def expand_composites(parsed: ParsedInput,
                      *,
                      diagnostics_prefix: str = "composite:",
                      ) -> ParsedInput:
    """Return a NEW ParsedInput with composite string values cracked
    into sibling fields.

    Deterministic. Never raises. Vendor-neutral.
    """
    if not parsed.records:
        return parsed

    new_diagnostics = list(parsed.diagnostics or ())
    new_records: List[Dict[str, Any]] = []
    expanded_any = False

    for rec in parsed.records:
        if not isinstance(rec, dict):
            new_records.append(rec)
            continue
        expanded_rec, expansions = _expand_record(rec)
        if expansions:
            expanded_any = True
            for origin, pairs in expansions:
                new_diagnostics.append(
                    f"{diagnostics_prefix}{origin}={len(pairs)} pairs"
                )
        new_records.append(expanded_rec)

    if not expanded_any:
        return parsed

    return ParsedInput(
        kind=parsed.kind,
        records=new_records,
        text=parsed.text,
        diagnostics=new_diagnostics,
    )


def _expand_record(rec: Dict[str, Any]
                   ) -> Tuple[Dict[str, Any],
                              List[Tuple[str, Dict[str, str]]]]:
    """Return a new record dict with cracked siblings + a list of
    (origin_field, extracted_pairs) for diagnostics."""
    out: Dict[str, Any] = {}
    expansions: List[Tuple[str, Dict[str, str]]] = []

    for key, val in rec.items():
        out[key] = val
        if not isinstance(val, str):
            continue
        if key.lower() in _SKIP_FIELDS:
            continue
        pairs = _extract_kv(val)
        if not pairs:
            continue
        # Composite gate:
        #   ≥ 2 KV pairs                  → expand (default)
        #   exactly 1 pair with an
        #     uppercase key (≥ 3 chars)    → expand (SHA256=…, MD5=…,
        #                                    IMPHASH=…, MITRE=…, CVE=…)
        # Single lowercase pair like "reason=timeout" stays intact
        # (analyst prose, not composite).
        if len(pairs) < _MIN_KV_PAIRS:
            if not (len(pairs) == 1
                    and _looks_like_composite_marker(next(iter(pairs)))):
                continue
        # Emit sibling fields prefixed by the origin key.
        # Preserve provenance by keeping the origin value intact.
        for sub_key, sub_val in pairs.items():
            sibling = f"{key}.{sub_key}"
            # Never overwrite a pre-existing sibling.
            if sibling in out:
                continue
            out[sibling] = sub_val
        expansions.append((key, pairs))

    return out, expansions


def _looks_like_composite_marker(key: str) -> bool:
    """Uppercase key of ≥ 3 chars is a strong marker that the value
    is a composite (e.g. ``SHA256=…``, ``MITRE=…``, ``CVE=…``, ``MD5=…``).

    Lowercase keys ("reason=timeout") are ambiguous and stay unexpanded
    per the ≥ 2 pair rule.
    """
    return (len(key) >= 3 and key == key.upper()
            and key.replace("_", "").isalnum())


def _extract_kv(value: str) -> Optional[Dict[str, str]]:
    """Return a dict of KV pairs found in ``value``, or empty dict."""
    if len(value) > 4096:
        return None
    out: Dict[str, str] = {}
    for m in _COMPOSITE_KV.finditer(value):
        k = m.group(1)
        v = m.group(2).strip().strip("\"'")
        # Deduplicate: keep first occurrence for stability.
        if k in out:
            continue
        out[k] = v
    return out


__all__ = ["expand_composites"]
