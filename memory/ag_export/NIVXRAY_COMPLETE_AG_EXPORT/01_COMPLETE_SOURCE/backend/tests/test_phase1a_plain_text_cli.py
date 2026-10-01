"""Phase 1a regression suite — Plain-Text CLI Investigation.

v1.6.0 Phase 1a · SME-ratified acceptance gate (Feb-2026)
=========================================================

Every conclusion the investigation engine emits must comply with the
Product Charter's Rules 1-4 (see /app/memory/PRODUCT_CHARTER.md).
This test file locks the specific acceptance behaviour for the SME
plain-text CLI acceptance sample:

    --runaszvideo=TRUE
    --useroption=…
    …
    --haszoomim=1

Historically the engine returned:

    Verdict: BENIGN (confidence 60)
    "The artefact appears benign and no immediate action is required."
    "Zoom-related option flags (--runaszvideo, --haszoomim)"
    "Appears to be legitimate application configuration"

Every one of those statements violates Rule 1 (unsupported conclusion),
Rule 4 (unknown-is-acceptable), or the ban on single-flag vendor
identification. This test enforces the correct behaviour going forward.

If any assertion in this file fails, DO NOT weaken the assertion —
the engine has regressed. Fix the engine.
"""

from __future__ import annotations

import re

import pytest

from analysis_core import deterministic_best_decode


SME_PLAIN_TEXT_CLI = """--runaszvideo=TRUE
--useroption=2347222064534913024
--useroption2=1152956688981395520
--useroption3=6917600633341970944
--useroption4=0
--useroption5=2594989113597953028
--useroption6=6193578274037952
--useroption7=-3458764213071970300
--useroption8=185290410950664
--useroption9=7908259395570177
--userroomoption=0
--userroomoption2=0
--userroomoption5=0
--haszoomim=1"""


# Phrases that must NEVER appear anywhere in the investigation output.
# Case-insensitive substring match.
FORBIDDEN_PHRASES = [
    "appears benign",
    "artefact appears benign",
    "artifact appears benign",
    "legitimate application",
    "no immediate action",
    "no action required",
    "likely zoom",
    # NB: "zoom" as a vendor claim is banned, but the raw string
    # "zoom" also appears in the input token "--haszoomim". We
    # therefore forbid CLAIMS about Zoom (see _has_zoom_claim below)
    # rather than a plain substring of "zoom".
]


def _has_zoom_claim(text: str) -> bool:
    """Detect vendor-identification claims about Zoom (Charter Rule 4).

    We deliberately do NOT flag the raw input token `--haszoomim`
    which contains the substring `zoom`. What is forbidden is any
    NARRATIVE claim identifying the artefact as Zoom-related.
    """
    haystack = text.lower()
    patterns = [
        r"\bzoom\b(?!\s*im\b)",   # "Zoom" as a standalone word
        r"zoom-?related",
        r"zoom (?:app|application|client|software|product|vendor)",
    ]
    return any(re.search(p, haystack) for p in patterns)


@pytest.fixture(scope="module")
def sme_result():
    """Run the deterministic pipeline once for the SME sample."""
    return deterministic_best_decode(SME_PLAIN_TEXT_CLI, analysis_mode="balanced")


def _extract_all_text(result: dict) -> str:
    """Flatten every human-readable string in the result payload for
    substring assertions. Investigations are heavily nested — one flat
    string is the safest way to catch a Charter-violating phrase
    regardless of which section emitted it."""
    parts: list[str] = []

    def walk(obj):
        if isinstance(obj, str):
            parts.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                walk(v)

    walk(result)
    return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────
# Verdict-band assertions (tri-state model)
# ─────────────────────────────────────────────────────────────────

def test_verdict_band_is_unknown_not_benign(sme_result):
    """SME plain-text CLI must produce UNKNOWN, never BENIGN.

    The absence of malicious indicators is NOT evidence of legitimacy.
    Requires POSITIVE evidence (signed binary, allow-listed hash) to
    upgrade to BENIGN — none is available for a raw CLI paste.
    """
    verdict = sme_result.get("verdict") or ""
    assert verdict == "unknown", (
        f"expected verdict 'unknown' for SME plain-text CLI, "
        f"got {verdict!r}. Charter Rule 4 violation — the engine may "
        f"NOT default to BENIGN from absence of malicious indicators."
    )


def test_verdict_reason_cites_insufficient_evidence(sme_result):
    """The full investigation output must, somewhere in its narrative,
    cite the evidence gap. Analysts must never see 'appears benign' or
    'no immediate action required' — instead they must see WHY the
    engine could not conclude further."""
    text = _extract_all_text(sme_result).lower()
    ok = any(k in text for k in [
        "insufficient", "additional context", "evidence is insufficient",
        "cannot be determined", "not consistent with routine",
    ])
    assert ok, (
        "investigation narrative must cite insufficient evidence / "
        "required additional context / undeterminable — not silence. "
        f"Snippet:\n{text[:800]}"
    )


# ─────────────────────────────────────────────────────────────────
# Forbidden-phrase assertions (Charter Rules 1 & 4)
# ─────────────────────────────────────────────────────────────────

def test_no_forbidden_phrases_anywhere_in_output(sme_result):
    """Full-payload sweep — no offending narrative anywhere."""
    text = _extract_all_text(sme_result).lower()
    hits = [p for p in FORBIDDEN_PHRASES if p in text]
    assert not hits, (
        f"Charter Rule 1/4 violation — investigation output contains "
        f"forbidden phrase(s): {hits}. "
        f"See /app/memory/PRODUCT_CHARTER.md § Phase 1a."
    )


def test_no_zoom_vendor_claim(sme_result):
    """--haszoomim is a single-flag inference — banned per Rule 4."""
    text = _extract_all_text(sme_result)
    assert not _has_zoom_claim(text), (
        "single-flag vendor identification (--haszoomim → Zoom) is "
        "forbidden — Charter Rule 4. Vendor recognition requires ≥2 "
        "corroborating indicators."
    )
