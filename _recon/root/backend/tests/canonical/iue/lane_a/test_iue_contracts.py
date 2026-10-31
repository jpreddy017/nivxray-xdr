"""Lane-A · Failure envelope, tenant fallback, recursion parity,
security caps, flag-off inertness, understanding.py thinness."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[4]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


# ── Failure envelope ──────────────────────────────────────────────
def test_failure_vocabulary_is_closed():
    from services.iue.failure import IUEFailure

    with pytest.raises(ValueError):
        IUEFailure(status="bogus", stage="intake",
                    error_code="intake_unknown_kind",
                    message="x", recoverable=False)
    with pytest.raises(ValueError):
        IUEFailure(status="terminal", stage="not_a_stage",
                    error_code="intake_unknown_kind",
                    message="x", recoverable=False)
    with pytest.raises(ValueError):
        IUEFailure(status="terminal", stage="intake",
                    error_code="not_in_vocabulary",
                    message="x", recoverable=False)


def test_failure_ok_shape_serialisable():
    from services.iue.failure import IUEFailure
    f = IUEFailure(status="recoverable", stage="parse",
                    error_code="parse_malformed_record",
                    message="one bad row", recoverable=True,
                    input_id="in-1", tenant_id="t-1")
    d = f.to_dict()
    assert d["status"] == "recoverable"
    assert d["error_code"] == "parse_malformed_record"
    # Provenance replaces the inline 'at' field (STEP 6c.2 refactor).
    assert d["provenance"]["engine"] == "iue.failure.parse"
    assert d["provenance"]["at"]
    assert d["provenance"]["version"] == "1.0"


# ── Tenant fallback (STEP 3 §4) ───────────────────────────────────
def test_prev_mode_falls_back_to_prev_public_sentinel():
    from services.iue.tenancy import resolve_tenant, PREV_PUBLIC_TENANT
    assert resolve_tenant(None, allow_prev_fallback=True) == PREV_PUBLIC_TENANT


def test_prod_mode_refuses_tenantless_traffic():
    from services.iue.tenancy import resolve_tenant
    assert resolve_tenant(None, allow_prev_fallback=False) == ""


def test_intake_fails_terminally_without_tenant_in_prod_mode():
    from services.iue.intake import intake
    from services.iue.failure import IUEFailure

    result = intake("plain text",
                     allow_prev_fallback=False)
    assert isinstance(result, IUEFailure)
    assert result.error_code == "tenant_context_missing"
    assert result.status == "terminal"


# ── Recursion parity (STEP 5 §3 P8/P9/P10) ────────────────────────
def test_recurse_depth_cap_matches_uaie():
    from services.iue.recurse import recurse, UAIE_MAX_DEPTH
    from services.iue.failure import IUEFailure
    from services.uaie.ledger import Ledger

    ledger = Ledger()
    result = recurse(b"payload",
                      ledger=ledger,
                      parent_input_id="parent",
                      tenant_id="t-1",
                      discovery_depth=UAIE_MAX_DEPTH)
    assert isinstance(result, IUEFailure)
    assert result.error_code == "recurse_depth_exceeded"
    # Ledger must have recorded the skip
    snap = ledger.snapshot()
    assert any("depth_cap" in (e.get("output_summary") or "") for e in snap)


def test_recurse_cycle_detected_via_shared_ledger():
    from services.iue.recurse import recurse
    from services.iue.failure import IUEFailure
    from services.uaie.ledger import Ledger

    ledger = Ledger()
    payload = b'{"a": 1}'
    # First recurse succeeds — writes fingerprint entry.
    first = recurse(payload, ledger=ledger,
                     parent_input_id="parent",
                     tenant_id="t-1",
                     discovery_depth=0)
    # Second recurse of same bytes → cycle.
    second = recurse(payload, ledger=ledger,
                      parent_input_id="parent",
                      tenant_id="t-1",
                      discovery_depth=0)
    assert isinstance(second, IUEFailure)
    assert second.error_code == "recurse_cycle_detected"


# ── Security caps ────────────────────────────────────────────────
def test_collect_size_cap_returns_failure_not_exception():
    from services.iue.collectors.log_collector import collect
    from services.iue.failure import IUEFailure
    from services.iue import security as sec

    # Temporarily lower the cap
    orig = sec.MAX_RAW_BYTES
    sec.MAX_RAW_BYTES = 100
    try:
        result = collect(b"x" * 200, mime="application/x-ndjson",
                          input_id="in-1", tenant_id="t-1")
        assert isinstance(result, IUEFailure)
        assert result.error_code == "collect_size_exceeded"
        assert result.status == "terminal"
    finally:
        sec.MAX_RAW_BYTES = orig


def test_archive_path_traversal_rejected():
    from services.iue.security import is_safe_archive_member
    assert not is_safe_archive_member("../etc/passwd")
    assert not is_safe_archive_member("/absolute/path")
    assert not is_safe_archive_member("a/../b")
    assert is_safe_archive_member("safe/nested/file.log")


# ── Flag-off inertness ───────────────────────────────────────────
def test_flag_off_demotes_structured_to_raw_text(monkeypatch):
    monkeypatch.delenv("IUE_STRUCTURED_LANE", raising=False)
    from services.iue.intake import intake

    payload = b'{"host":"srv","event":"login"}\n' * 5
    d = intake(payload, allow_prev_fallback=True)
    assert d.lane == "raw_text"
    assert d.flag_state == "off"
    assert "structured_lane_disabled" in d.reasons


def test_flag_on_activates_structured_lane(monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "on")
    from services.iue.intake import intake

    payload = b'{"host":"srv","event":"login"}\n' * 5
    d = intake(payload, allow_prev_fallback=True)
    assert d.lane == "structured"
    assert d.flag_state == "on"
    assert d.kind in {"raw_json", "ndjson"}


# ── understanding.py thinness (STEP 5 §6 residual risk 6) ────────
def test_understanding_module_is_thin_consolidator():
    """40-LOC ceiling on functional (non-comment / non-blank) code in
    services/iue/understanding.py.  Grows past this → the module must
    be split.  See STEP 3 §8 risk 8."""
    import inspect
    from services.iue import understanding
    src = inspect.getsource(understanding)
    lines = [l for l in src.splitlines()
              if l.strip() and not l.strip().startswith(('#', '"""', "'''"))]
    # Exclude imports which are trivially cheap.
    code_lines = [l for l in lines
                   if not l.strip().startswith(("from ", "import "))]
    assert len(code_lines) <= 40, (
        f"understanding.py has {len(code_lines)} lines of functional "
        f"code — exceeds the 40-line thin-consolidator ceiling."
    )
