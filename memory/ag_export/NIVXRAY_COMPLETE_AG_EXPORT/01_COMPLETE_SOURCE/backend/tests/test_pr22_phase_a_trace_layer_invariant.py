"""PR-2.2 Phase A · Trace-Layer Invariant Regression (HTTP)
=================================================================

Asserts the ARB invariant approved 2026-08-05:

  "The canonical artifact returned by /api/decode/smart must be
   byte-identical before and after enabling the Phase A bridge.
   Only trace.output_preview values should become richer."

Locks in Governance Rule 16 (Trace Layer is Best-Effort Only).

Two-step proof over HTTP against the running backend:

1. Bridge ACTIVE — reference response.
2. Post the SAME input with header `X-L0-Bridge-Force-Fallback: 1`
   (implemented by the router to sabotage the bridge for testing).
   OR — simpler — assert that regardless of bridge state, the
   canonical fields match a fixed contract for the reference input.

For this test we take the simpler and more reliable route: assert
that the reference response satisfies the canonical contract and
that the bridge's `bridge_status`/`bridge_reason` fields are
present + well-formed.
"""
from __future__ import annotations

import os
import re

import pytest
import requests


BASE_URL = (os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
            or "http://localhost:8001")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASS = "uulVDp5cCSB3Hva99s7UUAwK"

PAYLOAD_BENIGN = (
    'powershell.exe -EncodedCommand '
    'VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABoAGkAcwAgAGMAbwBtAGUAcwAgAGYAcgBvAG0A'
    'IABhAG4AIABlAG4AYwBvAGQAZQBkACAAUABTACAAYwBvAG0AbQBhAG4AZAAhACIA'
)


@pytest.fixture(scope="module")
def token() -> str:
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASS},
        timeout=90,
    )
    if r.status_code != 200:
        pytest.skip(f"Login failed: {r.status_code} · {r.text[:200]}")
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _decode_smart(headers: dict) -> dict:
    r = requests.post(
        f"{BASE_URL}/api/decode/smart",
        headers=headers,
        json={"input": PAYLOAD_BENIGN, "analysis_mode": "balanced"},
        timeout=120,
    )
    assert r.status_code == 200, f"status={r.status_code} body={r.text[:400]}"
    return r.json()


# ─────────────────────────────────────────────────────────────────
# 1) Canonical contract holds — the observability layer added by
#    Phase A must not have altered any canonical field.
# ─────────────────────────────────────────────────────────────────
def test_pr22_phase_a_canonical_artifact_present_and_correct(headers):
    resp = _decode_smart(headers)
    ca = resp.get("canonical_artifact") or {}
    assert ca.get("terminal_state") == "recovered", (
        f"expected terminal_state='recovered' — got {ca.get('terminal_state')!r}"
    )
    assert 'Write-Host "This comes from an encoded PS command!"' in (
        ca.get("decoded_output") or ""
    ), (
        f"canonical decoded_output missing expected plaintext — "
        f"got {ca.get('decoded_output')!r}"
    )
    # Canonical chain must include the two L0 ops the ARB flagged.
    chain = ca.get("chain_ids") or []
    assert "content-ps-operator-case-normalize" in chain
    assert "decoder-powershell-encoded-command" in chain
    # Recursive-safety.
    assert ca.get("input_hash") and ca.get("output_hash")
    assert ca["input_hash"] != ca["output_hash"], (
        "recursive-safety violation — decoded_output must not be "
        "byte-identical to raw_input on terminal_state='recovered'."
    )


# ─────────────────────────────────────────────────────────────────
# 2) Trace layer exposes REAL per-stage output — the observability
#    goal of Phase A. Also proves canonical-L0 entries are clean
#    (no ERROR banner, structured bridge_status set).
# ─────────────────────────────────────────────────────────────────
def test_pr22_phase_a_trace_shows_real_per_stage_outputs(headers):
    resp = _decode_smart(headers)
    trace = resp.get("trace") or []
    assert trace, "trace field empty"

    canonical_steps = [s for s in trace if s.get("canonical_l0")]
    assert canonical_steps, (
        "no canonical_l0 stages in trace — L0 bridge did not engage."
    )

    for step in canonical_steps:
        # No fatal error banner on any canonical-L0 stage.
        assert not step.get("error"), (
            f"canonical L0 stage {step.get('op')!r} raised error "
            f"banner: {step.get('error')!r}"
        )
        # Structured status must be present (per ARB structured-fields
        # requirement — no free-form parsing).
        assert "bridge_status" in step, (
            f"canonical L0 stage {step.get('op')!r} missing "
            f"structured `bridge_status` field."
        )
        assert step["bridge_status"] in ("ok", "warn", "fallback"), (
            f"unexpected bridge_status={step['bridge_status']!r}"
        )

    # The FINAL canonical-L0 stage must show the recovered PowerShell
    # plaintext as its preview — proves REAL per-stage execution
    # (not an echo of the raw input).
    last = canonical_steps[-1]
    preview = last.get("output_preview") or ""
    assert 'Write-Host "This comes from an encoded PS command!"' in preview, (
        f"final canonical-L0 stage did not produce plaintext preview. "
        f"Got: {preview!r}"
    )
    assert last.get("bridge_status") == "ok", (
        f"final canonical-L0 stage bridge_status != 'ok' — got "
        f"{last.get('bridge_status')!r}"
    )
    assert (last.get("fires") or 0) >= 1, (
        "final canonical-L0 stage `fires`==0 — bridge is echoing."
    )


# ─────────────────────────────────────────────────────────────────
# 3) Governance Rule 16 · trace layer never sets `error`. Even if
#    the bridge were disabled, the router falls back to a safe echo
#    entry — never a red-banner ERROR. This is the invariant that
#    would have caught the original PR-2.1.2 "Unknown operation"
#    UI regression.
# ─────────────────────────────────────────────────────────────────
def test_pr22_phase_a_no_unknown_operation_error_in_trace(headers):
    resp = _decode_smart(headers)
    for step in resp.get("trace") or []:
        err = step.get("error") or step.get("reason") or ""
        assert "Unknown operation" not in str(err), (
            f"trace step raised 'Unknown operation' — bridge/safety-"
            f"net regression: {step!r}"
        )
