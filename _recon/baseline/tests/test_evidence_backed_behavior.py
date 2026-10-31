"""
Independent regression tests for PR-2.1 hotfix: evidence-backed Behavior claims
in the ▼ POWERSHELL NORMALIZATION & RUNTIME RECONSTRUCTION block of /api/decode/smart.

Also verifies:
  - Canonical verdict invariant (verdict_card.verdict == risk.verdict, scores equal)
  - Rule 14 Decode/Auto-Investigate equivalence via /api/analyze/async
"""
import os
import re
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def auth_headers():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=90,
    )
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"
    tok = r.json().get("access_token") or r.json().get("token")
    assert tok, f"no token in login response: {r.json()}"
    return {"Authorization": f"Bearer {tok}"}

# Exact user-shared payload — decodes (UTF-16LE) to:
#   Write-Host "This comes from an encoded PS command!"
BENIGN_B64 = (
    "VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABoAGkAcwAgAGMAbwBtAGUAcwAgAGYAcgBvAG0AIABhAG4AIABlAG4AYwBvAGQAZQBkACAAUABTACAAYwBvAG0AbQBhAG4AZAAhACIA"
)
INPUT_LOWER = f"powershell -EncodedCommand {BENIGN_B64}"
INPUT_MIXED = f"PoWeRsHeLl -EncodedCommand {BENIGN_B64}"

BLOCK_HEADER = "▼ POWERSHELL NORMALIZATION & RUNTIME RECONSTRUCTION"


def _decode(payload: str, headers: dict) -> dict:
    r = requests.post(f"{BASE_URL}/api/decode/smart", json={"input": payload}, headers=headers, timeout=60)
    assert r.status_code == 200, f"decode/smart failed: {r.status_code} {r.text[:400]}"
    return r.json()


def _extract_ps_block(output_text: str) -> str:
    assert BLOCK_HEADER in output_text, f"PS normalization block missing.\nOUTPUT:\n{output_text[:2000]}"
    idx = output_text.index(BLOCK_HEADER)
    tail = output_text[idx:]
    # Block ends at next ▼ header or end
    m = re.search(r"\n▼ ", tail[len(BLOCK_HEADER):])
    return tail if not m else tail[: len(BLOCK_HEADER) + m.start()]


def _output_text(resp: dict) -> str:
    # Primary location: output_raw contains the ▼ blocks
    for key in ("output_raw", "output", "output_text", "text", "report_text"):
        v = resp.get(key)
        if isinstance(v, str) and BLOCK_HEADER in v:
            return v
    # Nested fallback
    for key in ("decode", "result", "data"):
        sub = resp.get(key) or {}
        if isinstance(sub, dict):
            for k in ("output_raw", "output", "output_text", "text", "report_text"):
                v = sub.get(k)
                if isinstance(v, str) and BLOCK_HEADER in v:
                    return v
    # Last resort: any string value in top-level containing block
    for k, v in resp.items():
        if isinstance(v, str) and BLOCK_HEADER in v:
            return v
    import json
    dump = json.dumps(resp)
    assert BLOCK_HEADER in dump, f"PS block not found. Keys: {list(resp.keys())}"
    return dump


class TestEvidenceBackedBehavior:
    def test_smart_returns_200(self, auth_headers):
        resp = _decode(INPUT_LOWER, auth_headers)
        assert isinstance(resp, dict)

    def test_no_mixed_case_claim_on_benign_input(self, auth_headers):
        resp = _decode(INPUT_LOWER, auth_headers)
        block = _extract_ps_block(_output_text(resp))
        assert "Mixed-case obfuscation" not in block, (
            f"Rule-13 violation: 'Mixed-case obfuscation' emitted with no mixed-case input.\nBLOCK:\n{block}"
        )

    def test_no_comma_obfuscation_claim_when_absent(self, auth_headers):
        resp = _decode(INPUT_LOWER, auth_headers)
        block = _extract_ps_block(_output_text(resp))
        assert "Comma-separated token obfuscation" not in block, (
            f"Rule-13 violation: 'Comma-separated token obfuscation' emitted without commas.\nBLOCK:\n{block}"
        )

    def test_positive_base64_wrapper_line_present(self, auth_headers):
        resp = _decode(INPUT_LOWER, auth_headers)
        block = _extract_ps_block(_output_text(resp))
        assert "Base64 UTF-16LE EncodedCommand wrapper (T1027.010)" in block, (
            f"Expected T1027.010 wrapper line in block.\nBLOCK:\n{block}"
        )

    def test_positive_safe_builtin_line_present(self, auth_headers):
        resp = _decode(INPUT_LOWER, auth_headers)
        block = _extract_ps_block(_output_text(resp))
        assert "Safe built-in — no malicious behavior" in block, (
            f"Expected safe-builtin line for Write-Host payload.\nBLOCK:\n{block}"
        )

    def test_runtime_simulation_shows_decoded_literal(self, auth_headers):
        resp = _decode(INPUT_LOWER, auth_headers)
        text = _output_text(resp)
        assert "This comes from an encoded PS command!" in text, (
            "Runtime Output (Simulation) missing decoded literal"
        )

    def test_mixed_case_input_does_not_crash(self, auth_headers):
        resp = _decode(INPUT_MIXED, auth_headers)
        block = _extract_ps_block(_output_text(resp))
        # When mixed-case IS present, the claim SHOULD be allowed (evidence-backed)
        # We don't assert it must be present (impl detail); we only assert no crash.
        assert block  # non-empty

    def test_canonical_verdict_invariant(self, auth_headers):
        resp = _decode(INPUT_LOWER, auth_headers)
        vc = resp.get("verdict_card")
        risk = resp.get("risk")
        assert vc is not None and risk is not None, f"missing verdict_card/risk. keys={list(resp.keys())}"
        assert vc.get("verdict") == risk.get("verdict"), f"verdict mismatch vc={vc.get('verdict')} risk={risk.get('verdict')}"
        assert vc.get("risk_score") == risk.get("score"), f"score mismatch vc={vc.get('risk_score')} risk={risk.get('score')}"


class TestDecodeAnalyzeEquivalence:
    """Rule 14: /api/analyze/async and /api/decode/smart must agree on verdict_card."""

    def test_analyze_matches_decode_verdict(self, auth_headers):
        decode_resp = _decode(INPUT_LOWER, auth_headers)
        decode_vc = decode_resp.get("verdict_card") or {}

        r = requests.post(f"{BASE_URL}/api/analyze/async", json={"input": INPUT_LOWER}, headers=auth_headers, timeout=30)
        if r.status_code == 404:
            pytest.skip("/api/analyze/async not exposed")
        assert r.status_code in (200, 202), f"analyze/async failed: {r.status_code} {r.text[:400]}"
        job = r.json()
        job_id = job.get("job_id") or job.get("id")
        assert job_id, f"no job_id in analyze/async response: {job}"

        deadline = time.time() + 60
        status = None
        result = None
        while time.time() < deadline:
            s = requests.get(f"{BASE_URL}/api/analyze/status/{job_id}", headers=auth_headers, timeout=15)
            if s.status_code != 200:
                time.sleep(1); continue
            body = s.json()
            status = body.get("status")
            if status in ("done", "completed", "finished", "success"):
                # give the writer a moment to finalize verdict_card
                time.sleep(2)
                s2 = requests.get(f"{BASE_URL}/api/analyze/status/{job_id}", headers=auth_headers, timeout=15)
                if s2.status_code == 200:
                    result = s2.json()
                else:
                    result = body
                break
            if status in ("error", "failed"):
                pytest.fail(f"analyze/async errored: {body}")
            time.sleep(1)
        assert result is not None, f"analyze/async did not complete; last status={status}"

        # find verdict_card in result
        analyze_vc = result.get("verdict_card") or (result.get("result") or {}).get("verdict_card") or {}
        if not analyze_vc:
            # analyze/async may only expose canonical `risk` (verdict projection)
            analyze_risk = result.get("risk") or {}
            decode_risk = decode_resp.get("risk") or {}
            assert analyze_risk.get("verdict") == decode_risk.get("verdict"), (
                f"Rule-14 violation: analyze risk.verdict={analyze_risk.get('verdict')} "
                f"decode risk.verdict={decode_risk.get('verdict')}"
            )
            return
        assert analyze_vc.get("verdict") == decode_vc.get("verdict"), (
            f"Rule-14 violation: analyze verdict={analyze_vc.get('verdict')} decode verdict={decode_vc.get('verdict')}"
        )
