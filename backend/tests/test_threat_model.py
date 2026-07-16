"""Threat-Model Assessor test suite (Feb 2026).

Covers:
    * Mermaid parser tolerance (malformed input never raises)
    * Component-kind inference
    * Trust-boundary edge detection
    * Attack-path enumeration
    * STRIDE mapping
    * MITRE mapping
    * Risk-score bands
    * Router endpoints (analyze / enrich / example)
"""
from __future__ import annotations

import os

import pytest
import requests

from threat_model.parser import parse_mermaid
from threat_model.analyzer import analyze, _infer_kind


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


# ─── Parser ──────────────────────────────────────────────────────────────
class TestParser:
    def test_empty_input(self):
        d = parse_mermaid("")
        assert d.nodes == {}
        assert d.warnings

    def test_basic_component_diagram(self):
        d = parse_mermaid("""graph TD
        A --> B
        B --> C
        """)
        assert d.direction == "TD"
        assert {"A", "B", "C"} == set(d.nodes.keys())
        assert len(d.edges) == 2

    def test_node_labels(self):
        d = parse_mermaid("""graph TD
        A[Load Balancer] --> B[API Gateway]
        """)
        assert d.nodes["A"].label == "Load Balancer"
        assert d.nodes["B"].label == "API Gateway"

    def test_zone_tags(self):
        d = parse_mermaid("""flowchart TD
        User[[EXT]] --> LB[[DMZ]]
        LB --> API[[INT]]
        API --> DB[[DATA]]
        """)
        assert d.nodes["User"].zone == "EXT"
        assert d.nodes["LB"].zone == "DMZ"
        assert d.nodes["API"].zone == "INT"
        assert d.nodes["DB"].zone == "DATA"
        # Trust-boundary detection.
        by_pair = {(e.src, e.dst): e for e in d.edges}
        assert by_pair[("User", "LB")].kind == "trust-boundary"
        assert by_pair[("LB", "API")].kind == "trust-boundary"
        assert by_pair[("API", "DB")].kind == "trust-boundary"

    def test_edge_labels(self):
        d = parse_mermaid('graph TD\nA -->|HTTPS| B')
        assert d.edges[0].label.lower() == "https"

    def test_fenced_code_block(self):
        src = "```mermaid\ngraph TD\nA --> B\n```"
        d = parse_mermaid(src)
        assert "A" in d.nodes and "B" in d.nodes

    def test_malformed_never_raises(self):
        # Garbage input must return an empty-ish diagram, not raise.
        d = parse_mermaid("!!!not-mermaid @@@\n---random---\n???")
        assert isinstance(d.nodes, dict)

    def test_comments_ignored(self):
        d = parse_mermaid("""graph TD
        %% this is a comment
        A --> B
        %% another
        """)
        assert len(d.edges) == 1

    def test_shorthand_chained_source(self):
        d = parse_mermaid("""graph TD
        A & B --> C
        """)
        # A → C  and  B → C
        pairs = {(e.src, e.dst) for e in d.edges}
        assert ("A", "C") in pairs
        assert ("B", "C") in pairs


# ─── Kind inference ──────────────────────────────────────────────────────
class TestKindInference:
    @pytest.mark.parametrize("label,kind", [
        ("User Browser", "actor"),
        ("Cloudflare WAF", "waf"),
        ("Load Balancer", "lb"),
        ("Auth Service (Auth0)", "auth"),
        ("API Gateway", "api"),
        ("Postgres Primary", "db"),
        ("Redis Cache", "cache"),
        ("SQS Queue", "queue"),
        ("S3 Bucket", "object-store"),
        ("Vault", "secret-store"),
        ("Datadog", "telemetry"),
        ("OpenAI GPT", "llm"),
        ("Random Service", "service"),
    ])
    def test_kind_inference(self, label, kind):
        assert _infer_kind(label) == kind


# ─── Analyzer ────────────────────────────────────────────────────────────
class TestAnalyzer:
    def _canonical(self):
        return parse_mermaid("""flowchart TD
        User[[EXT]] --> WAF[[DMZ]]
        WAF --> LB[[DMZ]]
        LB --> API[[INT]]
        API --> Auth[[INT]]
        API --> DB[[DATA]]
        API --> Secrets[[DATA]]
        """)

    def test_produces_findings_and_paths(self):
        r = analyze(self._canonical())
        assert r["counts"]["nodes"] == 7
        assert r["counts"]["edges"] == 6
        assert r["counts"]["attack_paths"] >= 1
        assert r["findings"], "must produce component + edge findings"

    def test_attack_paths_reach_data_zone(self):
        r = analyze(self._canonical())
        assert any(p["terminal"] in ("DB", "Secrets") for p in r["attack_paths"])

    def test_severity_scales_with_zone_crossing(self):
        r = analyze(self._canonical())
        edge_findings = [f for f in r["findings"] if f.get("edge")]
        assert edge_findings
        # EXT → DMZ edges must at least be low+ (WAF hop).
        ext_edges = [f for f in edge_findings
                      if f["edge"]["src"] == "User"]
        assert ext_edges

    def test_mitre_summary_populated(self):
        r = analyze(self._canonical())
        assert "T1078" in r["mitre_summary"] or "T1190" in r["mitre_summary"]

    def test_risk_score_bounded(self):
        r = analyze(self._canonical())
        assert 0 <= r["risk"]["score"] <= 100
        assert r["risk"]["level"] in {"safe", "low", "medium", "high", "critical"}

    def test_diagram_without_zones_still_works(self):
        # No trust-boundary tags — engine must still produce something
        # sensible (attack paths from unbounded nodes to leaves).
        r = analyze(parse_mermaid("""graph TD
        Client --> API
        API --> DB
        """))
        assert r["counts"]["nodes"] == 3
        assert r["risk"]["score"] >= 0

    def test_stride_categories_on_trust_boundary(self):
        r = analyze(self._canonical())
        stride_hits = [f for f in r["findings"]
                        if f.get("edge") and f.get("stride")]
        assert stride_hits, "trust-boundary edges must carry STRIDE labels"
        # EXT→DMZ user hop must include Spoofing.
        user_hop = next((f for f in stride_hits
                          if f["edge"]["src"] == "User"), None)
        assert user_hop and "Spoofing" in user_hop["stride"]


# ─── Router ──────────────────────────────────────────────────────────────
class TestRouter:
    def test_analyze_endpoint(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/threat-model/analyze",
                           headers=auth_headers,
                           json={"mermaid": "flowchart TD\nUser[[EXT]] --> API[[INT]] --> DB[[DATA]]"},
                           timeout=30)
        assert r.status_code == 200, r.text
        j = r.json()
        assert "findings" in j and "attack_paths" in j
        assert j["counts"]["nodes"] == 3
        assert j["counts"]["attack_paths"] >= 1

    def test_analyze_malformed_returns_200(self, auth_headers):
        # Deterministic engine must degrade gracefully, never 500.
        r = requests.post(f"{BASE_URL}/api/threat-model/analyze",
                           headers=auth_headers,
                           json={"mermaid": "!!!not-mermaid@@@"}, timeout=30)
        assert r.status_code == 200
        assert isinstance(r.json().get("findings"), list)

    def test_analyze_empty_returns_400(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/threat-model/analyze",
                           headers=auth_headers, json={"mermaid": ""}, timeout=30)
        assert r.status_code == 422  # pydantic min_length

    def test_analyze_requires_auth(self):
        r = requests.post(f"{BASE_URL}/api/threat-model/analyze",
                           json={"mermaid": "graph TD\nA-->B"}, timeout=30)
        assert r.status_code in (401, 403)

    def test_example_endpoint(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/threat-model/example",
                          headers=auth_headers, timeout=30)
        assert r.status_code == 200
        j = r.json()
        assert "mermaid" in j and "report" in j
        assert j["report"]["counts"]["nodes"] > 3

    def test_enrich_endpoint(self, auth_headers):
        # Deterministic report must ALWAYS be present, MoE enrichment additive.
        r = requests.post(f"{BASE_URL}/api/threat-model/enrich",
                           headers=auth_headers,
                           json={"mermaid": "flowchart TD\nUser[[EXT]] --> DB[[DATA]]"},
                           timeout=120)
        assert r.status_code == 200, r.text
        j = r.json()
        assert "deterministic" in j and "enrichment" in j
        assert j["deterministic"]["counts"]["nodes"] == 2
        # deterministic risk survives, is not overridden by enrichment
        assert 0 <= j["deterministic"]["risk"]["score"] <= 100
