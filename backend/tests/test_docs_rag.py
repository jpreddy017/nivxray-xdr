"""Tests for Feb-2026 Phase-3 · Docs RAG (BM25 cross-feature retrieval)."""
from __future__ import annotations
import os

import pytest
import requests


BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or "http://localhost:8001"
if BASE_URL == "http://localhost:8001":
    try:
        with open("/app/frontend/.env") as f:
            for line in f:
                if line.startswith("REACT_APP_BACKEND_URL="):
                    BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
    except Exception:
        pass

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def auth_headers():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=30)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


class TestRagIndexUnit:
    """Direct unit tests on the pure Python retriever."""

    def test_build_and_stats(self):
        from docs import rag_index
        rag_index.build_index()
        s = rag_index.index_stats()
        assert s["ready"] is True
        assert s["documents"] >= 10
        assert s["features"] >= 10
        assert s["workflows"] >= 3

    def test_retrieve_finds_expected_top_hits(self):
        from docs import rag_index
        hits = rag_index.retrieve("STIX TAXII bundle", k=3)
        ids = [h["id"] for h in hits]
        assert "taxii_push" in ids
        assert hits[0]["score"] > hits[-1]["score"]  # sorted DESC

    def test_retrieve_excludes_ids(self):
        from docs import rag_index
        hits = rag_index.retrieve("candidate decoder encoding", k=3,
                                  exclude_ids=["candidate_explorer"])
        ids = [h["id"] for h in hits]
        assert "candidate_explorer" not in ids
        assert len(ids) >= 1

    def test_retrieve_empty_query_returns_empty(self):
        from docs import rag_index
        assert rag_index.retrieve("", k=3) == []
        assert rag_index.retrieve("   ", k=3) == []

    def test_snippet_is_short_and_centred(self):
        from docs import rag_index
        hits = rag_index.retrieve("VirusTotal enrichment", k=1)
        assert hits
        # Snippet should not be the full document
        assert 0 < len(hits[0]["snippet"]) <= 220


class TestRagEndpoints:
    def test_stats_endpoint(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/rag/stats",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        s = r.json()
        assert s["ready"] is True
        assert s["documents"] >= 10

    def test_related_by_query(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/related?q=STIX+TAXII&k=3",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        ids = [h["id"] for h in d["hits"]]
        assert "taxii_push" in ids
        assert d["query"]

    def test_related_by_page_excludes_self(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/related?page=candidate_explorer&k=3",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        ids = [h["id"] for h in r.json()["hits"]]
        assert "candidate_explorer" not in ids
        assert len(ids) >= 1

    def test_related_k_param_bounds(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/related?q=powershell&k=5",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        assert len(r.json()["hits"]) <= 5

    def test_related_k_out_of_bounds_422(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/related?q=powershell&k=99",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 422

    def test_reindex_endpoint(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/rag/reindex",
                          headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "invalidated"
        assert d["stats"]["ready"] is True


class TestExplainRagIntegration:
    def test_explain_returns_related_pages(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                          headers=auth_headers,
                          json={"page": "candidate_explorer"}, timeout=45)
        assert r.status_code == 200
        d = r.json()
        assert "related_pages" in d
        assert isinstance(d["related_pages"], list)
        # Should have at least one cross-feature hit for a well-connected page
        assert len(d["related_pages"]) >= 1
        # Must exclude the current page
        assert all(rp["id"] != "candidate_explorer" for rp in d["related_pages"])
        # Each entry has the promised shape
        for rp in d["related_pages"]:
            assert set(rp.keys()) >= {"id", "kind", "title", "score"}
            assert rp["kind"] in {"feature", "workflow"}

    def test_explain_with_question_uses_question_for_retrieval(self, auth_headers):
        # Ask about STIX from a totally unrelated page → related_pages should
        # still surface taxii_push because the RAG query uses the analyst's
        # question when present.
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                          headers=auth_headers,
                          json={"page": "rot13",
                                "question": "How do I push STIX bundles?"},
                          timeout=45)
        assert r.status_code == 200
        ids = [rp["id"] for rp in r.json()["related_pages"]]
        assert "taxii_push" in ids

    def test_static_fallback_appends_related_hint(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                          headers=auth_headers,
                          json={"page": "threat_intel_enrichment"}, timeout=45)
        assert r.status_code == 200
        d = r.json()
        if d["provider"] == "static-registry" and d["related_pages"]:
            # Static branch appends a "Related pages" tail
            assert "Related pages" in d["explanation"]
