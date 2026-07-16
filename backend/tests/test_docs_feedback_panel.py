"""Tests for the Docs Feedback admin panel endpoints:
- GET /api/docs/explain/feedback/stats now surfaces `weakest_pages`
- GET /api/docs/explain/feedback/recent — filterable recent 👎/👍 events
"""
from __future__ import annotations
import os
import time

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


@pytest.fixture(scope="module")
def seeded_feedback(auth_headers):
    """Ensure the DB has at least one 👎 and one 👍 for stable assertions."""
    for i, (page, vote) in enumerate([
        ("investigation_timeline", "down"),
        ("investigation_timeline", "down"),
        ("investigation_timeline", "up"),
        ("auto_investigate",       "up"),
    ]):
        requests.post(f"{BASE_URL}/api/docs/explain/feedback",
                       headers=auth_headers,
                       json={"page": page,
                             "session_id": f"panel-seed-{time.time_ns()}-{i}",
                             "message_index": 0,
                             "vote": vote,
                             "provider": "static-registry",
                             "question": f"seed-q-{i}",
                             "reply_snippet": f"seed-reply-{i}"},
                       timeout=15)
    yield


class TestStatsWeakestPages:
    def test_weakest_pages_returned(self, auth_headers, seeded_feedback):
        r = requests.get(f"{BASE_URL}/api/docs/explain/feedback/stats",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert "weakest_pages" in d
        assert isinstance(d["weakest_pages"], list)
        assert len(d["weakest_pages"]) <= 10

    def test_weakest_pages_sorted_desc_by_net_negative(self, auth_headers, seeded_feedback):
        r = requests.get(f"{BASE_URL}/api/docs/explain/feedback/stats",
                         headers=auth_headers, timeout=15)
        wp = r.json()["weakest_pages"]
        scores = [p["net_negative"] for p in wp]
        assert scores == sorted(scores, reverse=True), scores

    def test_weakest_pages_shape(self, auth_headers, seeded_feedback):
        r = requests.get(f"{BASE_URL}/api/docs/explain/feedback/stats",
                         headers=auth_headers, timeout=15)
        for entry in r.json()["weakest_pages"]:
            assert set(entry.keys()) >= {"page", "up", "down", "net_negative"}


class TestRecentEndpoint:
    def test_recent_default(self, auth_headers, seeded_feedback):
        r = requests.get(f"{BASE_URL}/api/docs/explain/feedback/recent",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert "events" in d
        assert isinstance(d["events"], list)

    def test_recent_filter_by_vote(self, auth_headers, seeded_feedback):
        r = requests.get(f"{BASE_URL}/api/docs/explain/feedback/recent?vote=down&limit=50",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        for ev in r.json()["events"]:
            assert ev["vote"] == "down"

    def test_recent_filter_by_page(self, auth_headers, seeded_feedback):
        r = requests.get(f"{BASE_URL}/api/docs/explain/feedback/recent",
                         params={"page": "investigation_timeline",
                                 "vote": "down", "limit": 20},
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        for ev in r.json()["events"]:
            assert ev["page"] == "investigation_timeline"
            assert ev["vote"] == "down"

    def test_recent_invalid_vote_422(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/explain/feedback/recent?vote=maybe",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 422

    def test_recent_limit_upper_bound(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/explain/feedback/recent?limit=999",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 422

    def test_event_shape(self, auth_headers, seeded_feedback):
        r = requests.get(f"{BASE_URL}/api/docs/explain/feedback/recent?vote=down&limit=1",
                         headers=auth_headers, timeout=15)
        events = r.json()["events"]
        if events:  # only assert if we have any
            ev = events[0]
            for k in ("id", "page", "vote", "provider", "analyst_id",
                      "question", "reply_snippet", "created_at", "session_id"):
                assert k in ev, f"missing key {k}"
