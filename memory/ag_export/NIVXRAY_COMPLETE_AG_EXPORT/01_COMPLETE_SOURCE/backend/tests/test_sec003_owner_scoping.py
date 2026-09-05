"""Regression: SEC-003 owner-scoping on investigations & timeline.

The Feb-2026 security audit (SEC-003) flagged that ``list_all``,
``recent``, ``{iid}/timeline``, and ``DELETE {iid}`` all leaked
cross-user data. This suite proves the fix:

* User A's `/api/timeline/recent` never returns User B's events
* User A cannot read User B's `/api/investigations/{iid}/timeline` (404)
* User A cannot delete User B's investigation (404)
* Notes may only be posted on investigations the caller owns (404)
* Admin gets the SAME scoping (no blanket bypass — audit-recommended)
"""
import os
import time
import pytest
import requests

BASE_URL = ""
with open("/app/frontend/.env") as f:
    for line in f:
        if line.startswith("REACT_APP_BACKEND_URL="):
            BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
assert BASE_URL

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")


def _admin_headers():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=15)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _create_bob_and_login():
    """Create a second, non-admin user directly in Mongo and return a JWT
    for them. We can't sign up via the API (no signup endpoint), so we
    seed straight into the users collection using the same bcrypt hasher
    the backend uses. Cleanup is best-effort."""
    from pymongo import MongoClient
    import bcrypt
    c = MongoClient(os.environ.get("MONGO_URL", "mongodb://localhost:27017"))
    db = c[os.environ.get("DB_NAME", "test_database")]
    email = f"bob-sec003-{int(time.time())}@example.com"
    pw = "BobSec003Test!Password"
    db.users.replace_one(
        {"email": email},
        {
            "email": email,
            "password": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode(),
            "role": "analyst",
        },
        upsert=True,
    )
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": email, "password": pw}, timeout=15)
    assert r.status_code == 200, r.text
    return email, {"Authorization": f"Bearer {r.json()['access_token']}"}, db


@pytest.fixture(scope="module")
def bob():
    email, headers, db = _create_bob_and_login()
    yield email, headers
    # Cleanup
    db.users.delete_one({"email": email})


def test_admin_and_bob_see_only_their_own_recent_events(bob):
    """Each user's /api/timeline/recent must return only their own
    events — never the other user's."""
    admin_h = _admin_headers()
    bob_email, bob_h = bob

    # Admin records a decode event
    ra = requests.post(f"{BASE_URL}/api/timeline/events", headers=admin_h,
                       json={"kind": "decode", "title": "sec003-admin-marker",
                             "investigation_id": "sec003adminA",
                             "summary": "admin-only"},
                       timeout=15)
    assert ra.status_code == 200, ra.text
    # Bob records a different decode event
    rb = requests.post(f"{BASE_URL}/api/timeline/events", headers=bob_h,
                       json={"kind": "decode", "title": "sec003-bob-marker",
                             "investigation_id": "sec003bobB",
                             "summary": "bob-only"},
                       timeout=15)
    assert rb.status_code == 200, rb.text

    # Bob's recent feed must NOT contain admin's marker title
    r_bob = requests.get(f"{BASE_URL}/api/timeline/recent?limit=500",
                        headers=bob_h, timeout=15).json()
    titles_bob = {e.get("title") for e in r_bob["events"]}
    assert "sec003-bob-marker" in titles_bob
    assert "sec003-admin-marker" not in titles_bob, (
        f"BOB SAW ADMIN EVENTS — SEC-003 LEAK: {titles_bob}"
    )

    # Admin's recent feed must NOT contain bob's marker title
    r_adm = requests.get(f"{BASE_URL}/api/timeline/recent?limit=500",
                        headers=admin_h, timeout=15).json()
    titles_adm = {e.get("title") for e in r_adm["events"]}
    assert "sec003-admin-marker" in titles_adm
    assert "sec003-bob-marker" not in titles_adm, (
        f"ADMIN SAW BOB EVENTS — SEC-003 LEAK: {titles_adm}"
    )


def test_bob_cannot_read_admins_investigation_timeline(bob):
    """GET /api/investigations/{iid}/timeline must 404 when the caller
    doesn't own the investigation — even if the iid exists."""
    admin_h = _admin_headers()
    bob_email, bob_h = bob

    # Admin records under a specific iid Bob will try to read
    iid = f"sec003priv{int(time.time())}"[:16]
    r_a = requests.post(f"{BASE_URL}/api/timeline/events", headers=admin_h,
                       json={"kind": "decode", "title": "admin-secret",
                             "investigation_id": iid,
                             "summary": "private admin data"},
                       timeout=15)
    assert r_a.status_code == 200

    # Bob queries the same iid — must 404
    r_b = requests.get(f"{BASE_URL}/api/investigations/{iid}/timeline",
                      headers=bob_h, timeout=15)
    assert r_b.status_code == 404, f"expected 404, got {r_b.status_code}: {r_b.text}"

    # Admin can still read their own
    r_own = requests.get(f"{BASE_URL}/api/investigations/{iid}/timeline",
                        headers=admin_h, timeout=15)
    assert r_own.status_code == 200
    titles = {e["title"] for e in r_own.json()["events"]}
    assert "admin-secret" in titles


def test_bob_cannot_delete_admins_investigation(bob):
    """DELETE /api/investigations/{iid} must 404 when the caller doesn't
    own any event under that iid, AND must not remove any events."""
    admin_h = _admin_headers()
    _, bob_h = bob

    iid = f"sec003del{int(time.time())}"[:16]
    ra = requests.post(f"{BASE_URL}/api/timeline/events", headers=admin_h,
                       json={"kind": "decode", "title": "delete-me-not",
                             "investigation_id": iid,
                             "summary": "admin owns this"},
                       timeout=15)
    assert ra.status_code == 200

    # Bob tries to delete — must 404
    r_del = requests.delete(f"{BASE_URL}/api/investigations/{iid}",
                           headers=bob_h, timeout=15)
    assert r_del.status_code == 404, r_del.text

    # Confirm event still exists for admin
    r_read = requests.get(f"{BASE_URL}/api/investigations/{iid}/timeline",
                         headers=admin_h, timeout=15).json()
    assert any(e["title"] == "delete-me-not" for e in r_read["events"])


def test_bob_cannot_post_note_on_admins_investigation(bob):
    """POST /api/investigations/{iid}/note must 404 when the caller does
    not own the investigation — prevents a mischief actor from polluting
    another analyst's timeline with fake notes."""
    admin_h = _admin_headers()
    _, bob_h = bob

    iid = f"sec003nt{int(time.time())}"[:16]
    ra = requests.post(f"{BASE_URL}/api/timeline/events", headers=admin_h,
                      json={"kind": "decode", "title": "admin-analysis",
                            "investigation_id": iid, "summary": ""},
                      timeout=15)
    assert ra.status_code == 200

    r_note = requests.post(
        f"{BASE_URL}/api/investigations/{iid}/note",
        headers=bob_h,
        json={"note": "malicious injected note by bob"},
        timeout=15,
    )
    assert r_note.status_code == 404, r_note.text


def test_investigations_list_returns_only_own_investigations(bob):
    """GET /api/investigations must only return investigations the caller
    owns — no cross-tenant enumeration."""
    admin_h = _admin_headers()
    bob_email, bob_h = bob

    iid = f"sec003ls{int(time.time())}"[:16]
    ra = requests.post(f"{BASE_URL}/api/timeline/events", headers=admin_h,
                      json={"kind": "decode", "title": "admin-list-marker",
                            "investigation_id": iid, "summary": ""},
                      timeout=15)
    assert ra.status_code == 200

    r_bob = requests.get(f"{BASE_URL}/api/investigations?limit=500",
                        headers=bob_h, timeout=15).json()
    iids = {i.get("investigation_id") for i in r_bob["investigations"]}
    assert iid not in iids, (
        f"BOB LISTED ADMIN INVESTIGATION — SEC-003 LEAK. iid={iid} in {iids}"
    )
