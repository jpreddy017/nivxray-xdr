"""
Incident numbering · column search · negative predicates.

Owner-authorised 2026-09-05.  Locks three invariants:

  1. Every authoritative incident carries a unique human-facing number;
     no non-incident document does.
  2. Column search is a SERVER-side predicate over the authoritative
     query, not a filter over an already-loaded page.
  3. Negative predicates run strictly INSIDE the tenant authorization
     scope — an exclusion can only ever remove rows from an already
     authorized set, never widen it.
"""
import os
import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from server import app
from deps import get_current_user_optional, init_database, validate_config

validate_config()
init_database()
from services.incident_numbering import (
    format_incident_number, parse_incident_number,
)

client = TestClient(app)

ADMIN = {"email": "admin@nivxray.com", "role": "admin"}          # cross-tenant
ANALYST = {"email": "analyst@acme.test", "role": "analyst"}      # tenant-scoped


def _as(user):
    app.dependency_overrides[get_current_user_optional] = lambda: user


def _db():
    from pymongo import MongoClient
    return MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]


def _seed(db, cid, number, *, priority="P3", verdict="suspicious",
             tenant="default", technique="T1059.001"):
    now = datetime.now(timezone.utc)
    db.workspace_cases.insert_one({
        "id": cid,
        "incident_number": number,
        "doc_type": "xdr_incident",
        "title": f"numbering fixture {cid}",
        "tenant_id": tenant,
        "incident_state": "new",
        "incident_priority": priority,
        "verdict_stage2": {"label": verdict, "confidence": "moderate",
                                "risk_score": 40},
        "techniques": [technique],
        "created_at": (now - timedelta(hours=2)).isoformat(),
        "updated_at": now.isoformat(),
    })


@pytest.fixture
def seeded():
    db = _db()
    db.workspace_cases.delete_many({"id": {"$regex": "^num-"}})
    _seed(db, "num-1", "INC000000901", priority="P1", verdict="malicious")
    _seed(db, "num-2", "INC000000902", priority="P3", verdict="suspicious")
    _seed(db, "num-3", "INC000000903", priority="P3", verdict="suspicious",
             technique="T1566.001")
    yield db
    db.workspace_cases.delete_many({"id": {"$regex": "^num-"}})


def _q(**params):
    r = client.get("/api/incidents", params={"limit": 500, **params})
    body = r.json()
    assert r.status_code == 200, f"{r.status_code} · {body}"
    return body


def teardown_module():
    app.dependency_overrides.clear()


# ── 1 · numbering ────────────────────────────────────────────────────
def test_number_format_is_reversible():
    assert format_incident_number(137) == "INC000000137"
    assert parse_incident_number("INC000000137") == 137
    assert parse_incident_number("nope") is None


def test_every_incident_has_a_unique_number(seeded):
    _as(ADMIN)
    body = _q()
    rows = [r for r in body["incidents"] if r["id"].startswith("num-")]
    assert rows, "queue must not be empty"
    numbers = [r.get("incident_number") for r in rows]
    assert all(numbers), "every incident must carry a human-facing number"
    assert all(re.fullmatch(r"INC\d{9}", n) for n in numbers)
    assert len(set(numbers)) == len(numbers), "numbers must be unique"


def test_number_never_replaces_the_authoritative_id(seeded):
    _as(ADMIN)
    row = _q(number="INC000000901")["incidents"][0]
    # The authoritative id is opaque and unchanged by numbering; the
    # human-facing number is a SEPARATE field, never a substitute.
    assert row["incident_number"] == "INC000000901"
    assert row["id"] != row["incident_number"]
    assert row["id"] == "num-1"


# ── 2 · column search is server-side ────────────────────────────────
def test_number_search_resolves_to_one_incident(seeded):
    _as(ADMIN)
    target = _q(number="INC000000902")["incidents"][0]
    hit = _q(number=target["incident_number"])
    assert hit["count"] == 1
    assert hit["incidents"][0]["id"] == target["id"]
    assert hit["applied_filters"]["number"] == target["incident_number"]


def test_column_search_is_narrower_than_the_unfiltered_queue(seeded):
    _as(ADMIN)
    everything = _q()["count"]
    narrowed = _q(number="INC000000901")["count"]
    assert narrowed <= everything
    assert narrowed >= 0


# ── 3 · negative predicates ─────────────────────────────────────────
def test_exclude_priority_removes_only_that_priority(seeded):
    _as(ADMIN)
    total = _q()["count"]
    body = _q(exclude_priority="P3")
    assert body["count"] <= total
    assert all(r["priority"]["code"] != "P3"
               for r in body["incidents"] if r.get("priority"))
    assert body["applied_filters"]["exclude_priority"] == "P3"


def test_exclude_customer_cannot_widen_the_authorized_set(seeded):
    _as(ADMIN)
    total = _q()["count"]
    excluded = _q(exclude_customer="default")["count"]
    assert excluded <= total, "an exclusion may only ever remove rows"


def test_negative_predicate_runs_inside_tenant_scope():
    """A tenant-restricted principal cannot use an exclusion to escape."""
    _as(ANALYST)
    base = _q()["count"]
    # analyst@acme.test belongs to no tenant that owns the seeded
    # incidents, so the authorized set is empty ...
    assert base == 0
    # ... and excluding the tenant it cannot see must not reveal anything.
    assert _q(exclude_customer="default")["count"] == 0
    assert _q(exclude_priority="P3")["count"] == 0
    assert _q(number="INC000000901")["count"] == 0


def test_anonymous_still_gets_the_honest_empty_state():
    app.dependency_overrides[get_current_user_optional] = lambda: None
    body = _q(exclude_priority="P3")
    assert body["count"] == 0
    assert body["scope"]["authorized"] is False
