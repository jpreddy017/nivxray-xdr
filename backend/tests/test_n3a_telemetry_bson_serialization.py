"""N-3A · `GET /api/telemetry/frontend/recent` survives real BSON.

The N-3 investigation reproduced an unauthenticated HTTP 500 on this endpoint:
a single stored document carrying a nested `ObjectId` or a `Decimal128` turned
a 200 into a 500, and removing the document restored the 200. The handler
returned raw Mongo documents to FastAPI's serializer, normalising only the
top-level `_id` and `recorded_at`.

These tests are that reproduction, inverted: each one inserts the document
that used to be fatal and asserts a valid JSON 200 whose values are the
documented conversion of the stored value — not merely "no 500", which a
`try/except` returning an empty list would also satisfy.

Scope is this endpoint only. The other two N-3 endpoints are untouched, and
so is every authentication and tenant control: this route takes no credential
today and this suite does not change that — it asserts serialization, not
authorization. Whether the route should be open at all is N-2.
"""
from __future__ import annotations

import base64
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("NIVX_L3_DISABLE", "1")
from fastapi.testclient import TestClient

from bson import Binary, Code, Decimal128, MinKey, ObjectId, Regex
from bson.timestamp import Timestamp

import deps
from routers.telemetry import _json_safe
from server import app

PATH = "/api/telemetry/frontend/recent"

client = TestClient(app)


def _coll():
    return deps.sync_collection("frontend_telemetry")


@pytest.fixture(scope="module", autouse=True)
def _module_client():
    """One lifespan-managed client, and the collection left as we found it.

    `frontend_telemetry` is a bounded rolling diagnostic window, but it is not
    this suite's to discard: the existing rows are snapshotted and reinserted
    on teardown so running the suite against a populated database destroys
    nothing.
    """
    global client
    with TestClient(app) as c:
        client = c
        saved = list(_coll().find({}))
        _coll().delete_many({})
        try:
            yield
        finally:
            _coll().delete_many({})
            if saved:
                _coll().insert_many(saved)


@pytest.fixture(autouse=True)
def _blank_collection():
    _coll().delete_many({})
    yield
    _coll().delete_many({})


def _insert(**fields) -> dict:
    """Store one telemetry record, returning the document as written."""
    doc = {"session_id": "ses_n3a", "recorded_at": datetime.now(timezone.utc)}
    doc.update(fields)
    _coll().insert_one(doc)
    return doc


def _records() -> list[dict]:
    r = client.get(PATH)
    assert r.status_code == 200, f"{r.status_code}: {r.text[:300]}"
    body = r.json()                       # must be parseable JSON, not a 500
    assert set(body) == {"count", "records"}
    assert body["count"] == len(body["records"])
    return body["records"]


# ── the previously fatal documents ───────────────────────────────────
def test_nested_objectid_no_longer_returns_500():
    oid = ObjectId()
    _insert(case_ref={"oid": oid}, trail=[{"oid": oid}])
    rec = _records()[0]
    assert rec["case_ref"]["oid"] == str(oid)
    assert rec["trail"][0]["oid"] == str(oid)
    assert len(str(oid)) == 24


def test_decimal128_is_exact_and_never_a_lossy_float():
    exact = "0.1000000000000000000000000001"      # unrepresentable as float
    _insert(total_ms=Decimal128(exact))
    value = _records()[0]["total_ms"]
    assert value == exact
    assert isinstance(value, str)                  # not float(exact)


def test_invalid_utf8_binary_is_base64_not_a_decode_attempt():
    raw = b"\xde\xad\xbe\xef"                      # 0xbe is not valid UTF-8
    _insert(blob=Binary(raw))
    value = _records()[0]["blob"]
    assert value == base64.b64encode(raw).decode("ascii") == "3q2+7w=="
    assert base64.b64decode(value) == raw          # lossless


def test_utf8_decodable_binary_is_also_base64_not_text():
    raw = b"abc"
    _insert(blob=Binary(raw))
    # Previously the serializer rendered this as "abc" by guessing UTF-8.
    # Binary is not text; one rule for all bytes keeps the output predictable.
    assert _records()[0]["blob"] == base64.b64encode(raw).decode("ascii")


# ── the behaviour that must not change ───────────────────────────────
def test_ordinary_record_is_unchanged():
    now = datetime.now(timezone.utc)
    _coll().insert_one({"session_id": "ses_plain", "backend_ms": 3107.82,
                        "renders": 3, "notes": "", "recorded_at": now})
    rec = _records()[0]
    assert rec["session_id"] == "ses_plain"
    assert rec["backend_ms"] == 3107.82 and isinstance(rec["backend_ms"], float)
    assert rec["renders"] == 3 and isinstance(rec["renders"], int)
    assert rec["notes"] == ""
    # Compared against the value as Mongo returns it, not against `now`:
    # BSON datetimes come back millisecond-truncated and naive.
    stored = _coll().find_one({"session_id": "ses_plain"})["recorded_at"]
    assert rec["recorded_at"] == stored.isoformat()


def test_json_native_values_keep_their_types():
    _insert(flag=True, missing=None, count=0, ratio=0.5, label="x")
    rec = _records()[0]
    assert rec["flag"] is True
    assert rec["missing"] is None
    assert rec["count"] == 0 and isinstance(rec["count"], int)
    assert rec["ratio"] == 0.5 and isinstance(rec["ratio"], float)
    assert rec["label"] == "x"


def test_nested_dicts_and_arrays_are_walked_and_order_preserved():
    oid = ObjectId()
    _insert(stages=[{"name": "layout", "ms": 212},
                    {"name": "paint", "ms": 41, "ref": oid}],
            nested={"a": {"b": {"c": [1, 2, {"d": oid}]}}})
    rec = _records()[0]
    assert [s["name"] for s in rec["stages"]] == ["layout", "paint"]
    assert rec["stages"][1]["ref"] == str(oid)
    assert rec["nested"]["a"]["b"]["c"][:2] == [1, 2]
    assert rec["nested"]["a"]["b"]["c"][2]["d"] == str(oid)


def test_no_field_is_added_dropped_or_renamed():
    doc = _insert(case_ref={"oid": ObjectId()}, blob=Binary(b"\xff\xfe"),
                  total_ms=Decimal128("1.5"))
    rec = _records()[0]
    # `_id` is the stored key, returned as a string exactly as before. No new
    # key appears, and nothing the document carried disappears.
    assert set(rec) == set(doc) | {"_id"}
    assert rec["_id"] == str(doc["_id"])
    assert all(k in rec for k in doc)


def test_response_is_deterministic():
    _insert(case_ref={"oid": ObjectId()}, total_ms=Decimal128("2.25"),
            blob=Binary(b"\x00\xff"))
    first, second = client.get(PATH), client.get(PATH)
    assert first.status_code == second.status_code == 200
    assert first.text == second.text                 # byte-identical


def test_limit_and_ordering_are_unchanged():
    base = datetime.now(timezone.utc)
    for i in range(4):
        _coll().insert_one({"session_id": f"ses_{i}", "ref": ObjectId(),
                            "recorded_at": base - timedelta(minutes=i)})
    r = client.get(PATH, params={"limit": 2})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2                        # limit honoured
    assert [x["session_id"] for x in body["records"]] == ["ses_0", "ses_1"]


def test_empty_collection():
    assert _coll().count_documents({}) == 0
    r = client.get(PATH)
    assert r.status_code == 200
    assert r.json() == {"count": 0, "records": []}


# ── the helper itself, for types no fixture can conveniently store ───
def test_unanticipated_bson_types_degrade_to_strings_not_500s():
    for value in (Regex("^x"), Code("function(){}"), Timestamp(1, 1), MinKey()):
        assert isinstance(_json_safe({"v": value})["v"], str)


def test_uuid_and_bare_bytes():
    u = uuid.uuid4()
    assert _json_safe(u) == str(u)
    assert _json_safe(b"\x01\x02") == base64.b64encode(b"\x01\x02").decode()


def test_helper_suppresses_nothing():
    """A value that cannot be converted must raise, not vanish."""

    class Explodes:
        def __str__(self):
            raise RuntimeError("deliberate")

    with pytest.raises(RuntimeError):
        _json_safe({"v": Explodes()})
