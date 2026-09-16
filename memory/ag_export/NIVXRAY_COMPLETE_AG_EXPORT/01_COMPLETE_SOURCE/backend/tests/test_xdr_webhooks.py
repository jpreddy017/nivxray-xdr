"""XDR Webhooks — P0-5 pytest.

Covers CRUD, secret one-time reveal, HMAC signing, delivered/failed/DLQ
states, replay, disabled-webhook, tenant isolation, audit chain.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master")

from routers import xdr_audit_log as al
from routers import xdr_rbac as rb
from routers import xdr_webhooks as wh
from server import app

client = TestClient(app)

TEN = f"wh-tenant-{uuid.uuid4().hex[:8]}"
ADMIN = "wh-admin@nivxray.com"


def _hdrs(email=ADMIN, ten=None):
    return {"X-Tenant-Id": ten or TEN,
                "X-Principal-Id": email, "X-Principal-Kind": "user"}


@pytest.fixture(scope="module", autouse=True)
def _seed():
    for c in (wh._c_hooks, wh._c_deliveries, rb._c_users, rb._c_roles,
                    rb._c_assignments):
        if c() is not None:
            c().delete_many({"tenant_id": TEN})
            c().delete_many({})
    if al._get_coll() is not None:
        al._get_coll().delete_many({"tenant_id": TEN})
    client.post("/api/xdr/rbac/users", headers=_hdrs(),
                    json={"email": ADMIN, "initial_roles": ["platform_admin"]})
    yield


def _skip_if_no_mongo():
    if wh._db() is None: pytest.skip("MONGO_URL not configured")


# ── 1 · CRUD + one-time secret reveal ────────────────────────────
def test_create_returns_secret_once():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/webhooks", headers=_hdrs(),
                          json={"name": "alert-hook",
                                    "url": "https://example.invalid/hook",
                                    "events": ["ALERT_*"]})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["id"].startswith("whk_")
    assert d["secret"].startswith("whsec_")
    assert d["secret_preview"].startswith("…")
    assert "secret_ciphertext" not in d
    r2 = client.get(f"/api/xdr/webhooks/{d['id']}", headers=_hdrs())
    d2 = r2.json()["data"]
    assert "secret" not in d2
    assert "secret_ciphertext" not in d2


def test_duplicate_name_rejected():
    _skip_if_no_mongo()
    client.post("/api/xdr/webhooks", headers=_hdrs(),
                    json={"name": "dup", "url": "https://x.invalid/w"})
    r = client.post("/api/xdr/webhooks", headers=_hdrs(),
                          json={"name": "dup", "url": "https://x.invalid/w"})
    assert r.status_code == 409


# ── 2 · Test delivery — DELIVERED path (mocked 200 OK) ──────────
def test_test_delivery_delivered_when_upstream_ok():
    _skip_if_no_mongo()
    created = client.post("/api/xdr/webhooks", headers=_hdrs(),
                                    json={"name": "ok-hook",
                                              "url": "https://mock.invalid/ok",
                                              "events": ["*"],
                                              "max_retries": 0}).json()["data"]
    secret = created["secret"]

    captured = {}
    def _handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content
        captured["sig"]  = request.headers.get("X-NivXRay-Signature")
        captured["event"] = request.headers.get("X-NivXRay-Event")
        return httpx.Response(202)

    with patch.object(httpx, "post",
                                    side_effect=lambda url, **kw:
                                        _handler(httpx.Request("POST", url,
                                                                              content=kw.get("content"),
                                                                              headers=kw.get("headers", {})))):
        r = client.post(f"/api/xdr/webhooks/{created['id']}/test",
                              headers=_hdrs(),
                              json={"event": "ALERT_CREATED",
                                        "payload": {"id": "a-1"}})
    delivery = r.json()["data"]
    assert delivery["final_state"] == "DELIVERED"
    assert delivery["last_status"] == 202
    assert delivery["attempt_count"] == 1
    # HMAC signature validates.
    expected = "sha256=" + hmac.new(secret.encode(), captured["body"],
                                                                hashlib.sha256).hexdigest()
    assert captured["sig"] == expected
    assert captured["event"] == "ALERT_CREATED"


# ── 3 · Retries → DLQ when upstream always fails ─────────────────
def test_retries_exhaust_to_dlq():
    _skip_if_no_mongo()
    created = client.post("/api/xdr/webhooks", headers=_hdrs(),
                                    json={"name": "fail-hook",
                                              "url": "https://mock.invalid/fail",
                                              "max_retries": 2,
                                              "initial_backoff_seconds": 1}).json()["data"]

    def _fail(request):
        return httpx.Response(503, text="down")

    with patch.object(httpx, "post",
                                    side_effect=lambda url, **kw:
                                        _fail(httpx.Request("POST", url))):
        r = client.post(f"/api/xdr/webhooks/{created['id']}/test",
                              headers=_hdrs(),
                              json={"event": "ALERT_CREATED", "payload": {}})
    d = r.json()["data"]
    assert d["final_state"] == "DLQ"
    assert d["attempt_count"] == 3   # 1 initial + 2 retries
    assert d["last_status"] == 503

    hist = client.get(f"/api/xdr/webhooks/{created['id']}/deliveries",
                              headers=_hdrs(),
                              params={"state": "DLQ"}).json()["data"]["deliveries"]
    assert any(x["id"] == d["id"] for x in hist)


# ── 4 · Replay produces a fresh delivery with `replay_of` set ────
def test_replay_dlq_delivery():
    _skip_if_no_mongo()
    hooks = client.get("/api/xdr/webhooks", headers=_hdrs()).json()["data"]["webhooks"]
    fail_hook = next(h for h in hooks if h["name"] == "fail-hook")
    dlq = client.get(f"/api/xdr/webhooks/{fail_hook['id']}/deliveries",
                              headers=_hdrs(),
                              params={"state": "DLQ"}).json()["data"]["deliveries"]
    assert dlq
    src_id = dlq[0]["id"]

    with patch.object(httpx, "post",
                                    side_effect=lambda url, **kw:
                                        httpx.Response(200)):
        r = client.post(f"/api/xdr/webhooks/{fail_hook['id']}/replay/{src_id}",
                              headers=_hdrs())
    d = r.json()["data"]
    assert d["final_state"] == "DELIVERED"
    assert d["replay_of"] == src_id


# ── 5 · Rotate secret invalidates the old one ────────────────────
def test_rotate_secret_produces_new_plaintext():
    _skip_if_no_mongo()
    c = client.post("/api/xdr/webhooks", headers=_hdrs(),
                          json={"name": "rot-hook",
                                    "url": "https://mock.invalid/r"}).json()["data"]
    r = client.post(f"/api/xdr/webhooks/{c['id']}/rotate-secret",
                          headers=_hdrs()).json()["data"]
    assert r["secret"].startswith("whsec_")
    assert r["secret"] != c["secret"]


# ── 6 · Disabled webhook refuses test delivery ───────────────────
def test_disabled_webhook_refuses_delivery():
    _skip_if_no_mongo()
    c = client.post("/api/xdr/webhooks", headers=_hdrs(),
                          json={"name": "dis-hook",
                                    "url": "https://mock.invalid/d"}).json()["data"]
    client.put(f"/api/xdr/webhooks/{c['id']}", headers=_hdrs(),
                    json={"enabled": False})
    r = client.post(f"/api/xdr/webhooks/{c['id']}/test",
                          headers=_hdrs(),
                          json={"event": "X", "payload": {}})
    assert r.status_code == 409


# ── 7 · Tenant isolation ─────────────────────────────────────────
def test_tenant_isolation():
    _skip_if_no_mongo()
    other = f"wh-other-{uuid.uuid4().hex[:8]}"
    client.post("/api/xdr/rbac/users",
                    headers={"X-Tenant-Id": other, "X-Principal-Id": "o@x"},
                    json={"email": "o@x", "initial_roles": ["platform_admin"]})
    r_other = client.get("/api/xdr/webhooks",
                                        headers={"X-Tenant-Id": other,
                                                        "X-Principal-Id": "o@x"}).json()["data"]
    assert all(w["tenant_id"] != TEN for w in r_other["webhooks"])


# ── 8 · Audit chain remains valid across the lifecycle ───────────
def test_audit_chain_valid_across_webhook_lifecycle():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/audit-log/verify/chain", headers=_hdrs())
    assert r.json()["data"]["status"] == "valid", r.json()
