"""Test WebhookConnector: timestamp-bound HMAC, replay guard, envelopes."""
import hashlib
import hmac
import json
import time

from framework.webhook import REPLAY_WINDOW_SECONDS, WebhookConnector


def _sig(secret: str, body: bytes, ts: str, algo="sha256", prefix="sha256=") -> str:
    hasher = hashlib.sha256 if algo == "sha256" else hashlib.sha1
    signed = ts.encode() + b"." + body
    return prefix + hmac.new(secret.encode(), signed, hasher).hexdigest()


def _make(secret="s3cr3t", extra=None):
    cfg = {
        "secret_id": "wh-abc",
        "credentials": {"hmac_secret": secret},
        "signature": {"header": "X-Hub-Signature-256",
                      "algo": "sha256", "prefix": "sha256="},
        "event_id_path": "id",
        "records_path": "events",
    }
    if extra:
        cfg.update(extra)
    return WebhookConnector(tenant_id="acme", config=cfg, identity="wh-test")


def _headers(secret: str, body: bytes, ts: str | None = None):
    ts = ts or str(time.time())
    return {"X-Timestamp": ts, "X-Hub-Signature-256": _sig(secret, body, ts)}


def test_verify_accepts_valid_signature_with_fresh_timestamp():
    conn = _make()
    body = json.dumps({"events": [{"id": "e1"}]}).encode()
    ok = conn.verify(body, _headers("s3cr3t", body))
    assert ok["ok"] is True
    assert ok["authenticated"] is True
    assert ok["replay_window_seconds"] == REPLAY_WINDOW_SECONDS


def test_verify_rejects_bad_signature():
    conn = _make()
    body = b'{"events":[]}'
    out = conn.verify(body, {"X-Timestamp": str(time.time()),
                             "X-Hub-Signature-256": "sha256=deadbeef"})
    assert out["ok"] is False
    assert out["reason"] == "signature_mismatch"


def test_verify_rejects_missing_signature():
    assert _make().verify(b"{}", {"X-Timestamp": str(time.time())})["reason"] == "missing_signature_header"


def test_verify_rejects_missing_timestamp():
    body = b"{}"
    out = _make().verify(body, {"X-Hub-Signature-256": "sha256=deadbeef"})
    assert out["reason"] == "missing_timestamp_header"


def test_verify_no_secret_fails_closed_in_production(monkeypatch):
    conn = WebhookConnector("acme", {"secret_id": "wh-open"}, "wh-open-1")
    monkeypatch.setenv("XDR_COLLECTOR_ENV", "production")
    monkeypatch.delenv("XDR_WEBHOOK_ALLOW_UNSIGNED_DEV", raising=False)
    assert conn.verify(b"{}", {})["reason"] == "hmac_secret_not_configured"


def test_verify_no_secret_requires_explicit_dev_bypass(monkeypatch):
    conn = WebhookConnector("acme", {"secret_id": "wh-open"}, "wh-open-1")
    monkeypatch.setenv("XDR_COLLECTOR_ENV", "test")
    monkeypatch.setenv("XDR_WEBHOOK_ALLOW_UNSIGNED_DEV", "1")
    out = conn.verify(b"{}", {})
    assert out["ok"] is True
    assert out["reason"] == "explicit_unsigned_dev_bypass"


def test_verify_rejects_expired_timestamp():
    conn, body = _make(), b'{"events":[]}'
    ts = str(time.time() - REPLAY_WINDOW_SECONDS - 1)
    out = conn.verify(body, _headers("s3cr3t", body, ts))
    assert out["reason"] == "expired_timestamp"


def test_verify_rejects_future_timestamp():
    conn, body = _make(), b'{"events":[]}'
    ts = str(time.time() + REPLAY_WINDOW_SECONDS + 1)
    out = conn.verify(body, _headers("s3cr3t", body, ts))
    assert out["reason"] == "future_timestamp"


def test_verify_rejects_tampered_body():
    conn = _make()
    original, tampered, ts = b'{"id":"a"}', b'{"id":"b"}', str(time.time())
    headers = {"X-Timestamp": ts,
               "X-Hub-Signature-256": _sig("s3cr3t", original, ts)}
    assert conn.verify(tampered, headers)["reason"] == "signature_mismatch"


def test_verify_rejects_identical_authenticated_replay():
    conn, body, ts = _make(), b'{"events":[]}', str(time.time())
    headers = _headers("s3cr3t", body, ts)
    assert conn.verify(body, headers)["ok"] is True
    assert conn.verify(body, headers)["reason"] == "replayed_request"


def test_envelopes_from_records_path():
    conn = _make()
    envs = conn.envelopes_from({"events": [{"id": "e1", "ts": "2024-01-01"},
                                           {"id": "e2"}]})
    assert len(envs) == 2
    assert envs[0].source_event_id == "e1"
    assert envs[0].collection_method == "webhook"
    assert envs[0].tenant_id == "acme"


def test_envelopes_from_single_object():
    conn = WebhookConnector("acme", {"secret_id": "wh-x",
                                     "event_id_path": "uuid"}, "wh-1")
    envs = conn.envelopes_from({"uuid": "abc", "payload": "hello"})
    assert len(envs) == 1
    assert envs[0].source_event_id == "abc"
    assert envs[0].raw["payload"] == "hello"
