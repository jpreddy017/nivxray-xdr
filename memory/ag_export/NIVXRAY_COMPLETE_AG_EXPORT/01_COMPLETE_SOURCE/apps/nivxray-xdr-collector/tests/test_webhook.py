"""Test WebhookConnector: HMAC verification, replay guard, envelopes."""
import hashlib
import hmac
import json
import time

import pytest

from framework.webhook import WebhookConnector


def _sig(secret: str, body: bytes, algo="sha256", prefix="sha256=") -> str:
    hasher = hashlib.sha256 if algo == "sha256" else hashlib.sha1
    return prefix + hmac.new(secret.encode(), body, hasher).hexdigest()


def _make(secret="s3cr3t", extra=None):
    cfg = {
        "secret_id":     "wh-abc",
        "credentials":   {"hmac_secret": secret},
        "signature":     {"header": "X-Hub-Signature-256",
                           "algo": "sha256", "prefix": "sha256="},
        "event_id_path": "id",
        "records_path":  "events",
    }
    if extra:
        cfg.update(extra)
    return WebhookConnector(tenant_id="acme", config=cfg, identity="wh-test")


def test_verify_accepts_valid_signature():
    conn = _make()
    body = json.dumps({"events": [{"id": "e1"}]}).encode()
    ok = conn.verify(body, {"X-Hub-Signature-256": _sig("s3cr3t", body)})
    assert ok["ok"] is True
    assert ok["authenticated"] is True


def test_verify_rejects_bad_signature():
    conn = _make()
    body = json.dumps({"events": []}).encode()
    out = conn.verify(body, {"X-Hub-Signature-256": "sha256=deadbeef"})
    assert out["ok"] is False
    assert out["reason"] == "signature_mismatch"


def test_verify_rejects_missing_header():
    conn = _make()
    out = conn.verify(b"{}", {})
    assert out["ok"] is False
    assert out["reason"] == "missing_signature_header"


def test_verify_no_secret_accepts_but_flags_unauthenticated():
    conn = WebhookConnector(tenant_id="acme",
                                 config={"secret_id": "wh-open"},
                                 identity="wh-open-1")
    out = conn.verify(b"{}", {})
    assert out["ok"] is True
    assert out.get("authenticated") is False


def test_verify_replay_window():
    conn = _make()
    body = b'{"events":[]}'
    old_ts = str(int(time.time()) - 10_000)  # way outside 5-min window
    out = conn.verify(body, {"X-Hub-Signature-256": _sig("s3cr3t", body),
                                 "X-Timestamp": old_ts})
    assert out["ok"] is False
    assert out["reason"] == "replay_window_exceeded"


def test_envelopes_from_records_path():
    conn = _make()
    envs = conn.envelopes_from({"events": [{"id": "e1", "ts": "2024-01-01"},
                                                 {"id": "e2"}]})
    assert len(envs) == 2
    assert envs[0].source_event_id == "e1"
    assert envs[0].collection_method == "webhook"
    assert envs[0].tenant_id == "acme"


def test_envelopes_from_single_object():
    conn = WebhookConnector(tenant_id="acme",
                                 config={"secret_id": "wh-x",
                                          "event_id_path": "uuid"},
                                 identity="wh-1")
    envs = conn.envelopes_from({"uuid": "abc", "payload": "hello"})
    assert len(envs) == 1
    assert envs[0].source_event_id == "abc"
    assert envs[0].raw["payload"] == "hello"
