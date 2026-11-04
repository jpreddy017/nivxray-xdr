"""G1-R5 evidence recovery · exact-50 in-flight reconciliation."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sqlite3
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOL = os.path.join(_HERE, os.pardir, "scripts",
                     "g1_r5_inflight50_reconcile.py")
_spec = importlib.util.spec_from_file_location("g1_r5_inflight50", _TOOL)
tool = importlib.util.module_from_spec(_spec)
sys.modules["g1_r5_inflight50"] = tool
_spec.loader.exec_module(tool)

COLLECTOR = "col-test-1"
TENANT = "tenant-a"


def _make_db(tmp_path, delivering=50, queued=7):
    path = os.path.join(tmp_path, "outbox.db")
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE envelopes (id TEXT PRIMARY KEY, tenant_id TEXT, "
        "connector_id TEXT, source TEXT, source_event_id TEXT, "
        "raw_json TEXT, status TEXT, attempts INTEGER, "
        "next_attempt_at TEXT, last_error TEXT, updated_at TEXT)")
    conn.execute("CREATE TABLE windows_channel_state (channel TEXT, "
                 "bookmark TEXT)")
    conn.execute("INSERT INTO windows_channel_state VALUES ('Security', 'bm')")
    refs = []
    for index in range(delivering):
        ref = f"env-{index:04d}"
        refs.append(ref)
        conn.execute(
            "INSERT INTO envelopes VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (ref, TENANT, "conn-1", "windows_security", f"sei-{index}",
             json.dumps({"EventID": 4624, "i": index}), "delivering", 1,
             None, None, "2026-06-24T06:00:00+00:00"))
    for index in range(queued):
        conn.execute(
            "INSERT INTO envelopes VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (f"q-{index:04d}", TENANT, "conn-1", "windows_security",
             f"q-sei-{index}", json.dumps({"EventID": 4688, "i": index}),
             "queued", 0, None, None, "2026-06-24T06:00:00+00:00"))
    conn.commit()
    conn.close()
    return path, refs


def _responder(refs, canonical=22, retryable=28, *, seen=None):
    def respond(identities):
        if seen is not None:
            seen.append(identities)
        rows = []
        for position, identity in enumerate(identities):
            bucket = (tool.CANONICAL if position < canonical
                      else tool.RETRYABLE)
            rows.append({
                "ref": identity["ref"],
                "delivery_key": identity["delivery_key"],
                "bucket": bucket,
                "disposition": ("CANONICAL_EVIDENCE_PRESENT"
                                if bucket == tool.CANONICAL else "NOT_FOUND"),
                "evidence_ref": (f"xdr_canonical_events/{identity['ref']}"
                                 if bucket == tool.CANONICAL else None),
                "claim": ({"status": "delivered",
                           "canonical_event_id": f"ce-{identity['ref']}"}
                          if bucket == tool.CANONICAL else None),
            })
        buckets = {tool.CANONICAL: canonical, tool.RETRYABLE: retryable,
                   tool.RETAINED: 0, tool.TERMINAL: 0, tool.UNEXPLAINED: 0}
        return {"attempted": len(identities), "accounted": len(identities),
                "buckets": buckets, "rows": rows,
                "tenant_scope": {"basis": "TEST"}}
    return respond


def _run(tmp_path, refs, **kwargs):
    defaults = dict(state_dir=str(tmp_path), refs=refs,
                    base_url="http://unused", token="tok",
                    collector_id=COLLECTOR,
                    expect_histogram={"delivering": 50, "queued": 7},
                    expect_total=57)
    defaults.update(kwargs)
    return tool.run(**defaults)


def test_pass_recovers_the_22_28_split_and_mutates_nothing(tmp_path):
    _, refs = _make_db(str(tmp_path))
    sent = []
    report = _run(tmp_path, refs,
                  transport=_responder(refs, seen=sent))

    assert report["pass"] is True
    assert report["identities_requested"] == 50
    assert report["reconciliation_requests_issued"] == 1
    assert report["negative_control_issued"] is False
    assert len(sent) == 1, "exactly one reconciliation request"
    assert len(sent[0]) == 50
    assert len(report["canonical_refs"]) == 22
    assert len(report["retryable_refs"]) == 28
    assert not set(report["canonical_refs"]) & set(report["retryable_refs"])
    assert set(report["canonical_refs"]) | set(report["retryable_refs"]) \
        == set(refs)
    for name in ("database_file_unchanged", "status_histogram_unchanged",
                 "total_rows_unchanged", "bookmarks_unchanged",
                 "delivering_set_unchanged", "no_delivery_surface_loaded",
                 "refs_one_to_one", "canonical_exactly", "retryable_exactly",
                 "retained_raw_zero", "terminal_zero", "unexplained_zero"):
        assert report["checks"][name]["holds"] is True, name


def test_wrong_input_count_refuses_before_any_request(tmp_path):
    _, refs = _make_db(str(tmp_path))
    sent = []
    with pytest.raises(tool.PreRequestRefusal) as ex:
        _run(tmp_path, refs[:49], transport=_responder(refs, seen=sent))
    assert "expected exactly 50" in str(ex.value)
    assert sent == [], "no request may be issued"


def test_local_delivering_set_mismatch_refuses(tmp_path):
    _, refs = _make_db(str(tmp_path))
    sent = []
    swapped = refs[:-1] + ["q-0000"]
    with pytest.raises(tool.PreRequestRefusal):
        _run(tmp_path, swapped, transport=_responder(refs, seen=sent))
    assert sent == []


def test_histogram_drift_refuses(tmp_path):
    _, refs = _make_db(str(tmp_path))
    sent = []
    with pytest.raises(tool.PreRequestRefusal) as ex:
        _run(tmp_path, refs, expect_histogram={"delivering": 50, "queued": 9},
             transport=_responder(refs, seen=sent))
    assert "histogram drift" in str(ex.value)
    assert sent == []


def test_unexpected_split_fails_with_untrusted_response(tmp_path):
    _, refs = _make_db(str(tmp_path))
    with pytest.raises(tool.PostResponseFailure) as ex:
        _run(tmp_path, refs,
             transport=_responder(refs, canonical=21, retryable=29))
    assert "canonical_exactly" in ex.value.reasons
    assert ex.value.report["pass"] is False
    assert ex.value.response["rows"], "the raw response is kept for forensics"


def test_foreign_ref_in_response_fails(tmp_path):
    _, refs = _make_db(str(tmp_path))

    def respond(identities):
        base = _responder(refs)(identities)
        base["rows"][0]["ref"] = "not-one-of-ours"
        return base

    with pytest.raises(tool.PostResponseFailure) as ex:
        _run(tmp_path, refs, transport=respond)
    assert "refs_one_to_one" in ex.value.reasons


def test_authoritative_file_only_written_on_pass(tmp_path, monkeypatch):
    _, refs = _make_db(str(tmp_path))
    ids_path = os.path.join(str(tmp_path), "inflight.json")
    with open(ids_path, "w", encoding="utf-8") as fh:
        json.dump({"identities": [{"ref": r} for r in refs]}, fh)
    out = os.path.join(str(tmp_path), "authority.json")

    monkeypatch.setenv("NIVX_COLLECTOR_ID", COLLECTOR)
    monkeypatch.setenv("NIVX_RECONCILE_TOKEN", "tok")
    monkeypatch.setattr(tool, "post_reconcile",
                        lambda *a, **k: _responder(refs)(a[2]))

    argv = ["--state-dir", str(tmp_path), "--identities", ids_path,
            "--out", out, "--base-url", "http://unused",
            "--expect-total", "57",
            "--expect-histogram", "delivering=50,queued=7"]
    assert tool.main(argv) == 0
    with open(out, encoding="utf-8") as fh:
        written = json.load(fh)
    assert written["pass"] is True
    assert len(written["canonical_refs"]) == 22
    assert len(written["rows"]) == 50
    assert not os.path.exists(out + tool.FAILED_SUFFIX)

    # a second run refuses to overwrite existing authoritative evidence
    assert tool.main(argv) == 2


def test_failed_run_writes_untrusted_file_only(tmp_path, monkeypatch):
    _, refs = _make_db(str(tmp_path))
    ids_path = os.path.join(str(tmp_path), "inflight.json")
    with open(ids_path, "w", encoding="utf-8") as fh:
        json.dump([{"ref": r} for r in refs], fh)
    out = os.path.join(str(tmp_path), "authority.json")

    monkeypatch.setenv("NIVX_COLLECTOR_ID", COLLECTOR)
    monkeypatch.setenv("NIVX_RECONCILE_TOKEN", "tok")
    monkeypatch.setattr(
        tool, "post_reconcile",
        lambda *a, **k: _responder(refs, canonical=23, retryable=27)(a[2]))

    assert tool.main([
        "--state-dir", str(tmp_path), "--identities", ids_path,
        "--out", out, "--base-url", "http://unused",
        "--expect-total", "57",
        "--expect-histogram", "delivering=50,queued=7"]) == 2
    assert not os.path.exists(out), "no authoritative evidence on failure"
    with open(out + tool.FAILED_SUFFIX, encoding="utf-8") as fh:
        doc = json.load(fh)
    assert "NOT AUTHORITY FOR R6" in doc["VERDICT"]
    assert "canonical_exactly" in doc["failed_checks"]
    assert len(doc["raw_server_response"]["rows"]) == 50


def test_no_delivery_or_acquisition_surface_is_imported():
    assert tool._own_delivery_imports() == []
    with open(_TOOL, encoding="utf-8") as fh:
        source = fh.read()
    # executable surface only: the module docstring and comments explain what
    # is deliberately NOT used, so they must not fail the check.
    code = "\n".join(line for line in source.split('"""', 2)[-1].splitlines()
                     if not line.strip().startswith("#"))
    for forbidden in ("EvtSubscribe", "UPDATE envelopes", "INSERT INTO",
                      "DELETE FROM", "Outbox(", "DeliveryWorker("):
        assert forbidden not in code, forbidden


def test_identity_matches_the_drain_derivation(tmp_path):
    raw = {"EventID": 4624, "i": 3}
    assert tool.delivery_key(
        tenant_id=TENANT, collector_id=COLLECTOR, source="windows_security",
        source_event_id="sei-3", raw=raw) == tool.delivery_key(
        tenant_id=TENANT, collector_id=COLLECTOR, source="windows_security",
        source_event_id="sei-3", raw=raw)
    assert tool.payload_digest(raw) != tool.payload_digest({"EventID": 4624})


def _captured_request(monkeypatch, status=200, body=b'{"rows":[]}'):
    """Capture the urllib Request the tool builds, without opening a socket."""
    captured = {}

    class _Resp:
        def read(self):
            return body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(request, timeout=None):
        captured["request"] = request
        captured["timeout"] = timeout
        if status >= 400:
            import urllib.error
            raise urllib.error.HTTPError(
                request.full_url, status, "refused", {}, io.BytesIO(body))
        return _Resp()

    monkeypatch.setattr(tool.urllib.request, "urlopen", fake_urlopen)
    return captured


def test_request_carries_an_explicit_non_urllib_user_agent(monkeypatch):
    captured = _captured_request(monkeypatch)
    tool.post_reconcile("https://host.example/", "tok-secret",
                        [{"ref": "env-0000"}], 120)
    request = captured["request"]

    # the edge bans the default Python-urllib signature; ours must not match it
    sent_ua = request.get_header("User-agent")
    assert sent_ua == tool.USER_AGENT
    assert "urllib" not in sent_ua.lower()
    assert "NivXForge" in sent_ua

    # nothing else about the request changed
    assert request.full_url == "https://host.example" + tool.RECONCILE_PATH
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer tok-secret"
    assert request.get_header("Content-type") == "application/json"
    assert json.loads(request.data)["identities"] == [{"ref": "env-0000"}]
    assert captured["timeout"] == 120


def test_edge_ban_is_reported_as_an_edge_block_not_an_authz_failure(
        monkeypatch):
    _captured_request(monkeypatch, status=403, body=b"error code: 1010\n")
    with pytest.raises(tool.PreRequestRefusal) as ex:
        tool.post_reconcile("https://host.example", "tok", [{"ref": "a"}], 30)
    message = str(ex.value)
    assert "SECURITY EDGE" in message
    assert "never reached the backend" in message
    assert "NOT an application authorization failure" in message
    assert "No evidence was written" in message


def test_application_403_is_still_reported_verbatim(monkeypatch):
    _captured_request(monkeypatch, status=403,
                      body=b'{"detail":"Not authorized"}')
    with pytest.raises(tool.PreRequestRefusal) as ex:
        tool.post_reconcile("https://host.example", "tok", [{"ref": "a"}], 30)
    assert "SECURITY EDGE" not in str(ex.value)
    assert "Not authorized" in str(ex.value)
