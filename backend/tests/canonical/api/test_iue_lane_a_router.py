"""Backend contract test for the Lane-A analyze router.

Exercises POST /api/iue/lane-a/analyze end-to-end with a small NDJSON
payload and asserts:
  - Flag OFF → 503 `iue_structured_lane_disabled`
  - Flag ON  → wire-shape identical to the T2 golden contract
"""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


NDJSON = (
    b'{"event_time":"2026-02-14T12:00:00.010Z","host":"srv-01","user":"jsmith",'
    b'"action":"exec","category":"process","CommandLine":"powershell -enc AAA",'
    b'"src_ip":"10.0.0.1","dst_ip":"185.220.101.7"}\n'
    b'{"event_time":"2026-02-14T12:00:00.240Z","host":"srv-01","user":"jsmith",'
    b'"action":"exec","category":"process","CommandLine":"powershell -enc AAA",'
    b'"src_ip":"10.0.0.1","dst_ip":"185.220.101.7"}\n'
    b'{"event_time":"2026-02-14T12:00:07.500Z","host":"srv-02","user":"rjones",'
    b'"action":"network_connect","category":"network",'
    b'"src_ip":"10.0.0.2","dst_ip":"198.51.100.20","dst_port":"443"}\n'
)


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from server import app
    return TestClient(app)


def test_status_endpoint_returns_flag_state(client):
    r = client.get("/api/iue/lane-a/status")
    assert r.status_code == 200
    body = r.json()
    assert "enabled" in body
    assert "flag" in body
    assert "caps" in body
    assert "max_raw_bytes" in body["caps"]


def test_analyze_returns_503_when_flag_off(client, monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "off")
    files = {"file": ("in.ndjson", io.BytesIO(NDJSON),
                        "application/x-ndjson")}
    r = client.post("/api/iue/lane-a/analyze",
                      files=files, data={"parser": "ndjson"})
    assert r.status_code == 503
    body = r.json()
    assert body["detail"]["error"] == "iue_structured_lane_disabled"


def test_analyze_produces_t2_wire_contract_when_flag_on(client, monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "on")
    files = {"file": ("in.ndjson", io.BytesIO(NDJSON),
                        "application/x-ndjson")}
    r = client.post("/api/iue/lane-a/analyze",
                      files=files, data={"parser": "ndjson"})
    assert r.status_code == 200
    body = r.json()

    # T2 wire-shape key surface — mirrors
    # test_t2_wire_contract_key_surface_stable in the goldens.
    assert set(body.keys()) >= {
        "intake_decision", "raw_payload", "logical_events",
        "malformed", "report_extraction_fragment",
    }

    events = body["logical_events"]
    # 3 records → 2 LogicalEvents (2 exec-in-1s-bucket + 1 network)
    assert len(events) == 2
    biggest = max(events, key=lambda e: e["count"])
    assert biggest["count"] == 2
    assert biggest["canonical_fields"]["canonical.event.action"] == "exec"
    assert biggest["canonical_fields"]["canonical.source.ip"] == "10.0.0.1"

    # Provenance schema is the composed canonical.ssot.models.Provenance
    assert set(biggest["provenance"].keys()) == {
        "engine", "version", "at", "upstream_evidence_ids",
    }
    assert biggest["provenance"]["engine"] == "iue.aggregator"

    # Lineage walkable end-to-end
    chain = biggest["provenance"]["upstream_evidence_ids"]
    assert any("iue.intake" in s for s in chain)
    assert any("iue.parsers.ndjson" in s for s in chain)
    assert any("iue.normalizers.field_map" in s for s in chain)


def test_analyze_rejects_unsupported_parser(client, monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "on")
    files = {"file": ("in.log", io.BytesIO(b"anything"),
                        "text/plain")}
    r = client.post("/api/iue/lane-a/analyze",
                      files=files, data={"parser": "syslog"})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "unsupported_parser"


def test_analyze_rejects_missing_file(client, monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "on")
    r = client.post("/api/iue/lane-a/analyze", data={"parser": "ndjson"})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "missing_file"
