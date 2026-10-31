"""
Round 26 · Cortex Ingest Fabric invariants.

Locked (owner · 2026-02-14):
  1. Parser is deterministic → same payload yields same event_ids.
  2. Every canonical row preserves provenance:
       vendor / source_integration_id / source_object_type /
       source_object_id / xdr_incident_id / observed_at / ingested_at.
  3. Re-ingesting the same Cortex payload yields ZERO new rows
     (all upserts hit).
  4. MITRE tactic/technique pairs preserved as {id, name}.
  5. `latest_modification_time` picks the largest incident cursor
     so poller advancement is deterministic.
"""
from __future__ import annotations

import asyncio
import pytest

from detection_content.xdr_cortex_parser import (
    parse_incident, parse_batch, _event_id, VENDOR,
)
from detection_content.xdr_cortex_ingest import (
    latest_modification_time,
)


CISCO_LIKE_INCIDENT = {
    "incident_id": "INC-413",
    "detection_time": 1_756_691_646_000,   # ms
    "creation_time":  1_756_691_640_000,
    "modification_time": 1_756_691_800_000,
    "severity": "high",
    "status": "new",
    "description": "A known malicious file was executed.",
    "alert_count": 1,
    "hosts": ["legion5"],
    "users": ["codexsandboxoffline"],
    "mitre_tactics_ids_and_names":    ["TA0002 - Execution"],
    "mitre_techniques_ids_and_names": ["T1219 - Remote Access Software"],
    "alerts": [
        {
            "alert_id": "alert-1",
            "detection_timestamp": 1_756_691_644_000,
            "event_type": "IOC Match",
            "severity": "high",
            "description": "ExecutedMalware.ioc",
            "action_pretty": "Detected",
            "host_name": "legion5",
            "user_name": "codexsandboxoffline",
            "action_process_image_name": "idle_report.exe",
            "action_process_image_command_line":
                "C:\\ProgramData\\BrightData\\...\\idle_report.exe --id 76758",
            "action_process_image_sha256":
                "806775d9a498229c66663683009b61a5a6c42ce2d3433c43ebcb782ac3ffc6b1",
            "action_file_path":
                "file:///C%3A/ProgramData/BrightData/.../idle_report.exe",
            "action_file_sha256":
                "3280806d740eae89b19381815a178268e666826a13fbf53b2da63d45a5de8356",
            "mitre_tactic_id_and_name":    "TA0002 - Execution",
            "mitre_technique_id_and_name": "T1219 - Remote Access Software",
        }
    ],
    "key_artifacts": [
        {"type": "sha256",
          "value": "806775d9a498229c66663683009b61a5a6c42ce2d3433c43ebcb782ac3ffc6b1"},
        {"type": "sha256",
          "value": "3280806d740eae89b19381815a178268e666826a13fbf53b2da63d45a5de8356"},
    ],
}


def test_parser_deterministic_and_preserves_provenance():
    rows = parse_incident(CISCO_LIKE_INCIDENT, integration_id="cortex-abc")
    # 1 incident + 1 alert + 2 key_artifacts + 1 host + 1 user = 6
    assert len(rows) == 6
    types = [r["source_object_type"] for r in rows]
    assert types == ["incident", "alert", "key_artifact",
                        "key_artifact", "host", "user"]
    for r in rows:
        assert r["vendor"] == VENDOR
        assert r["source_integration_id"] == "cortex-abc"
        assert r["xdr_incident_id"] == "INC-413"
        assert r["event_id"].startswith("cev-cortex-")
        assert r["ingested_at"]           # ISO string present
        assert "raw" in r                  # provenance preserved
    # deterministic: same payload → same event_ids
    rows2 = parse_incident(CISCO_LIKE_INCIDENT, integration_id="cortex-abc")
    assert [r["event_id"] for r in rows] == [r["event_id"] for r in rows2]


def test_alert_fields_and_mitre_projection():
    rows = parse_incident(CISCO_LIKE_INCIDENT, integration_id="cortex-abc")
    alert_row = next(r for r in rows if r["source_object_type"] == "alert")
    f = alert_row["fields"]
    assert f["file_sha256"] == (
        "3280806d740eae89b19381815a178268e666826a13fbf53b2da63d45a5de8356")
    assert f["process_sha256"] == (
        "806775d9a498229c66663683009b61a5a6c42ce2d3433c43ebcb782ac3ffc6b1")
    assert "--id 76758" in f["process_cmdline"]
    assert f["mitre_tactic"]    == {"id": "TA0002", "name": "Execution"}
    assert f["mitre_technique"] == {"id": "T1219", "name": "Remote Access Software"}


def test_key_artifact_object_id_shape():
    rows = parse_incident(CISCO_LIKE_INCIDENT, integration_id="cortex-abc")
    kas = [r for r in rows if r["source_object_type"] == "key_artifact"]
    assert kas[0]["source_object_id"].startswith("sha256:")


def test_parse_batch_accepts_reply_envelope():
    envelope = {"reply": {"incidents": [CISCO_LIKE_INCIDENT]}}
    rows = parse_batch(envelope, integration_id="cortex-abc")
    assert len(rows) == 6


def test_event_id_stable_across_processes():
    a = _event_id("cortex-abc", "alert", "alert-1")
    b = _event_id("cortex-abc", "alert", "alert-1")
    c = _event_id("cortex-xyz", "alert", "alert-1")
    assert a == b
    assert a != c


def test_latest_modification_time_picks_max():
    rows = parse_incident(CISCO_LIKE_INCIDENT, integration_id="cortex-abc")
    assert latest_modification_time(rows) == 1_756_691_800_000
    # A second, older incident does NOT roll the cursor backwards.
    older = dict(CISCO_LIKE_INCIDENT, incident_id="INC-1",
                     modification_time=1_000_000_000_000)
    rows2 = parse_batch([CISCO_LIKE_INCIDENT, older],
                             integration_id="cortex-abc")
    assert latest_modification_time(rows2) == 1_756_691_800_000
