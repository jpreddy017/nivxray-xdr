"""P0-B + P0-D · the real Linux sensor and the canonical bridge.

These tests read the ACTUAL /proc of the machine running them. There is no
fixture telemetry: if the collector cannot see a real process, a real
socket or a real file change, the test fails.

The bridge tests then prove the honesty properties that matter more than
throughput: a file event with no observed writer is still classified as a
file event (never silently downgraded), a parse failure retains and marks
the raw event rather than losing it, and the authenticated identity
travels all the way onto the canonical observation.
"""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import sys
import tempfile
from pathlib import Path

import pytest

SENSOR_PATH = Path("/app/agents/nivxforge-linux/nivxforge_sensor.py")


def _sensor():
    spec = importlib.util.spec_from_file_location("nivxforge_sensor",
                                                   SENSOR_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["nivxforge_sensor"] = mod
    spec.loader.exec_module(mod)
    return mod


# ── the sensor collects REAL kernel state ─────────────────────────

def test_sensor_file_exists_and_is_executable_python():
    assert SENSOR_PATH.exists()
    assert SENSOR_PATH.read_text().startswith("#!/usr/bin/env python3")


def test_collects_real_processes_including_the_test_runner():
    s = _sensor()
    procs = s.collect_processes(set(), hash_exe=False)
    assert len(procs) > 1
    me = [p for p in procs if p["pid"] == os.getpid()]
    assert me, "the collector did not see the process running this test"
    p = me[0]
    assert p["ppid"] == os.getppid()
    assert "python" in (p["image"] or "").lower()
    assert p["image_path"] and Path(p["image_path"]).exists()
    # A real command line, whatever the harness happens to be — under a
    # parallel worker this is an execnet bootstrap, not "pytest".
    assert p["command_line"]
    assert p["start_time"]
    # Never claimed, because polling cannot distinguish exit from a miss.
    assert "exit_time" in p["not_observed"]
    assert p.get("exit_time") is None


def test_process_dedup_means_a_second_scan_reports_nothing_new():
    s = _sensor()
    seen = set()
    first = s.collect_processes(seen, hash_exe=False)
    second = s.collect_processes(seen, hash_exe=False)
    assert first
    # Only genuinely NEW processes on the second pass, so a restart does
    # not re-report the whole process table as fresh activity.
    assert len(second) < len(first)


def test_hashes_a_real_executable_from_disk():
    s = _sensor()
    with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as f:
        f.write(b"nivxforge-hash-probe")
        path = f.name
    try:
        import hashlib
        assert s._sha256_file(path) == hashlib.sha256(
            b"nivxforge-hash-probe").hexdigest()
    finally:
        os.unlink(path)


def test_collects_a_real_listening_socket_it_just_created():
    s = _sensor()
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        conns = s.collect_network(set())
        mine = [c for c in conns if c["local_port"] == port]
        assert mine, f"collector did not see the real listener on {port}"
        c = mine[0]
        assert c["direction"] == "LISTEN"
        assert c["protocol"] in ("TCP", "TCP6")
        # A listener has no peer, and the sensor says so rather than
        # inventing 0.0.0.0:0 as a remote endpoint.
        assert c["remote_ip"] is None and c["remote_port"] is None
        assert "remote_ip" in c["not_observed"]
    finally:
        srv.close()


def test_hex_ip_decoding_is_correct():
    s = _sensor()
    assert s._hexip("0100007F") == "127.0.0.1"
    assert s._hexip("00000000") == "0.0.0.0"


def test_collects_real_file_create_modify_and_delete():
    s = _sensor()
    with tempfile.TemporaryDirectory() as d:
        known: dict = {}
        assert s.collect_files(d, known) == []          # empty baseline
        target = Path(d) / "dropper.sh"
        target.write_text("payload-v1")
        created = s.collect_files(d, known)
        assert [e["operation"] for e in created] == ["CREATE"]
        assert created[0]["path"] == str(target)
        assert created[0]["sha256"]
        # The WRITER is never attributed to a guess.
        assert "actor_process" in created[0]["not_observed"]

        target.write_text("payload-v2-longer")
        modified = s.collect_files(d, known)
        assert [e["operation"] for e in modified] == ["MODIFY"]
        assert modified[0]["sha256"] != created[0]["sha256"]

        target.unlink()
        deleted = s.collect_files(d, known)
        assert [e["operation"] for e in deleted] == ["DELETE"]
        assert deleted[0]["sha256"] is None
        assert "sha256" in deleted[0]["not_observed"]


def test_sensor_declares_its_limits_rather_than_hiding_them():
    s = _sensor()
    caps = s.CAPABILITIES
    assert "process.exit_time" in caps["fields_not_supported"]
    assert "file.actor_process" in caps["fields_not_supported"]
    joined = " ".join(caps["limits"])
    assert "visibility gap, not an absence of activity" in joined
    assert "eBPF" in joined


def test_machine_facts_yield_a_durable_attribute_on_this_box():
    s = _sensor()
    f = s._machine_facts()
    assert f["platform"] == "LINUX"
    assert f["processor_id"] or f["machine_guid"], \
        "no durable machine attribute; the sensor must refuse to enrol"


def test_sensor_never_proposes_its_own_endpoint_id():
    """The sensor may STORE the endpoint_id the platform returns; it must
    never SEND one. Assert on the enrol REQUEST body specifically."""
    s = _sensor()
    sent = {}

    def fake_post(api, path, body, bearer=None):
        sent.update({"path": path, "body": body})
        return {"endpoint_id": "ep_platform_minted",
                "credential_id": "cred_1", "agent_credential": "eak_x",
                "sensor_state": "ENROLLED_NEVER_REPORTED"}

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        s.STATE_DIR = Path(d)
        s.IDENTITY_FILE = Path(d) / "identity.json"
        s._post = fake_post
        s.enrol("http://x", "default", "enr_test")

    assert sent["path"] == "/api/edr/agent/enroll"
    assert "endpoint_id" not in sent["body"]
    assert "tenant_id" in sent["body"]          # tenant IS the agent's
    # Only durable machine attributes are offered.
    assert {"processor_id", "machine_guid", "hostname"} <= set(sent["body"])
    stored = json.loads((Path(d := s.IDENTITY_FILE.parent)
                         / "identity.json").read_text()) \
        if s.IDENTITY_FILE.exists() else None
    assert stored is None or stored["endpoint_id"] == "ep_platform_minted"


# ── the canonical bridge ──────────────────────────────────────────

def test_bridge_parses_a_real_process_event():
    from edr_plane.canonical_bridge import parse
    s = _sensor()
    ev = [p for p in s.collect_processes(set(), hash_exe=False)
          if p["pid"] == os.getpid()][0]
    c = parse(json.dumps(ev))
    assert c["process"]["pid"] == os.getpid()
    assert c["process"]["ppid"] == os.getppid()
    assert c["additional_fields"]["activity_type"] == "PROCESS"
    assert c["additional_fields"]["lineage_state"] == "PARENT_OBSERVED"
    est = c["additional_fields"]["epistemic_state"]
    assert "exit_time" in est["not_observed"]
    assert "Neither means the activity did not occur" in est["note"]


def test_bridge_classifies_a_file_event_with_no_observed_writer():
    """The regression this exists to prevent: the shared kind classifier
    required an actor for `file_write`, so a file event whose writer was
    honestly NOT_OBSERVED was silently reclassified to `detection` and
    vanished from the file lane. A visibility gap created by the
    classifier, not by the telemetry."""
    from edr_plane.canonical_bridge import parse
    from v2.ingestion.canonical import _resolve_kind
    from v2.ingestion.telemetry_bridge import canonical_to_ces
    c = parse(json.dumps({
        "activity": "FILE", "operation": "CREATE",
        "observed_at": "2026-06-01T00:00:00+00:00",
        "path": "/tmp/x/dropper.sh", "filename": "dropper.sh", "size": 10,
        "sha256": "a" * 64, "not_observed": ["actor_process"]}))
    c["host"] = {"host_id": "ep_x", "hostname": "h"}
    c["event_id"] = "cev_x"
    c["provenance"] = {"trace_id": "raw_x", "normalizer_id": "n/1"}
    ces = canonical_to_ces(c, envelope={
        "source": "s", "connector_id": "c", "collector_id": "c",
        "collection_method": "PROC_POLL", "parser_version": "1",
        "source_event_id": "cev_x",
        "collection_timestamp": c["event_time"]})
    assert ces.file_path == "/tmp/x/dropper.sh"
    assert not ces.image                       # writer genuinely unknown
    assert _resolve_kind(ces) == "file_write"  # still a file event


def test_bridge_maps_a_network_event_without_inventing_a_process():
    from edr_plane.canonical_bridge import parse
    c = parse(json.dumps({
        "activity": "NETWORK", "operation": "CONNECTION_OBSERVED",
        "observed_at": "2026-06-01T00:00:00+00:00", "protocol": "TCP",
        "local_ip": "10.0.0.2", "local_port": 55000,
        "remote_ip": "203.0.113.7", "remote_port": 443,
        "direction": "OUTBOUND", "tcp_state": "01", "pid": None,
        "not_observed": ["owning_process"]}))
    assert c["network"]["dest_ip"] == "203.0.113.7"
    # A remote IP is a network peer. It is never promoted to a process or
    # an endpoint — the bug this codebase already had to fix once.
    assert c["process"] == {}
    assert "owning_process" in c["additional_fields"][
        "epistemic_state"]["not_observed"]


def test_bridge_rejects_an_unknown_activity():
    from edr_plane.canonical_bridge import parse
    with pytest.raises(ValueError, match="unknown sensor activity"):
        parse(json.dumps({"activity": "TELEPATHY"}))


def test_bridge_declares_what_the_sensor_cannot_produce():
    from edr_plane.canonical_bridge import SENSOR_NOT_SUPPORTED
    for f in ("process.exit_time", "file.actor_process", "registry"):
        assert f in SENSOR_NOT_SUPPORTED


@pytest.mark.asyncio
async def test_a_parse_failure_retains_the_raw_event_and_marks_it():
    import uuid
    from motor.motor_asyncio import AsyncIOMotorClient
    from edr_plane.canonical_bridge import bridge
    from edr_plane.raw_events import (COLLECTION, RawEndpointEvent, append,
                                      ensure_indexes, get)
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0b-{uuid.uuid4().hex[:8]}"
    try:
        await ensure_indexes(db)
        bad = '{"activity":"NOT_A_REAL_ACTIVITY"}'
        ev = RawEndpointEvent.build(tenant_id=tenant, source="ep_x",
                                    payload=bad, trust_state="AUTHENTICATED")
        await append(db, ev)
        out = await bridge(db, raw_id=ev.raw_id, tenant_id=tenant,
                          payload=bad, endpoint_id="ep_x", hostname="h",
                          authentication={"authenticated_endpoint_id": "ep_x"})
        assert out["canonicalized"] is False
        assert out["parser_state"] == "FAILED"

        doc = await get(db, tenant_id=tenant, raw_id=ev.raw_id)
        assert doc["payload"] == bad          # bytes retained verbatim
        d = doc["derivations"][-1]
        assert d["parser_state"] == "FAILED"
        assert d["outcome"] == "NO_CANONICAL_EVIDENCE"
        assert "replayable" in d["reason"]
    finally:
        await db[COLLECTION].delete_many({"tenant_id": tenant})
        client.close()


@pytest.mark.asyncio
async def test_authenticated_identity_reaches_the_canonical_observation():
    import uuid
    from motor.motor_asyncio import AsyncIOMotorClient
    from edr_plane.canonical_bridge import bridge
    from edr_plane.raw_events import (COLLECTION, RawEndpointEvent, append,
                                      ensure_indexes, get)
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0b-{uuid.uuid4().hex[:8]}"
    auth = {"authenticated_endpoint_id": "ep_real", "credential_id": "cred_1",
            "session_id": "sess_1", "auth_method": "bearer_session",
            "device_iid": None}
    try:
        await ensure_indexes(db)
        payload = json.dumps({
            "activity": "PROCESS", "operation": "PROCESS_OBSERVED",
            "observed_at": "2026-06-01T00:00:00+00:00",
            "start_time": "2026-06-01T00:00:00+00:00", "pid": 4242,
            "ppid": 1, "image": "bash", "image_path": "/bin/bash",
            "command_line": "bash -c whoami", "user": "root",
            "sha256": "c" * 64, "not_observed": ["exit_time"]})
        ev = RawEndpointEvent.build(tenant_id=tenant, source="ep_real",
                                    payload=payload,
                                    trust_state="AUTHENTICATED")
        ev.authentication = auth
        await append(db, ev)
        out = await bridge(db, raw_id=ev.raw_id, tenant_id=tenant,
                          payload=payload, endpoint_id="ep_real",
                          hostname="lab-01", authentication=auth)
        assert out["canonicalized"] is True
        assert out["activity_type"] == "PROCESS"
        assert out["observation_id"]

        doc = await get(db, tenant_id=tenant, raw_id=ev.raw_id)
        # "Which authenticated endpoint produced this exact evidence?"
        assert doc["authentication"]["authenticated_endpoint_id"] == "ep_real"
        # P0-F appended a detection derivation, so match on the outcome
        # rather than on position.
        outcomes = [x["outcome"] for x in doc["derivations"]]
        assert "CANONICAL_EVIDENCE_CREATED" in outcomes
        d = [x for x in doc["derivations"]
             if x["outcome"] == "CANONICAL_EVIDENCE_CREATED"][0]
        assert d["parser_state"] == "OK"
        assert d["evidence_ids"] == [out["observation_id"]]
    finally:
        await db[COLLECTION].delete_many({"tenant_id": tenant})
        client.close()



# ── real ancestry, and the refusal to invent it ───────────────────

def test_the_real_parent_of_the_test_runner_is_observed_not_guessed():
    s = _sensor()
    procs = s.collect_processes(set(), hash_exe=False)
    me = [p for p in procs if p["pid"] == os.getpid()][0]
    assert me["parent_lookup_state"] == "OBSERVED"
    assert me["parent_image"], "a resolvable parent must carry its image"
    assert "parent_image" not in me["not_observed"]


def test_a_parent_that_is_gone_is_not_attributed():
    s = _sensor()
    # PID 0 is the kernel boundary — not a missing parent, and not a root
    # we are allowed to invent.
    assert s._proc_parent(0, 10)["parent_lookup_state"] == "KERNEL_BOUNDARY"
    # An unused high pid cannot be read, so nothing is claimed.
    gone = s._proc_parent(4194303, 10)
    assert gone["parent_lookup_state"] == "PARENT_NOT_PRESENT"
    assert gone["parent_image"] is None
    # A "parent" that started AFTER its child is a reused pid.
    reused = s._proc_parent(os.getpid(), 0)
    assert reused["parent_lookup_state"] == \
        "PID_REUSED_PARENT_NOT_ATTRIBUTABLE"
    assert reused["parent_image"] is None


def test_bridge_carries_real_lineage_and_never_fabricates_it():
    from edr_plane.canonical_bridge import parse
    base = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
            "observed_at": "2026-06-01T00:00:00+00:00", "pid": 10,
            "ppid": 4, "image": "curl", "image_path": "/usr/bin/curl",
            "command_line": "curl http://x", "user": "root"}
    ok = parse(json.dumps({**base, "parent_image": "bash",
                           "parent_image_path": "/bin/bash",
                           "parent_lookup_state": "OBSERVED"}))
    assert ok["process"]["parent_pid"] == 4
    assert ok["process"]["parent_name"] == "bash"
    assert ok["additional_fields"]["lineage_state"] == "PARENT_OBSERVED"

    for state, expected in (
            ("PARENT_NOT_PRESENT", "PARENT_NOT_OBSERVED"),
            ("KERNEL_BOUNDARY", "ROOT_KERNEL_BOUNDARY"),
            ("PID_REUSED_PARENT_NOT_ATTRIBUTABLE",
             "PARENT_NOT_ATTRIBUTABLE_PID_REUSE")):
        out = parse(json.dumps({**base, "parent_image": None,
                                "parent_lookup_state": state}))
        assert out["additional_fields"]["lineage_state"] == expected
        assert out["process"]["parent_name"] is None


def test_lineage_reaches_ces_so_a_process_tree_can_actually_link():
    from v2.ingestion.telemetry_bridge import canonical_to_ces
    from edr_plane.canonical_bridge import parse
    child = parse(json.dumps({
        "activity": "PROCESS", "operation": "PROCESS_OBSERVED",
        "observed_at": "2026-06-01T00:00:00+00:00", "pid": 10, "ppid": 4,
        "image": "curl", "image_path": "/usr/bin/curl",
        "command_line": "curl http://x", "user": "root",
        "parent_image": "bash", "parent_image_path": "/bin/bash",
        "parent_lookup_state": "OBSERVED"}))
    child["host"] = {"host_id": "ep_1", "hostname": "lab-01"}
    ces = canonical_to_ces(child, envelope={})
    assert ces.parent_process_id == "4"
    assert ces.parent_image == "/bin/bash"

    # And the parent's own event must mint the SAME process iid, otherwise
    # the tree renders as two unrelated lifelines.
    from v2.ingestion.canonical import ces_to_cem_dict
    parent = parse(json.dumps({
        "activity": "PROCESS", "operation": "PROCESS_OBSERVED",
        "observed_at": "2026-06-01T00:00:00+00:00", "pid": 4, "ppid": 1,
        "image": "bash", "image_path": "/bin/bash",
        "command_line": "/bin/bash", "user": "root",
        "parent_image": "init", "parent_image_path": "/sbin/init",
        "parent_lookup_state": "OBSERVED"}))
    parent["host"] = {"host_id": "ep_1", "hostname": "lab-01"}
    child_ev = ces_to_cem_dict(canonical_to_ces(child, envelope={}),
                               case_id=None)
    parent_ev = ces_to_cem_dict(canonical_to_ces(parent, envelope={}),
                                case_id=None)
    assert child_ev["process"]["parent_iid"] == parent_ev["process_iid"]


# ── one real activity is one piece of evidence ────────────────────

def test_activity_identity_is_stable_across_re_observation():
    from edr_plane.canonical_bridge import activity_identity
    ev = {"activity": "PROCESS", "pid": 10, "start_time": "2026-06-01T00:00Z",
          "image_path": "/bin/bash"}
    first = activity_identity(ev, "ep_1")
    # A later scan of the SAME running process differs only in when we
    # looked at it. That must not mint a new identity.
    second = activity_identity({**ev, "observed_at": "later"}, "ep_1")
    assert first == second
    # A different endpoint, pid or start time is a different activity.
    assert activity_identity(ev, "ep_2") != first
    assert activity_identity({**ev, "pid": 11}, "ep_1") != first
    assert activity_identity({**ev, "start_time": "2026-06-02T00:00Z"},
                             "ep_1") != first


@pytest.mark.asyncio
async def test_a_re_observed_process_does_not_become_second_evidence():
    import uuid
    from motor.motor_asyncio import AsyncIOMotorClient
    from edr_plane.canonical_bridge import bridge
    from edr_plane.raw_events import (COLLECTION, RawEndpointEvent, append,
                                      ensure_indexes, get)
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    tenant = f"p0b-{uuid.uuid4().hex[:8]}"
    auth = {"authenticated_endpoint_id": "ep_dup"}
    base = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
            "start_time": "2026-06-01T00:00:00+00:00", "pid": 777,
            "ppid": 1, "image": "bash", "image_path": "/bin/bash",
            "command_line": "bash -l", "user": "root",
            "parent_lookup_state": "PARENT_NOT_PRESENT"}
    try:
        await ensure_indexes(db)
        ids = []
        for observed_at in ("2026-06-01T00:00:01+00:00",
                            "2026-06-01T00:05:00+00:00"):
            payload = json.dumps({**base, "observed_at": observed_at})
            ev = RawEndpointEvent.build(tenant_id=tenant, source="ep_dup",
                                        payload=payload,
                                        trust_state="AUTHENTICATED")
            await append(db, ev)
            out = await bridge(db, raw_id=ev.raw_id, tenant_id=tenant,
                               payload=payload, endpoint_id="ep_dup",
                               hostname="lab-01", authentication=auth)
            ids.append((ev.raw_id, out))

        # Both deliveries are DIFFERENT bytes, so both are retained raw.
        assert ids[0][0] != ids[1][0]
        assert ids[0][1]["canonicalized"] is True
        # The second is honestly reported as the same activity, and no
        # second evidence row is created for one real process.
        assert ids[1][1]["canonicalized"] is False
        assert ids[1][1]["duplicate_activity"] is True
        assert ids[1][1]["existing_observation_id"] == \
            ids[0][1]["observation_id"]
        d = (await get(db, tenant_id=tenant,
                       raw_id=ids[1][0]))["derivations"][-1]
        assert d["outcome"] == "DUPLICATE_OBSERVATION_OF_KNOWN_ACTIVITY"
        assert d["parser_state"] == "OK"      # nothing failed to parse
        assert d["evidence_ids"] == [ids[0][1]["observation_id"]]

        n = await db["v2_shadow_observations"].count_documents(
            {"tenant_id": tenant})
        assert n == 1, "one real process must be one piece of evidence"
    finally:
        await db[COLLECTION].delete_many({"tenant_id": tenant})
        await db["v2_shadow_observations"].delete_many({"tenant_id": tenant})
        client.close()


def test_observed_state_survives_a_restart_so_the_table_is_not_re_reported():
    s = _sensor()
    with tempfile.TemporaryDirectory() as d:
        s.STATE_DIR = Path(d)
        s.OBSERVED_FILE = Path(d) / "observed.json"
        s._save_observed({"5:100"}, {"tcp|a|b|01"},
                         {"/tmp/x": (1, 2)}, {"/tmp/watch"})
        procs, conns, files, baselined = s._load_observed()
        assert procs == {"5:100"}
        assert conns == {"tcp|a|b|01"}
        assert files == {"/tmp/x": (1, 2)}
        # The baseline is recorded EXPLICITLY: an empty watched directory
        # must not be re-baselined, or the first real file created in it is
        # swallowed as if it had always been there.
        assert baselined == {"/tmp/watch"}
