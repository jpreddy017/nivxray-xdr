"""The §d -> Behavior evidence adapter: truthful mapping, or nothing.

Nothing here executes a Behavior rule, instantiates the engine, touches a
store, reads a DB, or emits a Fabric Finding. Only the E3 CONTRACT TYPES are
imported.
"""
import copy
from datetime import datetime, timezone

import pytest

from edr_behavior import predicates as P
from edr_behavior.contracts import (KIND_AUTH, KIND_DETECTION, KIND_DNS,
                                    KIND_FILE, KIND_NETWORK, KIND_PROCESS,
                                    KIND_PROCESS_TERMINATION, KIND_REGISTRY,
                                    STORE_SHADOW_OBSERVATION,
                                    STORE_XDR_CANONICAL)
from edr_plane.behavior_evidence_adapter import (REFUSED_FIELD_COLLISION,
                                                 REFUSED_FIELD_SHAPE,
                                                 REFUSED_KIND,
                                                 REFUSED_NO_ENDPOINT,
                                                 REFUSED_NO_RAW_REF,
                                                 REFUSED_NO_TENANT,
                                                 REFUSED_NO_TIME,
                                                 REFUSED_TENANT_CONFLICT,
                                                 to_evidence_record)

TEN = "ten_e759b7288598bd882e3dcac49d"
TEN_B = "ten_b000000000000000000000000"
EP = "ep_a67be48d5b4e01d4d9e8"
RAW = "raw_9f12c0a3"
OBS = "obs_7731aa90"
ACT = "act_4c8e11f2"
US = 1_759_462_207_123_456


def row(**kw):
    base = {
        "schema": "e3.dt.event.v1",
        "event_id": ACT,
        "tenant_id": TEN,
        # an ADDRESSING alias, and deliberately the substituted-name case
        "device_id": EP,
        "kind": "PROCESS_START",
        "observed_ms": US // 1000,
        "observed_us": US,
        "ingested_ms": US // 1000 + 9_000,
        "ingested_at": "2026-10-03T04:10:16.123Z",
        "severity": "NONE",
        "process": {"pid": "7120", "guid": "{a1b2}", "image": r"C:\\Windows\\chrome.exe",
                    "command_line": "chrome.exe --type=renderer", "user": "KUSHU\\jp",
                    "sha256": "ab" * 32, "start_time": "2026-10-03T04:10:07.000Z"},
        "parent": {"pid": "640", "guid": "{p0p0}", "image": r"C:\\Windows\\explorer.exe"},
        "file": {}, "network": {}, "detection": None, "boot_id": "boot_1",
        "sources": ["v2_shadow_observations"],
        "provenance": {"store": "v2_shadow_observations", "ref": OBS, "label": "windows-sysmon"},
        "process_key": "pk_8812", "process_identity": "SOURCE_PROCESS_GUID",
        "parent_key": "pk_0640", "parent_identity": "SOURCE_PROCESS_GUID",
        "observed_at": "2026-10-03T04:10:07.123Z",
    }
    base.update(kw)
    return base


def ok(**kw):
    rec, why = to_evidence_record(row(**kw), tenant_id=TEN, endpoint_id=EP,
                                 raw_id=RAW)
    assert why is None, why
    assert rec is not None
    return rec


# ── supported mappings ───────────────────────────────────────────────────

def test_process_start_maps_to_canonical_process_evidence():
    rec = ok()
    assert rec.kind == KIND_PROCESS
    assert rec.fields["process"]["executable_path"].endswith("chrome.exe")
    assert rec.fields["process"]["name"] == "chrome.exe"
    assert rec.fields["process"]["command_line"] == \
        "chrome.exe --type=renderer"
    assert rec.fields["user"]["name"] == "KUSHU\\jp"
    # the canonical paths the shipped rules actually address
    assert P.get_field(rec, "process.name") == "chrome.exe"
    assert P.get_field(rec, "process.command_line").startswith("chrome.exe")
    assert P.get_field(rec, "user.name") == "KUSHU\\jp"


@pytest.mark.parametrize("family,expected", [
    ("PROCESS_START", KIND_PROCESS),
    ("PROCESS_END", KIND_PROCESS_TERMINATION),
    ("FILE_CREATE", KIND_FILE),
    ("FILE_WRITE", KIND_FILE),
    ("FILE_DELETE", KIND_FILE),
    ("FILE_MOVE", KIND_FILE),
    ("FILE_EXECUTE", KIND_FILE),
    ("NETWORK_CONNECT", KIND_NETWORK),
    ("DNS_QUERY", KIND_DNS),
    ("REGISTRY_SET", KIND_REGISTRY),
    ("AUTH", KIND_AUTH),
    ("DETECTION", KIND_DETECTION),
])
def test_every_supported_family_maps_to_its_declared_kind(family, expected):
    assert ok(kind=family).kind == expected


def test_file_evidence_fields():
    rec = ok(kind="FILE_MOVE",
             file={"path": r"C:\\tmp\\b.exe", "prev_path": r"C:\\tmp\\a.exe",
                   "sha256": "cd" * 32, "operation": "rename"})
    assert P.get_field(rec, "file.path").endswith("b.exe")
    assert P.get_field(rec, "file.name") == "b.exe"
    assert P.get_field(rec, "file.previous_path").endswith("a.exe")
    assert P.get_field(rec, "file.operation") == "rename"
    assert P.get_field(rec, "file.sha256") == "cd" * 32


def test_network_and_dns_evidence_fields():
    rec = ok(kind="NETWORK_CONNECT",
             network={"dest_ip": "93.184.216.34", "dest_port": 443,
                      "protocol": "tcp", "src_ip": "10.0.0.5"})
    assert P.get_field(rec, "network.dest_ip") == "93.184.216.34"
    assert P.get_field(rec, "network.dest_port") == 443
    assert P.get_field(rec, "network.src_ip") == "10.0.0.5"
    dns = ok(kind="DNS_QUERY", network={"query": "updates.example.test"})
    assert P.get_field(dns, "dns.query_name") == "updates.example.test"


def test_canonically_unavailable_domains_stay_absent():
    """§d carries no registry, auth, signer or DNS-answer data. Those canonical
    paths must be ABSENT, so a predicate reads UNKNOWN instead of matching a
    fabricated value."""
    rec = ok(kind="REGISTRY_SET")
    for path in ("registry.key", "registry.operation", "auth.logon_type",
                 "process.signer", "process.integrity_level",
                 "process.current_directory", "dns.answers",
                 "network.dest_hostname", "network.direction"):
        assert P.get_field(rec, path) is None, path


def test_parent_process_is_canonical_when_the_row_states_one():
    rec = ok(parent={"image": r"C:\\Windows\\explorer.exe", "pid": 7})
    assert P.get_field(rec, "parent.executable_path").endswith("explorer.exe")
    assert P.get_field(rec, "parent.name") == "explorer.exe"


def test_detection_family_carries_the_detection_the_row_holds():
    rec = ok(kind="DETECTION",
             detection={"rule_id": "R-1", "basis": "DETECTION_CARRIED_ON_THE_OBSERVATION"})
    assert rec.fields["detection"]["rule_id"] == "R-1"


# ── authority ────────────────────────────────────────────────────────────

def test_tenant_comes_from_the_resolved_identity():
    assert ok().tenant_id == TEN
    assert ok().ref.tenant_id == TEN


def test_endpoint_is_the_platform_minted_id():
    assert ok().endpoint_id == EP


def test_a_substituted_hostname_device_alias_is_never_promoted_to_identity():
    """§d `device_id` may be a substituted ep_/hostname alias — it is addressing,
    never identity, so it must not become the endpoint or leak into fields."""
    rec = ok(device_id="KUSHU")
    assert rec.endpoint_id == EP
    assert "KUSHU" not in str(P.get_field(rec, "process.executable_path"))
    assert "device_id" not in rec.fields


def test_row_tenant_disagreeing_with_resolved_tenant_fails_closed():
    rec, why = to_evidence_record(row(tenant_id=TEN_B), tenant_id=TEN,
                                  endpoint_id=EP, raw_id=RAW)
    assert rec is None and why == REFUSED_TENANT_CONFLICT


# ── time authority ───────────────────────────────────────────────────────

def test_event_time_is_stored_observation_time_at_full_precision():
    rec = ok()
    assert rec.event_time == datetime.fromtimestamp(US / 1_000_000,
                                                    tz=timezone.utc)
    assert rec.event_time.tzinfo is timezone.utc
    assert rec.provenance["observation_time_authority"] == \
        "STORED_OBSERVATION_TIME"


def test_millisecond_time_is_used_when_microseconds_are_absent():
    r = row()
    r.pop("observed_us")
    rec, why = to_evidence_record(r, tenant_id=TEN, endpoint_id=EP, raw_id=RAW)
    assert why is None
    assert rec.event_time == datetime.fromtimestamp(US // 1000 / 1000,
                                                    tz=timezone.utc)


def test_changing_only_ingest_time_changes_neither_event_time_nor_identity():
    a = ok()
    b = ok(ingested_ms=US // 1000 + 999_999,
           ingested_at="2026-12-25T00:00:00.000Z")
    assert a.event_time == b.event_time
    assert a.ref.stable_key() == b.ref.stable_key()
    assert a.sort_key() == b.sort_key()


def test_ingest_time_never_becomes_the_event_time():
    rec = ok()
    assert rec.event_time.timestamp() * 1000 != rec.provenance.get("ingested_ms")
    assert rec.provenance["ingested_at"] == "2026-10-03T04:10:16.123Z"


# ── evidence reference ───────────────────────────────────────────────────

def test_shadow_reference_maps_observation_id_to_record_id():
    ref = ok().ref
    assert ref.store == STORE_SHADOW_OBSERVATION
    assert ref.record_id == OBS
    assert ref.canonical_event_id is None
    assert ref.raw_id == RAW
    assert ref.sub_key == ACT


def test_canonical_reference_maps_event_id_to_canonical_event_id():
    ref = ok(provenance={"store": "xdr_canonical_evidence", "ref": "cev_88"},
             sources=["xdr_canonical_evidence"]).ref
    assert ref.store == STORE_XDR_CANONICAL
    assert ref.canonical_event_id == "cev_88"
    assert ref.record_id is None


def test_evidence_reference_round_trip():
    d = ok().ref.to_dict()
    assert d["tenant_id"] == TEN
    assert d["raw_id"] == RAW
    assert d["record_id"] == OBS
    assert d["sub_key"] == ACT
    assert d["store"] == STORE_SHADOW_OBSERVATION
    assert d["stable_key"] == ok().ref.stable_key()


def test_stable_key_is_replay_stable_across_generations():
    a = ok().ref
    from dataclasses import replace
    assert replace(a, generation=7).stable_key() == a.stable_key()


def test_activity_identity_is_preserved_as_the_sub_key():
    assert ok().ref.sub_key == ACT
    assert ok(event_id="act_other").ref.stable_key() != ok().ref.stable_key()


def test_missing_raw_reference_fails_closed_rather_than_substituting_one():
    rec, why = to_evidence_record(row(), tenant_id=TEN, endpoint_id=EP)
    assert rec is None and why == REFUSED_NO_RAW_REF


# ── process identity, no inference ───────────────────────────────────────

def test_process_ref_is_built_only_from_stated_evidence():
    p = ok().process
    assert p.process_iid == "pk_8812"
    assert p.process_guid == "{a1b2}"
    assert p.parent_process_guid == "{p0p0}"
    assert p.attribution_state == "SOURCE_PROCESS_GUID"


def test_absent_parent_is_absent_not_inferred():
    rec = ok(parent={}, parent_key=None, parent_identity=None)
    assert rec.process.parent_pid is None
    assert rec.process.parent_process_guid is None


def test_no_process_evidence_yields_no_process_ref():
    rec = ok(kind="DNS_QUERY", process={}, parent={}, process_key=None,
             process_identity=None, parent_key=None,
             network={"query": "a.test"})
    assert rec.process is None


# ── missing evidence stays missing ───────────────────────────────────────

def test_absent_fields_are_omitted_never_emptied():
    rec = ok(process={"pid": "9", "image": None, "command_line": "",
                      "user": None, "sha256": None})
    assert "process" not in rec.fields          # nothing left to carry
    assert "user" not in rec.fields
    for path in ("process.name", "process.executable_path",
                 "process.command_line", "user.name"):
        assert P.get_field(rec, path) is None, path


def test_a_structurally_incompatible_source_container_fails_closed():
    """A scalar where the evidence contract says object is a SOURCE defect: it
    is refused, never coerced and never silently dropped."""
    for bad in ({"process": "chrome.exe"}, {"file": "C:/a.exe"},
                {"network": 443}, {"parent": []}):
        rec, why = to_evidence_record(row(**bad), tenant_id=TEN,
                                      endpoint_id=EP, raw_id=RAW)
        assert rec is None and why == REFUSED_FIELD_SHAPE, bad


def test_two_source_values_colliding_on_one_canonical_path_fail_closed():
    rec, why = to_evidence_record(
        row(kind="DETECTION", detection="not-an-object"), tenant_id=TEN,
        endpoint_id=EP, raw_id=RAW)
    assert rec is None and why == REFUSED_FIELD_SHAPE
    assert REFUSED_FIELD_COLLISION == \
        "SOURCE_FIELDS_COLLIDE_ON_ONE_CANONICAL_PATH"


def test_native_types_are_preserved_not_stringified():
    rec = ok(kind="NETWORK_CONNECT",
             network={"dest_ip": "10.1.1.1", "dest_port": 443,
                      "initiated": True})
    assert P.get_field(rec, "network.dest_port") == 443
    assert isinstance(P.get_field(rec, "network.dest_port"), int)
    assert P.get_field(rec, "network.initiated") is True
    det = ok(kind="DETECTION", detection={"rule_id": "R-1", "score": 7,
                                          "tags": ["a", "b"]})
    assert P.get_field(det, "detection.score") == 7
    assert P.get_field(det, "detection.tags") == ["a", "b"]


def test_not_observed_not_supported_and_truncated_are_preserved():
    rec = ok(not_observed=["actor_process"], not_supported=["signer"],
             truncated_fields=["command_line"])
    assert rec.not_observed == ("actor_process",)
    assert rec.not_supported == ("signer",)
    assert rec.truncated_fields == ("command_line",)


def test_provenance_is_preserved_with_store_and_reference():
    prov = ok().provenance
    assert prov["store"] == "v2_shadow_observations"
    assert prov["ref"] == OBS
    assert prov["label"] == "windows-sysmon"
    assert prov["evidence_stores"] == ["v2_shadow_observations"]
    assert prov["sd_activity_family"] == "PROCESS_START"


# ── fail closed ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("tenant", [None, "", "   "])
def test_missing_tenant_fails_closed(tenant):
    rec, why = to_evidence_record(row(), tenant_id=tenant, endpoint_id=EP,
                                  raw_id=RAW)
    assert rec is None and why == REFUSED_NO_TENANT


@pytest.mark.parametrize("endpoint", [None, "", "  "])
def test_missing_endpoint_fails_closed(endpoint):
    rec, why = to_evidence_record(row(), tenant_id=TEN, endpoint_id=endpoint,
                                  raw_id=RAW)
    assert rec is None and why == REFUSED_NO_ENDPOINT


def test_missing_stored_observation_time_fails_closed():
    r = row()
    r.pop("observed_us")
    r["observed_ms"] = None
    rec, why = to_evidence_record(r, tenant_id=TEN, endpoint_id=EP, raw_id=RAW)
    assert rec is None and why == REFUSED_NO_TIME


def test_ingest_time_alone_cannot_rescue_a_row_with_no_observation_time():
    r = row(ingested_ms=US // 1000)
    r.pop("observed_us")
    r["observed_ms"] = None
    rec, why = to_evidence_record(r, tenant_id=TEN, endpoint_id=EP, raw_id=RAW)
    assert rec is None and why == REFUSED_NO_TIME


@pytest.mark.parametrize("family", ["OTHER", "", None, "SOMETHING_NEW",
                                    "process_create"])
def test_unsupported_or_malformed_family_fails_closed(family):
    rec, why = to_evidence_record(row(kind=family), tenant_id=TEN,
                                  endpoint_id=EP, raw_id=RAW)
    assert rec is None and why == REFUSED_KIND


# ── purity ───────────────────────────────────────────────────────────────

def test_source_row_is_not_mutated():
    r = row()
    before = copy.deepcopy(r)
    to_evidence_record(r, tenant_id=TEN, endpoint_id=EP, raw_id=RAW)
    assert r == before


def test_mutating_the_record_provenance_does_not_reach_back_into_the_row():
    r = row()
    rec, _ = to_evidence_record(r, tenant_id=TEN, endpoint_id=EP, raw_id=RAW)
    rec.provenance["store"] = "TAMPERED"
    assert r["provenance"]["store"] == "v2_shadow_observations"


def test_conversion_is_deterministic():
    a, b = ok(), ok()
    assert a.ref.to_dict() == b.ref.to_dict()
    assert a.fields == b.fields
    assert a.event_time == b.event_time


def test_adapter_does_not_import_the_behavior_runtime():
    """Checked in a CLEAN interpreter: a session-wide sys.modules check would
    be satisfied by whatever another test imported."""
    import subprocess
    import sys as _s
    out = subprocess.run(
        [_s.executable, "-c",
         "import sys; import edr_plane.behavior_evidence_adapter;"
         "print(sorted(m for m in sys.modules if m.startswith('edr_behavior')))"],
        capture_output=True, text=True, cwd=str(
            __import__("pathlib").Path(__file__).resolve().parents[2]))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "['edr_behavior', 'edr_behavior.contracts']"


def test_adapter_module_references_no_db_network_or_findings_intake():
    from pathlib import Path
    src = Path(__file__).resolve().parents[2] / "edr_plane" / \
        "behavior_evidence_adapter.py"
    text = src.read_text()
    for forbidden in ("motor", "find_one", "aiohttp", "requests",
                      "record_endpoint_detection", "sync_collection",
                      "resolve_endpoint", "datetime.now", "utcnow"):
        assert forbidden not in text, forbidden
