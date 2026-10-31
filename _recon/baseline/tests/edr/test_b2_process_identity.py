"""B2 · PROCESS IDENTITY invariants.

What this file pins:

* `ProcessGuid` is the preferred authority; PID alone is NEVER authority;
* PID reuse produces TWO processes, and the reuse is REPORTED;
* tenant and endpoint are identity boundaries;
* parentage exists only where the SOURCE stated it — a parent PID with no
  parent identity is DESCRIBED and never resolved, and nothing is
  inferred from time, name or row adjacency;
* termination is an EVENT. With none collected the lifetime is UNKNOWN,
  and the last observation is never read as an exit.
"""
from __future__ import annotations

import sys

sys.path.insert(0, "/app/backend")

from edr_plane import canonical_bridge                          # noqa: E402
from edr_plane import process_identity as pi                    # noqa: E402
from tests.edr import fixtures_windows_eventlog as fx           # noqa: E402
from v2.ingestion.telemetry_bridge import observation_doc       # noqa: E402

TENANT = "ten_b2"
ENDPOINT = "ep_b2"
GUID_A = "{aaaaaaaa-0000-0000-0000-00000000000a}"
GUID_B = "{bbbbbbbb-0000-0000-0000-00000000000b}"
PARENT_GUID = "{cccccccc-0000-0000-0000-00000000000c}"


def view(**kw) -> pi.ProcessView:
    base = {"tenant_id": TENANT, "endpoint_id": ENDPOINT,
            "kind": "process_create", "observed_at": "2026-06-01T10:00:00Z"}
    return pi.ProcessView(**{**base, **kw})


# ── A · the authority ladder ─────────────────────────────────────────
def test_a_source_process_guid_is_the_preferred_authority():
    got = pi.resolve_identity(view(process_guid=GUID_A, pid="1000"))
    assert got.authority == pi.AUTHORITY_SOURCE_GUID
    assert got.is_authoritative
    assert got.process_key
    assert "process_guid" in got.identity_basis


def test_endpoint_pid_and_start_time_are_a_supporting_authority():
    got = pi.resolve_identity(view(pid="1000",
                                   start_time="2026-06-01T09:59:00Z"))
    assert got.authority == pi.AUTHORITY_ENDPOINT_PID_START
    assert got.is_authoritative
    assert set(got.identity_basis) == {"tenant_id", "endpoint_id", "pid",
                                       "start_time"}


def test_a_pid_alone_is_never_an_identity():
    got = pi.resolve_identity(view(pid="1000"))
    assert got.authority == pi.AUTHORITY_PID_ONLY
    assert got.is_authoritative is False
    assert got.process_key is None, (
        "a PID-only observation must not mint a process key — it would be "
        "indistinguishable from an identity")
    assert "reused" in got.reason


def test_an_observation_with_no_process_is_not_observed():
    got = pi.resolve_identity(view())
    assert got.authority == pi.AUTHORITY_NOT_OBSERVED
    assert got.process_key is None


def test_a_pid_only_observation_is_never_merged_into_a_process():
    out = pi.build([view(process_guid=GUID_A, pid="1000"),
                    view(pid="1000", kind="network_connect",
                         evidence_ref="obs_pidonly")])
    assert out["counts"]["processes"] == 1
    assert out["counts"]["unattributed_observations"] == 1
    assert out["unattributed_observations"][0]["authority"] == \
        pi.AUTHORITY_PID_ONLY


# ── B · PID reuse ────────────────────────────────────────────────────
def test_pid_reuse_yields_two_processes_and_is_reported():
    out = pi.build([
        view(process_guid=GUID_A, pid="4242", evidence_ref="obs_1"),
        view(process_guid=GUID_B, pid="4242", evidence_ref="obs_2",
             observed_at="2026-06-01T10:30:00Z"),
    ])
    assert out["counts"]["processes"] == 2
    assert len(out["pid_reuse"]) == 1
    assert out["pid_reuse"][0]["pid"] == "4242"
    assert out["pid_reuse"][0]["count"] == 2


def test_the_same_pid_with_two_start_times_is_two_processes():
    a = pi.resolve_identity(view(pid="7", start_time="2026-06-01T10:00:00Z"))
    b = pi.resolve_identity(view(pid="7", start_time="2026-06-01T10:05:00Z"))
    assert a.process_key != b.process_key


# ── C · identity boundaries ──────────────────────────────────────────
def test_the_tenant_is_an_identity_boundary():
    a = pi.resolve_identity(view(process_guid=GUID_A))
    b = pi.resolve_identity(view(process_guid=GUID_A, tenant_id="ten_other"))
    assert a.process_key != b.process_key


def test_the_endpoint_is_an_identity_boundary_for_pid_based_identity():
    a = pi.resolve_identity(view(pid="9", start_time="t0"))
    b = pi.resolve_identity(view(pid="9", start_time="t0",
                                 endpoint_id="ep_other"))
    assert a.process_key != b.process_key


# ── D · parentage ────────────────────────────────────────────────────
def test_a_parent_guid_resolves_to_the_same_key_as_the_parent_itself():
    child = view(process_guid=GUID_A, pid="2", parent_process_guid=GUID_B,
                 parent_pid="1")
    parent = view(process_guid=GUID_B, pid="1")
    got = pi.resolve_parent(child)
    assert got.basis == pi.PARENT_BY_SOURCE_GUID
    assert got.parent_key == pi.resolve_identity(parent).process_key


def test_a_parent_pid_without_a_parent_identity_is_described_not_resolved():
    got = pi.resolve_parent(view(process_guid=GUID_A, parent_pid="1",
                                 parent_image=r"C:\Windows\explorer.exe"))
    assert got.basis == pi.PARENT_BY_SOURCE_PID
    assert got.parent_key is None, (
        "resolving a parent from a PID alone is how a fabricated process "
        "tree gets built")
    assert "reused" in got.reason


def test_the_kernel_boundary_is_a_real_root_not_a_missing_parent():
    got = pi.resolve_parent(view(process_guid=GUID_A, parent_pid="0"))
    assert got.basis == pi.PARENT_KERNEL_BOUNDARY
    assert got.parent_key is None


def test_no_parentage_is_inferred_from_timestamp_or_name_proximity():
    """Two processes seconds apart, no parent field stated by the source."""
    out = pi.build([
        view(process_guid=GUID_A, pid="10", image=r"C:\a\powershell.exe",
             observed_at="2026-06-01T10:00:00Z"),
        view(process_guid=GUID_B, pid="11", image=r"C:\a\cmd.exe",
             observed_at="2026-06-01T10:00:01Z"),
    ])
    assert out["relationships"] == [], (
        "a relationship was invented from proximity alone")


def test_a_relationship_keeps_its_evidence_and_its_derivation_basis():
    out = pi.build([view(process_guid=GUID_A, pid="2",
                         parent_process_guid=PARENT_GUID,
                         evidence_ref="obs_child")])
    edge = out["relationships"][0]
    assert edge["basis"] == pi.PARENT_BY_SOURCE_GUID
    assert edge["evidence_refs"] == ["obs_child"]
    assert edge["resolved"] is True
    assert edge["reason"]


# ── E · lifetime ─────────────────────────────────────────────────────
def test_a_process_with_no_termination_event_has_an_unknown_lifetime():
    life = pi.lifecycle([
        view(process_guid=GUID_A, kind="process_create",
             observed_at="2026-06-01T10:00:00Z"),
        view(process_guid=GUID_A, kind="network_connect",
             observed_at="2026-06-01T10:09:00Z"),
    ])
    assert life["start"]["state"] == pi.PROCESS_START_OBSERVED
    assert life["termination"]["state"] == pi.PROCESS_TERMINATION_NOT_OBSERVED
    assert life["lifetime_state"] == pi.PROCESS_LIFETIME_UNKNOWN
    # the span is evidence, NOT a lifetime
    assert life["observed_evidence_span"]["last_observed_at"] == \
        "2026-06-01T10:09:00Z"
    assert "not an exit" in life["lifetime_reason"]


def test_termination_is_only_ever_a_collected_event():
    life = pi.lifecycle([
        view(process_guid=GUID_A, kind="process_create",
             observed_at="2026-06-01T10:00:00Z"),
        view(process_guid=GUID_A, kind="process_exit",
             observed_at="2026-06-01T10:10:00Z", evidence_ref="obs_exit"),
    ])
    assert life["lifetime_state"] == pi.PROCESS_TERMINATION_OBSERVED
    assert life["termination"]["observed_at"] == "2026-06-01T10:10:00Z"
    assert life["termination"]["evidence_ref"] == "obs_exit"


def test_a_process_seen_only_in_later_activity_has_no_observed_start():
    life = pi.lifecycle([view(process_guid=GUID_A, kind="dns_query",
                              observed_at="2026-06-01T10:00:00Z")])
    assert life["start"]["state"] == pi.PROCESS_START_NOT_OBSERVED
    assert life["lifetime_state"] == pi.PROCESS_LIFETIME_UNKNOWN


# ── F · it consumes the REAL read model (B1 output) ──────────────────
def _projected(event_id: int, record_id: int, data: dict) -> dict:
    canonical = canonical_bridge.parse(fx.sysmon(event_id, record_id, data))
    canonical_bridge.bind_process_identity(canonical, ENDPOINT)
    canonical["event_id"] = f"cev_b2_{record_id}"
    canonical["additional_fields"]["endpoint_id"] = ENDPOINT
    return observation_doc(
        canonical,
        envelope={"connector_id": ENDPOINT, "collector_id": ENDPOINT,
                  "source": "nivxforge-windows-sensor",
                  "collection_method": "WINDOWS_EVENT_LOG",
                  "parser_version": "1.0.0", "source_event_id": "cev_b2",
                  "collection_timestamp": "2026-06-01T10:04:00+00:00"},
        tenant_id=TENANT)


def test_identity_resolves_from_a_real_projected_observation():
    doc = _projected(1, 7001, {
        "UtcTime": "2026-06-01 10:04:00.123", "ProcessGuid": GUID_A,
        "ProcessId": "7364", "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": "cmd /c whoami", "ParentProcessGuid": PARENT_GUID,
        "ParentProcessId": "4120", "ParentImage": r"C:\Windows\explorer.exe",
    })
    v = pi.from_observation(doc)
    assert v.process_guid == GUID_A
    assert v.parent_process_guid == PARENT_GUID
    assert v.pid == "7364"
    assert v.kind == "process_create"
    ident = pi.resolve_identity(v)
    assert ident.authority == pi.AUTHORITY_SOURCE_GUID
    assert pi.resolve_parent(v).basis == pi.PARENT_BY_SOURCE_GUID


def test_the_canonical_and_projected_dialects_resolve_to_the_same_identity():
    data = {"UtcTime": "2026-06-01 10:04:00.123", "ProcessGuid": GUID_A,
            "ProcessId": "7364", "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "cmd /c whoami"}
    canonical = canonical_bridge.parse(fx.sysmon(1, 7002, data))
    canonical_bridge.bind_process_identity(canonical, ENDPOINT)
    canonical["event_id"] = "cev_b2_7002"
    canonical["additional_fields"]["endpoint_id"] = ENDPOINT
    from_authority = pi.resolve_identity(
        pi.from_canonical(canonical, tenant_id=TENANT))
    from_read_model = pi.resolve_identity(pi.from_observation(_projected(
        1, 7002, data)))
    assert from_authority.process_key == from_read_model.process_key
    assert from_authority.authority == from_read_model.authority


def test_a_windows_4688_process_create_is_pid_only_and_says_so():
    """4688 carries NO ProcessGuid. The downgrade is the honest outcome."""
    payload = fx.winsec(4688, 7003, {
        "SubjectUserName": "svc-admin", "NewProcessId": "0x1cc4",
        "NewProcessName": r"C:\Windows\System32\cmd.exe",
        "CreatorProcessId": "0x1018",
        "CreatorProcessName": r"C:\Windows\explorer.exe",
        "CommandLine": "cmd /c whoami",
    })
    canonical = canonical_bridge.parse(payload)
    canonical_bridge.bind_process_identity(canonical, ENDPOINT)
    v = pi.from_canonical(canonical, tenant_id=TENANT, endpoint_id=ENDPOINT)
    ident = pi.resolve_identity(v)
    assert v.process_guid == ""
    assert ident.authority in (pi.AUTHORITY_PID_ONLY,
                               pi.AUTHORITY_ENDPOINT_PID_START)
    if ident.authority == pi.AUTHORITY_PID_ONLY:
        assert ident.process_key is None
