"""Wave 0 acceptance tests.

These do not test that code runs. They test that the code makes DISHONESTY
IMPOSSIBLE — which is the only claim Wave 0 actually makes:

  * an evidence field cannot be silently null
  * a response cannot claim success without endpoint evidence
  * a capability cannot claim more than the repo can prove
  * raw telemetry cannot be overwritten
  * the 43-item baseline cannot be silently faked
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from edr_plane.capability import INVENTORY, SENSOR_REGISTRY, summary, taxonomy
from edr_plane.capability.model import (Capability, ComponentStatus, FeatureState,
                                  GapClass, Plane, SensorCapability)
from edr_plane.contracts import CONTRACTS
from edr_plane.contracts.epistemic import (EPISTEMIC_ABSENT, EpistemicState,
                                     FORBIDDEN_EQUIVALENCES, absent)
from edr_plane.contracts.identity import (EndpointIdentity, EventIdentity,
                                    FileIdentity, LINEAGE_PRESENTATION,
                                    ProcessIdentity)
from edr_plane.contracts.response import (EnforcementResult, ResponseAction,
                                    ResponseCommand, ResponseLifecycle,
                                    ResponseResult)
from edr_plane.contracts.health import (NivxTelemetryHealth, TO_DIRECTIVE_TELEMETRY,
                                  TelemetryHealthContract)
from edr_plane.contracts.schema_export import export_all, manifest
from edr_plane.contracts.telemetry import EndpointEvidence, Platform
from edr_plane.raw_events import Derivation, RawEndpointEvent


# ── the twelve contracts exist and are executable ─────────────────

def test_all_twelve_contracts_are_executable():
    assert len(CONTRACTS) == 10, CONTRACTS.keys()
    # 10 evidence/response contracts + the 2 registry contracts
    assert Capability and SensorCapability


def test_every_contract_exports_json_schema():
    schemas = export_all()
    assert set(schemas) == set(CONTRACTS)
    for name, s in schemas.items():
        assert s["$id"].endswith(f"{name}.schema.json")
        assert "x-nivxforge-epistemic-states" in s


def test_manifest_publishes_the_six_forbidden_equivalences():
    m = manifest()
    assert len(m["forbidden_equivalences"]) == 6
    assert len(FORBIDDEN_EQUIVALENCES) == 6


# ── §6 · a null evidence field must state WHY ─────────────────────

def test_null_evidence_field_without_state_is_rejected():
    with pytest.raises(ValidationError) as e:
        ProcessIdentity(process_iid="proc_x", endpoint_id="ep_x")
    msg = str(e.value)
    assert "epistemic state" in msg
    assert "sha256" in msg or "pid" in msg


def test_null_evidence_field_with_declared_state_is_accepted():
    p = ProcessIdentity(
        process_iid="proc_x", endpoint_id="ep_x", pid=4242,
        **_all_absent(ProcessIdentity, keep={"pid"},
                      state=EpistemicState.NOT_COLLECTED,
                      reason="CEF carries no such field"))
    assert p.is_observed("pid")
    assert not p.is_observed("sha256")
    assert p.state_of("sha256") == EpistemicState.NOT_COLLECTED


def test_present_value_is_auto_stamped_observed():
    p = ProcessIdentity(
        process_iid="p", endpoint_id="e", pid=1, image="cmd.exe",
        **_all_absent(ProcessIdentity, keep={"pid", "image"},
                      state=EpistemicState.NOT_OBSERVED, reason="not seen"))
    assert p.field_states["image"] == EpistemicState.OBSERVED.value


def test_declaring_observed_on_a_null_field_is_rejected():
    kw = _all_absent(ProcessIdentity, keep={"pid"},
                     state=EpistemicState.NOT_COLLECTED, reason="n/a")
    kw["field_states"]["sha256"] = EpistemicState.OBSERVED
    with pytest.raises(ValidationError) as e:
        ProcessIdentity(process_iid="p", endpoint_id="e", pid=1, **kw)
    assert "OBSERVED asserts a value exists" in str(e.value)


def test_presentation_never_returns_an_empty_field():
    p = ProcessIdentity(
        process_iid="p", endpoint_id="e", pid=1,
        **_all_absent(ProcessIdentity, keep={"pid"},
                      state=EpistemicState.NOT_COLLECTED,
                      reason="source does not hash file content"))
    pres = p.presentation("sha256")
    assert pres["value"] is None
    assert pres["glyph"] == "⊘"
    assert "does not hash" in pres["reason"]


@pytest.mark.parametrize("state", sorted(EPISTEMIC_ABSENT, key=lambda s: s.value))
def test_every_absent_state_yields_a_glyph_and_a_reason(state):
    p = ProcessIdentity(
        process_iid="p", endpoint_id="e", pid=1,
        **_all_absent(ProcessIdentity, keep={"pid"}, state=state,
                      reason=f"declared {state.value}"))
    pres = p.presentation("command_line")
    assert pres["glyph"], state
    assert pres["reason"]


# ── §8 · lineage is evidence-based, never invented ────────────────

def test_the_three_lineage_states_are_the_only_ones():
    assert set(LINEAGE_PRESENTATION) == {
        "PARENT_OBSERVED", "PARENT_NOT_OBSERVED",
        "PARENT_LINEAGE_INCOMPLETE_PARSER_FAILED"}
    assert LINEAGE_PRESENTATION["PARENT_NOT_OBSERVED"] == \
        "[ROOT / PARENT NOT OBSERVED]"


def test_process_identity_requires_a_pid():
    with pytest.raises(ValueError, match="without a PID"):
        ProcessIdentity.mint(endpoint_id="e", pid=None, start_time=None)


def test_process_iid_includes_start_time_so_pid_reuse_cannot_collide():
    a = ProcessIdentity.mint(endpoint_id="e", pid=1000,
                             start_time="2026-06-01T10:00:00Z")
    b = ProcessIdentity.mint(endpoint_id="e", pid=1000,
                             start_time="2026-06-01T11:00:00Z")
    assert a != b


# ── endpoint identity: an IP is never an endpoint ─────────────────

def test_endpoint_id_prefers_hardware_over_hostname():
    hw = EndpointIdentity.mint(tenant_id="t", processor_id="CPU1",
                               hostname="HOST")
    host = EndpointIdentity.mint(tenant_id="t", hostname="HOST")
    assert hw != host


def test_endpoint_id_cannot_be_minted_without_a_durable_attribute():
    with pytest.raises(ValueError, match="unattributed observation"):
        EndpointIdentity.mint(tenant_id="t")


def test_file_identity_degrades_honestly_without_a_hash():
    named = FileIdentity.mint(filename="evil.exe")
    assert named.startswith("filename_")
    hashed = FileIdentity.mint(sha256="a" * 64)
    assert hashed.startswith("file_")


# ── §10 · response cannot claim success without evidence ──────────

def _result() -> ResponseResult:
    return ResponseResult(
        result_id="r1", command_id="c1", tenant_id="t",
        endpoint_id="ep", action=ResponseAction.KILL_PROCESS,
        **absent({k: (EpistemicState.NOT_OBSERVED, "not yet")
                  for k in ResponseResult.evidence_fields()}))


def test_there_is_no_succeeded_lifecycle_state():
    assert not hasattr(ResponseLifecycle, "SUCCEEDED")
    assert "SUCCEEDED" not in {s.value for s in ResponseLifecycle}


def test_response_cannot_jump_from_requested_to_verified():
    r = _result()
    with pytest.raises(ValueError, match="illegal response transition"):
        r.advance(ResponseLifecycle.VERIFIED)


def test_response_cannot_be_verified_without_endpoint_evidence():
    r = _result()
    with pytest.raises(ValueError, match="never report success"):
        r.verify(evidence_ref="")


def test_full_response_loop_reaches_verified_only_with_evidence():
    r = _result()
    for st in (ResponseLifecycle.AUTHORIZATION_PENDING,
               ResponseLifecycle.POLICY_EVALUATION,
               ResponseLifecycle.APPROVAL_PENDING,
               ResponseLifecycle.DISPATCHED,
               ResponseLifecycle.ENDPOINT_ACKED,
               ResponseLifecycle.EXECUTING,
               ResponseLifecycle.EXECUTED_UNVERIFIED):
        r.advance(st)
    assert not r.succeeded
    r.verify(evidence_ref="evt_proof_123")
    assert r.succeeded
    assert r.enforcement_result == EnforcementResult.VERIFIED
    assert len(r.transitions) == 8


def test_driverless_action_terminates_at_driver_not_registered():
    r = _result()
    r.advance(ResponseLifecycle.DRIVER_NOT_REGISTERED)
    assert not r.succeeded
    with pytest.raises(ValueError, match="terminal"):
        r.advance(ResponseLifecycle.DISPATCHED)


def test_response_command_carries_the_full_audit_record():
    c = ResponseCommand(
        command_id="c", tenant_id="t", endpoint_id="e",
        action=ResponseAction.ISOLATE, requested_by="analyst@x",
        requested_at=ResponseCommand.now(), reason="confirmed C2 beacon")
    for f in ("requested_by", "approved_by", "policy_id", "policy_mode",
              "playbook_id", "reason", "requested_at"):
        assert f in c.model_dump()


# ── §7 · health: two dimensions, never collapsed ──────────────────

def test_health_contract_has_no_collapsed_summary_field():
    fields = set(TelemetryHealthContract.model_fields)
    for forbidden in ("overall", "status", "healthy", "health", "state"):
        assert forbidden not in fields, forbidden


def test_health_contract_adapts_the_shipped_resolver():
    from services.edr.endpoint_health import resolve_endpoint_health
    resolved = resolve_endpoint_health(agent=None, last_telemetry_at=None)
    c = TelemetryHealthContract.from_resolver(resolved, endpoint_id="ep")
    assert c.agent_lifecycle.state == "NO_AGENT"
    assert c.telemetry_health.state == "NEVER_ENROLLED"
    assert c.agent_lifecycle.reason and c.telemetry_health.reason


def test_nine_state_health_is_finer_than_the_directive_six():
    assert len(NivxTelemetryHealth) == 9
    assert len(set(TO_DIRECTIVE_TELEMETRY.values())) < len(NivxTelemetryHealth)
    # the three that would be flattened, and must not be
    flattened = {NivxTelemetryHealth.ISOLATED, NivxTelemetryHealth.UNENROLLED,
                 NivxTelemetryHealth.NEVER_ENROLLED}
    assert len({TO_DIRECTIVE_TELEMETRY[f] for f in flattened}) == 1


# ── §5 · raw telemetry is immutable and replayable ────────────────

def test_raw_event_dedup_key_is_the_verbatim_payload_digest():
    a = RawEndpointEvent.build(tenant_id="t", source="s", payload="LINE")
    b = RawEndpointEvent.build(tenant_id="t", source="s", payload="LINE")
    assert a.dedup_key == b.dedup_key and a.raw_id == b.raw_id
    c = RawEndpointEvent.build(tenant_id="t", source="s", payload="LINE ")
    assert c.dedup_key != a.dedup_key


def test_raw_events_module_exposes_no_update_or_delete():
    from edr_plane import raw_events
    names = set(dir(raw_events))
    for forbidden in ("update", "delete", "overwrite", "replace", "set_payload"):
        assert forbidden not in names, forbidden
    assert {"append", "add_derivation", "replay_candidates"} <= names


def test_derivation_carries_every_version_stamp():
    d = Derivation(derived_at=RawEndpointEvent.now())
    for f in ("parser_version", "normalizer_version",
              "detection_content_version", "analysis_version",
              "verdict_version", "replay_generation", "parser_state"):
        assert f in d.model_dump()


def test_parser_failure_still_produces_a_retained_record():
    d = Derivation(derived_at=RawEndpointEvent.now(), parser_state="FAILED",
                   parser_notes=["unterminated CEF extension"])
    assert d.parser_state == "FAILED"
    ev = RawEndpointEvent.build(tenant_id="t", source="s", payload="garbage")
    assert ev.payload == "garbage"  # bytes preserved despite the failure


def test_rejected_payload_is_retained_but_untrusted():
    ev = RawEndpointEvent.build(tenant_id="t", source="rogue",
                                payload="X", trust_state="REJECTED")
    assert ev.trust_state == "REJECTED"
    assert ev.payload == "X"


# ── §14 · a capability cannot over-claim ──────────────────────────

def test_capability_claiming_operational_without_telemetry_is_downgraded():
    c = Capability(
        capability_id="x", plane=Plane.BACKEND, domain="d", name="n",
        description="d", declared_state=FeatureState.OPERATIONAL,
        backend_status=ComponentStatus.PRESENT,
        telemetry_status=ComponentStatus.ABSENT,
        e2e_status=ComponentStatus.ABSENT,
        evidence_reference="somewhere.py")
    assert c.effective_state == FeatureState.BACKEND_IMPLEMENTED
    assert "no endpoint evidence" in c.downgrade_reason
    assert not c.claim_is_honest


def test_capability_with_ui_but_no_backend_is_ui_only():
    c = Capability(
        capability_id="x", plane=Plane.EXPERIENCE, domain="d", name="n",
        description="d", declared_state=FeatureState.BACKEND_IMPLEMENTED,
        ui_status=ComponentStatus.PRESENT,
        backend_status=ComponentStatus.ABSENT,
        evidence_reference="Page.jsx")
    assert c.effective_state == FeatureState.UI_IMPLEMENTED
    assert c.gap_class == GapClass.UI_ONLY


def test_capability_claim_without_evidence_reference_is_downgraded():
    c = Capability(
        capability_id="x", plane=Plane.BACKEND, domain="d", name="n",
        description="d", declared_state=FeatureState.BACKEND_IMPLEMENTED,
        backend_status=ComponentStatus.PRESENT)
    assert c.effective_state == FeatureState.CONTRACT_DEFINED
    assert "no evidence_reference" in c.downgrade_reason


def test_inventory_covers_all_three_planes_and_is_large_enough():
    s = summary()
    assert s["total"] >= 90, s["total"]
    assert set(s["by_plane"]) == {"AGENT", "BACKEND", "EXPERIENCE"}


def test_every_non_absent_status_row_cites_evidence():
    offenders = [
        c.capability_id for c in INVENTORY
        if c.effective_state not in (FeatureState.NOT_IMPLEMENTED,
                                     FeatureState.CONTRACT_DEFINED)
        and not c.evidence_reference]
    assert not offenders, offenders


def test_the_real_linux_sensor_is_registered_with_honest_limits():
    """Was 'no sensor is registered' at Wave 0 — correct then. P0-B
    delivered a real Linux sensor, so the invariant is now that whatever
    IS registered declares its limits truthfully."""
    assert len(SENSOR_REGISTRY) == 1
    s = SENSOR_REGISTRY[0]
    assert s.platform == "LINUX"
    assert set(s.collects) == {"PROCESS", "FILE", "NETWORK"}
    assert s.attested_by and "live /proc" in s.attested_by
    # No response driver, so every action must read ⊘ NOT REGISTERED.
    assert s.response_actions == []
    # The fields it genuinely cannot produce resolve NOT_SUPPORTED, never
    # NOT_OBSERVED.
    for absent_field in ("process.exit_time", "process.signer",
                         "file.actor_process", "registry.key"):
        assert s.epistemic_for(absent_field) == "NOT_SUPPORTED"
    assert s.epistemic_for("process.ppid") == "OBSERVED"


def test_sensor_capability_reports_not_supported_for_unknown_fields():
    s = SensorCapability(sensor_id="s", platform="LINUX",
                         sensor_version="0.0.0",
                         fields_supported=["process.pid"])
    assert s.epistemic_for("process.pid") == "OBSERVED"
    assert s.epistemic_for("process.sha256") == "NOT_SUPPORTED"


# ── §11 · the 43-item baseline is pending, not faked ──────────────

def test_filter_taxonomy_is_pending_and_says_so():
    st = taxonomy.status()
    assert st["complete"] is False
    assert st["registered_item_count"] == 0
    assert st["expected_item_count"] == 43
    assert "must disclose" in st["disclosure"]
    assert len(st["categories"]) == 5


def test_taxonomy_refuses_a_partial_item_list():
    with pytest.raises(ValueError, match="exactly 43 items"):
        taxonomy.register_baseline_items(
            {"Activity": ["a", "b"]}, attested_by="owner")


def test_taxonomy_refuses_unknown_categories():
    with pytest.raises(ValueError, match="unknown categories"):
        taxonomy.register_baseline_items(
            {"Bogus": ["x"] * 43}, attested_by="owner")


def test_extension_dimensions_do_not_replace_the_baseline():
    st = taxonomy.status()
    assert len(st["extension_dimensions"]) == 20
    assert st["complete"] is False   # extensions cannot satisfy the baseline


# ── canonical evidence ties it together ───────────────────────────

def test_endpoint_evidence_requires_provenance_and_honest_absence():
    from edr_plane.contracts.epistemic import Provenance
    ev = EndpointEvidence(
        tenant_id="t", event_id="evt_1", dedup_key="d",
        ingest_time=EventIdentity.now(), event_type="process_start",
        platform=Platform.LINUX,
        provenance=Provenance(source="sensor-linux-01", parser_version="1"),
        **_all_absent(EndpointEvidence, keep=set(),
                      state=EpistemicState.NOT_COLLECTED,
                      reason="no sensor is enrolled"))
    assert ev.observed_activities() == ()
    assert ev.provenance.replay_generation == 0
    assert ev.presentation("process")["glyph"] == "⊘"


# ── helper ────────────────────────────────────────────────────────

def _all_absent(model, *, keep: set[str], state: EpistemicState,
                reason: str) -> dict:
    fields = [f for f in model.evidence_fields() if f not in keep]
    return absent({f: (state, reason) for f in fields})
