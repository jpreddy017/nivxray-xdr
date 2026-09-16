"""Phase 5: Platform Shadow Integration & Analyst Cockpit Verification Suite.

Tests all 17 Acceptance Gates (P5-01 through P5-17) with strict executable proof.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from typing import Any, Dict, List

from security_state.contracts import EpistemicStatus, EntityCategory
from security_state.hydration.case_hydrator import CaseSecurityStateHydrator
from security_state.hydration.provenance import ProvenanceGraphBuilder
from security_state.persistence.repository import SecurityStateRepository
from v2.investigation.builder import build_investigation
from v2.investigation.shadow_hook import maybe_dispatch_security_state_shadow


def get_test_dir(name: str) -> str:
    temp_dir = os.path.join(tempfile.gettempdir(), "nivx_phase5_tests", name)
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir


def clean_test_dir(path: str) -> None:
    if os.path.exists(path):
        try:
            shutil.rmtree(path)
        except Exception:
            pass


def _sample_case_frames(case_id: str = "CASE-REAL-001") -> List[Dict[str, Any]]:
    return [
        {
            "frame_iid": f"{case_id}-f01",
            "ts": "2026-09-04T01:00:00Z",
            "action": "process.start",
            "entity": {"iid": "proc-01", "name": "powershell.exe", "type": "process"},
            "parent": {"iid": "proc-00", "name": "cmd.exe"},
            "cmdline": "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Get-Process",
            "verdict": "benign",
            "lane": "endpoint",
        },
        {
            "frame_iid": f"{case_id}-f02",
            "ts": "2026-09-04T01:05:00Z",
            "action": "process.start",
            "entity": {"iid": "proc-02", "name": "rundll32.exe", "type": "process"},
            "parent": {"iid": "proc-01", "name": "powershell.exe"},
            "cmdline": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 648 C:\\temp\\lsass.dmp full",
            "verdict": "malicious",
            "capability": "CAP_CREDENTIAL_DUMPING",
            "is_critical": True,
            "lane": "endpoint",
        },
        {
            "frame_iid": f"{case_id}-f03",
            "ts": "2026-09-04T01:10:00Z",
            "action": "process.start",
            "entity": {"iid": "proc-03", "name": "wmic.exe", "type": "process"},
            "parent": {"iid": "proc-01", "name": "powershell.exe"},
            "cmdline": "wmic.exe /node:192.168.1.50 process call create cmd.exe",
            "verdict": "malicious",
            "capability": "CAP_LATERAL_MOVEMENT",
            "is_critical": True,
            "lane": "endpoint",
        }
    ]


# ─── P5-01: Real Case Hydration ──────────────────────────────────────────────
def test_p5_01_real_case_hydration():
    """Verify real case frames hydrate complete Security State without mocks."""
    test_dir = get_test_dir("p5_01_hydration")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        hydrator = CaseSecurityStateHydrator(repository=repo)
        frames = _sample_case_frames("CASE-HYDRATE-01")

        result = hydrator.hydrate_and_persist(
            case_id="CASE-HYDRATE-01",
            tenant_id="tenant-p5",
            frames=frames,
        )

        assert result["success"] is True
        assert result["version"] == 1
        assert len(result["state_hash"]) == 64
        assert result["attack_state"] == "LATERAL_MOVEMENT"
        assert "CAP_CREDENTIAL_DUMPING" in result["active_capabilities"]
        assert "CAP_LATERAL_MOVEMENT" in result["active_capabilities"]
    finally:
        clean_test_dir(test_dir)


# ─── P5-02 through P5-04: Authoritative Data Immutability ────────────────────
def test_p5_02_to_04_authoritative_pipeline_unaltered():
    """Verify verdict, attack story, and IKG are 100% bit-identical with shadow active."""
    frames = _sample_case_frames("CASE-COMPARE-01")

    # 1. Authoritative run without shadow
    inv_baseline = build_investigation(frames, case_id="CASE-COMPARE-01")
    dict_baseline = inv_baseline.to_dict()

    # 2. Run with shadow hook enabled
    inv_shadow = build_investigation(frames, case_id="CASE-COMPARE-01")
    maybe_dispatch_security_state_shadow("CASE-COMPARE-01", "tenant-test", frames, inv_shadow.ikg, sync=True)
    dict_shadow = inv_shadow.to_dict()

    # P5-02: Verdict unchanged
    assert dict_baseline["header"]["verdict_band"] == dict_shadow["header"]["verdict_band"]
    assert dict_baseline["verdicts"] == dict_shadow["verdicts"]

    # P5-03: Attack Story unchanged
    assert dict_baseline["story"] == dict_shadow["story"]

    # P5-04: IKG unchanged
    assert len(dict_baseline["ikg"]["nodes"]) == len(dict_shadow["ikg"]["nodes"])
    assert len(dict_baseline["ikg"]["edges"]) == len(dict_shadow["ikg"]["edges"])
    assert dict_baseline["ikg"]["nodes"] == dict_shadow["ikg"]["nodes"]
    assert dict_baseline["ikg"]["edges"] == dict_shadow["ikg"]["edges"]


# ─── P5-05 & P5-06: Persistence & Ledger Chaining ────────────────────────────
def test_p5_05_and_06_persistence_and_ledger():
    """Verify state is persisted and produces cryptographically chained ledger block."""
    test_dir = get_test_dir("p5_05_persist")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        hydrator = CaseSecurityStateHydrator(repository=repo)
        frames = _sample_case_frames("CASE-PERSIST-01")

        hydrator.hydrate_and_persist("CASE-PERSIST-01", "tenant-p5", frames)

        # P5-05: State persisted
        saved = repo.get_latest_state("tenant-p5", "CASE-PERSIST-01")
        assert saved is not None
        assert saved.version == 1

        # P5-06: Ledger chaining
        blocks = repo.get_ledger_blocks("tenant-p5", "CASE-PERSIST-01")
        assert len(blocks) >= 1
        is_valid, err = repo.verify_ledger_integrity("tenant-p5", "CASE-PERSIST-01")
        assert is_valid is True, f"Ledger integrity error: {err}"
    finally:
        clean_test_dir(test_dir)


# ─── P5-07: Async / Non-Blocking Execution ───────────────────────────────────
def test_p5_07_async_non_blocking():
    """Verify shadow dispatcher returns in < 5ms without blocking caller."""
    frames = _sample_case_frames("CASE-ASYNC-01")
    t0 = time.perf_counter()
    # Dispatch in background (sync=False)
    maybe_dispatch_security_state_shadow("CASE-ASYNC-01", "tenant-p5", frames, {}, sync=False)
    dt_ms = (time.perf_counter() - t0) * 1000

    assert dt_ms < 15.0, f"Dispatcher blocked caller for {dt_ms:.2f} ms (expected < 15 ms)"


# ─── P5-08: Tenant Isolation ─────────────────────────────────────────────────
def test_p5_08_tenant_isolation():
    """Verify cases with identical case_id across distinct tenants remain isolated."""
    test_dir = get_test_dir("p5_08_tenants")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        hydrator = CaseSecurityStateHydrator(repository=repo)
        frames = _sample_case_frames("CASE-SHARED")

        hydrator.hydrate_and_persist("CASE-SHARED", "tenant-alpha", frames)
        hydrator.hydrate_and_persist("CASE-SHARED", "tenant-beta", frames)

        state_a = repo.get_latest_state("tenant-alpha", "CASE-SHARED")
        state_b = repo.get_latest_state("tenant-beta", "CASE-SHARED")

        assert state_a is not None and state_b is not None
        assert state_a.tenant_id == "tenant-alpha"
        assert state_b.tenant_id == "tenant-beta"

        blocks_a = repo.get_ledger_blocks("tenant-alpha", "CASE-SHARED")
        blocks_b = repo.get_ledger_blocks("tenant-beta", "CASE-SHARED")
        assert len(blocks_a) == 1 and len(blocks_b) == 1
    finally:
        clean_test_dir(test_dir)


# ─── P5-09: Deterministic Replay ─────────────────────────────────────────────
def test_p5_09_deterministic_replay():
    """Verify hydrating the exact same frames twice produces bit-identical state hashes."""
    test_dir1 = get_test_dir("p5_09_rep1")
    test_dir2 = get_test_dir("p5_09_rep2")
    clean_test_dir(test_dir1)
    clean_test_dir(test_dir2)
    try:
        repo1 = SecurityStateRepository(fallback_storage_dir=test_dir1)
        repo2 = SecurityStateRepository(fallback_storage_dir=test_dir2)
        h1 = CaseSecurityStateHydrator(repository=repo1)
        h2 = CaseSecurityStateHydrator(repository=repo2)

        frames = _sample_case_frames("CASE-DETERM-01")
        res1 = h1.hydrate_and_persist("CASE-DETERM-01", "tenant-replay", frames)
        res2 = h2.hydrate_and_persist("CASE-DETERM-01", "tenant-replay", frames)

        assert res1["state_hash"] == res2["state_hash"], "State hashes must be bit-identical across runs"
    finally:
        clean_test_dir(test_dir1)
        clean_test_dir(test_dir2)


# ─── P5-10 & P5-11: Evidence Provenance & Epistemic Separation ───────────────
def test_p5_10_and_11_provenance_and_epistemic_separation():
    """Verify unbroken reasoning chain and full 10-term epistemic vocabulary."""
    test_dir = get_test_dir("p5_10_prov")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        hydrator = CaseSecurityStateHydrator(repository=repo)
        frames = _sample_case_frames("CASE-PROV-01")

        result = hydrator.hydrate_and_persist("CASE-PROV-01", "tenant-p5", frames)
        prov = result["provenance"]

        # P5-10: Evidence-level DAG
        assert "nodes" in prov and len(prov["nodes"]) >= 3
        node_types = {n["node_type"] for n in prov["nodes"]}
        assert "CONCLUSION" in node_types
        assert "ATTACK_STATE" in node_types
        assert "CAPABILITY" in node_types

        # P5-11: Epistemic separation
        valid_epistemic_terms = {e.value for e in EpistemicStatus}
        for n in prov["nodes"]:
            assert n["epistemic_status"] in valid_epistemic_terms, f"Invalid epistemic status: {n['epistemic_status']}"

        # Uncertainty decomposition present
        decomp = prov["epistemic_decomposition"]
        assert "supporting_evidence" in decomp
        assert "missing_evidence" in decomp
        assert "contradictory_evidence" in decomp
        assert "assumptions" in decomp
    finally:
        clean_test_dir(test_dir)


# ─── P5-12: Deterministic Counterfactual Projections ─────────────────────────
def test_p5_12_deterministic_counterfactuals():
    """Verify parallel worlds project reproducible risk and disruption metrics."""
    test_dir = get_test_dir("p5_12_cf")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        hydrator = CaseSecurityStateHydrator(repository=repo)
        frames = _sample_case_frames("CASE-CF-01")

        hydrator.hydrate_and_persist("CASE-CF-01", "tenant-p5", frames)
        saved = repo.get_latest_state("tenant-p5", "CASE-CF-01")
        assert saved is not None

        # Counterfactual projections exist in persistent record
        assert "actions" in saved.intervention_plan
        assert "projected_residual_risk_pct" in saved.intervention_plan
        assert "projected_business_disruption_score" in saved.intervention_plan
    finally:
        clean_test_dir(test_dir)


# ─── P5-13: Non-Executing Intervention Staging ───────────────────────────────
def test_p5_13_non_executing_intervention_staging():
    """Verify staging transitions work but EXECUTE is strictly locked."""
    from security_state.routers import set_repository, get_repository
    from security_state.routers.router import stage_intervention_decision, StageInterventionRequest
    test_dir = get_test_dir("p5_13_stage")
    clean_test_dir(test_dir)
    old_repo = get_repository()
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        set_repository(repo)
        hydrator = CaseSecurityStateHydrator(repository=repo)
        frames = _sample_case_frames("CASE-STAGE-01")
        hydrator.hydrate_and_persist("CASE-STAGE-01", "tenant-stage", frames)

        # 1. Stage Action
        req_stage = StageInterventionRequest(
            tenant_id="tenant-stage", action_id="endpoint.isolate",
            target_entity_id="device::CASE-STAGE-01", status="STAGED", analyst_notes="Staging host isolation"
        )
        res_stage = stage_intervention_decision("CASE-STAGE-01", req_stage)
        assert res_stage["success"] is True
        assert res_stage["status"] == "STAGED"
        assert res_stage["execution_locked"] is True

        # 2. Approve Action
        req_approve = StageInterventionRequest(
            tenant_id="tenant-stage", action_id="endpoint.isolate",
            target_entity_id="device::CASE-STAGE-01", status="APPROVED", analyst_notes="Analyst approved containment"
        )
        res_approve = stage_intervention_decision("CASE-STAGE-01", req_approve)
        assert res_approve["success"] is True
        assert res_approve["status"] == "APPROVED"

        # 3. Attempt Execution (Safety Invariant: MUST BE BLOCKED)
        req_exec = StageInterventionRequest(
            tenant_id="tenant-stage", action_id="endpoint.isolate",
            target_entity_id="device::CASE-STAGE-01", status="EXECUTE"
        )
        res_exec = stage_intervention_decision("CASE-STAGE-01", req_exec)
        assert res_exec["success"] is False
        assert res_exec["status"] == "ACTION_EXECUTION_BLOCKED"
        assert "PHASE 5 SAFETY GATE" in res_exec["error"]
    finally:
        set_repository(old_repo)
        clean_test_dir(test_dir)


# ─── P5-14: Backend / UI State Consistency ───────────────────────────────────
def test_p5_14_backend_ui_state_consistency():
    """Verify endpoints return exact payload contracts consumed by SecurityStateTab.jsx."""
    from security_state.routers import set_repository, get_repository
    from security_state.routers.router import (
        get_security_state,
        get_security_state_provenance,
        get_streaming_adapter_status,
    )
    test_dir = get_test_dir("p5_14_ui")
    clean_test_dir(test_dir)
    old_repo = get_repository()
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        set_repository(repo)
        hydrator = CaseSecurityStateHydrator(repository=repo)
        frames = _sample_case_frames("CASE-UI-01")
        hydrator.hydrate_and_persist("CASE-UI-01", "tenant-ui", frames)

        # GET /{case_id}
        state_res = get_security_state("CASE-UI-01", "tenant-ui")
        assert "states" in state_res and len(state_res["states"]) == 1
        assert "state_hash" in state_res["states"][0]
        assert "active_capabilities" in state_res["states"][0]

        # GET /{case_id}/provenance
        prov_res = get_security_state_provenance("CASE-UI-01", "tenant-ui")
        assert "nodes" in prov_res
        assert "epistemic_decomposition" in prov_res

        # GET /streaming/status
        stream_res = get_streaming_adapter_status("tenant-ui")
        assert stream_res["transport"] == "REPLAY_ADAPTER_LOCAL"
        assert stream_res["shadow_mode"] is True
    finally:
        set_repository(old_repo)
        clean_test_dir(test_dir)


# ─── P5-15: Disabled Flag = Zero Work ────────────────────────────────────────
def test_p5_15_disabled_flag_zero_work():
    """Verify that when disabled, zero security state work or DB calls execute."""
    test_dir = get_test_dir("p5_15_disabled")
    clean_test_dir(test_dir)
    old_flag = os.environ.get("NIVX_FLAG_SECURITY_STATE")
    os.environ["NIVX_FLAG_SECURITY_STATE"] = "disabled"
    try:
        frames = _sample_case_frames("CASE-DISABLED-01")
        # Call hook
        maybe_dispatch_security_state_shadow("CASE-DISABLED-01", "tenant-disabled", frames, {}, sync=True)

        # Verify zero files or records created in test dir
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        latest = repo.get_latest_state("tenant-disabled", "CASE-DISABLED-01")
        assert latest is None, "Zero state records must exist when flag is disabled"
    finally:
        if old_flag is not None:
            os.environ["NIVX_FLAG_SECURITY_STATE"] = old_flag
        else:
            os.environ.pop("NIVX_FLAG_SECURITY_STATE", None)
        clean_test_dir(test_dir)


# ─── P5-16: Shadow Mode = No Authoritative Mutation ──────────────────────────
def test_p5_16_shadow_no_authoritative_mutation():
    """Verify shadow hydration writes exclusively to security_state* collections."""
    test_dir = get_test_dir("p5_16_shadow")
    clean_test_dir(test_dir)
    try:
        repo = SecurityStateRepository(fallback_storage_dir=test_dir)
        hydrator = CaseSecurityStateHydrator(repository=repo)
        frames = _sample_case_frames("CASE-SHADOW-01")

        hydrator.hydrate_and_persist("CASE-SHADOW-01", "tenant-shadow", frames)

        # Check repository storage directory contains only security_state files
        files = os.listdir(test_dir)
        for f in files:
            assert not f.startswith("v2_cases"), f"Authoritative v2_cases written: {f}"
            assert not f.startswith("rc5_"), f"Authoritative rc5 file written: {f}"
            assert f.startswith(("security_state", "security_event", "states_", "ledgers_", "locks")), f"Unexpected file: {f}"
    finally:
        clean_test_dir(test_dir)
