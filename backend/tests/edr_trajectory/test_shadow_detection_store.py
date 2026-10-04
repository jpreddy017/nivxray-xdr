"""The shadow detection sink: isolation, markers, evidence integrity, outcomes.

Hermetic. No SequenceEngine construction or execution, no rule evaluation, no §d
evidence read, no provider, no checkpoint, no run record, no Fabric Finding, no
evaluation ledger, no analyst detection collection, no index or collection
creation, no production, no real endpoint.
"""
from __future__ import annotations

import inspect
import io
import tokenize

import pytest

from edr_behavior import contracts as C
from edr_behavior.store import ConcurrencyConflict
from edr_plane import behavior_shadow_detection_store as sd
from edr_plane.behavior_shadow_detection_store import (
    MARKERS, REFUSED_ENDPOINT, REFUSED_KEY_MISMATCH, REFUSED_MARKER_OVERRIDE,
    REFUSED_NO_EVIDENCE_REFS, REFUSED_NO_RULE_IDENTITY, REFUSED_READBACK,
    REFUSED_REF_RAW_ID, REFUSED_REF_STABLE_KEY, REFUSED_REF_TENANT,
    REFUSED_RULESET_STREAM, REFUSED_TENANT, REFUSED_TRIGGER_ABSENT,
    SHADOW_COLLECTION, STATUS_SHADOW_ONLY, WRITE_CREATED, WRITE_DUPLICATE,
    WRITE_FAILED, WRITE_MERGED, InMemoryShadowDetectionBackend,
    ShadowDetectionRefused, ShadowDetectionStore)

T = "ten_a"
T_B = "ten_b"
EP = "ep_1"
EP_B = "ep_2"
RUN = "shadow_run_0001"
HASH = "a1" * 16
HASH_B = "b2" * 16
TRIGGER = "ev_trigger_0001"


def code_only(module):
    """Executable source: comments and docstrings removed, literals kept.

    The module explains in prose why the analyst store is unsafe and why
    `SequenceEngine` cannot be trusted for persistence proof, so a raw text scan
    would flag its own documentation.
    """
    out = []
    for tok in tokenize.generate_tokens(
            io.StringIO(inspect.getsource(module)).readline):
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.STRING and \
                tok.string.lstrip("rbfu").startswith(('"""', "'''")):
            continue
        out.append(tok.string)
    return "\n".join(out)


def ref(key=TRIGGER, *, tenant=T, raw="raw_1"):
    return {"tenant_id": tenant, "raw_id": raw, "canonical_event_id": None,
            "generation": None, "store": "XDR_CANONICAL", "record_id": None,
            "sub_key": "act_1", "stable_key": key}


def det(*, detection_id="e3det_aaa", tenant=T, endpoint=EP, refs=None,
        status="OPEN", confidence=70, last_seen="2026-10-03T04:10:00Z",
        **extra):
    refs = refs if refs is not None else [ref()]
    doc = {"detection_id": detection_id, "tenant_id": tenant,
           "endpoint_id": endpoint, "rule_id": "rule_x", "rule_version": 2,
           "rule_content_hash": "c" * 32,
           "detection_type": "BEHAVIORAL_SEQUENCE",
           "first_seen": "2026-10-03T04:00:00Z", "last_seen": last_seen,
           "severity": "HIGH", "confidence": confidence, "status": status,
           "scope_key": "scope_1", "matched_stages": [],
           "involved_entities": {}, "evidence_refs": refs,
           "evidence_keys": sorted({r["stable_key"] for r in refs}),
           "raw_refs": sorted({r["raw_id"] for r in refs}),
           "canonical_event_ids": [], "process_identities": [], "mitre": [],
           "explanation": "shadow", "provenance": {"mode": C.MODE_SHADOW},
           "engine_version": "e3-seq-1.1.0",
           "created_at": "2026-10-03T04:11:00Z", "suppression": None}
    doc.update(extra)
    return doc


def store(backend=None, *, tenant=T, endpoint=EP, h=HASH, run=RUN):
    return ShadowDetectionStore(
        backend or InMemoryShadowDetectionBackend(), tenant_id=tenant,
        endpoint_id=endpoint, shadow_run_id=run, replay_id=f"shadow:{h}",
        ruleset_id="rs_core", ruleset_version=3, ruleset_content_hash=h)


# ── MODE_SHADOW is additive ──────────────────────────────────────────────

def test_mode_shadow_exists_and_is_distinct():
    assert C.MODE_SHADOW == "SHADOW"
    assert C.MODE_SHADOW not in (C.MODE_LIVE, C.MODE_RETRO)
    assert C.MODE_SHADOW in C.EXECUTION_MODES


def test_live_and_retro_are_unchanged():
    assert C.MODE_LIVE == "LIVE" and C.MODE_RETRO == "RETRO"
    assert C.EXECUTION_MODES == {"LIVE", "RETRO", "SHADOW"}


def test_no_existing_code_path_treats_shadow_as_live_or_retro():
    import edr_behavior.engine as eng
    import edr_behavior.replay as rp
    assert "MODE_SHADOW" not in inspect.getsource(eng)
    assert "MODE_SHADOW" not in inspect.getsource(rp)
    assert inspect.signature(eng.SequenceEngine.process).parameters[
        "mode"].default == C.MODE_LIVE


# ── collection isolation ─────────────────────────────────────────────────

def test_routes_only_to_the_shadow_collection():
    assert SHADOW_COLLECTION == "e3_behavior_shadow_detections"
    assert store().collection == SHADOW_COLLECTION
    assert InMemoryShadowDetectionBackend.collection == SHADOW_COLLECTION
    assert sd.MongoShadowDetectionBackend.collection == SHADOW_COLLECTION


def test_analyst_detection_collection_is_never_named():
    src = code_only(sd)
    assert "e3_behavior_detections" not in src
    assert "e3_behavior_replay_checkpoints" not in src


def test_mongo_backend_resolves_one_collection_only():
    seen = []

    class FakeDb:
        def __getitem__(self, name):
            seen.append(name)
            return object()

    sd.MongoShadowDetectionBackend(FakeDb())
    assert seen == [SHADOW_COLLECTION]


# ── mandatory markers ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_every_write_carries_the_mandatory_markers():
    b = InMemoryShadowDetectionBackend()
    s = store(b)
    await s.put(det(), None)
    doc = b.all()[0]
    assert doc["shadow"] is True
    assert doc["analyst_visible"] is False
    assert doc["detection_source_claim"] == "NONE"
    assert doc["status"] == STATUS_SHADOW_ONLY
    assert doc["shadow_run_id"] == RUN
    assert doc["replay_id"] == f"shadow:{HASH}"
    assert doc["ruleset_id"] == "rs_core"
    assert doc["ruleset_version"] == 3
    assert doc["ruleset_content_hash"] == HASH


@pytest.mark.asyncio
async def test_engine_status_is_rewritten_but_preserved_for_audit():
    b = InMemoryShadowDetectionBackend()
    await store(b).put(det(status="OPEN"), None)
    doc = b.all()[0]
    assert doc["status"] == STATUS_SHADOW_ONLY   # no reader can see OPEN
    assert doc["engine_status"] == "OPEN"


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("shadow", False),
                                         ("analyst_visible", True),
                                         ("detection_source_claim", "E3")])
async def test_marker_tampering_is_refused(field, value):
    with pytest.raises(ShadowDetectionRefused) as e:
        await store().put(det(**{field: value}), None)
    assert e.value.reason == REFUSED_MARKER_OVERRIDE


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("replay_id", "shadow:zzz"),
                                         ("ruleset_content_hash", HASH_B),
                                         ("ruleset_id", "rs_other"),
                                         ("ruleset_version", 99)])
async def test_stream_identity_cannot_be_supplied_by_the_caller(field, value):
    with pytest.raises(ShadowDetectionRefused) as e:
        await store().put(det(**{field: value}), None)
    assert e.value.reason == REFUSED_MARKER_OVERRIDE


@pytest.mark.asyncio
async def test_shadow_run_id_is_restamped_and_the_first_one_is_retained():
    """A later run legitimately merges a document an earlier run created, so an
    inherited run id is write provenance — not a stream override."""
    b = InMemoryShadowDetectionBackend()
    await store(b, run="run_a").put(det(), None)
    stored = b.all()[0]
    merged = {**stored, "confidence": 90,
              "last_seen": "2026-10-03T04:30:00Z", "status": "OPEN"}
    await store(b, run="run_b").put(merged, 1)
    doc = b.all()[0]
    assert doc["shadow_run_id"] == "run_b"
    assert doc["first_shadow_run_id"] == "run_a"


# ── evidence integrity ───────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("refs", [[], None, "nope", [["not-a-dict"]]])
async def test_missing_or_malformed_evidence_refs_are_refused(refs):
    doc = det()
    doc["evidence_refs"] = refs
    with pytest.raises(ShadowDetectionRefused) as e:
        await store().put(doc, None)
    assert e.value.reason == REFUSED_NO_EVIDENCE_REFS


@pytest.mark.asyncio
async def test_an_evidence_ref_missing_its_identity_fields_is_refused():
    doc = det()
    doc["evidence_refs"] = [{"x": 1}]
    with pytest.raises(ShadowDetectionRefused) as e:
        await store().put(doc, None)
    assert e.value.reason == REFUSED_REF_TENANT


@pytest.mark.asyncio
async def test_foreign_tenant_evidence_ref_is_refused():
    with pytest.raises(ShadowDetectionRefused) as e:
        await store().put(det(refs=[ref(tenant=T_B)]), None)
    assert e.value.reason == REFUSED_REF_TENANT


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", [None, "", "   "])
async def test_evidence_ref_without_durable_raw_id_is_refused(raw):
    with pytest.raises(ShadowDetectionRefused) as e:
        await store().put(det(refs=[ref(raw=raw)]), None)
    assert e.value.reason == REFUSED_REF_RAW_ID


@pytest.mark.asyncio
async def test_evidence_ref_without_stable_key_is_refused():
    with pytest.raises(ShadowDetectionRefused) as e:
        await store().put(det(refs=[ref(key="")]), None)
    assert e.value.reason == REFUSED_REF_STABLE_KEY


@pytest.mark.asyncio
async def test_evidence_keys_must_agree_with_refs():
    doc = det()
    doc["evidence_keys"] = ["ev_something_else"]
    with pytest.raises(ShadowDetectionRefused) as e:
        await store().put(doc, None)
    assert e.value.reason == REFUSED_KEY_MISMATCH


@pytest.mark.asyncio
async def test_nothing_is_inferred_or_repaired():
    """A refused document leaves NO trace: no partial write, no patched doc."""
    b = InMemoryShadowDetectionBackend()
    with pytest.raises(ShadowDetectionRefused):
        await store(b).put(det(refs=[ref(raw=None)]), None)
    assert b.all() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("rule_id", ""),
                                         ("rule_content_hash", "  "),
                                         ("rule_version", "2")])
async def test_rule_identity_is_required(field, value):
    with pytest.raises(ShadowDetectionRefused) as e:
        await store().put(det(**{field: value}), None)
    assert e.value.reason == REFUSED_NO_RULE_IDENTITY


@pytest.mark.asyncio
async def test_trigger_evidence_must_be_represented_when_declared():
    s = store()
    s.expect_trigger(TRIGGER)
    await s.put(det(), None)                       # trigger present: accepted
    s.expect_trigger("ev_other_item")
    with pytest.raises(ShadowDetectionRefused) as e:
        await s.put(det(detection_id="e3det_bbb"), None)
    assert e.value.reason == REFUSED_TRIGGER_ABSENT


@pytest.mark.asyncio
async def test_trigger_requirement_is_off_when_not_declared():
    s = store()
    s.expect_trigger(None)
    assert await s.put(det(), None) == 1


# ── write outcome contract ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_created_is_reported_and_verified():
    s = store()
    rev = await s.put(det(), None)
    assert rev == 1
    w = s.last_write
    assert w["outcome"] == WRITE_CREATED and w["verified"] is True
    assert w["revision"] == 1 and w["collection"] == SHADOW_COLLECTION
    assert w["shadow_run_id"] == RUN


@pytest.mark.asyncio
async def test_merged_is_reported_on_a_revision_matched_write():
    s = store()
    await s.put(det(), None)
    merged = det(refs=[ref(), ref(key="ev_second", raw="raw_2")],
                 last_seen="2026-10-03T04:20:00Z")
    rev = await s.put(merged, 1)
    assert rev == 2
    assert s.last_write["outcome"] == WRITE_MERGED
    assert s.last_write["verified"] is True


@pytest.mark.asyncio
async def test_repeating_the_same_match_is_a_duplicate_and_writes_nothing():
    b = InMemoryShadowDetectionBackend()
    s = store(b)
    await s.put(det(), None)
    rev = await s.put(det(), None)
    assert rev == 1
    assert s.last_write["outcome"] == WRITE_DUPLICATE
    assert len(b.all()) == 1
    assert b.all()[0]["revision"] == 1


@pytest.mark.asyncio
async def test_conflicting_create_is_reported_failed():
    s = store()
    await s.put(det(), None)
    with pytest.raises(ConcurrencyConflict):
        await s.put(det(confidence=90), None)      # same id, different content
    assert s.last_write["outcome"] == WRITE_FAILED
    assert s.last_write["verified"] is False
    assert s.last_write["reason"] == "DETECTION_ALREADY_EXISTS"


@pytest.mark.asyncio
async def test_stale_revision_write_is_reported_failed():
    s = store()
    await s.put(det(), None)
    with pytest.raises(ConcurrencyConflict):
        await s.put(det(confidence=90), 7)
    assert s.last_write["outcome"] == WRITE_FAILED
    assert s.last_write["reason"] == "REVISION_CONFLICT"


@pytest.mark.asyncio
async def test_all_four_outcomes_are_observable_per_detection():
    s = store()
    await s.put(det(), None)
    await s.put(det(), None)
    assert {w["outcome"] for w in s.writes} == {WRITE_CREATED, WRITE_DUPLICATE}
    assert s.write_outcome_for("e3det_aaa")["outcome"] == WRITE_DUPLICATE
    assert s.write_outcome_for("nope") is None
    assert set(sd.WRITE_OUTCOMES) == {WRITE_CREATED, WRITE_MERGED,
                                      WRITE_DUPLICATE, WRITE_FAILED}


@pytest.mark.asyncio
async def test_only_verified_writes_are_reported_as_verified():
    s = store()
    await s.put(det(), None)
    with pytest.raises(ConcurrencyConflict):
        await s.put(det(confidence=90), None)
    assert len(s.verified_writes()) == 1


# ── read-back verification ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_reads_back_what_is_durable():
    s = store()
    await s.put(det(), None)
    got = await s.verify("e3det_aaa")
    assert got["detection_id"] == "e3det_aaa"
    assert got["status"] == STATUS_SHADOW_ONLY
    assert await s.verify("e3det_zzz") is None


@pytest.mark.asyncio
async def test_a_write_that_does_not_persist_is_never_reported_successful():
    """A lying backend must not be able to produce a successful write."""
    class Amnesiac(InMemoryShadowDetectionBackend):
        async def insert(self, doc):
            return True                 # claims success, stores nothing

    s = store(Amnesiac())
    with pytest.raises(ShadowDetectionRefused) as e:
        await s.put(det(), None)
    assert e.value.reason == REFUSED_READBACK
    assert s.last_write["outcome"] == WRITE_FAILED
    assert s.last_write["verified"] is False


@pytest.mark.asyncio
async def test_a_write_stored_with_altered_content_fails_verification():
    class Mangler(InMemoryShadowDetectionBackend):
        async def insert(self, doc):
            doc = dict(doc)
            doc["confidence"] = 1
            return await super().insert(doc)

    with pytest.raises(ShadowDetectionRefused) as e:
        await store(Mangler()).put(det(), None)
    assert e.value.reason == REFUSED_READBACK


# ── idempotency and identity ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_deterministic_identity_is_preserved_not_reinvented():
    """The store never mints or rewrites a detection_id."""
    b = InMemoryShadowDetectionBackend()
    await store(b).put(det(detection_id="e3det_fixed"), None)
    assert b.all()[0]["detection_id"] == "e3det_fixed"
    assert "detection_id=" not in inspect.getsource(sd)


@pytest.mark.asyncio
async def test_repeated_writes_never_create_a_second_document():
    b = InMemoryShadowDetectionBackend()
    s = store(b)
    for _ in range(5):
        await s.put(det(), None)
    assert len(b.all()) == 1


@pytest.mark.asyncio
async def test_overlap_search_finds_a_prior_shadow_detection():
    b = InMemoryShadowDetectionBackend()
    s = store(b)
    await s.put(det(), None)
    found = await s.find_overlapping(tenant_id=T, endpoint_id=EP,
                                     rule_id="rule_x", rule_version=2,
                                     scope_key="scope_1",
                                     evidence_keys=[TRIGGER])
    assert found["detection_id"] == "e3det_aaa"
    assert await s.find_overlapping(tenant_id=T, endpoint_id=EP,
                                    rule_id="rule_x", rule_version=2,
                                    scope_key="scope_1",
                                    evidence_keys=["ev_unrelated"]) is None


@pytest.mark.asyncio
async def test_overlap_search_requires_evidence_keys():
    assert await store().find_overlapping(
        tenant_id=T, endpoint_id=EP, rule_id="rule_x", rule_version=2,
        scope_key="scope_1", evidence_keys=[]) is None


# ── tenant isolation ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_two_tenants_sharing_a_detection_id_never_merge():
    b = InMemoryShadowDetectionBackend()
    await store(b, tenant=T).put(det(tenant=T), None)
    await store(b, tenant=T_B).put(det(tenant=T_B, refs=[ref(tenant=T_B)]),
                                   None)
    assert len(b.all()) == 2
    assert len(b.all(T)) == 1 and len(b.all(T_B)) == 1


@pytest.mark.asyncio
async def test_cross_tenant_document_is_not_visible_or_mergeable():
    b = InMemoryShadowDetectionBackend()
    await store(b, tenant=T).put(det(tenant=T), None)
    other = store(b, tenant=T_B)
    assert await other.verify("e3det_aaa") is None
    assert await other.find_overlapping(
        tenant_id=T_B, endpoint_id=EP, rule_id="rule_x", rule_version=2,
        scope_key="scope_1", evidence_keys=[TRIGGER]) is None


@pytest.mark.asyncio
async def test_writing_another_tenants_document_is_refused():
    with pytest.raises(ShadowDetectionRefused) as e:
        await store(tenant=T).put(det(tenant=T_B), None)
    assert e.value.reason == REFUSED_TENANT


@pytest.mark.asyncio
async def test_reads_outside_the_bound_tenant_are_refused():
    s = store()
    with pytest.raises(ShadowDetectionRefused):
        await s.get(T_B, "e3det_aaa")
    with pytest.raises(ShadowDetectionRefused):
        await s.find_overlapping(tenant_id=T_B, endpoint_id=EP,
                                 rule_id="r", rule_version=1,
                                 scope_key="s", evidence_keys=[TRIGGER])


# ── endpoint isolation ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_writing_another_endpoints_document_is_refused():
    with pytest.raises(ShadowDetectionRefused) as e:
        await store(endpoint=EP).put(det(endpoint=EP_B), None)
    assert e.value.reason == REFUSED_ENDPOINT


@pytest.mark.asyncio
async def test_overlap_search_is_endpoint_scoped():
    b = InMemoryShadowDetectionBackend()
    await store(b, endpoint=EP).put(det(endpoint=EP), None)
    other = store(b, endpoint=EP_B)
    assert await other.find_overlapping(
        tenant_id=T, endpoint_id=EP_B, rule_id="rule_x", rule_version=2,
        scope_key="scope_1", evidence_keys=[TRIGGER]) is None
    with pytest.raises(ShadowDetectionRefused):
        await other.find_overlapping(
            tenant_id=T, endpoint_id=EP, rule_id="rule_x", rule_version=2,
            scope_key="scope_1", evidence_keys=[TRIGGER])


# ── ruleset stream isolation ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_another_ruleset_stream_cannot_be_merged_into():
    b = InMemoryShadowDetectionBackend()
    await store(b, h=HASH).put(det(), None)
    with pytest.raises(ShadowDetectionRefused) as e:
        await store(b, h=HASH_B).put(det(confidence=90), None)
    assert e.value.reason == REFUSED_RULESET_STREAM


@pytest.mark.asyncio
async def test_overlap_search_does_not_cross_ruleset_streams():
    b = InMemoryShadowDetectionBackend()
    await store(b, h=HASH).put(det(), None)
    assert await store(b, h=HASH_B).find_overlapping(
        tenant_id=T, endpoint_id=EP, rule_id="rule_x", rule_version=2,
        scope_key="scope_1", evidence_keys=[TRIGGER]) is None


@pytest.mark.asyncio
async def test_a_non_shadow_document_is_never_adopted():
    b = InMemoryShadowDetectionBackend()
    await b.insert({"tenant_id": T, "detection_id": "e3det_aaa",
                    "endpoint_id": EP, "status": "OPEN", "revision": 1,
                    "evidence_keys": [TRIGGER], "rule_id": "rule_x",
                    "rule_version": 2, "scope_key": "scope_1",
                    "ruleset_content_hash": HASH})
    s = store(b)
    with pytest.raises(ShadowDetectionRefused) as e:
        await s.get(T, "e3det_aaa")
    assert e.value.reason == sd.REFUSED_NOT_SHADOW
    with pytest.raises(ShadowDetectionRefused):
        await s.put(det(), None)


# ── index design only ────────────────────────────────────────────────────

def test_indexes_are_designed_but_never_created():
    specs = {opts.get("name"): (keys, opts) for keys, opts in sd.INDEXES}
    assert specs["uniq_tenant_shadow_detection"][0] == \
        [("tenant_id", 1), ("detection_id", 1)]
    assert specs["uniq_tenant_shadow_detection"][1]["unique"] is True
    assert specs["tenant_shadow_run"][0] == \
        [("tenant_id", 1), ("shadow_run_id", 1)]
    assert specs["tenant_endpoint_rule_scope"][0] == \
        [("tenant_id", 1), ("endpoint_id", 1), ("rule_id", 1),
         ("rule_version", 1), ("scope_key", 1)]
    assert specs["tenant_evidence_keys"][0] == \
        [("tenant_id", 1), ("evidence_keys", 1)]
    src = inspect.getsource(sd)
    assert "create_index" not in src and "ensure_indexes" not in src
    assert "create_collection" not in src


# ── isolation from everything else ───────────────────────────────────────

def test_module_constructs_no_engine_and_reads_no_evidence():
    src = code_only(sd)
    for forbidden in ("SequenceEngine", "engine.process", "evaluate_rule",
                      "page_device_evidence", "SdEvidenceProvider",
                      "behavior_shadow_frontier", "behavior_sd_provider",
                      "behavior_shadow_run", "advance(", "initialize(",
                      "findings_intake", "EvaluationState", "MongoClient",
                      "motor"):
        assert forbidden not in src, forbidden


def test_importing_the_module_does_not_import_the_engine():
    import subprocess
    import sys
    from pathlib import Path
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys; import edr_plane.behavior_shadow_detection_store as m;"
         "print('edr_behavior.engine' in sys.modules,"
         " 'edr_behavior.matcher' in sys.modules)"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).resolve().parents[2]))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "False False"


def test_store_exposes_only_the_required_detection_store_surface():
    from edr_behavior.store import DetectionStore
    for name in ("get", "find_overlapping", "put"):
        assert callable(getattr(ShadowDetectionStore, name))
    assert hasattr(DetectionStore, "put")


@pytest.mark.asyncio
async def test_no_fabric_finding_or_ledger_shape_is_produced():
    b = InMemoryShadowDetectionBackend()
    await store(b).put(det(), None)
    doc = b.all()[0]
    for forbidden in ("finding_id", "incident_id", "verdict", "response_action",
                      "analyst_note", "evaluation_state", "fabric_finding"):
        assert forbidden not in doc, forbidden
    assert doc["detection_source_claim"] == "NONE"
    assert doc["analyst_visible"] is False


def test_markers_constant_is_the_single_source_of_truth():
    assert MARKERS == {"shadow": True, "analyst_visible": False,
                       "detection_source_claim": "NONE",
                       "status": STATUS_SHADOW_ONLY}
    assert "status" not in sd.SHADOW_MARKERS
