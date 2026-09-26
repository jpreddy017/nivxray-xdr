"""P0-C · DURABLE EDR FINDINGS — acceptance suite.

Owner acceptance criteria, one test each, against REAL Mongo and the real
write path. Evidence labelling: TEST/SYNTHETIC — every test uses its own
throwaway tenant (`p0c-*`) and deletes exactly what it created.

What is proven here:

  1  a detection produces a durable finding
  2  the finding survives the process (read back through a NEW client)
  3  a duplicate evaluation does not create uncontrolled duplicates
  4  a historical finding is not silently mutated
  5  a finding belongs to the correct tenant, and only to it
  6  cited evidence references resolve — and an unresolved one says so
  7  the producing source is preserved
  8  an XDR-derived finding is never represented as a local EDR detection
  9  EVALUATED_NO_FINDING is distinguishable from NOT_EVALUATED
 10  EVALUATION_FAILED is distinguishable from both
 11  an exclusion-suppressed evaluation is its own fact
 12  the ingest path is actually wired to the finding plane
"""
from __future__ import annotations

import os
import uuid

import pytest
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import ValidationError
from pymongo import MongoClient

from edr_plane import findings_intake
from edr_plane.fabric import evaluation_state as ev_state, store as f_store
from edr_plane.fabric.contracts import (AnalyzerClass, DetectionSource,
                                        Finding, InferenceLocation, Severity)

CITATIONS = findings_intake.CITATIONS
CANONICAL = "xdr_canonical_evidence"
RAW = "edr_raw_events"

ENGINE = "nivxray::detection_content::nivxray_native_sigma"
PAYLOAD = ('{"activity": "PROCESS", "process": "bash", '
           '"image_path": "/usr/bin/bash", '
           '"command_line": "/bin/bash /tmp/p0c.sh"}')


def _derivation(cev: str, *, outcome: str = "DETECTION_MATCHED",
                rules: str = "rules: EDR-P0C-001",
                verdict: str = "SUSPICIOUS") -> dict:
    return {"outcome": outcome,
            "event_id": cev,
            "reason": rules if outcome == "DETECTION_MATCHED" else (
                "no detection content version was deployed"
                if outcome == "DETECTION_NOT_EVALUATED" else None),
            "detection_content_version": ENGINE,
            "verdict_version": verdict,
            "derived_at": "2026-09-26T10:00:05+00:00"}


class _Scope:
    """A throwaway tenant with REAL seeded evidence and REAL citations."""

    def __init__(self, tenants: int = 1):
        self.n = tenants

    async def __aenter__(self):
        self.mongo = MongoClient(os.environ["MONGO_URL"])
        self.client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        self.db = self.client[os.environ["DB_NAME"]]
        self.sync = self.mongo[os.environ["DB_NAME"]]
        self.stamp = uuid.uuid4().hex[:8]
        self.tenants = [f"p0c-{self.stamp}-{i}" for i in range(self.n)]
        return self

    async def __aexit__(self, *exc):
        q = {"tenant_id": {"$regex": f"^p0c-{self.stamp}"}}
        for c in (f_store.COLLECTION, ev_state.COLLECTION, CITATIONS,
                  CANONICAL, RAW):
            self.sync[c].delete_many(q)
        self.client.close()
        self.mongo.close()
        return False

    def seed(self, tenant: str, *, cev: str, endpoint: str,
             rule_id: str = "EDR-P0C-001", severity: str = "medium",
             confidence: str = "high",
             attck=("T1059", "T1036")) -> None:
        """The producing source's OWN records, in their real shape."""
        self.sync[CITATIONS].insert_one({
            "tenant_id": tenant, "canonical_event_id": cev,
            "rule_id": rule_id, "rule_version": "1",
            "rule_name": "Execution of a world-writable script",
            "engine_id": ENGINE, "rule_result": "MATCH",
            "severity": severity, "confidence": confidence,
            "mitre_attack": list(attck)})
        self.sync[CANONICAL].insert_one({
            "tenant_id": tenant, "event_id": cev,
            "event_time": "2026-09-26T10:00:00+00:00", "source": "sensor"})
        self.sync[RAW].insert_one({
            "tenant_id": tenant, "raw_id": f"raw_{cev}",
            "dedup_key": f"dedup_{cev}",
            "endpoint_ref": endpoint, "ingest_time":
                "2026-09-26T10:00:01+00:00",
            "derivations": [{"event_id": cev, "outcome": "DETECTION_MATCHED"}]})

    async def evaluate(self, tenant: str, *, cev: str, endpoint: str,
                       derivation: dict | None = None) -> dict:
        return await findings_intake.record_endpoint_detection(
            self.db, tenant_id=tenant, endpoint_ref=endpoint,
            canonical_event_id=cev, payload=PAYLOAD,
            observed_at="2026-09-26T10:00:00+00:00",
            derivation=derivation or _derivation(cev))


# ── 1 · a detection produces a durable finding ──────────────────────────
@pytest.mark.asyncio
async def test_a_detection_produces_a_durable_finding():
    async with _Scope() as s:
        t, cev, ep = s.tenants[0], f"cev_p0c_{s.stamp}_1", "ep_p0c_1"
        s.seed(t, cev=cev, endpoint=ep)
        out = await s.evaluate(t, cev=cev, endpoint=ep)

        assert out["findings_persisted"] == 1
        assert out["evaluation_state"] == "FINDINGS_PRESENT"

        rows, _ = f_store.read(t)
        assert len(rows) == 1
        f = rows[0]
        # the owner's required, non-fabricated field set
        assert f["finding_id"].startswith("fnd_")
        assert f["tenant_id"] == t
        assert f["endpoint_ref"] == ep
        assert f["rule_id"] == "EDR-P0C-001"
        assert f["rule_version"] == "1"
        assert f["severity"] == Severity.MEDIUM.value
        assert "PRODUCING_RULE_SEVERITY" in f["severity_basis"]
        # the rule records a categorical confidence — no number is invented
        assert f["confidence"] is None
        assert f["confidence_label"] == "high"
        assert "CATEGORICAL" in f["confidence_basis"]
        assert f["attck"] == ["T1059", "T1036"]
        assert f["attck_basis"] == "PRODUCING_RULE_MITRE_MAPPING"
        assert f["evidence_refs"] == [cev]
        assert f["first_seen"] and f["last_seen"] and f["created_at"]
        assert f["recurrence_count"] == 1
        assert f["detection_source"] == (
            DetectionSource.XDR_PLATFORM_DETERMINISTIC_DETECTION.value)


# ── 2 · durability across the process ───────────────────────────────────
@pytest.mark.asyncio
async def test_the_finding_survives_the_process_that_wrote_it():
    """Read back through a brand-new client and a fresh query, so nothing
    in this process's memory can be what answers."""
    async with _Scope() as s:
        t, cev, ep = s.tenants[0], f"cev_p0c_{s.stamp}_2", "ep_p0c_2"
        s.seed(t, cev=cev, endpoint=ep)
        await s.evaluate(t, cev=cev, endpoint=ep)

        fresh = MongoClient(os.environ["MONGO_URL"])
        try:
            doc = fresh[os.environ["DB_NAME"]][f_store.COLLECTION].find_one(
                {"tenant_id": t}, {"_id": 0})
            ledger = fresh[os.environ["DB_NAME"]][ev_state.COLLECTION
                                                  ].find_one({"tenant_id": t})
        finally:
            fresh.close()
        assert doc and doc["rule_id"] == "EDR-P0C-001"
        assert doc["detection_source"] == (
            DetectionSource.XDR_PLATFORM_DETERMINISTIC_DETECTION.value)
        assert ledger and ledger["state"] == "FINDINGS_PRESENT"
        assert ledger["finding_ids"] == [doc["finding_id"]]


# ── 3 · idempotency ─────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a_repeated_evaluation_does_not_duplicate_the_finding():
    async with _Scope() as s:
        t, cev, ep = s.tenants[0], f"cev_p0c_{s.stamp}_3", "ep_p0c_3"
        s.seed(t, cev=cev, endpoint=ep)
        first = await s.evaluate(t, cev=cev, endpoint=ep)
        second = await s.evaluate(t, cev=cev, endpoint=ep)
        third = await s.evaluate(t, cev=cev, endpoint=ep)

        assert first["newly_inserted"] == 1
        assert second["newly_inserted"] == 0 and second["already_present"] == 1
        assert third["already_present"] == 1
        assert first["finding_ids"] == second["finding_ids"] == \
            third["finding_ids"]

        rows, _ = f_store.read(t)
        assert len(rows) == 1
        # the recurrence is ACCOUNTED, not duplicated
        assert rows[0]["recurrence_count"] == 3
        # and the ledger holds ONE row for this evidence, with the attempts
        ledger = s.sync[ev_state.COLLECTION].find_one({"tenant_id": t})
        assert ledger["evaluation_attempts"] == 3


# ── 4 · immutability ────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a_historical_finding_is_never_silently_rewritten():
    """Same identity, different analysis => the ORIGINAL analysis stands.

    This is what stops a later content change from quietly re-writing what
    the platform said it found. A genuinely different analysis has a
    different identity and would be a NEW finding; supersession is Gate 6
    and is deliberately not implemented."""
    async with _Scope() as s:
        t, cev, ep = s.tenants[0], f"cev_p0c_{s.stamp}_4", "ep_p0c_4"
        s.seed(t, cev=cev, endpoint=ep)
        await s.evaluate(t, cev=cev, endpoint=ep)
        original = f_store.get(t, f_store.read(t)[0][0]["finding_id"])

        forged = Finding(**{**{k: v for k, v in original.items()
                               if k not in ("finding_id", "created_at",
                                            "first_seen", "last_seen",
                                            "recurrence_count",
                                            "last_recorded_at")},
                            "label": "REWRITTEN",
                            "severity": Severity.CRITICAL.value,
                            "severity_basis": "REWRITTEN"})
        assert forged.finding_id == original["finding_id"], (
            "the identity must not depend on the mutable presentation "
            "fields this test rewrites")
        f_store.persist([forged])

        after = f_store.get(t, original["finding_id"])
        assert after["label"] == original["label"] != "REWRITTEN"
        assert after["severity"] == Severity.MEDIUM.value
        assert after["severity_basis"] == original["severity_basis"]
        assert after["created_at"] == original["created_at"]
        assert after["first_seen"] == original["first_seen"]
        assert after["recurrence_count"] == 2       # accounting only


# ── 5 · tenant isolation ────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a_finding_belongs_to_one_tenant_and_is_invisible_to_others():
    async with _Scope(tenants=2) as s:
        a, b = s.tenants
        cev, ep = f"cev_p0c_{s.stamp}_5", "ep_p0c_5"
        for t in (a, b):
            s.seed(t, cev=cev, endpoint=ep)
            await s.evaluate(t, cev=cev, endpoint=ep)

        rows_a, _ = f_store.read(a)
        rows_b, _ = f_store.read(b)
        assert len(rows_a) == len(rows_b) == 1
        # identical evidence in two tenants is TWO findings, never one
        assert rows_a[0]["finding_id"] != rows_b[0]["finding_id"]
        assert rows_a[0]["tenant_id"] == a and rows_b[0]["tenant_id"] == b
        # and neither tenant can be answered with the other's finding
        assert f_store.get(a, rows_b[0]["finding_id"]) is None
        assert f_store.get(b, rows_a[0]["finding_id"]) is None
        assert ev_state.for_evidence(a, [cev])[cev]["tenant_id"] == a


# ── 6 · evidence references resolve ─────────────────────────────────────
@pytest.mark.asyncio
async def test_every_cited_evidence_reference_resolves_or_says_it_does_not():
    from routers.edr_findings import _resolve_evidence
    async with _Scope() as s:
        t, cev, ep = s.tenants[0], f"cev_p0c_{s.stamp}_6", "ep_p0c_6"
        s.seed(t, cev=cev, endpoint=ep)
        await s.evaluate(t, cev=cev, endpoint=ep)

        resolved = _resolve_evidence(t, [cev])[0]
        assert resolved["state"] == "EVIDENCE_RESOLVED"
        assert resolved["canonical_evidence"]["event_id"] == cev
        assert resolved["raw_event"]["endpoint_ref"] == ep
        assert set(resolved["resolved_in"]) == {CANONICAL, RAW}
        absent = _resolve_evidence(t, ["cev_does_not_exist"])[0]
        assert absent["state"] == "EVIDENCE_REFERENCE_UNRESOLVED"
        assert "will NOT substitute" in absent["reason"]
        # the same reference in ANOTHER tenant does not resolve either
        assert _resolve_evidence(f"{t}-foreign", [cev])[0]["state"] == \
            "EVIDENCE_REFERENCE_UNRESOLVED"


# ── 7 + 8 · provenance is preserved, and never re-labelled ──────────────
@pytest.mark.asyncio
async def test_an_xdr_derived_finding_is_never_presented_as_a_local_detection():
    async with _Scope() as s:
        t, cev, ep = s.tenants[0], f"cev_p0c_{s.stamp}_7", "ep_p0c_7"
        s.seed(t, cev=cev, endpoint=ep)
        await s.evaluate(t, cev=cev, endpoint=ep)
        f = f_store.read(t)[0][0]

        assert f["detection_source"] == (
            DetectionSource.XDR_PLATFORM_DETERMINISTIC_DETECTION.value)
        assert "NivXRay XDR ingest detection pipeline" in \
            f["detection_source_detail"]
        assert "does not re-run detection" in f["analysis_basis"]
        assert f["inference_location"] == InferenceLocation.BACKEND.value
        for forbidden in ("local", "offline", "behavioural", "behavioral"):
            assert forbidden not in f["detection_source_detail"].lower()


def test_a_finding_may_not_claim_an_engine_that_does_not_exist():
    base = dict(tenant_id="p0c-contract", analyzer_id="x",
                analyzer_class=AnalyzerClass.BEHAVIORAL,
                analyzer_version="1", label="x", evidence_refs=["cev_x"],
                detection_source_detail="x", severity_basis="x",
                confidence_basis="x", attck_basis="x", analysis_basis="x")
    for claimed in (DetectionSource.NIVXFORGE_ENDPOINT_BEHAVIORAL,
                    DetectionSource.NIVXFORGE_ENDPOINT_PREVENTION,
                    DetectionSource.NIVXFORGE_BACKEND_REPUTATION):
        with pytest.raises(ValidationError) as e:
            Finding(**base, detection_source=claimed)
        assert "no local behavioural" in str(e.value)

    # and no finding may claim endpoint-side inference either
    with pytest.raises(ValidationError) as e:
        Finding(**base, inference_location=InferenceLocation.ENDPOINT,
                detection_source=(
                    DetectionSource.XDR_PLATFORM_DETERMINISTIC_DETECTION))
    assert "no endpoint-side inference engine exists" in str(e.value)


# ── 9 · no finding != not evaluated ─────────────────────────────────────
@pytest.mark.asyncio
async def test_evaluated_no_finding_is_distinguishable_from_not_evaluated():
    async with _Scope(tenants=2) as s:
        t, other = s.tenants
        clean, unseen = f"cev_p0c_{s.stamp}_8a", f"cev_p0c_{s.stamp}_8b"
        s.seed(t, cev=clean, endpoint="ep_p0c_8")
        s.seed(t, cev=unseen, endpoint="ep_p0c_8")

        evaluated = await s.evaluate(
            t, cev=clean, endpoint="ep_p0c_8",
            derivation=_derivation(clean,
                                   outcome="DETECTION_EVALUATED_NO_MATCH"))
        not_evaluated = await s.evaluate(
            t, cev=unseen, endpoint="ep_p0c_8",
            derivation=_derivation(unseen,
                                   outcome="DETECTION_NOT_EVALUATED"))

        assert evaluated["evaluation_state"] == "EVALUATED_NO_FINDING"
        assert not_evaluated["evaluation_state"] == "NOT_EVALUATED"
        assert not_evaluated["reason"]

        # both are zero findings — and they are NOT the same answer
        rows, _ = f_store.read(t)
        assert rows == []
        summary = ev_state.summary(t)
        assert summary["by_state"] == {"EVALUATED_NO_FINDING": 1,
                                       "NOT_EVALUATED": 1}
        assert "not a statement that the activity was benign" in \
            summary["state_meaning"]["EVALUATED_NO_FINDING"]

        # an endpoint nobody evaluated is NOT_EVALUATED · the reason says so
        never = ev_state.endpoint_states(t, ["ep_never_seen"])[0]
        assert never["state"] == "NOT_EVALUATED"
        assert never["reason"] == ev_state.NO_EVALUATION_RECORDED

        # and a tenant with no evaluation at all says so explicitly
        empty = ev_state.summary(other)
        assert empty["evidence_with_a_recorded_evaluation"] == 0
        assert "NOT 'evaluated and clean'" in empty["empty_result_meaning"]


# ── 10 · evaluation failure is its own fact ─────────────────────────────
@pytest.mark.asyncio
async def test_evaluation_failure_is_distinguishable_from_no_finding(
        monkeypatch):
    async with _Scope() as s:
        t, cev, ep = s.tenants[0], f"cev_p0c_{s.stamp}_9", "ep_p0c_9"
        s.seed(t, cev=cev, endpoint=ep)

        def boom(*_a, **_k):
            raise RuntimeError("citation store unreachable")
        monkeypatch.setattr(findings_intake, "_citations", boom)

        out = await s.evaluate(t, cev=cev, endpoint=ep)
        assert out["evaluation_state"] == "EVALUATION_FAILED"
        assert "citation store unreachable" in out["reason"]
        assert f_store.read(t)[0] == []

        row = s.sync[ev_state.COLLECTION].find_one({"tenant_id": t})
        assert row["state"] == "EVALUATION_FAILED"
        assert "unknown, not absent" in row["reason"]
        assert ev_state.summary(t)["by_state"] == {"EVALUATION_FAILED": 1}


# ── 11 · an exclusion-suppressed evaluation is its own fact ─────────────
@pytest.mark.asyncio
async def test_an_exclusion_suppressed_evaluation_is_not_reported_as_clean():
    async with _Scope() as s:
        t, cev, ep = s.tenants[0], f"cev_p0c_{s.stamp}_10", "ep_p0c_10"
        s.seed(t, cev=cev, endpoint=ep)
        approved = [{"exclusion_id": "exc_p0c", "set_id": "set_p0c",
                     "type": "PROCESS", "match": "EXACT", "value": "bash",
                     "reason": "tuning",
                     "enforcement_scope": "DETECTION",
                     "affected_engines": [findings_intake.SERVER_ENGINE]}]
        from edr_plane.exclusions import store as exclusion_store
        monkey = exclusion_store.enforceable_for_endpoint

        async def only_ours(*_a, **_k):
            return approved
        exclusion_store.enforceable_for_endpoint = only_ours
        try:
            out = await s.evaluate(t, cev=cev, endpoint=ep)
        finally:
            exclusion_store.enforceable_for_endpoint = monkey

        assert out["evaluation_state"] == "EVALUATION_SUPPRESSED_BY_EXCLUSION"
        assert out["exclusion_id"] == "exc_p0c"
        assert f_store.read(t)[0] == []
        # a suppressed verdict is NOT "evaluated and clean"
        assert ev_state.summary(t)["by_state"] == {
            "EVALUATION_SUPPRESSED_BY_EXCLUSION": 1}


# ── 12 · the ingest path is actually wired ──────────────────────────────
def test_the_authenticated_ingest_path_records_the_finding_plane():
    """Structural: if this call is removed, detections stop becoming
    durable findings silently. The bridge must record BOTH the detection
    outcome and the not-evaluated outcome."""
    import pathlib
    src = pathlib.Path("/app/backend/edr_plane/canonical_bridge.py").read_text()
    assert src.count("record_endpoint_detection(") == 2, (
        "the canonical bridge must hand BOTH the detection outcome and the "
        "DETECTION_NOT_EVALUATED outcome to the finding plane")
    assert "DETECTION_NOT_EVALUATED" in src
