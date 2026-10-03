"""The ONLY durable sink for Behavior shadow output.

A shadow MATCH must never be mistakable for an analyst detection. The existing
`edr_behavior.store` is unsafe for that purpose for one decisive reason: the
engine computes `status` as OPEN (or TESTING), so a shadow document landing in
`e3_behavior_detections` would read as an open detection to any present or
future consumer. This store closes that path:

* every write is routed to a SEPARATE logical collection
  (`e3_behavior_shadow_detections`) and this module never names, imports or
  resolves the analyst detection collection;
* every stored document carries non-overridable shadow markers, and `status` is
  forced to `SHADOW_ONLY`, so no reader can see OPEN;
* evidence identity is VALIDATED, never inferred or repaired — a detection whose
  refs do not all belong to the resolved tenant, or which lacks a durable
  `raw_id`, is refused rather than stored with a hole in it;
* every write is READ BACK before it is reported as successful, and the per-write
  outcome is observable. This exists because `SequenceEngine._emit` exhausts its
  retries, increments `rule_errors` and STILL returns `OUTCOME_MATCH` — so
  `outcome == MATCH` is not proof of persistence, and only the sink can tell the
  truth about what became durable.

It satisfies exactly the `DetectionStore` surface the engine requires
(`get` / `find_overlapping` / `put`) and nothing more. It constructs no engine,
evaluates no rule, reads no evidence, touches no checkpoint, writes no Fabric
Finding and no evaluation-state ledger, and creates no collection or index.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

from edr_behavior.detection import material
from edr_behavior.store import ConcurrencyConflict

#: Deliberately NOT the analyst detection collection.
SHADOW_COLLECTION = "e3_behavior_shadow_detections"

#: Additive index design for the shadow sink. Never created by this module.
INDEXES: List[Tuple[List[Tuple[str, int]], Dict[str, Any]]] = [
    ([("tenant_id", 1), ("detection_id", 1)],
     {"unique": True, "name": "uniq_tenant_shadow_detection"}),
    ([("tenant_id", 1), ("shadow_run_id", 1)],
     {"name": "tenant_shadow_run"}),
    ([("tenant_id", 1), ("endpoint_id", 1), ("rule_id", 1), ("rule_version", 1),
      ("scope_key", 1)], {"name": "tenant_endpoint_rule_scope"}),
    ([("tenant_id", 1), ("evidence_keys", 1)],
     {"name": "tenant_evidence_keys"}),
]

STATUS_SHADOW_ONLY = "SHADOW_ONLY"
DETECTION_SOURCE_CLAIM = "NONE"

#: Exclusively ours. A caller that sets any of these to anything else is
#: refused — nothing but this store may make a shadow claim.
SHADOW_MARKERS: Dict[str, Any] = {
    "shadow": True,
    "analyst_visible": False,
    "detection_source_claim": DETECTION_SOURCE_CLAIM,
}

#: What every stored document carries. `status` is FORCED rather than refused:
#: `detection.build` always computes OPEN / TESTING / SUPPRESSED, so refusing it
#: would make the shadow path unusable. The engine's computed value is preserved
#: as `engine_status` for audit, and `status` is rewritten so that no reader can
#: ever see OPEN on a shadow document.
MARKERS: Dict[str, Any] = {**SHADOW_MARKERS, "status": STATUS_SHADOW_ONLY}

#: STREAM identity. A caller may not choose or inherit a different stream.
STREAM_FIELDS = ("replay_id", "ruleset_id", "ruleset_version",
                 "ruleset_content_hash")

WRITE_CREATED = "CREATED"
WRITE_MERGED = "MERGED"
WRITE_DUPLICATE = "DUPLICATE_UNCHANGED"
WRITE_FAILED = "FAILED_CONFLICT"
WRITE_OUTCOMES = (WRITE_CREATED, WRITE_MERGED, WRITE_DUPLICATE, WRITE_FAILED)

REFUSED_TENANT = "SHADOW_DETECTION_TENANT_MISMATCH_REFUSED"
REFUSED_ENDPOINT = "SHADOW_DETECTION_ENDPOINT_MISMATCH_REFUSED"
REFUSED_MARKER_OVERRIDE = "SHADOW_DETECTION_MARKER_OVERRIDE_REFUSED"
REFUSED_NO_EVIDENCE_REFS = "SHADOW_DETECTION_NO_EVIDENCE_REFS"
REFUSED_REF_TENANT = "SHADOW_DETECTION_EVIDENCE_REF_FOREIGN_TENANT"
REFUSED_REF_RAW_ID = "SHADOW_DETECTION_EVIDENCE_REF_NO_DURABLE_RAW_ID"
REFUSED_REF_STABLE_KEY = "SHADOW_DETECTION_EVIDENCE_REF_NO_STABLE_KEY"
REFUSED_KEY_MISMATCH = "SHADOW_DETECTION_EVIDENCE_KEYS_DISAGREE_WITH_REFS"
REFUSED_TRIGGER_ABSENT = "SHADOW_DETECTION_TRIGGER_EVIDENCE_NOT_REPRESENTED"
REFUSED_NO_RULE_IDENTITY = "SHADOW_DETECTION_NO_RULE_IDENTITY"
REFUSED_NO_DETECTION_ID = "SHADOW_DETECTION_NO_DETECTION_ID"
REFUSED_RULESET_STREAM = "SHADOW_DETECTION_RULESET_STREAM_MISMATCH_REFUSED"
REFUSED_NOT_SHADOW = "SHADOW_DETECTION_EXISTING_DOCUMENT_IS_NOT_SHADOW"
REFUSED_READBACK = "SHADOW_DETECTION_READBACK_VERIFICATION_FAILED"
REFUSED_BINDING = "SHADOW_DETECTION_STREAM_BINDING_INCOMPLETE"


class ShadowDetectionRefused(RuntimeError):
    """A refusal with a named reason. Deliberately NOT a ValueError: the engine
    swallows ValueError/KeyError/TypeError into `rule_errors`, and a refusal to
    persist must stay visible to the caller."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ── backing persistence ──────────────────────────────────────────────────

class ShadowDetectionBackend(Protocol):
    collection: str

    async def load(self, tenant_id: str,
                   detection_id: str) -> Optional[Dict[str, Any]]: ...

    async def overlapping(self, query: Dict[str, Any],
                          evidence_keys: Sequence[str]
                          ) -> Optional[Dict[str, Any]]: ...

    async def insert(self, doc: Dict[str, Any]) -> bool: ...

    async def replace(self, doc: Dict[str, Any],
                      expected_revision: int) -> bool: ...


class InMemoryShadowDetectionBackend:
    """Hermetic. Keyed by (tenant_id, detection_id) so cross-tenant reads and
    merges are impossible by construction."""

    collection = SHADOW_COLLECTION

    def __init__(self) -> None:
        self._d: Dict[Tuple[str, str], Dict[str, Any]] = {}

    async def load(self, tenant_id, detection_id):
        d = self._d.get((tenant_id, detection_id))
        return copy.deepcopy(d) if d else None

    async def overlapping(self, query, evidence_keys):
        keys = set(evidence_keys)
        for (t, _), d in sorted(self._d.items()):
            if t != query["tenant_id"]:
                continue
            if any(d.get(k) != v for k, v in query.items()):
                continue
            if keys & set(d.get("evidence_keys") or []):
                return copy.deepcopy(d)
        return None

    async def insert(self, doc):
        k = (doc["tenant_id"], doc["detection_id"])
        if k in self._d:
            return False
        self._d[k] = copy.deepcopy(doc)
        return True

    async def replace(self, doc, expected_revision):
        k = (doc["tenant_id"], doc["detection_id"])
        cur = self._d.get(k)
        if cur is None or int(cur.get("revision") or 0) != int(expected_revision):
            return False
        self._d[k] = copy.deepcopy(doc)
        return True

    def all(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return [copy.deepcopy(d) for (t, _), d in sorted(self._d.items())
                if tenant_id is None or t == tenant_id]


class MongoShadowDetectionBackend:
    """Motor-style. Resolves ONE collection — the shadow one — and no other."""

    collection = SHADOW_COLLECTION

    def __init__(self, db: Any) -> None:
        self._c = db[SHADOW_COLLECTION]

    async def load(self, tenant_id, detection_id):
        return await self._c.find_one(
            {"tenant_id": tenant_id, "detection_id": detection_id}, {"_id": 0})

    async def overlapping(self, query, evidence_keys):
        return await self._c.find_one(
            {**query, "evidence_keys": {"$in": list(evidence_keys)}},
            {"_id": 0}, sort=[("detection_id", 1)])

    async def insert(self, doc):
        try:
            await self._c.insert_one(dict(doc))
        except Exception as e:
            text = str(e).lower()
            if "duplicate key" in text or "e11000" in text:
                return False
            raise
        return True

    async def replace(self, doc, expected_revision):
        res = await self._c.replace_one(
            {"tenant_id": doc["tenant_id"],
             "detection_id": doc["detection_id"],
             "revision": int(expected_revision)}, dict(doc))
        return getattr(res, "matched_count", 0) == 1


# ── the store ────────────────────────────────────────────────────────────

def _text(value: Any, reason: str) -> str:
    s = str(value or "").strip()
    if not s:
        raise ShadowDetectionRefused(reason)
    return s


class ShadowDetectionStore:
    """`DetectionStore` for ONE tenant, ONE endpoint and ONE shadow stream."""

    def __init__(self, backend: Any, *, tenant_id: str, endpoint_id: str,
                 shadow_run_id: str, replay_id: str, ruleset_id: str,
                 ruleset_version: Any, ruleset_content_hash: str) -> None:
        if ruleset_version is None:
            raise ShadowDetectionRefused(REFUSED_BINDING)
        self._b = backend
        self.tenant_id = _text(tenant_id, REFUSED_TENANT)
        self.endpoint_id = _text(endpoint_id, REFUSED_ENDPOINT)
        self.stream: Dict[str, Any] = {
            "shadow_run_id": _text(shadow_run_id, REFUSED_BINDING),
            "replay_id": _text(replay_id, REFUSED_BINDING),
            "ruleset_id": _text(ruleset_id, REFUSED_BINDING),
            "ruleset_version": ruleset_version,
            "ruleset_content_hash": _text(ruleset_content_hash,
                                          REFUSED_BINDING),
        }
        self.writes: List[Dict[str, Any]] = []
        self._trigger_key: Optional[str] = None

    @property
    def collection(self) -> str:
        return getattr(self._b, "collection", SHADOW_COLLECTION)

    def expect_trigger(self, evidence_key: Optional[str]) -> None:
        """The trigger the caller is evaluating. When set, a detection that does
        not represent it is refused — a shadow MATCH built entirely from window
        context is not a result for this item."""
        self._trigger_key = str(evidence_key).strip() if evidence_key else None

    # ── DetectionStore surface ───────────────────────────────────────────

    async def get(self, tenant_id: str,
                  detection_id: str) -> Optional[Dict[str, Any]]:
        if str(tenant_id or "").strip() != self.tenant_id:
            raise ShadowDetectionRefused(REFUSED_TENANT)
        doc = await self._b.load(self.tenant_id,
                                 _text(detection_id, REFUSED_NO_DETECTION_ID))
        if doc is not None:
            self._assert_shadow(doc)
        return doc

    async def find_overlapping(self, *, tenant_id: str, endpoint_id: str,
                               rule_id: str, rule_version: int, scope_key: str,
                               evidence_keys: Sequence[str]
                               ) -> Optional[Dict[str, Any]]:
        """Overlap search is confined to this tenant, endpoint AND ruleset
        stream, so one shadow stream can never merge into another's result."""
        self._assert_scope(tenant_id, endpoint_id)
        keys = [k for k in (evidence_keys or []) if str(k or "").strip()]
        if not keys:
            return None
        doc = await self._b.overlapping(
            {"tenant_id": self.tenant_id, "endpoint_id": self.endpoint_id,
             "rule_id": rule_id, "rule_version": rule_version,
             "scope_key": scope_key,
             "ruleset_content_hash": self.stream["ruleset_content_hash"]}, keys)
        if doc is not None:
            self._assert_shadow(doc)
        return doc

    async def put(self, doc: Dict[str, Any],
                  expected_revision: Optional[int]) -> int:
        body = self._validate_and_stamp(doc)
        det_id = body["detection_id"]
        existing = await self._b.load(self.tenant_id, det_id)
        if existing is not None:
            self._assert_shadow(existing)
            self._assert_stream(existing)
            if material(existing) == material(body):
                rev = int(existing.get("revision") or 0)
                self._record(det_id, WRITE_DUPLICATE, rev, True)
                return rev

        if expected_revision is None:
            if existing is not None:
                self._record(det_id, WRITE_FAILED, None, False,
                             "DETECTION_ALREADY_EXISTS")
                raise ConcurrencyConflict(det_id)
            rev = 1
            body["revision"] = rev
            if not await self._b.insert(body):
                self._record(det_id, WRITE_FAILED, None, False,
                             "CONCURRENT_INSERT")
                raise ConcurrencyConflict(det_id)
            outcome = WRITE_CREATED
        else:
            rev = int(expected_revision) + 1
            body["revision"] = rev
            if not await self._b.replace(body, int(expected_revision)):
                self._record(det_id, WRITE_FAILED, None, False,
                             "REVISION_CONFLICT")
                raise ConcurrencyConflict(det_id)
            outcome = WRITE_MERGED

        stored = await self._b.load(self.tenant_id, det_id)
        if stored is None or int(stored.get("revision") or 0) != rev or \
                material(stored) != material(body) or not self._is_shadow(stored):
            self._record(det_id, WRITE_FAILED, None, False, REFUSED_READBACK)
            raise ShadowDetectionRefused(REFUSED_READBACK)
        self._record(det_id, outcome, rev, True)
        return rev

    # ── verification and observability ───────────────────────────────────

    async def verify(self, detection_id: str) -> Optional[Dict[str, Any]]:
        """Read back what is actually durable. The runner's only trustworthy
        answer to "did this MATCH persist?"."""
        return await self._b.load(self.tenant_id,
                                 _text(detection_id, REFUSED_NO_DETECTION_ID))

    @property
    def last_write(self) -> Optional[Dict[str, Any]]:
        return dict(self.writes[-1]) if self.writes else None

    def write_outcome_for(self, detection_id: str) -> Optional[Dict[str, Any]]:
        for w in reversed(self.writes):
            if w["detection_id"] == detection_id:
                return dict(w)
        return None

    def verified_writes(self) -> List[Dict[str, Any]]:
        return [dict(w) for w in self.writes if w["verified"]]

    def _record(self, detection_id: str, outcome: str,
                revision: Optional[int], verified: bool,
                reason: Optional[str] = None) -> None:
        self.writes.append({"detection_id": detection_id, "outcome": outcome,
                            "revision": revision, "verified": verified,
                            "reason": reason,
                            "collection": self.collection,
                            "shadow_run_id": self.stream["shadow_run_id"]})

    # ── validation ───────────────────────────────────────────────────────

    def _assert_scope(self, tenant_id: str, endpoint_id: str) -> None:
        if str(tenant_id or "").strip() != self.tenant_id:
            raise ShadowDetectionRefused(REFUSED_TENANT)
        if str(endpoint_id or "").strip() != self.endpoint_id:
            raise ShadowDetectionRefused(REFUSED_ENDPOINT)

    def _is_shadow(self, doc: Dict[str, Any]) -> bool:
        return all(doc.get(k) == v for k, v in MARKERS.items())

    def _assert_shadow(self, doc: Dict[str, Any]) -> None:
        if not self._is_shadow(doc):
            raise ShadowDetectionRefused(REFUSED_NOT_SHADOW)

    def _assert_stream(self, doc: Dict[str, Any]) -> None:
        if doc.get("ruleset_content_hash") != \
                self.stream["ruleset_content_hash"]:
            raise ShadowDetectionRefused(REFUSED_RULESET_STREAM)
        if doc.get("tenant_id") != self.tenant_id:
            raise ShadowDetectionRefused(REFUSED_TENANT)
        if doc.get("endpoint_id") != self.endpoint_id:
            raise ShadowDetectionRefused(REFUSED_ENDPOINT)

    def _validate_and_stamp(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Validate identity and evidence, then stamp. Nothing is repaired: a
        missing or foreign piece of evidence identity is a refusal."""
        if not isinstance(doc, dict):
            raise ShadowDetectionRefused(REFUSED_NO_DETECTION_ID)
        for field, value in SHADOW_MARKERS.items():
            if field in doc and doc[field] != value:
                raise ShadowDetectionRefused(REFUSED_MARKER_OVERRIDE)
        for field in STREAM_FIELDS:
            if field in doc and doc[field] != self.stream[field]:
                raise ShadowDetectionRefused(REFUSED_MARKER_OVERRIDE)

        body = {k: v for k, v in doc.items() if k not in ("_id", "revision")}
        _text(body.get("detection_id"), REFUSED_NO_DETECTION_ID)
        if str(body.get("tenant_id") or "").strip() != self.tenant_id:
            raise ShadowDetectionRefused(REFUSED_TENANT)
        if str(body.get("endpoint_id") or "").strip() != self.endpoint_id:
            raise ShadowDetectionRefused(REFUSED_ENDPOINT)
        _text(body.get("rule_id"), REFUSED_NO_RULE_IDENTITY)
        _text(body.get("rule_content_hash"), REFUSED_NO_RULE_IDENTITY)
        if not isinstance(body.get("rule_version"), int):
            raise ShadowDetectionRefused(REFUSED_NO_RULE_IDENTITY)

        refs = body.get("evidence_refs")
        if not isinstance(refs, (list, tuple)) or not refs:
            raise ShadowDetectionRefused(REFUSED_NO_EVIDENCE_REFS)
        ref_keys = set()
        for ref in refs:
            if not isinstance(ref, dict):
                raise ShadowDetectionRefused(REFUSED_NO_EVIDENCE_REFS)
            if str(ref.get("tenant_id") or "").strip() != self.tenant_id:
                raise ShadowDetectionRefused(REFUSED_REF_TENANT)
            if not str(ref.get("raw_id") or "").strip():
                raise ShadowDetectionRefused(REFUSED_REF_RAW_ID)
            key = str(ref.get("stable_key") or "").strip()
            if not key:
                raise ShadowDetectionRefused(REFUSED_REF_STABLE_KEY)
            ref_keys.add(key)
        keys = body.get("evidence_keys")
        if not isinstance(keys, (list, tuple)) or not keys:
            raise ShadowDetectionRefused(REFUSED_KEY_MISMATCH)
        if {str(k).strip() for k in keys} != ref_keys:
            raise ShadowDetectionRefused(REFUSED_KEY_MISMATCH)
        if self._trigger_key and self._trigger_key not in ref_keys:
            raise ShadowDetectionRefused(REFUSED_TRIGGER_ABSENT)

        # `shadow_run_id` is write PROVENANCE, not stream identity: a later run
        # legitimately merges a document a previous run created, so an inherited
        # value is re-stamped to the current run and the first one is retained.
        inherited = str(body.get("shadow_run_id") or "").strip()
        body.update(self.stream)
        if inherited and inherited != self.stream["shadow_run_id"]:
            body["first_shadow_run_id"] = \
                body.get("first_shadow_run_id") or inherited
        engine_status = str(body.get("status") or "").strip()
        if engine_status and engine_status != STATUS_SHADOW_ONLY:
            body["engine_status"] = engine_status
        body.update(MARKERS)
        return body
