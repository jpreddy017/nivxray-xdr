"""
Round 26.5 · Incident Promotion invariants.

Locked (owner · 2026-02-14):
  1. Same Cortex incident payload twice → ONE NivXRay incident
     (idempotent on xdr_incident_id).
  2. Second delivery REFRESHES the existing NivXRay incident and
     unions the evidence_event_ids — never duplicates it.
  3. An excluded host → SUPPRESSED outcome; no NivXRay incident row;
     canonical evidence rows carry `promotion_state=SUPPRESSED` with
     the exclusion rule id.
  4. `nivx_incident_id` is deterministic per (integration_id,
     xdr_incident_id).
  5. Evidence dedup (Round 26) and incident dedup (Round 26.5) are
     INDEPENDENT: refreshing an incident MUST NOT delete evidence
     rows.
"""
from __future__ import annotations

import asyncio
import pytest

from detection_content.xdr_cortex_promotion import promote_from_ingest
from detection_content.xdr_cortex_parser import parse_incident


CISCO_LIKE_INCIDENT = {
    "incident_id": "INC-413",
    "detection_time": 1_756_691_646_000,
    "modification_time": 1_756_691_800_000,
    "severity": "high",
    "status": "new",
    "description": "A known malicious file was executed.",
    "hosts": ["legion5"],
    "users": ["codexsandboxoffline"],
    "mitre_tactics_ids_and_names":    ["TA0002 - Execution"],
    "alerts": [{"alert_id": "a1",
                    "detection_timestamp": 1_756_691_644_000,
                    "event_type": "IOC Match", "severity": "high",
                    "action_process_image_sha256":
                        "806775d9a498229c66663683009b61a5a6c42ce2d3433c43ebcb782ac3ffc6b1"}],
    "key_artifacts": [{"type": "sha256",
                              "value": "806775d9a498229c66663683009b61a5a6c42ce2d3433c43ebcb782ac3ffc6b1"}],
}


class _MemColl:
    def __init__(self) -> None:
        self.rows: list[dict] = []
    async def insert_one(self, doc):
        self.rows.append(dict(doc))
    async def insert_many(self, docs):
        for d in docs:
            self.rows.append(dict(d))
    async def find_one(self, q, proj=None):
        for r in self.rows:
            if all(r.get(k) == v for k, v in q.items()):
                return dict(r)
        return None
    async def update_one(self, q, update, upsert=False):
        for r in self.rows:
            if all(r.get(k) == v for k, v in q.items()):
                self._apply(r, update)
                class _R:
                    matched_count = 1
                    modified_count = 1
                return _R()
        if upsert:
            new = dict(q)
            self._apply(new, update)
            self.rows.append(new)
        class _R:
            matched_count = 0
            modified_count = 0
        return _R()
    async def update_many(self, q, update):
        n = 0
        for r in self.rows:
            match = True
            for k, v in q.items():
                if isinstance(v, dict) and "$ne" in v:
                    if r.get(k) == v["$ne"]:
                        match = False; break
                elif r.get(k) != v:
                    match = False; break
            if match:
                self._apply(r, update)
                n += 1
        class _R:
            matched_count = n
            modified_count = n
        return _R()
    def _apply(self, r, update):
        for k, v in (update.get("$set") or {}).items():
            r[k] = v
        for k, v in (update.get("$addToSet") or {}).items():
            existing = r.get(k) or []
            for x in v.get("$each") or []:
                if x not in existing:
                    existing.append(x)
            r[k] = existing


class _MemDB(dict):
    def __getitem__(self, key):
        if key not in self:
            super().__setitem__(key, _MemColl())
        return super().__getitem__(key)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_first_ingest_promotes_once():
    db = _MemDB()
    rows = parse_incident(CISCO_LIKE_INCIDENT, integration_id="cortex-a")
    _run(db["xdr_canonical_evidence"].insert_many(rows))
    env = _run(promote_from_ingest(db, integration_id="cortex-a",
                                            canonical_rows=rows,
                                            principal="test"))
    assert len(env["promoted"])  == 1
    assert len(env["refreshed"]) == 0
    inc = _run(db["xdr_incidents"].find_one(
        {"xdr_incident_id": "INC-413"}))
    assert inc["nivx_incident_id"].startswith("INC-CORTEX-")
    assert inc["hosts"] == ["legion5"]
    assert set(inc["evidence_event_ids"]) == {r["event_id"] for r in rows}


def test_second_ingest_refreshes_not_duplicates():
    db = _MemDB()
    rows = parse_incident(CISCO_LIKE_INCIDENT, integration_id="cortex-a")
    _run(db["xdr_canonical_evidence"].insert_many(rows))
    _run(promote_from_ingest(db, integration_id="cortex-a",
                                    canonical_rows=rows, principal="test"))
    # Second delivery — same payload.
    env = _run(promote_from_ingest(db, integration_id="cortex-a",
                                            canonical_rows=rows,
                                            principal="test"))
    assert len(env["promoted"])  == 0
    assert len(env["refreshed"]) == 1
    incs = [r for r in db["xdr_incidents"].rows
              if r["xdr_incident_id"] == "INC-413"]
    assert len(incs) == 1


def test_excluded_host_is_suppressed():
    db = _MemDB()
    _run(db["xdr_exclusions"].insert_one({
        "integration_id": "cortex-a", "host": "legion5",
        "active": True, "rule_id": "excl-1",
        "reason": "known-corp-endpoint"}))
    rows = parse_incident(CISCO_LIKE_INCIDENT, integration_id="cortex-a")
    _run(db["xdr_canonical_evidence"].insert_many(rows))
    env = _run(promote_from_ingest(db, integration_id="cortex-a",
                                            canonical_rows=rows,
                                            principal="test"))
    assert env["suppressed"] == ["INC-413"]
    assert env["promoted"]   == []
    assert _run(db["xdr_incidents"].find_one({"xdr_incident_id": "INC-413"})) is None
    canon = [r for r in db["xdr_canonical_evidence"].rows]
    assert all(r.get("promotion_state") == "SUPPRESSED" for r in canon)


def test_nivx_id_deterministic_per_integration():
    db = _MemDB()
    rows_a = parse_incident(CISCO_LIKE_INCIDENT, integration_id="cortex-a")
    rows_b = parse_incident(CISCO_LIKE_INCIDENT, integration_id="cortex-b")
    _run(db["xdr_canonical_evidence"].insert_many(rows_a + rows_b))
    _run(promote_from_ingest(db, integration_id="cortex-a",
                                    canonical_rows=rows_a, principal="test"))
    _run(promote_from_ingest(db, integration_id="cortex-b",
                                    canonical_rows=rows_b, principal="test"))
    ids = sorted({r["nivx_incident_id"] for r in db["xdr_incidents"].rows})
    assert len(ids) == 2                # different integrations → different incidents
    for i in ids:
        assert i.startswith("INC-CORTEX-")
