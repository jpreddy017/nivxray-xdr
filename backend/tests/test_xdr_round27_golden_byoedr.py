"""
Round 27.x · Golden BYO-EDR End-to-End Proof.

Locked owner criterion (2026-02-14):

    Cortex webhook
       → 5 canonical evidence objects
       → 1 promoted incident
       → Recommendation (capability-gated)
       → Execute
       → run_cortex_action()
       → real vendor action id
       → ACTIONED canonical evidence
       → same incident
       → provenance traversal

Every layer in the chain must be independently observable.  A
success at ONE layer does NOT count as success at another.

The test does not use HTTP transport for the vendor call — it
overrides `xdr_cortex_executor.run_cortex_action` with a mock that
returns the vendor envelope shape verbatim, so this test proves
the NivXRay side of the loop without a live Cortex tenant.
"""
from __future__ import annotations

import asyncio
import pytest
import httpx

from detection_content.xdr_cortex_parser import parse_incident
from detection_content.xdr_cortex_ingest import ingest_payload
from detection_content.xdr_cortex_promotion import promote_from_ingest
import routers.xdr_cortex_actions as actions_module


CISCO_LIKE_INCIDENT = {
    "incident_id": "INC-GOLD-1",
    "detection_time":    1_756_691_646_000,
    "modification_time": 1_756_691_800_000,
    "severity": "high",
    "status": "new",
    "description": "A known malicious file was executed.",
    "hosts": ["legion5"],
    "users": ["codexsandboxoffline"],
    "mitre_tactics_ids_and_names":    ["TA0002 - Execution"],
    "mitre_techniques_ids_and_names": ["T1219 - Remote Access Software"],
    "alerts": [{
        "alert_id": "a1",
        "detection_timestamp": 1_756_691_644_000,
        "event_type": "IOC Match",
        "severity": "high",
        "description": "ExecutedMalware.ioc",
        "host_name": "legion5",
        "user_name": "codexsandboxoffline",
        "action_process_image_sha256":
            "806775d9a498229c66663683009b61a5a6c42ce2d3433c43ebcb782ac3ffc6b1",
        "action_file_sha256":
            "3280806d740eae89b19381815a178268e666826a13fbf53b2da63d45a5de8356",
        "mitre_tactic_id_and_name":    "TA0002 - Execution",
        "mitre_technique_id_and_name": "T1219 - Remote Access Software",
    }],
    "key_artifacts": [{
        "type": "sha256",
        "value": "806775d9a498229c66663683009b61a5a6c42ce2d3433c43ebcb782ac3ffc6b1"
    }],
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
            if _match(r, q):
                return dict(r)
        return None
    async def update_one(self, q, update, upsert=False):
        for r in self.rows:
            if _match(r, q):
                _apply(r, update)
                class _R:
                    matched_count = 1; modified_count = 1
                    upserted_id = None
                return _R()
        if upsert:
            new = dict(q)
            _apply(new, update)
            self.rows.append(new)
            class _R:
                matched_count = 0; modified_count = 0
                upserted_id = new
            return _R()
        class _R:
            matched_count = 0; modified_count = 0
            upserted_id = None
        return _R()
    async def update_many(self, q, update):
        n = 0
        for r in self.rows:
            if _match(r, q):
                _apply(r, update)
                n += 1
        class _R:
            matched_count = n; modified_count = n
        return _R()
    async def count_documents(self, q):
        return sum(1 for r in self.rows if _match(r, q))
    def find(self, q=None, proj=None):
        rows = [dict(r) for r in self.rows if _match(r, q or {})]
        return _Cursor(rows)


class _Cursor:
    def __init__(self, rows):
        self._rows = rows
    def sort(self, key, direction):
        self._rows.sort(key=lambda r: r.get(key) or "",
                            reverse=direction == -1)
        return self
    def limit(self, n):
        self._rows = self._rows[:n]
        return self
    def __aiter__(self):
        async def _agen():
            for r in self._rows:
                yield r
        return _agen()


def _match(r, q):
    for k, v in q.items():
        if isinstance(v, dict) and "$ne" in v:
            if r.get(k) == v["$ne"]:
                return False
        elif r.get(k) != v:
            return False
    return True


def _apply(r, update):
    for k, v in (update.get("$set")         or {}).items(): r[k] = v
    for k, v in (update.get("$setOnInsert") or {}).items():
        if k not in r: r[k] = v
    for k in (update.get("$unset") or {}).keys(): r.pop(k, None)
    for k, v in (update.get("$addToSet") or {}).items():
        existing = r.get(k) or []
        # `$addToSet` may take either a single value or `{$each: [...]}`.
        values = v.get("$each") if isinstance(v, dict) and "$each" in v else [v]
        for x in values or []:
            if x not in existing: existing.append(x)
        r[k] = existing
    for k, v in (update.get("$push") or {}).items():
        r.setdefault(k, []).append(v)


class _MemDB(dict):
    def __getitem__(self, key):
        if key not in self:
            super().__setitem__(key, _MemColl())
        return super().__getitem__(key)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_golden_byoedr_e2e(monkeypatch):
    db = _MemDB()

    # Seed the integration record + capability matrix.
    _run(db["xdr_integrations"].insert_one({
        "integration_id": "cortex-gold",
        "vendor":         "palo_alto_cortex_xdr",
        "active":         True,
        "connected":      True,
        "capability_matrix": [
            {"action_id": "ENDPOINT_ISOLATE",
              "capability_id": "edr.isolate_endpoint",
              "state": "AVAILABLE",  "detail": "probed 2026-09-01"},
            {"action_id": "PROCESS_KILL",
              "capability_id": "edr.contain_process",
              "state": "NOT_SUPPORTED",
              "detail": "advanced-api scope missing"},
        ],
        "hosts": ["legion5"],
    }))

    # ── 1. INGEST → 5 canonical evidence rows ────────────
    envelope = _run(ingest_payload(
        db, integration_id="cortex-gold",
        payload=CISCO_LIKE_INCIDENT,
        source="webhook", principal="test"))
    assert envelope["rows_parsed"]    == 5
    assert envelope["rows_inserted"]  == 5
    assert envelope["incidents_promoted"] == 1

    # ── 2. PROMOTION → 1 NivXRay incident ────────────────
    inc = _run(db["xdr_incidents"].find_one(
        {"xdr_incident_id": "INC-GOLD-1"}))
    assert inc is not None
    nivx_id = inc["nivx_incident_id"]
    assert len(inc["evidence_event_ids"]) == 5

    # ── 3. CAPABILITY GATE (backend-enforced) ────────────
    # NOT_SUPPORTED action must be rejected with 409.
    from fastapi import HTTPException
    body_bad = actions_module.ExecuteBody(
        integration_id="cortex-gold",
        xdr_incident_id="INC-GOLD-1",
        action_id="PROCESS_KILL",
        entity={"kind": "process", "value": "idle_report.exe"})
    async def _bad():
        # Patch the executor so we can prove the gate rejects BEFORE
        # any vendor call is made.
        called = {"n": 0}
        async def _boom(*a, **kw): called["n"] += 1; return {"ok": True}
        monkeypatch.setattr(actions_module, "run_cortex_action", _boom)
        monkeypatch.setattr(actions_module, "db", db)
        try:
            await actions_module.cortex_execute(body_bad)
            return "no_exception"
        except HTTPException as e:
            return e.detail, called["n"]
    detail, called_n = _run(_bad())
    assert detail["error"] == "capability_denied"
    assert detail["capability_state"] == "NOT_SUPPORTED"
    assert called_n == 0        # vendor was NOT called

    # ── 4. EXECUTE (AVAILABLE) → vendor mock returns ok  ─
    async def _mock_ok(_db, *, integration_id, action_id, params, principal):
        assert action_id == "ENDPOINT_ISOLATE"
        assert principal == "cortex_response_console"
        return {
            "ok": True,
            "action_id": action_id,
            "vendor": "palo_alto_cortex_xdr",
            "vendor_action_id":  "CORTEX-ACTION-42",
            "vendor_request_id": "req-abc",
            "detail": "endpoint isolate accepted",
            "http_status": 200,
        }
    monkeypatch.setattr(actions_module, "run_cortex_action", _mock_ok)
    monkeypatch.setattr(actions_module, "db", db)
    body_ok = actions_module.ExecuteBody(
        integration_id="cortex-gold",
        xdr_incident_id="INC-GOLD-1",
        recommendation_id="reco-1",
        action_id="ENDPOINT_ISOLATE",
        entity={"kind": "host", "value": "legion5"})
    result = _run(actions_module.cortex_execute(body_ok))
    assert result["ok"] is True
    assert result["vendor_action_id"] == "CORTEX-ACTION-42"
    assert result["result_state"] == "ACTIONED"

    # ── 5. ACTION ROW persisted with full provenance ─────
    action_row = _run(db["xdr_response_actions"].find_one(
        {"action_row_id": result["action_row_id"]}))
    assert action_row["vendor_action_id"] == "CORTEX-ACTION-42"
    assert action_row["recommendation_id"] == "reco-1"
    assert action_row["capability_state_at_request"] == "AVAILABLE"
    assert action_row["result"]["vendor_action_id"] == "CORTEX-ACTION-42"

    # ── 6. ACTIONED canonical evidence written ───────────
    ev = _run(db["xdr_canonical_evidence"].find_one(
        {"event_id": result["evidence_event_id"]}))
    assert ev["source_object_type"] == "action_result"
    assert ev["promotion_state"] == "ACTIONED"
    assert ev["fields"]["vendor_action_id"] == "CORTEX-ACTION-42"
    assert ev["fields"]["provenance"]["action_row_id"] == result["action_row_id"]
    assert ev["fields"]["provenance"]["recommendation_id"] == "reco-1"

    # ── 7. Incident references the new evidence ──────────
    inc2 = _run(db["xdr_incidents"].find_one(
        {"xdr_incident_id": "INC-GOLD-1"}))
    assert inc2["nivx_incident_id"] == nivx_id  # unchanged (idempotent)
    assert result["evidence_event_id"] in inc2["evidence_event_ids"]
    assert len(inc2["evidence_event_ids"]) == 6  # 5 + ACTIONED

    # ── 8. FAILURE PATH is honest — no fake ACTIONED ─────
    async def _mock_fail(_db, *, integration_id, action_id, params, principal):
        return {"ok": False, "action_id": action_id,
                    "vendor": "palo_alto_cortex_xdr",
                    "vendor_action_id": None,
                    "detail": "endpoint offline (Cortex 409)",
                    "http_status": 409}
    monkeypatch.setattr(actions_module, "run_cortex_action", _mock_fail)
    body_fail = actions_module.ExecuteBody(
        integration_id="cortex-gold",
        xdr_incident_id="INC-GOLD-1",
        action_id="ENDPOINT_ISOLATE",
        entity={"kind": "host", "value": "legion5"})
    fail_result = _run(actions_module.cortex_execute(body_fail))
    assert fail_result["ok"] is False
    assert fail_result["result_state"] == "EXECUTION_FAILED"
    fail_ev = _run(db["xdr_canonical_evidence"].find_one(
        {"event_id": fail_result["evidence_event_id"]}))
    assert fail_ev["promotion_state"] == "EXECUTION_FAILED"
    # Failure evidence is ALSO attached to the incident (auditable).
    inc3 = _run(db["xdr_incidents"].find_one(
        {"xdr_incident_id": "INC-GOLD-1"}))
    assert fail_result["evidence_event_id"] in inc3["evidence_event_ids"]

    # ── 9. Provenance traversal closes ───────────────────
    # From incident → ACTIONED evidence event_id → action_row_id →
    # vendor_action_id.  Every step resolves against the same
    # backing store.
    traversal_start_incident = inc3["nivx_incident_id"]
    actioned_events = [
        _run(db["xdr_canonical_evidence"].find_one({"event_id": eid}))
        for eid in inc3["evidence_event_ids"]
    ]
    actioned = [e for e in actioned_events
                     if e and e.get("source_object_type") == "action_result"
                        and e.get("promotion_state") == "ACTIONED"]
    assert len(actioned) == 1
    action_row_id_from_ev = actioned[0]["fields"]["provenance"]["action_row_id"]
    action_row_final = _run(db["xdr_response_actions"].find_one(
        {"action_row_id": action_row_id_from_ev}))
    assert action_row_final["vendor_action_id"] == "CORTEX-ACTION-42"
    assert action_row_final["xdr_incident_id"] == "INC-GOLD-1"
