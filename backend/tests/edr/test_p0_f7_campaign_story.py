"""P0-F.7 · the Campaign Story must be a projection, and must never fill
in a link it does not have.

The runtime proof (`scripts/p0_f7_campaign_story_proof.py`, 30/30) covers
the happy path against real records. These tests pin the awkward cases
that real data does not conveniently contain: evidence that went missing,
a parser that failed, a response that sits outside the campaign window,
and an incident that never came from an endpoint at all.
"""
from __future__ import annotations

import json
import os
import uuid

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

from edr_plane import campaign_story as story
from edr_plane import response as resp


class _Scope:
    def __init__(self):
        self.tenant = f"t_{uuid.uuid4().hex[:12]}"
        self.endpoint = f"ep_{uuid.uuid4().hex[:16]}"
        self.incident = f"inc_{uuid.uuid4().hex[:20]}"

    async def __aenter__(self):
        self.client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        self.db = self.client[os.environ["DB_NAME"]]
        await self.db["edr_endpoints"].insert_one(
            {"tenant_id": self.tenant, "endpoint_id": self.endpoint,
             "hostname": "story-host", "enrollment_state": "ENROLLED"})
        return self

    async def __aexit__(self, *_):
        for c in ("edr_endpoints", "edr_raw_events", "workspace_cases",
                  "v2_shadow_observations", resp.COLLECTION):
            await self.db[c].delete_many({"tenant_id": self.tenant})
        self.client.close()

    async def observed(self, *, pid, cmd, rule, at, parser_state="OK",
                       retain_raw=True, with_canonical=True):
        raw_id = f"raw_{uuid.uuid4().hex[:24]}"
        cev = f"cev_{raw_id[4:]}_pl"
        ev = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
              "pid": pid, "ppid": 1, "image": "bash",
              "image_path": "/usr/bin/bash", "command_line": cmd,
              "user": "root", "start_ticks": 4242,
              "start_time": at, "parent_image": "python3.11",
              "parent_lookup_state": "OBSERVED"}
        if retain_raw:
            await self.db["edr_raw_events"].insert_one(
                {"raw_id": raw_id, "tenant_id": self.tenant,
                 "dedup_key": raw_id,
                 "endpoint_ref": self.endpoint, "payload": json.dumps(ev),
                 "trust_state": "AUTHENTICATED",
                 "authentication": {"authenticated_endpoint_id":
                                    self.endpoint},
                 "derivations": [{"parser_state": parser_state,
                                  "outcome": "CANONICAL_EVIDENCE_CREATED"},
                                 {"outcome": "DETECTION_MATCHED"}]})
        if with_canonical:
            await self.db["v2_shadow_observations"].insert_one(
                {"tenant_id": self.tenant, "canonical_event_id":
                 f"cev_{raw_id[4:]}_0", "kind": "process_create",
                 "epistemic_state": {"not_observed": ["exit_time"],
                                     "not_supported": ["registry"],
                                     "note": "n/a"},
                 "event": {"kind": "process_create",
                           "process": {"iid": f"proc_{pid}",
                                       "parent_iid": "proc_parent",
                                       "name": "bash"},
                           "provenance": {"ingest_job_id": raw_id}}})
        return {"at": at, "verdict": "MALICIOUS", "score": 80,
                "rule_ids": [rule], "raw_event_id": raw_id,
                "canonical_event_id": cev,
                "process": {"pid": pid, "ppid": 1, "name": "bash",
                            "command_line": cmd}}

    async def incident_with(self, detections, **campaign):
        await self.db["workspace_cases"].insert_one(
            {"tenant_id": self.tenant, "id": self.incident,
             "incident_number": "INC000000999", "title": "story test",
             "incident_state": "new", "incident_priority": "P1",
             "endpoint_campaign": {
                 "endpoint_id": self.endpoint, "hostname": "story-host",
                 "detections": detections,
                 "rule_ids": sorted({r for d in detections
                                     for r in d["rule_ids"]}),
                 "max_label": "MALICIOUS", "max_score": 80,
                 "window_minutes": 30,
                 "first_activity_at": detections[0]["at"],
                 "last_activity_at": detections[-1]["at"], **campaign},
             "xdr_pipeline": {"engine_id": "xdr::iue",
                              "iue_id": "iue_test",
                              "ice_matches": [],
                              "veee": {"label": "MALICIOUS", "score": 80,
                                       "reason": "test reason",
                                       "contributors": [
                                           {"source": "detection",
                                            "weight": 45,
                                            "detail": "EDR-LNX-004"}]}},
             "verdict_card": {"engine": "veee"}})

    async def build(self):
        return await story.build_story(self.db, tenant_id=self.tenant,
                                       incident_id=self.incident)


@pytest.mark.asyncio
async def test_story_projects_the_chain_without_recomputing_it():
    async with _Scope() as s:
        d1 = await s.observed(pid=101, cmd="/bin/bash /tmp/a.sh",
                              rule="EDR-LNX-002",
                              at="2026-06-01T10:00:00+00:00")
        d2 = await s.observed(pid=102, cmd="exec 3<>/dev/tcp/1.1.1.1/9",
                              rule="EDR-LNX-004",
                              at="2026-06-01T10:05:00+00:00")
        await s.incident_with([d1, d2])
        out = await s.build()
        assert out["read_model"] is True
        assert out["engine_id"].endswith("campaign_story")
        assert len(out["activities"]) == 2
        a = out["activities"][0]
        assert a["provenance"]["raw_event_id"] == d1["raw_event_id"]
        assert a["provenance"]["process_iid"] == "proc_101"
        assert a["provenance"]["process_identity_resolved_via"] == \
            "raw_event_id"
        assert a["evidence_states"]["process_start_identity"] == "OBSERVED"
        assert a["epistemic_state"]["not_supported"] == ["registry"]
        # the verdict is the incident's, not the story's
        assert out["reasoning"]["veee"]["reason"] == "test reason"
        assert out["reasoning"]["engines"]["detection"] == "xdr::iue"


@pytest.mark.asyncio
async def test_missing_raw_evidence_becomes_a_gap_not_a_silent_row():
    async with _Scope() as s:
        d = await s.observed(pid=103, cmd="/bin/bash /tmp/b.sh",
                             rule="EDR-LNX-002",
                             at="2026-06-01T10:00:00+00:00",
                             retain_raw=False)
        await s.incident_with([d])
        out = await s.build()
        a = out["activities"][0]
        assert a["provenance"]["raw_event_retained"] is False
        gaps = {g["gap"]: g for g in out["gaps"]}
        assert "raw_evidence" in gaps
        assert gaps["raw_evidence"]["state"] == "NOT_OBSERVED"
        # the command line still shown came from the incident record, and
        # the parser state is not asserted as OK
        assert a["evidence_states"]["parser"] == "UNKNOWN"


@pytest.mark.asyncio
async def test_a_failed_parser_is_reported_as_parser_failed():
    async with _Scope() as s:
        d = await s.observed(pid=104, cmd="/bin/bash /tmp/c.sh",
                             rule="EDR-LNX-002",
                             at="2026-06-01T10:00:00+00:00",
                             parser_state="FAILED")
        await s.incident_with([d])
        out = await s.build()
        assert out["activities"][0]["evidence_states"]["parser"] == "FAILED"


@pytest.mark.asyncio
async def test_missing_canonical_identity_is_named_not_invented():
    async with _Scope() as s:
        d = await s.observed(pid=105, cmd="/bin/bash /tmp/d.sh",
                             rule="EDR-LNX-002",
                             at="2026-06-01T10:00:00+00:00",
                             with_canonical=False)
        await s.incident_with([d])
        out = await s.build()
        a = out["activities"][0]
        assert a["provenance"]["process_iid"] is None
        assert a["provenance"]["process_identity_resolved_via"] is None
        assert any(g["gap"] == "canonical_process_identity"
                   for g in out["gaps"])


@pytest.mark.asyncio
async def test_responses_are_correlated_by_window_and_say_so():
    async with _Scope() as s:
        d = await s.observed(pid=106, cmd="/bin/bash /tmp/e.sh",
                             rule="EDR-LNX-002",
                             at="2026-06-01T10:00:00+00:00")
        await s.incident_with([d])
        inside = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="ISOLATE_ENDPOINT", target={}, requested_by="analyst",
            reason="inside")
        outside = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="ISOLATE_ENDPOINT", target={}, requested_by="analyst",
            reason="outside")
        await s.db[resp.COLLECTION].update_one(
            {"command_id": inside["command_id"]},
            {"$set": {"requested_at": "2026-06-01T10:10:00+00:00"}})
        await s.db[resp.COLLECTION].update_one(
            {"command_id": outside["command_id"]},
            {"$set": {"requested_at": "2026-06-01T18:00:00+00:00"}})
        out = await s.build()
        ids = [r["command_id"] for r in out["responses"]]
        assert ids == [inside["command_id"]], ids
        r = out["responses"][0]
        assert r["link_strength"].endswith("NOT_INCIDENT_KEYED")
        assert "campaign activity window" in r["link_basis"]
        # AUTHORIZED proves nothing, and the story must not imply it did
        assert r["proof"]["success_claimed"] is False
        assert any(g["gap"] == "response_to_incident_binding"
                   for g in out["gaps"])


@pytest.mark.asyncio
async def test_no_response_reads_as_an_absence_of_action_not_of_risk():
    async with _Scope() as s:
        d = await s.observed(pid=107, cmd="/bin/bash /tmp/f.sh",
                             rule="EDR-LNX-002",
                             at="2026-06-01T10:00:00+00:00")
        await s.incident_with([d])
        out = await s.build()
        assert out["responses"] == []
        assert any("absence of action, not an absence of risk" in line
                   for line in out["narrative"])


@pytest.mark.asyncio
async def test_process_exit_is_never_claimed_anywhere():
    async with _Scope() as s:
        d = await s.observed(pid=108, cmd="/bin/bash /tmp/g.sh",
                             rule="EDR-LNX-002",
                             at="2026-06-01T10:00:00+00:00")
        await s.incident_with([d])
        out = await s.build()
        assert out["activities"][0]["evidence_states"]["process_exit"] == \
            "NOT_SUPPORTED"
        assert out["activities"][0]["evidence_states"]["file_writer"] == \
            "NOT_SUPPORTED"
        text = " ".join(out["narrative"]).lower()
        for forbidden in ("exited", "terminated at", "then stopped"):
            assert forbidden not in text


@pytest.mark.asyncio
async def test_a_non_endpoint_incident_gets_no_invented_story():
    async with _Scope() as s:
        await s.db["workspace_cases"].insert_one(
            {"tenant_id": s.tenant, "id": s.incident,
             "incident_number": "INC000001000", "title": "not endpoint"})
        out = await s.build()
        assert out["error"] == "NOT_AN_ENDPOINT_CAMPAIGN"
        assert "Nothing is invented" in out["reason"]
        missing = await story.build_story(s.db, tenant_id=s.tenant,
                                          incident_id="inc_nope")
        assert missing["error"] == "INCIDENT_NOT_FOUND"


@pytest.mark.asyncio
async def test_the_story_is_tenant_scoped():
    async with _Scope() as s:
        d = await s.observed(pid=109, cmd="/bin/bash /tmp/h.sh",
                             rule="EDR-LNX-002",
                             at="2026-06-01T10:00:00+00:00")
        await s.incident_with([d])
        other = await story.build_story(s.db, tenant_id="someone_else",
                                        incident_id=s.incident)
        assert other["error"] == "INCIDENT_NOT_FOUND"
