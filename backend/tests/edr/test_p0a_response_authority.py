"""P0-A · EDR response AUTHORITY — deterministic positive and negative proof.

What these tests exist to close: before P0-A, any authenticated principal
holding a console session could isolate a host or kill a process on the
EDR API. There was no action-level permission, no approver distinct from
the requester, and no replay protection.

The authority is NOT re-implemented here and is NOT re-implemented in
EDR: permissions come from the platform's own RBAC and the approval
artifact comes from the single response-engine approval authority. These
tests stub only the AUTHORITY TRANSPORT (`action_spec`, `fetch_approval`)
so the binding rules are proven deterministically without depending on a
live engine; the wired route is proven separately in
`test_p0a_response_authority_live.py`.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

import os

from edr_plane import authority as authz
from edr_plane import response as resp

#: Platform roles used, and what the platform's own RBAC grants them:
#:   responder       → response.execute            (may act, may NOT approve)
#:   soc_manager     → response.approve            (may approve, may NOT act)
#:   l2_investigator → response.recommend only     (may neither)
#:   l1_analyst      → nothing
REQUESTER = "p0a-responder@nivxray.test"
APPROVER = "p0a-soc-manager@nivxray.test"
WEAK_APPROVER = "p0a-l2@nivxray.test"
NO_EXECUTE = "p0a-l1@nivxray.test"
_USERS = {REQUESTER: "responder", APPROVER: "soc_manager",
          WEAK_APPROVER: "l2_investigator", NO_EXECUTE: "l1_analyst"}

ISOLATE_SPEC = {"action_id": "endpoint.isolate", "approval_required": True,
                "destructive": True}
KILL_SPEC = {"action_id": "endpoint.kill_process", "approval_required": True,
             "destructive": True}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _Scope:
    """Real Mongo, isolated tenant, real RBAC principals, always cleaned."""

    def __init__(self):
        self.tenant = f"t_{uuid.uuid4().hex[:12]}"
        self.endpoint = f"ep_{uuid.uuid4().hex[:16]}"
        self.other_endpoint = f"ep_{uuid.uuid4().hex[:16]}"

    async def __aenter__(self):
        self.client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        self.db = self.client[os.environ["DB_NAME"]]
        await resp.ensure_indexes(self.db)
        for email, role in _USERS.items():
            await self.db["users"].update_one(
                {"email": email},
                {"$set": {"email": email, "role": role,
                          "p0a_test_fixture": True}}, upsert=True)
        for ep in (self.endpoint, self.other_endpoint):
            await self.db["edr_endpoints"].insert_one(
                {"tenant_id": self.tenant, "endpoint_id": ep,
                 "hostname": "authority-test-host",
                 "enrollment_state": "ENROLLED"})
        await self.db["edr_isolation_policy"].update_one(
            {"tenant_id": self.tenant},
            {"$set": {"tenant_id": self.tenant,
                      "verification_target": {"host": "1.1.1.1", "port": 443},
                      "allow_list": [], "allow_dns": True,
                      "updated_by": "p0a-fixture", "updated_at": _now()}},
            upsert=True)
        return self

    async def __aexit__(self, *_):
        for c in ("edr_endpoints", "edr_raw_events", "edr_response_commands",
                  "edr_isolation_policy"):
            await self.db[c].delete_many({"tenant_id": self.tenant})
        await self.db["users"].delete_many({"p0a_test_fixture": True})
        self.client.close()

    async def observe(self, *, pid: int, start_ticks: int) -> str:
        ev = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
              "observed_at": "2026-06-01T00:00:00+00:00",
              "start_time": "2026-06-01T00:00:00+00:00",
              "pid": pid, "ppid": 1, "image": "sleep",
              "image_path": "/usr/bin/sleep", "start_ticks": start_ticks,
              "command_line": "/bin/sleep 600", "user": "root"}
        raw_id = f"raw_{uuid.uuid4().hex[:24]}"
        await self.db["edr_raw_events"].insert_one(
            {"raw_id": raw_id, "tenant_id": self.tenant,
             "endpoint_ref": self.endpoint, "payload": json.dumps(ev),
             "derivations": [{"event_id": f"cev_{raw_id[4:]}_0"}]})
        return raw_id

    def approval(self, *, action_id="endpoint.isolate", endpoint=None,
                 tenant=None, requester=REQUESTER, approver=APPROVER,
                 status="approved", approved_at=None,
                 ref=None, disclose_target=True) -> dict:
        """An artifact shaped exactly like the authority's own record."""
        exec_id = ref or f"exec_{uuid.uuid4().hex[:16]}"
        rec = {"execution_id": exec_id, "state": "EXECUTING",
               "action_id": action_id, "tenant_id": tenant or self.tenant,
               "invoker": {"kind": "analyst", "id": requester},
               "parameters": ({"host_id": endpoint or self.endpoint}
                              if disclose_target else {}),
               "canonical_target": {},
               "approval": {"required": True, "status": status,
                            "ref": exec_id, "approved_by": approver,
                            "approved_at": approved_at or _now()}}
        return rec


@pytest.fixture
def stub(monkeypatch):
    """Stub ONLY the authority transport. Every binding rule stays real."""
    state = {"records": {}, "specs": {"endpoint.isolate": ISOLATE_SPEC,
                                      "endpoint.kill_process": KILL_SPEC}}

    async def action_spec(action_id):
        spec = state["specs"].get(action_id)
        if not spec:
            raise authz.AuthorityError(
                "ACTION_NOT_IN_AUTHORITATIVE_CATALOGUE", "not declared", 503)
        return spec

    async def fetch_approval(ref):
        return state["records"].get(ref)

    monkeypatch.setattr(authz, "action_spec", action_spec)
    monkeypatch.setattr(authz, "fetch_approval", fetch_approval)

    def publish(record):
        state["records"][record["execution_id"]] = record
        return record["execution_id"]

    state["publish"] = publish
    return state


async def _authorize(s, *, verb, approval_ref=None, requester=REQUESTER,
                     endpoint=None, session_role=None):
    return await authz.authorize(
        verb=verb, tenant_id=s.tenant, endpoint_id=endpoint or s.endpoint,
        requester=requester, session_role=session_role,
        approval_ref=approval_ref, db=s.db)


# ── positive: an approved, correctly bound action is accepted ──────────

@pytest.mark.asyncio
async def test_valid_approved_isolate_is_accepted_and_records_authority(stub):
    async with _Scope() as s:
        ref = stub["publish"](s.approval())
        decision = await _authorize(s, verb="ISOLATE_ENDPOINT",
                                    approval_ref=ref)
        assert decision["approval_validated"] is True
        assert decision["approved_by"] == APPROVER
        assert decision["authorization_basis"] == "builtin_role:responder"
        cmd = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="ISOLATE_ENDPOINT", target={}, requested_by=REQUESTER,
            reason="p0a", authority=decision)
        # Containment binds a policy, so the record is AUTHORIZED — and
        # AUTHORIZED is still not dispatched, executed or verified.
        assert cmd["state"] == "AUTHORIZED"
        assert cmd["authority"]["approval_ref"] == ref
        assert cmd["authority"]["approved_by"] == APPROVER
        assert cmd["authority"]["principal"] == REQUESTER
        states = [h["state"] for h in cmd["history"]]
        assert "APPROVAL_VALIDATED" in states
        assert cmd["dispatched_at"] is None and cmd["executed_at"] is None \
            and cmd["verified_at"] is None
        stored = await s.db[resp.COLLECTION].find_one(
            {"command_id": cmd["command_id"]})
        assert stored["authority"]["approval_ref"] == ref


@pytest.mark.asyncio
async def test_valid_approved_kill_is_accepted_and_bound_to_identity(stub):
    async with _Scope() as s:
        await s.observe(pid=4242, start_ticks=987654)
        ref = stub["publish"](s.approval(action_id="endpoint.kill_process"))
        decision = await _authorize(s, verb="KILL_PROCESS", approval_ref=ref)
        cmd = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="KILL_PROCESS", target={"pid": 4242},
            requested_by=REQUESTER, reason="p0a", authority=decision)
        assert cmd["state"] == "REQUESTED"
        assert cmd["target"]["observed_start_ticks"] == 987654
        assert cmd["authority"]["approval_ref"] == ref


# ── negative: permission ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_requester_without_response_execute_is_refused(stub):
    async with _Scope() as s:
        ref = stub["publish"](s.approval(requester=NO_EXECUTE))
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT", approval_ref=ref,
                             requester=NO_EXECUTE)
        assert e.value.code == "RESPONSE_EXECUTE_NOT_AUTHORIZED"
        assert e.value.http == 403
        assert await s.db[resp.COLLECTION].count_documents(
            {"tenant_id": s.tenant}) == 0


# ── negative: the approval itself ──────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_approval_is_refused_with_the_workflow_to_use(stub):
    async with _Scope() as s:
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT")
        assert e.value.code == "APPROVAL_REQUIRED"
        assert e.value.http == 403
        assert "respond/approve" in e.value.detail["workflow"]


@pytest.mark.asyncio
async def test_nonexistent_approval_is_refused(stub):
    async with _Scope() as s:
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT",
                             approval_ref="exec_does_not_exist")
        assert e.value.code == "APPROVAL_NOT_FOUND"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["pending", "rejected", ""])
async def test_unapproved_approval_states_are_refused(stub, status):
    async with _Scope() as s:
        ref = stub["publish"](s.approval(status=status))
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT", approval_ref=ref)
        assert e.value.code == "APPROVAL_NOT_APPROVED"


@pytest.mark.asyncio
async def test_approval_for_another_action_authorizes_nothing(stub):
    async with _Scope() as s:
        ref = stub["publish"](s.approval(action_id="endpoint.kill_process"))
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT", approval_ref=ref)
        assert e.value.code == "APPROVAL_ACTION_MISMATCH"


@pytest.mark.asyncio
async def test_approval_for_another_endpoint_authorizes_nothing(stub):
    async with _Scope() as s:
        ref = stub["publish"](s.approval(endpoint=s.other_endpoint))
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT", approval_ref=ref)
        assert e.value.code == "APPROVAL_ENDPOINT_MISMATCH"


@pytest.mark.asyncio
async def test_approval_for_another_tenant_authorizes_nothing(stub):
    async with _Scope() as s:
        ref = stub["publish"](s.approval(tenant="t_someone_else"))
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT", approval_ref=ref)
        assert e.value.code == "APPROVAL_TENANT_MISMATCH"


@pytest.mark.asyncio
async def test_approval_that_discloses_no_target_is_refused(stub):
    async with _Scope() as s:
        ref = stub["publish"](s.approval(disclose_target=False))
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT", approval_ref=ref)
        assert e.value.code == "APPROVAL_TARGET_NOT_DISCLOSED"


@pytest.mark.asyncio
async def test_approval_requested_by_someone_else_is_refused(stub):
    async with _Scope() as s:
        ref = stub["publish"](s.approval(requester="other@nivxray.test"))
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT", approval_ref=ref)
        assert e.value.code == "APPROVAL_REQUESTER_MISMATCH"


@pytest.mark.asyncio
async def test_self_approval_fails_closed(stub):
    async with _Scope() as s:
        ref = stub["publish"](s.approval(approver=REQUESTER))
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT", approval_ref=ref)
        assert e.value.code == "SELF_APPROVAL_REFUSED"


@pytest.mark.asyncio
async def test_approver_without_response_approve_is_refused(stub):
    async with _Scope() as s:
        ref = stub["publish"](s.approval(approver=WEAK_APPROVER))
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT", approval_ref=ref)
        assert e.value.code == "APPROVER_NOT_AUTHORIZED"
        assert e.value.detail["approver"] == WEAK_APPROVER


@pytest.mark.asyncio
async def test_approval_with_no_approver_recorded_is_refused(stub):
    async with _Scope() as s:
        ref = stub["publish"](s.approval(approver=""))
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT", approval_ref=ref)
        assert e.value.code == "APPROVER_NOT_RECORDED"


@pytest.mark.asyncio
async def test_expired_approval_is_refused(stub):
    async with _Scope() as s:
        old = (datetime.now(timezone.utc)
               - timedelta(seconds=authz.APPROVAL_MAX_AGE_SECONDS + 60)
               ).isoformat()
        ref = stub["publish"](s.approval(approved_at=old))
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT", approval_ref=ref)
        assert e.value.code == "APPROVAL_EXPIRED"


@pytest.mark.asyncio
async def test_approval_without_a_usable_time_is_refused(stub):
    async with _Scope() as s:
        ref = stub["publish"](s.approval(approved_at="not-a-time"))
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT", approval_ref=ref)
        assert e.value.code == "APPROVAL_AGE_UNKNOWN"


# ── negative: replay ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_validated_approval_authorizes_exactly_one_command(stub):
    async with _Scope() as s:
        ref = stub["publish"](s.approval())
        decision = await _authorize(s, verb="ISOLATE_ENDPOINT",
                                    approval_ref=ref)
        first = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="ISOLATE_ENDPOINT", target={}, requested_by=REQUESTER,
            reason="p0a", authority=decision)
        assert first["command_id"]
        with pytest.raises(resp.ResponseError) as e:
            await resp.request_action(
                s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
                action="ISOLATE_ENDPOINT", target={},
                requested_by=REQUESTER, reason="p0a-replay",
                authority=decision)
        assert e.value.code == "APPROVAL_ALREADY_CONSUMED"
        assert e.value.http == 409
        assert await s.db[resp.COLLECTION].count_documents(
            {"tenant_id": s.tenant, "action": "ISOLATE_ENDPOINT"}) == 1


# ── fail closed when the authority cannot be consulted ─────────────────

@pytest.mark.asyncio
async def test_unreachable_authority_fails_closed(monkeypatch):
    async with _Scope() as s:
        authz._catalogue_cache.update({"at": 0.0, "actions": None})
        monkeypatch.setattr(authz, "_service_url",
                            lambda: "http://127.0.0.1:59999")
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT",
                             approval_ref="exec_whatever")
        assert e.value.code == "RESPONSE_AUTHORITY_UNAVAILABLE"
        assert e.value.http == 503
        authz._catalogue_cache.update({"at": 0.0, "actions": None})


@pytest.mark.asyncio
async def test_unconfigured_authority_fails_closed(monkeypatch):
    async with _Scope() as s:
        authz._catalogue_cache.update({"at": 0.0, "actions": None})
        monkeypatch.setattr(authz, "_service_url", lambda: None)
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT",
                             approval_ref="exec_whatever")
        assert e.value.code == "RESPONSE_AUTHORITY_NOT_CONFIGURED"
        assert e.value.http == 503
        authz._catalogue_cache.update({"at": 0.0, "actions": None})


@pytest.mark.asyncio
async def test_an_action_the_authority_does_not_declare_fails_closed(stub):
    async with _Scope() as s:
        stub["specs"].pop("endpoint.isolate")
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="ISOLATE_ENDPOINT",
                             approval_ref="exec_whatever")
        assert e.value.code == "ACTION_NOT_IN_AUTHORITATIVE_CATALOGUE"
        assert e.value.http == 503


# ── release: permission-gated, never second-person gated, idempotent ───

@pytest.mark.asyncio
async def test_release_needs_response_execute_but_no_approval(stub):
    async with _Scope() as s:
        decision = await _authorize(s, verb="RELEASE_ISOLATION")
        assert decision["approval_required"] is False
        assert decision["approval_requirement_basis"] == \
            "RESTORATIVE_ACTION_PERMISSION_ONLY"


@pytest.mark.asyncio
async def test_release_without_response_execute_is_refused(stub):
    async with _Scope() as s:
        with pytest.raises(authz.AuthorityError) as e:
            await _authorize(s, verb="RELEASE_ISOLATION",
                             requester=NO_EXECUTE)
        assert e.value.code == "RESPONSE_EXECUTE_NOT_AUTHORIZED"


@pytest.mark.asyncio
async def test_release_of_an_uncontained_endpoint_records_nothing(stub):
    async with _Scope() as s:
        decision = await _authorize(s, verb="RELEASE_ISOLATION")
        with pytest.raises(resp.ResponseError) as e:
            await resp.request_action(
                s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
                action="RELEASE_ISOLATION", target={},
                requested_by=REQUESTER, reason="p0a", authority=decision)
        assert e.value.code == "NO_ACTIVE_ISOLATION"
        assert e.value.http == 409
        assert await s.db[resp.COLLECTION].count_documents(
            {"tenant_id": s.tenant}) == 0


@pytest.mark.asyncio
async def test_repeated_release_is_idempotent_and_claims_nothing(stub):
    async with _Scope() as s:
        await s.db["edr_endpoints"].update_one(
            {"tenant_id": s.tenant, "endpoint_id": s.endpoint},
            {"$set": {"isolation": {"state": "ISOLATED", "at": _now()}}})
        decision = await _authorize(s, verb="RELEASE_ISOLATION")
        first = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="RELEASE_ISOLATION", target={}, requested_by=REQUESTER,
            reason="p0a", authority=decision)
        assert first["verified_at"] is None
        # the endpoint is now recorded as released (verified elsewhere)
        await s.db["edr_endpoints"].update_one(
            {"tenant_id": s.tenant, "endpoint_id": s.endpoint},
            {"$set": {"isolation": {"state": "RELEASED", "at": _now()}}})
        again = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="RELEASE_ISOLATION", target={}, requested_by=REQUESTER,
            reason="p0a-again", authority=decision)
        assert again["idempotent_replay"] is True
        assert again["command_id"] == first["command_id"]
        assert await s.db[resp.COLLECTION].count_documents(
            {"tenant_id": s.tenant, "action": "RELEASE_ISOLATION"}) == 1


# ── the internal automation path is recorded as what it is ─────────────

@pytest.mark.asyncio
async def test_internal_automation_is_labelled_not_operator_authorised():
    async with _Scope() as s:
        cmd = await resp.request_action(
            s.db, tenant_id=s.tenant, endpoint_id=s.endpoint,
            action="RELEASE_ISOLATION", target={},
            requested_by="policy:auto_release", reason="timer")
        assert cmd["authority"]["decision"] == "INTERNAL_POLICY_AUTOMATION"
        assert cmd["authority"]["approval_required"] is False
