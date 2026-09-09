"""Intelligence Policy service (hierarchical, auditable).

Data model
──────────
`IntelligencePolicy` — the raw switches at ONE scope.  Global policy
uses this shape directly.  An incident override uses `IntelligencePolicy`
with `null` values for switches that inherit from global.

`EffectivePolicy` — the RESOLVED policy at a specific scope, produced
by `resolve_effective()`.  This is what the Model Gateway consults.

`PolicySnapshot` — immutable capture of the effective policy at
a specific point in time (attached to narration requests etc).
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Literal
import os
import uuid


# ─── shape ──────────────────────────────────────────────────────────
Toggle = Literal["on", "off"]


@dataclass(frozen=True)
class IntelligencePolicy:
    """Raw policy at one scope (global or incident override).

    For an incident override, `None` on a switch means "inherit
    from the parent (global) scope".  For global, `None` is
    normalised to a concrete default at read time.
    """
    online_ai:  Toggle | None = None       # master permission for cloud AI
    online_llm: Toggle | None = None       # cloud LLM sub-permission

    def to_dict(self) -> dict[str, Any]:
        return {"online_ai": self.online_ai, "online_llm": self.online_llm}


@dataclass(frozen=True)
class EffectivePolicy:
    """Resolved policy at a specific scope.

    Fields that are ALWAYS ON at both scopes (offline AI, offline
    LLM, narration engine) are represented as HEALTH not switches.
    """
    online_ai:                Toggle       # "on"|"off"
    online_llm:               Toggle       # "on"|"off" (implicit off if online_ai=off)
    offline_ai:               Toggle       # constant "on"
    offline_llm:              Toggle       # constant "on"
    nivxray_narration_engine: Toggle       # constant "on"

    # Health readouts — decoupled from switches per §OFFLINE ARCHITECTURE.
    offline_ai_health:  Literal["ready", "not_provisioned"]
    offline_llm_health: Literal["ready", "not_provisioned"]
    narration_engine_health: Literal["ready"]      # never fails

    # Provenance — where each switch's ACTIVE value came from.
    online_ai_source:  Literal["global", "incident_override"]
    online_llm_source: Literal["global", "incident_override", "implicit"]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PolicySnapshot:
    """Captured effective policy at request start time — immutable.

    Attached to any long-running operation (narration request,
    orchestration step) so it completes under its original policy
    even if an administrator changes global/incident policy mid-flight.
    """
    snapshot_id: str
    scope:       Literal["global", "incident"]
    scope_id:    str
    captured_at: str
    effective:   EffectivePolicy


# ─── defaults ───────────────────────────────────────────────────────
def default_global_policy() -> IntelligencePolicy:
    """Safe defaults: everything ON.  Operators narrow via UI."""
    return IntelligencePolicy(online_ai="on", online_llm="on")


def default_incident_override() -> IntelligencePolicy:
    """An incident with no override yet — inherit everything."""
    return IntelligencePolicy(online_ai=None, online_llm=None)


# ─── health probes ──────────────────────────────────────────────────
def _offline_ai_health() -> Literal["ready", "not_provisioned"]:
    """The offline AI slot is provisioned when an operator has wired
    a local ML runtime.  We DO NOT fabricate readiness — if no
    runtime env is present, we honestly say `not_provisioned`."""
    if os.environ.get("OFFLINE_AI_ENDPOINT"):
        return "ready"
    return "not_provisioned"


def _offline_llm_health() -> Literal["ready", "not_provisioned"]:
    """Offline LLM (Ollama/local runtime) is `ready` iff env is set."""
    if os.environ.get("OLLAMA_HOST") and os.environ.get("OLLAMA_MODEL"):
        return "ready"
    return "not_provisioned"


# ─── resolver ───────────────────────────────────────────────────────
def _norm(toggle: Toggle | None, default: Toggle = "on") -> Toggle:
    if toggle in ("on", "off"):
        return toggle       # type: ignore[return-value]
    return default


def resolve_effective(
    global_policy:   IntelligencePolicy,
    incident_policy: IntelligencePolicy | None = None,
) -> EffectivePolicy:
    """Compute the effective policy at incident scope.

    Rules (locked):
      · Global is the ceiling.  Incident may only NARROW.
      · Incident `None` → inherit global.
      · Incident `on` where global is `off` → clamped to `off`
        (never widens).
      · `online_llm` is implicitly `off` when `online_ai` is `off`,
        regardless of the raw switches.
    """
    g_ai  = _norm(global_policy.online_ai,  "on")
    g_llm = _norm(global_policy.online_llm, "on")

    if incident_policy is None:
        i_ai_raw:  Toggle | None = None
        i_llm_raw: Toggle | None = None
    else:
        i_ai_raw  = incident_policy.online_ai
        i_llm_raw = incident_policy.online_llm

    # Start with inherited values.
    ai_source:  Literal["global", "incident_override"] = "global"
    llm_source: Literal["global", "incident_override", "implicit"] = "global"

    eff_ai: Toggle  = g_ai
    if i_ai_raw is not None:
        # Incident specified something → clamp to global ceiling.
        eff_ai = "off" if g_ai == "off" else i_ai_raw
        if eff_ai != g_ai or i_ai_raw != g_ai:
            ai_source = "incident_override"

    eff_llm: Toggle = g_llm
    if i_llm_raw is not None:
        eff_llm = "off" if g_llm == "off" else i_llm_raw
        if eff_llm != g_llm or i_llm_raw != g_llm:
            llm_source = "incident_override"

    # AI is master permission for LLM.
    if eff_ai == "off" and eff_llm == "on":
        eff_llm = "off"
        llm_source = "implicit"

    return EffectivePolicy(
        online_ai                = eff_ai,
        online_llm               = eff_llm,
        offline_ai               = "on",
        offline_llm              = "on",
        nivxray_narration_engine = "on",
        offline_ai_health        = _offline_ai_health(),
        offline_llm_health       = _offline_llm_health(),
        narration_engine_health  = "ready",
        online_ai_source         = ai_source,
        online_llm_source        = llm_source,
    )


def capture_snapshot(
    effective: EffectivePolicy,
    *,
    scope:    Literal["global", "incident"],
    scope_id: str,
) -> PolicySnapshot:
    return PolicySnapshot(
        snapshot_id = f"pol-snap-{uuid.uuid4().hex[:12]}",
        scope       = scope,
        scope_id    = scope_id,
        captured_at = datetime.now(timezone.utc).isoformat(),
        effective   = effective,
    )


# ─── storage service (Mongo-backed, RBAC-agnostic; router enforces RBAC) ─
_GLOBAL_COLL   = "xdr_intelligence_policy_global"
_INCIDENT_COLL = "xdr_intelligence_policy_incident"
_AUDIT_COLL    = "xdr_intelligence_policy_audit"


class IntelligencePolicyService:
    def __init__(self, db):
        self._db = db

    # -- Global ------------------------------------------------------
    async def get_global(self, tenant_id: str) -> IntelligencePolicy:
        doc = await self._db[_GLOBAL_COLL].find_one({"_id": tenant_id})
        if not doc:
            return default_global_policy()
        return IntelligencePolicy(
            online_ai  = doc.get("online_ai")  or "on",
            online_llm = doc.get("online_llm") or "on",
        )

    async def set_global(
        self, tenant_id: str, new_policy: IntelligencePolicy,
        *, changed_by: str, changed_by_role: str,
        reason: str | None = None,
    ) -> IntelligencePolicy:
        old = await self.get_global(tenant_id)
        # Master-permission invariant: if online_ai is OFF, online_llm
        # must also be OFF in storage.  This prevents a stale
        # `online_llm=on` value from surviving after the master
        # permission is revoked, which would confuse the UI even
        # though the RESOLVER already forces the effective value off.
        norm_ai  = _norm(new_policy.online_ai,  "on")
        norm_llm = _norm(new_policy.online_llm, "on")
        if norm_ai == "off":
            norm_llm = "off"
        norm = IntelligencePolicy(online_ai=norm_ai, online_llm=norm_llm)
        await self._db[_GLOBAL_COLL].update_one(
            {"_id": tenant_id},
            {"$set": {
                "online_ai":  norm.online_ai,
                "online_llm": norm.online_llm,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "updated_by": changed_by,
            }},
            upsert=True,
        )
        # Audit rows use scope_id='global' at global scope so the
        # UI can query them with a stable key.  Tenant isolation
        # is preserved by the `tenant_id` field on every row.
        await self._audit(
            tenant_id=tenant_id, scope="global", scope_id="global",
            previous=old, new=norm,
            changed_by=changed_by, changed_by_role=changed_by_role,
            reason=reason, source="global",
        )
        return norm

    # -- Incident ----------------------------------------------------
    async def get_incident(
        self, tenant_id: str, incident_id: str,
    ) -> IntelligencePolicy:
        doc = await self._db[_INCIDENT_COLL].find_one(
            {"tenant_id": tenant_id, "incident_id": incident_id})
        if not doc:
            return default_incident_override()
        return IntelligencePolicy(
            online_ai  = doc.get("online_ai"),
            online_llm = doc.get("online_llm"),
        )

    async def set_incident(
        self, tenant_id: str, incident_id: str,
        new_policy: IntelligencePolicy,
        *, changed_by: str, changed_by_role: str,
        reason: str | None = None,
    ) -> IntelligencePolicy:
        old = await self.get_incident(tenant_id, incident_id)
        norm = IntelligencePolicy(
            online_ai  = new_policy.online_ai,        # keep None (=inherit)
            online_llm = new_policy.online_llm,
        )
        await self._db[_INCIDENT_COLL].update_one(
            {"tenant_id": tenant_id, "incident_id": incident_id},
            {"$set": {
                "tenant_id":   tenant_id,
                "incident_id": incident_id,
                "online_ai":   norm.online_ai,
                "online_llm":  norm.online_llm,
                "updated_at":  datetime.now(timezone.utc).isoformat(),
                "updated_by":  changed_by,
            }},
            upsert=True,
        )
        await self._audit(
            tenant_id=tenant_id, scope="incident", scope_id=incident_id,
            previous=old, new=norm,
            changed_by=changed_by, changed_by_role=changed_by_role,
            reason=reason, source="incident",
        )
        return norm

    async def clear_incident_override(
        self, tenant_id: str, incident_id: str,
        *, changed_by: str, changed_by_role: str,
        reason: str | None = None,
    ) -> IntelligencePolicy:
        old = await self.get_incident(tenant_id, incident_id)
        await self._db[_INCIDENT_COLL].delete_one(
            {"tenant_id": tenant_id, "incident_id": incident_id})
        cleared = default_incident_override()
        await self._audit(
            tenant_id=tenant_id, scope="incident", scope_id=incident_id,
            previous=old, new=cleared,
            changed_by=changed_by, changed_by_role=changed_by_role,
            reason=reason, source="incident",
            action="clear",
        )
        return cleared

    # -- Effective + snapshot ---------------------------------------
    async def effective_for_incident(
        self, tenant_id: str, incident_id: str,
    ) -> EffectivePolicy:
        g = await self.get_global(tenant_id)
        i = await self.get_incident(tenant_id, incident_id)
        return resolve_effective(g, i)

    async def snapshot_for_incident(
        self, tenant_id: str, incident_id: str,
    ) -> PolicySnapshot:
        eff = await self.effective_for_incident(tenant_id, incident_id)
        return capture_snapshot(eff, scope="incident", scope_id=incident_id)

    # -- Audit -------------------------------------------------------
    async def _audit(
        self, *, tenant_id: str, scope: str, scope_id: str,
        previous: IntelligencePolicy, new: IntelligencePolicy,
        changed_by: str, changed_by_role: str,
        reason: str | None, source: str,
        action: str = "update",
    ) -> None:
        await self._db[_AUDIT_COLL].insert_one({
            "tenant_id":       tenant_id,
            "scope":           scope,
            "scope_id":        scope_id,
            "action":          action,
            "previous":        previous.to_dict(),
            "new":             new.to_dict(),
            "changed_by":      changed_by,
            "changed_by_role": changed_by_role,
            "reason":          reason,
            "source":          source,
            "recorded_at":     datetime.now(timezone.utc).isoformat(),
            "audit_id":        f"pol-aud-{uuid.uuid4().hex[:14]}",
        })

    async def history(
        self, tenant_id: str, scope: str, scope_id: str,
        *, limit: int = 200,
    ) -> list[dict[str, Any]]:
        cur = self._db[_AUDIT_COLL].find(
            {"tenant_id": tenant_id, "scope": scope, "scope_id": scope_id},
            {"_id": 0},
        ).sort("recorded_at", -1).limit(limit)
        return await cur.to_list(length=limit)
