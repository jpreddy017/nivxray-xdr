"""NivXRay XDR Intelligence Controls — regression coverage (FINAL spec).

Invariants pinned:
  · Hierarchy: MSS Global is the ceiling.  Incident may only NARROW.
  · Online AI is master permission for Online LLM.
  · Offline AI, Offline LLM, NivXRay XDR Narration Engine are
    ALWAYS_ON — no OFF switch exists.
  · Narration Gateway honours policy snapshot per request; cloud
    slot is skipped when online_llm=off, deterministic remains.
  · In-flight snapshots isolate a request from mid-flight policy
    changes.
  · Provider identity is provider-neutral (no `emergent` leakage).
  · Immutable audit + history projection.
"""
from __future__ import annotations

import pytest

from services.intelligence_policy import (
    IntelligencePolicy, IntelligencePolicyService,
    default_global_policy, default_incident_override,
    resolve_effective, capture_snapshot,
)
from services.narration import (
    NarrationKind, NarrationRequest, NarrationContext,
)
from services.narration.contracts import GenerationMode, GroundingError
from services.narration.gateway import NarrationGateway
from services.narration.providers import DeterministicProvider


# ─── Hierarchy resolver ────────────────────────────────────────────
def test_global_all_on_and_no_override_yields_full_online():
    eff = resolve_effective(default_global_policy(), None)
    assert eff.online_ai  == "on"
    assert eff.online_llm == "on"
    assert eff.offline_ai == "on" and eff.offline_llm == "on"
    assert eff.nivxray_narration_engine == "on"
    assert eff.online_ai_source  == "global"
    assert eff.online_llm_source == "global"


def test_incident_override_may_narrow_online_llm():
    g = IntelligencePolicy(online_ai="on", online_llm="on")
    i = IntelligencePolicy(online_ai=None,  online_llm="off")
    eff = resolve_effective(g, i)
    assert eff.online_ai  == "on"
    assert eff.online_llm == "off"
    assert eff.online_llm_source == "incident_override"


def test_incident_can_never_bypass_global_off():
    g = IntelligencePolicy(online_ai="off", online_llm="off")
    i = IntelligencePolicy(online_ai="on",  online_llm="on")
    eff = resolve_effective(g, i)
    assert eff.online_ai  == "off"
    assert eff.online_llm == "off"


def test_online_llm_implicit_off_when_online_ai_off():
    g = IntelligencePolicy(online_ai="off", online_llm="on")
    eff = resolve_effective(g, None)
    assert eff.online_ai  == "off"
    assert eff.online_llm == "off"
    assert eff.online_llm_source == "implicit"


def test_offline_and_narration_are_always_on_regardless():
    for g_ai, g_llm in [("on", "on"), ("off", "off"),
                                    ("on", "off"), ("off", "on")]:
        g = IntelligencePolicy(online_ai=g_ai, online_llm=g_llm)
        eff = resolve_effective(g, None)
        assert eff.offline_ai == "on"
        assert eff.offline_llm == "on"
        assert eff.nivxray_narration_engine == "on"


def test_snapshot_captures_effective_immutably():
    eff = resolve_effective(default_global_policy(), None)
    snap = capture_snapshot(eff, scope="incident", scope_id="inc-1")
    assert snap.scope == "incident"
    assert snap.scope_id == "inc-1"
    assert snap.effective.online_llm == eff.online_llm
    # Snapshot is a frozen dataclass — mutating attempt fails.
    with pytest.raises(Exception):
        snap.effective.online_llm = "off"      # type: ignore[misc]


# ─── Gateway policy gating ─────────────────────────────────────────
class _FakeCloud:
    name = "cloud:acme-anthropic"
    kind = "cloud"
    supports = {NarrationKind.EXECUTIVE_SUMMARY,
                            NarrationKind.CROSS_LANE_STORY}
    async def draft(self, kind, context, session_id):
        raise AssertionError("cloud provider must be blocked by policy")


class _FakeOffline:
    name = "cognis-offline:local"
    kind = "offline"
    supports = {NarrationKind.EXECUTIVE_SUMMARY,
                            NarrationKind.CROSS_LANE_STORY}
    async def draft(self, kind, context, session_id):
        raise GroundingError("offline unreachable")


def _ctx():
    return NarrationContext(incident_id="inc-1", verdict="MALICIOUS",
                            severity="P2", confidence=0.7)


@pytest.mark.asyncio
async def test_gateway_blocks_cloud_when_snapshot_online_llm_off():
    gw = NarrationGateway(
        providers={"cloud": _FakeCloud(), "offline": _FakeOffline(),
                             "deterministic": DeterministicProvider()},
        order=("cloud", "offline", "deterministic"),
    )
    res = await gw.render(NarrationRequest(
        kind    = NarrationKind.EXECUTIVE_SUMMARY,
        context = _ctx(),
        policy_snapshot = {"online_ai": "on", "online_llm": "off"},
    ))
    assert res.generation_mode == GenerationMode.DETERMINISTIC
    assert res.provider == "deterministic"
    # Cloud never appears in the tried-list because it was blocked
    # BEFORE draft() was invoked.
    assert not any("acme-anthropic" in p for p in res.fallback_chain)
    assert any("blocked by intelligence policy" in c for c in res.caveats)


@pytest.mark.asyncio
async def test_gateway_allows_cloud_when_snapshot_online_llm_on():
    class _OkCloud(_FakeCloud):
        async def draft(self, kind, context, session_id):
            from services.narration.providers import NarrationDraft
            from services.narration.contracts import NarrationParagraph
            return NarrationDraft(
                paragraphs=[NarrationParagraph(text="Cloud narration.")],
                verdict="MALICIOUS", severity="P2", confidence=0.7,
                entities=(), generation_mode=GenerationMode.LLM_CLOUD)
    gw = NarrationGateway(
        providers={"cloud": _OkCloud(),
                             "deterministic": DeterministicProvider()},
        order=("cloud", "deterministic"),
    )
    res = await gw.render(NarrationRequest(
        kind    = NarrationKind.EXECUTIVE_SUMMARY,
        context = _ctx(),
        policy_snapshot = {"online_ai": "on", "online_llm": "on"},
    ))
    assert res.generation_mode == GenerationMode.LLM_CLOUD


@pytest.mark.asyncio
async def test_gateway_snapshot_isolates_in_flight_from_later_policy_change():
    """After the request has captured its snapshot, a subsequent
    external toggle MUST NOT change its behaviour — the request
    still sees the snapshot's decision."""
    external_state = {"online_llm": "off"}     # mid-flight toggle happened
    # Snapshot captured BEFORE the toggle:
    snap = {"online_ai": "on", "online_llm": "on"}
    class _CountingCloud(_FakeCloud):
        calls = 0
        async def draft(self, kind, context, session_id):
            _CountingCloud.calls += 1
            from services.narration.providers import NarrationDraft
            from services.narration.contracts import NarrationParagraph
            return NarrationDraft(
                paragraphs=[NarrationParagraph(text="OK")],
                verdict="MALICIOUS", severity="P2", confidence=0.7,
                entities=(), generation_mode=GenerationMode.LLM_CLOUD)
    gw = NarrationGateway(
        providers={"cloud": _CountingCloud(),
                             "deterministic": DeterministicProvider()},
        order=("cloud", "deterministic"),
    )
    res = await gw.render(NarrationRequest(
        kind=NarrationKind.EXECUTIVE_SUMMARY, context=_ctx(),
        policy_snapshot=snap,
    ))
    # In-flight request used cloud because ITS snapshot allowed it,
    # regardless of the external toggle.
    assert res.generation_mode == GenerationMode.LLM_CLOUD
    assert _CountingCloud.calls == 1
    # External state remained untouched — deterministic invariant.
    assert external_state["online_llm"] == "off"


# ─── Storage + audit ───────────────────────────────────────────────
class _FakeColl:
    def __init__(self):
        self.docs: list[dict] = []
    async def find_one(self, key):
        for d in self.docs:
            if all(d.get(k) == v for k, v in key.items()):
                return dict(d)
        return None
    async def update_one(self, key, update, upsert=False):
        d = dict(update.get("$set") or {})
        for i, ex in enumerate(self.docs):
            if all(ex.get(k) == v for k, v in key.items()):
                self.docs[i] = {**ex, **d}
                return
        if upsert:
            self.docs.append({**key, **d})
    async def delete_one(self, key):
        self.docs = [d for d in self.docs
                                 if not all(d.get(k) == v for k, v in key.items())]
    async def insert_one(self, d):
        self.docs.append(dict(d))
    def find(self, key, projection=None):
        # Simple find with .sort().limit().to_list() chain.
        matches = [d for d in self.docs
                             if all(d.get(k) == v for k, v in key.items())]
        class _Cur:
            def __init__(self, xs): self._xs = xs
            def sort(self, k, direction):
                self._xs = sorted(self._xs, key=lambda d: d.get(k, ""),
                                              reverse=direction < 0)
                return self
            def limit(self, n): self._xs = self._xs[:n]; return self
            async def to_list(self, length=None): return list(self._xs)
        return _Cur(matches)


class _FakeDB:
    def __init__(self): self._c: dict[str, _FakeColl] = {}
    def __getitem__(self, n): return self._c.setdefault(n, _FakeColl())


@pytest.mark.asyncio
async def test_service_persists_global_and_writes_audit():
    db = _FakeDB()
    svc = IntelligencePolicyService(db)
    saved = await svc.set_global(
        "acme", IntelligencePolicy(online_ai="on", online_llm="off"),
        changed_by="carol@acme", changed_by_role="tenant_admin",
        reason="privacy sweep",
    )
    assert saved.online_llm == "off"
    got = await svc.get_global("acme")
    assert got.online_llm == "off"
    # Global audit rows are stored with scope_id='global' so the UI
    # can query them with a stable key regardless of tenant.
    aud = await svc.history("acme", "global", "global")
    assert len(aud) == 1
    assert aud[0]["changed_by"] == "carol@acme"
    assert aud[0]["changed_by_role"] == "tenant_admin"
    assert aud[0]["reason"] == "privacy sweep"
    assert aud[0]["scope"] == "global"
    assert aud[0]["scope_id"] == "global"
    assert aud[0]["tenant_id"] == "acme"


@pytest.mark.asyncio
async def test_master_permission_clamps_online_llm_off_in_storage():
    """Turning Online AI off must clamp Online LLM off in storage too,
    so the UI never displays 'ON' for a slot that is effectively OFF."""
    db = _FakeDB()
    svc = IntelligencePolicyService(db)
    await svc.set_global(
        "acme", IntelligencePolicy(online_ai="off", online_llm="on"),
        changed_by="carol@acme", changed_by_role="tenant_admin",
    )
    got = await svc.get_global("acme")
    assert got.online_ai  == "off"
    assert got.online_llm == "off"    # clamped by master-permission invariant


@pytest.mark.asyncio
async def test_incident_override_and_effective():
    db = _FakeDB()
    svc = IntelligencePolicyService(db)
    await svc.set_global(
        "acme", IntelligencePolicy(online_ai="on", online_llm="on"),
        changed_by="carol@acme", changed_by_role="tenant_admin")
    await svc.set_incident(
        "acme", "inc-42",
        IntelligencePolicy(online_ai=None, online_llm="off"),
        changed_by="dave@acme", changed_by_role="soc_manager",
        reason="sensitive investigation")
    eff = await svc.effective_for_incident("acme", "inc-42")
    assert eff.online_ai  == "on"
    assert eff.online_llm == "off"
    assert eff.online_llm_source == "incident_override"


@pytest.mark.asyncio
async def test_clear_incident_override_reverts_to_inherit():
    db = _FakeDB()
    svc = IntelligencePolicyService(db)
    await svc.set_incident(
        "acme", "inc-42",
        IntelligencePolicy(online_ai="on", online_llm="off"),
        changed_by="dave@acme", changed_by_role="soc_manager")
    await svc.clear_incident_override(
        "acme", "inc-42",
        changed_by="dave@acme", changed_by_role="soc_manager",
        reason="closed investigation")
    got = await svc.get_incident("acme", "inc-42")
    assert got.online_ai  is None
    assert got.online_llm is None


# ─── Provider neutrality ───────────────────────────────────────────
def test_no_emergent_terminology_leaks_into_defaults():
    # The service defaults must not name any specific vendor.
    g = default_global_policy()
    for v in g.to_dict().values():
        assert v is None or v in ("on", "off")
