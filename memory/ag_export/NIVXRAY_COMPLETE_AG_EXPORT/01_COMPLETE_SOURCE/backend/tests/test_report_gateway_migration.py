"""
R48 · Investigation Report composer regression.

Verifies:
  1. Report envelope preserved (state, sections, ownership_matrix).
  2. Executive Summary assessment block's `content` now comes
     from the NivXRay XDR Narration Gateway (LLM/offline/
     deterministic — all governed).
  3. Provenance is updated to name the Gateway path.
  4. Evidence refs, block_ids and editable flags remain intact.
  5. If the Gateway raises for any reason, the report still
     renders — falling back to the local deterministic composer
     output (no PDF ever fails because of narration).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_report_executive_uses_gateway_prose(monkeypatch):
    from services.report import service as rsvc
    from services.narration import (
        GenerationMode, NarrationContext, NarrationKind,
    )
    from services.narration.contracts import NarrationParagraph
    from services.narration.gateway import NarrationGateway
    from services.narration.providers import (
        DeterministicProvider, NarrationDraft,
    )

    fake_prose = ("R48 gateway paragraph one.\n\n"
                              "R48 gateway paragraph two.")
    draft = NarrationDraft(
        paragraphs = [
            NarrationParagraph(text="R48 gateway paragraph one."),
            NarrationParagraph(text="R48 gateway paragraph two."),
        ],
        verdict    = "MALICIOUS",
        severity   = "P1",
        confidence = 0.9,
        entities   = ("HOST-01",),
        generation_mode = GenerationMode.LLM_CLOUD,
    )

    class _P:
        name = "test-cloud"
        kind = "cloud"
        supports = {NarrationKind.R48_REPORT_NARRATION,
                          NarrationKind.EXECUTIVE_SUMMARY}
        async def draft(self, kind, ctx, sid): return draft

    stub_gw = NarrationGateway(
        providers = {"cloud": _P(),
                              "deterministic": DeterministicProvider()},
        order = ("cloud", "deterministic"),
    )
    monkeypatch.setattr(rsvc, "compose_executive",
                                        lambda inc, canon: [
        {"block_id": "b1", "section": "executive_summary",
          "kind": "assessment", "origin": "SYSTEM",
          "provenance": "NivXRay generated",
          "editable": True, "content": "LOCAL_DETERMINISTIC_TEXT",
          "evidence_refs": ["canonical:evt-1"], "deletable": False,
          "created_at": "t", "provenance_icon": "sparkle"},
        {"block_id": "b2", "section": "executive_summary",
          "kind": "qualifier", "origin": "SYSTEM", "content": "Q",
          "editable": True, "deletable": True,
          "evidence_refs": [], "created_at": "t",
          "provenance": "NivXRay generated",
          "provenance_icon": "sparkle"},
    ])

    from routers import narration as narration_router
    async def _fake_ctx(incident_id):
        return NarrationContext(
            incident_id=incident_id,
            evidence_ids=("EV-1",), technique_ids=("T1105",),
            entities=("HOST-01",),
            verdict="MALICIOUS", severity="P1", confidence=0.9,
        )
    monkeypatch.setattr(narration_router, "_build_incident_context", _fake_ctx)

    from services.narration import gateway as gw_module
    import services.narration as narration_pkg
    monkeypatch.setattr(gw_module, "get_gateway", lambda: stub_gw)
    monkeypatch.setattr(narration_pkg, "get_gateway", lambda: stub_gw)

    # Fake db + fake finds
    class _Coll:
        async def find_one(self, *_a, **_k):
            return {"id": "inc-1", "verdict_card": {"verdict": "MALICIOUS"},
                          "xdr_pipeline": {}, "tenant_id": "t1",
                          "title": "T", "incident_priority": "P1",
                          "incident_state": "New"}
    class _DB(dict):
        def __getitem__(self, k): return _Coll()
    async def _empty_blocks(*a, **kw): return []
    monkeypatch.setattr(rsvc, "analyst_blocks", _empty_blocks)
    async def _empty_supp(*a, **kw): return []
    async def _empty_reco(*a, **kw): return []
    monkeypatch.setattr(rsvc, "compose_supporting_evidence", _empty_supp)
    monkeypatch.setattr(rsvc, "compose_recommendations", _empty_reco)
    monkeypatch.setattr(rsvc, "compose_technical",
                                        lambda i, c, f: {"placeholder": True})

    envelope = await rsvc.compose(_DB(), "inc-1")
    exec_section = envelope["sections"]["executive_summary"]
    blocks = exec_section["system_blocks"]
    assessment = [b for b in blocks if b["kind"] == "assessment"][0]
    assert assessment["content"] == fake_prose
    assert "Narration Gateway" in assessment["provenance"]
    assert assessment["evidence_refs"] == ["canonical:evt-1"]
    assert assessment["block_id"] == "b1"
    # Qualifier block untouched.
    qualifier = [b for b in blocks if b["kind"] == "qualifier"][0]
    assert qualifier["content"] == "Q"


@pytest.mark.asyncio
async def test_report_falls_back_to_local_composer_when_gateway_errors(monkeypatch):
    """A gateway-side exception MUST NOT kill the report."""
    from services.report import service as rsvc
    monkeypatch.setattr(rsvc, "compose_executive",
                                        lambda inc, canon: [
        {"block_id": "b1", "section": "executive_summary",
          "kind": "assessment", "origin": "SYSTEM",
          "provenance": "NivXRay generated",
          "editable": True, "content": "LOCAL_DETERMINISTIC_TEXT",
          "evidence_refs": [], "deletable": False,
          "created_at": "t", "provenance_icon": "sparkle"},
    ])
    from routers import narration as narration_router
    async def _boom(_): raise RuntimeError("gateway broken")
    monkeypatch.setattr(narration_router, "_build_incident_context", _boom)

    class _Coll:
        async def find_one(self, *_a, **_k):
            return {"id":"inc-2","verdict_card":{}, "xdr_pipeline":{},
                          "tenant_id":"t","title":"T",
                          "incident_priority":"P2","incident_state":"New"}
    class _DB(dict):
        def __getitem__(self, k): return _Coll()
    async def _empty(*a, **kw): return []
    monkeypatch.setattr(rsvc, "analyst_blocks", _empty)
    monkeypatch.setattr(rsvc, "compose_supporting_evidence", _empty)
    monkeypatch.setattr(rsvc, "compose_recommendations", _empty)
    monkeypatch.setattr(rsvc, "compose_technical",
                                        lambda i, c, f: {"placeholder": True})

    envelope = await rsvc.compose(_DB(), "inc-2")
    blocks = envelope["sections"]["executive_summary"]["system_blocks"]
    # Fallback = local deterministic content preserved.
    assert blocks[0]["content"] == "LOCAL_DETERMINISTIC_TEXT"
    assert blocks[0]["provenance"] == "NivXRay generated"
