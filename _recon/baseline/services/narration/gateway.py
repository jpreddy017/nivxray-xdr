"""
Narration Gateway — the single call-site every consumer uses.

Terminology (owner-locked):

    · **Provider Priority Chain** — the ordered list of providers
      the gateway tries.  Configurable via
      `NARRATION_PROVIDER_ORDER`; default `cloud,offline,deterministic`.
    · **Guaranteed-baseline provider** — the deterministic
      narrator.  Always present in the chain (appended if the
      operator forgot).  Not a "fallback" in the pejorative sense —
      it is the honest floor of the platform's narration
      capability that survives credit exhaustion, cloud outage,
      offline-runtime absence, and legacy NivXRay decommissioning.

    NivXRay XDR Narration Gateway
                 │
           Provider Resolver
                 │
         ┌───────┼────────┐
         ▼       ▼        ▼
       Cloud   Offline  Deterministic  (guaranteed baseline)
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Any

from .contracts import (
    GenerationMode, GroundingError, NarrationContext,
    NarrationKind, NarrationRequest, NarrationResult,
)
from .grounding import validate_machine_truth, validate_paragraphs
from .providers import (
    CloudLLMProvider, DeterministicProvider, NarrationProvider,
    OfflineLLMProvider,
)


log = logging.getLogger("nivxray.narration")


_DEFAULT_ORDER = ("cloud", "offline", "deterministic")


def _parse_order(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return _DEFAULT_ORDER
    parts = tuple(p.strip().lower() for p in raw.split(",") if p.strip())
    # Deterministic MUST always be in the chain; append it if the
    # operator forgot — the platform's honesty rule requires it.
    if "deterministic" not in parts:
        parts = parts + ("deterministic",)
    return parts


class NarrationGateway:
    def __init__(self,
                             providers: dict[str, NarrationProvider] | None = None,
                             order:     tuple[str, ...] | None = None):
        self._providers = providers or {
            "cloud":         CloudLLMProvider(),
            "offline":       OfflineLLMProvider(),
            "deterministic": DeterministicProvider(),
        }
        self._order = order or _parse_order(
            os.environ.get("NARRATION_PROVIDER_ORDER"))

    # --------- introspection --------------------------------------
    def describe(self) -> dict[str, Any]:
        return {
            "order":     list(self._order),
            "providers": [
                {
                    "slot": slot,
                    "name": self._providers[slot].name,
                    "kind": self._providers[slot].kind,
                    "supports": sorted(k.value for k in
                                                self._providers[slot].supports),
                }
                for slot in self._order if slot in self._providers
            ],
        }

    # --------- render ---------------------------------------------
    async def render(self, req: NarrationRequest) -> NarrationResult:
        tried:   list[str] = []
        caveats: list[str] = []

        chain = self._order
        if req.preferred_provider:
            # Try the preferred slot first, then fall through the
            # normal order (deterministic still last).
            pref = req.preferred_provider.lower()
            chain = (pref,) + tuple(x for x in self._order if x != pref)

        # Intelligence-policy gating.  A policy snapshot on the
        # request narrows which slots are allowed.  Deterministic
        # slot is ALWAYS allowed — it is the guaranteed baseline
        # per the NivXRay XDR Intelligence contract.
        snap = req.policy_snapshot or {}
        allow_cloud   = str(snap.get("online_llm", "on")).lower() != "off"
        allow_offline = True   # Offline LLM is ALWAYS_ON per contract.
        if snap:
            caveats.append(
                "policy_snapshot: online_llm=" +
                str(snap.get("online_llm", "on")) +
                " online_ai=" + str(snap.get("online_ai", "on")))

        for slot in chain:
            prov = self._providers.get(slot)
            if prov is None:
                continue
            if req.kind not in prov.supports:
                continue
            # Policy gate — the snapshot may have narrowed the chain.
            if slot == "cloud" and not allow_cloud:
                caveats.append(
                    f"{prov.name} blocked by intelligence policy "
                    "(online_llm=off)")
                continue
            if slot == "offline" and not allow_offline:
                caveats.append(
                    f"{prov.name} blocked by intelligence policy")
                continue
            tried.append(prov.name)
            try:
                draft = await prov.draft(req.kind, req.context, req.session_id)
                validate_paragraphs(list(draft.paragraphs), req.context)
                validate_machine_truth(
                    verdict    = draft.verdict,
                    severity   = draft.severity,
                    confidence = draft.confidence,
                    entities   = list(draft.entities),
                    context    = req.context,
                )
            except GroundingError as e:
                log.info("narration: %s rejected (%s) — trying next",
                         prov.name, e)
                caveats.append(
                    f"{prov.name} rejected by grounding validator: {e}")
                continue
            except Exception as e:                   # noqa: BLE001
                log.warning("narration: %s errored (%s) — trying next",
                            prov.name, e)
                caveats.append(f"{prov.name} error: {e}")
                continue

            # Inherit machine truth verbatim from the context.  We
            # NEVER trust an LLM to change it, even if it echoed
            # correctly — this collapses the entire risk of drift.
            return NarrationResult(
                kind            = req.kind,
                text            = "\n\n".join(p.text for p in draft.paragraphs),
                paragraphs      = tuple(draft.paragraphs),
                evidence_ids    = tuple(req.context.evidence_ids  or ()),
                finding_ids     = tuple(req.context.finding_ids   or ()),
                technique_ids   = tuple(req.context.technique_ids or ()),
                entities        = tuple(draft.entities or req.context.entities or ()),
                verdict         = req.context.verdict,
                severity        = req.context.severity,
                confidence      = req.context.confidence,
                provenance      = tuple(req.context.provenance or ()),
                generation_mode = draft.generation_mode,
                provider        = prov.name,
                fallback_chain  = tuple(tried),
                grounded        = True,
                caveats         = tuple(caveats),
            )

        # UNREACHABLE — the deterministic narrator NEVER raises for
        # supported kinds.  But if the caller passed an unsupported
        # kind and every provider bailed, the platform must still
        # not 500.  Emit an honest empty result.
        return NarrationResult(
            kind            = req.kind,
            text            = "Narration is not yet available for "
                                    f"kind={req.kind.value}.",
            paragraphs      = (),
            evidence_ids    = tuple(req.context.evidence_ids  or ()),
            finding_ids     = tuple(req.context.finding_ids   or ()),
            technique_ids   = tuple(req.context.technique_ids or ()),
            entities        = tuple(req.context.entities      or ()),
            verdict         = req.context.verdict,
            severity        = req.context.severity,
            confidence      = req.context.confidence,
            provenance      = tuple(req.context.provenance    or ()),
            generation_mode = GenerationMode.DETERMINISTIC,
            provider        = "unsupported-kind",
            fallback_chain  = tuple(tried),
            grounded        = True,
            caveats         = tuple(caveats +
                                                [f"no provider supports kind={req.kind.value}"]),
        )


@lru_cache(maxsize=1)
def get_gateway() -> NarrationGateway:
    return NarrationGateway()
