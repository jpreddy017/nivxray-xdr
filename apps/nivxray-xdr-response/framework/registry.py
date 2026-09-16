"""Response Action Registry — mirrors the XDR frontend registry.

Owner-locked: this is the ONLY table the executor consults for
metadata (permissions, approval, reversibility, parameters).  It is
NOT sourced from the collector connector registry — connectors move
data in; actions move control out.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing      import Any, Callable, Dict, List, Optional


@dataclass
class ActionSpec:
    action_id:            str
    provider:             str
    capability:           str
    label:                str
    parameters:           List[Dict[str, Any]] = field(default_factory=list)
    required_permissions: List[Dict[str, Any]] = field(default_factory=list)
    approval_required:    bool = False
    reversible:           bool = False
    destructive:          bool = False
    # STUB_NO_SIDE_EFFECT | REAL_PRODUCT_API — surfaced everywhere so a
    # consumer can never mistake a stub for a real control action.
    dispatch_mode:        str = "STUB_NO_SIDE_EFFECT"
    # An adapter is `async (params, ctx) -> {ok: bool, result: {}, error?: str, reversal_id?: str}`.
    adapter:              Optional[Callable] = None


class ActionRegistry:
    def __init__(self) -> None:
        self._by_id: Dict[str, ActionSpec] = {}

    def register(self, spec: ActionSpec) -> None:
        self._by_id[spec.action_id] = spec

    def get(self, action_id: str) -> Optional[ActionSpec]:
        return self._by_id.get(action_id)

    def list(self) -> List[ActionSpec]:
        return list(self._by_id.values())

    @classmethod
    def default(cls) -> "ActionRegistry":
        from framework.adapters import STUB_ACTIONS
        r = cls()
        for spec in STUB_ACTIONS:
            r.register(spec)
        # P0-1 · the endpoint domain is owned by NivXForge EDR, so those
        # actions dispatch into the authoritative EDR response API
        # instead of a stub. This REPLACES the adapter on the existing
        # spec — it does not add a second registry or a second action.
        from framework.nivxforge_edr import EDR_ACTION_VERBS, dispatch
        for action_id in EDR_ACTION_VERBS:
            spec = r.get(action_id)
            if spec is not None:
                spec.adapter = dispatch
                spec.dispatch_mode = "REAL_PRODUCT_API"
        return r
