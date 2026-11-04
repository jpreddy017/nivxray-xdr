"""RC5 · Phase 11.0 — Evidence Knowledge Graph feature flag + metrics.

Env vars (backend/.env)
-----------------------
NIVX_EVIDENCE_GRAPH        "off" | "sidecar"        (default: "off")
NIVX_EVIDENCE_GRAPH_METRICS "off" | "on"            (default: "off")

Contract
--------
* `"off"`     — no work is done. Builder short-circuits. Zero overhead.
* `"sidecar"` — graph is constructed alongside `ExecGraph` and attached to
                the pipeline result under `evidence_graph`. **Does NOT
                influence verdicts.**

Metrics (when enabled)
----------------------
Every build emits a `EvidenceGraphMetrics` record capturing node/edge
counts, wall-time in milliseconds, integrity error count, and the
`ExecGraph.SCHEMA_VERSION` used. These are opt-in because we do not want
to add I/O overhead to the hot path unless we are actively measuring.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, asdict
from typing import Any, Dict, Literal

EvidenceGraphMode = Literal["off", "sidecar"]


def evidence_graph_mode() -> EvidenceGraphMode:
    v = (os.environ.get("NIVX_EVIDENCE_GRAPH") or "off").strip().lower()
    return "sidecar" if v == "sidecar" else "off"


def evidence_graph_metrics_enabled() -> bool:
    v = (os.environ.get("NIVX_EVIDENCE_GRAPH_METRICS") or "off").strip().lower()
    return v == "on"


@dataclass(frozen=True)
class EvidenceGraphMetrics:
    node_count: int
    edge_count: int
    build_ms: float
    peak_memory_kb: float
    integrity_errors: int
    exec_graph_schema_version: int
    evidence_graph_schema_version: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


__all__ = [
    "EvidenceGraphMode",
    "evidence_graph_mode",
    "evidence_graph_metrics_enabled",
    "EvidenceGraphMetrics",
]
