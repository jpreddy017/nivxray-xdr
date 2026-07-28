"""NivXRay Investigation Brain — version identity.

v1.4.0 (2026-08-01) — Stabilization release. The Behaviour Graph is
now a versioned, CI-locked contract. No pipeline / verdict / analyst-
output behaviour changed from v1.3.4 — this is purely the freeze,
regression-lock, and legacy-audit release.

Semantic versioning:
    v1.z.y  — corpus expansion + regression-driven fixes only
    v1.y.0  — new analyst-facing capability that does not add engines
    v2.0.0  — reserved for a genuine architectural change proven
              necessary by repeated real-world evidence
"""
from __future__ import annotations

VERSION            = "1.4.1"
CODENAME           = "Investigation Brain"
RELEASE_DATE       = "2026-07-27"
BASELINE_TESTS     = 332
TRUST_CORPUS_SIZE  = 15
ARCHITECTURE_FROZEN = True   # do not introduce new engines without SME evidence

# The stable component set at this baseline. Adding a component here
# requires a v2.0.0 major bump — deliberately hard to do.
COMPONENTS: tuple[str, ...] = (
    "input_understanding",
    "command_reconstruction_engine",
    "recursive_transformation_engine",
    "semantic_intent_layer",
    "behaviour_graph",
    "verdict_uplift",
    "evidence_graph",
    "analyst_report",
    "trust_metrics_harness",
)


def version_string() -> str:
    return f"NivXRay v{VERSION} · {CODENAME} ({RELEASE_DATE})"


__all__ = [
    "VERSION",
    "CODENAME",
    "RELEASE_DATE",
    "COMPONENTS",
    "ARCHITECTURE_FROZEN",
    "BASELINE_TESTS",
    "TRUST_CORPUS_SIZE",
    "version_string",
]
