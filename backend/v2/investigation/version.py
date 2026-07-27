"""NivXRay Investigation Brain — version identity.

Locked as the stable baseline on 2026-07-29 per Product Owner
directive:

    "Deploy this version as the stable Investigation Brain baseline.
     Freeze the core architecture. From now on, evolve the platform
     primarily through real-world corpus expansion, regression-driven
     improvements, analyst workflow enhancements, and report quality."

Semantic versioning:
    v1.0.z  — corpus expansion + regression-driven fixes only
    v1.y.0  — new analyst-facing capability that does not add engines
    v2.0.0  — reserved for a genuine architectural change proven
              necessary by repeated real-world evidence
"""
from __future__ import annotations

VERSION            = "1.0.0"
CODENAME           = "Investigation Brain"
RELEASE_DATE       = "2026-07-29"
BASELINE_TESTS     = 326
TRUST_CORPUS_SIZE  = 11
ARCHITECTURE_FROZEN = True   # do not introduce new engines without SME evidence

# The stable component set at this baseline. Adding a component here
# requires a v2.0.0 major bump — deliberately hard to do.
COMPONENTS: tuple[str, ...] = (
    "input_understanding",
    "command_reconstruction_engine",
    "recursive_transformation_engine",
    "semantic_intent_layer",
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
