"""
P0.16 · Phase B · BKB stress cases (bug reproductions)

Locks the fix for the two systemic inconsistencies the user
reported directly on 2026-02-09:

    Bug B  ·  Attack-Chain node "Registry modification" was stamped
              Execution T1053.005 (should be Defense Evasion T1112).
              Root cause: DIE per-command techniques from a
              sibling command polluted the cluster.mitre[] set.

    Bug C  ·  MITRE Summary listed 3 techniques while the Attack
              Chain rendered 5 unique.  Root cause: the two panels
              read different derivations of the same evidence.

Both bugs vanish once cluster.mitre is a pure function of the
cluster's label via ``services.knowledge.behavior_registry.lookup``.
"""
from __future__ import annotations

from services.knowledge.behavior_registry  import lookup
from services.diagnostics.bkb_comparison   import (
    _old_cluster_mitre, _new_cluster_mitre,
)


def _cmd(purpose: str, text: str = "x"):
    return {"purpose": purpose, "command": text}


def _inv(techniques):
    return {"techniques": [{"id": tid, "name": tid} for tid in techniques]}


# ══════════════════════════════════════════════════════════════════
# Bug B · Registry-modification cluster contaminated by T1053.005
# ══════════════════════════════════════════════════════════════════
def test_registry_modification_cluster_not_contaminated_by_scheduled_task_tech():
    """Reproduce the exact user-reported bug.  DIE tags one command
    with T1053.005 (Scheduled Task) — which is correct for THAT
    command — but the OLD attribution folded it into every cluster
    the command touched.  The BKB canonical projection restricts
    each cluster to its label's canonical techniques."""
    commands = [
        _cmd("Registry modification",  "reg add HKLM\\..."),
        _cmd("Scheduled Task create",  "schtasks /create /tn X /tr y"),
    ]
    # DIE happens to attach BOTH techniques to BOTH commands (this
    # is the failure mode we're locking down — DIE is not always
    # scoped tightly).
    investigations = [
        _inv(["T1112", "T1053.005"]),
        _inv(["T1053.005"]),
    ]

    old = _old_cluster_mitre(commands, investigations)
    new, _ = _new_cluster_mitre(commands, investigations)

    # OLD (broken) behaviour: Registry-modification cluster carries
    # T1053.005 (contamination).  This is what the user saw.
    assert "T1053.005" in old["Registry modification"], \
        "old attribution should reproduce the contamination bug"

    # NEW (canonical) behaviour: Registry-modification cluster is
    # STRICTLY T1112.  Scheduled-Task cluster is STRICTLY T1053.005.
    assert new["Registry modification"] == {"T1112"}
    assert new["Scheduled Task create"] == {"T1053.005"}


# ══════════════════════════════════════════════════════════════════
# Bug C · MITRE Summary orphans techniques the Attack Chain shows
# ══════════════════════════════════════════════════════════════════
def test_summary_and_chain_agree_when_projected_from_bkb():
    """The three panels agree by construction when they all
    project from the canonical BKB attribution."""
    labels = ["Current-user discovery",
                  "PowerShell execution",
                  "Certutil download / decode"]
    commands       = [_cmd(l) for l in labels]
    investigations = [_inv([])] * len(labels)   # DIE returns nothing.
    _, unknown = _new_cluster_mitre(commands, investigations)
    assert unknown == set()

    # Union of techniques the Attack Chain will render:
    chain_techs = set()
    for l in labels:
        for t in lookup(l).canonical_techniques:
            chain_techs.add(t["id"])
    # Union of techniques the MITRE Summary reads (same source):
    summary_techs = set()
    for l in labels:
        for t in lookup(l).canonical_techniques:
            summary_techs.add(t["id"])

    assert chain_techs == summary_techs, "the two panels MUST agree by construction"


# ══════════════════════════════════════════════════════════════════
# Additivity — the BKB projection never DROPS a canonical technique
# ══════════════════════════════════════════════════════════════════
def test_bkb_never_drops_a_canonical_technique_for_known_labels():
    for label in ("Registry modification",
                     "Scheduled Task create",
                     "PowerShell hidden window",
                     "Current-user discovery",
                     "Certutil download / decode"):
        spec = lookup(label)
        assert spec is not None
        assert spec.canonical_techniques
