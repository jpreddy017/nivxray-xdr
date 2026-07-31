"""ADR-0014 · Slice-C · Unified Verdict Engine (§1.1.3).

One verdict engine. One confidence score. Reads the Evidence Graph
directly — never HTTP JSON, never a legacy verdict blob.

Retires (via deprecation, per §1.1.13) the `executive_card` /
`build_verdict_card` fork. Legacy fields keep working for existing
consumers, but `cio.verdict` becomes the canonical source of truth
that both Lab and Workspace derive from.

Verdict labels (fixed vocabulary):
    - Malicious         · at least one dominant (weight ≥ 9) node fires
    - Suspicious        · at least one high-signal (weight ≥ 7) node fires
                          with no dominant contribution
    - Runtime Dependent · has decoded fragments + LOLBIN or encoded
                          payload but no confirmed malicious behaviour
    - Informational     · vendor telemetry present but no high-signal
                          evidence recovered
    - Undetermined      · graph has no non-artifact evidence

Confidence is a weighted mean of the contributing nodes' confidence,
capped by the highest contributor's weight class.
"""
from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from nivxforge.investigation.graph import EvidenceGraph, Node
from nivxforge.investigation.evidence_priority import (
    WEIGHTS,
    is_dominant,
    is_high_signal,
)
from nivxforge.investigation.ioc_classifier import classify


# ─── Public verdict model ──────────────────────────────────────────

class VerdictContribution(BaseModel):
    """One node's contribution to the verdict. Explainability by design."""
    model_config = ConfigDict(extra="forbid")

    node_id: str
    kind: str
    weight: int
    confidence: float
    category: Optional[str] = None
    label: str = ""


class VerdictNode(BaseModel):
    """The single verdict node · written by the unified engine."""
    model_config = ConfigDict(extra="forbid")

    label: str = Field(..., description="Malicious | Suspicious | Runtime Dependent | Informational | Undetermined")
    confidence: float = Field(..., ge=0.0, le=1.0)
    confidence_pct: int = Field(..., ge=0, le=100)
    reason: str = Field(default="", description="One-sentence rationale citing the top contributor(s).")
    contributors: List[VerdictContribution] = Field(default_factory=list)
    not_counted: List[VerdictContribution] = Field(default_factory=list,
        description="Nodes observed but weight=0 (vendor infra / CA infra) — for explainability.")
    engine: str = Field(default="unified-verdict-engine-v1")


# ─── Node → evidence-kind mapping ──────────────────────────────────

def _kind_for(node: Node) -> str:
    """Map a graph node to an entry in the WEIGHTS table."""
    if node.kind == "ioc":
        ik = (node.attrs or {}).get("ioc_kind", "")
        return {
            "url": "external_ioc_url",
            "domain": "external_ioc_domain",
            "ip": "external_ioc_ip",
            "hash": "hash_ioc",
            "md5": "hash_ioc",
            "sha1": "hash_ioc",
            "sha256": "hash_ioc",
            "email": "external_ioc_url",
        }.get(ik, "external_ioc_domain")
    if node.kind == "mitre_technique":
        return "mitre_technique"
    if node.kind == "lolbin":
        return "lolbin"
    if node.kind == "family_match":
        return "sha_matched_family"
    if node.kind == "behaviour":
        # Behaviour label → keyword map. Deterministic + governed by §1.1.17.
        label = (node.label or "").lower()
        if any(k in label for k in ("credential", "lsass", "mimikatz")):
            return "credential_access"
        if any(k in label for k in ("lateral", "psexec", "winrm", "wmiexec")):
            return "lateral_movement"
        if any(k in label for k in ("persist", "registry run", "scheduled task", "startup")):
            return "persistence"
        if any(k in label for k in ("beacon", "c2", "command-and-control", "callback")):
            return "network_beacon"
        if any(k in label for k in ("reflect", "virtualalloc", "unmanaged", "shellcode")):
            return "reflective_injection"
        if any(k in label for k in ("quarantine", "malicious", "disposition")):
            return "malware_disposition"
        if any(k in label for k in ("signed", "binary proxy", "regsvr32", "rundll32", "mshta")):
            return "signed_binary_proxy"
        if any(k in label for k in ("encoded", "obfusc", "base64", "xor")):
            return "obfuscated_command"
        return "unknown"
    if node.kind == "decoded_fragment":
        # A decoded PowerShell / cmd layer is a minor semantic signal
        op = (node.attrs or {}).get("op", "").lower()
        if "encoded" in op or "powershell" in op:
            return "encoded_powershell"
        return "obfuscated_command"
    return "unknown"


def _category_for(node: Node) -> Optional[str]:
    """For IOC nodes, classify and return the category for down-weighting."""
    if node.kind != "ioc":
        return None
    ik = (node.attrs or {}).get("ioc_kind", "")
    r = classify(node.value or "", ioc_kind=ik)
    return r.category


# ─── Verdict computation ──────────────────────────────────────────

def _label_from_max_weight(top_weight: int, has_decoded: bool) -> str:
    if top_weight >= 9:
        return "Malicious"
    if top_weight >= 7:
        return "Suspicious"
    if top_weight >= 5 and has_decoded:
        return "Runtime Dependent"
    if top_weight >= 1:
        return "Informational"
    return "Undetermined"


def compute_verdict(graph: EvidenceGraph) -> VerdictNode:
    """Compute the single verdict from the Evidence Graph.

    Rules (§1.1.3 / §1.1.16 / §1.1.17):
      - Vendor / CA infra IOCs have weight 0 — recorded in `not_counted`
        but never influence label or confidence.
      - Verdict label is derived from the MAX effective weight.
      - Confidence is the weight-normalised mean of contributor confidences.
      - The verdict node itself is idempotent — same graph, same verdict.
    """
    contributors: List[VerdictContribution] = []
    not_counted: List[VerdictContribution] = []

    has_decoded_fragment = False
    for node in graph.nodes:
        if node.kind == "artifact":
            continue
        if node.kind == "decoded_fragment":
            has_decoded_fragment = True
        kind = _kind_for(node)
        category = _category_for(node)
        base_w = WEIGHTS.get(kind, 0)
        # Category can down-weight (vendor / CA infra → 0)
        if category in ("vendor_infrastructure", "certificate_infrastructure"):
            eff_w = 0
        elif category == "internal_asset":
            eff_w = min(base_w, WEIGHTS["internal_asset"])
        else:
            eff_w = base_w

        contrib = VerdictContribution(
            node_id=node.id,
            kind=kind,
            weight=eff_w,
            confidence=node.confidence,
            category=category,
            label=node.label,
        )
        if eff_w == 0:
            not_counted.append(contrib)
        else:
            contributors.append(contrib)

    if not contributors:
        return VerdictNode(
            label="Undetermined" if not has_decoded_fragment else "Informational",
            confidence=0.0,
            confidence_pct=0,
            reason=("No high-signal evidence recovered from the input; "
                    "verdict cannot be determined."),
            contributors=[],
            not_counted=not_counted,
        )

    # Sort contributors by weight desc, confidence desc — for a stable
    # explanation and a deterministic "top contributor" reason.
    contributors.sort(key=lambda c: (c.weight, c.confidence), reverse=True)
    top = contributors[0]
    top_weight = top.weight

    # Weighted mean confidence
    weight_sum = sum(c.weight for c in contributors)
    if weight_sum:
        conf = sum(c.weight * c.confidence for c in contributors) / weight_sum
    else:
        conf = 0.0
    conf = max(0.0, min(1.0, conf))

    label = _label_from_max_weight(top_weight, has_decoded_fragment)

    # ADR-0007 gating: label cannot exceed the top contributor's ceiling
    # (verdict cap principle — no "Malicious" without at least one
    # dominant contributor).
    if label == "Malicious" and not is_dominant(top_weight):
        label = "Suspicious"
    if label == "Suspicious" and not is_high_signal(top_weight):
        label = "Runtime Dependent" if has_decoded_fragment else "Informational"

    reason = (
        f"Top contributor: {top.label} (kind={top.kind}, weight={top.weight}, "
        f"confidence={top.confidence:.2f}). Total contributing nodes: {len(contributors)}."
    )

    return VerdictNode(
        label=label,
        confidence=round(conf, 4),
        confidence_pct=int(round(conf * 100)),
        reason=reason,
        contributors=contributors,
        not_counted=not_counted,
    )


__all__ = ["compute_verdict", "VerdictNode", "VerdictContribution"]
