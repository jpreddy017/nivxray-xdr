"""ADR-0014 · Slice-C · Unified Verdict Engine (§1.1.3).

P1-02b · Rev 2 · Tiered evidence classes + deterministic escalation.

One verdict engine. One confidence formula. Reads the Evidence Graph
and CIO metadata directly — never HTTP JSON, never a legacy blob.

Design invariants:

  1. **Tiered evidence classes** (see `evidence_classes.py`) replace
     hand-tuned per-kind numbers. Adding a new detection is 1 line.
  2. **Deterministic escalation rules** promote verdicts when specific
     evidence combinations fire — pattern recognition, not scoring.
  3. **Monotonic confidence** (Noisy-OR): adding a contributor can only
     RAISE confidence, never lower it. Enforced by CI.
  4. **Every contributor is visible + traceable** — either it maps to
     a real graph node, or to a `META-<source>` pseudo-id that names
     the CIO metadata field it came from.
  5. **Explainability**: `verdict.reason` cites the top three
     contributors + the escalation rule (if any) that fired.

Verdict vocabulary (fixed):
    Malicious · Suspicious · Runtime Dependent · Informational · Undetermined
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from nivxforge.investigation.graph import EvidenceGraph, Node
from nivxforge.investigation.evidence_classes import (
    CLASS_WEIGHT,
    EvidenceClass,
    apply_escalation,
    class_of,
    weight_of,
)
from nivxforge.investigation.ioc_classifier import classify


# ─── Public verdict model ──────────────────────────────────────────

class VerdictContribution(BaseModel):
    """One contributor's imprint on the verdict. Explainability by design."""
    model_config = ConfigDict(extra="forbid")

    node_id: str                                            # Graph node id OR `META-<slug>`
    kind: str
    weight: float                                           # Numeric weight (was int; now float for CONTEXT=0.5)
    confidence: float                                       # Per-contributor confidence 0..1
    category: Optional[str] = None
    label: str = ""
    evidence_class: Optional[str] = None                    # critical | high | medium | low | context
    source: str = "graph"                                   # "graph" | "metadata:<field>"
    escalated_by: Optional[str] = None                      # Which escalation rule flagged this


class VerdictNode(BaseModel):
    """The single verdict node · written by the unified engine."""
    model_config = ConfigDict(extra="forbid")

    label: str = Field(..., description="Malicious | Suspicious | Runtime Dependent | Informational | Undetermined")
    confidence: float = Field(..., ge=0.0, le=1.0)
    confidence_pct: int = Field(..., ge=0, le=100)
    reason: str = Field(default="", description="Human-readable rationale citing top contributors.")
    contributors: List[VerdictContribution] = Field(default_factory=list)
    not_counted: List[VerdictContribution] = Field(default_factory=list,
        description="Nodes observed but weight=0 (vendor infra / CA infra) — for explainability.")
    escalation_rule: Optional[str] = Field(default=None,
        description="Which deterministic escalation rule promoted the verdict (if any).")
    engine: str = Field(default="unified-verdict-engine-v1")


# ─── Node → contributor-kind mapping ──────────────────────────────

def _kind_for_graph_node(node: Node) -> str:
    """Map an EvidenceGraph node to a contributor-kind token.

    Kinds must exist in `evidence_classes.KIND_TO_CLASS`.
    """
    if node.kind == "ioc":
        ik = ((node.attrs or {}).get("ioc_kind") or "").lower()
        # If OSINT enrichment flagged the IOC as confirmed malicious,
        # promote it to the CRITICAL class.
        enr = (node.attrs or {}).get("enrichment") or {}
        provs = enr.get("providers") or []
        hits = sum(1 for p in provs if p.get("state") == "hit"
                   and (p.get("malicious") or 0) >= 3)
        if hits >= 1:
            if ik in ("ip",):
                return "confirmed_malicious_ip"
            if ik in ("url", "domain"):
                return "confirmed_malicious_url"
            if ik in ("hash", "md5", "sha1", "sha256"):
                return "confirmed_malicious_hash"
        return {
            "url":    "external_ioc_url",
            "domain": "external_ioc_domain",
            "ip":     "external_ioc_ip",
            "hash":   "hash_ioc",
            "md5":    "hash_ioc",
            "sha1":   "hash_ioc",
            "sha256": "hash_ioc",
            "email":  "external_ioc_url",
        }.get(ik, "external_ioc_domain")

    if node.kind == "mitre_technique":
        return "mitre_technique"

    if node.kind == "lolbin":
        # Bucket well-known lolbins into their explicit abuse tokens so
        # escalation rules can pick them up individually.
        v = (node.value or "").lower()
        return {
            "bitsadmin":   "bits_abuse",
            "rundll32":    "rundll32_abuse",
            "regsvr32":    "regsvr32_abuse",
            "mshta":       "mshta_abuse",
            "wmic":        "wmi_abuse",
            "certutil":    "lolbin",
            "powershell":  "lolbin",
        }.get(v, "lolbin")

    if node.kind == "family_match":
        return "sha_matched_family"

    if node.kind == "behaviour":
        # Behaviour label → keyword map. Deterministic + governed by §1.1.17.
        label = (node.label or "").lower()
        if any(k in label for k in ("credential", "lsass", "mimikatz")):
            return "lsass_access" if "lsass" in label else "credential_access"
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
        if any(k in label for k in ("child process", "childproc", "spawn", "execution")):
            return "child_process_execution"
        if any(k in label for k in ("staging", "download", "upload", "exfil")):
            return "network_staging"
        return "behavioural_note"

    if node.kind == "decoded_fragment":
        op = ((node.attrs or {}).get("op") or "").lower()
        preview = ((node.value or "") + " " + (node.label or "")).lower()
        # Structural: which decoder ran
        if "base64" in op or "b64" in op:
            base = "base64_layer"
        elif "hex" in op:
            base = "hex_layer"
        elif "gzip" in op or "deflate" in op or "lzma" in op or "zstd" in op:
            base = "compression_layer"
        elif "archive" in op or "zip" in op or "tar" in op:
            base = "archive_extract"
        elif "encoded" in op or "powershell" in op:
            base = "encoded_powershell"
        else:
            base = "obfuscated_command"
        # Semantic: did it reveal IEX / Invoke-Expression?
        if "invoke-expression" in preview or "iex " in preview or preview.startswith("iex"):
            return "invoke_expression"
        return base

    return "unknown"


def _category_for(node: Node) -> Optional[str]:
    """For IOC nodes, classify and return the category for down-weighting."""
    if node.kind != "ioc":
        return None
    ik = (node.attrs or {}).get("ioc_kind", "")
    try:
        r = classify(node.value or "", ioc_kind=ik)
        return r.category
    except Exception:
        return None


# ─── Metadata contributor synthesis ────────────────────────────────

def _synthesize_metadata_contributors(metadata: Optional[Dict[str, Any]]) -> List[VerdictContribution]:
    """Emit contributors from `cio.metadata` fields that the graph doesn't
    natively carry — Rules · LOLBAS · Recipes · YARA · Sigma · TI shield.

    Each returned contribution has:
      * `node_id`  = `META-<slug>` (traceable to origin)
      * `source`   = `metadata:<field>`
      * `kind`     ∈ evidence_classes.KIND_TO_CLASS
    """
    if not metadata:
        return []
    out: List[VerdictContribution] = []
    idx = 0

    def _add(kind: str, label: str, conf: float, source_field: str) -> None:
        nonlocal idx
        idx += 1
        cls = class_of(kind)
        w = weight_of(kind)
        if w == 0 or cls is None:
            return
        out.append(VerdictContribution(
            node_id=f"META-{source_field}-{idx:03d}",
            kind=kind,
            weight=w,
            confidence=max(0.0, min(1.0, conf)),
            label=label,
            evidence_class=cls.value,
            source=f"metadata:{source_field}",
        ))

    # 1) Custom recipes — CRITICAL when a full recipe fires.
    for src_key in ("custom_recipes_matched", "recipes_matched"):
        for r in (metadata.get(src_key) or [])[:20]:
            if isinstance(r, dict):
                name = r.get("name") or r.get("id") or r.get("recipe") or "custom recipe"
                conf = float(r.get("confidence", 0.9))
            else:
                name = str(r)
                conf = 0.9
            _add("custom_recipe_hit", f"Recipe · {name}", conf, src_key)

    # 2) Detection rules — HIGH when a Sigma/YARA/rule engine fires.
    for r in (metadata.get("rules_hit") or [])[:20]:
        if isinstance(r, dict):
            name = r.get("rule") or r.get("name") or r.get("id") or "rule"
            severity = (r.get("severity") or "").lower()
            conf = float(r.get("confidence", 0.85))
            kind = "rule_hit" if severity not in ("low", "info") else "yara_hit"
        else:
            name = str(r); conf = 0.85; kind = "rule_hit"
        _add(kind, f"Rule · {name}", conf, "rules_hit")

    for r in (metadata.get("sigma") or [])[:20]:
        if isinstance(r, dict):
            name = r.get("rule") or r.get("name") or r.get("id") or "sigma"
            conf = float(r.get("confidence", 0.85))
        else:
            name = str(r); conf = 0.85
        _add("sigma_hit", f"Sigma · {name}", conf, "sigma")

    for r in (metadata.get("yara") or [])[:20]:
        if isinstance(r, dict):
            name = r.get("rule") or r.get("name") or r.get("id") or "yara"
            conf = float(r.get("confidence", 0.75))
        else:
            name = str(r); conf = 0.75
        _add("yara_hit", f"YARA · {name}", conf, "yara")

    # 3) LOLBAS v2 — HIGH-class per binary, with abuse-specific mapping.
    lolbas_seen: set[str] = set()

    def _iter_lolbas(value: Any):
        """Normalise both shapes: list of {binary} OR
        dict {executed:[…], referenced:[…], expanded:[…]}."""
        if isinstance(value, dict):
            for bucket in ("executed", "referenced", "expanded"):
                for it in (value.get(bucket) or []):
                    yield it
        elif isinstance(value, list):
            for it in value:
                yield it

    for src_key in ("lolbins_v2", "lolbas"):
        count = 0
        for item in _iter_lolbas(metadata.get(src_key)):
            if count >= 20:
                break
            count += 1
            if isinstance(item, dict):
                name = (item.get("binary") or item.get("name") or "").lower()
                conf = float(item.get("confidence", 0.8))
            else:
                name = str(item).lower(); conf = 0.8
            if not name or name in lolbas_seen:
                continue
            lolbas_seen.add(name)
            kind = {
                "bitsadmin":  "bits_abuse",
                "rundll32":   "rundll32_abuse",
                "regsvr32":   "regsvr32_abuse",
                "mshta":      "mshta_abuse",
                "wmic":       "wmi_abuse",
            }.get(name, "lolbin")
            _add(kind, f"LOLBAS · {name}", conf, src_key)

    # 4) TI shield / TI hits — CONTEXT (already covered by IOC nodes
    #    if the value made it into the graph; here it acts as a tie-
    #    breaker for CONTEXT-class contributions).
    ti_shield = metadata.get("ti_shield")
    if isinstance(ti_shield, dict):
        for layer in (ti_shield.get("layers") or [])[:10]:
            if not isinstance(layer, dict):
                continue
            name = layer.get("name") or layer.get("provider") or "TI"
            conf = float(layer.get("confidence", 0.5))
            # If any TI provider labels this as malicious, upgrade it into
            # the CRITICAL escalation path via `confirmed_malicious_*`.
            verdict_hint = str(layer.get("verdict") or "").lower()
            if verdict_hint in ("malicious", "high") and (layer.get("ti_hits") or []):
                _add("known_c2", f"TI · {name}", conf, "ti_shield")
            else:
                _add("ti_layer", f"TI · {name}", conf, "ti_shield")

    return out


# ─── Confidence formula (Noisy-OR · monotonic by construction) ────

def _noisy_or_confidence(contributors: List[VerdictContribution]) -> float:
    """Combine contributors into a single confidence in [0..1].

    Formula: 1 - ∏(1 - (w_norm * conf))

    Where w_norm = weight / 5 (5 is the CRITICAL class weight = max).

    Properties:
      * Bounded in [0, 1) — never reaches 1 unless a single contributor
        has weight=5 AND conf=1.0.
      * Monotonic: adding any positive contributor RAISES confidence.
      * Order-independent: multiplication is commutative.
      * Zero-safe: no contributors → 0.
    """
    if not contributors:
        return 0.0
    p_none = 1.0
    for c in contributors:
        w_norm = min(1.0, c.weight / 5.0)
        signal = max(0.0, min(1.0, w_norm * c.confidence))
        p_none *= (1.0 - signal)
    return max(0.0, min(1.0, 1.0 - p_none))


# ─── Label ceiling from evidence-class distribution ────────────────

def _label_from_class_distribution(
    contributors: List[VerdictContribution],
    has_decoded: bool,
) -> str:
    """Baseline label BEFORE escalation rules apply. Uses the highest
    evidence class present + count of contributors at/above HIGH.

    * ≥ 1 CRITICAL → Malicious
    * ≥ 2 HIGH     → Malicious
    * exactly 1 HIGH → Suspicious
    * ≥ 1 MEDIUM   → Runtime Dependent (if decoded) else Suspicious
    * only LOW/CONTEXT → Informational
    * empty        → Undetermined
    """
    if not contributors:
        return "Undetermined"
    counts = {c.value: 0 for c in EvidenceClass}
    for c in contributors:
        ec = c.evidence_class or ""
        if ec in counts:
            counts[ec] += 1

    if counts["critical"] >= 1:
        return "Malicious"
    if counts["high"] >= 2:
        return "Malicious"
    if counts["high"] == 1:
        return "Suspicious"
    if counts["medium"] >= 1:
        return "Runtime Dependent" if has_decoded else "Suspicious"
    if counts["low"] >= 1 or counts["context"] >= 1:
        return "Informational"
    return "Undetermined"


# ─── Verdict computation ──────────────────────────────────────────

def compute_verdict(
    graph: EvidenceGraph,
    metadata: Optional[Dict[str, Any]] = None,
) -> VerdictNode:
    """Compute the single verdict from the Evidence Graph + optional
    CIO metadata.

    Backward-compat: `metadata` is optional. Callers that don't pass it
    get the graph-only verdict — identical determinism guarantees.

    Rules (§1.1.3 / §1.1.16 / §1.1.17):
      * Vendor / CA infra IOCs have weight 0 — recorded in `not_counted`.
      * Baseline verdict from evidence-class distribution.
      * Deterministic escalation rules can PROMOTE the verdict (never
        demote).
      * Confidence is Noisy-OR over contributors — monotonic.
    """
    contributors: List[VerdictContribution] = []
    not_counted: List[VerdictContribution] = []
    has_decoded_fragment = False

    # ── 1. Graph contributors ─────────────────────────────────────
    for node in graph.nodes:
        if node.kind in ("artifact", "verdict"):
            continue
        if node.kind == "decoded_fragment":
            has_decoded_fragment = True

        kind = _kind_for_graph_node(node)
        category = _category_for(node)
        cls = class_of(kind)
        base_w = weight_of(kind)

        # Category can down-weight IOCs (vendor / CA infra → 0).
        if category in ("vendor_infrastructure", "certificate_infrastructure"):
            eff_w = 0.0
            cls = None
        elif category == "internal_asset":
            eff_w = min(base_w, CLASS_WEIGHT[EvidenceClass.CONTEXT])
            cls = EvidenceClass.CONTEXT
        else:
            eff_w = base_w

        contrib = VerdictContribution(
            node_id=node.id,
            kind=kind,
            weight=eff_w,
            confidence=node.confidence,
            category=category,
            label=node.label,
            evidence_class=(cls.value if cls else None),
            source="graph",
        )
        if eff_w == 0:
            not_counted.append(contrib)
        else:
            contributors.append(contrib)

    # ── 2. Metadata contributors (Rules · LOLBAS · Recipes · TI) ──
    contributors.extend(_synthesize_metadata_contributors(metadata))

    # ── 3. Empty-evidence short-circuit ───────────────────────────
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

    # ── 4. Sort deterministically for a stable explanation ────────
    _CLASS_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "context": 0}
    contributors.sort(
        key=lambda c: (
            -_CLASS_RANK.get(c.evidence_class or "", -1),
            -c.weight,
            -c.confidence,
            c.node_id,
        )
    )

    # ── 5. Baseline label from class distribution ────────────────
    base_label = _label_from_class_distribution(contributors, has_decoded_fragment)

    # ── 6. Deterministic escalation rules (may promote) ──────────
    active_kinds = {c.kind for c in contributors}
    esc_label, esc_rule = apply_escalation(active_kinds)

    _LABEL_RANK = {"Undetermined": 0, "Informational": 1, "Runtime Dependent": 2,
                   "Suspicious": 3, "Malicious": 4}
    if esc_label and _LABEL_RANK[esc_label] >= _LABEL_RANK[base_label]:
        # Rule fires whenever it agrees with OR promotes the baseline.
        # Recording it here gives analysts the human-readable pattern
        # name instead of just "2 high + 1 medium" statistics.
        label = esc_label
        for c in contributors:
            if c.kind in active_kinds:
                c.escalated_by = esc_rule
    else:
        label = base_label
        esc_rule = None

    # ── 7. Monotonic confidence (Noisy-OR) ───────────────────────
    conf = _noisy_or_confidence(contributors)

    # ── 8. Reason (top 3 contributors + escalation rule) ─────────
    tops = contributors[:3]
    top_lines = " · ".join(
        f"{c.label} [{c.evidence_class}, w={c.weight}]" for c in tops
    )
    if esc_rule:
        reason = (
            f"Verdict promoted by escalation rule: '{esc_rule}'. "
            f"Top contributors: {top_lines}. "
            f"Total contributing nodes: {len(contributors)}."
        )
    else:
        reason = (
            f"Verdict derived from class distribution: "
            f"{sum(1 for c in contributors if c.evidence_class == 'critical')} critical · "
            f"{sum(1 for c in contributors if c.evidence_class == 'high')} high · "
            f"{sum(1 for c in contributors if c.evidence_class == 'medium')} medium · "
            f"{sum(1 for c in contributors if c.evidence_class == 'low')} low · "
            f"{sum(1 for c in contributors if c.evidence_class == 'context')} context. "
            f"Top contributors: {top_lines}."
        )

    return VerdictNode(
        label=label,
        confidence=round(conf, 4),
        confidence_pct=int(round(conf * 100)),
        reason=reason,
        contributors=contributors,
        not_counted=not_counted,
        escalation_rule=esc_rule,
    )


__all__ = ["compute_verdict", "refresh_verdict", "VerdictNode", "VerdictContribution"]


def refresh_verdict(cio) -> Any:
    """Re-compute `cio.verdict` from the current graph + `cio.metadata`.

    Use this from wire-in sites AFTER stashing Workspace-parity metadata
    onto the CIO. Keeps the verdict in sync with the metadata without
    the caller having to touch the engine directly.
    """
    graph = getattr(cio, "evidence_graph", None)
    if not graph:
        return cio
    metadata = getattr(cio, "metadata", None) or {}
    v = compute_verdict(graph, metadata=metadata)
    cio.verdict = v.model_dump(mode="json")
    # Also refresh the aggregate confidence field (§1.1.3).
    try:
        cio.confidence = round(v.confidence, 4)
    except Exception:  # noqa: BLE001
        pass
    return cio
