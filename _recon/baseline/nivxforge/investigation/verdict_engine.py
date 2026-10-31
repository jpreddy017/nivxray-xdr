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
    # Sprint 3 · per-class confidence breakdown for the Verdict Panel.
    confidence_breakdown: Dict[str, int] = Field(
        default_factory=dict,
        description="Per-EvidenceClass confidence percentage · {critical, high, medium, low, context, mitigating}."
    )
    # Sprint 3 · confidence timeline · ordered snapshots of how the
    # verdict evolved as contributors were folded in.
    confidence_timeline: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Ordered stages · [{stage, contributor_label, contributor_kind, class, confidence_pct}]"
    )
    # P0.4 · Verdict Calibration Audit — the "why is confidence X%?"
    # explanation. Enumerates fired contributors by class, escalation
    # rules applied vs skipped, cap that was hit (if any), and the
    # mitigation dampening applied (if any). Every UI surface that
    # shows the verdict MUST also expose this so analysts can trace
    # the confidence number back to concrete evidence, not a black box.
    explain: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Auditable breakdown of the confidence calculation: "
            "{fired[], missing[], escalations_applied[], escalations_skipped[], "
            " confidence_cap, dampening, formula_terms{}}."
        ),
    )



# ─── BUG-P4-01 · Behaviour-class-aware WMI classification ─────────
# Discovery ≠ Execution. `wmic ... get commandline` is enumeration and
# must NOT trigger attack-chain HIGH escalation. Severity is derived
# from OBSERVED behaviour, not from the executable name alone.
_WMI_EXECUTION_PATTERNS = (
    "call create", "process call", "invoke.*create",
    "invoke-wmimethod", "invoke-cimmethod",
    "wmic /node", "wmic node",
)
_WMI_DISCOVERY_PATTERNS = (
    " get ", " list ", " list full", " list brief",
    " where ", " select ",
    "get-wmiobject", "get-ciminstance",
)


def _wmi_kind_from_context(node: "Node", label_lc: str) -> str:
    """Return `wmi_abuse` (HIGH, attack-chain) or `wmi_discovery`
    (LOW, non-escalating) based on the observed command context.

    Reads the node's `context_text` attr (the enclosing command line
    substring populated by builder.py), falling back to the node label.
    When nothing signals execution AND nothing signals discovery, we
    stay with the historical `wmi_abuse` classification so we don't
    silently mask true WMI abuse cases where the context field simply
    isn't populated. The compute_verdict post-pass performs a
    second-order sweep against the full input_text when available.
    """
    ctx = str((node.attrs or {}).get("context_text") or "")
    ctx = (ctx + " " + label_lc).lower()
    exec_hit = any(p in ctx for p in _WMI_EXECUTION_PATTERNS)
    disc_hit = any(p in ctx for p in _WMI_DISCOVERY_PATTERNS)
    if exec_hit:
        return "wmi_abuse"
    if disc_hit:
        return "wmi_discovery"
    return "wmi_abuse"


def _input_text_is_wmi_discovery(text: str) -> bool:
    """Whole-input behaviour-class check. Returns True when the input
    is unambiguously WMI enumeration with no execution signal."""
    if not text:
        return False
    t = text.lower()
    has_wmi = "wmic" in t or "wmi" in t or "get-wmiobject" in t or "get-ciminstance" in t
    if not has_wmi:
        return False
    exec_hit = any(p in t for p in _WMI_EXECUTION_PATTERNS)
    disc_hit = any(p in t for p in _WMI_DISCOVERY_PATTERNS)
    return disc_hit and not exec_hit




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
        # Some MITRE techniques ARE abuse patterns — elevate them to
        # their attack-chain kind so the escalation rules fire.
        lbl = (node.label or "").lower() + " " + (node.value or "").lower()
        if "bits job" in lbl or "t1197" in lbl:
            return "bits_abuse"
        if "invoke-expression" in lbl or "invoke expression" in lbl:
            return "invoke_expression"
        if "rundll32" in lbl:
            return "rundll32_abuse"
        if "regsvr32" in lbl:
            return "regsvr32_abuse"
        if "mshta" in lbl:
            return "mshta_abuse"
        if "windows management instrumentation" in lbl or "wmi" in lbl or "t1047" in lbl:
            # BUG-P4-01 architectural fix · WMI is only HIGH when it
            # EXECUTES something (call create / process create / method
            # invoke). Pure query patterns (`wmic ... get`, `wmic ...
            # list`, Get-WmiObject, Get-CimInstance) are DISCOVERY and
            # must not trigger attack-chain escalation.
            return _wmi_kind_from_context(node, lbl)
        if "signed binary proxy" in lbl or "t1218" in lbl:
            return "signed_binary_proxy"
        if "ingress tool transfer" in lbl or "t1105" in lbl:
            return "network_staging"
        if any(k in lbl for k in ("persistence", "registry run", "startup", "t1547", "t1053")):
            return "persistence"
        if any(k in lbl for k in ("credential", "lsass", "t1003", "t1555")):
            return "credential_access"
        if any(k in lbl for k in ("lateral", "t1021")):
            return "lateral_movement"
        return "mitre_technique"

    if node.kind == "lolbin":
        # Bucket well-known lolbins into their explicit abuse tokens so
        # escalation rules can pick them up individually.
        v = (node.value or "").lower()
        # BUG-P4-01 · behaviour-class gate for wmic — same principle as
        # the MITRE branch. `wmic ... get commandline` is discovery.
        if v == "wmic":
            return _wmi_kind_from_context(node, (node.label or "").lower())
        return {
            "bitsadmin":   "bits_abuse",
            "rundll32":    "rundll32_abuse",
            "regsvr32":    "regsvr32_abuse",
            "mshta":       "mshta_abuse",
            "certutil":    "lolbin",
            "powershell":  "lolbin",
        }.get(v, "lolbin")

    if node.kind == "family_match":
        return "sha_matched_family"

    if node.kind == "behaviour":
        # Synthetic behaviour nodes name their kind explicitly.
        val = (node.value or "").strip().lower()
        if val in ("execution_chain_correlated", "temporal_burst",
                   "entity_chain_correlated", "shellcode_detected"):
            return val
        if val == "mitigating_signal":
            sub = ((node.attrs or {}).get("subkind") or "").strip().lower()
            if sub in ("signed_microsoft_binary", "internal_ip",
                       "enterprise_allowlist", "benign_parent"):
                return sub
            return "mitigating_signal"
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
        label_lc = (node.label or "").lower()
        preview = ((node.value or "") + " " + label_lc).lower()
        # Alias normalisation isn't attack behaviour — it's just the
        # decoder resolving cmd/ps aliases. Drop to LOW.
        if "alias" in op or "alias-normalize" in label_lc:
            return "base64_layer"  # LOW-class · "a decoding step happened"
        # P0.approved · Fix classification bug — PS -EncodedCommand
        # is the STRUCTURAL evidence of `encoded_powershell`. It must
        # not be shadowed by the semantic `invoke_expression` mapping
        # below (which used to short-circuit when IEX appeared in the
        # recovered preview, causing the "encoded PS + IEX + network
        # download" escalation rule to miss).
        if (
            "ps-encodedcommand" in op
            or "encoded_command" in op
            or "encodedcommand" in op
            or ("powershell" in op and "encoded" in op)
        ):
            return "encoded_powershell"
        # Structural: which decoder ran
        if "base64" in op or "b64" in op:
            base = "base64_layer"
        elif "hex" in op:
            base = "hex_layer"
        elif "gzip" in op or "deflate" in op or "lzma" in op or "zstd" in op:
            base = "compression_layer"
        elif "archive" in op or "zip" in op or "tar" in op:
            base = "archive_extract"
        elif "encoded" in op or ("powershell" in op and "encoded" in preview):
            # Only true PS -EncodedCommand recovery is HIGH.
            base = "encoded_powershell"
        else:
            base = "base64_layer"   # generic layer → LOW
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

    Positive contributors use Noisy-OR with per-class normalisers.
    MITIGATING contributors apply a multiplicative dampener (up to
    0.5× per signal) — they cannot flip a verdict, only reduce
    confidence.

    Properties:
      * Bounded in [0, 1)
      * Positive additions RAISE confidence
      * Mitigating additions REDUCE confidence but only after positives
        have been combined; strong CRITICAL evidence resists dampening.
    """
    if not contributors:
        return 0.0
    p_none = 1.0
    mitigators: List[float] = []
    has_critical = any(c.evidence_class == "critical" for c in contributors)
    for c in contributors:
        ec = c.evidence_class or ""
        if ec == "mitigating":
            mitigators.append(max(0.0, min(1.0, c.confidence)))
            continue
        if ec == "low":
            denom = 10.0
        elif ec == "context":
            denom = 20.0
        else:
            denom = 5.0
        w_norm = min(1.0, c.weight / denom)
        signal = max(0.0, min(1.0, w_norm * c.confidence))
        p_none *= (1.0 - signal)
    base = 1.0 - p_none
    # Single aggregate dampener — capped so mitigating evidence cannot
    # overturn a Malicious verdict. Max mitigation:
    #   * With CRITICAL: total dampening capped at 0.3 (min factor 0.7)
    #   * Without CRITICAL: capped at 0.5 (min factor 0.5)
    if mitigators:
        avg = sum(mitigators) / len(mitigators)
        # Multiple mitigators strengthen the effect but only up to +50%.
        strength = avg * min(1.5, 1.0 + 0.25 * (len(mitigators) - 1))
        max_reduction = 0.30 if has_critical else 0.50
        factor = 1.0 - min(max_reduction, strength * max_reduction)
        base *= factor
    return max(0.0, min(1.0, base))


# ─── Label ceiling from evidence-class distribution ────────────────

def _label_from_class_distribution(
    contributors: List[VerdictContribution],
    has_decoded: bool,
) -> str:
    """Baseline label BEFORE escalation rules apply. Uses the highest
    evidence class present + count of contributors at/above HIGH.

    Analyst-intuition rules:
      * Wrapper-only benign (Rule 13) → Informational
      * ≥ 1 CRITICAL → Malicious
      * ≥ 2 HIGH AND ≥ 1 of those is an attack-chain kind → Malicious
      * ≥ 2 HIGH (all ambient) → Suspicious (LOLBIN/tooling noise)
      * exactly 1 HIGH → Suspicious
      * ≥ 1 MEDIUM → Runtime Dependent (if decoded) else Suspicious
      * only LOW/CONTEXT → Informational
      * empty        → Undetermined
    """
    from nivxforge.investigation.evidence_classes import ATTACK_CHAIN_HIGH
    if not contributors:
        return "Undetermined"
    # ARB PR-2.1 · Governance Rule 13 · Evidence-Verdict Separation.
    # Obfuscation / wrapper markers alone do not drive a verdict.
    # If every ≥ MEDIUM contributor is a wrapper kind and the payload
    # exposed no attack capabilities, this is Informational.
    if _is_wrapper_only_benign(contributors):
        return "Informational"
    counts = {c.value: 0 for c in EvidenceClass}
    high_kinds: set[str] = set()
    for c in contributors:
        ec = c.evidence_class or ""
        if ec in counts:
            counts[ec] += 1
        if ec == "high":
            high_kinds.add(c.kind)

    if counts["critical"] >= 1:
        return "Malicious"
    if counts["high"] >= 2:
        if high_kinds & ATTACK_CHAIN_HIGH:
            return "Malicious"
        return "Suspicious"      # LOLBIN + tooling only — not an attack chain
    if counts["high"] == 1:
        return "Suspicious"
    if counts["medium"] >= 1:
        return "Runtime Dependent" if has_decoded else "Suspicious"
    if counts["low"] >= 1 or counts["context"] >= 1:
        return "Informational"
    return "Undetermined"


def _is_wrapper_only_benign(contributors: List[VerdictContribution]) -> bool:
    """Return True when the sole ≥ MEDIUM signal is a wrapper-obfuscation
    marker and NO attack-capability signal is present.

    Capability-driven, not command-whitelisted (ARB Governance Rule 12).
    We look at what the *decoded artifact* did — not at whether the
    payload happens to be ``Write-Host`` or ``Get-Date`` — via the
    ``ATTACK_CHAIN_HIGH`` set which enumerates attacker-behaviour kinds
    (execution abuse · network · persistence · credential access ·
    lateral movement · shellcode, etc.). Any of those disqualifies the
    downgrade.

    Wrapper markers we treat as "encoded shell" evidence:
        encoded_powershell · encoded_command · base64_wrapper · obfuscation

    Benign context signals we tolerate (they are LOW/CONTEXT class
    already, but we explicitly allow them for readability):
        · powershell_binary_present (mere presence of powershell.exe)
        · mitre_defense_evasion_obfuscation (T1027.010)

    Anything else at MEDIUM+ blocks the downgrade so we never mask a
    real attack.
    """
    from nivxforge.investigation.evidence_classes import ATTACK_CHAIN_HIGH

    WRAPPER_KINDS = {
        "encoded_powershell",
        "encoded_command",
        "base64_wrapper",
        "obfuscation",
    }

    medium_or_higher = [
        c for c in contributors
        if c.evidence_class in ("critical", "high", "medium")
    ]
    if not medium_or_higher:
        # Zero-signal case is already handled by the existing cap of 0.30.
        return False

    # Any CRITICAL or attack-chain HIGH kind → not wrapper-only.
    # Also: any HIGH-class kind that is NOT itself a wrapper marker
    # must block the downgrade (e.g. lolbas_usage, powershell_binary_usage
    # are HIGH but not wrapper — they carry independent context).
    for c in medium_or_higher:
        if c.evidence_class == "critical":
            return False
        if c.evidence_class == "high":
            if c.kind in ATTACK_CHAIN_HIGH:
                return False
            if c.kind not in WRAPPER_KINDS:
                return False
        if c.evidence_class == "medium":
            # MEDIUM signals may or may not be attack-capability. Be
            # conservative — if a MEDIUM is not clearly wrapper/context,
            # block the downgrade. This preserves correct verdicts on
            # partial-decode / MITRE-only cases.
            if c.kind not in WRAPPER_KINDS:
                return False

    # Reach here → every ≥ MEDIUM contributor is a wrapper kind. Confirm
    # that at least one wrapper kind is present (otherwise the set is
    # empty which is not what this rule targets).
    return any(c.kind in WRAPPER_KINDS for c in medium_or_higher)


def _confidence_cap(contributors: List[VerdictContribution]) -> float:
    """Cap the raw Noisy-OR confidence when the evidence set is weak.

    * No signals ≥ MEDIUM               → cap 0.30 (benign-shape input)
    * Wrapper-only benign (Rule 12)     → cap 0.30 (decoded payload
                                           produced no attack capability)
    * No CRITICAL AND no attack-chain
      HIGH kind present                 → cap 0.75 (suspicious ambient)
    * Otherwise                         → no cap
    """
    from nivxforge.investigation.evidence_classes import ATTACK_CHAIN_HIGH
    has_medium_plus = any(
        c.evidence_class in ("critical", "high", "medium") for c in contributors
    )
    has_critical = any(c.evidence_class == "critical" for c in contributors)
    has_attack_high = any(
        c.evidence_class == "high" and c.kind in ATTACK_CHAIN_HIGH
        for c in contributors
    )
    if not has_medium_plus:
        return 0.30
    # ARB PR-2.1 · Governance Rule 12 · Canonical Artifact Consistency.
    # If the only ≥ MEDIUM signal is a wrapper marker AND no attack
    # capability is present in the decoded artifact, cap at 0.30 so the
    # label distribution + cap combined demote to Informational.
    if _is_wrapper_only_benign(contributors):
        return 0.30
    if not has_critical and not has_attack_high:
        return 0.75
    return 1.0


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

    # ── 0. Sprint 1+2 · attach synthetic signals ─────────────────
    # Pure functions of the current graph; idempotent; deterministic.
    try:
        from nivxforge.investigation.topology_signals import (
            attach_topology_and_temporal_signals,
        )
        attach_topology_and_temporal_signals(graph)
    except Exception:  # noqa: BLE001
        pass
    try:
        from nivxforge.investigation.correlation_signals import (
            attach_entity_and_negative_signals,
        )
        attach_entity_and_negative_signals(graph)
    except Exception:  # noqa: BLE001
        pass

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

    # ── 2.5 · BUG-P4-01 · Behaviour-class-aware post-pass ─────────
    # When the WHOLE INPUT is unambiguously discovery-only WMI, downgrade
    # every wmi_abuse / lolbin(powershell) HIGH contributor to
    # wmi_discovery / discovery LOW class. Severity comes from
    # observed behaviour, never from executable name alone.
    input_text = str((metadata or {}).get("input_text_normalised") or "")
    if _input_text_is_wmi_discovery(input_text):
        _downgraded: List[VerdictContribution] = []
        for c in contributors:
            if c.kind == "wmi_abuse":
                _downgraded.append(c.model_copy(update={
                    "kind": "wmi_discovery",
                    "weight": weight_of("wmi_discovery"),
                    "evidence_class": EvidenceClass.LOW.value,
                }))
            elif c.kind == "lolbin" and str(c.label or "").lower().endswith("powershell"):
                # Bare `powershell.exe` invocation in a discovery-only
                # context isn't attack activity by itself.
                _downgraded.append(c.model_copy(update={
                    "evidence_class": EvidenceClass.LOW.value,
                    "weight": min(c.weight, weight_of("wmi_discovery")),
                }))
            else:
                _downgraded.append(c)
        contributors = _downgraded

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

    # ── 7. Monotonic confidence (Noisy-OR) with class-based cap ──
    conf = _noisy_or_confidence(contributors)
    conf = min(conf, _confidence_cap(contributors))

    # ── 7b · Sprint 3 · confidence breakdown per evidence class ──
    _CLASS_ORDER = ["critical", "high", "medium", "low", "context", "mitigating"]
    breakdown: Dict[str, int] = {}
    for cls_name in _CLASS_ORDER:
        subset = [c for c in contributors if (c.evidence_class or "") == cls_name]
        if not subset:
            breakdown[cls_name] = 0
            continue
        # Per-class Noisy-OR contribution (0..100)
        sub_conf = _noisy_or_confidence(subset)
        breakdown[cls_name] = int(round(sub_conf * 100))

    # ── 7c · Sprint 3 · confidence timeline · how it evolved ─────
    timeline: List[Dict[str, Any]] = []
    running: List[VerdictContribution] = []
    # Only walk contributors that carry positive weight (mitigating are
    # tracked separately at the tail so the story stays legible).
    positives = [c for c in contributors if (c.evidence_class or "") != "mitigating"]
    mitigators = [c for c in contributors if (c.evidence_class or "") == "mitigating"]
    for i, c in enumerate(positives):
        running.append(c)
        stage_conf = _noisy_or_confidence(running)
        stage_conf = min(stage_conf, _confidence_cap(running))
        timeline.append({
            "stage": i + 1,
            "contributor_label": c.label,
            "contributor_kind": c.kind,
            "class": c.evidence_class,
            "confidence_pct": int(round(stage_conf * 100)),
            "source": c.source,
        })
    if mitigators:
        for i, c in enumerate(mitigators):
            running.append(c)
            stage_conf = _noisy_or_confidence(running)
            stage_conf = min(stage_conf, _confidence_cap(running))
            timeline.append({
                "stage": len(positives) + i + 1,
                "contributor_label": c.label,
                "contributor_kind": c.kind,
                "class": c.evidence_class,
                "confidence_pct": int(round(stage_conf * 100)),
                "source": c.source,
            })

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

    # ── P3.1 · Canonical Verdict Sanitization ─────────────────────
    # Every downstream surface (Verdict Card, Investigation Ledger,
    # Customer Report, top-card reason string, API consumers) reads
    # `contributor.label`, `reason`, and `confidence_timeline[].contributor_label`
    # directly. Sanitizing here means decoder-op names / "Layer N" /
    # "Recovered payload" / "Base64" never leak past the engine.
    # One source, one vocabulary, one truth.
    from .customer_report import _sanitize_customer_text as _san
    _sanitized_contributors = []
    for c in contributors:
        try:
            _sanitized_contributors.append(c.model_copy(update={"label": _san(str(c.label or ""))}))
        except Exception:  # noqa: BLE001
            try:
                c.label = _san(str(c.label or ""))
            except Exception:  # noqa: BLE001
                pass
            _sanitized_contributors.append(c)
    contributors = _sanitized_contributors
    reason = _san(reason)
    for tl_entry in timeline:
        try:
            tl_entry["contributor_label"] = _san(str(tl_entry.get("contributor_label") or ""))
        except Exception:  # noqa: BLE001
            pass

    # ── P0.4 · Auditable confidence explanation ───────────────────
    # Show the analyst EXACTLY which contributors fired, which
    # escalation rules were considered and why they were skipped,
    # and which caps / dampeners changed the raw score.
    from nivxforge.investigation.evidence_classes import (
        _ESCALATIONS_TO_MALICIOUS,
        _ESCALATIONS_TO_SUSPICIOUS,
        ATTACK_CHAIN_HIGH as _AC_HIGH,
    )
    _kset_final = {c.kind for c in contributors}
    _fired_summary = []
    for _cls_name in _CLASS_ORDER:
        _subset = [c for c in contributors if (c.evidence_class or "") == _cls_name]
        if _subset:
            _fired_summary.append({
                "class": _cls_name,
                "count": len(_subset),
                "contributors": [
                    {"node_id": c.node_id, "kind": c.kind, "label": c.label,
                     "weight": c.weight, "confidence": c.confidence,
                     "source": c.source}
                    for c in _subset
                ],
            })

    def _describe_escalation(reason_name: str, required: frozenset, promotion: str):
        missing = required - _kset_final
        return {
            "rule": reason_name,
            "promotes_to": promotion,
            "required_kinds": sorted(required),
            "missing_kinds": sorted(missing),
            "status": "applied" if not missing else "skipped",
        }

    _rules_audit = []
    for _r, _req in _ESCALATIONS_TO_MALICIOUS:
        _rules_audit.append(_describe_escalation(_r, _req, "Malicious"))
    for _r, _req in _ESCALATIONS_TO_SUSPICIOUS:
        _rules_audit.append(_describe_escalation(_r, _req, "Suspicious"))

    _cap_applied = _confidence_cap(contributors)
    _has_critical = any(c.evidence_class == "critical" for c in contributors)
    _has_attack_high = any(
        c.evidence_class == "high" and c.kind in _AC_HIGH for c in contributors
    )
    _mitigators_present = [c for c in contributors
                           if (c.evidence_class or "") == "mitigating"]

    _raw_noisy_or = _noisy_or_confidence(
        [c for c in contributors if (c.evidence_class or "") != "mitigating"]
    )

    explain_dict: Dict[str, Any] = {
        "fired": _fired_summary,
        "missing": [
            {"reason": "no CRITICAL-class evidence present"} if not _has_critical else None,
            {"reason": "no attack-chain HIGH kind present (see ATTACK_CHAIN_HIGH set)"}
            if not _has_attack_high else None,
        ],
        "escalations": _rules_audit,
        "escalation_applied": esc_rule,
        "confidence_calculation": {
            "formula": "Noisy-OR over positive contributors, capped, then dampened by mitigators.",
            "raw_noisy_or_pct": int(round(_raw_noisy_or * 100)),
            "confidence_cap_pct": int(round(_cap_applied * 100)),
            "cap_reason": (
                "no CRITICAL / no attack-chain HIGH → cap 0.75"
                if not _has_critical and not _has_attack_high
                else ("no MEDIUM+ signals → cap 0.30"
                      if not any(c.evidence_class in ("critical", "high", "medium")
                                 for c in contributors)
                      else "no cap (0..1.0)")
            ),
            "mitigators_present": len(_mitigators_present),
            "mitigator_dampening_max_pct": (30 if _has_critical else 50)
            if _mitigators_present else 0,
            "final_confidence_pct": int(round(conf * 100)),
        },
    }
    # Prune Nones
    explain_dict["missing"] = [m for m in explain_dict["missing"] if m is not None]

    return VerdictNode(
        label=label,
        confidence=round(conf, 4),
        confidence_pct=int(round(conf * 100)),
        reason=reason,
        contributors=contributors,
        not_counted=not_counted,
        escalation_rule=esc_rule,
        confidence_breakdown=breakdown,
        confidence_timeline=timeline,
        explain=explain_dict,
    )


__all__ = ["compute_verdict", "refresh_verdict", "VerdictNode", "VerdictContribution"]


def refresh_verdict(cio) -> Any:
    """Re-compute `cio.verdict` from the current graph + `cio.metadata`.

    Use this from wire-in sites AFTER stashing Workspace-parity metadata
    onto the CIO. Keeps the verdict AND the Investigation Truth Model in
    sync with the metadata without the caller having to touch the
    engine directly.
    """
    graph = getattr(cio, "evidence_graph", None)
    if not graph:
        return cio
    metadata = getattr(cio, "metadata", None) or {}
    v = compute_verdict(graph, metadata=metadata)
    cio.verdict = v.model_dump(mode="json")
    try:
        cio.confidence = round(v.confidence, 4)
    except Exception:  # noqa: BLE001
        pass
    # P1-02d · truth is a pure derivation of the CIO — re-derive on
    # every verdict refresh so all surfaces stay drift-free.
    try:
        from nivxforge.investigation.truth_model import build_truth
        cio.truth = build_truth(cio).model_dump(mode="json")
    except Exception:  # noqa: BLE001
        pass
    return cio
