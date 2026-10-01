"""
P0.2d · Rule ↔ Capability Matching
──────────────────────────────────

Deterministic matcher between a strictly-parsed Sigma rule and the
declared Implementation Capability Contracts (P0.2c).

Given:
    • a SigmaRule (from sigma_strict.strict_parse)
    • the current contract registry (from xdr_capability_contracts)

Produces:
    {
      "rule_id": "...",
      "requirements": { evidence_types: [...], operators: [...] },
      "matches": [
        { engine_id, classification, compatibility, reasons: [] },
        ...
      ],
      "status": "COMPATIBLE" | "ENGINE_UNBOUND" | "CANDIDATE_ONLY"
    }

Compatibility model
───────────────────
A rule–engine pair can end in one of four verdicts, decided by
deterministic checks in this order:

    COMPATIBLE          contract.execution.detection is True AND
                        rule's required evidence types ⊆ contract.consumes
                        semantic domain.

    CANDIDATE_ONLY      contract.consumes matches BUT
                        contract.execution.detection is False —
                        the engine could execute this rule if
                        promoted through P0.2e, but has not been
                        proven to do so today.

    INCOMPATIBLE_INPUT  detection=True but consumes[] doesn't cover
                        the required evidence types.

    NOT_DETECTION       everything else (default).

A rule's overall status:
    • has ≥1 COMPATIBLE match  → status = COMPATIBLE.
    • has 0 COMPATIBLE but ≥1 CANDIDATE_ONLY → status = CANDIDATE_ONLY.
    • otherwise                → status = ENGINE_UNBOUND.

`ENGINE_UNBOUND` is a first-class product state, not an error.
It is the honest, expected outcome today because
`detection_capable = 0` in the registry.
"""
from __future__ import annotations
from typing import Any, Iterable

# Local imports kept type-string to keep the module import-safe
# even when pysigma isn't installed.
try:
    from sigma.rule import SigmaRule    # type: ignore
    _PYSIGMA_AVAILABLE = True
except Exception:
    SigmaRule = None                    # type: ignore
    _PYSIGMA_AVAILABLE = False


# ── Evidence-type extraction from a SigmaRule ────────────────────
#
# We map (product, category) → canonical evidence type family.
# The matcher only checks whether a contract *consumes* something
# from this family — it does not attempt field-level mapping (that
# is a P1 refinement).
#
_PRODUCT_CATEGORY_TO_EVIDENCE: dict[tuple[str, str], list[str]] = {
    ("windows", "process_creation"):
        ["process.artifact", "canonical.evidence", "process_event"],
    ("windows", "ps_module"):
        ["script", "canonical.evidence"],
    ("windows", "ps_script"):
        ["script", "canonical.evidence"],
    ("windows", "powershell"):
        ["script", "canonical.evidence", "command_line"],
    ("windows", "amsi"):
        ["script", "canonical.evidence"],
    ("windows", "file_event"):
        ["file.artifact", "canonical.evidence"],
    ("windows", "network_connection"):
        ["network.artifact", "canonical.evidence"],
    ("windows", "security"):
        ["security.event", "canonical.evidence", "auth.event"],
    ("windows", "registry"):
        ["file.artifact", "canonical.evidence"],
    ("windows", "service"):
        ["process.artifact", "canonical.evidence"],
    ("windows", "scheduled_task"):
        ["process.artifact", "canonical.evidence"],
    ("active_directory", "kerberos"):
        ["identity.artifact", "canonical.evidence", "auth.event"],
    ("active_directory", "ad_cs"):
        ["identity.artifact", "canonical.evidence"],
    ("active_directory", "directory_service"):
        ["identity.artifact", "canonical.evidence"],
    ("cloud", "iam"):
        ["cloud.artifact", "identity.artifact", "canonical.evidence"],
    ("cloud", "audit"):
        ["cloud.artifact", "canonical.evidence"],
    ("cloud", "storage"):
        ["cloud.artifact", "canonical.evidence"],
    ("linux", "process_creation"):
        ["process.artifact", "canonical.evidence", "process_event"],
    ("linux", "auditd"):
        ["process.artifact", "canonical.evidence", "security.event"],
    ("linux", "network_connection"):
        ["network.artifact", "canonical.evidence"],
    ("macos", "process_creation"):
        ["process.artifact", "canonical.evidence", "process_event"],
    ("container", "k8s_audit"):
        ["cloud.artifact", "canonical.evidence"],
    ("container", "runtime"):
        ["process.artifact", "canonical.evidence"],
    ("vmware", "esxi"):
        ["process.artifact", "canonical.evidence", "security.event"],
    ("email", "m365"):
        ["cloud.artifact", "canonical.evidence"],
}
_DEFAULT_EVIDENCE_TYPES = ["canonical.evidence"]


def _rule_surface(rule_like: Any) -> tuple[str, str, list[str], str]:
    """
    Return (product, category, required_fields, rule_id) from either
    a SigmaRule (pysigma) or a dict surface fallback.
    """
    if (_PYSIGMA_AVAILABLE and isinstance(rule_like, SigmaRule)) or hasattr(rule_like, "logsource"):
        ls = getattr(rule_like, "logsource", None)
        product  = (getattr(ls, "product",  None) or "").lower() if ls else ""
        category = (getattr(ls, "category", None) or "").lower() if ls else ""
        rule_id  = str(getattr(rule_like, "id", "") or "")
        # Field extraction — walk detection selections.
        req: set[str] = set()
        det = getattr(rule_like, "detection", None)
        try:
            for name, sel in getattr(det, "detections", {}).items():
                for atom in getattr(sel, "detection_items", []):
                    fld = getattr(atom, "field", None)
                    if fld: req.add(str(fld))
        except Exception:
            pass
        return product, category, sorted(req), rule_id

    # dict surface fallback (from strict_parse .surface)
    if isinstance(rule_like, dict):
        s = rule_like
        return (
            str(s.get("product") or "").lower(),
            str(s.get("category") or "").lower(),
            [],  # unknown — dict surface doesn't hold detection
            str(s.get("id") or ""),
        )
    return "", "", [], ""


def rule_required_evidence(rule_like: Any) -> list[str]:
    p, c, _, _ = _rule_surface(rule_like)
    return _PRODUCT_CATEGORY_TO_EVIDENCE.get((p, c), _DEFAULT_EVIDENCE_TYPES)


# ── Per-pair compatibility ───────────────────────────────────────

def _pair_compat(contract: dict,
                       required_evidence: list[str]) -> tuple[str, list[str]]:
    """
    Return (verdict, reasons) — deterministic, side-effect-free.
    """
    reasons: list[str] = []
    exec_ = contract.get("execution") or {}
    consumes = set(contract.get("consumes") or [])
    detection = bool(exec_.get("detection"))

    input_match = any(ev in consumes for ev in required_evidence)

    if detection and input_match:
        return "COMPATIBLE", ["contract.execution.detection=True",
                                        "evidence type in consumes"]
    if detection and not input_match:
        reasons.append("contract.execution.detection=True but "
                             f"consumes {sorted(consumes)} does not include any "
                             f"of the rule's required evidence "
                             f"types {required_evidence}")
        return "INCOMPATIBLE_INPUT", reasons
    if not detection and input_match:
        reasons.append("contract.consumes matches the rule's evidence "
                             "types, BUT execution.detection is False. Promotion "
                             "requires P0.2e Detection Execution Harness.")
        return "CANDIDATE_ONLY", reasons
    return "NOT_DETECTION", ["contract.execution.detection=False"]


# ── Top-level matcher ─────────────────────────────────────────────

def match_rule_to_contracts(rule_like: Any,
                                     contracts: Iterable[dict]) -> dict:
    """
    Compute the deterministic match report for one rule against a
    list of declared contracts.  `contracts` is any iterable of
    contract dicts (as stored in xdr_capability_contracts).
    """
    product, category, req_fields, rule_id = _rule_surface(rule_like)
    required_evidence = rule_required_evidence(rule_like)

    matches: list[dict] = []
    n_compat = n_cand = 0
    for c in contracts:
        verdict, reasons = _pair_compat(c, required_evidence)
        if verdict == "NOT_DETECTION":
            continue  # keep the report tight — only surface real signal
        if verdict == "COMPATIBLE":
            n_compat += 1
        elif verdict == "CANDIDATE_ONLY":
            n_cand += 1
        matches.append({
            "engine_id":       c.get("engine_id"),
            "classification":  c.get("classification"),
            "compatibility":   verdict,
            "reasons":         reasons,
        })

    if n_compat:
        status = "COMPATIBLE"
    elif n_cand:
        status = "CANDIDATE_ONLY"
    else:
        status = "ENGINE_UNBOUND"

    return {
        "rule_id":            rule_id,
        "logsource":          {"product": product, "category": category},
        "required_evidence":  required_evidence,
        "required_fields":    req_fields,
        "matches":            matches,
        "status":             status,
        "counts": {
            "compatible":       n_compat,
            "candidate_only":   n_cand,
            "considered":       len(matches),
        },
    }
