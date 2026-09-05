"""Executive Summary service · Blueprint §9 (Summary lens) · PR-4.

Answers the Tier-1 analyst question: "What is this, how bad, and what
do I do in the next 60 seconds?"

PR-4 populates:
  * `risk`        — deterministic bucket derived from evidence signals
  * `risk_score`  — deterministic integer 0..100 (same signals)
  * `top_actions` — top-3 evidence-anchored recommendations
  * `bullets`     — evidence-anchored one-line facts

Determinism contract (protected by tests):
  * Same bundle in → byte-identical `ServiceOutput.to_json()`.
  * No wall-clock time, no randomness, no LLM.
  * Every action / bullet carries an ``anchor`` back to evidence
    (Blueprint §8.4 Evidence Navigation Contract).
"""
from __future__ import annotations

from typing import Any

from ..schemas import EvidenceBundle, ServiceOutput
from .base import BaseService, register_service

_NAME = "executive_summary"
_VERSION = "0.2.0-pr4"


# ---------------------------------------------------------------------------
# Verdict (unchanged from scaffold — protected by contract tests)
# ---------------------------------------------------------------------------


def _verdict(bundle: EvidenceBundle) -> str:
    if bundle.sample.family and bundle.capabilities:
        return "malicious"
    if bundle.capabilities or bundle.iocs:
        return "suspicious"
    return "unknown"


# ---------------------------------------------------------------------------
# Risk scoring (deterministic bucket)
# ---------------------------------------------------------------------------


def _risk_score(bundle: EvidenceBundle) -> int:
    """Deterministic 0..100 score from evidence signals.

    The score is a sum of bounded contributions:
      * +40 if family attributed
      * +5 per capability (capped at 20)
      * +3 per MITRE technique (capped at 15)
      * +2 per IOC (capped at 15)
      * +10 if certificate.ready_for_behavioral_analysis is False
             (residual obfuscation → operator concern)
    Total capped at 100. Order-independent by construction.
    """
    score = 0
    if bundle.sample.family:
        score += 40
    score += min(20, 5 * len(bundle.capabilities))
    score += min(15, 3 * len(bundle.mitre))
    score += min(15, 2 * len(bundle.iocs))
    if not bundle.certificate.get("ready_for_behavioral_analysis", False):
        score += 10
    return min(100, score)


def _risk_bucket(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "informational"


# ---------------------------------------------------------------------------
# Top IOCs / actions / bullets (each carries an anchor)
# ---------------------------------------------------------------------------


def _top_iocs(bundle: EvidenceBundle, n: int = 3) -> list[dict[str, Any]]:
    ordered = sorted(bundle.iocs, key=lambda x: x.ioc_id)[:n]
    return [i.to_dict() for i in ordered]


def _ioc_action_text(ioc_type: str, value: str) -> str:
    # Deterministic phrasing per IOC type.
    verb = {
        "url":      "Block URL at proxy / DNS sinkhole",
        "domain":   "Block domain at DNS + add watchlist",
        "ip":       "Block IP at firewall + add watchlist",
        "sha256":   "Add hash to EDR block list",
        "md5":      "Add hash to EDR block list",
        "email":    "Add sender to email gateway block list",
        "filepath": "Hunt for filepath across endpoints",
    }.get(ioc_type, "Investigate indicator")
    return f"{verb}: {value}"


def _top_actions(bundle: EvidenceBundle) -> list[dict[str, Any]]:
    """Top-3 recommended immediate actions — every action anchored.

    Deterministic priority order:
      1. Block/hunt first IOC (sorted by ioc_id).
      2. Contain host if any EXEC.* capability present.
      3. Hunt for MITRE technique across corpus (first by technique_id).
    Fewer than 3 if evidence doesn't support them.
    """
    actions: list[dict[str, Any]] = []

    for ioc in sorted(bundle.iocs, key=lambda x: x.ioc_id)[:1]:
        actions.append({
            "action_id": "act-block-primary-ioc",
            "priority": "P1",
            "text": _ioc_action_text(ioc.ioc_type, ioc.value),
            "anchor": {
                "kind": "ioc",
                "ioc_id": ioc.ioc_id,
                "iteration": ioc.source_iteration,
            },
        })

    exec_caps = sorted(
        (c for c in bundle.capabilities if c.capability_id.startswith("EXEC.")),
        key=lambda c: c.capability_id,
    )
    if exec_caps:
        cap = exec_caps[0]
        actions.append({
            "action_id": "act-contain-host",
            "priority": "P1",
            "text": f"Isolate host — {cap.display_name} detected",
            "anchor": {
                "kind": "capability",
                "capability_id": cap.capability_id,
                "iterations": list(cap.source_iterations),
            },
        })

    if bundle.mitre:
        mt = sorted(bundle.mitre, key=lambda m: m.technique_id)[0]
        actions.append({
            "action_id": "act-hunt-mitre",
            "priority": "P2",
            "text": f"Hunt corpus for {mt.technique_id} · {mt.technique_name}",
            "anchor": {
                "kind": "mitre",
                "technique_id": mt.technique_id,
            },
        })

    return actions[:3]


def _bullets(
    bundle: EvidenceBundle,
    verdict: str,
    risk: str,
    risk_score: int,
) -> list[dict[str, Any]]:
    """One-line facts, each anchored to evidence.

    Deterministic ordering:
      1. Verdict + risk score summary
      2. Family / technique attribution (if any)
      3. Convergence readiness
      4. Capability count summary (if any)
      5. IOC count summary (if any)
    Every bullet has an ``anchor`` per §8.4.
    """
    bullets: list[dict[str, Any]] = []

    bullets.append({
        "bullet_id": "b-verdict",
        "text": f"Verdict {verdict} · risk {risk} ({risk_score}/100)",
        "anchor": {
            "kind": "verdict",
            "certificate_hash": bundle.certificate.get("final_artifact_hash_sha256", ""),
        },
    })

    if bundle.sample.family:
        bullets.append({
            "bullet_id": "b-family",
            "text": f"Attributed family: {bundle.sample.family}"
                    + (f" · technique {bundle.sample.technique}" if bundle.sample.technique else ""),
            "anchor": {
                "kind": "sample",
                "sample_id": bundle.sample.sample_id,
            },
        })

    ready = bundle.certificate.get("ready_for_behavioral_analysis", False)
    bullets.append({
        "bullet_id": "b-canonical",
        "text": (
            "Canonical state reached — ready for behavioural analysis"
            if ready else
            "Residual obfuscation remains — canonical state NOT reached"
        ),
        "anchor": {
            "kind": "certificate",
            "field": "ready_for_behavioral_analysis",
        },
    })

    if bundle.capabilities:
        top_cap = sorted(bundle.capabilities, key=lambda c: c.capability_id)[0]
        bullets.append({
            "bullet_id": "b-capabilities",
            "text": f"{len(bundle.capabilities)} capability signal(s) · e.g. {top_cap.display_name}",
            "anchor": {
                "kind": "capability",
                "capability_id": top_cap.capability_id,
            },
        })

    if bundle.iocs:
        by_type: dict[str, int] = {}
        for i in bundle.iocs:
            by_type[i.ioc_type] = by_type.get(i.ioc_type, 0) + 1
        # Deterministic type ordering: alpha.
        parts = ", ".join(f"{n} {t}" for t, n in sorted(by_type.items()))
        bullets.append({
            "bullet_id": "b-iocs",
            "text": f"{len(bundle.iocs)} IOC(s) recovered · {parts}",
            "anchor": {
                "kind": "ioc_group",
                "types": sorted(by_type.keys()),
            },
        })

    return bullets


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def run(bundle: EvidenceBundle) -> ServiceOutput:
    verdict = _verdict(bundle)
    risk_score = _risk_score(bundle)
    risk = _risk_bucket(risk_score)

    body: dict[str, Any] = {
        "verdict": verdict,
        "risk": risk,
        "risk_score": risk_score,
        "family": bundle.sample.family,
        "technique": bundle.sample.technique,
        "canonical_state": bundle.certificate.get("canonical_state", False),
        "ready_for_behavioral_analysis": bundle.certificate.get(
            "ready_for_behavioral_analysis", False
        ),
        "top_iocs": _top_iocs(bundle, 3),
        "top_actions": _top_actions(bundle),
        "bullets": _bullets(bundle, verdict, risk, risk_score),
    }
    return ServiceOutput(
        service=_NAME,
        version=_VERSION,
        case_id=bundle.case_id,
        body=body,
    )


SERVICE = register_service(BaseService(name=_NAME, version=_VERSION, run=run))

__all__ = ["run", "SERVICE"]
