"""Verdict Uplift · analyst-facing 5-second answer.

Consumes the fired :class:`Intent` list from the Semantic Intent
Layer and produces a deterministic verdict band + short reason +
per-intent evidence citation.

Deliberately conservative:
    * only aggregates intents that already exist,
    * cites intent evidence directly — nothing new is inferred,
    * runtime-dependent outcomes remain runtime-dependent.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from ..evidence import Evidence
from ..intent.models import Intent, IntentCategory, RiskBand


class VerdictBand(str, Enum):
    MALICIOUS         = "malicious"
    SUSPICIOUS        = "suspicious"
    RUNTIME_DEPENDENT = "runtime_dependent"
    BENIGN            = "benign"


@dataclass
class Verdict:
    """Analyst-facing verdict — the 5-second answer.

    Fields:
        band       — canonical verdict band.
        reason     — one plain-English sentence describing WHY.
        confidence — 0-100 confidence derived from supporting intents.
        top_intents — the up-to-3 highest-confidence intents that
                      drove the verdict, so the analyst can drill in.
        evidence   — canonical Evidence objects that support the
                      verdict — always drawn from the fired intents.
    """
    band:        VerdictBand
    reason:      str
    confidence:  int
    top_intents: list[Intent] = field(default_factory=list)
    evidence:    list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "band":        self.band.value,
            "reason":      self.reason,
            "confidence":  self.confidence,
            "top_intents": [i.to_dict() for i in self.top_intents],
            "evidence":    [e.to_dict() for e in self.evidence],
        }


# ── Deterministic verdict rules ────────────────────────────────
# Every rule is (predicate, band, reason-template). The FIRST rule
# to fire wins — order matters. Conservative by design: adversarial
# combinations must fire BEFORE the RUNTIME_DEPENDENT fallback so a
# download-and-run cradle is `malicious`, not merely `runtime_dependent`.
_HIGH_RISK = {RiskBand.HIGH}


def _has(intents: list[Intent], cat: IntentCategory,
         risk: set[RiskBand] | None = None) -> bool:
    for i in intents:
        if i.category != cat:
            continue
        if risk is not None and i.risk not in risk:
            continue
        return True
    return False


def assess_verdict(intents: list[Intent]) -> Verdict:
    """Produce a deterministic verdict from the fired intents."""
    top = sorted(intents, key=lambda i: (-i.confidence,
                                          i.category.value))[:3]
    evidence: list[Evidence] = []
    for i in top:
        evidence.extend(i.evidence)

    if not intents:
        return Verdict(
            band=VerdictBand.BENIGN,
            reason=("No adversarial intent was inferred from the effective "
                     "payload. The artefact appears benign."),
            confidence=60,
            top_intents=[],
            evidence=[],
        )

    fetch_and_run = (
        _has(intents, IntentCategory.STAGING, _HIGH_RISK)
        and _has(intents, IntentCategory.REMOTE_EXECUTION, _HIGH_RISK)
    )
    creds_or_persist = (
        _has(intents, IntentCategory.CREDENTIAL_ACCESS, _HIGH_RISK)
        or _has(intents, IntentCategory.PERSISTENCE, _HIGH_RISK)
    )
    high_evasion = _has(intents, IntentCategory.DEFENSE_EVASION, _HIGH_RISK)
    # Credentialed remote administration is dual-use: legitimate admin
    # OR post-compromise lateral movement. Fire MALICIOUS only when
    # LATERAL_MOVEMENT co-occurs with DEFENSE_EVASION (firewall
    # reconfiguration) — the composition strongly indicates covert
    # remote-management setup. Standalone LATERAL_MOVEMENT stays
    # SUSPICIOUS so the analyst can distinguish authorised admin.
    lateral_admin_composed = (
        _has(intents, IntentCategory.LATERAL_MOVEMENT, _HIGH_RISK)
        and high_evasion
    )

    # ── Malicious: multi-tactic high-risk combinations
    # ── OR a single HIGH-risk defense-evasion primitive (AMSI /
    # ──   ETW / Defender tamper have no legitimate use).
    if fetch_and_run or creds_or_persist or high_evasion or lateral_admin_composed:
        drivers: list[str] = []
        for i in top:
            if i.risk == RiskBand.HIGH and i.category.value not in drivers:
                drivers.append(i.category.value)
            if len(drivers) >= 3:
                break
        reason = (
            "High-risk adversarial intent chain detected: "
            + " + ".join(drivers)
            + ". Behaviour is consistent with malicious execution."
        )
        return Verdict(
            band=VerdictBand.MALICIOUS,
            reason=reason,
            confidence=min(95, max(i.confidence for i in top)),
            top_intents=top,
            evidence=evidence,
        )

    # ── Runtime dependent: only unknowns fired ─────────────────
    if all(i.risk == RiskBand.UNKNOWN for i in intents):
        return Verdict(
            band=VerdictBand.RUNTIME_DEPENDENT,
            reason=("Effective payload's behaviour depends on runtime context "
                     "(remote content, environment variable, user input, or "
                     "reflectively loaded assembly). Verdict cannot be determined "
                     "statically."),
            confidence=max(i.confidence for i in intents),
            top_intents=top,
            evidence=evidence,
        )

    # ── Suspicious: any high-risk intent that didn't hit a
    # ── malicious combination, OR a mix of medium-risk intents.
    reason_lead = top[0].purpose if top else "Suspicious intent observed."
    return Verdict(
        band=VerdictBand.SUSPICIOUS,
        reason=(
            "Suspicious behaviour observed. " + reason_lead
        ),
        confidence=min(85, max(i.confidence for i in top)) if top else 60,
        top_intents=top,
        evidence=evidence,
    )


__all__ = ["Verdict", "VerdictBand", "assess_verdict"]
