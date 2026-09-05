"""RC5 · Phase 7 · Verdict v2 — deterministic 7-dimension risk score.

See § 10 of `/app/memory/RC5_SEMANTIC_ENGINE_SPEC.md`.

Seven orthogonal dimensions, each 0-100, computed strictly from
Behavior[], MitreMapping[], and LolbinRow[] (all evidence-first):

  * intent           — obfuscation / evasion markers
  * capability       — what the reconstructed graph *could* do
  * execution        — count of behaviors that actually emitted (not just parsed)
  * impact           — severity of reconstructed outcome
  * stealth          — anti-forensic markers (AMSI/ETW bypass, log clearing)
  * persistence      — autoruns / tasks / services / WMI subs
  * defense_evasion  — obfuscation, LOLBIN abuse for evasion

**Composite risk = round(Σ weight_i · score_i)** with weights `WEIGHTS`.

**Cap-and-floor (§ 10 architectural invariant):**

Locked by user directive:
    "Execution alone must never determine maliciousness.
     An obfuscated but benign command must remain benign if reconstructed
     behavior is benign."

Mechanism:
  * If `capability ≤ CAP_LOW_THRESHOLD` AND `impact ≤ CAP_LOW_THRESHOLD`
    then composite is CAPPED at `TIER_BENIGN_MAX` (24).
  * If `execution == 0` then composite is CAPPED at `TIER_BENIGN_MAX` (24).
  * If `impact ≥ FLOOR_HIGH_THRESHOLD` OR `capability ≥ FLOOR_HIGH_THRESHOLD`
    AND `execution > 0`, then composite is FLOORED at `TIER_MALICIOUS_MIN` (50).

**Invariants enforced here:**
  * Deterministic: same inputs → identical scores.
  * No AI. No `emergentintegrations` import.
  * Every top_reason references ≥ 1 `evidence_behavior_id`.
  * Advisor-origin behaviors are ignored (guaranteed by upstream extractor).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..exec_graph import Behavior, SCHEMA_VERSION, TacticKind
from .lolbin_v2 import LolbinRow, LolbinState
from .mitre_mapper import MitreMapping


# ---------------------------------------------------------------------------
# Public constants — all tuning happens here (single source of truth).
# ---------------------------------------------------------------------------
WEIGHTS: Dict[str, float] = {
    "intent":          0.15,
    "capability":      0.30,
    "execution":       0.05,
    "impact":          0.25,
    "stealth":         0.10,
    "persistence":     0.10,
    "defense_evasion": 0.05,
}  # Sum = 1.00, verified in tests.

CAP_LOW_THRESHOLD = 20
FLOOR_HIGH_THRESHOLD = 80
TIER_BENIGN_MAX = 24
TIER_SUSPICIOUS_MAX = 49
TIER_MALICIOUS_MAX = 74
TIER_MALICIOUS_MIN = 50


class VerdictTier(str, Enum):
    benign      = "Benign"
    suspicious  = "Suspicious"
    malicious   = "Malicious"
    critical    = "Critical"


def _tier_from_risk(risk: int) -> VerdictTier:
    if risk <= TIER_BENIGN_MAX:
        return VerdictTier.benign
    if risk <= TIER_SUSPICIOUS_MAX:
        return VerdictTier.suspicious
    if risk <= TIER_MALICIOUS_MAX:
        return VerdictTier.malicious
    return VerdictTier.critical


# ---------------------------------------------------------------------------
# VerdictReason — one analyst-facing reason line with evidence.
# ---------------------------------------------------------------------------
class VerdictReason(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: str
    evidence_behavior_ids: Tuple[str, ...]
    tactic: str
    contribution: int          # dimension points contributed
    dimension: str             # which of the 7 dims

    @field_validator("evidence_behavior_ids")
    @classmethod
    def _one(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if not v:
            raise ValueError("VerdictReason must reference ≥ 1 behavior")
        return v


# ---------------------------------------------------------------------------
# Verdict — final scored result.
# ---------------------------------------------------------------------------
class Verdict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    verdict: VerdictTier
    risk: int
    raw_risk: int                           # pre cap-and-floor
    scores: Dict[str, int]                  # 7 dims, 0-100
    top_reasons: Tuple[VerdictReason, ...]  # up to 5, deterministic order
    cap_applied: Optional[str] = None       # "low_capability_impact" | "no_execution" | None
    floor_applied: Optional[str] = None
    weights: Dict[str, float] = Field(default_factory=lambda: dict(WEIGHTS))
    schema_version: int = SCHEMA_VERSION

    @field_validator("scores")
    @classmethod
    def _scores_shape(cls, v: Dict[str, int]) -> Dict[str, int]:
        expected = set(WEIGHTS)
        if set(v) != expected:
            raise ValueError(
                f"Verdict.scores must have exactly {sorted(expected)}, got {sorted(v)}"
            )
        for k, s in v.items():
            if not (0 <= int(s) <= 100):
                raise ValueError(f"score {k}={s} out of [0, 100]")
        return v

    @field_validator("risk", "raw_risk")
    @classmethod
    def _clamp(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError(f"risk must be in [0, 100], got {v}")
        return v


# ---------------------------------------------------------------------------
# Scorer — one method per dimension. All inputs are structured; no regex.
# ---------------------------------------------------------------------------
@dataclass
class _Contribution:
    dimension: str
    points: int
    reason: str
    tactic: str
    behavior_ids: Tuple[str, ...]


class VerdictComputer:
    """Compute a `Verdict` from Behaviors + Mitre + Lolbins."""

    # Human-readable reasons per (tactic, sub_kind).
    _REASON_TABLE: Dict[Tuple[str, Optional[str]], str] = {
        (TacticKind.execution.value, "shellcode_exec"):        "Shellcode reflectively executed in-memory",
        (TacticKind.execution.value, "dll_load"):              "Runtime DLL load",
        (TacticKind.execution.value, "process_spawn"):         "Process spawned by the reconstructed graph",
        (TacticKind.persistence.value, "autorun_registration"): "Autorun registry key written",
        (TacticKind.persistence.value, "create_task"):          "Scheduled task created for persistence",
        (TacticKind.persistence.value, "install_service"):      "Windows Service installed for persistence",
        (TacticKind.persistence.value, "write_registry"):       "Persistence-relevant registry key written",
        (TacticKind.credential_access.value, "dump_credentials"): "Credential-dumping tooling invoked",
        (TacticKind.command_and_control.value, "download"):     "Ingress tool transfer / payload download",
        (TacticKind.command_and_control.value, "http"):         "HTTP/S beacon channel established",
        (TacticKind.exfiltration.value, "upload"):              "Data exfiltration via upload channel",
        (TacticKind.impact.value, "file_delete"):               "Destructive file deletion",
        (TacticKind.defense_evasion.value, "bypass_amsi"):      "AMSI bypass — anti-forensic evasion",
        (TacticKind.defense_evasion.value, "bypass_etw"):       "ETW bypass — telemetry blinding",
        (TacticKind.defense_evasion.value, "reflection"):       "Reflective assembly loader — evasion",
        (TacticKind.defense_evasion.value, "obfuscation"):      "Encoded / obfuscated command payload",
        (TacticKind.defense_evasion.value, "memory_alloc"):     "Manual memory allocation for injection",
        (TacticKind.wmi_subscription.value, None):              "WMI permanent subscription — stealth persistence",
    }

    def compute(
        self,
        behaviors: List[Behavior],
        mitre: Optional[List[MitreMapping]] = None,
        lolbins: Optional[List[LolbinRow]] = None,
    ) -> Verdict:
        mitre = mitre or []
        lolbins = lolbins or []
        contribs = self._contributions(behaviors, mitre, lolbins)

        # Sum contributions per dimension, cap at 100.
        scores = {k: 0 for k in WEIGHTS}
        for c in contribs:
            scores[c.dimension] = min(100, scores[c.dimension] + c.points)

        # Weighted sum
        raw_risk = int(round(sum(WEIGHTS[k] * scores[k] for k in WEIGHTS)))
        raw_risk = max(0, min(100, raw_risk))

        # Cap-and-floor
        cap_applied: Optional[str] = None
        floor_applied: Optional[str] = None
        risk = raw_risk
        if scores["execution"] == 0:
            if risk > TIER_BENIGN_MAX:
                cap_applied = "no_execution"
                risk = TIER_BENIGN_MAX
        elif scores["capability"] <= CAP_LOW_THRESHOLD and scores["impact"] <= CAP_LOW_THRESHOLD:
            if risk > TIER_BENIGN_MAX:
                cap_applied = "low_capability_and_impact"
                risk = TIER_BENIGN_MAX
        elif (scores["impact"] >= FLOOR_HIGH_THRESHOLD
              or scores["capability"] >= FLOOR_HIGH_THRESHOLD) and scores["execution"] > 0:
            if risk < TIER_MALICIOUS_MIN:
                floor_applied = "high_capability_or_impact"
                risk = TIER_MALICIOUS_MIN

        # Top reasons — highest-contribution items first, dedup by reason string.
        contribs_sorted = sorted(contribs, key=lambda c: (-c.points, c.dimension, c.reason))
        seen_reasons: set = set()
        top_reasons: List[VerdictReason] = []
        for c in contribs_sorted:
            if c.reason in seen_reasons:
                continue
            seen_reasons.add(c.reason)
            top_reasons.append(VerdictReason(
                reason=c.reason,
                evidence_behavior_ids=c.behavior_ids,
                tactic=c.tactic,
                contribution=c.points,
                dimension=c.dimension,
            ))
            if len(top_reasons) >= 5:
                break

        # Deterministic ID
        digest = hashlib.sha1(
            f"{raw_risk}|{risk}|{sorted(scores.items())}|{cap_applied}|{floor_applied}"
            .encode("utf-8")
        ).hexdigest()[:12]
        return Verdict(
            id="v_" + digest,
            verdict=_tier_from_risk(risk),
            risk=risk,
            raw_risk=raw_risk,
            scores=scores,
            top_reasons=tuple(top_reasons),
            cap_applied=cap_applied,
            floor_applied=floor_applied,
        )

    # ── Contribution builder ─────────────────────────────────────────
    def _contributions(
        self,
        behaviors: List[Behavior],
        mitre: List[MitreMapping],
        lolbins: List[LolbinRow],
    ) -> List[_Contribution]:
        out: List[_Contribution] = []

        def emit(dim: str, pts: int, reason: str, tactic: str, bid: str) -> None:
            if pts > 0:
                out.append(_Contribution(dim, pts, reason, tactic, (bid,)))

        for b in behaviors:
            key = (b.tactic.value, b.sub_kind)
            reason = self._REASON_TABLE.get(key,
                     self._REASON_TABLE.get((b.tactic.value, None),
                     f"{b.tactic.value} · {b.sub_kind or '—'}"))

            t = b.tactic
            sk = b.sub_kind

            # execution dimension — each meaningful attacker behavior counts
            if t in (TacticKind.execution, TacticKind.persistence,
                     TacticKind.credential_access,
                     TacticKind.command_and_control,
                     TacticKind.exfiltration, TacticKind.impact,
                     TacticKind.collection):
                emit("execution", 25, reason, t.value, b.id)
            if t == TacticKind.defense_evasion:
                emit("execution", 10, reason, t.value, b.id)

            # capability — what the graph could do
            if t == TacticKind.execution and sk == "process_spawn":
                emit("capability", 5, reason, t.value, b.id)  # deliberately tiny
            if sk in ("shellcode_exec",):
                emit("capability", 90, reason, t.value, b.id)
            if sk in ("reflection", "dll_load"):
                emit("capability", 80, reason, t.value, b.id)
            if t == TacticKind.command_and_control and sk == "download":
                emit("capability", 55, reason, t.value, b.id)
            if t == TacticKind.command_and_control and sk == "http":
                emit("capability", 30, reason, t.value, b.id)
            if t == TacticKind.credential_access:
                emit("capability", 70, reason, t.value, b.id)
            if t == TacticKind.persistence:
                emit("capability", 30, reason, t.value, b.id)
            if t == TacticKind.exfiltration:
                emit("capability", 30, reason, t.value, b.id)

            # impact
            if t == TacticKind.impact:
                emit("impact", 55, reason, t.value, b.id)
            if t == TacticKind.credential_access:
                emit("impact", 80, reason, t.value, b.id)
            if t == TacticKind.exfiltration:
                emit("impact", 60, reason, t.value, b.id)
            if t == TacticKind.command_and_control and sk == "download":
                emit("impact", 35, reason, t.value, b.id)
            if t == TacticKind.persistence:
                emit("impact", 30, reason, t.value, b.id)
            if sk == "shellcode_exec":
                emit("impact", 50, reason, t.value, b.id)

            # persistence
            if t == TacticKind.persistence:
                emit("persistence", 45, reason, t.value, b.id)
            if sk == "autorun_registration":
                emit("persistence", 40, reason, t.value, b.id)
            if sk in ("create_task", "install_service"):
                emit("persistence", 35, reason, t.value, b.id)
            if t == TacticKind.wmi_subscription:
                emit("persistence", 50, reason, t.value, b.id)

            # stealth
            if sk == "bypass_amsi":
                emit("stealth", 45, reason, t.value, b.id)
            if sk == "bypass_etw":
                emit("stealth", 45, reason, t.value, b.id)
            if sk == "shellcode_exec":
                emit("stealth", 30, reason, t.value, b.id)
            if t == TacticKind.command_and_control and sk == "download":
                emit("stealth", 10, reason, t.value, b.id)

            # defense_evasion (as a distinct concept from stealth)
            if t == TacticKind.defense_evasion:
                pts = 30 if sk in ("bypass_amsi", "bypass_etw",
                                   "reflection") else 20
                emit("defense_evasion", pts, reason, t.value, b.id)
            if t == TacticKind.command_and_control and sk == "download":
                # download via LOLBIN family flag — defensive evasion posture
                emit("defense_evasion", 40, reason, t.value, b.id)

            # intent — obfuscation / anti-analysis / evasion signals
            if t == TacticKind.defense_evasion:
                emit("intent", 20, reason, t.value, b.id)
            if sk == "obfuscation":
                emit("intent", 30, reason, t.value, b.id)
            if t == TacticKind.command_and_control and sk == "download":
                emit("intent", 20, reason, t.value, b.id)

        # LOLBIN v2 uplift — only `executed` state (§ 9 invariant).
        # Phase 9.5 RCA: uplift excludes the shells themselves (`cmd`,
        # `powershell`, `pwsh`, `cscript`, `wscript`) since their abuse
        # is already captured by other behaviors (obfuscation, encoded
        # commands, autorun writes, etc). Uplift only applies to the
        # "surprise" LOLBIN family (certutil, mshta, bitsadmin, rundll32,
        # regsvr32, wmic, installutil, msbuild, schtasks, sc, mimikatz…).
        _SHELL_BARE_NAMES = frozenset({
            "cmd", "powershell", "pwsh", "cscript", "wscript",
        })
        for l in lolbins:
            if l.state != LolbinState.executed:
                continue
            if l.binary in _SHELL_BARE_NAMES:
                continue
            fake_bid = "l_" + l.id
            emit("defense_evasion", 25,
                 f"LOLBIN executed: {l.display_name}",
                 "defense_evasion", fake_bid)
            emit("capability", 40,
                 f"LOLBIN executed: {l.display_name}",
                 "defense_evasion", fake_bid)
            emit("impact", 35,
                 f"LOLBIN executed: {l.display_name}",
                 "defense_evasion", fake_bid)
            emit("intent", 20,
                 f"LOLBIN executed: {l.display_name}",
                 "defense_evasion", fake_bid)

        return out


# ---------------------------------------------------------------------------
# Module-level accessors
# ---------------------------------------------------------------------------
_INSTANCE = VerdictComputer()


def compute_verdict(
    behaviors: List[Behavior],
    mitre: Optional[List[MitreMapping]] = None,
    lolbins: Optional[List[LolbinRow]] = None,
) -> Verdict:
    return _INSTANCE.compute(behaviors, mitre, lolbins)


def get_verdict_computer() -> VerdictComputer:
    return _INSTANCE


__all__ = [
    "VerdictTier",
    "VerdictReason",
    "Verdict",
    "VerdictComputer",
    "compute_verdict",
    "get_verdict_computer",
    "WEIGHTS",
    "CAP_LOW_THRESHOLD",
    "FLOOR_HIGH_THRESHOLD",
    "TIER_BENIGN_MAX",
    "TIER_SUSPICIOUS_MAX",
    "TIER_MALICIOUS_MAX",
    "TIER_MALICIOUS_MIN",
]
