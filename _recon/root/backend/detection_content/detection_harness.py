"""
P0.2e · Detection Execution Harness
───────────────────────────────────

The authoritative promotion gate for a Capability Contract to move
from CONTRACT_DECLARED → RUNTIME_VERIFIED → EXECUTION_VERIFIED.

The harness runs an engine against BOTH a positive fixture (should
detect) AND a negative fixture (should NOT detect).  Only when both
outcomes are correct does the contract's `execution.detection`
flag become True.

    ┌──────────────────┐
    │ CONTRACT_DECLARED│
    └─────────┬────────┘
              │  run_harness(engine_id, rule, positive, negative)
              ▼
    ┌──────────────────┐
    │  positive DETECT │  correct?
    └─────────┬────────┘
              │
              ▼                         ┌───────────────────────┐
    ┌──────────────────┐ any FAILURE →  │ CONTRACT_DECLARED     │
    │  negative NOT-D  │  ────────────→ │ (unchanged, evidence  │
    └─────────┬────────┘                │  recorded in history) │
              │                          └───────────────────────┘
              ▼  both correct
    ┌──────────────────┐
    │ EXECUTION_VERIFIED│  execution.detection = True
    └──────────────────┘

The harness itself is engine-agnostic — it calls
`engine.evaluate(rule, evidence) → bool`.  Each candidate engine
that wants to prove detection capability must implement this
callable surface.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from .capability_contract import COLLECTION as CONTRACTS_COLLECTION, ContractStatus
from .sigma_strict import strict_parse, StrictParseStatus


@dataclass
class HarnessFixture:
    """One positive OR negative test case."""
    name:      str
    evidence:  dict           # canonical evidence dict fed to the engine
    expected:  bool           # True → engine should DETECT this
                              # False → engine should NOT detect this


@dataclass
class HarnessResult:
    engine_id:            str
    rule_id:              str
    positive_passed:      bool
    negative_passed:      bool
    positive_detail:      dict
    negative_detail:      dict
    verdict:              str          # EXECUTION_VERIFIED | FAILED
    ran_at:               str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "engine_id":        self.engine_id,
            "rule_id":          self.rule_id,
            "positive_passed":  self.positive_passed,
            "negative_passed":  self.negative_passed,
            "positive_detail":  self.positive_detail,
            "negative_detail":  self.negative_detail,
            "verdict":          self.verdict,
            "ran_at":           self.ran_at,
        }


def run_harness(
    engine_id:  str,
    rule_body:  str,
    engine_evaluate: Callable[[Any, dict], bool],
    positive:   HarnessFixture,
    negative:   HarnessFixture,
) -> HarnessResult:
    """
    Deterministically run the harness for one (engine, rule) pair.
    No persistence — persistence is done separately by the API layer
    via `record_verification()`.
    """
    parsed = strict_parse(rule_body)
    if parsed.status != StrictParseStatus.PARSED:
        # Rule itself is broken — harness cannot progress.
        return HarnessResult(
            engine_id       = engine_id,
            rule_id         = (parsed.surface.get("id")
                                        or "unknown"),
            positive_passed = False,
            negative_passed = False,
            positive_detail = {"error": "rule failed strict parse",
                                       "parse": parsed.to_dict()},
            negative_detail = {},
            verdict         = "FAILED",
        )

    def _step(fix: HarnessFixture) -> tuple[bool, dict]:
        try:
            got = bool(engine_evaluate(parsed.rule, fix.evidence))
        except Exception as e:
            return False, {"fixture": fix.name,
                                 "error_type": type(e).__name__,
                                 "error_message": str(e)}
        return (got == fix.expected), {
            "fixture":  fix.name,
            "expected": fix.expected,
            "got":      got,
        }

    pos_ok, pos_detail = _step(positive)
    neg_ok, neg_detail = _step(negative)
    verdict = "EXECUTION_VERIFIED" if (pos_ok and neg_ok) else "FAILED"
    return HarnessResult(
        engine_id       = engine_id,
        rule_id         = str(parsed.surface.get("id") or "unknown"),
        positive_passed = pos_ok,
        negative_passed = neg_ok,
        positive_detail = pos_detail,
        negative_detail = neg_detail,
        verdict         = verdict,
    )


# ── Persistence (async · Motor) ──────────────────────────────────

async def record_verification(db, result: HarnessResult) -> dict:
    """
    Update the engine's capability contract based on the harness
    outcome.

    On EXECUTION_VERIFIED:
        contract_status         → EXECUTION_VERIFIED
        execution.detection     → True
        verification_history[] .append(result)
        classification          → DETECTION_ENGINE (promotion via proof)

    On FAILED:
        contract_status         unchanged
        execution.detection     unchanged (stays False)
        verification_history[] .append(result)
    """
    coll = db[CONTRACTS_COLLECTION]
    existing = await coll.find_one({"engine_id": result.engine_id})
    if not existing:
        return {"engine_id": result.engine_id,
                    "recorded": False,
                    "note": "No declared contract for this engine — "
                              "call POST /contracts/declare first."}

    update: dict = {
        "$push": {"verification_history": result.to_dict()},
    }
    if result.verdict == "EXECUTION_VERIFIED":
        update["$set"] = {
            "contract_status":       ContractStatus.EXECUTION_VERIFIED.value,
            "execution.detection":   True,
            "classification":        "DETECTION_ENGINE",
            "last_verified_at":      result.ran_at,
        }
    else:
        update["$set"] = {"last_verified_at": result.ran_at}

    await coll.update_one({"engine_id": result.engine_id}, update)
    return {"engine_id": result.engine_id,
                "recorded": True,
                "verdict":  result.verdict}
