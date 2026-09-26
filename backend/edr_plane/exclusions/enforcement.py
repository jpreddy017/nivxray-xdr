"""GATE 7 · the enforcement point.

Two DIFFERENT things happen here, and they are never merged:

  1. `gate(unit, exclusions)` runs BEFORE an analyzer. If it matches, the
     analyzer does not run at all and the outcome is
     `NOT_EVALUATED` with truth state
     `NOT_EVALUATED_DUE_TO_EXCLUSION` / `SERVER_EXCLUSION_APPLIED`.

  2. `suppress(result, decision)` is used when an engine ALREADY produced
     findings (for example the deterministic derivation was recorded at
     ingest, before the exclusion existed). Those findings are marked
     `SUPPRESSED` with `suppressed_by`, truth state `EXCLUDED`. The fact
     that a finding EXISTED is preserved — we do not rewrite history into
     "nothing was found".

Endpoint-side truth is derived separately, from the connector's declared
capability and the endpoint's actual policy state.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from edr_plane.exclusions.contracts import (ENDPOINT_ENGINE_CAPABILITY,
                                            EnforcementPoint, TruthState,
                                            matches)
from edr_plane.fabric.contracts import (AnalyzerResult, EvidenceUnit,
                                        FindingState, Outcome)


@dataclass(frozen=True)
class ExclusionDecision:
    excluded: bool
    truth_state: str
    enforcement_point: Optional[str] = None
    engine: Optional[str] = None
    exclusion_id: Optional[str] = None
    set_id: Optional[str] = None
    type: Optional[str] = None
    value: Optional[str] = None
    reason: Optional[str] = None
    basis: str = ""
    matched_attribute: Optional[str] = None
    observed_value: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


NOT_EXCLUDED = ExclusionDecision(
    excluded=False, truth_state="EVALUATED",
    basis="no approved, effective, in-scope exclusion matched the observed "
          "activity, so the engine ran normally")

_CEF_KV = re.compile(r"(\w+)=([^\s]+)")


def candidate_from_unit(unit: EvidenceUnit) -> Dict[str, Optional[str]]:
    """The attributes an exclusion can be evaluated against.

    Absent attributes stay absent. A `None` here is why an exclusion
    cannot match activity whose relevant attribute was never observed.
    """
    a = unit.activity if isinstance(unit.activity, dict) else {}
    raw = a.get("raw") if isinstance(a.get("raw"), dict) else {}
    event = a.get("event") if isinstance(a.get("event"), dict) else {}
    ev_raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}

    def first(*vals):
        for v in vals:
            if isinstance(v, str) and v.strip():
                return v.strip()
        return None

    cand = {
        "path": first(a.get("image_path"), a.get("path"), a.get("image"),
                      raw.get("target"), ev_raw.get("target")),
        "process": first(a.get("process"), a.get("process_name"),
                         raw.get("entity"), ev_raw.get("entity"),
                         a.get("dproc")),
        "command_line": first(a.get("command_line"), a.get("commandline"),
                              raw.get("text"), ev_raw.get("text"),
                              a.get("text")),
        "file_hash": first(a.get("sha256"), a.get("input_sha256"),
                           raw.get("sha256"), ev_raw.get("sha256")),
        "network_address": first(a.get("remote_address"), a.get("dest_ip"),
                                 raw.get("dest_ip"), ev_raw.get("dest_ip")),
    }
    if not any(cand.values()) and isinstance(a.get("_payload"), str):
        kv = dict(_CEF_KV.findall(a["_payload"]))
        cand["process"] = kv.get("dproc") or cand["process"]
        cand["path"] = kv.get("dpath") or cand["path"]
        cand["command_line"] = a["_payload"]
    return cand


def payload_activity(payload: str) -> Dict[str, Any]:
    """Best-effort activity view of a raw payload, for the gate only.

    A parse failure is not hidden: the verbatim payload is carried as
    `_payload` so a COMMANDLINE exclusion can still be evaluated against
    what was actually observed.
    """
    try:
        parsed = json.loads(payload or "{}")
        if isinstance(parsed, dict):
            parsed.setdefault("_payload", payload)
            return parsed
    except (ValueError, TypeError):
        pass
    return {"_payload": payload or ""}


def decide(*, exclusions: List[Dict[str, Any]], engine: str,
           candidate: Dict[str, Optional[str]]) -> ExclusionDecision:
    """First matching exclusion aimed at THIS engine wins."""
    for e in exclusions:
        if engine not in (e.get("affected_engines") or []):
            continue
        if not matches(e, candidate):
            continue
        attribute = {
            "PATH": "path", "FILE_EXTENSION": "path",
            "FILE_HASH": "file_hash", "PROCESS": "process",
            "PROCESS_COMMANDLINE": "command_line",
            "NETWORK_ADDRESS": "network_address",
        }.get(e.get("type"))
        return ExclusionDecision(
            excluded=True,
            truth_state=TruthState.SERVER_EXCLUSION_APPLIED.value,
            enforcement_point=EnforcementPoint.SERVER_FABRIC.value,
            engine=engine, exclusion_id=e.get("exclusion_id"),
            set_id=e.get("set_id"), type=e.get("type"), value=e.get("value"),
            reason=e.get("reason"), matched_attribute=attribute,
            observed_value=(candidate.get(attribute) if attribute else None),
            basis=(f"exclusion {e.get('exclusion_id')} "
                   f"({e.get('type')} {e.get('match')} '{e.get('value')}') "
                   f"is approved, effective and in scope, and it is aimed at "
                   f"{engine}; the engine was bypassed for this evidence"))
    return NOT_EXCLUDED


def gate(*, analyzer: Any, unit: EvidenceUnit,
         exclusions: List[Dict[str, Any]], engine: str
         ) -> tuple[AnalyzerResult, ExclusionDecision]:
    """Run an analyzer through the exclusion gate.

    On a match the analyzer is NOT called. That is the difference between
    a product that suppressed an alert and a product that did not look.
    """
    decision = decide(exclusions=exclusions, engine=engine,
                      candidate=candidate_from_unit(unit))
    if not decision.excluded:
        return analyzer.evaluate(unit), decision
    return AnalyzerResult(
        analyzer_id=analyzer.id, outcome=Outcome.NOT_EVALUATED,
        reason=(TruthState.NOT_EVALUATED_DUE_TO_EXCLUSION.value + ": "
                + decision.basis)), decision


def suppress(result: AnalyzerResult,
             decision: ExclusionDecision) -> AnalyzerResult:
    """Mark findings that already existed as SUPPRESSED, not absent.

    Used for evidence an engine evaluated BEFORE the exclusion existed.
    The finding, its evidence refs and its analyzer all survive; only its
    state changes, and it names the exclusion that suppressed it.
    """
    if not result.findings or not decision.excluded:
        return result
    suppressed = []
    for f in result.findings:
        suppressed.append(f.model_copy(update={
            "state": FindingState.SUPPRESSED.value,
            "suppressed_by": decision.exclusion_id}))
    return AnalyzerResult(analyzer_id=result.analyzer_id,
                          outcome=Outcome.FINDINGS, findings=suppressed)


def endpoint_truth_state(exclusion: Dict[str, Any], *,
                         engine: str,
                         connector_capabilities: Dict[str, bool],
                         endpoint_policy_state: Dict[str, Any]
                         ) -> Dict[str, Any]:
    """What is REALLY happening on the endpoint for this exclusion.

    Three genuinely different answers, and none of them is assumed:
      * the connector cannot honour it at all
      * it is carried by a policy version the endpoint has not applied
      * the endpoint applied that exact version, so it is enforced there
    """
    capability = ENDPOINT_ENGINE_CAPABILITY.get(engine)
    if capability and not connector_capabilities.get(capability, False):
        return {"truth_state":
                TruthState.EXCLUSION_NOT_SUPPORTED_BY_ENGINE.value,
                "enforcement_point": EnforcementPoint.ENDPOINT.value,
                "engine": engine,
                "basis": ("the released connector does not declare "
                          f"{capability}, so this exclusion cannot be "
                          "enforced on the endpoint; server-side "
                          "enforcement is unaffected")}
    bindings = exclusion.get("policy_version_bindings") or []
    applied_policy = endpoint_policy_state.get("assigned_policy_id")
    applied_version = endpoint_policy_state.get("applied_version")
    confirmed = endpoint_policy_state.get("confirmed_by_endpoint")
    if confirmed and any(b.get("policy_id") == applied_policy
                         and int(b.get("version") or -1) == int(
                             applied_version or -2) for b in bindings):
        return {"truth_state": TruthState.ENDPOINT_EXCLUSION_APPLIED.value,
                "enforcement_point": EnforcementPoint.ENDPOINT.value,
                "engine": engine,
                "basis": (f"the endpoint acknowledged applying policy "
                          f"{applied_policy} v{applied_version}, which "
                          "carries this exclusion")}
    return {"truth_state": TruthState.EXCLUSION_PENDING_POLICY.value,
            "enforcement_point": EnforcementPoint.ENDPOINT.value,
            "engine": engine,
            "basis": ("no policy version carrying this exclusion has been "
                      "acknowledged as applied by the endpoint, so it is "
                      "not being enforced there yet")}
