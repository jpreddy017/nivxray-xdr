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

from edr_plane.exclusions.contracts import (DETECTION_SUPPRESSING_SCOPES,
                                            ENDPOINT_ENGINE_CAPABILITY,
                                            EnforcementPoint, TruthState,
                                            enforcement_scope_of, matches)
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
    #: P0-B · WHAT was suppressed, and whether the evidence survived it.
    enforcement_scope: Optional[str] = None
    enforcement_scope_basis: Optional[str] = None
    evidence_retained: Optional[bool] = None

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
        # `image_path` is a path; `image` is the process NAME (comm on
        # Linux). Treating `image` as a path made PATH exclusions match
        # a bare name and PROCESS exclusions match nothing.
        "path": first(a.get("image_path"), a.get("path"),
                      raw.get("target"), ev_raw.get("target")),
        "process": first(a.get("process"), a.get("process_name"),
                         a.get("image"), raw.get("entity"),
                         ev_raw.get("entity"), a.get("dproc")),
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
    """First matching exclusion aimed at THIS engine wins.

    P0-B · only a COLLECTION- or DETECTION-scoped exclusion suppresses a
    verdict. One aimed solely at PREVENTION is NOT allowed to become
    detection blindness, so it is skipped here and the engine runs.
    """
    for e in exclusions:
        if engine not in (e.get("affected_engines") or []):
            continue
        scope, scope_basis = enforcement_scope_of(e)
        if scope not in DETECTION_SUPPRESSING_SCOPES:
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
            enforcement_scope=scope,
            enforcement_scope_basis=scope_basis,
            evidence_retained=(scope == "DETECTION"),
            basis=(f"exclusion {e.get('exclusion_id')} "
                   f"({e.get('type')} {e.get('match')} '{e.get('value')}') "
                   f"is approved, effective and in scope, and it is aimed at "
                   f"{engine}; the engine was bypassed for this evidence. "
                   f"Enforcement scope {scope}: "
                   + ("the verdict is suppressed and the underlying "
                      "evidence is retained"
                      if scope == "DETECTION" else
                      "the endpoint does not deliver this activity at all, "
                      "so the evidence does not exist to re-evaluate")))
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
                         endpoint_policy_state: Dict[str, Any],
                         enforcement: Optional[Dict[str, Any]] = None
                         ) -> Dict[str, Any]:
    """What is REALLY happening on the endpoint for this exclusion.

    Five genuinely different answers, and none is assumed:

      * the released connector cannot honour it at all,
      * the CONNECTOR ITSELF refused it (it said so on its own session),
      * it is carried by a policy version the endpoint has not applied,
      * the endpoint applied that version and its engine is consulting
        the exclusion, but nothing has matched yet,
      * the endpoint reported it actually enforced it — the only state
        that earns `ENDPOINT_EXCLUSION_APPLIED`.

    `ENDPOINT_EXCLUSION_APPLIED` is NEVER derived from a delivered
    configuration. It requires an enforcement record the endpoint
    produced.
    """
    capability = ENDPOINT_ENGINE_CAPABILITY.get(engine)
    if capability and not connector_capabilities.get(capability, False):
        return {"truth_state":
                TruthState.EXCLUSION_NOT_SUPPORTED_BY_ENGINE.value,
                "enforcement_point": EnforcementPoint.ENDPOINT.value,
                "engine": engine,
                "basis": ("the connector release installed on this endpoint "
                          f"does not declare {capability}, so this exclusion "
                          "cannot be enforced there; server-side enforcement "
                          "is unaffected")}

    acceptance = (enforcement or {}).get("acceptance")
    if acceptance and acceptance != "HONOURED":
        return {"truth_state":
                TruthState.EXCLUSION_NOT_SUPPORTED_BY_ENGINE.value,
                "enforcement_point": EnforcementPoint.ENDPOINT.value,
                "engine": engine, "acceptance": acceptance,
                "basis": ("the connector reported on its own authenticated "
                          f"session that it refused this exclusion: "
                          f"{acceptance}. It is not being enforced on the "
                          "endpoint and the platform does not claim it is")}

    bindings = exclusion.get("policy_version_bindings") or []
    applied_policy = endpoint_policy_state.get("assigned_policy_id")
    applied_version = endpoint_policy_state.get("applied_version")
    confirmed = endpoint_policy_state.get("confirmed_by_endpoint")
    carried = any(b.get("policy_id") == applied_policy
                  and int(b.get("version") or -1) == int(applied_version or -2)
                  for b in bindings)
    if not (confirmed and carried):
        return {"truth_state": TruthState.EXCLUSION_PENDING_POLICY.value,
                "enforcement_point": EnforcementPoint.ENDPOINT.value,
                "engine": engine,
                "basis": ("no policy version carrying this exclusion has "
                          "been acknowledged as applied by the endpoint, so "
                          "it is not being enforced there yet")}

    count = int((enforcement or {}).get("honoured_count") or 0)
    if count > 0:
        return {"truth_state": TruthState.ENDPOINT_EXCLUSION_APPLIED.value,
                "enforcement_point": EnforcementPoint.ENDPOINT.value,
                "engine": engine, "honoured_count": count,
                "matched_attribute": (enforcement or {}).get(
                    "matched_attribute"),
                "first_at": (enforcement or {}).get("first_at"),
                "last_at": (enforcement or {}).get("last_at"),
                "evaluator_version": (enforcement or {}).get(
                    "evaluator_version"),
                "basis": (f"the endpoint reported that its {engine} engine "
                          f"enforced this exclusion {count} time(s) while "
                          f"running policy {applied_policy} "
                          f"v{applied_version}; the matching evidence was "
                          "never delivered to the platform")}
    return {"truth_state":
            TruthState.ENDPOINT_EXCLUSION_ACTIVE_NO_MATCH_YET.value,
            "enforcement_point": EnforcementPoint.ENDPOINT.value,
            "engine": engine, "honoured_count": 0,
            "basis": ("the endpoint applied the policy version carrying this "
                      "exclusion and its engine is consulting it, but nothing "
                      "has matched yet — so nothing has been enforced and "
                      "APPLIED would be a claim without evidence")}
