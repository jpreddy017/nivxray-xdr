"""COMPROMISE / IOC CONTRIBUTOR CONTRACT (server-side, evidence only).

The architectural distinction this module exists to enforce:

    event.kind     = WHAT WAS OBSERVED
    detection      = WHAT A DETECTION ENGINE CONCLUDED
    compromise     = WHAT AN AUTHORITATIVE CORRELATION / IOC MECHANISM
                     CONCLUDED
    response state = WHAT RESPONSE ACTUALLY DID

A compromise is therefore never a telemetry kind and never a rendering
decision. Contributor membership must be STATED BY the authority that
raised the compromise. It is never inferred from temporal proximity, the
same PID, the same process name, the same lane, adjacency on screen, or
anything else a client can observe about layout.

If an authority raised a compromise but named no contributors, that is
recorded as `CONTRIBUTORS_NOT_PROVEN_BY_AUTHORITY` and the consumer must
render NO contributor emphasis. An honest absence beats a plausible guess.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ── Authorities allowed to raise a compromise ───────────────────────
#: The authoritative detection derivation recorded against the raw event
#: (`Derivation.outcome == "DETECTION_MATCHED"`).
AUTHORITY_DETECTION_FABRIC = "DETECTION_FABRIC_ATTRIBUTION"
#: The observation's OWN MITRE technique attribution, as persisted on the
#: canonical evidence (`event.mitre`).
AUTHORITY_MITRE_EVIDENCE = "MITRE_ATTRIBUTED_EVIDENCE"
#: The incident correlation engine, when it names its own members.
AUTHORITY_IOC_CORRELATION = "IOC_CORRELATION_ENGINE"

AUTHORITIES: frozenset[str] = frozenset({
    AUTHORITY_DETECTION_FABRIC, AUTHORITY_MITRE_EVIDENCE,
    AUTHORITY_IOC_CORRELATION,
})

#: Contributor bases that are NOT evidence. Rejected at construction so a
#: guess can never be persisted, shipped or rendered as provenance.
FORBIDDEN_BASES: frozenset[str] = frozenset({
    "TEMPORAL_PROXIMITY", "NEAR_IN_TIME", "SAME_TIME_BIN",
    "SAME_PID", "PID_SURROGATE", "SAME_PROCESS_NAME", "SAME_IMAGE_NAME",
    "SAME_LANE", "SAME_DEVICE", "SAME_TENANT",
    "UI_PROXIMITY", "ADJACENT_IN_RENDER", "VISUALLY_NEARBY",
    "SAME_FILE_PATH_GUESS", "ANALYST_ASSUMPTION", "HEURISTIC",
    "INFERRED", "ASSUMED", "GUESS",
})

CONTRIBUTORS_PROVEN = "CONTRIBUTORS_PROVEN_BY_AUTHORITY"
CONTRIBUTORS_NOT_PROVEN = "CONTRIBUTORS_NOT_PROVEN_BY_AUTHORITY"

_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
_TACTIC = re.compile(r"^TA\d{4}$")


class CompromiseContractError(ValueError):
    """A refusal with a machine code, so a caller cannot ignore it."""

    def __init__(self, code: str, reason: str):
        self.code, self.reason = code, reason
        super().__init__(f"{code}: {reason}")


def _clean(value: Any) -> str:
    return str(value).strip() if value not in (None, "") else ""


def _check_basis(basis: str, *, code: str) -> str:
    text = _clean(basis)
    if not text:
        raise CompromiseContractError(
            code, "a basis is required: an unexplained claim is not evidence")
    if text.upper() in FORBIDDEN_BASES:
        raise CompromiseContractError(
            code,
            f"{text!r} is not evidence of contribution. Contributor "
            f"membership must be STATED BY the authority that raised the "
            f"compromise, never inferred from proximity, identity "
            f"surrogates or layout")
    return text


@dataclass(frozen=True)
class ContributingEventRef:
    """ONE observation the authority itself named as contributing.

    `stated_by` is the authority that named it, and it must be the SAME
    authority that raised the compromise — a contributor cannot be
    imported from a different mechanism's opinion.
    """
    event_iid: str
    contribution_basis: str
    stated_by: str
    evidence_ref: str | None = None

    def __post_init__(self) -> None:
        if not _clean(self.event_iid):
            raise CompromiseContractError(
                "CONTRIBUTOR_EVENT_IID_REQUIRED",
                "a contributor must reference an existing observation")
        if _clean(self.stated_by) not in AUTHORITIES:
            raise CompromiseContractError(
                "CONTRIBUTOR_AUTHORITY_INVALID",
                f"stated_by must be one of {sorted(AUTHORITIES)}")
        _check_basis(self.contribution_basis,
                     code="CONTRIBUTOR_BASIS_FORBIDDEN")

    def to_dict(self) -> dict[str, Any]:
        out = {"event_iid": self.event_iid,
               "contribution_basis": self.contribution_basis,
               "stated_by": self.stated_by}
        if self.evidence_ref:
            out["evidence_ref"] = self.evidence_ref
        return out


@dataclass(frozen=True)
class CompromiseEvent:
    """A compromise, and the proof of who said so and on what evidence."""
    compromise_event_id: str
    indicator_id: str
    authority: str
    derivation_basis: str
    description: str
    contributing_event_refs: tuple[ContributingEventRef, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    observed_at: str | None = None
    contributors_state: str = field(default=CONTRIBUTORS_PROVEN)

    def __post_init__(self) -> None:
        if not _clean(self.compromise_event_id):
            raise CompromiseContractError(
                "COMPROMISE_ID_REQUIRED", "a compromise needs an identity")
        if not _clean(self.indicator_id):
            raise CompromiseContractError(
                "INDICATOR_ID_REQUIRED",
                "a compromise must name the indicator it was raised on")
        if _clean(self.authority) not in AUTHORITIES:
            raise CompromiseContractError(
                "COMPROMISE_AUTHORITY_INVALID",
                f"authority must be one of {sorted(AUTHORITIES)}; a "
                f"telemetry kind is not an authority")
        _check_basis(self.derivation_basis,
                     code="COMPROMISE_BASIS_FORBIDDEN")
        if not _clean(self.description):
            raise CompromiseContractError(
                "COMPROMISE_DESCRIPTION_REQUIRED",
                "a compromise must state what was concluded")
        if self.contributors_state not in (CONTRIBUTORS_PROVEN,
                                           CONTRIBUTORS_NOT_PROVEN):
            raise CompromiseContractError(
                "CONTRIBUTORS_STATE_INVALID",
                "contributors_state must be PROVEN or NOT_PROVEN")
        seen: set[str] = set()
        for ref in self.contributing_event_refs:
            if not isinstance(ref, ContributingEventRef):
                raise CompromiseContractError(
                    "CONTRIBUTOR_TYPE_INVALID",
                    "contributors must be ContributingEventRef instances, "
                    "so every one of them is validated")
            if ref.stated_by != self.authority:
                raise CompromiseContractError(
                    "CONTRIBUTOR_AUTHORITY_MISMATCH",
                    f"contributor {ref.event_iid!r} was named by "
                    f"{ref.stated_by!r} but this compromise was raised by "
                    f"{self.authority!r}")
            if ref.event_iid in seen:
                raise CompromiseContractError(
                    "CONTRIBUTOR_DUPLICATE",
                    f"{ref.event_iid!r} is listed more than once")
            seen.add(ref.event_iid)
        if self.contributors_state == CONTRIBUTORS_PROVEN \
                and not self.contributing_event_refs:
            raise CompromiseContractError(
                "CONTRIBUTORS_CLAIMED_BUT_ABSENT",
                "contributors cannot be PROVEN and empty; use "
                "CONTRIBUTORS_NOT_PROVEN_BY_AUTHORITY so the consumer "
                "renders no contributor emphasis")
        if self.contributors_state == CONTRIBUTORS_NOT_PROVEN \
                and self.contributing_event_refs:
            raise CompromiseContractError(
                "CONTRIBUTORS_PRESENT_BUT_DISCLAIMED",
                "contributors are listed, so they are proven; do not "
                "disclaim them")
        for tactic in self.tactics:
            if not _TACTIC.match(_clean(tactic)):
                raise CompromiseContractError(
                    "TACTIC_INVALID",
                    f"{tactic!r} is not a MITRE tactic id (TAnnnn)")
        for technique in self.techniques:
            if not _TECHNIQUE.match(_clean(technique)):
                raise CompromiseContractError(
                    "TECHNIQUE_INVALID",
                    f"{technique!r} is not a MITRE technique id "
                    f"(Tnnnn[.nnn])")

    def to_dict(self) -> dict[str, Any]:
        return {
            "compromise_event_id": self.compromise_event_id,
            "indicator_id": self.indicator_id,
            "authority": self.authority,
            "derivation_basis": self.derivation_basis,
            "description": self.description,
            "contributors_state": self.contributors_state,
            "contributing_event_refs": [r.to_dict() for r
                                        in self.contributing_event_refs],
            "evidence_refs": list(self.evidence_refs),
            "tactics": list(self.tactics),
            "techniques": list(self.techniques),
            "observed_at": self.observed_at,
        }


def from_detection_derivation(derivation: dict[str, Any], *,
                              observation_iid: str,
                              observed_at: str | None = None,
                              techniques: tuple[str, ...] = (),
                              ) -> CompromiseEvent:
    """Build a compromise from an AUTHORITATIVE detection derivation.

    The only contributors admitted are the ones the derivation itself
    names: the observation the detection was raised on, plus any
    `evidence_ids` the derivation recorded. Nothing is added, and when the
    derivation names nothing beyond its own observation that single
    contributor is exactly what is returned — never a widened set.
    """
    if str(derivation.get("outcome") or "") != "DETECTION_MATCHED":
        raise CompromiseContractError(
            "NOT_A_DETECTION_ATTRIBUTION",
            "only a DETECTION_MATCHED derivation is an authority for a "
            "compromise; NOT_EVALUATED and NO_MATCH are not")
    if not _clean(observation_iid):
        raise CompromiseContractError(
            "CONTRIBUTOR_EVENT_IID_REQUIRED",
            "the observation the detection was raised on is required")
    indicator = (_clean(derivation.get("detection_content_version"))
                 or _clean(derivation.get("event_id")))
    if not indicator:
        raise CompromiseContractError(
            "INDICATOR_ID_REQUIRED",
            "the derivation named neither its detection content nor its "
            "canonical event, so what raised this compromise is unknown")
    named = [observation_iid] + [
        _clean(e) for e in (derivation.get("evidence_ids") or ())
        if _clean(e) and _clean(e) != _clean(observation_iid)]
    refs = tuple(
        ContributingEventRef(
            event_iid=iid,
            contribution_basis=(
                "DETECTION_DERIVATION_SUBJECT_OBSERVATION"
                if iid == observation_iid
                else "DETECTION_DERIVATION_NAMED_EVIDENCE_ID"),
            stated_by=AUTHORITY_DETECTION_FABRIC,
            evidence_ref=_clean(derivation.get("event_id")) or None)
        for iid in named)
    return CompromiseEvent(
        compromise_event_id=f"cmp_{indicator}:{observation_iid}",
        indicator_id=indicator,
        authority=AUTHORITY_DETECTION_FABRIC,
        derivation_basis="DETECTION_FABRIC_DERIVATION_ON_RAW_EVENT",
        description=(_clean(derivation.get("reason"))
                     or "the detection fabric matched this observation"),
        contributing_event_refs=refs,
        evidence_refs=tuple(_clean(e) for e in
                            (derivation.get("evidence_ids") or ()) if e),
        techniques=tuple(t for t in techniques if _clean(t)),
        observed_at=observed_at or _clean(derivation.get("derived_at")) or None,
    )


def from_mitre_attributed_evidence(*, observation_iid: str,
                                   techniques: tuple[str, ...],
                                   observed_at: str | None = None,
                                   ) -> CompromiseEvent:
    """A compromise carried by the observation's OWN MITRE attribution.

    This authority speaks for exactly one observation, so it can prove
    exactly one contributor. Any wider contributor set would be invention,
    and the contract has no way to express it.
    """
    techs = tuple(_clean(t) for t in techniques if _clean(t))
    if not techs:
        raise CompromiseContractError(
            "MITRE_ATTRIBUTION_ABSENT",
            "this authority IS the technique attribution; without one "
            "there is no compromise to raise")
    return CompromiseEvent(
        compromise_event_id=f"cmp_mitre_{techs[0]}:{observation_iid}",
        indicator_id=techs[0],
        authority=AUTHORITY_MITRE_EVIDENCE,
        derivation_basis="OBSERVATION_OWN_MITRE_TECHNIQUE_ATTRIBUTION",
        description=("the observation's own evidence carries MITRE "
                     "technique attribution " + ", ".join(techs)),
        contributing_event_refs=(ContributingEventRef(
            event_iid=observation_iid,
            contribution_basis="MITRE_ATTRIBUTION_ON_THIS_OBSERVATION",
            stated_by=AUTHORITY_MITRE_EVIDENCE),),
        techniques=techs,
        observed_at=observed_at,
    )


def unproven_contributors(*, compromise_event_id: str, indicator_id: str,
                          authority: str, derivation_basis: str,
                          description: str,
                          observed_at: str | None = None,
                          ) -> CompromiseEvent:
    """A real compromise whose authority named NO contributing events.

    The compromise still exists and is still reported; only the
    contributor set is honestly absent, so a consumer must render no
    contributor emphasis rather than emphasise a plausible neighbour.
    """
    return CompromiseEvent(
        compromise_event_id=compromise_event_id,
        indicator_id=indicator_id,
        authority=authority,
        derivation_basis=derivation_basis,
        description=description,
        contributing_event_refs=(),
        contributors_state=CONTRIBUTORS_NOT_PROVEN,
        observed_at=observed_at,
    )
