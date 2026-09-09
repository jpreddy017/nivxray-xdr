"""Field-level epistemic enforcement — the Wave 0 foundation.

Directive §6 requires that every evidence field resolve to exactly one of
six states, and §7 requires four INDEPENDENT dimensions that may never be
collapsed. Directive §8 forbids inventing a value to fill a gap.

The rule this module makes UNBREAKABLE:

    An evidence field may be null ONLY if an explicit epistemic state
    says why it is null.

There is no path through this validator that yields a silent `None`. A
missing hash is `NOT_COLLECTED` with a reason, or it is a ValidationError.
That is the difference between "we did not observe it" and "there was
nothing to observe", and conflating them is exactly how a visibility gap
gets read as an all-clear.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EpistemicState(str, Enum):
    """Directive §6. The six — and only six — states an evidence field
    may resolve to."""
    OBSERVED = "OBSERVED"
    NOT_OBSERVED = "NOT_OBSERVED"
    NOT_COLLECTED = "NOT_COLLECTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    PARSER_FAILED = "PARSER_FAILED"
    UNKNOWN = "UNKNOWN"


#: The five states that mean "there is no value here". Only OBSERVED
#: carries a value. Used by the validator and by the UI to decide between
#: `◇ NO EVIDENCE` and `⊘ Not collected`.
EPISTEMIC_ABSENT = frozenset({
    EpistemicState.NOT_OBSERVED, EpistemicState.NOT_COLLECTED,
    EpistemicState.NOT_SUPPORTED, EpistemicState.PARSER_FAILED,
    EpistemicState.UNKNOWN,
})

#: Which glyph the console must render for each absent state. Directive §8.
EPISTEMIC_GLYPH = {
    EpistemicState.OBSERVED:      "",
    EpistemicState.NOT_OBSERVED:  "◇",   # no evidence
    EpistemicState.NOT_COLLECTED: "⊘",   # capability/source does not collect it
    EpistemicState.NOT_SUPPORTED: "⊘",   # this platform cannot produce it
    EpistemicState.PARSER_FAILED: "!",   # it arrived and we failed to read it
    EpistemicState.UNKNOWN:       "?",
}


# ── Directive §7 · four INDEPENDENT dimensions ────────────────────

class Verdict(str, Enum):
    BENIGN = "BENIGN"
    AUTHORIZED = "AUTHORIZED"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class EvidenceSufficiency(str, Enum):
    SUFFICIENT = "SUFFICIENT"
    PARTIAL = "PARTIAL"
    INSUFFICIENT = "INSUFFICIENT"
    CONFLICTING = "CONFLICTING"
    UNKNOWN = "UNKNOWN"


class TelemetryHealth(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    MISSING = "MISSING"
    PARSER_FAILED = "PARSER_FAILED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    STALE = "STALE"


class DetectionExecution(str, Enum):
    EVALUATED = "EVALUATED"
    MATCHED = "MATCHED"
    NO_MATCH = "NO_MATCH"
    PARTIALLY_EVALUATED = "PARTIALLY_EVALUATED"
    NOT_EVALUABLE = "NOT_EVALUABLE"
    DATA_MISSING = "DATA_MISSING"
    PARSER_FAILED = "PARSER_FAILED"


#: Directive §7 — the six inequalities that define this product. Held as
#: DATA so the test suite can assert them mechanically rather than trusting
#: that a future author remembered them.
FORBIDDEN_EQUIVALENCES: tuple[tuple[str, str, str], ...] = (
    ("DetectionExecution.NO_MATCH", "Verdict.BENIGN",
     "A rule that did not fire is not evidence of innocence."),
    ("DetectionExecution.NOT_EVALUABLE", "DetectionExecution.NO_MATCH",
     "A rule we could not run is not a rule that ran and found nothing."),
    ("DetectionExecution.DATA_MISSING", "Verdict.BENIGN",
     "Absent telemetry is a visibility gap, not an absence of attack."),
    ("DetectionExecution.PARSER_FAILED", "EpistemicState.NOT_OBSERVED",
     "An event that arrived and failed to parse DID occur."),
    ("Verdict.UNKNOWN", "Verdict.MALICIOUS",
     "Not knowing is not the same as convicting."),
    ("Verdict.AUTHORIZED", "Verdict.BENIGN",
     "Authorised means permitted by policy, not proven harmless."),
)


def evidence_field(default: Any = None, **kwargs: Any) -> Any:
    """Declare a field as EVIDENCE, subjecting it to §6 enforcement.

    A field declared this way cannot be null unless `field_states` names
    its epistemic state. Non-evidence fields (identifiers, timestamps,
    bookkeeping) are exempt because they are facts about the record, not
    claims about the endpoint.
    """
    extra = dict(kwargs.pop("json_schema_extra", None) or {})
    extra["nivxforge_evidence"] = True
    return Field(default, json_schema_extra=extra, **kwargs)


class EvidenceModel(BaseModel):
    """Base for every contract that carries claims about an endpoint."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True,
                              populate_by_name=True)

    field_states: dict[str, EpistemicState] = Field(
        default_factory=dict,
        description="Epistemic state per evidence field. Mandatory for any "
                    "evidence field that is null.")
    field_state_reasons: dict[str, str] = Field(
        default_factory=dict,
        description="Human reason per absent field, e.g. 'CEF carries no "
                    "parent-process field in either specification'. This is "
                    "what the console renders after '⊘ Not collected'.")

    @classmethod
    def evidence_fields(cls) -> tuple[str, ...]:
        out = []
        for name, f in cls.model_fields.items():
            extra = getattr(f, "json_schema_extra", None) or {}
            if isinstance(extra, dict) and extra.get("nivxforge_evidence"):
                out.append(name)
        return tuple(out)

    @model_validator(mode="after")
    def _enforce_epistemic_states(self):
        missing: list[str] = []
        for name in self.evidence_fields():
            declared = self.field_states.get(name)
            if getattr(self, name, None) is None:
                if declared is None:
                    missing.append(name)
                elif EpistemicState(declared) == EpistemicState.OBSERVED:
                    raise ValueError(
                        f"field '{name}' is null but declared OBSERVED. "
                        f"OBSERVED asserts a value exists.")
            elif declared is None:
                # A present value is self-evidently observed. Record it so
                # downstream consumers never have to infer.
                self.field_states[name] = EpistemicState.OBSERVED
        if missing:
            raise ValueError(
                f"{type(self).__name__}: evidence field(s) {sorted(missing)} "
                f"are null with no epistemic state. Directive §8 forbids a "
                f"silent gap — declare NOT_OBSERVED / NOT_COLLECTED / "
                f"NOT_SUPPORTED / PARSER_FAILED / UNKNOWN and say why.")
        return self

    def state_of(self, field: str) -> EpistemicState:
        return EpistemicState(self.field_states.get(field,
                                                    EpistemicState.UNKNOWN))

    def is_observed(self, field: str) -> bool:
        return self.state_of(field) == EpistemicState.OBSERVED

    def presentation(self, field: str) -> dict[str, Any]:
        """What the console should render for one field — value, or glyph
        plus reason. Never an empty string, never a bare dash."""
        st = self.state_of(field)
        if st == EpistemicState.OBSERVED:
            return {"state": st.value, "value": getattr(self, field, None),
                    "glyph": "", "reason": None}
        return {"state": st.value, "value": None,
                "glyph": EPISTEMIC_GLYPH[st],
                "reason": self.field_state_reasons.get(
                    field, f"declared {st.value}; no reason recorded")}


def absent(field_map: dict[str, tuple[EpistemicState, str]]
           ) -> dict[str, Any]:
    """Helper for constructing a contract whose fields are honestly absent.

    ``absent({"file_sha256": (EpistemicState.NOT_COLLECTED,
              "source does not hash file content")})``
    """
    return {
        "field_states": {k: v[0] for k, v in field_map.items()},
        "field_state_reasons": {k: v[1] for k, v in field_map.items()},
    }


class Provenance(BaseModel):
    """Directive §5 — every layer is additive and versioned."""
    model_config = ConfigDict(extra="forbid")

    source: str = Field(description="collector / sensor / adapter identity")
    sensor_version: Optional[str] = None
    parser_name: Optional[str] = None
    parser_version: Optional[str] = None
    normalizer_version: Optional[str] = None
    detection_content_version: Optional[str] = None
    analysis_version: Optional[str] = None
    verdict_version: Optional[str] = None
    replay_generation: int = Field(
        default=0,
        description="0 = original ingest. Incremented per replay so a "
                    "re-reasoned event never masquerades as a new one.")
    raw_ref: Optional[str] = Field(
        default=None,
        description="raw_id in edr_raw_events. The immutable original.")
