"""Contracts 11 & 12 · Capability Registry and Sensor Capability Registry.

Directive §14: *never hide incomplete state.* This registry is the truth
authority for NivXForge EDR capability status, and the owner-locked rule
it enforces is:

    No capability is considered implemented merely because a route, UI
    component, stub, simulator, or contract exists.

That rule is not advice here — `Capability.declared_state` is validated
against the evidence fields, so a row cannot claim `OPERATIONAL` while its
telemetry status says MISSING or its e2e status says absent. The registry
downgrades the claim and records why.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Plane(str, Enum):
    """Directive §4."""
    AGENT = "AGENT"                # Plane A · endpoint-resident
    BACKEND = "BACKEND"            # Plane B · EDR cloud/backend
    EXPERIENCE = "EXPERIENCE"      # Plane C · analyst/administrator


class FeatureState(str, Enum):
    """Directive §14, in ascending order of proof. `ORDER` below is what
    makes 'downgrade to the weakest supported claim' computable."""
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    CONTRACT_DEFINED = "CONTRACT_DEFINED"
    BACKEND_IMPLEMENTED = "BACKEND_IMPLEMENTED"
    UI_IMPLEMENTED = "UI_IMPLEMENTED"
    SYNTHETIC_VALIDATED = "SYNTHETIC_VALIDATED"
    GOLDEN_CORPUS_VALIDATED = "GOLDEN_CORPUS_VALIDATED"
    REAL_ENDPOINT_VALIDATED = "REAL_ENDPOINT_VALIDATED"
    END_TO_END_VALIDATED = "END_TO_END_VALIDATED"
    OPERATIONAL = "OPERATIONAL"
    PRODUCTION_READY = "PRODUCTION_READY"


FEATURE_ORDER: tuple[FeatureState, ...] = (
    FeatureState.NOT_IMPLEMENTED, FeatureState.CONTRACT_DEFINED,
    FeatureState.BACKEND_IMPLEMENTED, FeatureState.UI_IMPLEMENTED,
    FeatureState.SYNTHETIC_VALIDATED, FeatureState.GOLDEN_CORPUS_VALIDATED,
    FeatureState.REAL_ENDPOINT_VALIDATED, FeatureState.END_TO_END_VALIDATED,
    FeatureState.OPERATIONAL, FeatureState.PRODUCTION_READY,
)

#: States that assert the capability actually WORKS against a real
#: endpoint. Claiming any of these requires real-endpoint evidence.
FEATURE_REQUIRES_REAL_ENDPOINT = frozenset({
    FeatureState.REAL_ENDPOINT_VALIDATED, FeatureState.END_TO_END_VALIDATED,
    FeatureState.OPERATIONAL, FeatureState.PRODUCTION_READY,
})


class GapClass(str, Enum):
    """Directive §14 — WHY a capability is not operational."""
    NONE = "NONE"
    UI_ONLY = "UI_ONLY"
    BACKEND_ONLY = "BACKEND_ONLY"
    SCAFFOLD = "SCAFFOLD"
    TELEMETRY_MISSING = "TELEMETRY_MISSING"
    CONTROL_DRIVER_MISSING = "CONTROL_DRIVER_MISSING"
    CONTRACT_MISSING = "CONTRACT_MISSING"
    OWNER_INPUT_PENDING = "OWNER_INPUT_PENDING"


class ComponentStatus(str, Enum):
    ABSENT = "ABSENT"
    STUB = "STUB"
    PARTIAL = "PARTIAL"
    PRESENT = "PRESENT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Capability(BaseModel):
    """One row of the EDR honesty baseline."""
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    capability_id: str
    plane: Plane
    domain: str
    name: str
    description: str

    declared_state: FeatureState = FeatureState.NOT_IMPLEMENTED
    gap_class: GapClass = GapClass.NONE

    contract_status: ComponentStatus = ComponentStatus.ABSENT
    backend_status: ComponentStatus = ComponentStatus.ABSENT
    ui_status: ComponentStatus = ComponentStatus.ABSENT
    telemetry_status: ComponentStatus = ComponentStatus.ABSENT
    control_driver_status: ComponentStatus = ComponentStatus.NOT_APPLICABLE
    test_status: ComponentStatus = ComponentStatus.ABSENT
    e2e_status: ComponentStatus = ComponentStatus.ABSENT

    evidence_reference: Optional[str] = Field(
        default=None,
        description="File path, route, test file or report that PROVES the "
                    "declared state. A state with no evidence reference is "
                    "downgraded.")
    honest_note: Optional[str] = None
    last_verified: Optional[str] = None
    wave: Optional[str] = None

    # Populated by the validator; never supplied by the author.
    effective_state: FeatureState = FeatureState.NOT_IMPLEMENTED
    downgrade_reason: Optional[str] = None

    @model_validator(mode="after")
    def _downgrade_unproven_claims(self):
        declared = FeatureState(self.declared_state)
        eff, why = declared, None

        def cap(to: FeatureState, reason: str):
            nonlocal eff, why
            if FEATURE_ORDER.index(to) < FEATURE_ORDER.index(eff):
                eff, why = to, reason

        if declared in FEATURE_REQUIRES_REAL_ENDPOINT:
            if ComponentStatus(self.telemetry_status) in (
                    ComponentStatus.ABSENT, ComponentStatus.STUB):
                cap(FeatureState.BACKEND_IMPLEMENTED,
                    "claims real-endpoint validation but telemetry_status is "
                    f"{self.telemetry_status}; there is no endpoint evidence "
                    "to validate against")
            if ComponentStatus(self.e2e_status) in (
                    ComponentStatus.ABSENT, ComponentStatus.STUB):
                cap(FeatureState.BACKEND_IMPLEMENTED,
                    "claims end-to-end state but e2e_status is "
                    f"{self.e2e_status}")
        if (declared != FeatureState.NOT_IMPLEMENTED
                and ComponentStatus(self.backend_status) in (
                    ComponentStatus.ABSENT, ComponentStatus.STUB)
                and ComponentStatus(self.ui_status) == ComponentStatus.PRESENT):
            # A CLASSIFICATION, not a level: the UI genuinely is built, so
            # UI_IMPLEMENTED is the true state even though it sits higher in
            # FEATURE_ORDER. Claiming BACKEND_IMPLEMENTED with no backend is
            # the false statement; this replaces it outright.
            eff = FeatureState.UI_IMPLEMENTED
            why = ("UI exists without a backing backend — directive §14 "
                   "UI_ONLY. The surface is real; the capability is not.")
        if (FEATURE_ORDER.index(declared)
                >= FEATURE_ORDER.index(FeatureState.BACKEND_IMPLEMENTED)
                and not self.evidence_reference):
            cap(FeatureState.CONTRACT_DEFINED,
                "no evidence_reference; a claim without evidence is not a "
                "claim we are allowed to publish")

        self.effective_state = eff
        self.downgrade_reason = why

        if self.gap_class == GapClass.NONE and eff not in (
                FeatureState.OPERATIONAL, FeatureState.PRODUCTION_READY,
                FeatureState.END_TO_END_VALIDATED):
            if (ComponentStatus(self.ui_status) == ComponentStatus.PRESENT
                    and ComponentStatus(self.backend_status) in (
                        ComponentStatus.ABSENT, ComponentStatus.STUB)):
                # Most specific first: a live-looking surface with nothing
                # behind it is the most misleading gap, so it wins.
                self.gap_class = GapClass.UI_ONLY
            elif ComponentStatus(self.telemetry_status) == ComponentStatus.ABSENT:
                self.gap_class = GapClass.TELEMETRY_MISSING
            elif ComponentStatus(self.control_driver_status) == (
                    ComponentStatus.ABSENT):
                self.gap_class = GapClass.CONTROL_DRIVER_MISSING
        if not self.last_verified:
            self.last_verified = datetime.now(timezone.utc).date().isoformat()
        return self

    @property
    def is_operational(self) -> bool:
        return FeatureState(self.effective_state) in (
            FeatureState.OPERATIONAL, FeatureState.PRODUCTION_READY)

    @property
    def claim_is_honest(self) -> bool:
        return self.downgrade_reason is None


class SensorCapability(BaseModel):
    """Contract 12 · what a given sensor on a given platform can actually
    produce.

    This is the boundary object of directive §4: the backend cannot pretend
    to be a kernel sensor, so it must ASK. A field absent from
    `collects` resolves to `NOT_SUPPORTED`, never `NOT_OBSERVED` — the
    difference between "this platform cannot tell us" and "it told us
    nothing happened".
    """
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    sensor_id: str
    platform: str
    sensor_version: str
    collects: list[str] = Field(
        default_factory=list,
        description="ActivityType values this sensor emits.")
    fields_supported: list[str] = Field(
        default_factory=list,
        description="Dotted evidence paths, e.g. 'process.sha256'.")
    response_actions: list[str] = Field(
        default_factory=list,
        description="ResponseAction values this sensor can execute. Empty "
                    "means every action is ⊘ DRIVER NOT REGISTERED.")
    attested_at: Optional[str] = None
    attested_by: Optional[str] = Field(
        default=None,
        description="Who declared this. A capability the sensor claims but "
                    "has never demonstrated stays unattested.")

    def supports_field(self, dotted: str) -> bool:
        return dotted in self.fields_supported

    def epistemic_for(self, dotted: str) -> str:
        """The honest state for a field this sensor cannot produce."""
        return "OBSERVED" if self.supports_field(dotted) else "NOT_SUPPORTED"
