"""
NivXRay XDR — Multi-Tier Quality Validation Framework.
Implements Tier 1 (Structural), Tier 2 (Behavioral), and Tier 3 (Runtime/Regression) validation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..canonical_ir.models import CanonicalIR, TranslationFidelity
from .gates import GateResult, ValidationGates


class ValidationTier(str, Enum):
    TIER_1_STRUCTURAL = "TIER_1_STRUCTURAL"
    TIER_2_BEHAVIORAL = "TIER_2_BEHAVIORAL"
    TIER_3_RUNTIME    = "TIER_3_RUNTIME"


@dataclass
class TierValidationReport:
    tier: ValidationTier
    content_id: str
    passed: bool
    gate_results: List[GateResult] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier": self.tier.value,
            "content_id": self.content_id,
            "passed": self.passed,
            "blockers": self.blockers,
            "gates": [
                {
                    "name": g.gate_name,
                    "passed": g.passed,
                    "reasons": g.reasons,
                    "metrics": g.metrics,
                }
                for g in self.gate_results
            ],
        }


class QualityValidationFramework:

    @staticmethod
    def validate_tier_1(
        ir: CanonicalIR,
        positive_fixture: Optional[Dict[str, Any]] = None,
        negative_fixture: Optional[Dict[str, Any]] = None,
    ) -> TierValidationReport:
        """Tier 1: Structural completeness, license legality, provenance, and 1 pos + 1 neg fixture."""
        gates = [
            ValidationGates.check_schema(ir),
            ValidationGates.check_license_provenance(ir),
            ValidationGates.check_fixtures(ir, positive_fixture, negative_fixture),
        ]
        failed = [g.gate_name for g in gates if not g.passed]
        blockers = [r for g in gates if not g.passed for r in g.reasons]
        return TierValidationReport(
            tier=ValidationTier.TIER_1_STRUCTURAL,
            content_id=ir.content_id,
            passed=(len(failed) == 0),
            gate_results=gates,
            blockers=blockers,
        )

    @staticmethod
    def validate_tier_2(
        ir: CanonicalIR,
        positive_fixture: Dict[str, Any],
        negative_fixture: Dict[str, Any],
    ) -> TierValidationReport:
        """Tier 2: Tier 1 + Telemetry mapping, determinism, and fidelity check."""
        t1 = QualityValidationFramework.validate_tier_1(ir, positive_fixture, negative_fixture)
        gates = list(t1.gate_results)

        # Fidelity gate
        if ir.fidelity == TranslationFidelity.UNSUPPORTED or any(u.fatal for u in ir.unsupported_constructs):
            gates.append(
                GateResult("fidelity", False, [f"Fidelity '{ir.fidelity.value}' has fatal unsupported constructs"])
            )
        else:
            gates.append(GateResult("fidelity", True, [f"Translation fidelity is {ir.fidelity.value}"]))

        # Telemetry gate
        gates.append(ValidationGates.check_telemetry(ir))

        # Determinism gate
        gates.append(ValidationGates.check_determinism(ir, positive_fixture))

        failed = [g.gate_name for g in gates if not g.passed]
        blockers = [r for g in gates if not g.passed for r in g.reasons]
        return TierValidationReport(
            tier=ValidationTier.TIER_2_BEHAVIORAL,
            content_id=ir.content_id,
            passed=(len(failed) == 0),
            gate_results=gates,
            blockers=blockers,
        )

    @staticmethod
    def validate_tier_3(
        ir: CanonicalIR,
        positive_fixture: Dict[str, Any],
        negative_fixture: Dict[str, Any],
    ) -> TierValidationReport:
        """Tier 3: Tier 2 + Performance benchmark (< 5.0ms) and tenant isolation."""
        t2 = QualityValidationFramework.validate_tier_2(ir, positive_fixture, negative_fixture)
        gates = list(t2.gate_results)

        # Performance gate
        gates.append(ValidationGates.check_performance(ir, positive_fixture))

        # Tenant isolation gate
        gates.append(ValidationGates.check_tenant_isolation(ir, positive_fixture, "tenant-staging-02"))

        failed = [g.gate_name for g in gates if not g.passed]
        blockers = [r for g in gates if not g.passed for r in g.reasons]
        return TierValidationReport(
            tier=ValidationTier.TIER_3_RUNTIME,
            content_id=ir.content_id,
            passed=(len(failed) == 0),
            gate_results=gates,
            blockers=blockers,
        )
