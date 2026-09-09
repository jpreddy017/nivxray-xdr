"""
NivXRay XDR — Engine Binding & Security State Bridge.
Resolves engine capability contracts:
ENGINE -> CAPABILITY -> SUPPORTED CONTENT -> EXECUTION PATH -> VALIDATION -> READY
and connects validated detections to Causal Security State contextualization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..canonical_ir.models import CanonicalIR
try:
    from security_state.detection_bridge import CapabilityAbuseState, SecurityStateDetectionBridge
except Exception:
    from ...security_state.detection_bridge import CapabilityAbuseState, SecurityStateDetectionBridge


class BindingStatus(str, Enum):
    COMPATIBLE      = "COMPATIBLE"
    ENGINE_UNBOUND  = "ENGINE_UNBOUND"
    UNSUPPORTED     = "UNSUPPORTED"


@dataclass
class EngineBindingReport:
    content_id: str
    status: BindingStatus
    bound_engine_id: Optional[str] = None
    engine_role: str = ""
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content_id": self.content_id,
            "status": self.status.value,
            "bound_engine_id": self.bound_engine_id,
            "engine_role": self.engine_role,
            "reasons": self.reasons,
        }


class EngineBindingBridge:
    """Evaluates engine compatibility and binds CanonicalIR to verified runtime engines."""

    NATIVE_SIGMA_ENGINE = "nivxray::detection_content::nivxray_native_sigma"
    ENTERPRISE_LIBRARY_ENGINE = "nivxray::detection_content::enterprise_library"
    CORRELATION_ENGINE = "nivxray::xdr::correlation"

    VERIFIED_ENGINES = frozenset({
        "nivxray::detection_content::nivxray_native_sigma",
        "nivxray::detection_content::enterprise_library",
        "nivxray::xdr::correlation",
    })

    @classmethod
    def resolve_binding(
        cls,
        ir: CanonicalIR,
        target_engine_id: Optional[str] = None,
        available_contracts: Optional[List[Dict[str, Any]]] = None,
    ) -> EngineBindingReport:
        # 1. Check fidelity and promotability - fail closed on partial/approximate/unsupported
        if not ir.is_promotable():
            return EngineBindingReport(
                content_id=ir.content_id,
                status=BindingStatus.UNSUPPORTED,
                reasons=[f"Rule fidelity '{ir.fidelity.value}' has fatal unsupported constructs or is not promotable"],
            )

        # 2. Check for missing required telemetry
        if not ir.required_fields:
            return EngineBindingReport(
                content_id=ir.content_id,
                status=BindingStatus.ENGINE_UNBOUND,
                reasons=["Rule specifies zero required telemetry fields (missing required telemetry)"],
            )

        # 3. Check explicit target engine if provided
        if target_engine_id:
            # Check against provided contracts if passed
            if available_contracts is not None:
                matched_contract = next((c for c in available_contracts if c.get("engine_id") == target_engine_id), None)
                if not matched_contract:
                    return EngineBindingReport(
                        content_id=ir.content_id,
                        status=BindingStatus.ENGINE_UNBOUND,
                        reasons=[f"Target engine '{target_engine_id}' is unknown in active engine registry"],
                    )
                if matched_contract.get("contract_status") not in ("EXECUTION_VERIFIED", "RUNTIME_VERIFIED"):
                    return EngineBindingReport(
                        content_id=ir.content_id,
                        status=BindingStatus.ENGINE_UNBOUND,
                        reasons=[f"Target engine '{target_engine_id}' is unverified / not verified (status={matched_contract.get('contract_status')})"],
                    )
                if matched_contract.get("enabled") is False or matched_contract.get("status") == "DISABLED":
                    return EngineBindingReport(
                        content_id=ir.content_id,
                        status=BindingStatus.ENGINE_UNBOUND,
                        reasons=[f"Target engine '{target_engine_id}' is disabled"],
                    )
            elif target_engine_id not in cls.VERIFIED_ENGINES:
                return EngineBindingReport(
                    content_id=ir.content_id,
                    status=BindingStatus.ENGINE_UNBOUND,
                    reasons=[f"Target engine '{target_engine_id}' is unverified or unknown"],
                )

        # 4. Multi-event or Sequence/Aggregation -> Correlation Engine
        if ir.is_correlation or any("count" in f.lower() for f in ir.required_fields):
            # Verify no unsupported correlation/aggregation constructs
            unsupported_aggs = [u for u in ir.unsupported_constructs if "aggregation" in u.construct_name.lower() or "correlation" in u.construct_name.lower()]
            if unsupported_aggs:
                return EngineBindingReport(
                    content_id=ir.content_id,
                    status=BindingStatus.UNSUPPORTED,
                    reasons=[f"Unsupported aggregation or correlation construct: {unsupported_aggs[0].explanation}"],
                )
            return EngineBindingReport(
                content_id=ir.content_id,
                status=BindingStatus.COMPATIBLE,
                bound_engine_id=target_engine_id or cls.CORRELATION_ENGINE,
                engine_role="CORRELATION_ENGINE",
                reasons=["Binds to 13-operator stateful streaming Correlation Engine"],
            )

        # 5. Single-event atomic detection
        supported_domains = {
            "process.name", "process.command_line", "process.parent_name",
            "image", "command_line", "parent_image",
            "identity.principal_id", "user_id", "host.hostname",
            "network.src_ip", "network.dest_ip", "network.dest_port",
            "cloud.action", "file.path", "registry.path", "source_event_id",
        }

        req_set = set(ir.required_fields)
        if req_set and req_set.issubset(supported_domains):
            return EngineBindingReport(
                content_id=ir.content_id,
                status=BindingStatus.COMPATIBLE,
                bound_engine_id=target_engine_id or cls.ENTERPRISE_LIBRARY_ENGINE,
                engine_role="DETECTION_ENGINE",
                reasons=["Matches verified detection execution contract consumes semantic domain"],
            )

        # 6. If required fields exceed verified engine capability (unknown fields)
        return EngineBindingReport(
            content_id=ir.content_id,
            status=BindingStatus.ENGINE_UNBOUND,
            reasons=[f"Declared telemetry fields '{req_set - supported_domains}' not covered by active engine contracts"],
        )


class SecurityStateBridgeIntegration:
    """Connects CanonicalIR detections to Causal Security State contextual discrimination."""

    def __init__(self):
        self._bridge = SecurityStateDetectionBridge()

    def contextualize(
        self,
        ir: CanonicalIR,
        match_event: Dict[str, Any],
        user_id: str = "",
        host_id: str = "",
        crown_jewels: Optional[List[str]] = None,
        reachability_paths: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        detection_dict = {
            "rule_id": ir.content_id,
            "name": ir.name,
            "severity": ir.severity,
            "confidence": ir.confidence,
        }
        assessment = self._bridge.assess_detection(
            detection=detection_dict,
            host_id=host_id or match_event.get("host_id", ""),
            user_id=user_id or match_event.get("user_id", ""),
            crown_jewel_hosts=crown_jewels,
            reachability_paths=reachability_paths,
        )
        return assessment.to_dict()
