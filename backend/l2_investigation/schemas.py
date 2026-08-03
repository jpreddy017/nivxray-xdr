"""L2 shared schemas · Evidence input contract and Service output envelope.

Every L2 service consumes an ``EvidenceBundle`` and returns a
``ServiceOutput``. Both are dataclasses with deterministic dict + JSON
serialization (sort_keys, sorted lists), so hash-stability is trivial to
verify in tests.

The L2 layer does not construct EvidenceBundles from raw L0 output — L1
Evidence Services will do that in PR-2. For PR-1, tests build synthetic
bundles directly, which is enough to prove the L2 contract.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# --- L0 read-only import ---------------------------------------------------
# We touch only the ConvergenceCertificate dataclass. Nothing else in
# workspace.convergence is imported. This preserves the ARB frozen-engine
# contract: L2 reads downward through a stable data shape only.
from workspace.convergence.certificate import ConvergenceCertificate  # noqa: F401


# ---------------------------------------------------------------------------
# Evidence primitives (per Blueprint §8.4 Evidence Navigation Contract)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IocEvidence:
    """A single Indicator of Compromise with provenance to its source."""

    ioc_id: str            # deterministic id (sha256 of type+value)
    ioc_type: str          # "url" | "ip" | "domain" | "sha256" | "md5" | "email" | "filepath"
    value: str
    source_iteration: int  # iteration index in Convergence Certificate
    source_span: tuple[int, int] = (0, 0)  # (start, end) offsets in canonical output
    context: str = ""      # short surrounding-text snippet (deterministic)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "source_iteration": self.source_iteration,
            "source_span": list(self.source_span),
            "context": self.context,
        }


@dataclass(frozen=True)
class CapabilityEvidence:
    """A capability tag drawn from the Capability Vocabulary."""

    capability_id: str    # e.g. "PERSISTENCE.REG_RUN"
    display_name: str
    confidence: str = "high"  # "high" | "medium" | "low" — deterministic bucket
    source_iterations: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "display_name": self.display_name,
            "confidence": self.confidence,
            "source_iterations": list(self.source_iterations),
        }


@dataclass(frozen=True)
class MitreEvidence:
    """MITRE ATT&CK technique with mapping provenance."""

    technique_id: str      # e.g. "T1059.001"
    technique_name: str
    tactic: str            # e.g. "execution"
    via_capability: str    # capability_id that maps to this technique
    source_iterations: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "via_capability": self.via_capability,
            "source_iterations": list(self.source_iterations),
        }


@dataclass(frozen=True)
class TransformationEvidence:
    """One transformation applied during convergence."""

    iteration: int
    pass_name: str        # "structural" | "content" | "decoder" | "semantic"
    transformation: str   # transformation registry id
    changed: bool
    before_hash: str = ""
    after_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "iteration": self.iteration,
            "pass_name": self.pass_name,
            "transformation": self.transformation,
            "changed": self.changed,
            "before_hash": self.before_hash,
            "after_hash": self.after_hash,
        }


@dataclass(frozen=True)
class SampleMetadata:
    """Family / technique / variant identification for the case."""

    family: str = ""
    technique: str = ""
    variant: str = ""
    sample_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "technique": self.technique,
            "variant": self.variant,
            "sample_id": self.sample_id,
        }


# ---------------------------------------------------------------------------
# Evidence Bundle · L1 → L2 input contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceBundle:
    """The read-down input every L2 service consumes.

    A bundle is *evidence*, not presentation. It contains only what L1
    Evidence Services return from the deterministic L0 platform. L2
    services derive investigation content (summaries, stories, rules)
    from a bundle without any side-effects.
    """

    case_id: str
    certificate: dict[str, Any]  # ConvergenceCertificate.to_dict() output
    canonical_output: str
    transformations: tuple[TransformationEvidence, ...] = ()
    iocs: tuple[IocEvidence, ...] = ()
    capabilities: tuple[CapabilityEvidence, ...] = ()
    mitre: tuple[MitreEvidence, ...] = ()
    sample: SampleMetadata = field(default_factory=SampleMetadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "certificate": _sorted(self.certificate),
            "canonical_output": self.canonical_output,
            "transformations": [t.to_dict() for t in self.transformations],
            "iocs": [i.to_dict() for i in sorted(self.iocs, key=lambda x: x.ioc_id)],
            "capabilities": [
                c.to_dict()
                for c in sorted(self.capabilities, key=lambda x: x.capability_id)
            ],
            "mitre": [
                m.to_dict() for m in sorted(self.mitre, key=lambda x: x.technique_id)
            ],
            "sample": self.sample.to_dict(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# L2 output envelope
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServiceOutput:
    """Uniform envelope every L2 service returns.

    ``service`` and ``version`` let L1 read APIs (PR-2) discover and route
    outputs generically. ``fingerprint`` is the SHA-256 of the canonical
    JSON body — determinism tests compare this across repeated invocations.
    """

    service: str
    version: str
    case_id: str
    body: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "version": self.version,
            "case_id": self.case_id,
            "body": _sorted(self.body),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()


def _sorted(value: Any) -> Any:
    """Recursively canonicalize dict key ordering."""
    if isinstance(value, dict):
        return {k: _sorted(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [_sorted(v) for v in value]
    if isinstance(value, tuple):
        return [_sorted(v) for v in value]
    return value


__all__ = [
    "IocEvidence",
    "CapabilityEvidence",
    "MitreEvidence",
    "TransformationEvidence",
    "SampleMetadata",
    "EvidenceBundle",
    "ServiceOutput",
]
