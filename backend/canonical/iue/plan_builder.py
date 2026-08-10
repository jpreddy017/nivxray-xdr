"""Deterministic PlanStep + Capability emission for the IUE Composer.

Phase 1 strategy: lookup table by canonical primary_type; augmented by
embedded types + IDA hint. Dispatch policy fixed to strict_ordered in
Phase 1 (parallel_where_safe / dag deferred to Phase 3 executor).
"""
from __future__ import annotations

from typing import List, Optional

from .models import Capability, DispatchPolicy, PlanStep


def _step(capability: Capability, action: str, reason: str,
          required: bool = True, expected: str = "authoritative_evidence") -> PlanStep:
    return PlanStep(
        engine=f"canonical.executor.{capability.value.lower()}",
        action=action,
        reason=reason,
        required=required,
        expected_output_kind=expected,
        capability=capability,
    )


# Canonical primary types are the union of UIL InputKind, DIE input_type,
# and v2 ArtefactType — mapped to plan templates. Types not listed default
# to _GENERIC_TEXT_PLAN.
_ARCHIVE_TYPES     = {"docx", "pptx", "xlsx", "zip_archive", "seven_z", "rar_archive", "iso", "apk"}
_BINARY_TYPES      = {"pe_binary", "pe_file", "elf_binary", "elf_file", "macho_binary", "macho_file"}
_DOCUMENT_TYPES    = {"pdf", "docx", "pptx", "xlsx"}
_TELEMETRY_TYPES   = {"evtx", "pcap", "cisco_xdr", "crowdstrike", "defender",
                      "sentinelone", "qradar", "splunk", "sysmon_xml",
                      "windows_event", "vendor_json"}
_SHELL_TYPES       = {"powershell", "powershell_naked", "powershell_encoded",
                      "cmd", "bash", "batch", "command", "command_chain",
                      "nested_shell_chain"}
_ENCODED_TYPES     = {"base64", "hex", "encoded_blob"}
_STRUCTURED_TEXT   = {"json", "xml", "yaml", "stix", "openioc", "yara", "sigma",
                      "vendor_report_text", "documented_investigation_report"}
_EMAIL_TYPES       = {"email_eml", "email_msg"}
_IOC_TYPES         = {"ioc_list", "url", "url_only"}
_IMAGE_TYPES       = {"image"}

_GENERIC_TEXT_PLAN = [
    Capability.INPUT_HEALTH,
    Capability.IOC_EXTRACTOR,
    Capability.SEMANTIC_AST,
    Capability.MITRE_MAP,
    Capability.ATTACK_CHAIN,
]


def build_plan_and_dispatch(
    primary_type: str,
    embedded: List[str],
    ida_class: Optional[str],
    ida_artifact_hint: int,
    dispatch_hints_from_v2: List[str],
    intent_label: str,
    blocking_health: bool,
) -> tuple[List[PlanStep], List[Capability], DispatchPolicy]:
    """Deterministic plan + capability dispatch + policy."""

    if blocking_health:
        plan = [
            _step(Capability.INPUT_HEALTH,
                  "surface health blocking condition",
                  "input failed pre-IUE health check; downstream execution paused",
                  required=True,
                  expected="health_report"),
        ]
        return plan, [Capability.INPUT_HEALTH], DispatchPolicy.STRICT_ORDERED

    steps: List[PlanStep] = [
        _step(Capability.INPUT_HEALTH,
              "record input health signal into SSOT",
              "every canonical investigation records health",
              required=True,
              expected="health_report"),
    ]

    pt = (primary_type or "").lower()

    if pt in _ARCHIVE_TYPES:
        steps.append(_step(Capability.ARCHIVE_EXTRACT,
                           "extract archive members",
                           f"{pt} is an archive/container that must be unpacked before analysis",
                           expected="artifact_list"))

    if pt in _DOCUMENT_TYPES:
        steps.append(_step(Capability.ARTIFACT_SPLIT,
                           "split document into typed sub-artefacts",
                           "documents carry embedded IOCs / commands / URLs / images",
                           expected="artifact_list"))

    if pt in _BINARY_TYPES:
        steps.append(_step(Capability.SEMANTIC_AST,
                           "run static binary analyser",
                           f"{pt} requires binary static analysis",
                           expected="artifact_list"))

    if pt in _SHELL_TYPES or "powershell" in embedded or "command_line" in embedded:
        steps.append(_step(Capability.COMMAND_DETECT,
                           "detect and decompose command lines",
                           "shell / command inputs decompose into typed commands",
                           expected="command_list"))
        steps.append(_step(Capability.SEMANTIC_AST,
                           "run per-language semantic AST",
                           "each detected command is parsed by its language AST",
                           expected="ast_nodes"))

    if pt in _ENCODED_TYPES or "base64" in embedded:
        steps.append(_step(Capability.DECODER,
                           "iterative deterministic decode chain",
                           "encoded input must be peeled to terminal form",
                           expected="decoded_text"))

    if pt in _TELEMETRY_TYPES:
        steps.append(_step(Capability.VENDOR_NORMALISER,
                           "normalise vendor telemetry to canonical events",
                           f"{pt} arrives in vendor-specific schema",
                           expected="event_list"))

    if ida_class and ida_class != "none" and ida_artifact_hint > 0:
        # Avoid duplicating ARTIFACT_SPLIT if already emitted for documents.
        if not any(s.capability is Capability.ARTIFACT_SPLIT for s in steps):
            steps.append(_step(Capability.ARTIFACT_SPLIT,
                               "split paste into typed IDA artefacts",
                               f"IDA hint: {ida_class} with {ida_artifact_hint} artefacts",
                               expected="artifact_list"))

    # Structured-text / email / IOC-list inputs go straight to IOC extractor.
    if pt in _STRUCTURED_TEXT or pt in _EMAIL_TYPES or pt in _IOC_TYPES:
        steps.append(_step(Capability.IOC_EXTRACTOR,
                           "extract IOCs from structured text",
                           f"{pt} is text-structured; IOC extraction is deterministic",
                           expected="ioc_bundle"))

    # Every non-blocking plan performs IOC extraction, MITRE mapping,
    # attack-chain synthesis, and LOLBAS matching downstream.
    steps.append(_step(Capability.IOC_EXTRACTOR,
                       "extract IOCs from decoded fragments and artefacts",
                       "IOC extraction is universal across input types",
                       expected="ioc_bundle"))
    steps.append(_step(Capability.LOLBAS_MATCH,
                       "match LOLBAS binaries in commands and text",
                       "LOLBAS match is deterministic",
                       expected="lolbas_hits"))
    steps.append(_step(Capability.MITRE_MAP,
                       "map evidence to MITRE ATT&CK techniques",
                       "every canonical investigation maps to ATT&CK",
                       expected="attck_map"))
    steps.append(_step(Capability.ATTACK_CHAIN,
                       "assemble ordered attack chain from evidence",
                       "attack chain is a projection over the evidence graph",
                       expected="attack_chain"))

    # Optional recursion: if embedded types exist OR decoder output is
    # expected to surface new artefacts, arrange for recursive discovery.
    if embedded or any(s.capability is Capability.DECODER for s in steps):
        steps.append(_step(Capability.RECURSIVE_DISCOVERY,
                           "recurse into embedded / decoded artefacts",
                           "children may themselves be investigable artefacts",
                           required=False,
                           expected="child_ssot_refs"))

    steps.append(_step(Capability.THREAT_INTEL_ENRICH,
                       "external TI enrichment on IOCs (isolated Enricher role)",
                       "enrichment must never change deterministic conclusion",
                       required=False,
                       expected="ti_hits"))
    steps.append(_step(Capability.QUALITY_SCORE,
                       "score investigation completeness",
                       "produces buckets_populated + completeness_pct",
                       expected="quality_score"))

    # Deduplicate while preserving order.
    seen: set = set()
    deduped: List[PlanStep] = []
    for s in steps:
        key = (s.capability, s.action)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(s)

    capabilities = list(dict.fromkeys(s.capability for s in deduped))
    return deduped, capabilities, DispatchPolicy.STRICT_ORDERED
