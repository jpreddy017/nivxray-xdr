"""ADR-0009 · FactSubstrate — the transport-independent adapter between the
analysis pipeline and the CIM composer.

Design principle (ADR-0009 §2.6): the composer NEVER imports from
`routers/ops.py` and NEVER parses HTTP JSON. Instead, the analysis
pipeline calls `from_analysis_result(result_dict)` at the same place
the endpoint packages its HTTP response — an in-process, zero-I/O
conversion into a `FactSubstrate` that the composer then reads from.

Any future ingest surface (email parser, Sysmon parser, PCAP parser,
memory parser) can populate a `FactSubstrate` and get a CIM back — no
knowledge of `/api/decode/smart` shape required.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DecoderLayer:
    """One decoder layer in the chain."""
    idx: int
    op: str                       # "b64-decode" | "hex-decode" | "gzip-decompress" | ...
    input_kind: str = ""          # "text" | "b64" | "hex" | "gzip" | "shellcode" | ...
    output_kind: str = ""
    output_preview: str = ""      # up to ~200 chars for the composer
    confidence: str = "Possible"


@dataclass
class IOCRecord:
    """One extracted IOC with provenance (aligns with ADR-0008 §2 Stage 3)."""
    kind: str                     # "ip" | "domain" | "url" | "hash" | "email"
    value: str
    normalized_value: Optional[str] = None
    source_offset: int = 0
    source_length: int = 0
    context_snippet: str = ""
    stage_passed: List[str] = field(default_factory=list)


@dataclass
class TIHitRecord:
    provider: str
    label: str
    subject: str = ""             # what the TI was for (ioc value, hash, ...)
    confidence: str = "Possible"


@dataclass
class MITREHit:
    technique_id: str
    name: Optional[str] = None
    tactic: Optional[str] = None
    provenance: str = ""          # e.g. "ps-encoded-command", "lolbas:certutil"


@dataclass
class StageRecord:
    name: str
    status: str                   # "completed" | "skipped" | "failed" | "error"
    reason: Optional[str] = None
    duration_ms: Optional[int] = None


@dataclass
class VerdictRecord:
    label: str                    # "Confirmed Malicious" | "Suspicious" | ...
    confidence_pct: int = 0       # 0..100
    reasons: List[str] = field(default_factory=list)


@dataclass
class FactSubstrate:
    """Canonical facts produced by the analysis pipeline. Transport-independent.

    Populated by `from_analysis_result` OR by any future parser (email,
    Sysmon, PCAP, memory) OR by test fixtures. The CIM composer only
    reads from a FactSubstrate — nothing else.
    """
    input_text: str = ""
    input_kind: str = "text"      # "text" | "ps_encoded" | "pe" | "office" | "cisco_xdr_incident" | ...
    decoder_chain: List[DecoderLayer] = field(default_factory=list)
    iocs: List[IOCRecord] = field(default_factory=list)
    ti_hits: List[TIHitRecord] = field(default_factory=list)
    mitre_hits: List[MITREHit] = field(default_factory=list)
    stages: List[StageRecord] = field(default_factory=list)
    verdict: Optional[VerdictRecord] = None
    reasoning_notes: List[str] = field(default_factory=list)
    # Optional telemetry (populated by future parsers, empty for today's inputs)
    telemetry_processes: List[Dict[str, Any]] = field(default_factory=list)
    telemetry_network: List[Dict[str, Any]] = field(default_factory=list)
    telemetry_registry: List[Dict[str, Any]] = field(default_factory=list)
    telemetry_files: List[Dict[str, Any]] = field(default_factory=list)
    telemetry_authentication: List[Dict[str, Any]] = field(default_factory=list)
    telemetry_memory: List[Dict[str, Any]] = field(default_factory=list)
    # Source of the artifact (surface/endpoint/correlation id)
    source_surface: str = "api"
    source_endpoint: Optional[str] = None
    correlation_id: Optional[str] = None


# ─── Adapter from existing /api/decode/smart response dict ──────────────────
#
# NOTE — the composer never calls this. The endpoint code in routers/ops.py
# calls `from_analysis_result(result)` on the internal `result` dict BEFORE
# it becomes HTTP JSON, and passes the resulting `FactSubstrate` to
# `compose.from_facts(...)`. This keeps the CIM composer transport-independent.

def from_analysis_result(result: Dict[str, Any], *,
                          input_text: str = "",
                          source_endpoint: Optional[str] = None,
                          correlation_id: Optional[str] = None) -> FactSubstrate:
    """Convert an in-process analysis result dict → FactSubstrate.

    The `result` dict is the same object that `/api/decode/smart` returns to
    the client. We take it *before* serialization; the composer never sees
    HTTP JSON. This adapter is where legacy field names get mapped to
    canonical FactSubstrate slots — refactoring endpoint field names
    later will not touch the composer.
    """
    fs = FactSubstrate(
        input_text=input_text,
        source_endpoint=source_endpoint,
        correlation_id=correlation_id,
    )

    # ── IOCs · prefer ADR-0008 provenance if present ────────────────────
    iocs_dict = result.get("iocs") or {}
    if isinstance(iocs_dict, dict):
        for kind_key, values in iocs_dict.items():
            if not isinstance(values, list):
                continue
            k = kind_key.rstrip("s")  # ips -> ip · domains -> domain · urls -> url
            k = "hash" if k in ("md5", "sha1", "sha256") else k
            k = "email" if k == "email" else k
            for v in values:
                if isinstance(v, str) and v:
                    fs.iocs.append(IOCRecord(
                        kind=k if k in ("ip", "domain", "url", "hash", "email") else "domain",
                        value=v,
                        normalized_value=v.lower() if k in ("domain", "url", "email") else v,
                        stage_passed=["syntactic", "context"],  # ADR-0008 §2
                    ))

    # ── Decode chain ────────────────────────────────────────────────────
    for i, layer in enumerate(result.get("layer_trace") or []):
        if not isinstance(layer, dict):
            continue
        fs.decoder_chain.append(DecoderLayer(
            idx=i,
            op=str(layer.get("op") or layer.get("kind") or "decode"),
            input_kind=str(layer.get("input_kind") or ""),
            output_kind=str(layer.get("output_kind") or ""),
            output_preview=str(layer.get("preview") or layer.get("output") or "")[:200],
        ))

    # ── MITRE hits ──────────────────────────────────────────────────────
    mitre = result.get("mitre") or {}
    if isinstance(mitre, dict):
        for tech in mitre.get("techniques") or []:
            if isinstance(tech, dict):
                tid = tech.get("id") or tech.get("technique_id") or ""
                if tid:
                    fs.mitre_hits.append(MITREHit(
                        technique_id=str(tid),
                        name=tech.get("name"),
                        tactic=tech.get("tactic"),
                        provenance=str(tech.get("provenance") or ""),
                    ))
            elif isinstance(tech, str):
                fs.mitre_hits.append(MITREHit(technique_id=tech))

    # ── Verdict ─────────────────────────────────────────────────────────
    vc = result.get("verdict_card") or {}
    if isinstance(vc, dict) and vc.get("verdict"):
        fs.verdict = VerdictRecord(
            label=str(vc.get("verdict") or ""),
            confidence_pct=int(vc.get("confidence") or 0),
            reasons=[str(r) for r in (vc.get("reasons") or []) if r],
        )

    # ── TI hits (from ti_shield or ti_hits or ti_enrichment) ────────────
    ti = result.get("ti_shield") or {}
    if isinstance(ti, dict):
        for layer in ti.get("layers") or []:
            if isinstance(layer, dict):
                for hit in layer.get("ti_hits") or []:
                    if isinstance(hit, dict):
                        fs.ti_hits.append(TIHitRecord(
                            provider=str(hit.get("provider") or "internal"),
                            label=str(hit.get("label") or hit.get("family") or ""),
                            subject=str(hit.get("subject") or ""),
                        ))

    # ── Input detection ─────────────────────────────────────────────────
    detected = str(result.get("detected_type") or "").lower()
    if detected:
        fs.input_kind = detected

    # ── Reasoning notes ─────────────────────────────────────────────────
    reasoning = result.get("reasoning") or {}
    if isinstance(reasoning, dict):
        notes = reasoning.get("notes") or reasoning.get("summary") or []
        if isinstance(notes, str):
            fs.reasoning_notes.append(notes)
        elif isinstance(notes, list):
            fs.reasoning_notes.extend(str(n) for n in notes if n)

    # ── Stages executed (best-effort from `stages_executed` or synthesise) ──
    stages_raw = result.get("stages_executed") or []
    if isinstance(stages_raw, list) and stages_raw:
        for st in stages_raw:
            if isinstance(st, dict) and st.get("name"):
                fs.stages.append(StageRecord(
                    name=str(st["name"]),
                    status=str(st.get("status") or "completed"),
                    reason=st.get("reason"),
                    duration_ms=st.get("duration_ms"),
                ))
    else:
        # Synthesise from what we observed
        if fs.decoder_chain:
            fs.stages.append(StageRecord(name="decode", status="completed"))
        if fs.iocs:
            fs.stages.append(StageRecord(name="ioc_extract", status="completed"))
        if fs.mitre_hits:
            fs.stages.append(StageRecord(name="mitre_map", status="completed"))
        if fs.ti_hits:
            fs.stages.append(StageRecord(name="ti_enrich", status="completed"))
        if fs.verdict:
            fs.stages.append(StageRecord(name="reasoning", status="completed"))

    return fs
