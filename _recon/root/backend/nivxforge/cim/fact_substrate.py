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
    reason: str = ""              # analyst-facing rationale for WHY this decoder ran


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
    # P1-02b · Workspace-parity metadata that feeds the verdict engine:
    # {custom_recipes_matched, rules_hit, sigma, yara, lolbins_v2,
    #  ti_shield, ...}. Populated by `from_analysis_result` from the
    # legacy pipeline; consumed by `compute_verdict(graph, metadata)`.
    verdict_metadata: Dict[str, Any] = field(default_factory=dict)
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
            reason=str(layer.get("reason") or "")[:240],
        ))

    # ── P1-02c hotfix · Shellcode-reached parity ──────────────────────
    # When the decoder pipeline lands on x86/x64/ARM shellcode (the terminal
    # state of many encoded-PS → GZIP → IEX → shellcode payload chains),
    # Workspace's `/api/analyze` returns a proper "SHELLCODE DECODED"
    # banner with Capstone disassembly + extracted C2 IPs, UAs, strings.
    # `/api/decode/smart` (X-Lab's entry) exposes the same signal via
    # `result["reached_shellcode"]` + `result["output_raw"]`. We fold it
    # into `verdict_metadata['shellcode']` so the CIO + projector can
    # render the same analyst-facing card instead of dumping raw bytes.
    try:
        if result.get("reached_shellcode") or result.get("is_shellcode"):
            from shellcode_analyzer import analyze as _sc_analyze, _family_recognise
            raw = result.get("output_raw") or result.get("output") or b""
            if isinstance(raw, str):
                # Best-effort: encode as latin-1 to preserve byte values.
                raw = raw.encode("latin-1", errors="ignore")
            if raw:
                sc = _sc_analyze(raw)
                fam = None
                mitre_tech = None
                try:
                    fam, mitre_tech = _family_recognise(raw)
                except Exception:  # noqa: BLE001
                    pass
                iocs = sc.get("iocs") or {}
                fs.verdict_metadata["shellcode"] = {
                    "is_shellcode":  True,
                    "size":          sc.get("size", 0),
                    "entropy":       sc.get("entropy", 0.0),
                    "arch":          sc.get("arch"),
                    "family":        fam or "Generic shellcode",
                    "family_mitre":  mitre_tech,
                    "c2_ips":        iocs.get("ips") or [],
                    "c2_domains":    iocs.get("domains") or [],
                    "c2_urls":       iocs.get("urls") or [],
                    "user_agents":   iocs.get("user_agents") or [],
                    "strings":       (iocs.get("strings") or [])[:24],
                    "hex_preview":   sc.get("hex_preview") or "",
                    "disasm_lines":  len(sc.get("disassembly") or []),
                    "capstone_available": sc.get("capstone_available", False),
                }
    except Exception:  # noqa: BLE001
        # Never crash the substrate build over shellcode enrichment.
        pass

    # ── MITRE hits ──────────────────────────────────────────────────────
    # `/decode/smart` and `/v2/auto-investigate` differ in shape:
    #   • decode/smart returns `mitre` as a LIST of
    #     `{id, technique, tactic}` (field name is `technique`, not `name`).
    #   • auto-investigate returns `mitre` as a DICT
    #     `{techniques: [...], tactics: [...]}`.
    # Both must reach the CIO evidence graph so the Behaviour + Attack
    # lenses populate.
    mitre = result.get("mitre")

    def _push_mitre_tech(tech: Any) -> None:
        if isinstance(tech, dict):
            tid = tech.get("id") or tech.get("technique_id") or ""
            if tid:
                fs.mitre_hits.append(MITREHit(
                    technique_id=str(tid),
                    name=tech.get("name") or tech.get("technique"),
                    tactic=tech.get("tactic"),
                    provenance=str(tech.get("provenance") or ""),
                ))
        elif isinstance(tech, str):
            fs.mitre_hits.append(MITREHit(technique_id=tech))

    if isinstance(mitre, dict):
        for tech in mitre.get("techniques") or []:
            _push_mitre_tech(tech)
    elif isinstance(mitre, list):
        for tech in mitre:
            _push_mitre_tech(tech)

    # Also honour mitre_v2 (list of {id, name, tactic}) when present.
    mitre_v2 = result.get("mitre_v2")
    if isinstance(mitre_v2, list):
        for tech in mitre_v2:
            _push_mitre_tech(tech)

    # ── LOLBins ─────────────────────────────────────────────────────────
    # decode/smart returns `lolbas` (list or None). auto-investigate uses
    # `lolbins_v2 = {executed, referenced, expanded}` (each a list of dicts
    # or strings). Populate reasoning notes so the CIO builder emits
    # `lolbin` nodes even when the top-level field is null but the
    # tool clearly used a living-off-the-land binary.
    lolbas_top = result.get("lolbas")
    if isinstance(lolbas_top, list):
        for item in lolbas_top:
            name = ""
            if isinstance(item, dict):
                name = str(item.get("name") or item.get("binary") or "").strip()
            elif isinstance(item, str):
                name = item.strip()
            if name:
                fs.reasoning_notes.append(f"LOLBIN detected: {name}")

    lolbins_v2 = result.get("lolbins_v2") or {}
    if isinstance(lolbins_v2, dict):
        for bucket in ("executed", "referenced", "expanded"):
            for item in lolbins_v2.get(bucket) or []:
                name = ""
                if isinstance(item, dict):
                    name = str(item.get("name") or item.get("binary") or "").strip()
                elif isinstance(item, str):
                    name = item.strip()
                if name:
                    fs.reasoning_notes.append(f"LOLBIN detected: {name}")

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

    # ── P1-02b · Carry Workspace-parity verdict metadata forward ────────
    # Every field the tiered verdict engine reads directly (recipes,
    # rules, sigma, yara, lolbins, ti_shield). Passed through to
    # `compute_verdict(graph, metadata=fs.verdict_metadata)` inside the
    # CIO builder. Zero fork: one verdict engine, two data sources.
    for _mk in ("custom_recipes_matched", "recipes_matched", "rules_hit",
                "sigma", "yara", "lolbas", "lolbins_v2", "ti_shield"):
        if _mk in result and result[_mk]:
            fs.verdict_metadata[_mk] = result[_mk]

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

    # ── /api/v2/auto-investigate FALLBACK · read its distinct envelope ──
    # ADR-0009 parity remediation (2026-02-28): auto-investigate returns
    # `executive_card` (not `verdict_card`), `decode_pipeline.chains[].layers`
    # (not `layer_trace`), and `mdr_investigation.recommendations`.  Read
    # them here so the CIM has content parity across both endpoints.
    if not fs.verdict and isinstance(result.get("executive_card"), dict):
        ec = result["executive_card"]
        verdict_label = str(ec.get("verdict_pretty") or ec.get("verdict") or "").strip()
        if verdict_label:
            fs.verdict = VerdictRecord(
                label=verdict_label.title() if verdict_label.islower() else verdict_label,
                confidence_pct=int(ec.get("confidence") or 0),
                reasons=[str(ec.get("because") or "")[:200]] if ec.get("because") else [],
            )
    if not fs.decoder_chain and isinstance(result.get("decode_pipeline"), dict):
        chains = result["decode_pipeline"].get("chains") or []
        if isinstance(chains, list):
            for ch in chains:
                layers = (ch or {}).get("layers") or []
                for i, lyr in enumerate(layers):
                    if not isinstance(lyr, dict):
                        continue
                    fs.decoder_chain.append(DecoderLayer(
                        idx=len(fs.decoder_chain),
                        op=str(lyr.get("decoder") or "decode"),
                        input_kind="", output_kind="",
                        output_preview=str(lyr.get("preview") or "")[:200],
                        reason=str(lyr.get("reason") or lyr.get("why") or "")[:240],
                    ))
                    # Sub-IOCs recovered by each layer
                    sub = lyr.get("sub_iocs") or {}
                    if isinstance(sub, dict):
                        for k, vs in sub.items():
                            if not isinstance(vs, list):
                                continue
                            kind = "url" if "url" in k else "domain" if "domain" in k else "ip" if "ip" in k else "hash" if k in ("md5","sha1","sha256") else None
                            if not kind:
                                continue
                            for v in vs:
                                if isinstance(v, str) and v:
                                    fs.iocs.append(IOCRecord(
                                        kind=kind, value=v,
                                        normalized_value=v.lower() if kind in ("domain","url","email") else v,
                                        stage_passed=["syntactic","context"],
                                    ))

    # ── Fallback: /decode/smart returns decoder steps in `trace[]`
    # (not `layer_trace[]` nor `decode_pipeline`) for PowerShell
    # -EncodedCommand normalisation. Read from `trace[]` so the CIO's
    # decode_chain reflects the actual recovery steps.
    if not fs.decoder_chain and isinstance(result.get("trace"), list):
        for i, step in enumerate(result["trace"]):
            if not isinstance(step, dict):
                continue
            op = str(step.get("op") or step.get("kind") or "decode")
            preview = str(step.get("output_preview") or step.get("preview") or step.get("output") or "")[:200]
            evidence = step.get("evidence") or {}
            input_kind = ""
            output_kind = ""
            if isinstance(evidence, dict):
                input_kind = str(evidence.get("input_kind") or "")
                output_kind = str(evidence.get("encoding") or evidence.get("output_kind") or "")
            fs.decoder_chain.append(DecoderLayer(
                idx=i,
                op=op,
                input_kind=input_kind,
                output_kind=output_kind,
                output_preview=preview,
                reason=str(step.get("reason") or "")[:240],
            ))

    # ── Adapter for mdr_investigation.recommendations ──
    if isinstance(result.get("mdr_investigation"), dict):
        for rec in (result["mdr_investigation"].get("recommendations") or [])[:5]:
            if isinstance(rec, dict) and rec.get("title"):
                fs.reasoning_notes.append(str(rec.get("title") or "")[:200])

    return fs
