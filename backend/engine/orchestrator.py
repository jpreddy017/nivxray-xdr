"""Orchestrator — recursive plugin-driven decode + intelligence loop.

Production hardening (Feb 2026)
-------------------------------
* Loop detection — payload SHA-1 short-hash memo prevents same-content from
  being decoded twice. Same plugin cannot fire twice on identical bytes.
* Memory ceiling — per-step and cumulative output size caps.
* Wall-time + depth + branch caps (via Budget).
* Plugin execution report — records EVERY plugin invocation with its outcome
  (accepted / skipped / detect_zero / decode_error / no_improvement / loop).
* Explainable confidence — every point contributing to risk_score is stored
  in ConfidenceBreakdown with its source and evidence.
* Terminal states — english, family-identified, budget, no-candidate, complete.

Vision alignment
----------------
The orchestrator ONLY routes. AI cannot influence decoding, verdicts, or
Findings — it may enrich the executive_summary post-hoc via a separate,
opt-in step outside this loop.
"""
from __future__ import annotations

import hashlib
import logging
import time
from typing import List, Optional, Set, Tuple

from .fingerprint_util import compute as fingerprint_compute
from .models import (
    AnalysisContext,
    AnalystReport,
    ConfidenceBreakdown,
    Findings,
    Fingerprint,
    IOCBundle,
    InvestigationRecommendation,
    PluginExecutionEntry,
    PluginExecutionReport,
    RiskContribution,
    TraceStep,
)
from .registry import DecoderRegistry

log = logging.getLogger("nivx.engine.orchestrator")

# Terminal / scoring constants — kept in one place for tunability.
_TERMINAL_ENGLISH = 0.7
_TERMINAL_FAMILY_CONFIDENCE = 0.8
_IMPROVEMENT_EPS = 0.02

# Safety limits (env-tunable in Budget; defaults here are hard fallbacks).
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024        # 4 MB per intermediate output
_MAX_CUMULATIVE_BYTES = 32 * 1024 * 1024   # 32 MB across all layers
# Runaway loop guard (Feb-2026): if an incoming payload exceeds this cap AND
# is dominated by a single repetitive obfuscation pattern (10k+ hex escapes,
# gigantic base64 padding runs, etc.), skip the corresponding plugin outright.
# Prevents a single slow decoder from stalling the request for >60s and
# eating a Cloudflare 524 timeout.
_MAX_INPUT_BYTES_PER_DECODE = 8 * 1024 * 1024      # 8 MB
_SLOW_DECODE_WARN_MS = 6_000                         # log warning
_HARD_ABORT_MS = 12_000                              # hard-abort budget
# When the payload is highly repetitive (see March-1 / Cisco-embedded PS
# samples), a moderate 5-8KB input can still cascade into 25+ recursive
# layers because the pipeline peels one wrapper only to reveal another
# hex-escape stream. Bail out early: at depth ≥ 8 or when a single layer
# produces near-identical output to the previous one, we abort with a
# partial-result terminal instead of chasing the ghost for 60+ seconds.
_DEEP_RECURSION_DEPTH = 8
_DEEP_RECURSION_INPUT_BYTES = 512 * 1024             # 512 KB

_SEVERITY_WEIGHTS = {"info": 2, "low": 5, "medium": 25, "high": 35, "critical": 60}

# RC3.1 · verdict-precision hardening. LOLBAS tiering separates canonical
# malware download / AWL-bypass binaries (certutil, mshta, regsvr32, …)
# from parent shells that are only interesting when paired with a real
# indicator (cmd.exe, powershell.exe).
_HIGH_LOLBAS = {
    "certutil.exe", "mshta.exe", "regsvr32.exe", "bitsadmin.exe",
    "rundll32.exe", "wmic.exe", "cscript.exe", "wscript.exe",
    "msiexec.exe", "hh.exe", "installutil.exe", "msbuild.exe",
    "odbcconf.exe", "presentationhost.exe", "pcalua.exe",
    "regasm.exe", "regsvcs.exe",
}
_BENIGN_LOLBAS = {"cmd.exe", "powershell.exe", "pwsh.exe", "python.exe",
                  "python3.exe", "wsl.exe", "bash.exe"}

# Tradecraft flags that ALWAYS score (they imply eval / Execute code paths
# — they are their own hard signal). Every other tradecraft flag is gated
# behind at least one other indicator so isolated obfuscation stays at
# "unknown".
_ALWAYS_ACTIVE_TRADECRAFT = {
    "js-string-obfuscation", "vbs-string-obfuscation",
    "python-exec-b64", "eval-fromcharcode", "eval-atob", "eval-unescape",
    "wscript-execute", "vbs-createobject-shell",
}

# Canonical binary-encoding transforms — used to detect "payload staging"
# chains that push a decoded loader from suspicious into malicious even
# when the wrapper binary is only a parent shell (powershell / cmd).
_ENCODING_DECODERS = {
    "base64-decode", "base64", "utf16-decode", "utf16le-decode",
    "utf16-be-decode", "gzip-decompress", "hex-decode", "zlib-decompress",
    "brotli-decompress", "lzma-decompress", "bzip2-decompress",
    "ascii85-decode", "base32-decode", "base58-decode", "base85-decode",
    "base91-decode", "xor", "xor-brute",
}


def _short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("latin-1", errors="replace")).hexdigest()[:16]


def _score(fp: Fingerprint) -> float:
    return (fp.english_density * 0.6
            + fp.printable_ratio * 0.3
            + max(0.0, (5.0 - fp.entropy)) * 0.02)


def _merge_iocs(bundle: IOCBundle, add: dict) -> None:
    for k, v in (add or {}).items():
        if not isinstance(v, list):
            continue
        target = getattr(bundle, k, None)
        if target is None:
            continue
        for item in v:
            if item and item not in target:
                target.append(item)


def _post_decode_lolbas_scan(findings: Findings, final_output: str, raw_input: str) -> None:
    """RC3.1 · Run the global LOLBAS scanner across the concatenated raw +
    decoded surface and merge any hits back into `findings.lolbas` / MITRE.
    Individual decoder plugins only emit LOLBAS for the wrappers they
    recognise (powershell, cmd, mshta, python); the global scanner covers
    the full corpus (certutil, regsvr32, bitsadmin, rundll32, wmic, hh,
    msiexec, cscript, wscript, msbuild, installutil, etc.)."""
    try:
        from lolbas import scan_lolbas          # local import: avoids cycle
        from .models import LolbasHit, MitreHint
    except Exception:                              # pragma: no cover
        return

    seen_bins = {h.binary.lower() for h in findings.lolbas}
    seen_mitre = {(h.id, h.source) for h in findings.mitre_techniques}
    text = ((raw_input or "") + "\n" + (final_output or ""))[:200_000]
    try:
        hits = scan_lolbas(text) or []
    except Exception:                              # pragma: no cover
        return
    for h in hits:
        b = str(h.get("binary", "")).lower()
        if not b or b in seen_bins:
            continue
        seen_bins.add(b)
        tid = (h.get("mitre") or [""])[0]
        desc = h.get("description") or ""
        findings.lolbas.append(LolbasHit(
            binary=b, technique_id=tid, evidence=desc,
        ))
        # Merge every technique the LOLBAS entry advertises
        for tech in h.get("mitre") or []:
            key = (tech, "lolbas")
            if key in seen_mitre:
                continue
            seen_mitre.add(key)
            findings.mitre_techniques.append(MitreHint(
                id=tech, name=b, source="lolbas", evidence=desc,
            ))


def _aggregate_findings(trace: List[TraceStep]) -> Findings:
    findings = Findings()
    seen_mitre = set()
    seen_family = {}
    for step in trace:
        _merge_iocs(findings.iocs, step.sub_iocs)
        for hint in step.mitre_hints:
            key = (hint.id, hint.source)
            if key not in seen_mitre:
                findings.mitre_techniques.append(hint)
                seen_mitre.add(key)
        for fh in step.family_hints:
            prev = seen_family.get(fh.family)
            if prev is None or fh.confidence > prev.confidence:
                seen_family[fh.family] = fh
        for hit in step.lolbas_hits:
            findings.lolbas.append(hit)
        for tc in step.tradecraft:
            findings.tradecraft.append(tc)
    if seen_family:
        ranked = sorted(seen_family.values(), key=lambda h: -h.confidence)
        top = ranked[0]
        findings.family.family = top.family
        findings.family.confidence = top.confidence
        findings.family.evidence = [top.evidence] if top.evidence else []
        findings.family.alternatives = ranked[1:]
        # RC2.1a — propagate rich family evidence when a family plugin fires
        findings.family.evidence_items = list(top.evidence_items)
        findings.family.mitre_techniques = list(top.mitre_techniques)
        findings.family.yara_suggestion = top.yara_suggestion
        findings.family.atomic_red_hint = top.atomic_red_hint
    return findings


def _compute_confidence_breakdown(findings: Findings, decode_depth: int = 0,
                                    trace_decoders: Optional[List[str]] = None) -> ConfidenceBreakdown:
    """Explainable risk_score — one RiskContribution per signal source.

    RC3.1 rebalance (verdict precision 15/31 → ≥28/31):
      * LOLBAS is tiered — HIGH (certutil, mshta, regsvr32, …) always scores
        heavily, BENIGN (cmd.exe, powershell.exe) only counts when paired
        with a URL or another indicator.
      * MITRE / tradecraft / IOC-only scoring is gated behind a HARD SIGNAL
        (URL / high-LOLBAS / high-confidence family). Isolated obfuscation
        with no downstream artefact stays at "unknown" as analysts expect.
      * A canonical HIGH_LOLBAS + URL "download-and-execute" combo bumps
        into MALICIOUS (>70) without needing a family match.
      * Caps prevent runaway scores from over-classifying dev-obfuscation as
        MALICIOUS when the correct verdict is SUSPICIOUS.
    """
    contribs: List[RiskContribution] = []
    total = 0

    # ------------------------------------------------------------ tiering
    lolbas_names = {h.binary.lower() for h in findings.lolbas}
    high_lolbas = sorted(lolbas_names & _HIGH_LOLBAS)
    benign_lolbas = sorted(lolbas_names & _BENIGN_LOLBAS)
    unknown_lolbas = sorted(lolbas_names - _HIGH_LOLBAS - _BENIGN_LOLBAS)

    has_url = bool(findings.iocs.urls or findings.iocs.ips or findings.iocs.domains)
    has_high_lolbas = bool(high_lolbas)
    has_family = findings.family.confidence >= 0.5
    # T1059.005 (VBS), T1059.006 (Python), T1059.007 (JS) — the presence
    # of these subtechs implies an eval/exec engine is being asked to
    # interpret decoded bytes; treat that as a hard signal so downstream
    # tradecraft flags surface a "Suspicious" verdict.
    _EXEC_SUBTECHS = {"T1059.005", "T1059.006", "T1059.007"}
    has_exec_subtech = any(h.id in _EXEC_SUBTECHS for h in findings.mitre_techniques)
    has_hard_signal = has_url or has_high_lolbas or has_family or has_exec_subtech

    # Family match — strongest deterministic signal
    if findings.family.confidence >= 0.8:
        pts = 55
        contribs.append(RiskContribution(
            source="family-match", points=pts,
            detail=f"High-confidence family: {findings.family.family} "
                   f"({findings.family.confidence * 100:.0f}%)",
        ))
        total += pts
    elif findings.family.confidence >= 0.7:
        pts = 35
        contribs.append(RiskContribution(
            source="family-match", points=pts,
            detail=f"Family: {findings.family.family} "
                   f"({findings.family.confidence * 100:.0f}%)",
        ))
        total += pts
    elif findings.family.confidence >= 0.5:
        pts = 15
        contribs.append(RiskContribution(
            source="family-match", points=pts,
            detail=f"Weak family match: {findings.family.family}",
        ))
        total += pts

    # MITRE techniques — gated: score only when we have a hard signal OR
    # ≥3 techniques (broad tactic coverage is itself a signal).
    if findings.mitre_techniques and (has_hard_signal or len(findings.mitre_techniques) >= 3):
        raw_pts = 8 * len(findings.mitre_techniques)
        pts = min(24, raw_pts)  # cap at 24 (3 techniques equivalent)
        ids = ", ".join(sorted({h.id for h in findings.mitre_techniques}))
        contribs.append(RiskContribution(
            source="mitre", points=pts,
            detail=f"{len(findings.mitre_techniques)} MITRE technique(s): {ids}",
        ))
        total += pts

    # IOCs — always score when present (URLs are actionable regardless).
    ioc_total = (len(findings.iocs.urls) + len(findings.iocs.ips)
                 + len(findings.iocs.domains))
    if ioc_total:
        pts = min(20, 4 * ioc_total)
        contribs.append(RiskContribution(
            source="iocs", points=pts,
            detail=(f"{len(findings.iocs.ips)} IPs, {len(findings.iocs.urls)} URLs, "
                    f"{len(findings.iocs.domains)} domains extracted"),
        ))
        total += pts

    # LOLBAS — tiered
    lolbas_pts = 0
    if high_lolbas:
        lolbas_pts += 15 + 5 * (len(high_lolbas) - 1)  # 15 base + 5 per extra
    if benign_lolbas and has_hard_signal:
        # Parent shell only counts when paired with something concrete
        lolbas_pts += 5 * len(benign_lolbas)
    if unknown_lolbas and has_hard_signal:
        # Recon/utility binaries (whoami, schtasks, etc.) score ONLY when
        # paired with a URL / high-LOLBAS / family — isolated `whoami /all`
        # must stay at unknown.
        lolbas_pts += 3 * len(unknown_lolbas)
    if lolbas_pts:
        lolbas_pts = min(30, lolbas_pts)
        contribs.append(RiskContribution(
            source="lolbas", points=lolbas_pts,
            detail=f"LOLBAS usage: {', '.join(sorted(lolbas_names))}",
        ))
        total += lolbas_pts

    # HIGH_LOLBAS + URL combo — canonical download-and-execute tradecraft
    # (T1105). Bumps into MALICIOUS even without a family match.
    if has_high_lolbas and has_url:
        counts = []
        if findings.iocs.urls:    counts.append(f"{len(findings.iocs.urls)} URL(s)")
        if findings.iocs.ips:     counts.append(f"{len(findings.iocs.ips)} IP(s)")
        if findings.iocs.domains: counts.append(f"{len(findings.iocs.domains)} domain(s)")
        contribs.append(RiskContribution(
            source="network-lolbas-combo", points=35,
            detail=(f"HIGH-severity LOLBAS ({', '.join(high_lolbas)}) paired with "
                    f"network IOC ({', '.join(counts)}) — canonical "
                    "download-and-execute (T1105)."),
        ))
        total += 35
    elif benign_lolbas and has_url and not has_high_lolbas:
        # Weaker combo — powershell+URL is common but not always malicious;
        # +8 keeps us in suspicious range without over-classifying.
        contribs.append(RiskContribution(
            source="network-lolbas-combo", points=8,
            detail=f"Parent-shell LOLBAS ({', '.join(benign_lolbas)}) paired with URL",
        ))
        total += 8

    # Tradecraft flags — gated behind hard signal UNLESS the flag itself
    # implies code execution (js-string-obfuscation, vbs-string-obfuscation
    # imply eval/Execute, python-exec-b64 implies exec()).
    if findings.tradecraft:
        active = []
        for tc in findings.tradecraft:
            if has_hard_signal or tc.flag in _ALWAYS_ACTIVE_TRADECRAFT:
                active.append(tc)
        if active:
            raw = sum(_SEVERITY_WEIGHTS.get(tc.severity, 5) for tc in active)
            pts = min(25, raw)
            flags = ", ".join(f"{tc.flag}({tc.severity})" for tc in active)
            contribs.append(RiskContribution(
                source="tradecraft", points=pts, detail=flags,
            ))
            total += pts

    # Payload-staging bonus — canonical binary-encoding chain (base64 +
    # utf16 / gzip / xor / hex …) paired with a URL is the Empire /
    # Meterpreter / Cobalt-Strike loader pattern. Push from suspicious
    # into MALICIOUS even when the parent shell is only powershell / cmd.
    if trace_decoders and has_url:
        enc_layers = sum(1 for d in trace_decoders if d in _ENCODING_DECODERS)
        if enc_layers >= 2:
            contribs.append(RiskContribution(
                source="encoding-chain", points=10,
                detail=(f"{enc_layers} canonical encoding layers "
                        f"({', '.join(d for d in trace_decoders if d in _ENCODING_DECODERS)}) "
                        "paired with URL — payload staging pattern"),
            ))
            total += 10

    total = min(100, total)
    # Fallback chain-depth signal — when nothing else scored but we did
    # peel ≥1 encoding layer, keep the analyst in the "needs_review" band.
    if total == 0 and decode_depth >= 2:
        contribs.append(RiskContribution(
            source="obfuscation-chain", points=5,
            detail=f"Peeled {decode_depth} decode layer(s) without additional signals",
        ))
        total = 5
    if total >= 70:
        verdict = "malicious"
    elif total >= 40:
        verdict = "suspicious"
    elif total > 0:
        verdict = "needs_review"
    else:
        verdict = "unknown"
    return ConfidenceBreakdown(total=total, verdict=verdict, contributions=contribs)


def _executive_summary(trace: List[TraceStep], findings: Findings) -> str:
    if not trace and findings.risk_score == 0:
        return "No transforms applied; payload appears to be plaintext with no notable indicators."
    parts: List[str] = []
    if trace:
        chain = " → ".join(step.decoder for step in trace)
        parts.append(f"Deterministically decoded {len(trace)} layer(s): {chain}.")
    if findings.family.family and findings.family.family != "unknown":
        parts.append(f"Identified family: **{findings.family.family}** "
                     f"({findings.family.confidence * 100:.0f}% confidence).")
    if findings.mitre_techniques:
        ids = ", ".join(h.id for h in findings.mitre_techniques[:6])
        parts.append(f"MITRE ATT&CK: {ids}"
                     + ("…" if len(findings.mitre_techniques) > 6 else "") + ".")
    ioc_counts = [
        (n, len(getattr(findings.iocs, n)))
        for n in ("urls", "ips", "domains", "sha256", "sha1", "md5")
    ]
    ioc_bits = [f"{count} {name}" for name, count in ioc_counts if count]
    if ioc_bits:
        parts.append("IOCs: " + ", ".join(ioc_bits) + ".")
    if findings.lolbas:
        parts.append(f"LOLBAS usage: {', '.join(h.binary for h in findings.lolbas[:5])}.")
    parts.append(f"Verdict: **{findings.verdict}** (risk {findings.risk_score}/100).")
    return " ".join(parts)


def _default_recommendations(findings: Findings) -> List[InvestigationRecommendation]:
    recs: List[InvestigationRecommendation] = []
    if findings.iocs.ips:
        recs.append(InvestigationRecommendation(
            priority="high",
            action=f"Block and hunt for outbound connections to: {', '.join(findings.iocs.ips[:5])}",
            rationale="IP indicators extracted from decoded payload.",
            related_iocs=findings.iocs.ips[:5],
        ))
    if findings.iocs.domains:
        recs.append(InvestigationRecommendation(
            priority="high",
            action=f"Add DNS block / proxy denylist for: {', '.join(findings.iocs.domains[:5])}",
            rationale="Domain indicators extracted from decoded payload.",
            related_iocs=findings.iocs.domains[:5],
        ))
    if findings.family.confidence >= 0.7:
        recs.append(InvestigationRecommendation(
            priority="critical",
            action=f"Trigger IR playbook for {findings.family.family}",
            rationale=f"High-confidence family match ({findings.family.confidence * 100:.0f}%).",
        ))
    if not recs and findings.risk_score > 0:
        recs.append(InvestigationRecommendation(
            priority="medium",
            action="Review the decoded output and confirm the source system's context.",
            rationale="Non-zero risk indicators present but no direct IOCs to action.",
        ))
    return recs


def _is_printable_char(c: str) -> bool:
    """Wide printable check for tail-trim detection.

    ASCII printable + common whitespace are always printable. For Unicode
    codepoints ≥ 0x100 we accept the BMP "text" ranges (Latin Extended,
    Greek, Cyrillic, symbols, CJK, box-drawing …). The C1 control range
    (0x7F–0x9F) and Latin-1 supplement (0xA0–0xFF) are considered "binary
    garbage" because that's what XOR-brute residue typically looks like.
    """
    o = ord(c)
    if 32 <= o < 127:
        return True
    if o in (9, 10, 13):
        return True
    # Real Unicode text: Latin Extended-A onwards.
    if o >= 0x0100:
        return True
    return False


def _find_tail_garbage_start(text: str, *,
                             min_run: int = 8,
                             tail_probe: int = 200,
                             printable_thresh: float = 0.55) -> Optional[int]:
    """Return the index where a binary-garbage tail begins, else None.

    Heuristic:
      * Only consider inputs whose last `tail_probe` chars have a low
        printable ratio (< printable_thresh) — no point trimming clean text.
      * Walk backwards from the end; the tail is the maximal suffix whose
        printable ratio stays below `printable_thresh`.
      * Require the trimmed head to be non-empty and readable
        (printable_ratio ≥ 0.85). Otherwise the payload is uniformly
        garbage and truncation would hide it — better to keep it intact.
      * Require the garbage run to be at least `min_run` bytes so we don't
        chop off legitimate one-off non-printables (LF, tab, etc.).
    """
    n = len(text)
    if n < min_run * 2:
        return None
    # Sample the last 60 chars (or last third of text) — if that region is
    # mostly printable, don't bother walking. Sampling the whole 200-char
    # window misses cases where a short garbage tail is dwarfed by a longer
    # clean head.
    sample_len = min(60, max(min_run * 4, n // 3))
    sample = text[-sample_len:]
    sample_pr = sum(1 for c in sample if _is_printable_char(c))
    if sample_pr / len(sample) >= printable_thresh:
        return None
    # Walk backwards: find the earliest index such that the suffix from
    # there to end has printable_ratio < printable_thresh AND length >= min_run.
    cut = n
    non_print_run = 0
    for i in range(n - 1, -1, -1):
        is_print = _is_printable_char(text[i])
        if not is_print:
            non_print_run += 1
            if non_print_run >= min_run:
                cut = i - non_print_run + 1
        else:
            # break the run only if we've already found a long enough tail
            if cut < n:
                break
            non_print_run = 0
    if cut >= n:
        return None
    head = text[:cut]
    if not head:
        return None
    head_pr = sum(1 for c in head if _is_printable_char(c))
    if head_pr / len(head) < 0.85:
        return None
    return cut


def _trim_tail_garbage(current: str, ctx: AnalysisContext,
                       exec_report: PluginExecutionReport,
                       depth: int) -> str:
    """Attempt a retry on the binary tail; else cleanly truncate.

    Two-phase residual-obfuscation cleanup:
      1. Detect a clean head + binary tail split.
      2. Retry every decoder on the tail alone (one pass, non-recursive)
         and prepend the head if that pass produces readable output.
      3. Otherwise truncate the tail and record a trace note.
    """
    cut = _find_tail_garbage_start(current)
    if cut is None:
        return current
    head, tail = current[:cut], current[cut:]

    # Phase 1 — retry decoding on the tail (single non-recursive pass)
    try:
        tail_fp = fingerprint_compute(tail)
        cands = DecoderRegistry.candidates(tail, tail_fp, ctx, top_n=None)
        cands = [(p, d) for p, d in cands
                 if getattr(p, "category", "") != "intelligence"]
        for plugin, det in cands[:3]:
            try:
                res = plugin.decode(tail, det.args, ctx)
            except Exception:
                continue
            if not res.output or res.output == tail:
                continue
            out_fp = fingerprint_compute(res.output)
            if out_fp.printable_ratio >= 0.9 and out_fp.english_density >= 0.05:
                new_current = head + res.output
                step = TraceStep(
                    layer=depth,
                    decoder=f"{plugin.id} (tail-retry)",
                    schema_version=plugin.schema_version,
                    confidence=det.confidence,
                    why=f"tail-retry: recovered {len(res.output)}B from binary tail",
                    in_len=len(tail),
                    out_len=len(res.output),
                    exec_ms=0,
                    preview=res.output[:200],
                    args=det.args,
                    sub_iocs=res.iocs,
                    mitre_hints=res.mitre_hints,
                    family_hints=res.family_hints,
                    lolbas_hits=res.lolbas_hits,
                    tradecraft=res.tradecraft,
                )
                ctx.trace.add_step(step)
                exec_report.entries.append(PluginExecutionEntry(
                    plugin=plugin.id, layer=depth, outcome="accepted",
                    detect_confidence=det.confidence,
                    detect_reason="tail-retry: residual-obfuscation cleanup",
                    reason="tail successfully re-decoded", exec_ms=0,
                    signals_emitted=bool(res.iocs or res.mitre_hints
                                         or res.family_hints or res.lolbas_hits),
                ))
                return new_current
    except Exception as exc:                                # pragma: no cover
        log.warning("tail-retry pass raised: %s", exc)

    # Phase 2 — no plugin recovered the tail: truncate.
    exec_report.entries.append(PluginExecutionEntry(
        plugin="residual-trim", layer=depth, outcome="accepted",
        detect_confidence=1.0,
        detect_reason=f"binary tail {len(tail)}B detected after clean head",
        reason=f"truncated {len(tail)}B of non-printable residue",
        exec_ms=0, signals_emitted=False,
    ))
    return head + f"\n[… {len(tail)} bytes of residual non-printable data truncated]"


def _run_intelligence_pass(payload: str, fingerprint: Fingerprint,
                           ctx: AnalysisContext, current_depth: int,
                           exec_report: PluginExecutionReport,
                           raw_input: str = "") -> None:
    """Post-decode pass: run every `intelligence`-category plugin over the
    raw input, the final payload AND every trace layer's preview. Family
    signatures may live only in the original input (before over-eager XOR
    or base91 mangles them), in an intermediate layer, or in the final
    decoded blob. Scanning all three guarantees we don't miss a hit
    hidden behind extra decoding.
    """
    from .registry import DecoderRegistry

    # Candidate texts to scan — dedupe by first 512 chars to skip identicals.
    # Raw input is scanned FIRST so a family plugin that fires on plain-text
    # signatures (e.g. AsyncRAT config strings) always wins over noise from
    # aggressive intermediate decoders.
    candidates: List[Tuple[str, int]] = []
    seen_prefix: Set[str] = set()
    if raw_input:
        candidates.append((raw_input, 0))
        seen_prefix.add(raw_input[:512])
    if payload and payload[:512] not in seen_prefix:
        candidates.append((payload, current_depth))
        seen_prefix.add(payload[:512])
    for step in ctx.trace.steps:
        prev = step.preview or ""
        key = prev[:512]
        if not prev or key in seen_prefix:
            continue
        seen_prefix.add(key)
        candidates.append((prev, step.layer))

    for plugin in DecoderRegistry.all():
        if getattr(plugin, "category", "") != "intelligence":
            continue
        fired = False
        for text, layer in candidates:
            try:
                det = plugin.detect(text, fingerprint, ctx)
            except Exception as exc:                          # pragma: no cover
                log.warning("intelligence detect() raised in %s: %s",
                            plugin.id, exc)
                continue
            if det.confidence < 0.05:
                continue
            step_start = time.monotonic_ns()
            try:
                res = plugin.decode(text, det.args, ctx)
            except Exception as exc:                          # pragma: no cover
                exec_report.entries.append(PluginExecutionEntry(
                    plugin=plugin.id, layer=layer,
                    outcome="decode_error",
                    detect_confidence=det.confidence,
                    reason=f"{type(exc).__name__}: {exc}", exec_ms=0,
                ))
                continue
            exec_ms = (time.monotonic_ns() - step_start) // 1_000_000
            emitted = bool(res.family_hints or res.mitre_hints or res.iocs
                           or res.lolbas_hits or res.tradecraft)
            if not emitted:
                continue
            step = TraceStep(
                layer=layer, decoder=plugin.id,
                schema_version=plugin.schema_version,
                confidence=det.confidence, why=det.why,
                in_len=len(text), out_len=len(text),
                exec_ms=int(exec_ms), preview=text[:200],
                args=det.args, sub_iocs=res.iocs,
                mitre_hints=res.mitre_hints,
                family_hints=res.family_hints,
                lolbas_hits=res.lolbas_hits,
                tradecraft=res.tradecraft,
            )
            ctx.trace.add_step(step)
            exec_report.entries.append(PluginExecutionEntry(
                plugin=plugin.id, layer=layer, outcome="accepted",
                detect_confidence=det.confidence,
                detect_reason=det.why,
                reason="intelligence-pass: signals emitted",
                exec_ms=int(exec_ms), signals_emitted=True,
            ))
            fired = True
            break            # one hit per plugin is enough
        if not fired:
            exec_report.entries.append(PluginExecutionEntry(
                plugin=plugin.id, layer=current_depth,
                outcome="detect_zero", detect_confidence=0.0,
                reason="intelligence-pass: no signatures matched",
                exec_ms=0,
            ))


class Orchestrator:
    """Run the deterministic recursive decode + intelligence pipeline."""

    def __init__(self, ctx: Optional[AnalysisContext] = None):
        self.ctx = ctx or AnalysisContext()

    def run(self, payload: str) -> AnalystReport:
        ctx = self.ctx
        started = time.monotonic_ns()

        current = payload or ""

        # Runaway guard — pre-fingerprint gate (Feb-2026). Fingerprint compute
        # is O(n) over the entire payload and entropy calc allocates a Counter
        # of the byte histogram; on a 10 MB pathological input this alone
        # eats seconds. Short-circuit here BEFORE any expensive scan so the
        # request returns a clean "runaway-guard" terminal to the caller
        # instead of a Cloudflare 524 upstream timeout.
        if len(current) > _MAX_INPUT_BYTES_PER_DECODE:
            fp_stub = Fingerprint(
                input_len=len(current), entropy=0.0,
                printable_ratio=0.0, english_density=0.0,
                magic=None,
            )
            ctx.trace.add_fingerprint(fp_stub)
            exec_report = PluginExecutionReport()
            exec_report.entries.append(PluginExecutionEntry(
                plugin="runaway-guard", layer=0, outcome="skipped",
                detect_confidence=1.0,
                reason=(f"payload {len(current)}B exceeds per-decode "
                        f"cap {_MAX_INPUT_BYTES_PER_DECODE}B — refusing to fingerprint"),
                exec_ms=0,
            ))
            elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
            exec_report.layers_run = 0
            exec_report.total_time_ms = int(elapsed_ms)
            findings = Findings()
            breakdown = _compute_confidence_breakdown(findings)
            findings.risk_score = breakdown.total
            findings.verdict = breakdown.verdict
            return AnalystReport(
                output=current[:2048] + (
                    f"\n[… {len(current) - 2048} bytes suppressed by runaway guard]"
                    if len(current) > 2048 else ""
                ),
                trace=[], fingerprint_history=[fp_stub],
                terminal="budget",
                stopped_reason=(f"Runaway guard aborted: payload {len(current)}B "
                                f"exceeds {_MAX_INPUT_BYTES_PER_DECODE}B "
                                "per-decode input cap. No decode attempted."),
                elapsed_ms=int(elapsed_ms),
                engine="orchestrator-v1",
                findings=findings,
                executive_summary=(f"Payload {len(current)}B exceeds the "
                                    f"{_MAX_INPUT_BYTES_PER_DECODE // (1024 * 1024)} MB "
                                    "per-decode cap; no analysis performed."),
                investigation_steps=[],
                confidence_breakdown=breakdown,
                plugin_report=exec_report,
            )

        current_fp = fingerprint_compute(current)
        ctx.trace.add_fingerprint(current_fp)
        best_score = _score(current_fp)
        depth = 0
        terminal = "no-op"
        stopped_reason = ""

        # Production-hardening state
        seen_hashes: Set[str] = {_short_hash(current)}          # loop detection
        # Track (plugin_id, payload_hash) to prevent re-firing same plugin on same bytes
        plugin_payload_seen: Set[tuple] = set()
        cumulative_bytes = len(current)
        exec_report = PluginExecutionReport()

        def _log(**kw):
            exec_report.entries.append(PluginExecutionEntry(**kw))

        while True:
            # 1. Budget check
            reason = ctx.budget.exhausted(depth)
            if reason:
                terminal = "budget"
                stopped_reason = f"Budget exhausted ({reason})"
                break

            # 2. Terminal: already English
            if current_fp.english_density >= _TERMINAL_ENGLISH:
                terminal = "english"
                stopped_reason = (
                    f"english_density={current_fp.english_density:.2f} ≥ {_TERMINAL_ENGLISH}"
                )
                break

            # 3. Terminal: previous step identified a high-confidence family
            if ctx.trace.steps:
                last_step = ctx.trace.steps[-1]
                terminal_family = None
                for fh in last_step.family_hints:
                    if fh.confidence >= _TERMINAL_FAMILY_CONFIDENCE:
                        terminal_family = fh
                        break
                if terminal_family:
                    terminal = "family-identified"
                    stopped_reason = (
                        f"Family '{terminal_family.family}' identified with "
                        f"{terminal_family.confidence * 100:.0f}% confidence — "
                        "stopping recursion at terminal state."
                    )
                    break

            # 4. Candidate discovery — exclude intelligence-only plugins here;
            # they run in the dedicated post-decode intelligence pass so they
            # don't preempt decoder chaining (RC2.1a).
            # Runaway guard (Feb-2026): before invoking detect() on 40+
            # plugins (each of which may scan the entire payload), refuse to
            # even start on payloads over the per-decode input cap. This is
            # the strongest guard against Cloudflare 524 timeouts.
            if len(current) > _MAX_INPUT_BYTES_PER_DECODE:
                _log(plugin="runaway-guard", layer=depth, outcome="skipped",
                     detect_confidence=1.0,
                     reason=f"payload {len(current)}B exceeds per-decode "
                            f"cap {_MAX_INPUT_BYTES_PER_DECODE}B — no candidate discovery",
                     exec_ms=0)
                terminal = "budget"
                stopped_reason = (f"Runaway guard: payload {len(current)}B "
                                   f"exceeds {_MAX_INPUT_BYTES_PER_DECODE}B "
                                   "per-decode input cap.")
                break
            if ctx.budget.elapsed_ms() >= _HARD_ABORT_MS:
                _log(plugin="runaway-guard", layer=depth, outcome="skipped",
                     detect_confidence=1.0,
                     reason=f"pipeline elapsed {ctx.budget.elapsed_ms()}ms "
                            f"≥ hard-abort {_HARD_ABORT_MS}ms",
                     exec_ms=0)
                terminal = "budget"
                stopped_reason = (f"Runaway guard: pipeline elapsed "
                                   f"{ctx.budget.elapsed_ms()}ms exceeded "
                                   f"hard-abort {_HARD_ABORT_MS}ms.")
                break
            # Feb-2026 · deep-recursion guard for highly-repetitive payloads
            # (nested hex-escape streams that peel one layer only to reveal
            # another identical wrapper). At depth ≥ 8 AND input ≥ 512 KB,
            # we've almost certainly entered a runaway; return partial
            # results instead of chasing indefinitely.
            if depth >= _DEEP_RECURSION_DEPTH and len(current) >= _DEEP_RECURSION_INPUT_BYTES:
                _log(plugin="deep-recursion-guard", layer=depth, outcome="skipped",
                     detect_confidence=1.0,
                     reason=(f"depth {depth} ≥ {_DEEP_RECURSION_DEPTH} AND "
                             f"input {len(current)}B ≥ "
                             f"{_DEEP_RECURSION_INPUT_BYTES}B — likely runaway"),
                     exec_ms=0)
                terminal = "budget"
                stopped_reason = (f"Deep-recursion guard: {depth} layers deep "
                                   f"with {len(current)}B still expanding — "
                                   "returning partial result to avoid 60s+ hang.")
                break
            cands_all = DecoderRegistry.candidates(
                current, current_fp, ctx, top_n=None,
            )
            cands = [(p, d) for p, d in cands_all
                     if getattr(p, "category", "") != "intelligence"]
            cands = cands[: ctx.budget.max_branches]
            if not cands:
                # Record every plugin as "skipped: detect_zero"
                for dec in DecoderRegistry.all():
                    _log(plugin=dec.id, layer=depth, outcome="detect_zero",
                         detect_confidence=0.0, reason="detect() returned 0",
                         exec_ms=0)
                if depth == 0:
                    terminal = "no-candidate"
                    stopped_reason = (
                        f"No decoder claimed confidence ≥ 0.05 on the raw input "
                        f"({len(DecoderRegistry.all())} plugins considered)."
                    )
                else:
                    terminal = "complete"
                    stopped_reason = (
                        f"Decoded {depth} layer(s); no plugin claims further transform."
                    )
                break

            # 5. Try candidates
            accepted = None
            current_hash = _short_hash(current)
            for plugin, det in cands:
                # Loop-detection: same plugin can't run on same-content payload twice
                key = (plugin.id, current_hash)
                if key in plugin_payload_seen:
                    _log(plugin=plugin.id, layer=depth, outcome="skipped",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason="loop-detection: same plugin already applied to identical bytes",
                         exec_ms=0)
                    continue

                # Runaway guard: refuse decoders on giant payloads. Prevents a
                # single repetitive-pattern payload from stalling the request
                # long enough to trip a Cloudflare 524 upstream. Downstream
                # decoders never see the oversize input either — they get the
                # untouched `current` and either transform something smaller
                # or the loop terminates cleanly.
                if len(current) > _MAX_INPUT_BYTES_PER_DECODE:
                    _log(plugin=plugin.id, layer=depth, outcome="skipped",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason=f"runaway-guard: input {len(current)}B "
                                f"exceeds per-decode cap {_MAX_INPUT_BYTES_PER_DECODE}B",
                         exec_ms=0)
                    continue

                # Hard-abort budget: never let the pipeline run beyond
                # `_HARD_ABORT_MS` regardless of the plugin's own budget.
                # This is a floor that guards against pathological chains
                # where several decoders each consume ~5s.
                if ctx.budget.elapsed_ms() >= _HARD_ABORT_MS:
                    _log(plugin=plugin.id, layer=depth, outcome="skipped",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason=f"runaway-guard: pipeline elapsed "
                                f"{ctx.budget.elapsed_ms()}ms ≥ hard-abort "
                                f"{_HARD_ABORT_MS}ms",
                         exec_ms=0)
                    terminal = "budget"
                    stopped_reason = (f"Hard-abort budget hit "
                                       f"({_HARD_ABORT_MS}ms) mid-layer.")
                    accepted = "__hard_abort__"
                    break

                step_start = time.monotonic_ns()
                try:
                    res = plugin.decode(current, det.args, ctx)
                except Exception as exc:
                    exec_ms = (time.monotonic_ns() - step_start) // 1_000_000
                    _log(plugin=plugin.id, layer=depth, outcome="decode_error",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason=f"{type(exc).__name__}: {exc}", exec_ms=int(exec_ms))
                    log.warning("decode() raised in %s: %s", plugin.id, exc)
                    continue
                exec_ms = (time.monotonic_ns() - step_start) // 1_000_000
                if exec_ms >= _SLOW_DECODE_WARN_MS:
                    log.warning("slow decoder %s: %dms on %dB input",
                                plugin.id, int(exec_ms), len(current))

                # Memory safety: reject outputs above the per-step ceiling
                if len(res.output) > _MAX_OUTPUT_BYTES:
                    _log(plugin=plugin.id, layer=depth, outcome="skipped",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason=f"output {len(res.output)}B exceeds per-step limit {_MAX_OUTPUT_BYTES}B",
                         exec_ms=int(exec_ms))
                    continue
                if cumulative_bytes + len(res.output) > _MAX_CUMULATIVE_BYTES:
                    _log(plugin=plugin.id, layer=depth, outcome="skipped",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason=f"cumulative {cumulative_bytes + len(res.output)}B "
                                f"exceeds pipeline limit {_MAX_CUMULATIVE_BYTES}B",
                         exec_ms=int(exec_ms))
                    continue

                # Loop-detection on OUTPUT: if we've seen this exact payload already,
                # applying this plugin is guaranteed useless.
                out_hash = _short_hash(res.output)
                if out_hash in seen_hashes:
                    _log(plugin=plugin.id, layer=depth, outcome="skipped",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason="loop-detection: output identical to a previously-seen state",
                         exec_ms=int(exec_ms))
                    plugin_payload_seen.add(key)
                    continue

                cand_fp = fingerprint_compute(res.output)
                cand_score = _score(cand_fp)

                emitted_signals = bool(
                    res.mitre_hints or res.family_hints
                    or res.lolbas_hits or res.tradecraft or res.iocs
                )
                score_improved = cand_score >= best_score + _IMPROVEMENT_EPS
                high_conf_transform = (
                    det.confidence >= 0.7 and res.output and res.output != current
                )
                soft_improvement = (
                    res.output != current and cand_score >= best_score * 0.75
                )
                improved = score_improved or high_conf_transform or soft_improvement

                if improved or emitted_signals:
                    step = TraceStep(
                        layer=depth,
                        decoder=plugin.id,
                        schema_version=plugin.schema_version,
                        confidence=det.confidence,
                        why=det.why,
                        in_len=len(current),
                        out_len=len(res.output),
                        exec_ms=int(exec_ms),
                        preview=res.output[:200],
                        args=det.args,
                        sub_iocs=res.iocs,
                        mitre_hints=res.mitre_hints,
                        family_hints=res.family_hints,
                        lolbas_hits=res.lolbas_hits,
                        tradecraft=res.tradecraft,
                    )
                    ctx.trace.add_step(step)
                    plugin_payload_seen.add(key)
                    _log(plugin=plugin.id, layer=depth, outcome="accepted",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason=("score improved" if score_improved
                                 else ("high-confidence transform" if high_conf_transform
                                       else ("soft improvement" if soft_improvement
                                             else "signals emitted"))),
                         exec_ms=int(exec_ms), signals_emitted=emitted_signals)
                    if improved:
                        current = res.output
                        current_fp = cand_fp
                        ctx.trace.add_fingerprint(current_fp)
                        best_score = cand_score
                        seen_hashes.add(out_hash)
                        cumulative_bytes += len(res.output)
                    accepted = plugin.id
                    if improved:
                        break
                    # signals-only plugins don't advance the loop; try next candidate
                    continue

                _log(plugin=plugin.id, layer=depth, outcome="no_improvement",
                     detect_confidence=det.confidence, detect_reason=det.why,
                     reason=f"score {cand_score:.3f} vs best {best_score:.3f}",
                     exec_ms=int(exec_ms))

            if accepted == "__hard_abort__":
                # Hard-abort was set inside the inner loop; break the outer
                # while so we don't overwrite terminal / stopped_reason.
                break

            if not accepted:
                if depth == 0:
                    terminal = "no-candidate"
                    tried_names = ", ".join(
                        f"{d.id}({dr.confidence:.2f})" for d, dr in cands
                    )
                    stopped_reason = (
                        f"No plugin produced a useful transform on the raw input. "
                        f"Considered: {tried_names}."
                    )
                else:
                    terminal = "complete"
                    tried_names = ", ".join(
                        f"{d.id}({dr.confidence:.2f})" for d, dr in cands
                    )
                    stopped_reason = (
                        f"Decoded {depth} layer(s); no further transform improved the score. "
                        f"Considered at final layer: {tried_names}. "
                        f"Final english_density={current_fp.english_density:.2f}, "
                        f"printable={current_fp.printable_ratio:.2f}."
                    )
                break

            depth += 1

        elapsed_ms = (time.monotonic_ns() - started) // 1_000_000

        # RC2.2 — Residual-obfuscation cleanup pass.
        # After the decode loop terminates, look for a clean-head + binary-tail
        # split (typical when XOR brute recovers most but not all of the
        # payload). Retry decoding on the tail; if no plugin can salvage it,
        # cleanly truncate to keep the analyst output panel readable.
        try:
            trimmed = _trim_tail_garbage(current, ctx, exec_report, depth)
            if trimmed != current:
                current = trimmed
                current_fp = fingerprint_compute(current)
                ctx.trace.add_fingerprint(current_fp)
        except Exception as exc:                                # pragma: no cover
            log.warning("residual-trim pass raised: %s", exc)

        # RC2.1a — Post-decode intelligence pass.
        # After the decode chain terminates, run every `intelligence`-category
        # plugin over the final payload AND the original raw input. Family
        # plugins can then confirm or override earlier heuristic hints and
        # detect signatures that live in the raw payload even when the
        # orchestrator's XOR/base91 heuristics produced downstream garbage.
        _run_intelligence_pass(current, current_fp, ctx, depth, exec_report,
                               raw_input=payload or "")

        # Aggregate intelligence and build explainable confidence
        findings = _aggregate_findings(list(ctx.trace.steps))
        # RC3.1 · run global LOLBAS scanner on final decoded surface so
        # analysts get certutil/mshta/regsvr32/bitsadmin/… coverage even
        # when the wrapper decoder didn't fire.
        _post_decode_lolbas_scan(findings, current, payload or "")
        breakdown = _compute_confidence_breakdown(
            findings,
            decode_depth=len(ctx.trace.steps),
            trace_decoders=[s.decoder for s in ctx.trace.steps],
        )
        findings.risk_score = breakdown.total
        findings.verdict = breakdown.verdict

        # RC2.1a — promote terminal state if the intelligence pass surfaced
        # a high-confidence family match. The main decode loop couldn't do
        # this because family plugins run only after it terminates.
        if (terminal != "family-identified"
                and findings.family.confidence >= _TERMINAL_FAMILY_CONFIDENCE):
            terminal = "family-identified"
            stopped_reason = (
                f"Post-decode intelligence pass identified family "
                f"'{findings.family.family}' with "
                f"{findings.family.confidence * 100:.0f}% confidence."
            )

        summary = _executive_summary(list(ctx.trace.steps), findings)
        recommendations = _default_recommendations(findings)

        exec_report.layers_run = len(ctx.trace.steps)
        exec_report.total_time_ms = int(elapsed_ms)
        exec_report.budget_snapshot = {
            "max_depth": ctx.budget.max_depth,
            "max_branches": ctx.budget.max_branches,
            "wall_time_ms": ctx.budget.wall_time_ms,
            "elapsed_ms": ctx.budget.elapsed_ms(),
        }

        return AnalystReport(
            output=current,
            trace=list(ctx.trace.steps),
            fingerprint_history=list(ctx.trace.fingerprints),
            terminal=terminal,
            stopped_reason=stopped_reason,
            elapsed_ms=int(elapsed_ms),
            engine="orchestrator-v1",
            findings=findings,
            executive_summary=summary,
            investigation_steps=recommendations,
            confidence_breakdown=breakdown,
            plugin_report=exec_report,
        )
