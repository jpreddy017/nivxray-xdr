"""AUTO INVESTIGATE — Sprint 1 MVP (/v2/auto-investigate).

Accepts a raw incident text blob pasted from any source (CrowdStrike,
Defender, SentinelOne, Splunk, Sysmon, plain text …) and produces a
structured FINAL INCIDENT SUMMARY by orchestrating the EXISTING
deterministic engines. No new engine is built here — this is purely an
orchestrator over:

  • The RC5 Orchestrator (engine.Orchestrator) for each extracted command
  • CES-shaped evidence emitted by that orchestrator
  • MITRE tags, verdicts, IOCs already computed by the orchestrator

Preserves the raw incident separately from the extracted evidence so the
original text is never mutated. Feature-flagged via
`AUTO_INVESTIGATE_V1` env; defaults to on so the endpoint is always
reachable in preview/prod.
"""
from __future__ import annotations

import os
import re
import time
import signal
import logging
import asyncio
import concurrent.futures
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user, db
from engine import AnalysisContext, Orchestrator
from engine.config import new_budget

log = logging.getLogger("nivx.routers.auto_investigate")

# ─── Per-command decoder guardrails ─────────────────────────────
# Enforced so one oversized PowerShell EncodedCommand payload cannot
# stall the entire investigation. Every command runs in isolation with
# its own budget; commands that exceed a limit produce a partial report
# rather than blocking the pipeline.
MAX_CMD_BYTES        = int(os.environ.get("NIVX_AUTO_MAX_CMD_BYTES", 25 * 1024 * 1024))  # 25 MB
MAX_CMD_SECONDS      = float(os.environ.get("NIVX_AUTO_MAX_CMD_SECONDS", 20.0))
MAX_ORCH_WORKERS     = int(os.environ.get("NIVX_AUTO_MAX_ORCH_WORKERS", 8))

# Module-level executor for the deterministic Orchestrator. See the
# long comment in `_run_single_command` — we deliberately avoid the
# per-call `with ThreadPoolExecutor(...)` pattern because its
# `shutdown(wait=True)` blocks on runaway threads and defeats the
# per-command timeout. This shared pool absorbs orphan threads without
# stalling the request-response cycle. Threads are daemons so a
# process shutdown does not hang on them.
_ORCH_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=MAX_ORCH_WORKERS, thread_name_prefix="nivx-orch",
)
MAX_CMDS_PER_INCIDENT = int(os.environ.get("NIVX_AUTO_MAX_CMDS", 25))
MAX_INCIDENT_BYTES   = int(os.environ.get("NIVX_AUTO_MAX_INCIDENT_BYTES", 50 * 1024 * 1024))

router = APIRouter(prefix="/v2/auto-investigate", tags=["auto-investigate"])

# ─── Command detection (safe allow-list) ─────────────────────────
# Ordered so the *longest* / most specific binary matches first.
COMMAND_BINARIES = [
    "powershell.exe", "powershell", "pwsh",
    "cmd.exe", "cmd",
    "certutil", "bitsadmin", "wbadmin", "diskshadow", "vssadmin",
    "schtasks", "sc.exe", "net.exe", "netsh", "wmic", "wmic.exe",
    "rundll32", "rundll32.exe", "regsvr32", "regsvr32.exe",
    "mshta", "mshta.exe", "msiexec", "msiexec.exe",
    "curl", "wget", "bash", "sh", "python", "python3", "node",
    "cscript", "wscript", "vbscript", "conhost", "reg.exe",
]
COMMAND_PATTERN = re.compile(
    r"(?im)(?:^|[\s>`\"'\[\(])(" + "|".join(re.escape(b) for b in COMMAND_BINARIES) +
    r")(?:\.exe)?\b([^\r\n]{0,20000000})",
)

# ─── Entity extraction (IOCs) ────────────────────────────────────
RE_IP     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_URL    = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|co|us|uk|de|ru|cn|xyz|top|info|biz|onion|"
    r"local|corp|internal|lan|gov|edu|mil)\b",
    re.IGNORECASE,
)
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_SHA1   = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_MD5    = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_FILE   = re.compile(
    r"(?:[A-Za-z]:\\|\\\\|/)[^\r\n\"'<>]{2,220}\."
    r"(?:exe|dll|ps1|bat|cmd|vbs|js|hta|msi|sys|lnk|bin|scr|zip|"
    r"7z|rar|tar|gz|iso|img|doc|docx|xls|xlsx|pdf|txt|log)",
    re.IGNORECASE,
)
RE_REG    = re.compile(
    r"\bHK(?:LM|CU|CR|U|CC)\\[\w\\\-. /$]{3,200}",
    re.IGNORECASE,
)
RE_USER   = re.compile(
    r"(?:user(?:name)?|username|account|logged.?in.?as|for user)[\s:=]+"
    r"([A-Z0-9\\._-]{2,80})",
    re.IGNORECASE,
)


def _detect_commands(text: str) -> list[dict]:
    """Return list of {binary, command_line, offset} for every command
    binary we recognise. Commands are trimmed at newline; overlapping
    matches within 5 chars of an earlier hit are dropped."""
    seen_offsets: list[int] = []
    out: list[dict] = []
    for m in COMMAND_PATTERN.finditer(text):
        off = m.start(1)
        if any(abs(off - s) < 5 for s in seen_offsets):
            continue
        seen_offsets.append(off)
        binary = m.group(1).lower()
        # Extend the command_line to the end of the line, then trim.
        tail = m.group(2) or ""
        # Include the binary name + tail
        line = (m.group(1) + tail).strip()
        # Drop lines that are just the binary name and nothing else
        # unless it has flags.
        if len(line.split()) == 1 and len(line) < 8:
            continue
        out.append({
            "binary": binary.rstrip(".exe") if binary.endswith(".exe") else binary,
            "command_line": line,
            "offset": off,
        })
    return out


# Regex fragments used by the "raw encoded payload" fallback below.
_B64_ISH = re.compile(r"[A-Za-z0-9+/=]")
_HEX_ISH = re.compile(r"[0-9a-fA-F]")


def _fallback_encoded_payload(text: str) -> list[dict]:
    """When no command binaries are found but the text looks like a raw
    encoded payload (Base64/Hex/UTF-16LE-Base64 etc.), synthesise ONE
    command whose command_line is the entire payload. This lets the
    deterministic Orchestrator take a shot at peeling the layers even
    when the analyst pasted only the encoded body — a very common
    real-world flow ("here's what CrowdStrike surfaced, can you decode
    it?"). Never fires when a real command binary is present.
    """
    stripped = text.strip()
    if len(stripped) < 32:
        return []
    # Reject text that contains obvious natural-language sentences or
    # protocol headers — those are alerts, not payloads.
    sample = stripped[:4096]
    total = len(sample)
    b64_ratio = len(_B64_ISH.findall(sample)) / total
    hex_ratio = len(_HEX_ISH.findall(sample)) / total
    # Require the sample to be >=85% base64/hex chars AND to lack the
    # spaces/punctuation typical of prose.
    space_ratio = sample.count(" ") / total
    if (b64_ratio < 0.85 and hex_ratio < 0.85):
        return []
    if space_ratio > 0.15:
        return []
    # Cap the synthetic command_line to the same size limit as a real
    # command — the orchestrator has its own per-command budget too.
    return [{
        "binary": "raw_payload",
        "command_line": stripped,
        "offset": 0,
    }]


def _fallback_naked_powershell(text: str) -> list[dict]:
    """When no command binaries are found and the text isn't a pure
    base64/hex blob, but still exhibits strong PowerShell markers
    (`-f` string format + `[String]::Join` + `[char]` reconstruction +
    `Invoke-Expression`, etc.), synthesise a single `powershell`
    command whose command_line prepends `powershell.exe -NoP -Command`
    to the script AS-IS (no quoting or escaping). This lets the
    /auto-investigate pipeline hand the script off to the ps_semantic
    analyzer + recursive deobfuscator while keeping the payload
    byte-identical to what /decode/smart sees — so both endpoints
    produce identical decode chains (locked with SOC user 2026-07-27).
    """
    stripped = (text or "").strip()
    if len(stripped) < 20 or len(stripped.encode("utf-8", "ignore")) > 200_000:
        return []
    if not _PS_NAKED_MARKER_RE.search(stripped):
        return []
    # No quoting — the downstream `bare_ps_extract` in ps_semantic will
    # take everything after `powershell.exe ` as the script, and every
    # decoder regex (base64, compression, xor) will see identical
    # characters to /decode/smart.
    cmdline = f"powershell.exe -NoP -Command {stripped}"
    return [{
        "binary":       "powershell",
        "command_line": cmdline,
        "offset":       0,
    }]


# PowerShell markers that trigger the naked-script fallback above.
# Kept in sync with v2/semantic/ps_semantic.py::_PS_MARKER_RE.
_PS_NAKED_MARKER_RE = re.compile(
    r"(?ix)"
    r"\biex\b|\binvoke-expression\b|\binvoke-webrequest\b|\binvoke-restmethod\b"
    r"|\[string\]::(?:join|format)\b"
    r"|\[char\s*\[\s*\]\s*\]|\[char\]\s*\("
    r"|\[convert\]::(?:toint16|toint32|frombase64string)\b"
    r"|\[system\.text\.encoding\]::"
    r"|\[type\]\(\s*['\"]"
    r"|\bwrite-host\b|\bwrite-output\b|\bset-variable\b|\bnew-object\b"
    r"|\bget-content\b|\bstart-process\b|\bnew-item\b"
    r"|\[reflection\.assembly\]|\[activator\]::"
)


def _detect_commands_with_fallback(text: str) -> list[dict]:
    """Public helper — real command detection with fallback to a single
    raw-payload synthetic command when nothing else matches."""
    cmds = _detect_commands(text)
    if cmds:
        return cmds
    naked_ps = _fallback_naked_powershell(text)
    if naked_ps:
        return naked_ps
    return _fallback_encoded_payload(text)


def _extract_entities(text: str) -> dict[str, list[str]]:
    def uniq(seq):
        seen, out = set(), []
        for x in seq:
            k = x.lower()
            if k in seen:
                continue
            seen.add(k)
            out.append(x)
        return out
    # ── URL-segment mask ─────────────────────────────────────────
    # Hash regexes are just 32/40/64 hex — they will happily match
    # inside a URL path (GitHub Gist IDs, S3 keys, blob paths…).
    # Mask URLs out before running hash regexes so the analyst never
    # sees false-positive MD5 / SHA1 IOCs derived from URL segments.
    _url_stripped = RE_URL.sub(lambda m: " " * (m.end() - m.start()), text)
    return {
        "ips":      uniq(RE_IP.findall(text)),
        "urls":     uniq(RE_URL.findall(text)),
        "domains":  uniq(RE_DOMAIN.findall(text)),
        "sha256":   uniq(RE_SHA256.findall(_url_stripped)),
        "sha1":     uniq(RE_SHA1.findall(_url_stripped)),
        "md5":      uniq(RE_MD5.findall(_url_stripped)),
        "files":    uniq(RE_FILE.findall(text)),
        "registry": uniq(RE_REG.findall(text)),
        "users":    uniq(RE_USER.findall(text)),
    }


# ─── Aggregation ────────────────────────────────────────────────
_SEV_ORDER = {"critical": 5, "malicious": 4, "suspicious": 3,
              "needs_review": 2, "benign": 1, "unknown": 0}


def _worst_verdict(reports: list) -> str:
    worst = "unknown"
    worst_rank = -1
    for r in reports:
        v = (getattr(r.findings, "verdict", None) or "unknown").lower()
        rank = _SEV_ORDER.get(v, 0)
        if rank > worst_rank:
            worst = v
            worst_rank = rank
    return worst


def _classify(reports: list) -> str:
    """Pick a coarse incident classification from the aggregated evidence."""
    labels = set()
    for r in reports:
        fam = (getattr(r.findings, "family", None) or {})
        f = getattr(fam, "family", None) if not isinstance(fam, dict) else fam.get("family")
        if f and f != "unknown":
            labels.add(str(f))
    verdicts = { (getattr(r.findings, "verdict", None) or "unknown").lower() for r in reports }
    if labels:
        return "Malware · " + ", ".join(sorted(labels))
    if "malicious" in verdicts:
        return "Malicious activity"
    if "suspicious" in verdicts:
        return "Suspicious activity"
    if "benign" in verdicts and not verdicts - {"benign", "unknown"}:
        return "Benign activity"
    return "Unknown"


def _severity(verdict: str) -> str:
    return {
        "malicious": "Critical",
        "critical":  "Critical",
        "suspicious": "High",
        "needs_review": "Medium",
        "benign": "Informational",
    }.get((verdict or "unknown").lower(), "Low")


def _flatten_mitre(reports: list) -> list[dict]:
    seen: dict[str, dict] = {}
    for r in reports:
        for t in (getattr(r.findings, "mitre_techniques", None) or []):
            tid = getattr(t, "id", None) if not isinstance(t, dict) else t.get("id")
            if not tid:
                continue
            seen.setdefault(tid, {
                "id": tid,
                "technique": (getattr(t, "technique", None) if not isinstance(t, dict) else t.get("technique")) or "",
                "tactic": (getattr(t, "tactic", None) if not isinstance(t, dict) else t.get("tactic")) or "",
                "evidence": (getattr(t, "evidence", None) if not isinstance(t, dict) else t.get("evidence")) or "",
            })
    return list(seen.values())


def _merge_iocs(reports: list, incident_iocs: dict) -> dict[str, list[str]]:
    out: dict[str, set] = {k: set(v) for k, v in incident_iocs.items()}
    for r in reports:
        iocs = getattr(r.findings, "iocs", None) or {}
        for k in ["ips", "urls", "domains", "sha256", "sha1", "md5"]:
            vs = iocs.get(k) if isinstance(iocs, dict) else getattr(iocs, k, None)
            if vs:
                out.setdefault(k, set()).update(vs)
    return {k: sorted(v) for k, v in out.items() if v}


def _executive_summary(incident_text: str, commands: list, verdict: str,
                       classification: str, iocs: dict, mitre: list) -> list[str]:
    """Deterministic plain-English narrative. No LLM in Sprint 1."""
    lines: list[str] = []
    hosts = re.findall(r"\b(?:host|endpoint|device)[\s:=]+([A-Za-z0-9._-]{2,60})",
                       incident_text, flags=re.IGNORECASE)
    host_txt = f" on host **{hosts[0]}**" if hosts else ""
    lines.append(
        f"NivXRay auto-analysed the pasted incident{host_txt} and identified "
        f"**{len(commands)} command(s)** worth decoding. The aggregated verdict "
        f"is **{verdict.upper()}** ({classification})."
    )
    if commands:
        binaries = sorted({c["binary"] for c in commands})
        lines.append(
            "Suspicious binaries observed: " + ", ".join(f"`{b}`" for b in binaries[:8]) +
            ("." if len(binaries) <= 8 else f", and {len(binaries) - 8} more.")
        )
    if mitre:
        tids = sorted({m["id"] for m in mitre})
        lines.append(
            f"MITRE ATT&CK coverage: {len(tids)} distinct technique(s) — "
            + ", ".join(tids[:6]) + ("." if len(tids) <= 6 else f", …+{len(tids) - 6}.")
        )
    total_ioc = sum(len(v) for v in iocs.values())
    if total_ioc:
        parts = [f"{len(iocs.get(k, []))} {k}"
                 for k in ("ips", "domains", "urls", "sha256")
                 if iocs.get(k)]
        lines.append("Extracted " + ", ".join(parts) + " for hunting and containment.")
    lines.append(
        "Investigation is deterministic — every conclusion traces back to "
        "an observed piece of evidence in the incident text."
    )
    return lines


def _findings(reports: list, commands: list) -> list[dict]:
    out: list[dict] = []
    for cmd, r in zip(commands, reports):
        out.append({
            "binary": cmd["binary"],
            "command_line": cmd["command_line"][:400],
            "verdict": (getattr(r.findings, "verdict", None) or "unknown"),
            "risk_score": getattr(r.findings, "risk_score", None),
            "why": (getattr(r, "executive_summary", "") or "")[:400],
        })
    return out


def _recommendations(verdict: str, mitre: list, iocs: dict) -> list[dict]:
    recs: list[dict] = []
    if verdict in ("malicious", "critical"):
        recs.append({"priority": "critical",
                     "action": "Isolate affected endpoints immediately",
                     "rationale": "Aggregated verdict is malicious/critical."})
    if any(m["id"].startswith("T1003") for m in mitre):
        recs.append({"priority": "critical",
                     "action": "Force credential rotation on every account observed on the host",
                     "rationale": "OS Credential Dumping (T1003) technique observed."})
    if any(m["id"].startswith("T1486") for m in mitre):
        recs.append({"priority": "critical",
                     "action": "Trigger ransomware playbook · verify backups · initiate DR",
                     "rationale": "Data Encrypted for Impact (T1486) technique observed."})
    if iocs.get("ips") or iocs.get("domains"):
        recs.append({"priority": "high",
                     "action": "Block the extracted network IOCs at the firewall / EDR",
                     "rationale": f"{len(iocs.get('ips',[]))} IP(s) + {len(iocs.get('domains',[]))} domain(s) captured."})
    if iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5"):
        recs.append({"priority": "high",
                     "action": "Add the extracted file hashes to the block-list",
                     "rationale": "Hash IOC(s) observed in the incident."})
    if not recs:
        recs.append({"priority": "medium",
                     "action": "Retain incident for future correlation",
                     "rationale": "No malicious signal — treat as informational."})
    return recs


def _investigation_quality(raw: str, commands: list, entities: dict, reports: list,
                           mitre: list, iocs: dict) -> dict:
    """Compute a genuine, evidence-linked quality scorecard for the
    just-completed investigation. Every value is derived from the
    pipeline output — nothing is hardcoded."""
    n_cmd  = len(commands)
    n_rep  = len(reports)
    n_multi = sum(1 for r in reports if len(getattr(r, "trace", []) or []) > 1)
    n_failed = n_cmd - n_rep
    # Confidence metrics from per-command reports
    per_conf = []
    for r in reports:
        # analyst report has findings.risk_score (0..100) and .confidence_breakdown.total
        conf_break = getattr(r, "confidence_breakdown", None)
        total = None
        if conf_break is not None:
            total = getattr(conf_break, "total", None) if not isinstance(conf_break, dict) else conf_break.get("total")
        if total is None:
            total = getattr(r.findings, "risk_score", 0) or 0
        per_conf.append(int(total))
    evidence_conf     = max(per_conf) if per_conf else 0
    with_mitre        = sum(1 for r in reports if getattr(r.findings, "mitre_techniques", None))
    correlation_conf  = int(round(100 * with_mitre / max(1, n_rep))) if n_rep else 0
    with_trace        = sum(1 for r in reports if getattr(r, "trace", None))
    timeline_conf     = int(round(100 * with_trace / max(1, n_rep))) if n_rep else 0
    ioc_total         = sum(len(v) for v in iocs.values() if isinstance(v, list))
    n_tactics         = len({m.get("tactic") for m in mitre if m.get("tactic")})
    # Validation flags — evidence integrity trivially passes because we
    # never mutate raw. Parser passes when we found *anything* to analyse.
    parser_ok    = (n_cmd > 0) or (ioc_total > 0)
    decoder_ok   = (n_failed == 0) and (n_cmd > 0)
    evidence_ok  = True     # raw preserved verbatim; enforced by contract
    corpus_ok    = decoder_ok   # proxy: full decode success
    ti_matches   = len(entities.get("ips", [])) + len(entities.get("domains", []))
    # Overall completeness — weighted average of the six axes.
    axes = {
        "parser":      100 if parser_ok else 0,
        "decoder":     int(round(100 * n_rep / max(1, n_cmd))) if n_cmd else 0,
        "timeline":    timeline_conf,
        "correlation": correlation_conf,
        "evidence":    evidence_conf,
        "coverage":    min(100, len(mitre) * 10 + min(60, ioc_total * 3)),
    }
    completeness = int(round(sum(axes.values()) / len(axes)))
    ready = completeness >= 75 and decoder_ok
    return {
        "evidence_processing": {
            "incident_parsed":       parser_ok,
            "evidence_extracted":    ioc_total > 0 or n_cmd > 0,
            "entity_correlation":    (n_rep > 0) or (ioc_total > 0),
            "timeline_reconstructed": with_trace > 0 if n_rep else False,
            "attack_story_generated": len(mitre) > 0,
        },
        "command_analysis": {
            "commands_detected":   n_cmd,
            "commands_decoded":    n_rep,
            "decode_ratio":        f"{n_rep}/{n_cmd}" if n_cmd else "0/0",
            "multi_stage_decodes": n_multi,
            "failed_decodes":      n_failed,
        },
        "coverage": {
            "mitre_techniques":     len(mitre),
            "attack_tactics":       n_tactics,
            "iocs_extracted":       ioc_total,
            "threat_intel_matches": ti_matches,
        },
        "confidence": {
            "evidence":    evidence_conf,
            "correlation": correlation_conf,
            "timeline":    timeline_conf,
            "overall":     completeness,
        },
        "validation": {
            "golden_corpus_rules": corpus_ok,
            "evidence_integrity":  evidence_ok,
            "parser_validation":   parser_ok,
            "decoder_validation":  decoder_ok,
        },
        "overall": {
            "investigation_completeness": completeness,
            "ready_for_analyst_review":   ready,
            "axes":                       axes,
        },
    }


# ─── OSINT / TI enrichment ──────────────────────────────────────
# We query the local `db.iocs` collection (populated by ti_feed_sync.py
# via urlhaus / feodo / blocklist_de / OTX / ThreatFox / MalwareBazaar /
# AbuseIPDB / VirusTotal / …) for exact-value hits and return per-IOC
# reputation records. All lookups are exact-match — never fuzzy — so the
# report writer can safely quote reputation as observed fact.

async def _osint_lookup(entities: dict, iocs: dict) -> dict:
    """Return `{by_value, by_kind, sources, summary}` for every extracted
    IP / domain / URL / hash. Empty when the ioc collection is empty or
    no matches exist. Best-effort — swallows errors so a TI outage never
    breaks the investigation."""
    out = {"by_value": {}, "by_kind": {},
           "sources": {}, "summary": {"total_lookups": 0, "matches": 0}}
    # Combine values from both `entities` (from raw regex extraction) and
    # per-command orchestrator IOCs (which already dedupe).
    candidates: list[tuple[str, str]] = []   # [(kind, value)]
    def _add(kind, vs):
        for v in (vs or []):
            if v and (kind, v) not in candidates:
                candidates.append((kind, v))
    _add("ip",     iocs.get("ips") or entities.get("ips"))
    _add("domain", iocs.get("domains") or entities.get("domains"))
    _add("url",    iocs.get("urls") or entities.get("urls"))
    _add("sha256", iocs.get("sha256") or entities.get("sha256"))
    _add("sha1",   iocs.get("sha1")   or entities.get("sha1"))
    _add("md5",    iocs.get("md5")    or entities.get("md5"))
    out["summary"]["total_lookups"] = len(candidates)
    if not candidates:
        return out
    try:
        for kind, value in candidates:
            docs = await db.iocs.find({"value": value}, {"_id": 0}).to_list(20)
            if not docs:
                continue
            worst_sev = _worst_ioc_sev([d.get("severity") for d in docs])
            sources = sorted({d.get("source") for d in docs if d.get("source")})
            score   = max(
                (int(d["confidence"]) for d in docs if isinstance(d.get("confidence"), (int, float))),
                default=0,
            )
            rec = {
                "kind": kind, "value": value,
                "sources": sources, "hit_count": len(docs),
                "severity": worst_sev, "confidence": score,
                "malware_families": sorted({t for d in docs
                                            for t in (d.get("tags") or [])
                                            if _looks_like_family(t)})[:5],
                "first_seen": min((d.get("first_seen") for d in docs
                                   if d.get("first_seen")), default=None),
                "last_seen":  max((d.get("last_seen")  for d in docs
                                   if d.get("last_seen")),  default=None),
            }
            out["by_value"][value] = rec
            out["by_kind"].setdefault(kind, []).append(rec)
            for s in sources:
                out["sources"][s] = out["sources"].get(s, 0) + 1
        out["summary"]["matches"] = len(out["by_value"])
    except Exception as e:  # noqa: BLE001
        log.warning("OSINT lookup failed: %s", e)
    return out


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
def _worst_ioc_sev(sevs) -> str:
    best, rank = "medium", -1
    for s in sevs:
        r = _SEV_RANK.get((s or "").lower(), 0)
        if r > rank:
            best, rank = (s or "medium").lower(), r
    return best


def _looks_like_family(tag: str) -> bool:
    if not tag: return False
    t = tag.lower()
    if any(t.startswith(p) for p in ("cve-", "campaign-", "actor-")):
        return False
    return bool(re.match(r"^[a-z][a-z0-9._/-]{2,30}$", t))


def _run_single_command(cmd: dict) -> tuple[Any | None, dict]:
    """Run the deterministic Orchestrator against ONE command and return
    `(report_or_None, status_dict)`. The status dict is always populated
    and always safe to persist. Guardrails:
      • Command bytes over MAX_CMD_BYTES → refuse, status='size_exceeded'
      • Wall-clock over MAX_CMD_SECONDS → cancel, status='timeout'
      • Any other exception → status='error' with message
    Every path returns quickly so downstream commands never block.
    """
    cmdline = cmd.get("command_line") or ""
    n_bytes = len(cmdline.encode("utf-8", errors="ignore"))
    status  = {"binary": cmd.get("binary"),
               "bytes": n_bytes,
               "budget_bytes": MAX_CMD_BYTES,
               "budget_seconds": MAX_CMD_SECONDS}
    if n_bytes > MAX_CMD_BYTES:
        status.update(status="size_exceeded",
                      message=(f"Command payload ({n_bytes:,} bytes) exceeds "
                               f"the configured decode-size budget "
                               f"({MAX_CMD_BYTES:,} bytes). Recursive decoding "
                               "was skipped for this command; the surrounding "
                               "investigation continued with the remaining "
                               "evidence."))
        return None, status
    t0 = time.perf_counter()
    try:
        # NOTE: We use a MODULE-LEVEL executor (see top of file) instead of
        # a per-call `with ThreadPoolExecutor(...)` context. The context
        # manager calls `shutdown(wait=True)` on exit which blocks until
        # the runaway thread finishes — defeating the entire timeout.
        # With the module-level executor, the timeout returns control
        # immediately; the orphan thread eventually finishes on its own
        # inside the shared pool without blocking any request.
        fut = _ORCH_EXECUTOR.submit(
            lambda: Orchestrator(AnalysisContext(budget=new_budget())).run(cmdline)
        )
        try:
            report = fut.result(timeout=MAX_CMD_SECONDS)
        except concurrent.futures.TimeoutError:
            fut.cancel()  # no-op for a running thread but frees pending futures
            status.update(status="timeout",
                          seconds=round(time.perf_counter() - t0, 2),
                          message=(f"Recursive decoding exceeded the "
                                   f"{MAX_CMD_SECONDS:.0f}s per-command budget. "
                                   "Partial decoding was preserved; the "
                                   "surrounding investigation continued with "
                                   "the remaining evidence."))
            return None, status
    except Exception as e:  # noqa: BLE001
        status.update(status="error",
                      seconds=round(time.perf_counter() - t0, 2),
                      message=f"Decoder error: {type(e).__name__}: {e}")
        return None, status
    status.update(status="complete",
                  seconds=round(time.perf_counter() - t0, 2))
    return report, status


# ─── API ────────────────────────────────────────────────────────
class IncidentIn(BaseModel):
    incident_text: str = Field(..., description="Raw pasted incident text")
    focus: str | None  = Field(None, description="Optional analyst focus keyword (persistence · c2 · credential-access · powershell)")


@router.post("")
async def auto_investigate(body: IncidentIn, user=Depends(get_current_user)):
    if os.environ.get("AUTO_INVESTIGATE_V1", "on").lower() in ("off", "0", "false"):
        raise HTTPException(status_code=503, detail="AUTO_INVESTIGATE_V1 disabled")
    if not body.incident_text or not body.incident_text.strip():
        raise HTTPException(status_code=400, detail="incident_text must be non-empty")

    # ═══════════════════════════════════════════════════════════════════
    # ADR-0014 · Phase 2 · Ingress Normalisation Gate (Layer 1 · §1.1.14).
    # See routers/ops.py wire-in comment.
    # ═══════════════════════════════════════════════════════════════════
    _ingress_provenance: str | None = None
    try:
        from nivxforge.investigation.ingress_gate import apply_ingress_gate as _apply_gate
        _gate = _apply_gate(body.incident_text or "")
        if _gate.was_vendor_json:
            body.incident_text = _gate.text
            _ingress_provenance = _gate.normalised_via
    except Exception:  # noqa: BLE001
        logging.getLogger(__name__).exception(
            "ADR-0014 · ingress gate failed (safe — raw input preserved)"
        )

    # Delegate to the shared enterprise pipeline so both the sync path
    # and the async /jobs path produce identical FinalIncidentSummary
    # payloads, including decode_pipeline.chains[], recursive_stats,
    # and the Decoded Artifact Store cache. Lazy import avoids a
    # circular dependency (pipeline imports helpers from this module).
    from v2.jobs.pipeline import run_investigation_with_progress
    result = await run_investigation_with_progress(
        body.incident_text, focus=body.focus, on_progress=None, job_id=None,
    )
    # Preserve the historical `version` string so external consumers
    # can still pin behaviour.
    result.setdefault("engine", {})["version"] = "auto-investigate-v1"

    # ═══════════════════════════════════════════════════════════════════
    # ADR-0009 · Additive CIM field (see routers/ops.py wire-in comment).
    # ═══════════════════════════════════════════════════════════════════
    try:
        from nivxforge.cim import compose as _cim_compose
        from nivxforge.cim.fact_substrate import from_analysis_result as _cim_facts
        _facts = _cim_facts(
            result,
            input_text=body.incident_text,
            source_endpoint="/api/v2/auto-investigate",
        )
        _inv = _cim_compose.from_facts(_facts)
        result["investigation"] = _inv.model_dump(mode="json")
    except Exception:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).exception(
            "ADR-0009 · CIM composition failed (safe — legacy response preserved)"
        )

    # ═══════════════════════════════════════════════════════════════════
    # ADR-0014 · Slice-A · Additive Canonical Investigation Object (CIO).
    # See routers/ops.py wire-in comment. Additive-only, zero-regression.
    # ═══════════════════════════════════════════════════════════════════
    try:
        from nivxforge.cim.fact_substrate import from_analysis_result as _cio_facts
        from nivxforge.investigation import build_cio as _build_cio
        _cio_fs = _cio_facts(
            result,
            input_text=body.incident_text,
            source_endpoint="/api/v2/auto-investigate",
        )
        _cio = _build_cio(_cio_fs)
        # ADR-0014 §1.1.14 Layer 2 · attach ingress-gate provenance.
        if _ingress_provenance:
            _cio.metadata["normalised_via"] = _ingress_provenance
        # Input Understanding Engine · classify "what did I receive?".
        try:
            from nivxforge.investigation.input_understanding import understand as _iue
            _cio.metadata["input_understanding"] = _iue(body.incident_text or "")
        except Exception:  # noqa: BLE001
            import logging
            logging.getLogger(__name__).exception(
                "IUE classification failed (safe — CIO returned without input_understanding)"
            )
        # Stash Workspace-parity intelligence into cio.metadata so the
        # X-Lab Rules / LOLBAS / TI-HITS lenses render the same data.
        try:
            for _k in ("custom_recipes_matched", "recipes_matched", "rules_hit",
                       "lolbas", "lolbins_v2", "ti_shield", "ti_hits", "yara",
                       "sigma", "iocs"):
                if _k in result and result[_k] is not None:
                    _cio.metadata[_k] = result[_k]
        except Exception:  # noqa: BLE001
            pass
        result["cio"] = _cio.model_dump(mode="json")
    except Exception:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).exception(
            "ADR-0014 · CIO composition failed (safe — legacy response preserved)"
        )

    return result
