"""
IDA · Artifact Router (recursive investigation seed)
────────────────────────────────────────────────────
Frozen 2026-03-01 · P0 · Rule R20.

**Extracted artifacts are investigation seeds, not display strings.**

When IDA-4 extracts a command from a threat report, the platform
must NOT just render it — it must feed that command back through
the same deterministic investigation pipeline the analyst would
have triggered by pasting it into the workspace.  Result: one
consolidated SSOT that carries per-command behaviour, MITRE,
LOLBAS, IOCs, decoded payload, confidence — all traceable to the
source article.

This module is the tiny router that does exactly that.  It never
loops (a paranoia budget guards depth so recursive fetch never
becomes uncontrolled crawling), and it never invokes network.  It
only invokes the existing in-process `services.die.analyze()` engine
which is itself pure + deterministic.
"""
from __future__ import annotations
import base64
import re
from typing import Any, Dict, List, Optional

from services.die.api import analyze as _die_analyze
from services.die.preprocessor.recursive_decoder import peel_recursively as _peel


# Maximum artifacts we're willing to recursively investigate in one
# request.  Vendors publish up to ~30 commands in a single report; we
# cap at 40 as a paranoia budget so a runaway article can never
# balloon SSOT generation time.
_MAX_ARTIFACTS = 40


_PS_ENC_RE = re.compile(
    r"(?i)-e(?:nc(?:od(?:ed(?:command)?)?)?)?"
    r"\s+([A-Za-z0-9+/=]{20,})"
)


def _decode_powershell_encoded(cmd: str) -> Dict[str, Any]:
    """If ``cmd`` contains a `-EncodedCommand <base64>` blob, decode it
    and return ``{recovered_payload, encoding, blob_len}``.  UTF-16-LE
    is PowerShell's mandated encoding.  Returns ``{}`` on any failure —
    never raises.
    """
    m = _PS_ENC_RE.search(cmd or "")
    if not m:
        return {}
    blob = m.group(1)
    try:
        raw = base64.b64decode(blob + "=" * ((4 - len(blob) % 4) % 4))
    except Exception:  # noqa: BLE001
        return {}
    # PowerShell -EncodedCommand: UTF-16-LE.  Fall back to UTF-8 for
    # non-Windows variants that some vendors mis-render.
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            decoded = raw.decode(enc).strip("\x00")
        except UnicodeDecodeError:
            continue
        if decoded and any(ch.isprintable() for ch in decoded[:32]):
            return {
                "recovered_payload": decoded,
                "encoding":          enc,
                "blob_len":          len(blob),
            }
    return {}


def investigate_artifact(command: Dict[str, Any]) -> Dict[str, Any]:
    """Run the DIE analyzer over a single extracted command and
    return a compact per-artifact investigation record.

    Input:
        {command, head, purpose, line, source}      (from IDA-4)
    Output:
        {command, head, purpose, source_ref,
         language, cmdlets, lolbins, techniques,
         iocs, dkp_matches, attack_intent,
         obfuscation_score, confidence, verdict}
    """
    cmd_text = (command or {}).get("command") or ""
    if not cmd_text.strip():
        return {}
    try:
        env = _die_analyze(cmd_text)
    except Exception as e:  # noqa: BLE001 — never crash the pipeline
        return {
            "command":     cmd_text,
            "head":        command.get("head"),
            "purpose":     command.get("purpose"),
            "source_ref":  command.get("source"),
            "error":       f"{type(e).__name__}: {e!s}",
        }

    # Trim the envelope to the analyst-visible payload — we don't
    # want to pollute the SSOT with the full internal envelope.
    # 2026-02-09 · Also surface the decoded PowerShell body when the
    # command carries `-EncodedCommand <base64>`.  Analysts pasting a
    # URL that leads to an encoded PowerShell need to SEE what the
    # attacker was actually going to execute, not just the base64.
    _decoded = _decode_powershell_encoded(cmd_text)

    # 2026-02-09 · CHAIN THE PAYLOAD AS STAGES.
    # Run the recursive multi-layer decoder over the raw command so
    # nested encodings (base64 → utf-16le → base64 → gzip →
    # byte-array XOR → shellcode) all peel automatically.  This is
    # the "CyberChef chain" the vendor articles describe:
    #     ps_encodedcommand → from_base64_string → gzip →
    #     byte_array_xor_loop → shellcode/IPv4.
    # Returns per-layer telemetry (stage, bytes_in/out, elapsed_ms)
    # AND the final peeled text so any embedded IOCs (C2 IP, UA,
    # ASCII strings) surface even when they were buried 4 layers deep.
    _stages: List[Dict[str, Any]] = []
    _peeled_final: str = ""
    _peeled_iocs: List[str] = []
    try:
        _peeled_final, _stages = _peel(cmd_text, max_layers=8, max_bytes=2 * 1024 * 1024)
        if _peeled_final and _peeled_final != cmd_text:
            # Extract any IPv4 addresses that surfaced in the fully-
            # peeled output — these are ground-truth C2 IPs that were
            # invisible in the raw command line.
            _peeled_iocs = list({ip for ip in re.findall(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _peeled_final)})
    except Exception:  # noqa: BLE001 — never crash the pipeline
        pass

    return {
        "command":            cmd_text,
        "head":               command.get("head"),
        "purpose":            command.get("purpose"),
        "source_ref":         command.get("source"),
        "language":           env.get("language"),
        "cmdlets":            env.get("cmdlets") or [],
        "lolbins":            env.get("lolbins") or [],
        "techniques":         env.get("techniques") or [],
        "iocs":               env.get("iocs") or [],
        "dkp_matches":        env.get("dkp_matches") or [],
        "attack_intent":      env.get("attack_intent"),
        "obfuscation_score":  env.get("obfuscation_score", 0),
        "verdict":            env.get("verdict"),
        **({"recovered_payload":     _decoded["recovered_payload"],
            "recovered_encoding":    _decoded["encoding"],
            "recovered_blob_len":    _decoded["blob_len"]} if _decoded else {}),
        # Chained multi-layer decode ("CyberChef recipe" equivalent).
        # Always present (empty list when nothing peeled).
        "decode_stages":       _stages,
        "peeled_final":        _peeled_final if _peeled_final and _peeled_final != cmd_text else "",
        "peeled_iocs":         {"ips": _peeled_iocs} if _peeled_iocs else {},
    }


def investigate_all(commands: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Batch entry point.  Runs `investigate_artifact` over every
    extracted command, honouring the paranoia budget."""
    if not commands:
        return []
    hits: List[Dict[str, Any]] = []
    for c in commands[:_MAX_ARTIFACTS]:
        rec = investigate_artifact(c)
        if rec:
            hits.append(rec)
    return hits


def merge_into_ssot(command_investigations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate per-command investigations into a consolidated view.

    Returns::

        {
          "commands_analyzed":  int,
          "lolbins_union":      [ {binary, mitre, category, trust}, ... ],
          "techniques_union":   [ {id, name, source: 'command|inferred'} ],
          "languages":          [ 'powershell', 'cmd', ... ],
          "dkp_families":       [ family_ids ... ],
        }
    """
    if not command_investigations:
        return {
            "commands_analyzed": 0,
            "lolbins_union":     [],
            "techniques_union":  [],
            "languages":         [],
            "dkp_families":      [],
        }

    lolbin_seen: set = set()
    lolbins:     List[Dict[str, Any]] = []
    mitre_seen:  set = set()
    mitre:       List[Dict[str, Any]] = []
    langs:       set = set()
    dkp_seen:    set = set()

    for r in command_investigations:
        if r.get("language"):
            langs.add(r["language"])
        for lb in (r.get("lolbins") or []):
            key = (lb.get("binary") or "").lower()
            if key and key not in lolbin_seen:
                lolbin_seen.add(key)
                lolbins.append({
                    "binary":   key,
                    "mitre":    lb.get("mitre") or [],
                    "category": lb.get("category"),
                    "trust":    lb.get("trust"),
                })
        for t in (r.get("techniques") or []):
            tid = (t.get("id") or "").upper()
            if tid and tid not in mitre_seen:
                mitre_seen.add(tid)
                mitre.append({
                    "id":     tid,
                    "name":   t.get("name") or "",
                    "source": "command",         # provenance — from analysing a command
                })
        for m in (r.get("dkp_matches") or []):
            fid = m.get("id") or m.get("name")
            if fid and fid not in dkp_seen:
                dkp_seen.add(fid)

    return {
        "commands_analyzed": len(command_investigations),
        "lolbins_union":     lolbins,
        "techniques_union":  mitre,
        "languages":         sorted(langs),
        "dkp_families":      sorted(dkp_seen),
    }
