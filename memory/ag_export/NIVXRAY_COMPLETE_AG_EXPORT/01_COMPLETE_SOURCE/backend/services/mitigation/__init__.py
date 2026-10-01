"""Deterministic Mitigation Recommendations.

Pure function — takes a decode result (analysis_core.deterministic_best_decode
output shape) and derives an analyst-ready mitigation plan.  No LLM,
no external services — every recommendation is grounded in signals
that the deterministic engine already surfaces:

    · recipe / steps    · which decoders ran (byte_array_xor_loop,
                          ps.encoded_command, FromBase64String + GZip)
    · iocs              · promoted IPs / URLs / domains
    · reached_shellcode · terminal payload observed
    · output text       · signature strings (User-Agent, cmd-line flags)

Output schema (STABLE — analyst UI depends on this):

    {
      "schema_version": 1,
      "verdict": {
          "severity":  "critical" | "high" | "medium" | "low" | "informational",
          "one_liner": str,
      },
      "immediate":  [ { "id": str, "action": str, "why": str,
                          "priority": int }, ... ],
      "hunting":    [ { "id": str, "query": str, "why": str }, ... ],
      "containment":[ { "id": str, "action": str, "why": str }, ... ],
      "hardening":  [ { "id": str, "action": str, "why": str }, ... ],
      "signals_used": { <signal_name>: <what was observed> },
    }

Aligned with NIST SP 800-61 r2 sections (Contain / Eradicate / Recover +
Post-Incident) — analysts recognise the bucket structure.
"""
from __future__ import annotations

from typing import Any, Dict, List

MITIGATION_SCHEMA_VERSION = 1


# ═══════════════════════════════════════════════════════════════════
# Public entry point
# ═══════════════════════════════════════════════════════════════════
def derive_mitigations(decode_result: Dict[str, Any]) -> Dict[str, Any]:
    """Derive an analyst-facing mitigation plan from a decode result.

    Pure — no side effects.  Safe to call on empty / partial inputs.
    """
    result = decode_result or {}
    recipe_ops = _collect_recipe_ops(result)
    iocs        = result.get("iocs") or {}
    ips         = list(iocs.get("ip")     or iocs.get("ips")    or [])
    urls        = list(iocs.get("url")    or iocs.get("urls")   or [])
    domains     = list(iocs.get("domain") or iocs.get("domains") or [])
    hashes      = list(iocs.get("sha256") or []) + list(iocs.get("md5") or []) + list(iocs.get("sha1") or [])
    reached_sc  = bool(result.get("reached_shellcode"))
    out_text    = str(result.get("output") or "")
    signals     = _extract_signals(recipe_ops, out_text, reached_sc,
                                     ips, urls, domains, hashes)

    verdict     = _derive_verdict(signals)
    immediate   = _immediate_actions(signals)
    hunting     = _hunting_queries(signals)
    containment = _containment_actions(signals)
    hardening   = _hardening_actions(signals)

    return {
        "schema_version": MITIGATION_SCHEMA_VERSION,
        "verdict":        verdict,
        "immediate":      immediate,
        "hunting":        hunting,
        "containment":    containment,
        "hardening":      hardening,
        "signals_used": {
            "recipe_ops":              recipe_ops,
            "reached_shellcode":       reached_sc,
            "ips":                     ips,
            "urls":                    urls,
            "domains":                 domains,
            "hashes":                  hashes,
            "cobalt_strike_ua_seen":   signals["cobalt_strike_ua"],
            "obfuscation_layers":      signals["obfuscation_layers"],
        },
    }


# ═══════════════════════════════════════════════════════════════════
# Signal extraction
# ═══════════════════════════════════════════════════════════════════
def _collect_recipe_ops(result: Dict[str, Any]) -> List[str]:
    ops: List[str] = []
    for r in (result.get("recipe") or []):
        op = (r or {}).get("op")
        if op:
            ops.append(str(op))
    if not ops:
        for s in (result.get("steps") or []):
            op = (s or {}).get("op")
            if op:
                ops.append(str(op))
    return ops


# Signature strings a deterministic engine can reliably detect in the
# decoded output — every entry maps a substring → the family it evinces.
_KNOWN_UA_STRINGS = {
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;PTBR)":
        "cobalt_strike",
    "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko":
        "cobalt_strike",
    "Mozilla/4.0 (compatible; MSIE 8.0":
        "empire",
}


def _extract_signals(recipe_ops: List[str], out_text: str, reached_sc: bool,
                     ips: List[str], urls: List[str], domains: List[str],
                     hashes: List[str]) -> Dict[str, Any]:
    ops_joined = " ".join(op.lower() for op in recipe_ops)

    ps_encoded_cmd = ("encoded_command" in ops_joined
                        or "encodedcommand" in ops_joined)
    from_b64       = ("from_base64_string" in ops_joined
                        or "decoder-from-base64-string" in ops_joined)
    gzip_deflate   = ("gzip" in ops_joined or "zlib" in ops_joined
                        or "compression" in ops_joined)
    xor_loop       = ("xor" in ops_joined and "loop" in ops_joined)
    obfuscation_layers = sum([ps_encoded_cmd, from_b64, gzip_deflate, xor_loop])

    # Family attribution — deterministic fingerprinting.
    cobalt_strike_ua = None
    for ua, fam in _KNOWN_UA_STRINGS.items():
        if ua in out_text and fam == "cobalt_strike":
            cobalt_strike_ua = ua
            break
    family = None
    if cobalt_strike_ua:
        family = "cobalt_strike"
    elif reached_sc and xor_loop:
        # xor-loop + shellcode is a very high-fidelity Cobalt-Strike-family
        # indicator even without the User-Agent match.
        family = "cobalt_strike_likely"

    # WebClient / DownloadString / IEX etc. — post-download-execute pattern
    dl_and_exec = any(m in out_text for m in (
        "DownloadString", "DownloadFile", "WebClient",
        "Invoke-Expression", "IEX ",
    ))

    # Credential-access markers
    credential_access = any(m.lower() in out_text.lower() for m in (
        "lsass", "mimikatz", "sekurlsa", "hashdump",
    ))

    return {
        "recipe_ops":         recipe_ops,
        "obfuscation_layers": obfuscation_layers,
        "ps_encoded_command": ps_encoded_cmd,
        "from_base64":        from_b64,
        "gzip_or_deflate":    gzip_deflate,
        "xor_loop":           xor_loop,
        "reached_shellcode":  reached_sc,
        "cobalt_strike_ua":   cobalt_strike_ua,
        "family":             family,
        "download_and_exec":  dl_and_exec,
        "credential_access":  credential_access,
        "ips":                ips,
        "urls":               urls,
        "domains":            domains,
        "hashes":             hashes,
    }


# ═══════════════════════════════════════════════════════════════════
# Verdict
# ═══════════════════════════════════════════════════════════════════
def _derive_verdict(sig: Dict[str, Any]) -> Dict[str, Any]:
    if sig["family"] == "cobalt_strike":
        return {
            "severity":  "critical",
            "one_liner": ("Cobalt Strike beacon stager identified — "
                          "post-exploitation framework with confirmed "
                          "C2 signature and shellcode terminal payload."),
        }
    if sig["family"] == "cobalt_strike_likely":
        return {
            "severity":  "critical",
            "one_liner": ("Multi-stage shellcode loader with XOR-decoded "
                          "byte-array terminal payload — behaviour "
                          "matches Cobalt Strike / Empire family."),
        }
    if sig["reached_shellcode"]:
        return {
            "severity":  "high",
            "one_liner": ("Multi-layer obfuscated PowerShell reaches "
                          "in-memory shellcode — treat as active "
                          "compromise vector."),
        }
    if sig["obfuscation_layers"] >= 3:
        return {
            "severity":  "high",
            "one_liner": (f"Deep obfuscation "
                          f"({sig['obfuscation_layers']} layers) — "
                          "typical of malware loaders."),
        }
    if sig["download_and_exec"]:
        return {
            "severity":  "medium",
            "one_liner": ("PowerShell download-and-execute pattern — "
                          "possible dropper or living-off-the-land tool."),
        }
    if sig["obfuscation_layers"] >= 1 or sig["ips"] or sig["urls"]:
        return {
            "severity":  "medium",
            "one_liner": ("Obfuscated input with network IOCs — "
                          "warrants triage."),
        }
    return {
        "severity":  "informational",
        "one_liner": "No malicious signals identified in the input.",
    }


# ═══════════════════════════════════════════════════════════════════
# Recommendation buckets
# ═══════════════════════════════════════════════════════════════════
def _r(id_: str, **kw) -> Dict[str, Any]:
    return {"id": id_, **kw}


def _immediate_actions(sig: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if sig["reached_shellcode"]:
        out.append(_r("kill-powershell",
            action="Kill all running powershell.exe / pwsh.exe processes "
                    "on the affected endpoint (task-list, procdump before "
                    "termination if triage-worthy).",
            why="In-memory shellcode reached — process termination halts "
                "the beacon before persistence is established.",
            priority=1))
        out.append(_r("isolate-host",
            action="Isolate the affected host from the network via EDR "
                    "network containment or VLAN quarantine.",
            why="Prevents lateral movement while shellcode payload is "
                "still resident.",
            priority=1))
        out.append(_r("collect-memory",
            action="Collect a full memory image (winpmem, DumpIt) BEFORE "
                    "reboot for shellcode / injected-thread analysis.",
            why="Volatile memory holds the unpacked payload and beacon "
                "config — lost on reboot.",
            priority=2))
    for ip in (sig["ips"] or [])[:5]:
        out.append(_r(f"block-ip:{ip}",
            action=f"Block outbound traffic to {ip} at perimeter "
                    "firewall + DNS sinkhole.",
            why="Deterministic decoder promoted this IP as a C2 "
                "endpoint from the decoded payload.",
            priority=1))
    for url in (sig["urls"] or [])[:5]:
        out.append(_r(f"block-url:{url}",
            action=f"Block URL {url} at proxy / web-gateway "
                    "and add to threat-intel feed.",
            why="URL promoted from the decoded payload — active C2 or "
                "download endpoint.",
            priority=1))
    for dom in (sig["domains"] or [])[:5]:
        out.append(_r(f"block-domain:{dom}",
            action=f"Sinkhole {dom} in DNS + block at firewall.",
            why="Domain resolved from the payload during decoding.",
            priority=1))
    if sig["credential_access"]:
        out.append(_r("rotate-credentials",
            action="Force credential rotation for any account that "
                    "authenticated on the affected host in the last "
                    "72 hours (including service accounts).",
            why="Credential-access tooling markers (lsass / mimikatz / "
                "sekurlsa) detected in the decoded payload.",
            priority=1))
    if not out:
        out.append(_r("triage-and-monitor",
            action="No immediate blocking actions required.  Log the "
                    "artifact, monitor the endpoint, and re-evaluate "
                    "if additional indicators appear.",
            why="Deterministic analysis surfaced no active-compromise "
                "signals.",
            priority=3))
    return out


def _hunting_queries(sig: Dict[str, Any]) -> List[Dict[str, Any]]:
    q: List[Dict[str, Any]] = []
    if sig["ps_encoded_command"]:
        q.append(_r("hunt-ps-encodedcommand",
            query=('process_name:"powershell.exe" AND (command_line:'
                    '"-EncodedCommand" OR command_line:"-enc " OR '
                    'command_line:"-e ")'),
            why="Look for other hosts running PowerShell with "
                "base64-encoded command payloads."))
    if sig["from_base64"] and sig["gzip_or_deflate"]:
        q.append(_r("hunt-b64-gzip-loader",
            query=('process_name:"powershell.exe" AND command_line:'
                    '"FromBase64String" AND command_line:"GzipStream"'),
            why="Fingerprint of the Base64+GZip in-memory loader "
                "family (Cobalt Strike / Empire / Nishang)."))
    if sig["xor_loop"]:
        q.append(_r("hunt-byte-array-xor",
            query=('process_name:"powershell.exe" AND command_line:'
                    '"-bxor" AND command_line:"[Byte[]]"'),
            why="Byte-array XOR loop is the signature idiom of "
                "shellcode stagers."))
    if sig["download_and_exec"]:
        q.append(_r("hunt-download-and-exec",
            query=('process_name:"powershell.exe" AND (command_line:'
                    '"DownloadString" OR command_line:"DownloadFile") '
                    'AND command_line:"IEX"'),
            why="Living-off-the-land download-and-execute pattern."))
    for ip in (sig["ips"] or [])[:3]:
        q.append(_r(f"hunt-ip:{ip}",
            query=f'destination.ip:"{ip}"',
            why=f"Historical connections to the promoted C2 IP {ip}."))
    for dom in (sig["domains"] or [])[:3]:
        q.append(_r(f"hunt-domain:{dom}",
            query=f'dns.question.name:"{dom}"',
            why=f"Historical DNS queries to the promoted domain {dom}."))
    if not q:
        q.append(_r("hunt-baseline",
            query=("Baseline unusual parent-child process trees on the "
                    "affected host over the last 30 days."),
            why="No specific-pattern queries were derivable from this "
                "artifact — fall back to endpoint baselining."))
    return q


def _containment_actions(sig: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if sig["reached_shellcode"] or sig["family"]:
        out.extend([
            _r("disable-user",
                action="Disable the interactive user account on the "
                        "affected host and reset its password.",
                why="Prevents re-authentication if credentials were "
                    "harvested by the payload."),
            _r("review-lateral",
                action="Review SMB / WinRM / PSRemoting logs from the "
                        "affected host over the last 24 hours for "
                        "lateral-movement indicators.",
                why="Post-exploitation frameworks pivot within minutes "
                    "of initial access."),
            _r("dns-beacon-monitor",
                action="Monitor DNS beaconing patterns from the affected "
                        "host and its subnet for the next 72 hours.",
                why="Beacons often use covert DNS channels alongside "
                    "the primary HTTP C2."),
        ])
    out.append(_r("scheduled-tasks",
        action="Enumerate scheduled tasks, services, and Run keys "
                "created on the affected host in the last 7 days.",
        why="Common persistence vectors after initial payload "
            "execution."))
    if sig["credential_access"]:
        out.insert(0, _r("rotate-domain-admins",
            action="Reset every domain admin and privileged service "
                    "account password.",
            why="Credential-access markers indicate credentials on the "
                "host may already be compromised."))
    return out


def _hardening_actions(sig: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if sig["ps_encoded_command"] or sig["family"]:
        out.append(_r("ps-script-block-logging",
            action="Ensure PowerShell Script-Block Logging (EID 4104) "
                    "and Module Logging (EID 4103) are enabled fleet-wide "
                    "via GPO / Intune.",
            why="Would have captured the decoded payload contents in "
                "the Windows event log at execution time."))
        out.append(_r("ps-amsi",
            action="Verify AMSI is not being bypassed — audit any "
                    "endpoint AV/EDR alerts for AMSI-bypass patterns.",
            why="Encoded-command loaders often try to disable AMSI "
                "before executing the second stage."))
    if sig["download_and_exec"]:
        out.append(_r("egress-restrict-powershell",
            action="Restrict outbound network access from powershell.exe "
                    "at the endpoint firewall.",
            why="Legitimate PowerShell workflows rarely need direct "
                "internet access."))
    out.append(_r("constrained-language",
        action="Enable PowerShell Constrained Language Mode via WDAC "
                "on high-value endpoints.",
        why="Prevents most in-memory execution primitives used by "
            "malware loaders."))
    return out


__all__ = ["derive_mitigations", "MITIGATION_SCHEMA_VERSION"]
