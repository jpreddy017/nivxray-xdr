"""Phase 5.W · CSV / tabular EDR log analyzer (2026-08-10).

Detects and analyses vendor endpoint-security telemetry pasted or
uploaded as CSV — SEP, CrowdStrike, Defender, Sentinel-style logs.
The canonical narrative rules target prose ("remote access trojan",
"malicious file executed"); they miss tabular events like
`Exploit Prevention | detect | browserhost.exe`.

This analyser bridges that gap deterministically:
- Sniffs CSV structure via csv.Sniffer + header inspection.
- Maps known-vendor category / action columns → MITRE ATT&CK ids.
- Extracts IOCs (file hashes, source hosts, filenames).
- Detects LOLBins by well-known binary name.
- Builds attack_progression + kill_chain_coverage from mapped tactics.

Pure function — no I/O, no network, no clock, no random.
"""
from __future__ import annotations
import csv
import io
import re
from typing import Any, Dict, List, Optional, Tuple


# ── SEP category → MITRE technique mapping (deterministic, curated) ─
# Each entry maps a Symantec Endpoint Protection category string
# (or substring match) to zero-or-more (technique_id, technique_name,
# tactic) tuples.  When action='block' or 'detect', these are treated
# as high-confidence signals; other actions are informational only.
_SEP_CATEGORY_MAP: Dict[str, List[Tuple[str, str, str]]] = {
    "exploit prevention": [
        ("T1203", "Exploitation for Client Execution", "execution"),
        ("T1055", "Process Injection",                  "defense_evasion"),
    ],
    "system process protection": [
        ("T1055.012", "Process Hollowing",              "defense_evasion"),
        ("T1543.003", "Windows Service",                "persistence"),
    ],
    "suspicious endpoint findings": [
        ("T1204.002", "User Execution: Malicious File", "execution"),
    ],
    "file fetch": [
        ("T1105", "Ingress Tool Transfer",              "command_and_control"),
    ],
    "policy update failure": [
        ("T1562.001", "Impair Defenses: Disable or Modify Tools", "defense_evasion"),
    ],
    "scan failed": [
        ("T1562.001", "Impair Defenses: Disable or Modify Tools", "defense_evasion"),
    ],
    "component download failure": [
        # Downgrade — could be benign network hiccup; only report as low-conf informational.
    ],
    "tamper protection": [
        ("T1562.001", "Impair Defenses: Disable or Modify Tools", "defense_evasion"),
    ],
    "memory exploit mitigation": [
        ("T1055", "Process Injection",                  "defense_evasion"),
    ],
    "network intrusion prevention": [
        ("T1071", "Application Layer Protocol",         "command_and_control"),
    ],
    "sonar": [   # Symantec heuristic
        ("T1204.002", "User Execution: Malicious File", "execution"),
    ],
    "download insight": [
        ("T1105", "Ingress Tool Transfer",              "command_and_control"),
    ],
}


# ── Known LOLBins (subset relevant to endpoint logs) ────────────────
_LOLBINS: Dict[str, str] = {
    "powershell.exe":   "Category `Execution` — abused for T1059.001 tradecraft.",
    "cmd.exe":          "Category `Execution` — abused for T1059.003 tradecraft.",
    "rundll32.exe":     "Category `Execution` — abused for T1218.011 (proxy DLL execution).",
    "regsvr32.exe":     "Category `Execution` — abused for T1218.010 (Squiblydoo).",
    "mshta.exe":        "Category `Execution` — abused for T1218.005 (HTA execution).",
    "wscript.exe":      "Category `Execution` — abused for T1059.005 (Visual Basic scripts).",
    "cscript.exe":      "Category `Execution` — abused for T1059.005 (Visual Basic scripts).",
    "wmic.exe":         "Category `Execution` — abused for T1047 (WMI execution).",
    "certutil.exe":     "Category `Download` — abused for T1105 (Ingress Tool Transfer).",
    "bitsadmin.exe":    "Category `Download` — abused for T1197 / T1105 (BITS jobs).",
    "curl.exe":         "Category `Download` — abused for T1105 (Ingress Tool Transfer).",
    "schtasks.exe":     "Category `Persistence` — abused for T1053.005 (Scheduled Task).",
    "winlogon.exe":     "Critical system binary — process injection / hollowing target (T1055.012).",
    "browserhost.exe":  "Microsoft Edge/Chromium sandbox host — targeted by browser exploits (T1203).",
    "svchost.exe":      "Critical system binary — masquerading target (T1036.005).",
    "lsass.exe":        "Credential subsystem — dumping target (T1003.001).",
}


_MD5_RE    = re.compile(r"^[a-f0-9]{32}$", re.I)
_SHA1_RE   = re.compile(r"^[a-f0-9]{40}$", re.I)
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$", re.I)
_IP_RE     = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def looks_like_csv(text: str) -> bool:
    """Heuristic CSV detector — cheap enough to run on every input."""
    if not text or len(text) < 40:
        return False
    head = text[:4096]
    # First line must have ≥ 3 commas and ≥ 4 tokens.
    first_nl = head.find("\n")
    if first_nl < 8:
        return False
    header = head[:first_nl]
    if header.count(",") < 3:
        return False
    # 3rd line also has same-order-of-magnitude comma count.
    lines = head.splitlines()
    if len(lines) < 3:
        return False
    comma_counts = [ln.count(",") for ln in lines[:8] if ln.strip()]
    if not comma_counts:
        return False
    ref = comma_counts[0]
    close = sum(1 for c in comma_counts if abs(c - ref) <= 2)
    return close >= max(3, int(len(comma_counts) * 0.6))


def _norm_cat(s: str) -> str:
    return re.sub(r"[^a-z0-9 ]", " ", (s or "").lower()).strip()


def _match_categories(cat: str) -> List[Tuple[str, str, str]]:
    if not cat:
        return []
    norm = _norm_cat(cat)
    out: List[Tuple[str, str, str]] = []
    for needle, techs in _SEP_CATEGORY_MAP.items():
        if needle in norm:
            out.extend(techs)
    return out


def _classify_hash(v: str) -> Optional[str]:
    if not v:
        return None
    v = v.strip()
    if _MD5_RE.match(v):    return "md5"
    if _SHA1_RE.match(v):   return "sha1"
    if _SHA256_RE.match(v): return "sha256"
    return None


def analyse_csv_edr(text: str, max_rows: int = 5000
                    ) -> Optional[Dict[str, Any]]:
    """Return canonical-shaped analysis result or None if not CSV/EDR."""
    if not looks_like_csv(text):
        return None

    # Parse
    try:
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
    except Exception:
        return None
    if len(rows) < 3:
        return None
    header = [h.strip().lower() for h in rows[0]]
    body = rows[1: 1 + max_rows]

    # Column index lookup — tolerate variations.
    def col(*names: str) -> Optional[int]:
        for n in names:
            n_low = n.lower()
            for i, h in enumerate(header):
                if h == n_low or n_low in h:
                    return i
        return None

    i_action    = col("action")
    i_category  = col("category", "event", "alert", "signature", "detection")
    i_filename  = col("file_name", "filename", "process", "process_name", "image", "target_process")
    i_filehash  = col("file_hash", "sha256", "hash", "md5")
    i_parenthash= col("parent_file_hash", "parent_sha256", "parent_hash")
    i_filepath  = col("file_path", "path", "process_path")
    i_srchost   = col("src_host", "host", "hostname", "computer_name", "computer", "device")
    i_srcip     = col("src_ip", "source_ip", "ip")
    i_dstip     = col("dst_ip", "destination_ip", "remote_ip")
    i_user      = col("user", "user_name", "username")
    i_date      = col("date", "timestamp", "time", "event_time")
    i_parent_fn = col("parent_file_name", "parent_process", "parent_image")

    # If we couldn't identify EITHER a category or a filename column, this
    # is not a security-relevant CSV.  Bail out early.
    if i_category is None and i_filename is None:
        return None

    tactics_seen: Dict[str, List[Dict[str, str]]] = {}
    tech_by_id: Dict[str, Dict[str, str]] = {}
    iocs: Dict[str, set] = {"md5": set(), "sha1": set(), "sha256": set(),
                             "ip": set(), "domain": set(), "hostname": set(),
                             "filename": set(), "path": set(), "user": set()}
    lolbas_hits: Dict[str, Dict[str, Any]] = {}
    action_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}
    highconf_events: List[Dict[str, str]] = []
    total_rows = 0

    for row in body:
        if not row:
            continue
        total_rows += 1

        def cell(idx: Optional[int]) -> str:
            if idx is None or idx >= len(row):
                return ""
            return (row[idx] or "").strip()

        action = cell(i_action).lower()
        cat    = cell(i_category)
        fn     = cell(i_filename)
        fh     = cell(i_filehash)
        ph     = cell(i_parenthash)
        fp     = cell(i_filepath)
        host   = cell(i_srchost)
        sip    = cell(i_srcip)
        dip    = cell(i_dstip)
        usr    = cell(i_user)
        pfn    = cell(i_parent_fn)

        if action:   action_counts[action]     = action_counts.get(action, 0) + 1
        if cat:      category_counts[cat]      = category_counts.get(cat, 0) + 1

        # ── IOC harvesting ────────────────────────────────────────
        for hv in (fh, ph):
            kind = _classify_hash(hv)
            if kind:
                iocs[kind].add(hv.lower())
        for ip in (sip, dip):
            if ip and _IP_RE.match(ip) and not ip.startswith(("127.", "0.")):
                iocs["ip"].add(ip)
        if fn:
            iocs["filename"].add(fn.lower())
        if pfn:
            iocs["filename"].add(pfn.lower())
        if fp:
            iocs["path"].add(fp)
        if host:
            # Split hostname.domain — surface both hostname and domain.
            iocs["hostname"].add(host.lower())
            if "." in host:
                parts = host.split(".", 1)
                if len(parts) == 2 and "." in parts[1]:
                    dom = parts[1].lower()
                    # Skip internal-only / non-routable TLDs — they
                    # pollute the IOC list and aren't blockable at
                    # the perimeter.
                    _INTERNAL_TLDS = (".local", ".corp", ".lan",
                                       ".internal", ".arpa", ".home",
                                       ".localdomain")
                    if not any(dom.endswith(tld) for tld in _INTERNAL_TLDS):
                        iocs["domain"].add(dom)
        if usr:
            iocs["user"].add(usr)

        # ── Category → MITRE mapping ──────────────────────────────
        # Only high-confidence actions promote a category to a MITRE hit.
        # 'detect' / 'block' → definite.  'success' on scan / update → informational only.
        promote = action in ("detect", "block", "quarantine", "clean", "remove") or "suspicious" in _norm_cat(cat)
        matches = _match_categories(cat) if promote else []
        for tid, tname, tactic in matches:
            if tid not in tech_by_id:
                tech_by_id[tid] = {"id": tid, "name": tname, "tactic": tactic,
                                    "evidence": f"SEP category '{cat}' (action={action})"}
            tactics_seen.setdefault(tactic, [])
            if tech_by_id[tid] not in tactics_seen[tactic]:
                tactics_seen[tactic].append(tech_by_id[tid])
            highconf_events.append({
                "date": cell(i_date),
                "host": host,
                "category": cat,
                "action": action,
                "file": fn,
                "hash": fh,
                "technique": tid,
            })

        # ── LOLBAS harvest ────────────────────────────────────────
        for candidate in (fn, pfn):
            lower = candidate.lower()
            if lower in _LOLBINS:
                entry = lolbas_hits.setdefault(lower, {
                    "binary": candidate,
                    "count":  0,
                    "legit":  "",
                    "abuse":  _LOLBINS[lower],
                    "detection": [],
                    "mitre":  [],
                    "evidence": [],
                })
                entry["count"] += 1
                if promote and cat:
                    ev = f"{cat} ({action})"
                    if ev not in entry["evidence"]:
                        entry["evidence"].append(ev)

    # Nothing worth reporting?
    if not tech_by_id and not lolbas_hits and not any(iocs.values()):
        return None

    # ── Build attack_progression grouped by tactic ────────────────
    _TACTIC_ORDER = [
        "initial_access", "execution", "persistence", "privilege_escalation",
        "defense_evasion", "credential_access", "discovery", "lateral_movement",
        "collection", "command_and_control", "exfiltration", "impact",
    ]
    ordered = [t for t in _TACTIC_ORDER if t in tactics_seen]
    progression = []
    for i, tac in enumerate(ordered):
        techs = tactics_seen[tac]
        progression.append({
            "index":      i,
            "stage":      tac,
            "tactic":     tac,
            "title":      tac.replace("_", " ").title(),
            "kill_chain": tac,
            "mitre":      [{"id": t["id"], "name": t["name"], "evidence": t.get("evidence", "")}
                            for t in techs],
            "narrative":  (
                f"{len(techs)} technique(s) observed in **{tac.replace('_',' ')}** phase "
                f"across {total_rows} tabular EDR event(s)."
            ),
        })

    # ── Build MITRE technique list (flat) ─────────────────────────
    mitre_list = list(tech_by_id.values())

    # ── Compact IOC dict ──────────────────────────────────────────
    ioc_out = {k: sorted(v) for k, v in iocs.items() if v}

    # ── LOLBAS list ───────────────────────────────────────────────
    lolbas_out = []
    for binary_key, entry in lolbas_hits.items():
        # Pull mitre ids from _LOLBINS entry via TECHNIQUE map.
        # Keep it deterministic — no extra guessing.
        mitre_ids = []
        abuse_text = entry["abuse"]
        # Extract T-ids from abuse_text using regex.
        for tid in re.findall(r"T\d{4}(?:\.\d{3})?", abuse_text):
            if tid not in mitre_ids:
                mitre_ids.append(tid)
        entry["mitre"] = mitre_ids
        # Populate detection hints from technique catalog.
        try:
            from .canonical_narrative_enrichment import _TECHNIQUE_CATALOG
            for tid in mitre_ids:
                cat = _TECHNIQUE_CATALOG.get(tid)
                if cat and cat.get("sigma"):
                    hint = cat["sigma"]
                    if hint not in entry["detection"]:
                        entry["detection"].append(hint)
        except Exception:
            pass
        lolbas_out.append(entry)

    return {
        "source":                "csv_edr_analyzer",
        "total_rows":            total_rows,
        "action_distribution":   action_counts,
        "category_distribution": category_counts,
        "highconf_events":       highconf_events[:200],   # cap to keep response slim
        "mitre":                 mitre_list,
        "iocs":                  ioc_out,
        "lolbas":                lolbas_out,
        "attack_progression":    progression,
        "kill_chain_coverage":   ordered,
    }


__all__ = ["analyse_csv_edr", "looks_like_csv"]
