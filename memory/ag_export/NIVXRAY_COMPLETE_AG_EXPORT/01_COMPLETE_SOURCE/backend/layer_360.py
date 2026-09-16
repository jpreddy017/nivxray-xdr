"""NivXRay · Per-Layer 360° Intelligence Correlator  (v1.5.5 · Feb 2026)

Every decode layer (L0/L1/L2/L3 + every intermediate op) gets its output
scanned through EVERY available intelligence source:

    · extract_iocs         → urls, ips, domains, md5/sha1/sha256
    · scan_lolbas          → LOLBin abuse
    · mitre_map            → MITRE ATT&CK techniques
    · yara_lite_scan       → in-house YARA-lite rules
    · lookup_ti_hits       → local db.iocs feed match
    · osint.enrich_iocs    → LIVE providers (VT · AbuseIPDB · Shodan ·
                              GreyNoise · URLScan · OTX · IPinfo ·
                              Hybrid Analysis · abuse.ch)
    · risk_score           → aggregated severity
    · family_hint          → heuristic malware-family guess

Returns a structured `layer_intelligence[]` array — one entry per
successful decode step — that the Workspace UI renders as the
"360° LAYER INTELLIGENCE" panel.

Cost / latency profile
----------------------
Live OSINT is time-boxed and bucketed. We only enrich UNIQUE IOCs (no
duplicate calls across layers). Local db.iocs lookup is a Mongo find on
an indexed collection.
"""
from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger("nivxray.layer_360")


async def enrich_layers_360(layer_records: List[Dict[str, Any]],
                             raw_input: str,
                             final_output: str) -> List[Dict[str, Any]]:
    """Enrich each layer with the full stack of intelligence resources.

    Args
    ----
    layer_records: [{layer, op, iocs, lolbas}] emitted by /api/decode/smart
    raw_input:    original untouched input (for "L0" seed intel)
    final_output: fully-decoded final plaintext (for a "final" enrichment card)

    Returns
    -------
    List[Dict] — one entry per layer, PLUS a synthetic "L0-raw" and
    "L-final" if they surface distinct intel.
    """
    if not layer_records and not raw_input and not final_output:
        return []

    # Lazy imports keep module import cheap.
    from operations import extract_iocs, mitre_map, yara_lite_scan
    from lolbas import scan_lolbas
    try:
        from analysis_core import lookup_ti_hits, risk_score, detect_family
    except Exception:
        lookup_ti_hits = None
        risk_score = None
        detect_family = None
    try:
        from osint import enrich_iocs as osint_enrich
        from deps import load_osint_keys
        osint_keys = await load_osint_keys()
    except Exception:
        osint_enrich = None
        osint_keys = {}

    def _empty_iocs() -> Dict[str, List[str]]:
        return {"urls": [], "ips": [], "domains": [], "md5": [], "sha1": [], "sha256": []}

    def _scan_layer(text: str) -> Dict[str, Any]:
        try:    iocs = extract_iocs(text) or _empty_iocs()
        except Exception: iocs = _empty_iocs()
        try:    lol = scan_lolbas(text) or []
        except Exception: lol = []
        try:    mit = mitre_map(text) or []
        except Exception: mit = []
        try:    yr = yara_lite_scan(text) or []
        except Exception: yr = []
        return {"iocs": iocs, "lolbas": lol, "mitre": mit, "yara": yr}

    # Global de-dupe cache — same IOC seen in later layers gets a reference
    # to the earlier enrichment rather than re-hitting the API.
    _live_cache: Dict[str, Dict[str, Any]] = {}

    async def _live_enrich(iocs_bucket: Dict[str, List[str]]) -> Dict[str, Any]:
        if not osint_enrich or not any(osint_keys.values()):
            return {}
        # v1.5.5.1 · cap total live IOCs enriched per full 360 run at 12 —
        # keeps the whole call under the 18s router timeout even when all
        # 9 providers respond slowly.
        _remaining = 12 - len(_live_cache)
        if _remaining <= 0:
            return {}
        # Filter to values we HAVEN'T seen before
        fresh: Dict[str, List[str]] = {k: [] for k in ("ips", "domains", "urls", "md5", "sha1", "sha256")}
        _added = 0
        for kind, values in (iocs_bucket or {}).items():
            for v in (values or []):
                if _added >= _remaining:
                    break
                if v and v not in _live_cache:
                    _live_cache[v] = None
                    if kind in fresh:
                        fresh[kind].append(v)
                        _added += 1
        if not any(fresh.values()):
            return {}
        try:
            import asyncio as _a
            result = await _a.wait_for(
                osint_enrich(fresh, osint_keys, max_per_type=4),
                timeout=6.0,
            )
        except Exception as _e:  # noqa: BLE001
            log.warning("360 live-enrich failed: %s", _e)
            return {}
        for bucket_name in ("ips", "domains", "urls", "hashes"):
            for row in (result.get(bucket_name) or []):
                v = row.get("value")
                if v:
                    _live_cache[v] = row
        return result

    def _severity(scanned: Dict[str, Any], live: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        # Simple weighted score
        score = 0
        score += min(30, 6 * len(scanned["lolbas"]))
        score += min(35, 5 * len(scanned["mitre"]))
        score += min(15, 3 * sum(len(v or []) for v in scanned["iocs"].values()))
        score += min(15, 4 * len(scanned["yara"]))
        # Live provider malicious signal bumps severity
        if live:
            for bucket in ("ips", "domains", "urls", "hashes"):
                for row in (live.get(bucket) or []):
                    vt = (row.get("virustotal") or {})
                    ab = (row.get("abuseipdb") or {})
                    otx = (row.get("otx") or {})
                    if (vt.get("malicious") or 0) or (vt.get("suspicious") or 0):
                        score += 25
                    if (ab.get("abuse_confidence_score") or 0) > 25:
                        score += 15
                    if otx.get("pulse_count") or len(otx.get("pulses") or []):
                        score += 10
        score = min(100, score)
        band = ("critical" if score >= 80
                else "high" if score >= 60
                else "medium" if score >= 35
                else "low" if score >= 10
                else "none")
        return {"score": score, "band": band}

    def _family_hint(scanned: Dict[str, Any], preview: str) -> Optional[str]:
        # Cheap heuristic — the deterministic engine already sets `family`
        # on the top-level result; here we look for family-specific tokens
        # AT THIS LAYER.
        tokens_families = [
            ("cobaltstrike",    ["beacon", "artifactkit", "spawnto", "malleable"]),
            ("emotet",          ["emotet", "epoch4", "epoch5"]),
            ("qakbot",          ["qakbot", "qbot"]),
            ("meterpreter",     ["meterpreter", "metsrv", "reverse_https"]),
            ("empire",          ["empire", "invoke-empire", "$wc="]),
            ("mimikatz",        ["mimikatz", "sekurlsa", "lsadump"]),
            ("lockbit",         ["lockbit"]),
            ("blackcat/alphv",  ["alphv", "blackcat"]),
            ("lumma",           ["lumma"]),
            ("bumblebee",       ["bumblebee"]),
            ("icedid",          ["icedid", "bokbot"]),
            ("agenttesla",      ["agenttesla", "agent tesla"]),
            ("asyncrat",        ["asyncrat"]),
            ("nanocore",        ["nanocore"]),
            ("smokeloader",     ["smokeloader"]),
            ("gootloader",      ["gootloader"]),
            ("socgholish",      ["socgholish", "fromcharcode"]),
        ]
        low = (preview or "").lower()
        for fam, toks in tokens_families:
            if any(t in low for t in toks):
                return fam
        # LOLBAS pattern → family class hint
        lol_names = {l.get("bin") or l.get("name") or "" for l in scanned["lolbas"]}
        if "certutil.exe" in lol_names or "certutil" in lol_names:
            return "certutil-downloader-generic"
        if "regsvr32.exe" in lol_names or "regsvr32" in lol_names:
            return "regsvr32-scriptlet-generic"
        if "mshta.exe" in lol_names or "mshta" in lol_names:
            return "mshta-html-application-generic"
        return None

    # ── Build the enriched layer list ────────────────────────────────
    enriched: List[Dict[str, Any]] = []

    # L0 · Raw input intelligence
    if raw_input:
        s = _scan_layer(raw_input)
        live = await _live_enrich(s["iocs"])
        ti_local: List[Any] = []
        if lookup_ti_hits:
            try:
                ti_local = await lookup_ti_hits(s["iocs"])
            except Exception:
                ti_local = []
        enriched.append({
            "layer":         0,
            "label":         "L0 · RAW INPUT",
            "op":            "raw",
            "preview":       (raw_input or "")[:400],
            "iocs":          s["iocs"],
            "lolbas":        s["lolbas"],
            "mitre":         s["mitre"],
            "yara":          s["yara"],
            "ti_hits":       ti_local,
            "live_osint":    live,
            "family_hint":   _family_hint(s, raw_input),
            "severity":      _severity(s, live),
        })

    # L1..LN · Each decode intermediate
    for rec in (layer_records or []):
        # We already have iocs + lolbas from the /decode/smart pipeline —
        # but re-scan for MITRE + YARA (not surfaced by the caller) and
        # add live OSINT for the layer's unique IOCs.
        preview_text = ""
        # `rec` doesn't include the preview text — build it from the layer's
        # IOC values so live OSINT has something to enrich.
        # (The caller retains the actual preview in `trace[i].output_preview`
        # but doesn't pass it here to keep the payload small.)
        joined = []
        for k in ("urls", "ips", "domains"):
            joined.extend((rec.get("iocs") or {}).get(k) or [])
        preview_text = " ".join(joined)
        s = _scan_layer(preview_text) if preview_text else {
            "iocs": rec.get("iocs") or _empty_iocs(),
            "lolbas": rec.get("lolbas") or [],
            "mitre": [], "yara": [],
        }
        # Prefer caller's IOCs (already scanned on the ACTUAL preview text)
        s["iocs"] = rec.get("iocs") or s["iocs"]
        s["lolbas"] = rec.get("lolbas") or s["lolbas"]
        live = await _live_enrich(s["iocs"])
        ti_local = []
        if lookup_ti_hits:
            try:
                ti_local = await lookup_ti_hits(s["iocs"])
            except Exception:
                ti_local = []
        enriched.append({
            "layer":         rec.get("layer"),
            "label":         f"L{rec.get('layer')} · {(rec.get('op') or '').upper()}",
            "op":            rec.get("op"),
            "preview":       preview_text[:400],
            "iocs":          s["iocs"],
            "lolbas":        s["lolbas"],
            "mitre":         s["mitre"],
            "yara":          s["yara"],
            "ti_hits":       ti_local,
            "live_osint":    live,
            "family_hint":   _family_hint(s, preview_text),
            "severity":      _severity(s, live),
        })

    # L-final · Fully decoded output
    if final_output and final_output.strip() != (raw_input or "").strip():
        s = _scan_layer(final_output)
        live = await _live_enrich(s["iocs"])
        ti_local = []
        if lookup_ti_hits:
            try:
                ti_local = await lookup_ti_hits(s["iocs"])
            except Exception:
                ti_local = []
        enriched.append({
            "layer":         "final",
            "label":         "L-FINAL · DECODED PAYLOAD",
            "op":            "final",
            "preview":       (final_output or "")[:400],
            "iocs":          s["iocs"],
            "lolbas":        s["lolbas"],
            "mitre":         s["mitre"],
            "yara":          s["yara"],
            "ti_hits":       ti_local,
            "live_osint":    live,
            "family_hint":   _family_hint(s, final_output),
            "severity":      _severity(s, live),
        })

    return enriched
