"""v2/report/builder.py · Compose the 10-section investigation report.

All timestamps in the envelope are derived from observation data —
never `datetime.now()` — so the same case always yields the same
report bytes. This is what makes the SHA-256 signature deterministic.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from typing import Any
from motor.motor_asyncio import AsyncIOMotorDatabase

from v2.case_engine.schema import COLLECTIONS
from .schema import ReportEnvelope, ReportSection, REPORT_SCHEMA_VERSION
from .hashing import sign_report

# Same technique→tactic map used by the coverage endpoint. Duplicated
# intentionally so the report has zero import coupling to routers.
_TECHNIQUE_TO_TACTIC = {
    "T1082":"discovery","T1018":"discovery","T1033":"discovery","T1069":"discovery",
    "T1087":"discovery","T1087.002":"discovery","T1135":"discovery",
    "T1590.002":"reconnaissance",
    "T1136":"persistence","T1136.002":"persistence","T1098.007":"persistence","T1547":"persistence",
    "T1219":"command_and_control","T1572":"command_and_control",
    "T1003":"credential_access","T1003.001":"credential_access","T1003.003":"credential_access",
    "T1552":"credential_access","T1552.001":"credential_access",
    "T1059":"execution","T1059.001":"execution",
    "T1218":"defense_evasion","T1218.007":"defense_evasion","T1218.011":"defense_evasion",
    "T1490":"impact","T1486":"impact","T1489":"impact",
}


def _process_name_of(event: dict) -> str:
    """Extract a human-friendly executable name from an enriched frame.

    Order of precedence (most trustworthy → least):
        1. `raw.entity` / `raw.target` from the deterministic rule
           (highest signal — this is what fired).
        2. First `.exe/.dll/.msi/.ps1/.bat/.cmd/.sys/.com` token in
           label or action.
        3. `process.iid` / `parent.iid` (may be `proc_shadow_XXX`).
        4. `action` field (still readable — e.g. `dumped`, `enumerated`).
    """
    import re
    # 1) Deterministic rule extraction (highest signal)
    raw = event.get("raw") or {}
    for key in ("entity", "target"):
        v = raw.get(key)
        if isinstance(v, str) and re.search(r"\.(exe|dll|msi|ps1|bat|cmd|sys|com)$", v, re.IGNORECASE):
            return v.lower()

    # 2) Regex against label / action
    for src in (event.get("label"), event.get("action")):
        if not isinstance(src, str): continue
        m = re.search(r"([A-Za-z0-9_.-]+\.(?:exe|dll|msi|ps1|bat|cmd|sys|com))", src, re.IGNORECASE)
        if m:
            return m.group(1).lower()

    # 3) iids (usually proc_shadow_XXX — still stable)
    for k in ("process", "parent"):
        iid = ((event.get(k) or {}).get("iid"))
        if iid:
            return iid.split(":")[-1]

    # 4) Fall back to action string
    return (event.get("action") or "").strip() or "unattributed"


def _verdict_of(event: dict) -> str:
    has_mitre = bool(event.get("mitre"))
    rule = event.get("rule_id") or (event.get("provenance") or {}).get("rule_id") \
        or (event.get("raw") or {}).get("rule_id")
    if has_mitre and rule: return "malicious"
    if has_mitre:          return "suspicious"
    return "benign"


async def _load_events(db: AsyncIOMotorDatabase, case_id: str) -> list[dict]:
    """Load enriched CEM frames using the same trajectory composer that
    powers the Device Trajectory UI.

    This keeps Mode A (automated report) and Mode B (interactive UI)
    fed by ONE source of truth: the `raw.entity` / `raw.rule_id` /
    canonical `lane` / `label` / `action` all come from the same
    deterministic pipeline the analyst sees on screen.
    """
    from v2.trajectory.device import build_from_observations
    frames = await build_from_observations(db, case_id=case_id, limit=5000)
    # Attach the underlying `raw` block (rule_id / entity / target /
    # confidence) so `_process_name_of` and command-line decoding can
    # reach it. `build_from_observations` returns TrajectoryFrame
    # dataclasses; `to_dict()` includes provenance but not the raw
    # command block, so we merge from the observation store here.
    events = [f.to_dict() for f in frames]
    if not events:
        return events
    # Second pass — enrich each frame with its raw command block
    coll = db[COLLECTIONS["shadow_observations"]]
    raw_by_iid: dict[str, dict] = {}
    async for row in coll.find({"case_id": case_id}, {"event.iid": 1, "event.raw": 1}):
        ev = row.get("event") or {}
        iid = ev.get("iid")
        if iid:
            raw_by_iid[iid] = ev.get("raw") or {}
    for e in events:
        # `evidence_ids` is a top-level field on TrajectoryFrame (see
        # v2/trajectory/schema.py) holding the source observation iid.
        ev_ids = e.get("evidence_ids") or []
        if ev_ids and ev_ids[0] in raw_by_iid:
            e["raw"] = raw_by_iid[ev_ids[0]]
    return events


async def _load_case(db: AsyncIOMotorDatabase, case_id: str) -> dict:
    row = await db[COLLECTIONS["cases"]].find_one({"case_id": case_id}) or {}
    row.pop("_id", None)
    return row


# ─────────────────────────────────────────────────────────────────────
# Section composers — each returns a ReportSection
# ─────────────────────────────────────────────────────────────────────

def _section_executive(events: list[dict], case: dict) -> ReportSection:
    v_counts = Counter(_verdict_of(e) for e in events)
    tactics = {_TECHNIQUE_TO_TACTIC.get(t, "unmapped")
               for e in events for t in (e.get("mitre") or [])} - {"unmapped"}
    top_proc = Counter(_process_name_of(e) for e in events).most_common(1)
    span = _timeline_span(events)
    prose = (
        f"NivXRay investigated {len(events)} deterministic observations for case "
        f"`{case.get('case_id','—')}`{' (' + case.get('name','') + ')' if case.get('name') else ''}. "
        f"{v_counts.get('malicious',0)} malicious, {v_counts.get('suspicious',0)} suspicious, "
        f"{v_counts.get('benign',0)} observation-only. "
        f"The chain spans {span or '—'} and touches "
        f"{len(tactics)} MITRE ATT&CK tactic(s)"
        + (f" including {', '.join(sorted(tactics))}." if tactics else ".")
        + (f" Dominant process: `{top_proc[0][0]}` ({top_proc[0][1]} events)." if top_proc else "")
    )
    return ReportSection(
        id="executive_summary", title="Executive Summary", order=1,
        narrative=prose,
        body={
            "event_total": len(events),
            "verdict_counts": dict(v_counts),
            "tactics": sorted(tactics),
            "dominant_process": top_proc[0][0] if top_proc else None,
            "timeline_span": span,
        },
    )


def _timeline_span(events: list[dict]) -> str | None:
    ts = [e.get("ts") for e in events if e.get("ts")]
    if not ts: return None
    lo, hi = min(ts), max(ts)
    return f"{lo} → {hi}"


def _section_case_metadata(case: dict, events: list[dict]) -> ReportSection:
    ts = [e.get("ts") for e in events if e.get("ts")]
    return ReportSection(
        id="case_metadata", title="Case Metadata", order=2,
        narrative=f"Case `{case.get('case_id','—')}` opened; {len(events)} observations ingested.",
        body={
            "case_id": case.get("case_id"),
            "name": case.get("name"),
            "description": case.get("description"),
            "status": case.get("status"),
            "tags": case.get("tags") or [],
            "created_at": case.get("created_at"),
            "first_observed": min(ts) if ts else None,
            "last_observed": max(ts) if ts else None,
            "observation_count": len(events),
        },
    )


def _section_verdict_rollup(events: list[dict]) -> ReportSection:
    v_counts = Counter(_verdict_of(e) for e in events)
    total = sum(v_counts.values()) or 1
    return ReportSection(
        id="verdict_rollup", title="Verdict Rollup", order=3,
        narrative=(f"Deterministic verdict distribution: "
                   f"{v_counts.get('malicious',0)} malicious, "
                   f"{v_counts.get('suspicious',0)} suspicious, "
                   f"{v_counts.get('benign',0)} observation."),
        body={
            "counts": dict(v_counts),
            "percentages": {k: round(v * 100 / total, 2) for k, v in v_counts.items()},
        },
    )


def _section_mitre_coverage(events: list[dict]) -> ReportSection:
    tech = Counter()
    tactic = Counter()
    for e in events:
        for t in (e.get("mitre") or []):
            tech[t] += 1
            tactic[_TECHNIQUE_TO_TACTIC.get(t, "unmapped")] += 1
    return ReportSection(
        id="mitre_coverage", title="MITRE ATT&CK Coverage", order=4,
        narrative=(f"{len(tech)} unique technique(s) across {len(tactic)} tactic(s)."),
        body={
            "techniques": [{"id": t, "count": n} for t, n in tech.most_common()],
            "tactics":    [{"id": t, "count": n} for t, n in tactic.most_common()],
        },
    )


def _section_process_ancestry(events: list[dict]) -> ReportSection:
    # Build parent -> [children] using process/parent iids
    edges = defaultdict(set)
    proc_events = defaultdict(list)
    for e in events:
        proc = _process_name_of(e)
        proc_events[proc].append(e.get("frame_iid"))
        parent_iid = (e.get("parent") or {}).get("iid")
        if parent_iid:
            edges[parent_iid].add(proc)
    top_procs = Counter({p: len(v) for p, v in proc_events.items()}).most_common(10)
    return ReportSection(
        id="process_ancestry", title="Process Ancestry Snapshot", order=5,
        narrative=(f"{len(proc_events)} unique process(es) executed; "
                   f"top invoker is `{top_procs[0][0]}` with {top_procs[0][1]} events."
                   if top_procs else "No process-level activity captured."),
        body={
            "top_processes": [{"process": p, "event_count": n} for p, n in top_procs],
            "spawn_edges": [
                {"parent": p, "children": sorted(c)} for p, c in sorted(edges.items())
            ][:50],
        },
    )


def _section_top_entities(events: list[dict]) -> ReportSection:
    kinds = ("file", "network", "registry", "user", "device")
    bucket = {k: Counter() for k in kinds}
    for e in events:
        for k in kinds:
            iid = ((e.get(k) or {}).get("iid"))
            if iid:
                bucket[k][iid] += 1
    body = {k: [{"iid": iid, "count": n} for iid, n in c.most_common(10)]
            for k, c in bucket.items()}
    return ReportSection(
        id="top_entities", title="Top Entities", order=6,
        narrative=(f"{sum(len(v) for v in body.values())} entity references extracted "
                   "across file / network / registry / user / device."),
        body=body,
    )


def _section_chronological_timeline(events: list[dict]) -> ReportSection:
    # Compact per-event row — no huge blobs
    rows = [{
        "ts":        e.get("ts"),
        "lane":      e.get("lane"),
        "action":    e.get("action"),
        "process":   _process_name_of(e),
        "label":     e.get("label"),
        "mitre":     e.get("mitre") or [],
        "verdict":   _verdict_of(e),
        "rule_id":   e.get("rule_id") or (e.get("provenance") or {}).get("rule_id"),
        "frame_iid": e.get("frame_iid"),
    } for e in events]
    return ReportSection(
        id="chronological_timeline", title="Chronological Timeline", order=7,
        narrative=f"{len(rows)} observations in temporal order.",
        body={"rows": rows},
    )


def _section_commandline_decoding(events: list[dict]) -> ReportSection:
    """Extract encoded command evidence. Real RC5 output is captured
    at observation time and stored under `provenance.decoded`. If the
    field is absent (older observations), we still surface the raw."""
    decoded = []
    for e in events:
        prov = e.get("provenance") or {}
        dec = prov.get("decoded")
        raw = e.get("label") or ""
        # Heuristic surface: any label containing base64-ish or -enc flags
        if dec or any(tok in raw.lower() for tok in ("-enc", "-encodedcommand", "base64", "frombase64string")):
            decoded.append({
                "frame_iid": e.get("frame_iid"),
                "ts": e.get("ts"),
                "raw":       raw,
                "decoded":   dec,
                "rule_id":   e.get("rule_id") or prov.get("rule_id"),
                "confidence": prov.get("confidence"),
            })
    return ReportSection(
        id="commandline_decoding", title="Command-line Decoding Evidence", order=8,
        narrative=(f"{len(decoded)} encoded/obfuscated command(s) surfaced. "
                   "Full multi-layer decoding is emitted by RC5 at ingest time."),
        body={"decoded_events": decoded},
    )


def _section_enrichment(events: list[dict]) -> ReportSection:
    """R3 will fill this in. For R4 we ship a schema-stable stub so
    downstream consumers can bind against the shape today."""
    return ReportSection(
        id="enrichment", title="Enrichment", order=9,
        narrative="Enrichment kit ships in R3 (NIST IR + OSINT + CVE + full MITRE map).",
        body={
            "nist_ir_mapping": [],
            "osint_lookups":    [],
            "cve_correlations": [],
            "status": "stub",
        },
    )


def _section_signature() -> ReportSection:
    return ReportSection(
        id="signature", title="Report Signature", order=10,
        narrative="SHA-256 of the canonical envelope with signature blanked. "
                  "Same case + same observations → same hash.",
        body={"placeholder": True},
    )


# ─────────────────────────────────────────────────────────────────────
# Public builder
# ─────────────────────────────────────────────────────────────────────

async def build_report(db: AsyncIOMotorDatabase, case_id: str) -> ReportEnvelope:
    """Compose + sign the deterministic report for a case."""
    events = await _load_events(db, case_id)
    case = await _load_case(db, case_id)

    sections = [
        _section_executive(events, case),
        _section_case_metadata(case, events),
        _section_verdict_rollup(events),
        _section_mitre_coverage(events),
        _section_process_ancestry(events),
        _section_top_entities(events),
        _section_chronological_timeline(events),
        _section_commandline_decoding(events),
        _section_enrichment(events),
        _section_signature(),
    ]

    # generated_at is DERIVED from the newest observation, not wall clock.
    ts = [e.get("ts") for e in events if e.get("ts")]
    generated_at = max(ts) if ts else "1970-01-01T00:00:00Z"

    env = ReportEnvelope(
        schema_version=REPORT_SCHEMA_VERSION,
        case_id=case_id,
        generated_at=generated_at,
        sections=sections,
    )
    return sign_report(env)
