"""v2/verdict/correlation.py · Verdict Engine v3.1 — Multi-event Correlation.

Layered aggregation on top of the per-event `score(event, ctx)` engine.

    Event  →  Process  →  Chain  →  Device  →  Incident

Correlation substrate is the **Attack Graph** produced by
`v2/shadow/irg.enrich` — i.e. `entity.iid` + `parent.iid` + `root.iid` —
NOT timestamps and NOT PIDs. This ensures the aggregated score reflects
the actual attack path, not unrelated activity that happens to occur
around the same time.

Determinism guarantees:
  · Same input frames  →  byte-identical output (no randomness, no I/O).
  · Same evidence      →  same explanation.
  · No LLM. No binary-name reputation. No external TI.

Anti-inflation rules:
  · Signals are de-duplicated per layer (a signal fired by 5 events of the
    same process only contributes ONCE at the process layer).
  · Family caps are still enforced (evasion ≤ 25, execution ≤ 40, …).
  · Correlation bonuses only fire when *independent* signals corroborate
    (multiple families, multiple processes, or multiple lanes).

Public API:
    from v2.verdict.correlation import correlate
    report = correlate(frames)                  # frames = irg_enrich(trajectory)
    report.processes[iid].score / .band / .confidence / .contributing_events …
    report.device.score / .band / .confidence …
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from typing import Any, Iterable

from .engine import score as _score_event
from .weights import (
    WEIGHTS, FAMILY_OF, FAMILY_CAPS, band_of,
    AGGREGATE_MAX,
    MULTI_FAMILY_BONUSES,
    TACTIC_COVERAGE_BONUSES,
    MULTI_PROCESS_BONUS,
    CROSS_LANE_BONUS,
    IMPACT_CHAIN_BONUS,
    CRED_TO_LATERAL_BONUS,
    CONF_WEIGHTS,
    CORROBORATION_REQUIRED,
    CORROBORATION_CAP,
)

# ─── Data model ─────────────────────────────────────────────────────

@dataclass
class AggregateVerdict:
    """Deterministic aggregate verdict at any layer of the hierarchy."""
    layer: str                    # event|process|chain|device|incident
    id: str                       # entity iid · chain root iid · device id · case id
    label: str                    # human-readable name
    score: int                    # 0..100
    band: str                     # benign|informational|low|suspicious|malicious|critical
    confidence: int               # 0..100 evidence-density confidence
    explanation: str              # top-3 contributing signals as a compact string
    evidence_breakdown: list[dict] = field(default_factory=list)
    contributing_events: list[str] = field(default_factory=list)
    contributing_processes: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    correlation_bonuses: list[dict] = field(default_factory=list)
    children: list[str] = field(default_factory=list)  # ids of subordinate layer entries

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationReport:
    """Full multi-layer correlation output for a single case."""
    engine: str = "v3.1"
    case_id: str | None = None
    events: dict[str, dict] = field(default_factory=dict)        # frame_iid → per-event verdict
    processes: dict[str, AggregateVerdict] = field(default_factory=dict)
    chains: dict[str, AggregateVerdict] = field(default_factory=dict)
    device: AggregateVerdict | None = None
    incident: AggregateVerdict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine":    self.engine,
            "case_id":   self.case_id,
            "events":    self.events,
            "processes": {k: v.to_dict() for k, v in self.processes.items()},
            "chains":    {k: v.to_dict() for k, v in self.chains.items()},
            "device":    self.device.to_dict() if self.device else None,
            "incident":  self.incident.to_dict() if self.incident else None,
        }


# ─── Helpers ────────────────────────────────────────────────────────

def _lane_of(frame: dict) -> str:
    return str(frame.get("lane") or "").lower()

def _process_iid_for(frame: dict) -> str:
    """Return the process entity iid this frame belongs to.

    · If the frame's own entity is a process → use it.
    · Otherwise (file / net / registry event) → use its parent process iid.
    """
    ent = frame.get("entity") or {}
    if (ent.get("type") or "").lower() == "process" and ent.get("iid"):
        return ent["iid"]
    parent = frame.get("parent") or {}
    return parent.get("iid") or ent.get("iid") or "unknown"

def _mitre_bases(frame: dict) -> set[str]:
    return {str(t).split(".", 1)[0] for t in (frame.get("mitre") or []) if t}

# MITRE technique → tactic (base-only, small deterministic map).
_TACTIC_OF_BASE: dict[str, str] = {
    "T1189": "initial_access", "T1204": "initial_access", "T1566": "initial_access",
    "T1059": "execution",       "T1053": "execution",       "T1218": "execution",
    "T1547": "persistence",     "T1197": "persistence",
    "T1027": "defense_evasion", "T1562": "defense_evasion", "T1055": "defense_evasion",
    "T1620": "defense_evasion",
    "T1003": "credential_access", "T1555": "credential_access",
    "T1087": "discovery", "T1082": "discovery", "T1482": "discovery",
    "T1071": "command_and_control", "T1105": "command_and_control",
    "T1041": "exfiltration",
    "T1486": "impact", "T1489": "impact", "T1490": "impact",
}
def _tactic_of(base: str) -> str | None:
    return _TACTIC_OF_BASE.get(base)


def _apply_family_caps(hits: list[dict]) -> tuple[int, list[dict]]:
    """Group unique signal hits by family, apply anti-inflation caps.

    Returns (positive_score, breakdown_list).
    """
    per_family: dict[str, list[dict]] = defaultdict(list)
    for h in hits:
        fam = FAMILY_OF.get(h["signal"], "execution")
        per_family[fam].append(h)

    total = 0
    breakdown: list[dict] = []
    for fam, hs in per_family.items():
        raw = sum(WEIGHTS.get(h["signal"], 0) for h in hs)
        cap = FAMILY_CAPS.get(fam, 40)
        capped = min(raw, cap)
        factor = (capped / raw) if raw > 0 else 1.0
        for h in hs:
            w = WEIGHTS.get(h["signal"], 0)
            eff = int(round(w * factor))
            total += eff
            breakdown.append({
                "signal":           h["signal"],
                "family":           fam,
                "weight":           w,
                "effective_weight": eff,
                "reason":           h.get("reason", ""),
                "processes":        sorted(h.get("processes", set())) if isinstance(h.get("processes"), set) else h.get("processes", []),
                "events":           sorted(h.get("events", set())) if isinstance(h.get("events"), set) else h.get("events", []),
            })
    return total, breakdown


def _apply_correlation_bonuses(
    families: set[str],
    tactics: set[str],
    proc_ids_with_signals: set[str],
    lanes: set[str],
) -> tuple[int, list[dict]]:
    """Return (bonus_total, applied_bonuses)."""
    bonuses: list[dict] = []
    total = 0

    # Multi-family — highest-tier only.
    n_fam = len(families - {"decay"})
    for threshold, weight, key in MULTI_FAMILY_BONUSES:
        if n_fam >= threshold:
            bonuses.append({"signal": key, "weight": weight,
                            "reason": f"{n_fam} distinct signal families corroborate"})
            total += weight
            break

    # Tactic coverage — highest-tier only.
    n_tac = len(tactics)
    for threshold, weight, key in TACTIC_COVERAGE_BONUSES:
        if n_tac >= threshold:
            bonuses.append({"signal": key, "weight": weight,
                            "reason": f"{n_tac} MITRE tactic(s) covered"})
            total += weight
            break

    # Multi-process corroboration.
    mp_key, mp_w, mp_th = MULTI_PROCESS_BONUS
    if len(proc_ids_with_signals) >= mp_th:
        bonuses.append({"signal": mp_key, "weight": mp_w,
                        "reason": f"{len(proc_ids_with_signals)} distinct processes contribute signals"})
        total += mp_w

    # Cross-lane attack.
    xl_key, xl_w, xl_th = CROSS_LANE_BONUS
    if len(lanes) >= xl_th:
        bonuses.append({"signal": xl_key, "weight": xl_w,
                        "reason": f"attack spans {len(lanes)} lanes: {sorted(lanes)}"})
        total += xl_w

    # Impact chain (execution + persistence + impact).
    ic_key, ic_w, ic_reqs = IMPACT_CHAIN_BONUS
    if set(ic_reqs).issubset(families):
        bonuses.append({"signal": ic_key, "weight": ic_w,
                        "reason": "execution → persistence → impact chain observed"})
        total += ic_w

    # Credential-to-lateral chain.
    cl_key, cl_w, cl_reqs = CRED_TO_LATERAL_BONUS
    if set(cl_reqs).issubset(families):
        bonuses.append({"signal": cl_key, "weight": cl_w,
                        "reason": "credential → evasion → network chain observed"})
        total += cl_w

    return total, bonuses


def _confidence(n_signals: int, n_procs_with_sig: int, n_lanes: int, n_tactics: int) -> int:
    if n_signals == 0:
        return 0
    c = (CONF_WEIGHTS["min_when_any_signal"]
         + CONF_WEIGHTS["per_unique_signal"]      * n_signals
         + CONF_WEIGHTS["per_process_with_signal"]* max(0, n_procs_with_sig - 1)
         + CONF_WEIGHTS["per_lane"]               * max(0, n_lanes - 1)
         + CONF_WEIGHTS["per_mitre_base"]         * n_tactics)
    return min(100, c)


def _explain(breakdown: list[dict], bonuses: list[dict], corroboration_applied: bool) -> str:
    top = sorted(breakdown, key=lambda b: b["effective_weight"], reverse=True)[:3]
    parts = [f'{b["signal"]}(+{b["effective_weight"]})' for b in top]
    for b in bonuses[:2]:
        parts.append(f'{b["signal"]}(+{b["weight"]})')
    if corroboration_applied:
        parts.append("corroboration-capped")
    return "; ".join(parts) if parts else "no signals fired"


# ─── Signal collector per event ─────────────────────────────────────

def _collect_signals_for_frame(frame: dict, ctx: dict) -> list[dict]:
    """Run the event-level engine and lift its raw hits (dedup, family info).

    We *replay* the engine's dedup on the pre-family-cap list so the aggregate
    layer can control its own family-cap distribution across the union of
    signals from many events.
    """
    v = _score_event(frame, ctx)
    hits: list[dict] = []
    seen: set[str] = set()
    for b in v.breakdown:
        sig = b["signal"]
        # We DO want decay signals for context, but they don't contribute
        # to aggregate positive score. Skip them at aggregate layer.
        if b["family"] == "decay":
            continue
        if sig in seen:
            continue
        seen.add(sig)
        hits.append({
            "signal": sig,
            "reason": b.get("reason", ""),
            "frame_iid": frame.get("frame_iid") or frame.get("id"),
        })
    return hits


# ─── Aggregation entry point ────────────────────────────────────────

def correlate(frames: list[dict], case_id: str | None = None) -> CorrelationReport:
    """Run the full multi-layer correlation on IRG-enriched frames."""
    if not frames:
        return CorrelationReport(case_id=case_id)

    # 1 · Per-event scoring — build ctx (file-write counters per entity) once.
    file_writes: dict[str, int] = defaultdict(int)
    for f in frames:
        if _lane_of(f) == "file" and "write" in str(f.get("action") or "").lower():
            ent = (f.get("entity") or {}).get("iid") or ""
            if ent:
                file_writes[ent] += 1

    event_verdicts: dict[str, dict] = {}
    # process_iid → list of signal hits (each carrying originating frame_iid).
    signals_by_process: dict[str, list[dict]] = defaultdict(list)
    # process_iid → set of frame_iids
    events_by_process: dict[str, set[str]] = defaultdict(set)
    # process_iid → list of lanes seen (with signals or otherwise)
    lanes_by_process: dict[str, set[str]] = defaultdict(set)
    # process_iid → set of MITRE tactic bases seen across its events
    mitre_by_process: dict[str, set[str]] = defaultdict(set)
    # process_iid → label
    proc_label: dict[str, str] = {}

    for f in frames:
        pid = _process_iid_for(f)
        fid = f.get("frame_iid") or f.get("id") or f"?{len(event_verdicts)}"
        ent = f.get("entity") or {}
        # Track label — prefer explicit entity name for process rows.
        if (ent.get("type") or "").lower() == "process" and ent.get("iid"):
            proc_label.setdefault(ent["iid"], ent.get("name") or ent["iid"])
        else:
            proc_label.setdefault(pid, pid)

        ctx = {
            "file_writes_60s": file_writes.get(ent.get("iid") or "", 0),
        }
        v = _score_event(f, ctx)
        event_verdicts[fid] = {
            "frame_iid":   fid,
            "process_iid": pid,
            "ts":          f.get("ts"),
            "score":       v.score,
            "band":        v.band,
            "explanation": v.explanation,
        }
        events_by_process[pid].add(fid)
        lanes_by_process[pid].add(_lane_of(f) or "unknown")
        mitre_by_process[pid] |= _mitre_bases(f)
        for h in _collect_signals_for_frame(f, ctx):
            h["process_iid"] = pid
            h["lane"] = _lane_of(f)
            signals_by_process[pid].append(h)

    # 2 · Aggregate per process.
    processes: dict[str, AggregateVerdict] = {}
    for pid, hits in signals_by_process.items():
        av = _aggregate_layer(
            layer="process",
            layer_id=pid,
            label=proc_label.get(pid, pid),
            hits=hits,
            contributing_events=sorted(events_by_process[pid]),
            contributing_processes=[pid],
            proc_ids_with_signals={pid},
            lanes=lanes_by_process[pid],
            mitre_bases=mitre_by_process[pid],
        )
        processes[pid] = av

    # Also register processes that appear (as parent or entity) but produced
    # zero signals — so the UI can still show a benign row.
    all_process_iids: set[str] = set()
    parent_of: dict[str, str] = {}
    root_iid: str | None = None
    for f in frames:
        ent = f.get("entity") or {}
        parent = f.get("parent") or {}
        root = f.get("root") or {}
        if root.get("iid"):
            root_iid = root["iid"]
        if (ent.get("type") or "").lower() == "process" and ent.get("iid"):
            all_process_iids.add(ent["iid"])
            if parent.get("iid"):
                parent_of.setdefault(ent["iid"], parent["iid"])
        # Also register the parent iid itself so it appears in the graph.
        if parent.get("iid"):
            all_process_iids.add(parent["iid"])
    for pid in all_process_iids:
        if pid not in processes:
            processes[pid] = AggregateVerdict(
                layer="process", id=pid,
                label=proc_label.get(pid, pid),
                score=0, band="benign", confidence=0,
                explanation="no signals fired",
                contributing_processes=[pid],
            )

    # 3 · Chain aggregation — a chain is rooted at a process whose parent is
    #     the synthetic root_iid. Each chain aggregates itself + all descendants.
    #     Uses the attack-graph parent_of map, NOT timestamps.
    #     If root_iid is unknown, treat orphan processes as their own chains.

    # children map
    children_of: dict[str, list[str]] = defaultdict(list)
    for child, parent in parent_of.items():
        children_of[parent].append(child)

    # Every process has a set of attached events (file/net/registry included via
    # _process_iid_for). Any lane observed on ANY event of the chain counts as
    # lane diversity — this is what makes CROSS_LANE_ATTACK meaningful.
    # process_iid → lanes seen (already populated in step 1: `lanes_by_process`)
    # process_iid → mitre bases  (already populated:            `mitre_by_process`)
    # process_iid → events       (already populated:            `events_by_process`)

    def _descendants(pid: str) -> set[str]:
        """Iterative BFS with cycle guard."""
        out: set[str] = set()
        stack = [pid]
        while stack:
            cur = stack.pop()
            if cur in out:
                continue
            out.add(cur)
            for ch in children_of.get(cur, ()):
                if ch not in out:
                    stack.append(ch)
        return out

    # A "chain root" is any process whose parent is the synthetic root
    # (or has no parent). We de-dup so multi-root descendants only count once.
    chain_roots = [pid for pid in all_process_iids
                   if parent_of.get(pid) in (root_iid, None) and pid != root_iid]
    # If nothing qualifies (e.g. root_iid is None), promote every parent-less pid.
    if not chain_roots:
        chain_roots = [pid for pid in all_process_iids if pid not in parent_of]

    # ALSO account for processes that host non-process events (like x.exe hosting
    # a file write). Those pids may not appear in `parent_of` at all — attach
    # them to any chain that already covers their parent-event's process.
    # For simplicity: any orphan process becomes its own chain root.
    known_in_chains: set[str] = set()
    for cr in chain_roots:
        known_in_chains |= _descendants(cr)
    orphans = [pid for pid in all_process_iids
               if pid not in known_in_chains and pid != root_iid]
    chain_roots = list(chain_roots) + orphans

    chains: dict[str, AggregateVerdict] = {}
    for cr in chain_roots:
        desc = _descendants(cr)
        chain_hits: list[dict] = []
        chain_events: set[str] = set()
        proc_ids_with_sig: set[str] = set()
        lanes: set[str] = set()
        mitre_bases: set[str] = set()
        # Dedup signals across the chain by (signal_key) → collect first-fire
        # BUT keep track of *which* processes fired each signal so we can
        # decide whether "MULTI_PROCESS_CORROBORATION" applies.
        seen_signals: dict[str, dict] = {}
        for pid in desc:
            # Lanes/events/MITRE come from ALL frames attached to pid, whether
            # or not signals fired — a network beacon with no MITRE tag still
            # contributes lane diversity to the chain.
            lanes |= lanes_by_process.get(pid, set())
            mitre_bases |= mitre_by_process.get(pid, set())
            chain_events |= events_by_process.get(pid, set())
            for h in signals_by_process.get(pid, ()):
                proc_ids_with_sig.add(pid)
                sig = h["signal"]
                bucket = seen_signals.setdefault(sig, {
                    "signal": sig,
                    "reason": h.get("reason", ""),
                    "processes": set(),
                    "events": set(),
                })
                bucket["processes"].add(pid)
                if h.get("frame_iid"):
                    bucket["events"].add(h["frame_iid"])

        for bucket in seen_signals.values():
            chain_hits.append(bucket)

        av = _aggregate_layer(
            layer="chain",
            layer_id=cr,
            label=proc_label.get(cr, cr),
            hits=chain_hits,
            contributing_events=sorted(chain_events),
            contributing_processes=sorted(desc),
            proc_ids_with_signals=proc_ids_with_sig,
            lanes=lanes,
            mitre_bases=mitre_bases,
        )
        av.children = sorted(desc)
        chains[cr] = av

    # 4 · Device aggregation — union of ALL signals + ALL lanes/tactics.
    device_hits: list[dict] = []
    device_events: set[str] = set()
    device_procs: set[str] = set()
    device_lanes: set[str] = set()
    device_mitre: set[str] = set()
    seen_dev_sig: dict[str, dict] = {}
    # Lanes/mitre/events from EVERY tracked process, whether it fired signals or not.
    for pid in all_process_iids:
        device_lanes |= lanes_by_process.get(pid, set())
        device_mitre |= mitre_by_process.get(pid, set())
        device_events |= events_by_process.get(pid, set())
    # Now walk signals; dedup by signal key across the entire device.
    for pid, hits in signals_by_process.items():
        for h in hits:
            device_procs.add(pid)
            sig = h["signal"]
            bucket = seen_dev_sig.setdefault(sig, {
                "signal": sig,
                "reason": h.get("reason", ""),
                "processes": set(),
                "events": set(),
            })
            bucket["processes"].add(pid)
            if h.get("frame_iid"):
                bucket["events"].add(h["frame_iid"])
    for bucket in seen_dev_sig.values():
        device_hits.append(bucket)

    device = _aggregate_layer(
        layer="device",
        layer_id=case_id or "device",
        label=case_id or "device",
        hits=device_hits,
        contributing_events=sorted(device_events),
        contributing_processes=sorted(device_procs),
        proc_ids_with_signals=device_procs,
        lanes=device_lanes,
        mitre_bases=device_mitre,
    )
    device.children = sorted(chains.keys())

    # 5 · Incident aggregation — for now, incident is a 1:1 rollup of the
    #     device. Kept as a distinct layer so multi-device incidents plug in
    #     later without a schema break. Uses same evidence union.
    incident = _aggregate_layer(
        layer="incident",
        layer_id=case_id or "incident",
        label=case_id or "incident",
        hits=device_hits,
        contributing_events=sorted(device_events),
        contributing_processes=sorted(device_procs),
        proc_ids_with_signals=device_procs,
        lanes=device_lanes,
        mitre_bases=device_mitre,
    )
    incident.children = [device.id]

    return CorrelationReport(
        case_id=case_id,
        events=event_verdicts,
        processes=processes,
        chains=chains,
        device=device,
        incident=incident,
    )


def _aggregate_layer(
    *, layer: str, layer_id: str, label: str,
    hits: list[dict],
    contributing_events: list[str],
    contributing_processes: list[str],
    proc_ids_with_signals: set[str],
    lanes: set[str],
    mitre_bases: set[str],
) -> AggregateVerdict:
    """Compute an AggregateVerdict from a *pre-deduplicated* set of signal hits."""
    positive, breakdown = _apply_family_caps(hits)
    families = {b["family"] for b in breakdown}
    tactics = {_tactic_of(t) for t in mitre_bases}
    tactics.discard(None)

    bonus_total, bonuses = _apply_correlation_bonuses(
        families=families,
        tactics=tactics,
        proc_ids_with_signals=proc_ids_with_signals,
        lanes=lanes,
    )

    raw_score = positive + bonus_total

    # Corroboration ceiling at CORROBORATION_CAP if only high-value single-family
    # signals fired without independent corroboration (families count ≤ 1
    # AND no correlation bonuses fired).
    corroboration_applied = False
    fired_signals = {b["signal"] for b in breakdown}
    if fired_signals & CORROBORATION_REQUIRED:
        independent_families = families - {"execution"}  # execution is often the "carrier"
        independent_families.discard("decay")
        if not bonuses and len(independent_families) <= 1 and raw_score > CORROBORATION_CAP:
            raw_score = CORROBORATION_CAP
            corroboration_applied = True

    final = max(0, min(AGGREGATE_MAX, raw_score))
    band = band_of(final)
    conf = _confidence(
        n_signals=len(fired_signals),
        n_procs_with_sig=len(proc_ids_with_signals),
        n_lanes=len(lanes),
        n_tactics=len(tactics),
    )
    return AggregateVerdict(
        layer=layer,
        id=layer_id,
        label=label,
        score=final,
        band=band,
        confidence=conf,
        explanation=_explain(breakdown, bonuses, corroboration_applied),
        evidence_breakdown=breakdown,
        contributing_events=contributing_events,
        contributing_processes=contributing_processes,
        signals=sorted(fired_signals),
        families=sorted(families),
        mitre_tactics=sorted(tactics),
        correlation_bonuses=bonuses,
    )
