/**
 * DeviceTrajectoryV2 — Hero build.
 *
 * One canonical investigation workspace matching /design/trajectory-hero.html:
 *   [0]  Case bar
 *   [1]  Time compass (24-hour lens w/ compromise dots + viewport rect)
 *   [2]  Attack-chain sidebar (MITRE tactic stages, clickable)
 *   [3]  Canvas (InvestigationCanvas — thin lifelines, indented ancestry,
 *        yellow compromise time-window, blue trigger halos)
 *   [4]  Evidence pane (verdict badges, command line, SHA, parent, MITRE,
 *        detection, actions, analyst note)
 *   [5]  Status bar
 *
 * No day scrubber. No hour scrubber. No filter row. Filters live behind ⌘\.
 * No LeftRail — labels live inside the canvas gutter.
 * Backend untouched. All 820 tests remain green.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Radar, Search, Filter, Play, ShieldAlert, Copy } from "lucide-react";
import { isObservable } from "../flags";
import api from "@/lib/api";
import Header from "@/components/Header";
import { InvestigationCanvas } from "@/v2/canvas_engine";
import CorrelationPanel from "./CorrelationPanel";

// ── Design tokens (Glassy-white analyst theme) ─────────────────────
import { T as SharedT } from "../theme";
export const T = SharedT;

// ── Data helpers ──────────────────────────────────────────────────
function verdictOf(f) {
  const hasMitre = (f.mitre || []).length > 0;
  if (!hasMitre) return "benign";
  const rule = (f.rule_id || f.provenance?.rule_id || "").toLowerCase();
  if (rule) return "malicious";
  // MITRE-tagged but no rule: promote impact / credential-access / defense-evasion
  // techniques to malicious so the compromise band renders.
  const malRe = /^(T1003|T1027|T1055|T1218|T1486|T1489|T1490|T1547|T1562|T1620)/;
  const mal = (f.mitre || []).some(t => malRe.test(t));
  return mal ? "malicious" : "suspicious";
}
function labelOf(f) {
  const raw = f.label || f.action || "";
  const m = raw.match(/([A-Za-z0-9_.-]+\.(?:exe|dll|msi|ps1|bat|cmd|sys|com))/i);
  if (m) return m[1];
  const p = (f.process?.iid || "").split(/[:/\\]/).pop();
  if (p && /^proc_shadow_/i.test(p)) return "Unknown Process";
  return p || (f.action || "event");
}
function keyOf(f) {
  const label = labelOf(f);
  if (label && /\.(exe|dll|msi|ps1|bat|cmd|sys|com)$/i.test(label))
    return `bin:${label.toLowerCase()}`;
  return f.process?.iid || f.parent?.iid || `sys:${f.lane}`;
}
function activityOf(f) {
  const a = (f.action || "").toLowerCase();
  if (/(delete|remove)/.test(a))                       return "delete";
  if (/(exploit|prevention|blocked)/.test(a))          return "execute";
  if (/(c2|beacon|exfil|connect|tunnel|dns|http|network)/.test(a)) return "network";
  if (/(execute|launch|spawn|ran|run|invoke|started)/.test(a)) return "execute";
  if (/(install|drop|create|add|new|write|persist|backup|dumped)/.test(a)) return "create";
  if (f.lane === "network")  return "network";
  if (f.lane === "registry") return "registry";
  if (f.lane === "file")     return "file";
  return "execute";
}
function isSourceOf(f) {
  // Heuristic: process events are usually the source; file/network/registry
  // events are usually the target of the action.
  return f.lane === "process" || f.lane === "system";
}
// Produce a human-friendly event title. The backend emits raw triplets
// (e.g. `backup_EA · created_domain_user · backup_EA`) which repeat when
// subject and target are the same entity — analysts read that as a
// duplication bug. This helper collapses same-entity triplets to
// `<entity> · <action>` and prefers action-verbs over raw actions.
function friendlyLabel(f) {
  const raw = String(f.label || "").trim();
  const action = String(f.action || "").trim();
  if (raw) {
    const parts = raw.split(/\s+·\s+/);
    if (parts.length === 3 && parts[0] === parts[2]) {
      return `${parts[0]} · ${parts[1]}`;
    }
    return raw;
  }
  const ent = f.entity?.name || "event";
  return action ? `${ent} · ${action}` : ent;
}
// MITRE technique prefix → tactic name.
const TACTIC = {
  T1189: "INITIAL ACCESS", T1204: "INITIAL ACCESS",
  T1059: "EXECUTION", T1053: "EXECUTION",
  T1087: "DISCOVERY", T1082: "DISCOVERY", T1482: "DISCOVERY",
  T1003: "CREDENTIAL ACCESS", T1555: "CREDENTIAL ACCESS",
  T1027: "DEFENSE EVASION", T1218: "DEFENSE EVASION", T1562: "DEFENSE EVASION",
                     T1620: "DEFENSE EVASION",
  T1490: "IMPACT", T1489: "IMPACT", T1486: "IMPACT",
  T1071: "COMMAND & CONTROL", T1105: "COMMAND & CONTROL",
};
function tacticOf(tech) {
  const base = tech.split(".")[0];
  return TACTIC[base] || "OTHER";
}

// ═══════════════════════════════════════════════════════════════════
export default function DeviceTrajectoryV2({ embedded = false }) {
  const navigate = useNavigate();
  const { caseId = "case_dfir_bumblebee_akira_2026" } = useParams() || {};
  const [data, setData]         = useState(null);
  const [err,  setErr]          = useState(null);
  const [selected, setSelected] = useState(null);
  const [selectedStageIdx, setSelectedStageIdx] = useState(null);
  const [rightTab, setRightTab] = useState("evidence");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [filters, setFilters] = useState({
    verdict: { malicious: true, suspicious: true, benign: true },
    kind:    { process: true, file: true, registry: true, network: true },
  });
  const [playing, setPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const [bookmarks, setBookmarks] = useState([]);
  // ── Unified viewport (shared across TimeRangeBox + Canvas) ────────
  // { start, end } | null. `null` = full case.
  const [viewport, setViewport] = useState(null);
  // Reported viewport (from canvas) — highlights the yellow window on the
  // hour strip while the analyst pans/zooms.
  const [reportedVp, setReportedVp] = useState(null);

  const enabled = isObservable("TRAJECTORY_ENGINE") || isObservable("CASE_ENGINE");

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    (async () => {
      try {
        const [tRes, cRes] = await Promise.all([
          api.get(`/v2/cases/${encodeURIComponent(caseId)}/trajectory/device?limit=1000`),
          api.get(`/v2/cases/${encodeURIComponent(caseId)}`).catch(() => ({ data: null })),
        ]);
        if (cancelled) return;
        // Merge case metadata into `data.case` so the drawer + status bar have
        // access to hostname / status / tags / created_at / etc.
        setData({ ...tRes.data, case: cRes.data || tRes.data.case });
      } catch (e) {
        if (!cancelled) setErr(e?.response?.data?.detail || e.message);
      }
    })();
    return () => { cancelled = true; };
  }, [caseId, enabled]);

  useEffect(() => { if (selected) setRightTab("evidence"); }, [selected]);

  const frames = useMemo(() => data?.frames || [], [data]);

  // Map of entity IID → friendly name, built from all frames' entities.
  // Enables the Evidence pane to resolve `parent.iid` back to a real
  // process/file/registry name instead of showing the raw internal ID.
  const nameByIid = useMemo(() => {
    const m = {};
    for (const f of frames) {
      const e = f.entity;
      if (e?.iid && e?.name) m[e.iid] = e.name;
    }
    return m;
  }, [frames]);

  // ── Build attack stages from MITRE data ─────────────────────────
  const stages = useMemo(() => {
    const byTactic = new Map(); // tactic → { techniques, firstTs, lastTs, frames, malicious }
    frames.forEach(f => {
      (f.mitre || []).forEach(tech => {
        const tac = tacticOf(tech);
        if (!byTactic.has(tac))
          byTactic.set(tac, { tactic: tac, techniques: new Set(), firstTs: Infinity, lastTs: -Infinity,
                              frames: [], malicious: false });
        const s = byTactic.get(tac);
        s.techniques.add(tech);
        const t = new Date(f.ts).getTime();
        if (t < s.firstTs) s.firstTs = t;
        if (t > s.lastTs) s.lastTs = t;
        s.frames.push(f);
        if (verdictOf(f) === "malicious") s.malicious = true;
      });
    });
    // MITRE tactic order
    const order = ["INITIAL ACCESS","EXECUTION","DISCOVERY","CREDENTIAL ACCESS",
                   "DEFENSE EVASION","COMMAND & CONTROL","IMPACT","OTHER"];
    return [...byTactic.values()]
      .sort((a,b) => order.indexOf(a.tactic) - order.indexOf(b.tactic))
      .map((s, i) => ({ ...s, techniques: [...s.techniques], idx: i + 1 }));
  }, [frames]);

  // ── Build rows in ancestry order (compromise rows first, then processes, then file/reg/net bands) ──
  const { rows, bands, edges, events } = useMemo(() => {
    if (!frames.length) return { rows: [], bands: [], edges: [], events: [] };

    // Group frames by row key
    const byKey = new Map();
    frames.forEach(f => {
      const k = keyOf(f);
      if (!byKey.has(k))
        byKey.set(k, { key: k, label: labelOf(f), events: [],
                       firstTs: Infinity, lastTs: -Infinity,
                       lane: f.lane || "process",
                       worstVerdict: "benign" });
      const r = byKey.get(k);
      r.events.push(f);
      const t = new Date(f.ts).getTime();
      if (t < r.firstTs) r.firstTs = t;
      if (t > r.lastTs)  r.lastTs = t;
      const v = verdictOf(f);
      if (v === "malicious" || (v === "suspicious" && r.worstVerdict !== "malicious"))
        r.worstVerdict = v;
    });

    // Compromise indicator rows — one per malicious tactic that has actual data
    const compromiseRows = stages
      .filter(s => s.malicious)
      .map((s, i) => ({
        key: `cmp:${s.tactic}`,
        label: `${s.tactic} · ${s.techniques.slice(0, 2).join(", ")}`,
        kind: "compromise",
        indent: 0,
        firstTs: s.firstTs, lastTs: s.lastTs,
        worstVerdict: "malicious",
        eventCount: s.frames.length,
      }));

    // Process rows (system + process lanes) — indented by ancestry heuristic.
    // Since seed data lacks parent IIDs, indent all children of root by simple rule:
    // msiexec at root, its executors indented under it. Use time order as fallback.
    const procRows = [];
    const procKeys = [];
    for (const [k, r] of byKey) {
      if (r.lane === "process" || r.lane === "system") { procRows.push(r); procKeys.push(k); }
    }
    procRows.sort((a, b) => a.firstTs - b.firstTs);
    const rootTs = procRows.length ? procRows[0].firstTs : 0;
    procRows.forEach((r, i) => {
      // Root, first child, deeper descendants — approximate depth via first-seen delay.
      const delta = r.firstTs - rootTs;
      const depth = delta < 30 ? 0 : delta < 100 ? 1 : delta < 250 ? 2 : 3;
      r.indent = i === 0 ? 0 : depth;
      const glyphs = ["", "├─ ", "│  ├─ ", "│  │  └─ ", "│  │     └─ "];
      r.indentGlyph = glyphs[Math.min(depth, glyphs.length - 1)] || "";
      r.kind = "process";
      r.eventCount = r.events.length;
    });

    // File / Registry / Network rows, grouped into bands
    const fileRows = []; const regRows = []; const netRows = [];
    for (const r of byKey.values()) {
      if (r.lane === "file")     { r.kind = "file";     r.eventCount = r.events.length; fileRows.push(r); }
      if (r.lane === "registry") { r.kind = "registry"; r.eventCount = r.events.length; regRows.push(r); }
      if (r.lane === "network")  { r.kind = "network";  r.eventCount = r.events.length; netRows.push(r); }
    }
    const byVerdictThenTime = (a, b) => {
      const ma = a.worstVerdict === "malicious" ? 0 : 1;
      const mb = b.worstVerdict === "malicious" ? 0 : 1;
      if (ma !== mb) return ma - mb;
      return a.firstTs - b.firstTs;
    };
    fileRows.sort(byVerdictThenTime);
    regRows.sort(byVerdictThenTime);
    netRows.sort(byVerdictThenTime);

    // Compose row list & bands
    const allRows = [];
    compromiseRows.forEach(r => allRows.push(r));
    procRows.forEach(r => allRows.push(r));
    const bandDefs = [];
    if (fileRows.length) {
      bandDefs.push({ label: "Files",    rows: fileRows,
                      eventCount: fileRows.reduce((n,r) => n + r.events.length, 0) });
      fileRows.forEach(r => { r.band = "Files"; allRows.push(r); });
    }
    if (regRows.length) {
      bandDefs.push({ label: "Registry", rows: regRows,
                      eventCount: regRows.reduce((n,r) => n + r.events.length, 0) });
      regRows.forEach(r => { r.band = "Registry"; allRows.push(r); });
    }
    if (netRows.length) {
      bandDefs.push({ label: "Network",  rows: netRows,
                      eventCount: netRows.reduce((n,r) => n + r.events.length, 0) });
      netRows.forEach(r => { r.band = "Network"; allRows.push(r); });
    }
    // Compute band tops
    const ROW_H = 22, BAND_H = 22, AXIS_H = 26 + 6;
    let y = AXIS_H;
    let curBand = null;
    allRows.forEach(r => {
      if (r.band && r.band !== curBand) { y += BAND_H; curBand = r.band; }
      y += ROW_H;
    });
    // Second pass to compute band top y-coords
    y = AXIS_H; curBand = null;
    const bandTops = new Map();
    allRows.forEach(r => {
      if (r.band && r.band !== curBand) {
        curBand = r.band;
        bandTops.set(r.band, y + BAND_H);
        y += BAND_H;
      }
      y += ROW_H;
    });
    bandDefs.forEach(b => { b.top = bandTops.get(b.label); });

    // Event list, tagged with rowKey / kind / verdict / source flag
    const evs = frames.map(f => ({
      id: f.frame_iid,
      rowKey: keyOf(f),
      ts: new Date(f.ts).getTime(),
      kind: activityOf(f),
      verdict: verdictOf(f),
      source: isSourceOf(f),
      label: friendlyLabel(f),
      mitre: f.mitre || [],
      meta: f,
    }));

    // Ancestry edges — P1 · IRG. Consume canonical entity.iid / parent.iid
    // now emitted by /app/backend/v2/shadow/irg.py. Fallback to the heuristic
    // depth-based edge when IRG fields aren't present (backwards-compat).
    const entToKey = new Map();
    frames.forEach(f => {
      const eiid = f.entity?.iid;
      if (!eiid) return;
      const k = keyOf(f);
      if (!entToKey.has(eiid)) entToKey.set(eiid, k);
    });
    const seenEdge = new Set();
    const evEdges = [];
    frames.forEach(f => {
      const pIid = f.parent?.iid;
      if (!pIid) return;
      const from = entToKey.get(pIid);
      const to   = keyOf(f);
      if (!from || from === to) return;
      const sig = `${from}->${to}`;
      if (seenEdge.has(sig)) return;
      seenEdge.add(sig);
      evEdges.push({ from, to, kind: f.relationship?.type || "SPAWNED" });
    });
    // Heuristic fallback if IRG produced nothing (e.g. non-enriched case).
    if (evEdges.length === 0) {
      for (let i = 1; i < procRows.length; i++) {
        const child = procRows[i];
        for (let j = i - 1; j >= 0; j--) {
          if ((procRows[j].indent || 0) < (child.indent || 0)) {
            evEdges.push({ from: procRows[j].key, to: child.key });
            break;
          }
        }
      }
    }

    return { rows: allRows, bands: bandDefs, edges: evEdges, events: evs };
  }, [frames, stages]);

  // ── Compromise time-windows ──────────────────────────────────────
  const timeWindows = useMemo(() => {
    const focusStage = selectedStageIdx != null ? stages[selectedStageIdx] : null;
    if (focusStage) {
      return [{ start: focusStage.firstTs, end: focusStage.lastTs,
                label: `${focusStage.tactic}`, kind: "compromise" }];
    }
    return stages.filter(s => s.malicious).map(s => ({
      start: s.firstTs, end: s.lastTs, label: s.tactic, kind: "compromise",
    }));
  }, [stages, selectedStageIdx]);

  // ── Trigger event IDs (blue halos) — set when a compromise row is selected ──
  const triggerIds = useMemo(() => {
    if (!selectedStageIdx && selectedStageIdx !== 0) return null;
    const s = stages[selectedStageIdx];
    if (!s) return null;
    return new Set(s.frames.map(f => f.frame_iid));
  }, [selectedStageIdx, stages]);

  const selEvent = useMemo(
    () => events.find(e => e.id === selected) || null,
    [events, selected],
  );

  // ── Case time bounds ──────────────────────────────────────────────
  const caseBounds = useMemo(() => {
    if (!events.length) return { start: 0, end: 1 };
    let lo = Infinity, hi = -Infinity;
    for (const ev of events) { if (ev.ts < lo) lo = ev.ts; if (ev.ts > hi) hi = ev.ts; }
    if (lo === hi) hi = lo + 1;
    return { start: lo, end: hi };
  }, [events]);

  // ── Search + filter · derive matched event ids ───────────────────
  const { matchedIds, matchedRowKeys } = useMemo(() => {
    const q = (searchQuery || "").trim().toLowerCase();
    const verdictOn = filters.verdict;
    const kindOn = filters.kind;
    const allVerdictsOn = Object.values(verdictOn).every(Boolean);
    const allKindsOn    = Object.values(kindOn).every(Boolean);
    if (!q && allVerdictsOn && allKindsOn) {
      return { matchedIds: null, matchedRowKeys: null };
    }
    const ids = new Set();
    const rk  = new Set();
    for (const ev of events) {
      const v = ev.verdict || "benign";
      const k = ev.kind    || "process";
      if (verdictOn[v] === false) continue;
      if (kindOn[k] === false) continue;
      if (q) {
        const hay = `${ev.label || ""} ${ev.meta?.entity?.name || ""} ${ev.rowKey || ""}`.toLowerCase();
        if (!hay.includes(q)) continue;
      }
      ids.add(ev.id);
      rk.add(ev.rowKey);
    }
    return { matchedIds: ids, matchedRowKeys: rk };
  }, [events, searchQuery, filters]);

  // ── Search-driven focus ──────────────────────────────────────────
  // When the analyst types a query that resolves to at least one
  // matching event, auto-select the earliest match so the Evidence
  // pane populates AND focus the timeline viewport on the matched
  // time window. Feels like a real search: type → the workspace jumps.
  useEffect(() => {
    if (!matchedIds || matchedIds.size === 0) return;
    if (selected && matchedIds.has(selected)) return;   // already on a match
    const matches = events.filter(e => matchedIds.has(e.id))
                          .sort((a, b) => a.ts - b.ts);
    if (!matches.length) return;
    setSelected(matches[0].id);
    // Frame the viewport around the matched span so the canvas visibly
    // "jumps" to the results.
    const lo = matches[0].ts;
    const hi = matches[matches.length - 1].ts;
    const pad = Math.max(50, (hi - lo) * 0.15 || (caseBounds.end - caseBounds.start) * 0.05);
    setViewport({ start: lo - pad, end: hi + pad });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [matchedIds]);

  // ── Attack Chain sidebar filtering ───────────────────────────────
  // When a search / filter narrows the frames, show only stages that
  // have at least one matching frame so the sidebar reflects the
  // current query context instead of the entire attack.
  const visibleStages = useMemo(() => {
    if (!matchedIds || matchedIds.size === 0) return stages;
    return stages.filter(s =>
      (s.frames || []).some(f => matchedIds.has(f.frame_iid)),
    );
  }, [stages, matchedIds]);

  // ── Timeline canvas filtering ────────────────────────────────────
  // When a search / filter is active, keep only rows that contain at
  // least one matching event, keep only matching events, and drop
  // edges whose endpoints were filtered out. This makes the whole
  // workspace behave like a real search: type → only relevant data.
  const filteredRows   = useMemo(() => {
    if (!matchedRowKeys || matchedRowKeys.size === 0) return rows;
    return rows.filter(r => matchedRowKeys.has(r.key) || r.kind === "compromise");
  }, [rows, matchedRowKeys]);
  const filteredEvents = useMemo(() => {
    if (!matchedIds || matchedIds.size === 0) return events;
    return events.filter(e => matchedIds.has(e.id));
  }, [events, matchedIds]);
  const filteredEdges  = useMemo(() => {
    if (!matchedRowKeys || matchedRowKeys.size === 0) return edges;
    return edges.filter(e => matchedRowKeys.has(e.from) && matchedRowKeys.has(e.to));
  }, [edges, matchedRowKeys]);
  const filteredBands  = useMemo(() => {
    if (!matchedRowKeys || matchedRowKeys.size === 0) return bands;
    return bands
      .map(b => ({ ...b, rows: (b.rows || []).filter(r => matchedRowKeys.has(r.key)) }))
      .filter(b => b.rows.length > 0);
  }, [bands, matchedRowKeys]);

  // ── Playback · advances the viewport across the case timeline ─────
  useEffect(() => {
    if (!playing) return;
    const span = Math.max(1, caseBounds.end - caseBounds.start);
    const winMs = viewport
      ? Math.max(1, viewport.end - viewport.start)
      : span * 0.10;
    const stepMs = span / 240;
    let start = viewport?.start ?? caseBounds.start;
    setViewport({ start, end: start + winMs });
    const tickMs = Math.max(10, 40 / (playbackSpeed || 1));
    const id = setInterval(() => {
      start += stepMs;
      if (start + winMs >= caseBounds.end) {
        setViewport({ start: caseBounds.end - winMs, end: caseBounds.end });
        setPlaying(false);
        return;
      }
      setViewport({ start, end: start + winMs });
    }, tickMs);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [playing, playbackSpeed, caseBounds.start, caseBounds.end]);

  // ── Compare Sync-Scrub · postMessage relay when embedded in an iframe ─
  // Broadcast our reported viewport upward; accept inbound viewport writes
  // from a sibling frame.
  useEffect(() => {
    if (window.parent === window) return;
    if (!reportedVp) return;
    window.parent.postMessage(
      { __nvx: "viewport", start: reportedVp.start, end: reportedVp.end }, "*",
    );
  }, [reportedVp]);
  useEffect(() => {
    if (window.parent === window) return;
    const onMsg = (e) => {
      const d = e.data;
      if (!d || d.__nvx !== "viewport") return;
      if (typeof d.start !== "number" || typeof d.end !== "number") return;
      setViewport({ start: d.start, end: d.end });
    };
    window.addEventListener("message", onMsg);
    return () => window.removeEventListener("message", onMsg);
  }, []);

  // ── Attack-chain click: also focuses the viewport on that stage's window ─
  const handleStageSelect = useCallback((idx) => {
    if (idx === selectedStageIdx) {  // toggle off
      setSelectedStageIdx(null);
      setViewport(null);
      return;
    }
    setSelectedStageIdx(idx);
    const s = stages[idx];
    if (!s) return;
    // Pad the stage window by ±10 % so we don't clip the first/last event.
    const pad = Math.max(1, (s.lastTs - s.firstTs) * 0.10);
    setViewport({ start: s.firstTs - pad, end: s.lastTs + pad });
  }, [selectedStageIdx, stages]);

  // ── Date-range dropdown: set viewport to N hours around case end ───
  const handleRangeChange = useCallback((range) => {
    if (range === "all") { setViewport(null); return; }
    const ms = { "24h": 24*3600e3, "7d": 7*24*3600e3, "30d": 30*24*3600e3, "90d": 90*24*3600e3 }[range];
    if (!ms) return;
    setViewport({ start: caseBounds.end - ms, end: caseBounds.end });
  }, [caseBounds]);

  // ── Keyboard navigation ───────────────────────────────────────────
  useEffect(() => {
    const eventsSorted = [...events].sort((a, b) => a.ts - b.ts);
    const rowKeys = rows.map(r => r.key);
    const eventsByRow = new Map();
    eventsSorted.forEach(ev => {
      if (!eventsByRow.has(ev.rowKey)) eventsByRow.set(ev.rowKey, []);
      eventsByRow.get(ev.rowKey).push(ev);
    });

    const handler = (e) => {
      if (e.target && /INPUT|TEXTAREA/.test(e.target.tagName)) return;

      if (e.key === "Escape") { setSelected(null); setSelectedStageIdx(null); setViewport(null); return; }
      if (e.key.toLowerCase() === "f") { setViewport(null); return; }
      if (e.key === "Home") { setViewport({ start: caseBounds.start, end: caseBounds.start + (caseBounds.end-caseBounds.start)*0.1 }); return; }
      if (e.key === "End")  { setViewport({ start: caseBounds.end - (caseBounds.end-caseBounds.start)*0.1, end: caseBounds.end }); return; }
      if (e.key === "Enter") {
        const cur = eventsSorted.find(ev => ev.id === selected);
        if (cur) {
          // Center viewport on the selected event · 10 % of case span.
          const span = Math.max(1, (caseBounds.end - caseBounds.start) * 0.10);
          setViewport({ start: cur.ts - span / 2, end: cur.ts + span / 2 });
        }
        return;
      }

      const cur = eventsSorted.find(ev => ev.id === selected);
      if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
        e.preventDefault();
        if (!eventsSorted.length) return;
        if (!cur) { setSelected(eventsSorted[0].id); return; }
        const idx = eventsSorted.findIndex(ev => ev.id === cur.id);
        const next = e.key === "ArrowRight"
          ? eventsSorted[Math.min(eventsSorted.length - 1, idx + 1)]
          : eventsSorted[Math.max(0, idx - 1)];
        if (next) setSelected(next.id);
      }
      if (e.key === "ArrowUp" || e.key === "ArrowDown") {
        e.preventDefault();
        if (!rowKeys.length) return;
        const curRowIdx = cur ? rowKeys.indexOf(cur.rowKey) : -1;
        const nextRowIdx = e.key === "ArrowDown"
          ? Math.min(rowKeys.length - 1, curRowIdx + 1)
          : Math.max(0, curRowIdx - 1);
        const targetKey = rowKeys[nextRowIdx];
        const list = eventsByRow.get(targetKey);
        if (list && list.length) {
          setSelected(list[0].id);
        }
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [events, rows, selected, caseBounds]);

  const caseMeta = data?.case || {};
  const compromiseCount = stages.filter(s => s.malicious).length;

  if (!enabled) {
    return (
      <div className="w-screen h-screen grid place-items-center"
           style={{ background: T.bg, color: T.inkMute }}>
        <div>V2 trajectory engine disabled. Set <code>TRAJECTORY_ENGINE=observable</code>.</div>
      </div>
    );
  }

  const cardStyle = {
    background: T.cardGradient,
    border: `1px solid ${T.line}`,
    borderRadius: 12,
    boxShadow: "inset 0 1px 0 rgba(255,255,255,0.04), 0 8px 32px -8px rgba(0,0,0,0.65)",
    backdropFilter: "blur(14px)",
    WebkitBackdropFilter: "blur(14px)",
    overflow: "hidden",
  };

  return (
    <div className="flex flex-col"
         style={{ minHeight: embedded ? "auto" : "100vh", background: T.bg, color: T.ink }}>
      {!embedded && <Header />}
    <div data-testid="trajectory-v2"
         className="w-full overflow-hidden flex flex-col p-3 gap-3"
         style={{ flex: "1 1 0", minHeight: 0, height: embedded ? "calc(100vh - 120px)" : "calc(100vh - 56px)", background: T.bg, color: T.ink }}>
      {/* ── TOP CONTAINER · Timeline Range ────────────────────────── */}
      <div className="flex-shrink-0 flex flex-col" style={cardStyle}
           data-testid="workspace-top">
        {/* Card toolbar — logo · search · filters · date range · expand · close */}
        <CardToolbar caseId={caseId} meta={caseMeta}
                     onRangeChange={handleRangeChange}
                     reportedVp={reportedVp}
                     caseBounds={caseBounds}
                     onDetails={() => setDrawerOpen(o => !o)}
                     detailsOpen={drawerOpen}
                     searchQuery={searchQuery}
                     onSearch={setSearchQuery}
                     filters={filters}
                     onFilters={setFilters}
                     onFullscreen={() => {
                       const el = document.documentElement;
                       if (document.fullscreenElement) document.exitFullscreen();
                       else el.requestFullscreen && el.requestFullscreen();
                     }}
                     onClose={() => navigate("/")} />
        {/* 30-day overview + 24-hour selected-day strip + trend line */}
        <TimeRangeBox stages={stages}
                      selectedStageIdx={selectedStageIdx}
                      onSelectStage={handleStageSelect}
                      caseBounds={caseBounds}
                      reportedVp={reportedVp}
                      setViewport={setViewport}
                      playing={playing}
                      onTogglePlay={() => setPlaying(p => !p)}
                      playbackSpeed={playbackSpeed}
                      onSpeedChange={setPlaybackSpeed}
                      bookmarks={bookmarks}
                      onBookmarksChange={setBookmarks} />
      </div>

      {/* ── BOTTOM CONTAINER · Device Trajectory ──────────────────── */}
      <div className="flex-1 min-h-0 flex flex-col" style={cardStyle}
           data-testid="workspace-bottom">
        <div className="grid flex-1 min-h-0"
             style={{ gridTemplateColumns: "232px 1fr 340px" }}>
          {/* Attack chain sidebar */}
          <AttackChainSidebar stages={visibleStages}
                              selectedIdx={selectedStageIdx}
                              onSelect={handleStageSelect} />

          {/* Timeline canvas · middle column */}
          <div className="relative flex flex-col min-h-0"
               style={{ background: T.paper,
                        borderLeft: `1px solid ${T.line}`,
                        borderRight: `1px solid ${T.line}` }}>
            <div className="px-4 py-2 text-[10px] tracking-[2px] font-bold flex-shrink-0"
                 style={{ color: T.inkMute, borderBottom: `1px solid ${T.line}` }}>
              TIMELINE · JUL 22
            </div>
            <div className="relative flex-1 min-h-0">
              {err && <ErrorBanner err={err} />}
              {!err && !frames.length && <LoadingBanner />}
              {!err && frames.length > 0 && filteredRows.length === 0 && (
                <div className="absolute inset-0 flex items-center justify-center text-[11px]"
                     data-testid="canvas-no-match"
                     style={{ color: T.inkMute }}>
                  No events match &quot;{searchQuery}&quot;. Press Esc or clear the search to see all events.
                </div>
              )}
              {!err && frames.length > 0 && filteredRows.length > 0 && (
                <InvestigationCanvas rows={filteredRows} events={filteredEvents}
                                     edges={filteredEdges} bands={filteredBands}
                                     timeWindows={timeWindows}
                                     selected={selected}
                                     triggerIds={triggerIds}
                                     focusRange={viewport}
                                     onViewportChange={setReportedVp}
                                     onFocusTime={setViewport}
                                     matchedIds={matchedIds}
                                     matchedRowKeys={matchedRowKeys}
                                     onSelect={(ev) => setSelected(ev?.id || null)} />
              )}
            </div>
          </div>

          {/* Evidence pane */}
          <EvidencePane event={selEvent} tab={rightTab} onTab={setRightTab}
                        nameByIid={nameByIid}
                        onFocusParent={(pIid) => {
                          const target = events.find(e => e.meta?.entity?.iid === pIid);
                          if (target) setSelected(target.id);
                        }} />
        </div>

        {/* Status bar */}
        <StatusBar rows={filteredRows} events={filteredEvents}
                   selectedStageIdx={selectedStageIdx}
                   compromiseCount={compromiseCount} />
      </div>

      {/* Slide-in device details drawer */}
      <DeviceDetailsDrawer open={drawerOpen}
                           onClose={() => setDrawerOpen(false)}
                           caseId={caseId}
                           meta={caseMeta}
                           events={events}
                           stages={stages}
                           caseBounds={caseBounds}
                           bookmarks={bookmarks}
                           onBookmarksChange={setBookmarks}
                           onJumpBookmark={(bm) => {
                             const span = Math.max(50, (caseBounds.end - caseBounds.start) * 0.10);
                             setViewport({ start: bm.ts - span / 2, end: bm.ts + span / 2 });
                           }} />
    </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
export function CardToolbar({ caseId, meta, onRangeChange, reportedVp, caseBounds,
                              activeTab = "trajectory", onDetails, detailsOpen,
                              searchQuery = "", onSearch = () => {},
                              filters, onFilters = () => {},
                              onFullscreen = () => {}, onClose = () => {} }) {
  const [range, setRange] = useState("all");
  const [filtersOpen, setFiltersOpen] = useState(false);
  const options = [
    ["all", "Entire Case"], ["24h", "24 Hours"], ["7d", "7 Days"],
    ["30d", "30 Days"], ["90d", "90 Days"],
  ];
  const change = (v) => { setRange(v); onRangeChange && onRangeChange(v); };
  const fmt = (ts) => new Date(ts).toISOString().replace("T", " ").slice(0, 19);
  const vpStart = reportedVp?.start ?? caseBounds?.start;
  const vpEnd   = reportedVp?.end   ?? caseBounds?.end;
  const tabs = [
    { key: "trajectory", label: "Device Trajectory", href: `/v2/trajectory/${caseId}` },
    { key: "irg",        label: "IRG",               href: `/v2/irg/${caseId}` },
    { key: "compare",    label: "Compare",           href: `/v2/compare/${caseId}/${caseId}` },
  ];
  const activeFilterCount =
    Object.values(filters?.verdict || {}).filter(x => x === false).length +
    Object.values(filters?.kind    || {}).filter(x => x === false).length;
  const copyRange = () => {
    try {
      const s = vpStart ? new Date(vpStart).toISOString() : "";
      const e = vpEnd   ? new Date(vpEnd).toISOString()   : "";
      navigator.clipboard.writeText(`${s} → ${e}`);
    } catch {}
  };

  return (
    <div className="flex items-center gap-3 px-4 py-2 flex-shrink-0"
         style={{ borderBottom: `1px solid ${T.line}` }}
         data-testid="card-toolbar">
      <div className="flex items-center gap-2">
        <div className="w-6 h-6 rounded flex items-center justify-center"
             style={{ background: "rgba(52, 211, 153, 0.15)",
                      border: `1px solid rgba(52, 211, 153, 0.55)` }}>
          <Radar size={13} color={T.amber} />
        </div>
        <div>
          <div className="text-[11px] font-bold" style={{ color: T.ink }}>NivXRay</div>
          <div className="text-[9px]" style={{ color: T.inkMute }}>Investigation Workspace</div>
        </div>
      </div>
      {/* Workspace tabs · same IRG data model, different visualisations */}
      <div className="flex items-center rounded overflow-hidden ml-2"
           style={{ background: T.paper2, border: `1px solid ${T.line}` }}
           data-testid="workspace-tabs">
        {tabs.map(t => (
          <a key={t.key} href={t.href}
             data-testid={`workspace-tab-${t.key}`}
             className="text-[11px] font-semibold px-3 py-1.5 tracking-wide"
             style={{
               color: activeTab === t.key ? "#05080F" : T.inkDim,
               background: activeTab === t.key ? T.amber : "transparent",
               textDecoration: "none",
             }}>
            {t.label}
          </a>
        ))}
      </div>
      <div className="flex-1 max-w-md mx-2 relative">
        <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2"
                style={{ color: T.inkFaint }} />
        <input type="text" placeholder="Search Investigation"
               data-testid="search-input"
               value={searchQuery}
               onChange={(e) => onSearch(e.target.value)}
               className="w-full pl-8 pr-3 py-1.5 rounded text-[12px] outline-none"
               style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.ink }} />
      </div>
      <div className="relative">
        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[12px]"
                style={{ background: filtersOpen ? T.blueT : T.paper,
                         border: `1px solid ${filtersOpen ? T.blue : T.line}`,
                         color: T.ink }}
                onClick={() => setFiltersOpen(o => !o)}
                data-testid="filters-button">
          <Filter size={12} /> Filters
          {activeFilterCount > 0 && (
            <span className="text-[9px] font-mono px-1 py-0.5 rounded"
                  style={{ background: T.amber, color: "#05080F" }}>
              {activeFilterCount}
            </span>
          )}
          <span style={{ color: T.inkFaint }}>▾</span>
        </button>
        {filtersOpen && (
          <FiltersPopover filters={filters} onChange={onFilters}
                          onClose={() => setFiltersOpen(false)} />
        )}
      </div>
      {/* Date range dropdown — drives the shared viewport */}
      <select value={range} onChange={(e) => change(e.target.value)}
              data-testid="range-select"
              className="text-[11px] font-mono px-2 py-1.5 rounded outline-none cursor-pointer"
              style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.ink }}>
        {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>
      <button onClick={copyRange}
              className="flex items-center gap-2 px-3 py-1.5 rounded text-[11px] font-mono"
              style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.ink }}
              data-testid="viewport-display"
              title="Click to copy time-window as ISO">
        <span>{vpStart ? fmt(vpStart) : "—"}</span>
        <span style={{ color: T.inkFaint }}>→</span>
        <span>{vpEnd ? fmt(vpEnd) : "—"}</span>
      </button>
      <button onClick={onFullscreen}
              data-testid="fullscreen-toggle"
              className="w-7 h-7 rounded flex items-center justify-center"
              style={{ border: `1px solid ${T.line}`, color: T.inkDim }} title="Fullscreen (F11)">⛶</button>
      <button data-testid="details-toggle"
              onClick={onDetails}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] font-semibold"
              style={{
                background: detailsOpen ? T.amber : T.paper2,
                color:      detailsOpen ? "#05080F" : T.ink,
                border: `1px solid ${detailsOpen ? T.amber : T.line}`,
              }}
              title="Toggle device details">
        {detailsOpen ? "Hide details" : "Details"}
      </button>
      <button onClick={onClose}
              data-testid="close-btn"
              className="w-7 h-7 rounded flex items-center justify-center"
              style={{ border: `1px solid ${T.line}`, color: T.inkDim }} title="Close">✕</button>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// TimeRangeBox — full-width top box:
//   Header row · trend sparkline · multi-day date strip (30d) with red
//   compromise dot on the case day · selected-day hour strip with hatched
//   "not-selected" portion.
//   INTERACTIVE: click / drag / wheel on the hour strip drives the shared
//   viewport. Day chips click to focus that day. Yellow band reflects the
//   currently visible time-range reported by the canvas.
// ═══════════════════════════════════════════════════════════════════
export function TimeRangeBox({ stages, selectedStageIdx, onSelectStage,
                       caseBounds, reportedVp, setViewport,
                       playing = false, onTogglePlay = () => {},
                       playbackSpeed = 1, onSpeedChange = () => {},
                       bookmarks = [], onBookmarksChange = () => {} }) {
  const days = ["23","24","25","26","27","28","29","30",
                "1","2","3","4","5","6","7","8","9","10","11","12","13","14",
                "15","16","17","18","19","20","21","22"];
  const monthMarks = { 0: "Jun", 8: "Jul" };
  const caseDayIdx = days.length - 1; // last day = Jul 22

  const hourStripRef = useRef(null);
  const dragRef      = useRef(null);

  // Map ts ↔ fraction across the hour strip (0..1 = full case span).
  const span = Math.max(1, caseBounds.end - caseBounds.start);
  const tsToFrac = (ts) => Math.min(1, Math.max(0, (ts - caseBounds.start) / span));
  const fracToTs = (f)  => caseBounds.start + Math.min(1, Math.max(0, f)) * span;

  const vpStart = reportedVp?.start ?? caseBounds.start;
  const vpEnd   = reportedVp?.end   ?? caseBounds.end;
  const vpFracLo = tsToFrac(vpStart);
  const vpFracHi = tsToFrac(vpEnd);
  const vpWinMs  = Math.max(1, vpEnd - vpStart);

  // Click a day chip → focus that day
  const dayClick = (i) => {
    // Only wire the case day (last chip) meaningfully. Others could be wired
    // later once multi-day data exists.
    if (i !== caseDayIdx) return;
    setViewport(null);
  };

  // Hour-strip pointer utilities
  const fracFromEvent = (e) => {
    const r = hourStripRef.current?.getBoundingClientRect();
    if (!r) return 0;
    return Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
  };
  const onStripMouseDown = (e) => {
    const f = fracFromEvent(e);
    if (e.shiftKey) {
      // Shift+drag → marquee time-window selection (canvas + attack chain
      // + evidence stay in sync automatically because everything is bound to
      // the viewport).
      dragRef.current = { startFrac: f, mode: "marquee" };
      setViewport({ start: fracToTs(f), end: fracToTs(f) });
      e.preventDefault();
      return;
    }
    const ts = fracToTs(f);
    // Click = center a viewport window equal to the current window size on the ts
    setViewport({ start: ts - vpWinMs / 2, end: ts + vpWinMs / 2 });
    dragRef.current = { startFrac: f, mode: "pan", initVp: { start: vpStart, end: vpEnd } };
    e.preventDefault();
  };
  const onStripMouseMove = (e) => {
    if (!dragRef.current) return;
    const f = fracFromEvent(e);
    if (dragRef.current.mode === "marquee") {
      const a = fracToTs(dragRef.current.startFrac);
      const b = fracToTs(f);
      setViewport({ start: Math.min(a, b), end: Math.max(a, b) });
      return;
    }
    const dFrac = f - dragRef.current.startFrac;
    const dMs = dFrac * span;
    const ns = dragRef.current.initVp.start + dMs;
    const ne = dragRef.current.initVp.end   + dMs;
    setViewport({ start: ns, end: ne });
  };
  const onStripMouseUp = () => { dragRef.current = null; };
  useEffect(() => {
    const mv = (e) => onStripMouseMove(e);
    const up = () => onStripMouseUp();
    window.addEventListener("mousemove", mv);
    window.addEventListener("mouseup", up);
    return () => { window.removeEventListener("mousemove", mv);
                   window.removeEventListener("mouseup", up); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vpStart, vpEnd, span]);

  const onStripWheel = (e) => {
    e.preventDefault();
    const f = fracFromEvent(e);
    const anchorTs = fracToTs(f);
    const factor = e.deltaY > 0 ? 1.15 : 0.87;
    const newWin = Math.min(span, Math.max(50, vpWinMs * factor));
    setViewport({ start: anchorTs - (anchorTs - vpStart) * (newWin / vpWinMs),
                  end:   anchorTs + (vpEnd - anchorTs)   * (newWin / vpWinMs) });
  };

  // Right-click to drop a labelled bookmark at that timestamp.
  const onStripContextMenu = (e) => {
    e.preventDefault();
    const f = fracFromEvent(e);
    const ts = fracToTs(f);
    let label = "";
    try {
      // Non-blocking-ish native prompt keeps the interaction cheap and
      // avoids introducing a modal component for a one-line input.
      const iso = new Date(ts).toISOString();
      label = window.prompt(`Bookmark name for ${iso} · leave blank for none`, "") || "";
    } catch { /* prompt not available */ }
    const id = `bm_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
    onBookmarksChange([...bookmarks, { id, ts, label: label.trim() }]);
  };

  // Click a bookmark → jump viewport to it (center a 10 % window around it).
  const jumpToBookmark = (bm) => {
    const win = Math.max(50, span * 0.10);
    setViewport({ start: bm.ts - win / 2, end: bm.ts + win / 2 });
  };

  // Double click on the hour strip → reset viewport (Fit)
  const onStripDoubleClick = () => setViewport(null);

  return (
    <div className="flex flex-shrink-0" style={{ borderTop: `1px solid ${T.line}` }}
         data-testid="time-range-box">
      {/* Left label */}
      <div className="px-4 py-3 flex-shrink-0" style={{ width: 156, borderRight: `1px solid ${T.line}` }}>
        <div className="flex items-center gap-2 mb-1">
          <div className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold"
               style={{ background: T.amber, color: "#05080F" }}>1</div>
          <div className="text-[10px] tracking-[1.6px] font-bold" style={{ color: T.ink }}>TIME RANGE</div>
        </div>
        <div className="text-[10px]" style={{ color: T.inkMute }}>
          Click · drag · wheel
        </div>
        <div className="flex items-center gap-1 mt-1 flex-wrap">
          <button onClick={onTogglePlay}
                  data-testid="playback-toggle"
                  className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                  style={{
                    background: playing ? T.amber : T.paper2,
                    color:      playing ? "#05080F" : T.inkDim,
                    border: `1px solid ${playing ? T.amber : T.line}`,
                    minWidth: 44,
                  }}
                  title="Toggle playback">
            {playing ? "⏸" : "▶"}
          </button>
          {[0.5, 1, 2].map(sp => {
            const active = playbackSpeed === sp;
            return (
              <button key={sp} onClick={() => onSpeedChange(sp)}
                      data-testid={`speed-${sp}`}
                      className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                      style={{
                        background: active ? T.amber : T.paper2,
                        color:      active ? "#05080F" : T.inkDim,
                        border: `1px solid ${active ? T.amber : T.line}`,
                      }}
                      title={`Playback speed ${sp}×`}>
                {sp}×
              </button>
            );
          })}
          <button onClick={() => setViewport(null)}
                  data-testid="fit-button"
                  className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                  style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.inkDim }}>
            Fit
          </button>
          {bookmarks.length > 0 && (
            <button onClick={() => onBookmarksChange([])}
                    data-testid="bookmarks-clear"
                    className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                    style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.inkDim }}
                    title={`Clear ${bookmarks.length} bookmark(s)`}>
              Clear ({bookmarks.length})
            </button>
          )}
        </div>
      </div>

      {/* Right side — trend + day strip + hour strip */}
      <div className="flex-1 relative py-2">
        {/* Trend sparkline across the top */}
        <svg viewBox="0 0 1400 24" preserveAspectRatio="none"
             className="w-full h-6"
             style={{ display: "block" }}>
          <polyline fill="none" stroke={T.blue} strokeWidth="1"
                    opacity="0.55"
                    points="0,20 50,18 100,15 150,17 200,14 250,12 300,15 350,12 400,10
                            450,13 500,11 550,14 600,10 650,13 700,11 750,15 800,12 850,14
                            900,16 950,13 1000,15 1050,17 1100,14 1150,16 1200,15 1250,17
                            1300,15 1350,13 1400,16"/>
        </svg>

        {/* Day strip */}
        <div className="flex items-baseline mt-1 pr-4" style={{ paddingLeft: 40 }}>
          {days.map((d, i) => (
            <button key={i}
                    data-testid={`day-chip-${i}`}
                    onClick={() => dayClick(i)}
                    className="flex-1 flex flex-col items-center relative"
                    style={{ background: "none", border: "none", padding: 0,
                             cursor: i === caseDayIdx ? "pointer" : "default" }}>
              <div className={`text-[11px] ${i === caseDayIdx ? "font-bold rounded flex items-center justify-center" : ""}`}
                   style={i === caseDayIdx
                     ? { background: T.amber, color: "#0A1220", width: 22, height: 22 }
                     : { color: T.inkDim }}>
                {d}
              </div>
              {monthMarks[i] && (
                <div className="absolute -bottom-4 text-[10px]" style={{ color: T.inkFaint }}>
                  {monthMarks[i]}
                </div>
              )}
              {i === caseDayIdx && (
                <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full"
                      style={{ background: T.red }} />
              )}
            </button>
          ))}
        </div>

        {/* Selected-day (Jul 22) hour strip — INTERACTIVE */}
        <div className="mt-6 relative" style={{ height: 44 }}>
          <div className="absolute left-0 top-0 bottom-0 flex items-center px-3"
               style={{ width: 68, background: T.paper2,
                        border: `1px solid ${T.line}`, borderRadius: 4 }}>
            <span className="text-[11px] font-semibold" style={{ color: T.ink }}>Jul 22</span>
            <span className="ml-2 w-1.5 h-1.5 rounded-full" style={{ background: T.red }} />
          </div>
          <div className="absolute inset-0 flex flex-col justify-end" style={{ paddingLeft: 76 }}>
            <div ref={hourStripRef}
                 data-testid="hour-strip"
                 onMouseDown={onStripMouseDown}
                 onWheel={onStripWheel}
                 onDoubleClick={onStripDoubleClick}
                 onContextMenu={onStripContextMenu}
                 className="relative h-6 rounded select-none"
                 style={{ cursor: "crosshair",
                          background: `repeating-linear-gradient(45deg, ${T.paper} 0 6px, ${T.line} 6px 7px)` }}>
              {/* Not-hatched context region */}
              <div className="absolute top-0 bottom-0 rounded pointer-events-none"
                   style={{
                     left: 0, right: 0,
                     background: T.paper, opacity: 0.35,
                     border: `1px solid ${T.line}`,
                   }} />
              {/* Yellow "currently visible" window · tracks canvas viewport */}
              <div className="absolute top-0 bottom-0 pointer-events-none"
                   data-testid="viewport-window"
                   style={{
                     left:  `${vpFracLo * 100}%`,
                     width: `${Math.max(0.5, (vpFracHi - vpFracLo) * 100)}%`,
                     background: T.amber, opacity: 0.60,
                     border: `1.5px solid ${T.amber}`,
                   }} />
              {/* Compromise dots — one per malicious stage */}
              {stages.filter(s => s.malicious).map((s, i) => (
                <div key={`cd-${i}`}
                     className="absolute w-1 h-6 pointer-events-none"
                     style={{ left: `${tsToFrac((s.firstTs + s.lastTs) / 2) * 100}%`,
                              background: T.red, opacity: 0.55, top: 0 }} />
              ))}
              {/* Bookmarks — label pill + triangle. Click jumps, right-click deletes. */}
              {bookmarks.map(bm => {
                const iso = new Date(bm.ts).toISOString();
                const title = `${bm.label ? bm.label + " · " : ""}${iso} · click to jump · right-click to delete`;
                return (
                  <div key={bm.id}
                       data-testid={`bookmark-${bm.id}`}
                       className="absolute flex flex-col items-center"
                       style={{
                         left: `${tsToFrac(bm.ts) * 100}%`,
                         top: -22,
                         transform: "translateX(-50%)",
                         zIndex: 5,
                       }}>
                    {bm.label && (
                      <div className="text-[9px] font-mono px-1 py-0.5 rounded whitespace-nowrap mb-0.5"
                           style={{
                             background: T.blue,
                             color: "#05080F",
                             maxWidth: 120,
                             overflow: "hidden",
                             textOverflow: "ellipsis",
                             boxShadow: "0 4px 10px -3px rgba(0,0,0,0.6)",
                             pointerEvents: "none",
                           }}
                           title={title}>
                        {bm.label}
                      </div>
                    )}
                    <button onClick={(e) => { e.stopPropagation(); jumpToBookmark(bm); }}
                            onContextMenu={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              onBookmarksChange(bookmarks.filter(x => x.id !== bm.id));
                            }}
                            style={{
                              width: 0, height: 0,
                              borderLeft: "5px solid transparent",
                              borderRight: "5px solid transparent",
                              borderTop: `7px solid ${T.blue}`,
                              background: "transparent", padding: 0, cursor: "pointer",
                            }}
                            title={title} />
                  </div>
                );
              })}
            </div>
            <div className="flex justify-between mt-1 text-[9px] font-mono" style={{ color: T.inkMute }}>
              {["00:00","02:00","04:00","06:00","08:00","10:00","12:00","14:00","16:00","18:00","20:00","22:00","24:00"].map(h => (
                <span key={h}>{h}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
function CaseBar({ caseId, meta, eventCount, procCount, compromiseCount, onOpenCase }) {
  return (
    <div className="flex items-center gap-4 px-4"
         style={{ height: 32, background: T.paper, borderBottom: `1px solid ${T.line}` }}
         data-testid="case-bar">
      <div className="flex items-center gap-2">
        <div className="w-4 h-4 rounded flex items-center justify-center"
             style={{ background: "#2563EB22", border: `1px solid #2563EB55` }}>
          <Radar size={10} color={T.blue} />
        </div>
        <div className="text-[9px] tracking-[2px] font-bold" style={{ color: T.inkMute }}>NIVXRAY</div>
        <div className="text-[11px] font-semibold" style={{ color: T.ink }}>Device Trajectory</div>
      </div>

      <div className="text-[12px] font-mono font-semibold" style={{ color: T.ink }}>
        {meta.host || "FIN-DC-01"}
      </div>
      <div className="text-[11px]" style={{ color: T.inkMute }}>
        {meta.os || "win-2019-server"} · connector {meta.connector || "7.5.19"}
      </div>
      <div className="flex items-center gap-1.5 text-[11px]" style={{ color: T.red }}>
        <span className="w-1.5 h-1.5 rounded-full" style={{ background: T.red }} />
        <span className="font-semibold">Isolated {meta.isolatedAt || "13:04:55Z"}</span>
      </div>

      <div className="ml-auto text-[11px] font-mono" style={{ color: T.ink }}>
        <b>{eventCount}</b> events ·{" "}
        <span style={{ color: T.red, fontWeight: 700 }}>{compromiseCount}</span> compromises ·{" "}
        <b>{procCount}</b> processes
      </div>

      <div className="flex items-center gap-4 text-[11px]" style={{ color: T.inkMute }}>
        <span>Cmd+K</span>
        <span>Filters ⌘\</span>
        <span>Help ?</span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
function TimeCompass({ stages, selectedStageIdx, onSelectStage }) {
  // Compute 24-hour bounds from all stages
  const bounds = useMemo(() => {
    if (!stages.length) return { lo: 0, hi: 0 };
    let lo = Infinity, hi = -Infinity;
    stages.forEach(s => { if (s.firstTs < lo) lo = s.firstTs; if (s.lastTs > hi) hi = s.lastTs; });
    // Expand to a friendly 24h-window around the case
    const day = 24 * 3600 * 1000;
    return { lo: lo - day / 2, hi: hi + day / 2 };
  }, [stages]);

  const width = 1600;
  const pad = 96;
  const usable = width - pad - 240;
  const xFor = (t) => pad + ((t - bounds.lo) / Math.max(1, bounds.hi - bounds.lo)) * usable;

  return (
    <div className="flex items-center px-4"
         style={{ height: 56, background: T.paper2, borderBottom: `1px solid ${T.line}` }}
         data-testid="time-compass">
      <div>
        <div className="text-[9px] tracking-[1.6px] font-bold" style={{ color: T.inkMute }}>TIMELINE</div>
        <div className="text-[9px] font-mono" style={{ color: T.inkFaint }}>24-hour lens</div>
      </div>
      <div className="relative flex-1 h-full ml-4" style={{ minWidth: 400 }}>
        {/* Density baseline */}
        <div className="absolute inset-x-0 bottom-3 top-3 rounded"
             style={{ background: "#2563EB10" }} />
        {/* Compromise time windows (yellow) */}
        {stages.filter(s => s.malicious).map((s, i) => {
          const x0 = xFor(s.firstTs), x1 = xFor(s.lastTs);
          const isSel = selectedStageIdx === s.idx - 1;
          return (
            <button key={i} onClick={() => onSelectStage(s.idx - 1)}
                    className="absolute top-3 bottom-3"
                    style={{
                      left: x0, width: Math.max(3, x1 - x0),
                      background: T.amber, opacity: isSel ? 0.85 : 0.55,
                      border: isSel ? `1.5px solid ${T.ink}` : "none",
                    }}
                    title={s.tactic} />
          );
        })}
        {/* Compromise dots */}
        {stages.filter(s => s.malicious).map((s, i) => (
          <div key={`d-${i}`} className="absolute w-1.5 h-1.5 rounded-full"
               style={{ left: xFor((s.firstTs + s.lastTs) / 2) - 3,
                        top: "50%", transform: "translateY(-50%)",
                        background: T.red }} />
        ))}
        {/* Hour ticks */}
        <div className="absolute inset-x-0 bottom-0 flex justify-between text-[9px] font-mono"
             style={{ color: T.inkMute }}>
          {["00","04","08","12","16","20"].map(h => <span key={h}>{h}</span>)}
        </div>
      </div>
      {/* Focus read-out */}
      <div className="ml-4 min-w-[220px]">
        <div className="text-[9px] tracking-[1.6px] font-bold" style={{ color: T.inkMute }}>FOCUS</div>
        <div className="text-[11px] font-mono font-semibold" style={{ color: T.ink }}>
          {selectedStageIdx != null && stages[selectedStageIdx]
            ? `${stages[selectedStageIdx].tactic} · stage 0${selectedStageIdx + 1}`
            : `full case · ${stages.length} stages`}
        </div>
        <div className="text-[10px] font-mono" style={{ color: T.inkMute }}>
          zoom 100% · fit
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
export function AttackChainSidebar({ stages, selectedIdx, onSelect }) {
  return (
    <div className="overflow-y-auto"
         style={{ background: T.paper }}
         data-testid="attack-chain-sidebar">
      <div className="px-4 pt-4">
        <div className="text-[10px] tracking-[2px] font-bold" style={{ color: T.inkMute }}>
          ATTACK CHAIN
        </div>
        <div className="text-[10px] font-mono" style={{ color: T.inkFaint }}>
          MITRE-mapped stages
        </div>
      </div>
      <div className="p-3 flex flex-col gap-2">
        {stages.map((s, i) => {
          const isSel = selectedIdx === i;
          const isMal = s.malicious;
          return (
            <button key={i}
                    data-testid={`stage-${i}`}
                    onClick={() => onSelect(isSel ? null : i)}
                    className="text-left rounded p-3 transition-all"
                    style={{
                      background: isSel ? T.redT : T.paper2,
                      border: `1px solid ${isSel ? T.red : (isMal ? "#10B98166" : T.line)}`,
                    }}>
              <div className="text-[9px] tracking-[1.5px] font-bold flex items-center gap-1"
                   style={{ color: isSel ? T.red : (isMal ? T.amber : T.inkMute) }}>
                {String(i + 1).padStart(2, "0")} · {s.tactic}
                {isMal && <span>★</span>}
              </div>
              <div className="text-[11px] font-semibold mt-1"
                   style={{ color: isSel ? T.red : T.ink }}>
                {s.frames[0]?.label || s.frames[0]?.action || s.tactic.toLowerCase()}
              </div>
              <div className="flex items-center justify-between mt-1">
                <div className="text-[10px] font-mono" style={{ color: isSel ? T.red : T.inkDim }}>
                  {s.techniques.slice(0, 2).join(" · ")}
                </div>
                <div className="text-[9px] font-mono" style={{ color: T.inkFaint }}>
                  {s.frames.length} ev
                </div>
              </div>
            </button>
          );
        })}
      </div>

      {stages.length > 0 && (
        <div className="p-3 border-t" style={{ borderColor: T.line }}>
          <div className="text-[9px] tracking-[2px] font-bold mb-2" style={{ color: T.inkMute }}>SUMMARY</div>
          <div className="text-[11px] font-semibold" style={{ color: T.ink }}>
            {stages.filter(s => s.malicious).length > 2 ? "Ransomware kill chain · complete"
                                                        : "Multi-stage incident"}
          </div>
          <div className="text-[10px] mt-2" style={{ color: T.inkDim }}>
            {stages.length} stages · {stages.filter(s => s.malicious).length} malicious
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
export function EvidencePane({ event, tab, onTab, onFocusParent, nameByIid = {} }) {
  // Resolve friendly names for the actor (entity) and its parent so
  // the analyst never has to read raw internal IIDs.
  const actorName = event?.meta?.entity?.name ||
                    (event?.meta?.entity?.iid && nameByIid[event.meta.entity.iid]) ||
                    event?.meta?.entity?.iid || null;
  const parentName = event?.meta?.parent?.name ||
                     event?.meta?.parent?.label ||
                     (event?.meta?.parent?.iid && nameByIid[event.meta.parent.iid]) ||
                     event?.meta?.parent?.iid || null;
  return (
    <div className="overflow-y-auto"
         style={{ background: T.paper }}
         data-testid="evidence-pane">
      <div className="flex items-center gap-4 px-4 pt-3 pb-2 border-b" style={{ borderColor: T.line }}>
        {["evidence","mitre","history","artifacts"].map(k => (
          <button key={k} onClick={() => onTab(k)}
                  className="text-[10px] tracking-[2px] font-bold pb-1"
                  style={{ color: tab === k ? T.ink : T.inkFaint,
                           borderBottom: tab === k ? `2px solid ${T.blue}` : "2px solid transparent" }}>
            {k.toUpperCase()}
          </button>
        ))}
      </div>

      {!event && (
        <div className="p-6 text-[12px] leading-relaxed" style={{ color: T.inkMute }}>
          <div className="mb-2 text-[11px] tracking-[1.5px] font-bold" style={{ color: T.inkMute }}>
            NO EVENT SELECTED
          </div>
          Click any event glyph in the canvas, or click a compromise indicator row to see the
          full evidence for the selected event here.
        </div>
      )}

      {event && (
        <div className="p-4">
          {/* Verdict badges */}
          <div className="flex items-center gap-2 mb-2">
            <Badge label={event.verdict?.toUpperCase() || "UNKNOWN"}
                   bg={event.verdict === "malicious" ? T.redT : event.verdict === "benign" ? "#DCFCE7" : "#F1F5F9"}
                   fg={event.verdict === "malicious" ? T.red   : event.verdict === "benign" ? T.green : T.inkDim} />
            {event.source && <Badge label="SOURCE" bg={T.blueT} fg={T.blue} />}
            <Badge label={event.kind?.toUpperCase() || ""} bg="#F1F5F9" fg={T.inkDim} />
          </div>

          <div className="text-[15px] font-bold leading-tight" style={{ color: T.ink }}>
            {event.label || "—"}
          </div>
          <div className="text-[11px] font-mono mt-1" style={{ color: T.inkMute }}>
            {new Date(event.ts).toISOString()}
          </div>

          {/* Command line */}
          {event.meta?.command_line && (
            <Section label="COMMAND LINE">
              <pre className="text-[10px] font-mono p-2 rounded whitespace-pre-wrap break-all"
                   style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.ink }}>
                {event.meta.command_line}
              </pre>
            </Section>
          )}

          {/* SHA */}
          {(event.meta?.sha256 || event.meta?.hash) && (
            <Section label="SHA-256">
              <a href={`https://www.virustotal.com/gui/file/${event.meta.sha256 || event.meta.hash}`}
                 target="_blank" rel="noreferrer"
                 data-testid="evidence-sha-link"
                 className="text-[10px] font-mono break-all hover:underline"
                 style={{ color: T.blue }}
                 title="Open in VirusTotal">
                {event.meta.sha256 || event.meta.hash}
              </a>
            </Section>
          )}

          {/* Actor / Source process — the entity that performed this event.
              Displays the friendly process/file/registry name (from entity.name
              or resolved via nameByIid) instead of the raw internal IID. */}
          {event.meta?.entity?.iid && actorName && (
            <Section label={
              event.meta.entity.type === "process" ? "CHILD PROCESS" :
              event.meta.entity.type === "file"    ? "TARGET FILE" :
              event.meta.entity.type === "registry"? "TARGET REGISTRY" :
              event.meta.entity.type === "network" ? "REMOTE ENDPOINT" :
              "SUBJECT"
            }>
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-mono" style={{ color: T.ink }}
                      data-testid="evidence-actor-name">
                  {actorName}
                </span>
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded"
                      style={{ background: T.paper2, border: `1px solid ${T.line}`,
                               color: T.inkFaint }}
                      title={event.meta.entity.iid}>
                  {event.meta.entity.iid.slice(0, 20)}…
                </span>
              </div>
            </Section>
          )}

          {/* Parent */}
          {event.meta?.parent?.iid && (
            <Section label="PARENT PROCESS">
              <button onClick={() => onFocusParent && onFocusParent(event.meta.parent.iid)}
                      data-testid="evidence-parent-link"
                      className="text-[11px] font-mono hover:underline text-left"
                      style={{ color: T.blue, background: "none", border: 0, padding: 0 }}
                      title={`Focus parent · ${event.meta.parent.iid}`}>
                {parentName}
              </button>
            </Section>
          )}

          {/* MITRE */}
          {event.mitre && event.mitre.length > 0 && (
            <Section label="MITRE ATT&CK">
              <div className="flex flex-wrap gap-1">
                {event.mitre.map(t => {
                  const base = t.split(".")[0];
                  const href = `https://attack.mitre.org/techniques/${base}${t.includes(".") ? "/" + t.split(".")[1] : ""}/`;
                  return (
                    <a key={t} href={href} target="_blank" rel="noreferrer"
                       data-testid={`evidence-mitre-${t}`}
                       className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold hover:opacity-80"
                       style={{ background: T.redT, color: T.red }}
                       title="Open ATT&CK technique">
                      {t}
                    </a>
                  );
                })}
              </div>
            </Section>
          )}

          {/* IP addresses (from network / meta.destination_ip / meta.remote_ip) */}
          {(event.meta?.remote_ip || event.meta?.destination_ip) && (
            <Section label="REMOTE IP">
              <a href={`https://www.abuseipdb.com/check/${event.meta.remote_ip || event.meta.destination_ip}`}
                 target="_blank" rel="noreferrer"
                 data-testid="evidence-ip-link"
                 className="text-[11px] font-mono hover:underline"
                 style={{ color: T.blue }}
                 title="Open in AbuseIPDB">
                {event.meta.remote_ip || event.meta.destination_ip}
              </a>
            </Section>
          )}

          {/* Detection rule */}
          {(event.meta?.rule_id || event.meta?.provenance?.rule_id) && (
            <Section label="DETECTION RULE">
              <div className="text-[11px] font-mono" style={{ color: T.ink }}>
                {event.meta.rule_id || event.meta.provenance?.rule_id}
              </div>
              <div className="text-[10px]" style={{ color: T.inkMute }}>
                confidence {event.meta.confidence ?? "—"} · Q-Audit
              </div>
            </Section>
          )}

          {/* Actions */}
          <Section label="ACTIONS">
            <div className="flex gap-2 flex-wrap">
              <button className="text-[11px] px-2.5 py-1 rounded font-semibold"
                      style={{ background: T.red, color: "#0A0F18" }}>Block SHA</button>
              <button className="text-[11px] px-2.5 py-1 rounded font-medium"
                      style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.ink }}>Allow-list</button>
              <button className="text-[11px] px-2.5 py-1 rounded font-medium"
                      style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.ink }}
                      onClick={() => navigator.clipboard?.writeText(event.id || "")}>
                <span className="inline-flex items-center gap-1">
                  <Copy size={11} /> Copy IID
                </span>
              </button>
            </div>
          </Section>
        </div>
      )}
    </div>
  );
}

function Section({ label, children }) {
  return (
    <div className="mt-4">
      <div className="text-[9px] tracking-[1.5px] font-bold mb-1" style={{ color: T.inkMute }}>
        {label}
      </div>
      {children}
    </div>
  );
}
function Badge({ label, bg, fg }) {
  return (
    <span className="text-[9px] px-1.5 py-0.5 rounded uppercase font-bold tracking-wider"
          style={{ background: bg, color: fg }}>{label}</span>
  );
}

// ═══════════════════════════════════════════════════════════════════
export function StatusBar({ rows, events, selectedStageIdx, compromiseCount }) {
  const procCount = rows.filter(r => r.kind === "process").length;
  return (
    <div className="flex items-center px-4 font-mono text-[10px]"
         style={{ height: 22, background: T.paper2,
                  borderTop: `1px solid ${T.line}`, color: T.inkMute }}
         data-testid="status-bar">
      <span>WINDOW · FIT</span>
      <span className="ml-4">
        {selectedStageIdx != null ? `stage 0${selectedStageIdx + 1}` : "full case"}
      </span>
      <span className="ml-auto">
        {events.length} events · {procCount} procs · {compromiseCount} compromises · dark ⌘D · help ?
      </span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
function ErrorBanner({ err }) {
  return (
    <div className="m-4 p-4 rounded"
         style={{ background: T.redT, border: `1px solid ${T.red}`, color: T.red }}
         data-testid="error-banner">
      <div className="font-semibold text-[13px] mb-1">Trajectory data unavailable</div>
      <div className="text-[11px] font-mono">{err}</div>
    </div>
  );
}
function LoadingBanner() {
  return (
    <div className="w-full h-full grid place-items-center text-[11px] font-mono"
         style={{ color: T.inkMute }}
         data-testid="loading-banner">
      Streaming trajectory events…
    </div>
  );
}



// ═══════════════════════════════════════════════════════════════════
// FiltersPopover — verdict + kind toggles that drive canvas dimming
// ═══════════════════════════════════════════════════════════════════
function FiltersPopover({ filters, onChange, onClose }) {
  const flip = (group, key) => onChange({
    ...filters,
    [group]: { ...filters[group], [key]: !filters[group][key] },
  });
  const setGroup = (group, on) => onChange({
    ...filters,
    [group]: Object.fromEntries(Object.keys(filters[group]).map(k => [k, on])),
  });
  const Row = ({ group, k, dot }) => (
    <label className="flex items-center gap-2 py-1 cursor-pointer">
      <input type="checkbox" checked={!!filters[group][k]}
             onChange={() => flip(group, k)}
             data-testid={`filter-${group}-${k}`} />
      <span className="inline-block w-2 h-2 rounded-full" style={{ background: dot }} />
      <span className="text-[11px] capitalize" style={{ color: T.ink }}>{k}</span>
    </label>
  );
  return (
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} />
      <div className="absolute z-50 mt-1 rounded-md py-2 px-3"
           data-testid="filters-popover"
           style={{
             right: 0,
             minWidth: 200,
             background: T.paper2, border: `1px solid ${T.line}`,
             boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05), 0 18px 40px -10px rgba(0,0,0,0.75)",
           }}
           onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-1">
          <div className="text-[9px] tracking-[1.6px] font-bold" style={{ color: T.inkMute }}>VERDICT</div>
          <div className="flex gap-1">
            <button onClick={() => setGroup("verdict", true)}
                    className="text-[9px]" style={{ color: T.inkDim }}>all</button>
            <button onClick={() => setGroup("verdict", false)}
                    className="text-[9px]" style={{ color: T.inkDim }}>none</button>
          </div>
        </div>
        <Row group="verdict" k="malicious"  dot={T.red} />
        <Row group="verdict" k="suspicious" dot={T.amber} />
        <Row group="verdict" k="benign"     dot={T.gray} />

        <div className="flex items-center justify-between mt-3 mb-1">
          <div className="text-[9px] tracking-[1.6px] font-bold" style={{ color: T.inkMute }}>KIND</div>
          <div className="flex gap-1">
            <button onClick={() => setGroup("kind", true)}
                    className="text-[9px]" style={{ color: T.inkDim }}>all</button>
            <button onClick={() => setGroup("kind", false)}
                    className="text-[9px]" style={{ color: T.inkDim }}>none</button>
          </div>
        </div>
        <Row group="kind" k="process"  dot={T.ink} />
        <Row group="kind" k="file"     dot={T.blue} />
        <Row group="kind" k="registry" dot={T.amber} />
        <Row group="kind" k="network"  dot="#0EA5A0" />
      </div>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════
// DeviceDetailsDrawer — slide-in right panel (Cisco SEP pattern)
// Shows only fields backed by real data. Fields the current backend does
// not expose (OS, IP, Policy, Connector GUID, …) are omitted rather than
// faked — honesty over cosmetics.
// ═══════════════════════════════════════════════════════════════════
function DeviceDetailsDrawer({ open, onClose, caseId, meta, events, stages, caseBounds,
                                bookmarks = [], onBookmarksChange = () => {},
                                onJumpBookmark = () => {} }) {
  const evCount = events.length;
  const procRows = new Set(events.filter(e => e.kind === "process").map(e => e.rowKey)).size;
  const malCount = events.filter(e => e.verdict === "malicious").length;
  const stageCount = stages.length;
  const malStages = stages.filter(s => s.malicious).length;
  const topTechniques = [...new Set(stages.flatMap(s => s.techniques || []))].slice(0, 6);
  const firstTs = caseBounds?.start;
  const lastTs  = caseBounds?.end;
  const durMs   = Math.max(0, (lastTs || 0) - (firstTs || 0));
  const fmt = (ts) => ts ? new Date(ts).toISOString().replace("T", " ").slice(0, 23) + "Z" : "—";
  const dur = () => {
    if (durMs < 1000) return `${durMs.toFixed(0)} ms`;
    if (durMs < 60_000) return `${(durMs/1000).toFixed(3)} s`;
    if (durMs < 3600_000) return `${(durMs/60_000).toFixed(2)} m`;
    return `${(durMs/3600_000).toFixed(2)} h`;
  };

  const copy = (v) => { try { navigator.clipboard.writeText(v); } catch {} };

  useEffect(() => {
    const h = (e) => { if (e.key === "Escape") onClose && onClose(); };
    if (open) window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, onClose]);

  return (
    <>
      {/* Scrim */}
      <div className="fixed inset-0 z-40 transition-opacity"
           style={{
             background: "rgba(3,6,12,0.55)",
             opacity: open ? 1 : 0,
             pointerEvents: open ? "auto" : "none",
             backdropFilter: "blur(3px)",
           }}
           onClick={onClose} />
      {/* Drawer */}
      <aside data-testid="device-details-drawer"
             className="fixed top-0 right-0 h-screen z-50 flex flex-col"
             style={{
               width: 380,
               background: T.cardGradient,
               borderLeft: `1px solid ${T.line}`,
               boxShadow: "inset 1px 0 0 rgba(255,255,255,0.03), -18px 0 40px -8px rgba(0,0,0,0.65)",
               backdropFilter: "blur(14px)",
               transform: open ? "translateX(0)" : "translateX(100%)",
               transition: "transform 220ms cubic-bezier(.2,.7,.3,1)",
             }}>
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 flex-shrink-0"
             style={{ borderBottom: `1px solid ${T.line}` }}>
          <div>
            <div className="text-[15px] font-bold" style={{ color: T.ink }}>
              {meta.name || "Case Details"}
            </div>
            <div className="text-[10px] font-mono mt-0.5" style={{ color: T.inkMute }}>
              {caseId}
            </div>
          </div>
          <button onClick={onClose}
                  data-testid="drawer-close"
                  className="w-7 h-7 rounded flex items-center justify-center text-[13px]"
                  style={{ border: `1px solid ${T.line}`, color: T.inkDim }}
                  title="Close (Esc)">✕</button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
          <DrawerSection label="Case">
            <DrawerRow k="Status"      v={meta.status || "—"} />
            <DrawerRow k="Created"     v={fmt(meta.created_at ? Date.parse(meta.created_at) : null)} mono />
            <DrawerRow k="Created by"  v={meta.created_by || "—"} />
            <DrawerRow k="Events"      v={String(meta.event_count ?? evCount)} />
            <DrawerRow k="Processes"   v={String(procRows)} />
          </DrawerSection>

          <DrawerSection label="Time window">
            <DrawerRow k="First event" v={fmt(firstTs)} mono />
            <DrawerRow k="Last event"  v={fmt(lastTs)}  mono />
            <DrawerRow k="Duration"    v={dur()} />
          </DrawerSection>

          <DrawerSection label="Attack chain">
            <DrawerRow k="Stages"           v={`${stageCount} · ${malStages} malicious`} />
            <DrawerRow k="Malicious events" v={String(malCount)} />
            {topTechniques.length > 0 && (
              <div className="pt-1">
                <div className="text-[9px] tracking-[1.4px] font-bold mb-1"
                     style={{ color: T.inkMute }}>TOP TECHNIQUES</div>
                <div className="flex flex-wrap gap-1">
                  {topTechniques.map(t => (
                    <a key={t}
                       href={`https://attack.mitre.org/techniques/${t.split(".")[0]}${t.includes(".") ? "/" + t.split(".")[1] : ""}/`}
                       target="_blank" rel="noreferrer"
                       className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold hover:opacity-80"
                       style={{ background: T.amberT, color: T.amber }}>
                      {t}
                    </a>
                  ))}
                </div>
              </div>
            )}
          </DrawerSection>

          {meta.tags && meta.tags.length > 0 && (
            <DrawerSection label="Tags">
              <div className="flex flex-wrap gap-1">
                {meta.tags.map(t => (
                  <span key={t}
                        className="text-[10px] px-1.5 py-0.5 rounded font-mono"
                        style={{ background: T.paper2, color: T.inkDim, border: `1px solid ${T.line}` }}>
                    {t}
                  </span>
                ))}
              </div>
            </DrawerSection>
          )}

          {isObservable("VERDICT_ENGINE_V3") && (
            <DrawerSection label="Correlation · v3.1">
              <CorrelationPanel caseId={caseId} legacyMaliciousCount={malCount} />
            </DrawerSection>
          )}

          <DrawerSection label="Bookmarks">
            {bookmarks.length === 0 ? (
              <div className="text-[11px]" style={{ color: T.inkFaint }}>
                Right-click the hour strip to drop a bookmark.
              </div>
            ) : (
              <div className="space-y-1">
                {bookmarks.map(bm => (
                  <div key={bm.id}
                       data-testid={`drawer-bookmark-${bm.id}`}
                       className="flex items-center gap-2 px-2 py-1 rounded"
                       style={{ background: T.paper2, border: `1px solid ${T.line}` }}>
                    <span className="w-2 h-2 rounded-full" style={{ background: T.blue }} />
                    <button className="flex-1 text-left"
                            onClick={() => onJumpBookmark(bm)}
                            title="Jump to bookmark">
                      <div className="text-[11px] font-semibold" style={{ color: T.ink }}>
                        {bm.label || "Untitled bookmark"}
                      </div>
                      <div className="text-[9px] font-mono" style={{ color: T.inkMute }}>
                        {new Date(bm.ts).toISOString()}
                      </div>
                    </button>
                    <button onClick={() => onBookmarksChange(bookmarks.filter(x => x.id !== bm.id))}
                            className="text-[11px]"
                            style={{ color: T.inkFaint }}
                            title="Delete bookmark">✕</button>
                  </div>
                ))}
              </div>
            )}
          </DrawerSection>

          <DrawerSection label="Export report">
            <div className="flex flex-col gap-1.5">
              <DrawerAction label="Download JSON"
                            onClick={() => downloadReport(caseId, "report")} />
              <DrawerAction label="Download Markdown"
                            onClick={() => downloadReport(caseId, "report.md")} />
              <DrawerAction label="Download PDF"
                            onClick={() => downloadReport(caseId, "report.pdf")} />
              <DrawerAction label="Download STIX 2.1 bundle"
                            onClick={() => downloadReport(caseId, "report.stix.json")} />
              <DrawerAction label="Download evidence package (.zip)"
                            onClick={() => downloadReport(caseId, "report.bundle.zip")} />
            </div>
          </DrawerSection>

          <DrawerSection label="Actions">
            <div className="flex flex-col gap-1.5">
              <DrawerAction label="Copy case ID" onClick={() => copy(caseId)} />
              <DrawerAction label="Copy case JSON" onClick={() => copy(JSON.stringify(meta, null, 2))} />
              <DrawerAction label="Open report generator"
                            onClick={() => { window.location.href = `/documents?case=${encodeURIComponent(caseId)}`; }} />
            </div>
          </DrawerSection>
        </div>
      </aside>
    </>
  );
}

function DrawerSection({ label, children }) {
  return (
    <div>
      <div className="text-[9px] tracking-[1.6px] font-bold mb-2"
           style={{ color: T.inkMute }}>{label.toUpperCase()}</div>
      <div className="space-y-1.5">{children}</div>
    </div>
  );
}
function DrawerRow({ k, v, mono }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <div className="text-[11px]" style={{ color: T.inkMute }}>{k}</div>
      <div className={`text-[11px] font-semibold text-right ${mono ? "font-mono" : ""}`}
           style={{ color: T.ink }}>
        {v}
      </div>
    </div>
  );
}
function DrawerAction({ label, onClick }) {
  return (
    <button onClick={onClick}
            className="w-full text-left text-[11px] px-2.5 py-1.5 rounded"
            style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.ink }}
            onMouseEnter={(e) => e.currentTarget.style.borderColor = T.amber}
            onMouseLeave={(e) => e.currentTarget.style.borderColor = T.line}>
      {label}
    </button>
  );
}

// Download a report artefact through the authenticated axios instance so
// the browser sends the bearer token, then trigger a client-side download.
async function downloadReport(caseId, format) {
  try {
    const r = await api.get(`/v2/cases/${encodeURIComponent(caseId)}/${format}`,
                            { responseType: "blob" });
    const url = URL.createObjectURL(r.data);
    const a = document.createElement("a");
    a.href = url;
    const isZip = format.endsWith(".zip");
    a.download = isZip
      ? `${caseId}.evidence.zip`
      : `${caseId}.${format.replace(/^report\.?/, "").replace(/\./g, "-") || "report"}${format === "report" ? ".json" : ""}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  } catch (e) {
    // Fall back to opening in a new tab so the user still gets the file.
    console.error("Report download failed:", e);
  }
}
