/**
 * XdrMitreHeatmap · Native XDR MITRE ATT&CK Heatmap.
 *
 * Route: `/xdr/intelligence/mitre`
 *
 * Data honesty guardrails (owner-locked):
 *   • Heat = REAL detection count over the observation window from
 *     authoritative NivXRay incident evidence — never a fabricated
 *     risk score.
 *   • Every technique cell with zero hits is an HONEST coverage gap
 *     (not "safe").  Detail panel says so explicitly.
 *   • Refresh button re-fetches live and updates "Last synced" so
 *     the analyst can see the page is operational.
 *   • Auto-poll every 30s to keep the console live.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { RefreshCcw, Filter, ExternalLink } from "lucide-react";
import { useNavigate } from "react-router-dom";

import XdrShell from "@/xdr/XdrShell";
import { listIncidents } from "@/lib/incidentsApi";
import {
  KILL_CHAIN, TECHNIQUES_BY_TACTIC, TECHNIQUE_INDEX,
  DISTINCT_TECHNIQUE_IDS, RULE_TO_TECHNIQUE,
} from "@/xdr/mitre/mitreTactics";

const HEAT_BINS = [
  { max: 0,   color: "rgba(148, 163, 184, 0.08)", border: "var(--border)",  label: "0" },
  { max: 5,   color: "rgba(60, 232, 184, 0.20)",  border: "var(--mint)",    label: "1-5" },
  { max: 15,  color: "rgba(60, 232, 184, 0.42)",  border: "var(--mint)",    label: "6-15" },
  { max: 40,  color: "rgba(245, 166, 35, 0.55)",  border: "var(--amber)",   label: "16-40" },
  { max: 1e9, color: "rgba(239, 91, 91, 0.75)",   border: "var(--red)",     label: "41+" },
];
function heatFor(n) {
  for (const b of HEAT_BINS) if (n <= b.max) return b;
  return HEAT_BINS[HEAT_BINS.length - 1];
}

const AUTO_REFRESH_MS = 30_000;

function fmtRelative(iso) {
  if (!iso) return "never";
  const d = (Date.now() - new Date(iso).getTime()) / 1000;
  if (d < 5)   return "just now";
  if (d < 60)  return `${Math.floor(d)}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  return `${Math.floor(d / 3600)}h ago`;
}

export default function XdrMitreHeatmap() {
  const navigate = useNavigate();
  const [incidents, setIncidents] = useState(null);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefresh]  = useState(false);
  const [error, setError]         = useState(null);
  const [q, setQ]                 = useState("");
  const [selected, setSelected]   = useState(null);
  const [lastSyncedAt, setSynced] = useState(null);
  const [refreshCount, setRefreshCount] = useState(0);
  const [, forceTick]             = useState(0);          // for "Xs ago"
  const inflight = useRef(false);

  const load = useCallback(async (mode = "initial") => {
    if (inflight.current) return;
    inflight.current = true;
    if (mode === "initial") setLoading(true);
    if (mode === "refresh" || mode === "manual") setRefresh(true);
    // On a manual refresh, explicitly reset transient view state so
    // the analyst sees the page 'clear and re-fetch' — no lingering
    // filter or selection carrying over.
    if (mode === "manual") {
      setQ("");
      setSelected(null);
      setIncidents(null);
    }
    setError(null);
    try {
      const data = await listIncidents({ limit: 500 });
      setIncidents(data?.incidents || data || []);
      setSynced(new Date().toISOString());
      if (mode === "manual" || mode === "refresh") {
        setRefreshCount((n) => n + 1);
      }
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load incidents.");
    } finally {
      setLoading(false);
      setRefresh(false);
      inflight.current = false;
    }
  }, []);

  useEffect(() => { load("initial"); }, [load]);

  // Auto-refresh
  useEffect(() => {
    const t = setInterval(() => load("refresh"), AUTO_REFRESH_MS);
    return () => clearInterval(t);
  }, [load]);

  // Tick every 5s so "Last synced Xs ago" is live.
  useEffect(() => {
    const t = setInterval(() => forceTick((n) => n + 1), 5000);
    return () => clearInterval(t);
  }, []);

  // Roll up detections per technique + per tactic from evidence.
  const { counts, tacticTotals, incidentsScanned } = useMemo(() => {
    const c = {};
    const tt = {};
    const list = incidents || [];
    for (const inc of list) {
      const ev = inc?.verdict_stage2?.evidence || inc?.evidence || [];
      for (const e of ev) {
        const rid = (e.rule_id || "").toUpperCase();
        // Direct rule map first; otherwise use e.technique_id if the
        // authoritative evidence already carries it.
        const tid = RULE_TO_TECHNIQUE[rid] || e.technique_id;
        if (!tid || !TECHNIQUE_INDEX[tid]) continue;
        c[tid] = (c[tid] || 0) + 1;
        const tactic = TECHNIQUE_INDEX[tid].tactic;
        tt[tactic] = (tt[tactic] || 0) + 1;
      }
    }
    return { counts: c, tacticTotals: tt, incidentsScanned: list.length };
  }, [incidents]);

  const kpis = useMemo(() => {
    const totalTechniques = DISTINCT_TECHNIQUE_IDS.length;
    const mappedTechIds   = new Set(Object.values(RULE_TO_TECHNIQUE));
    const withMappedRule  = [...mappedTechIds].filter((t) => TECHNIQUE_INDEX[t]).length;
    const observed        = Object.keys(counts).length;
    const totalDetections = Object.values(counts).reduce((a, b) => a + b, 0);
    return { totalTechniques, withMappedRule, observed, totalDetections };
  }, [counts]);

  const filter = q.trim().toLowerCase();

  return (
    <XdrShell>
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                      marginBottom: 8 }}>
        <h1 className="page-h1" style={{ margin: 0 }}
             data-testid="xdr-mitre-heading">MITRE ATT&amp;CK Heatmap</h1>
        <div style={{ flex: 1 }} />
        <div style={{ display: "flex", alignItems: "center", gap: 6,
                        border: "1px solid var(--border)", borderRadius: 4,
                        padding: "3px 8px", background: "var(--panel2)" }}>
          <Filter size={11} style={{ color: "var(--muted)" }} />
          <input
            placeholder="Filter T-ID or name…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            data-testid="xdr-mitre-filter"
            style={{ background: "transparent", border: 0, outline: "none",
                        color: "var(--text)", fontSize: 11.5, width: 220 }}
          />
        </div>
        <button className="btn" style={{ padding: "4px 10px" }}
                  onClick={() => load("manual")}
                  disabled={refreshing || loading}
                  data-testid="xdr-mitre-refresh">
          <RefreshCcw size={11}
                        style={{ animation: refreshing ? "xdr-spin 900ms linear infinite" : "none" }} />
          {refreshing ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      <div className="page-sub" data-testid="xdr-mitre-sub"
             style={{ display: "flex", flexWrap: "wrap", gap: 12,
                        alignItems: "center" }}>
        <span>Environment-wide detection coverage — heat reflects
              <b> real detections</b>, <b>not a fabricated risk score</b>.</span>
      </div>

      {/* Catalog constants — static, deliberately not in KPIs so
             they can't be misread as live metrics. */}
      <div data-testid="xdr-mitre-meta"
             style={{ display: "flex", flexWrap: "wrap", gap: 14,
                        alignItems: "center", marginTop: 8,
                        padding: "8px 12px", borderRadius: 4,
                        background: "var(--panel2)",
                        border: "1px solid var(--border)",
                        fontFamily: "var(--mono)", fontSize: 11,
                        color: "var(--text-dim)" }}>
        <span><b style={{ color: "var(--faint)", fontWeight: 800,
                                 textTransform: "uppercase", letterSpacing: ".3px",
                                 fontSize: 10 }}>Catalog</b>
              &nbsp; MITRE ATT&amp;CK Enterprise v16 · 14 tactics ·{" "}
              <b style={{ color: "var(--text)" }}>{kpis.totalTechniques}</b> techniques ·{" "}
              <b style={{ color: "var(--text)" }}>{kpis.withMappedRule}</b> with mapped rule
        </span>
        <span style={{ color: "var(--faint)" }}>·</span>
        <span data-testid="xdr-mitre-last-sync">
          <b style={{ color: "var(--faint)", fontWeight: 800,
                          textTransform: "uppercase", letterSpacing: ".3px",
                          fontSize: 10 }}>Last synced</b>
          &nbsp; <b style={{ color: "var(--mint)" }}>{fmtRelative(lastSyncedAt)}</b>
        </span>
        <span style={{ color: "var(--faint)" }}>·</span>
        <span data-testid="xdr-mitre-window">
          <b style={{ color: "var(--faint)", fontWeight: 800,
                          textTransform: "uppercase", letterSpacing: ".3px",
                          fontSize: 10 }}>Auto-refresh</b>
          &nbsp; every 30s
        </span>
        <span style={{ color: "var(--faint)" }}>·</span>
        <span data-testid="xdr-mitre-scanned">
          <b style={{ color: "var(--faint)", fontWeight: 800,
                          textTransform: "uppercase", letterSpacing: ".3px",
                          fontSize: 10 }}>Incidents scanned</b>
          &nbsp; <b style={{ color: "var(--text)" }}>{incidentsScanned}</b>
        </span>
        <span style={{ color: "var(--faint)" }}>·</span>
        <span data-testid="xdr-mitre-refresh-counter">
          <b style={{ color: "var(--faint)", fontWeight: 800,
                          textTransform: "uppercase", letterSpacing: ".3px",
                          fontSize: 10 }}>Refreshes</b>
          &nbsp; <b style={{ color: "var(--text)" }}>{refreshCount}</b>
        </span>
      </div>

      {/* KPIs — live-only, computed from authoritative evidence. */}
      <div style={{ display: "grid", gap: 10, marginTop: 12,
                       gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))" }}
             data-testid="xdr-mitre-kpis">
        <Kpi label="Detections (window)"    value={kpis.totalDetections} color="var(--red)" />
        <Kpi label="Techniques Observed"    value={kpis.observed}         color="var(--amber)" />
        <Kpi label="Rule Coverage"
              value={`${kpis.withMappedRule}/${kpis.totalTechniques}`}
              color="var(--cyan)" />
        <Kpi label="Incidents Scanned"      value={incidentsScanned}      color="var(--mint)" />
      </div>

      {loading && <div className="x-empty" style={{ marginTop: 14 }}
                          data-testid="xdr-mitre-loading">Loading …</div>}
      {!loading && error && <div className="x-empty"
                                    style={{ marginTop: 14, color: "var(--red)" }}
                                    data-testid="xdr-mitre-error">{String(error)}</div>}

      {!loading && !error && (
        <>
          {/* Kill-chain grid */}
          <section className="panel" style={{ padding: 12, marginTop: 12,
                                                    overflow: "auto" }}
                     data-testid="xdr-mitre-grid">
            <div style={{ display: "grid", gap: 8,
                             gridTemplateColumns: `repeat(${KILL_CHAIN.length}, minmax(148px, 1fr))`,
                             minWidth: KILL_CHAIN.length * 152 }}>
              {KILL_CHAIN.map((tactic) => {
                const techs = TECHNIQUES_BY_TACTIC[tactic.key] || [];
                const shown = techs.filter((t) => !filter ||
                    t.id.toLowerCase().includes(filter) ||
                    t.name.toLowerCase().includes(filter));
                const tacticN = tacticTotals[tactic.key] || 0;
                return (
                  <div key={tactic.key}>
                    <div style={{
                      display: "flex", justifyContent: "space-between",
                      alignItems: "flex-end", gap: 6,
                      marginBottom: 6, paddingBottom: 4,
                      borderBottom: "1px solid var(--border)",
                    }}>
                      <div>
                        <div style={{
                          fontFamily: "var(--mono)", fontSize: 10,
                          letterSpacing: ".3px", fontWeight: 800,
                          color: "var(--muted)", textTransform: "uppercase",
                        }}>{tactic.label}</div>
                        <div style={{ fontSize: 9, fontWeight: 600,
                                         color: "var(--faint)", marginTop: 2 }}>
                          {techs.length} techniques
                        </div>
                      </div>
                      <div style={{
                        fontFamily: "var(--mono)", fontSize: 11, fontWeight: 800,
                        color: tacticN > 0 ? "var(--mint)" : "var(--faint)",
                      }} title="Detections in this tactic (window)">
                        {tacticN}
                      </div>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      {shown.map((t) => {
                        const n   = counts[t.id] || 0;
                        const bin = heatFor(n);
                        const isSel = selected?.id === t.id && selected?.tacticLabel === tactic.label;
                        return (
                          <button key={`${tactic.key}-${t.id}`} type="button"
                            data-testid={`xdr-mitre-cell-${tactic.key}-${t.id}`}
                            onClick={() => setSelected({ ...t, tactic: tactic.key,
                                                              tacticLabel: tactic.label, count: n })}
                            style={{
                              textAlign: "left", padding: "6px 8px",
                              borderRadius: 4, background: bin.color,
                              border: `1px solid ${isSel ? "var(--mint)" : bin.border}`,
                              cursor: "pointer", color: "inherit",
                            }}>
                            <div className="mono" style={{ fontSize: 10.5,
                                                                  color: "var(--text)",
                                                                  fontWeight: 700 }}>{t.id}</div>
                            <div style={{ fontSize: 10, color: "var(--text-dim)",
                                             marginTop: 2, lineHeight: 1.3 }}>{t.name}</div>
                            <div style={{ display: "flex", justifyContent: "flex-end",
                                             marginTop: 4, fontFamily: "var(--mono)",
                                             fontSize: 12, fontWeight: 800,
                                             color: n > 0 ? "var(--text)" : "var(--faint)" }}>
                              {n}
                            </div>
                          </button>
                        );
                      })}
                      {shown.length === 0 && (
                        <div style={{ fontSize: 10, color: "var(--faint)",
                                         padding: "6px 4px", fontStyle: "italic" }}>
                          no match
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
            {/* Legend */}
            <div style={{ display: "flex", alignItems: "center", gap: 12,
                             marginTop: 12, paddingTop: 10,
                             borderTop: "1px solid var(--border)",
                             fontSize: 10.5, color: "var(--muted)",
                             flexWrap: "wrap" }}
                    data-testid="xdr-mitre-legend">
              <span style={{ fontFamily: "var(--mono)", letterSpacing: ".3px",
                                fontWeight: 800, textTransform: "uppercase",
                                color: "var(--faint)" }}>Detections (window)</span>
              {HEAT_BINS.map((b) => (
                <span key={b.label} style={{ display: "inline-flex",
                                                    alignItems: "center", gap: 5 }}>
                  <span style={{ display: "inline-block", width: 12, height: 12,
                                    borderRadius: 2, background: b.color,
                                    border: `1px solid ${b.border}` }} />
                  <span className="mono">{b.label}</span>
                </span>
              ))}
            </div>
          </section>

          {/* Technique detail */}
          <section className="panel" style={{ padding: 14, marginTop: 12 }}
                     data-testid="xdr-mitre-detail">
            <div style={{ fontFamily: "var(--mono)", fontSize: 10,
                             letterSpacing: ".3px", fontWeight: 800,
                             color: "var(--muted)", textTransform: "uppercase",
                             marginBottom: 10 }}>Technique Detail</div>
            {!selected && (
              <div style={{ color: "var(--text-dim)", fontSize: 12 }}>
                Click a cell above to see technique detail + honest coverage gap.
              </div>
            )}
            {selected && (
              <div>
                <Row k="Technique" v={
                  <span className="mono" style={{ color: "var(--text)",
                                                        fontWeight: 800 }}>
                    {selected.id} — {selected.name}
                  </span>} />
                <Row k="Tactic" v={selected.tacticLabel} />
                <Row k="Detections (window)" v={
                  <span className="mono" style={{ color: selected.count > 0
                    ? "var(--mint)" : "var(--faint)", fontWeight: 800 }}>
                    {selected.count}
                  </span>} />
                <Row k="Mapped Detection Rule" v={
                  Object.entries(RULE_TO_TECHNIQUE)
                    .filter(([, tid]) => tid === selected.id)
                    .map(([r]) => r).join(", ")
                    || <span style={{ color: "var(--amber)", fontWeight: 700 }}>
                         None — coverage gap
                       </span>} />
                <Row k="MITRE Reference" v={
                  <a href={`https://attack.mitre.org/techniques/${selected.id.replace(".", "/")}/`}
                     target="_blank" rel="noreferrer"
                     style={{ color: "var(--cyan)" }}
                     data-testid="xdr-mitre-attack-link">
                    attack.mitre.org/techniques/{selected.id}
                  </a>} />
                {/* Pivot to filtered Incidents queue — real navigation,
                       driven by authoritative Stage-2 evidence. */}
                <div style={{ marginTop: 12, display: "flex", gap: 8,
                                 flexWrap: "wrap" }}>
                  <button className="btn primary"
                             style={{ padding: "5px 12px" }}
                             onClick={() => navigate(`/xdr/incidents?technique=${selected.id}`)}
                             data-testid="xdr-mitre-pivot-incidents">
                    <ExternalLink size={11} /> Open incidents mapped to {selected.id}
                  </button>
                </div>
                {selected.count === 0 && (
                  <div style={{
                    marginTop: 10, padding: 10,
                    background: "var(--panel2)",
                    border: "1px dashed var(--amber)", borderRadius: 4,
                    color: "var(--text-dim)", fontSize: 11.5, lineHeight: 1.6,
                  }} data-testid="xdr-mitre-coverage-gap">
                    <b style={{ color: "var(--amber)" }}>Honest coverage gap.</b>{" "}
                    No detections observed for this technique in the current
                    window.  This is <b>not</b> a "safe" result — consider
                    whether this technique is relevant to your environment
                    and write / enable a rule if it is.  Fabricating a green
                    tick here would mislead the analyst.
                  </div>
                )}
              </div>
            )}
          </section>
        </>
      )}

      <style>{`@keyframes xdr-spin { to { transform: rotate(360deg); } }`}</style>
    </XdrShell>
  );
}

function Kpi({ label, value, color }) {
  return (
    <div className="panel" style={{ padding: "12px 14px",
                                             borderLeft: `3px solid ${color}` }}>
      <div style={{ fontFamily: "var(--mono)", fontSize: 9.5,
                       letterSpacing: ".3px", fontWeight: 800,
                       color: "var(--faint)", textTransform: "uppercase",
                       marginBottom: 4 }}>{label}</div>
      <div style={{ fontFamily: "var(--mono)", fontSize: 26, color,
                       fontWeight: 800 }}>{value}</div>
    </div>
  );
}
function Row({ k, v }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "200px 1fr",
                    gap: 10, padding: "6px 0",
                    borderBottom: "1px solid var(--border)" }}>
      <div style={{ color: "var(--faint)", fontSize: 10,
                       fontWeight: 800, textTransform: "uppercase",
                       letterSpacing: ".3px" }}>{k}</div>
      <div style={{ color: "var(--text-dim)", fontSize: 12 }}>{v}</div>
    </div>
  );
}
