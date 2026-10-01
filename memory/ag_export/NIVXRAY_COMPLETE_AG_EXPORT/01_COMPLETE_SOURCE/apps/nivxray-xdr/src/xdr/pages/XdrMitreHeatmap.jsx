/**
 * XdrMitreHeatmap · ATT&CK Enterprise coverage matrix (v16.1).
 *
 * The full published ATT&CK Enterprise catalogue is served by
 * the backend at `/api/mitre/catalogue/coverage` — 203 top-level
 * techniques and 453 sub-techniques for v16.1.  The frontend
 * strictly projects that response; it does not fabricate any
 * technique, count or coverage state.
 *
 * Honesty rules (owner):
 *   · Catalogue presence ≠ detection coverage.  A technique or
 *     sub-technique with no observation in `workspace_cases`
 *     renders as an honest NO EVIDENCE / coverage gap.  Every
 *     highlighted cell cites the real incident ids that
 *     observed it.
 *   · Parent aggregate counts label themselves as aggregate and
 *     never imply that every child is covered.
 *   · Sub-technique coverage is independent from its parent —
 *     a parent that is OBSERVED does not promote its children.
 */
import React, {
  useCallback, useEffect, useMemo, useRef, useState,
} from "react";
import { RefreshCcw, Search, ExternalLink, ChevronRight, Target,
                ChevronDown, GitBranch } from "lucide-react";
import { useNavigate } from "react-router-dom";

import XdrShell from "@/xdr/XdrShell";
import { NxKpi, NxEmptyBlock as NxEmpty, NxPill } from "@/xdr/nx";
import { listIncidents } from "@/lib/incidentsApi";
import api from "@/lib/api";
import { attackHrefFor, attackLinkTitle }
  from "@/xdr/mitre/attackLink";

const AUTO_REFRESH_MS = 60_000;


function fmtRelative(iso) {
  if (!iso) return "never";
  const d = (Date.now() - new Date(iso).getTime()) / 1000;
  if (d < 5)   return "just now";
  if (d < 60)  return `${Math.floor(d)}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  return `${Math.floor(d / 3600)} h ago`;
}


export default function XdrMitreHeatmap() {
  const navigate = useNavigate();
  const [coverage, setCoverage]   = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefresh]  = useState(false);
  const [error, setError]         = useState(null);
  const [q, setQ]                 = useState("");
  const [selected, setSelected]   = useState(null);
  const [openTactic, setOpenTactic] = useState(null);
  const [openParent, setOpenParent] = useState(null);
  const [lastSyncedAt, setSynced] = useState(null);
  const [, forceTick]             = useState(0);
  const inflight = useRef(false);

  const load = useCallback(async (mode = "initial") => {
    if (inflight.current) return;
    inflight.current = true;
    if (mode === "initial") setLoading(true);
    if (mode === "refresh" || mode === "manual") setRefresh(true);
    setError(null);
    try {
      // Coverage is the source of truth for hierarchy + counts.
      // Incidents list only fuels the right-hand incident cards.
      const [cov, incs] = await Promise.all([
        api.get("/mitre/catalogue/coverage").then(r => r.data),
        listIncidents({ limit: 500 }).catch(() => ({ incidents: [] })),
      ]);
      setCoverage(cov);
      setIncidents(incs?.incidents || incs || []);
      setSynced(new Date().toISOString());
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load coverage.");
    } finally {
      setLoading(false); setRefresh(false); inflight.current = false;
    }
  }, []);

  useEffect(() => { load("initial"); }, [load]);
  useEffect(() => {
    const t = setInterval(() => load("refresh"), AUTO_REFRESH_MS);
    return () => clearInterval(t);
  }, [load]);
  useEffect(() => {
    const t = setInterval(() => forceTick((n) => n + 1), 5000);
    return () => clearInterval(t);
  }, []);

  const totals = coverage?.totals || {};
  const kpis = useMemo(() => {
    const totalTechniques = totals.techniques || 0;
    const totalSubs       = totals.sub_techniques || 0;
    const observed        = totals.techniques_observed || 0;
    const observedSubs    = totals.sub_techniques_observed || 0;
    const catalogueRows   = totalTechniques + totalSubs;
    const observedRows    = observed + observedSubs;
    const coveragePct     = catalogueRows
                              ? Math.round((observedRows / catalogueRows) * 1000) / 10
                              : 0;
    return {
      totalTechniques, totalSubs, observed, observedSubs,
      catalogueRows, observedRows, coveragePct,
      aggregateDetections: totals.aggregate_detections || 0,
      incidentsScanned:    incidents.length,
    };
  }, [totals, incidents.length]);

  const filter = q.trim().toLowerCase();

  // Filter helper — matches T#### or sub-technique id or name.
  const matches = useCallback((row) => {
    if (!filter) return true;
    return String(row.external_id).toLowerCase().includes(filter)
        || String(row.name).toLowerCase().includes(filter);
  }, [filter]);

  return (
    <XdrShell>
      <div className="mitre-page" data-testid="xdr-mitre-page">
        <header className="mitre-hero" data-testid="xdr-mitre-hero">
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="nx-page-hero-eyebrow">
              Intelligence · ATT&amp;CK Coverage
              {coverage?.catalogue_version && (
                <span style={{ marginLeft: 8, color: "var(--nx-muted)" }}>
                  · Enterprise v{coverage.catalogue_version}
                </span>
              )}
            </div>
            <h1 className="nx-page-hero-title" data-testid="xdr-mitre-heading">
              MITRE ATT&amp;CK Coverage Intelligence
            </h1>
            <div className="nx-page-hero-desc">
              Every technique and sub-technique published in ATT&amp;CK
              Enterprise v{coverage?.catalogue_version || "16.1"} — parents
              expandable to their sub-techniques.  Highlighted cells cite
              the real incident ids that observed them; unobserved rows
              are honest coverage gaps, not fabricated risk scores.
              Aggregate parent counts are labelled as aggregates and never
              imply a child is covered.
            </div>
          </div>
          <div className="mitre-hero-actions">
            <div className="mitre-search">
              <Search size={13} />
              <input
                placeholder="Search T-id / sub-technique / name…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                data-testid="xdr-mitre-filter"
              />
            </div>
            <button className="btn" onClick={() => load("manual")}
                       disabled={refreshing || loading}
                       data-testid="xdr-mitre-refresh">
              <RefreshCcw size={12}
                style={{ animation: refreshing ? "xdr-spin 900ms linear infinite" : "none" }} />
              {refreshing ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        </header>

        <div className="nx-attn nx-attn-5" data-testid="xdr-mitre-kpis">
          <NxKpi
            icon={Target}
            tone="critical"
            label="Coverage"
            value={`${kpis.coveragePct}%`}
            sub={`${kpis.observedRows}/${kpis.catalogueRows} catalogue rows observed`}
          />
          <NxKpi
            label="Techniques Observed"
            value={`${kpis.observed}/${kpis.totalTechniques}`}
            tone="high"
            sub="Parent techniques with real evidence"
          />
          <NxKpi
            label="Sub-Techniques Observed"
            value={`${kpis.observedSubs}/${kpis.totalSubs}`}
            tone="info"
            sub="Independent from parent coverage"
          />
          <NxKpi
            label="Incidents Scanned"
            value={kpis.incidentsScanned}
            tone="benign"
            sub={`Last synced ${fmtRelative(lastSyncedAt)}`}
          />
          <NxKpi
            label="Coverage Gaps"
            value={(kpis.catalogueRows - kpis.observedRows) || 0}
            tone="medium"
            sub="Rows with no evidence yet"
          />
        </div>

        {loading && <NxEmpty title="Loading matrix…" body="Fetching v16.1 catalogue and aggregating evidence." />}
        {!loading && error && <NxEmpty title="Failed to load" body={String(error)} />}

        {!loading && !error && coverage && (
          <div className="mitre-workspace">
            <section className="mitre-tactic-list" data-testid="xdr-mitre-tactics">
              <div className="mitre-tactic-list-head">
                <span className="mitre-list-title">Tactic Coverage</span>
                <span className="mitre-list-sub">
                  {coverage.tactics.length} tactics · {kpis.totalTechniques} techniques
                  · {kpis.totalSubs} sub-techniques
                </span>
              </div>
              <div className="mitre-tactic-list-body">
                {coverage.tactics.map((tactic) => {
                  const isOpen = openTactic === tactic.shortname;
                  const parents = tactic.techniques
                    .filter((p) =>
                      matches(p) || p.subs.some(matches));
                  const total    = tactic.parent_total;
                  const observed = tactic.parent_observed;
                  const subTotal = tactic.sub_total;
                  const subObs   = tactic.sub_observed;
                  const pct  = total ? Math.round((observed / total) * 100) : 0;
                  const dets = tactic.aggregate_detections;

                  return (
                    <div key={tactic.shortname} className="mitre-tactic-row"
                            data-testid={`xdr-mitre-tactic-${tactic.shortname}`}>
                      <button
                        type="button"
                        className={`mitre-tactic-head ${isOpen ? "open" : ""}`}
                        onClick={() => setOpenTactic(isOpen ? null : tactic.shortname)}
                        data-testid={`xdr-mitre-tactic-toggle-${tactic.shortname}`}
                      >
                        <ChevronRight
                          size={12}
                          className="mitre-caret"
                          style={{ transform: isOpen ? "rotate(90deg)" : "none" }}
                        />
                        <div className="mitre-tactic-title">
                          <div className="mitre-tactic-label">{tactic.name}</div>
                          <div className="mitre-tactic-meta">
                            <span className="mono">{observed}/{total}</span> tech ·{" "}
                            <span className="mono">{subObs}/{subTotal}</span> sub ·{" "}
                            <span className="mono">{dets}</span> aggregate detections
                          </div>
                        </div>
                        <div className="mitre-tactic-bar">
                          <div
                            className="mitre-tactic-bar-fill"
                            style={{
                              width: `${pct}%`,
                              background: pct >= 60 ? "var(--nx-benign)"
                                        : pct >= 25 ? "var(--nx-medium)"
                                        : pct > 0   ? "var(--nx-high)"
                                        : "transparent",
                            }}
                          />
                        </div>
                        <span className="mitre-tactic-pct mono">{pct}%</span>
                      </button>
                      {isOpen && (
                        <ul className="mitre-tactic-techs">
                          {parents.length === 0 && (
                            <li className="mitre-tech-empty">No matching techniques.</li>
                          )}
                          {parents.map((p) => (
                            <ParentRow
                              key={p.external_id}
                              parent={p}
                              tactic={tactic}
                              filter={filter}
                              isOpen={openParent === p.external_id}
                              onToggle={() => setOpenParent(
                                openParent === p.external_id
                                  ? null
                                  : p.external_id)}
                              onSelect={(row) => setSelected(row)}
                              selectedId={selected?.external_id}
                            />
                          ))}
                        </ul>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>

            <section className="mitre-detail" data-testid="xdr-mitre-detail">
              {!selected ? (
                <div className="mitre-detail-empty">
                  <Target size={22} />
                  <h4>Select a technique or sub-technique</h4>
                  <p>Expand a tactic on the left, expand a parent to see its sub-techniques,
                  and pick any row to see detections, incidents and coverage state.</p>
                </div>
              ) : (
                <TechniqueDetail
                  row={selected}
                  navigate={navigate}
                  incidentDocs={incidents}
                />
              )}
            </section>
          </div>
        )}
      </div>

      <style>{`
        .mitre-page { padding: 0; }
        .mitre-hero {
          display: flex; gap: 20px; align-items: flex-start;
          padding: 22px 4px 18px;
          border-bottom: 1px solid var(--nx-bd-quiet);
          margin-bottom: 20px;
        }
        .mitre-hero-actions { display: flex; gap: 8px; align-items: center; flex: 0 0 auto; }
        .mitre-search {
          display: inline-flex; align-items: center; gap: 6px;
          padding: 6px 10px;
          background: var(--nx-surf-primary);
          border: 1px solid var(--nx-bd-quiet);
          border-radius: 6px;
          color: var(--nx-muted);
          box-shadow: var(--nx-shadow-1);
        }
        .mitre-search input {
          background: transparent; border: 0; outline: none;
          font-family: var(--sans); font-size: 12px;
          color: var(--nx-text); width: 280px;
        }
        .mitre-search input::placeholder { color: var(--nx-muted); }

        .mitre-workspace {
          display: grid;
          grid-template-columns: minmax(0, 1.15fr) minmax(0, 1fr);
          gap: 16px;
          min-height: 620px;
          margin-top: 4px;
        }
        @media (max-width: 1200px) {
          .mitre-workspace { grid-template-columns: 1fr; }
        }

        .mitre-tactic-list, .mitre-detail {
          background: var(--nx-surf-primary);
          border: 1px solid var(--nx-bd-quiet);
          border-radius: 12px;
          box-shadow: var(--nx-shadow-1);
          overflow: hidden;
          display: flex; flex-direction: column;
        }
        .mitre-tactic-list-head {
          padding: 14px 16px;
          border-bottom: 1px solid var(--nx-bd-quiet);
          background: var(--nx-surf-inset);
        }
        .mitre-list-title {
          font-family: var(--sans); font-size: 13px; font-weight: 700;
          color: var(--nx-text);
        }
        .mitre-list-sub {
          display: block; margin-top: 2px;
          font-family: var(--sans); font-size: 11px;
          color: var(--nx-muted);
        }
        .mitre-tactic-list-body {
          overflow-y: auto;
          max-height: 720px;
          padding: 0;
        }

        .mitre-tactic-row { border-bottom: 1px solid var(--nx-bd-quiet); }
        .mitre-tactic-row:last-child { border-bottom: none; }

        .mitre-tactic-head {
          display: grid;
          grid-template-columns: 16px 1fr 120px 44px;
          gap: 12px;
          align-items: center;
          width: 100%;
          padding: 10px 16px;
          background: var(--nx-surf-primary);
          border: 0;
          text-align: left;
          cursor: pointer;
          transition: background 100ms ease;
        }
        .mitre-tactic-head:hover { background: var(--nx-surf-inset); }
        .mitre-tactic-head.open { background: var(--nx-surf-inset); }
        .mitre-caret {
          color: var(--nx-muted);
          transition: transform 120ms ease;
        }
        .mitre-tactic-label {
          font-family: var(--sans); font-size: 12.5px; font-weight: 700;
          color: var(--nx-text);
        }
        .mitre-tactic-meta {
          font-family: var(--sans); font-size: 11px;
          color: var(--nx-muted);
          margin-top: 2px;
        }
        .mitre-tactic-bar {
          position: relative;
          height: 6px;
          background: var(--nx-surf-inset);
          border-radius: 999px;
          overflow: hidden;
        }
        .mitre-tactic-bar-fill {
          height: 100%;
          transition: width 200ms ease;
        }
        .mitre-tactic-pct {
          font-family: var(--mono); font-size: 11px; font-weight: 700;
          color: var(--nx-text-dim);
          text-align: right;
        }

        .mitre-tactic-techs {
          list-style: none; margin: 0; padding: 8px 12px 12px 40px;
          background: var(--nx-surf-inset);
          display: flex; flex-direction: column;
          gap: 4px;
        }

        .mitre-parent { display: flex; flex-direction: column; gap: 4px; }
        .mitre-parent-head {
          display: grid;
          grid-template-columns: 14px 78px 1fr auto auto;
          gap: 10px;
          align-items: baseline;
          width: 100%;
          padding: 6px 10px;
          background: var(--nx-surf-primary);
          border: 1px solid var(--nx-bd-quiet);
          border-radius: 5px;
          text-align: left;
          cursor: pointer;
          transition: border-color 100ms ease, background 100ms ease;
        }
        .mitre-parent-head:hover { border-color: var(--nx-bd-strong); }
        .mitre-parent-head.selected {
          border-color: var(--nx-purple);
          background: var(--nx-purple-dim);
        }
        .mitre-parent-head.observed { border-left: 3px solid var(--nx-benign); }
        .mitre-parent-head.gap { border-left: 3px solid var(--nx-bd-quiet); }

        .mitre-tech-id {
          font-family: var(--mono); font-size: 11px; font-weight: 700;
          color: var(--nx-purple);
        }
        .mitre-tech-name {
          font-family: var(--sans); font-size: 11.5px;
          color: var(--nx-text);
          overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        }
        .mitre-tech-badge {
          font-family: var(--mono); font-size: 10px; font-weight: 700;
          padding: 1px 6px; border-radius: 2px;
          background: var(--nx-surf-inset);
          color: var(--nx-muted);
          border: 1px solid var(--nx-bd-quiet);
          white-space: nowrap;
        }
        .mitre-tech-badge.hot {
          color: var(--nx-benign); border-color: var(--nx-benign);
        }

        .mitre-sub-list {
          list-style: none; margin: 0 0 0 16px;
          padding: 4px 0 4px 12px;
          border-left: 1px dashed var(--nx-bd-quiet);
          display: flex; flex-direction: column;
          gap: 3px;
        }
        .mitre-sub-head {
          display: grid;
          grid-template-columns: 96px 1fr auto;
          gap: 10px;
          align-items: baseline;
          width: 100%;
          padding: 4px 8px;
          background: transparent;
          border: 1px solid transparent;
          border-radius: 4px;
          text-align: left;
          cursor: pointer;
        }
        .mitre-sub-head:hover { background: var(--nx-surf-primary); border-color: var(--nx-bd-quiet); }
        .mitre-sub-head.selected {
          border-color: var(--nx-purple); background: var(--nx-purple-dim);
        }
        .mitre-sub-head.observed .mitre-tech-id { color: var(--nx-benign); }

        .mitre-tech-empty {
          padding: 8px 10px;
          font-family: var(--sans); font-size: 11.5px;
          color: var(--nx-muted); font-style: italic;
        }

        .mitre-detail {
          padding: 22px 22px 18px;
        }
        .mitre-detail-empty {
          margin: auto;
          text-align: center;
          padding: 40px 20px;
          color: var(--nx-muted);
          max-width: 340px;
        }
        .mitre-detail-empty h4 {
          margin: 12px 0 6px;
          font-family: var(--sans); font-size: 14px; font-weight: 700;
          color: var(--nx-text);
        }
        .mitre-detail-empty p {
          font-family: var(--sans); font-size: 12.5px;
          color: var(--nx-text-dim); line-height: 1.55; margin: 0;
        }
      `}</style>
    </XdrShell>
  );
}


function ParentRow({ parent, tactic, filter, isOpen, onToggle,
                                onSelect, selectedId }) {
  const observed = parent.observed_count > 0;
  const aggObs   = parent.aggregate_count > 0;
  const subCount = parent.sub_total;
  const isSel    = selectedId === parent.external_id;
  const decorate = { ...parent, tactic_shortname: tactic.shortname,
                                  tactic_name: tactic.name, is_sub: false };
  return (
    <li className="mitre-parent"
          data-testid={`xdr-mitre-parent-row-${parent.external_id}`}>
      <div style={{ display: "flex", alignItems: "stretch", gap: 0 }}>
        <button
          type="button"
          className={`mitre-parent-head ${isSel ? "selected" : ""} ${aggObs ? "observed" : "gap"}`}
          onClick={() => onSelect(decorate)}
          data-testid={`xdr-mitre-tech-${parent.external_id}`}
          style={{ flex: 1 }}
        >
          <span style={{ width: 14 }} />
          <span className="mitre-tech-id">{parent.external_id}</span>
          <span className="mitre-tech-name">{parent.name}</span>
          {subCount > 0 && (
            <span className="mitre-tech-badge"
                     title="Sub-techniques observed / total (children are independent).">
              <GitBranch size={9} style={{ verticalAlign: -1, marginRight: 3 }} />
              {parent.observed_sub_count}/{subCount}
            </span>
          )}
          <span className={`mitre-tech-badge ${aggObs ? "hot" : ""}`}
                    title={`Direct observations: ${parent.observed_count} · Aggregate (self + subs): ${parent.aggregate_count}`}>
            Σ {parent.aggregate_count}
          </span>
        </button>
        {subCount > 0 && (
          <button
            type="button"
            onClick={onToggle}
            title={isOpen ? "Hide sub-techniques" : `Show ${subCount} sub-techniques`}
            data-testid={`xdr-mitre-parent-toggle-${parent.external_id}`}
            style={{
              padding: "0 8px", marginLeft: 4,
              background: "var(--nx-surf-primary)",
              border: "1px solid var(--nx-bd-quiet)",
              borderRadius: 5,
              color: "var(--nx-muted)",
              cursor: "pointer",
            }}
          >
            {isOpen
              ? <ChevronDown size={12} />
              : <ChevronRight size={12} />}
          </button>
        )}
      </div>
      {isOpen && subCount > 0 && (
        <ul className="mitre-sub-list">
          {parent.subs
            .filter((s) =>
              !filter
              || String(s.external_id).toLowerCase().includes(filter)
              || String(s.name).toLowerCase().includes(filter))
            .map((s) => {
              const sObserved = s.observed_count > 0;
              const sSel = selectedId === s.external_id;
              const sDecorate = { ...s, tactic_shortname: tactic.shortname,
                                                tactic_name: tactic.name, is_sub: true };
              return (
                <li key={s.external_id}>
                  <button
                    type="button"
                    className={`mitre-sub-head ${sSel ? "selected" : ""} ${sObserved ? "observed" : "gap"}`}
                    onClick={() => onSelect(sDecorate)}
                    data-testid={`xdr-mitre-sub-${s.external_id}`}
                  >
                    <span className="mitre-tech-id">{s.external_id}</span>
                    <span className="mitre-tech-name">{s.name}</span>
                    <span className={`mitre-tech-badge ${sObserved ? "hot" : ""}`}>
                      {sObserved
                        ? `${s.observed_count} obs`
                        : "NO EVIDENCE"}
                    </span>
                  </button>
                </li>
              );
            })}
        </ul>
      )}
    </li>
  );
}


function TechniqueDetail({ row, navigate, incidentDocs }) {
  const isSub = !!row.is_sub;
  const incs  = useMemo(() => {
    const set = new Set(row.incident_ids || []);
    return incidentDocs.filter((i) => set.has(i.id));
  }, [row, incidentDocs]);

  const attackUrl   = attackHrefFor({
    id: row.external_id, name: row.name,
  }) || row.url || null;
  const attackTitle = attackLinkTitle({ id: row.external_id });
  const observed    = (row.observed_count || 0) > 0
                    || (row.aggregate_count || 0) > 0;

  return (
    <div data-testid="xdr-mitre-detail-body"
            style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div>
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                        marginBottom: 6, flexWrap: "wrap" }}>
          <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 800,
                             color: "var(--nx-purple)" }}>{row.external_id}</span>
          <NxPill tone="purple">{row.tactic_name || row.tactic_shortname}</NxPill>
          {isSub && <NxPill tone="faint">SUB-TECHNIQUE</NxPill>}
          {observed
            ? <NxPill tone="benign">OBSERVED</NxPill>
            : <NxPill tone="amber">NO EVIDENCE</NxPill>}
        </div>
        <h2 style={{ margin: "0 0 6px",
                          fontFamily: "var(--sans)", fontSize: 20, fontWeight: 700,
                          color: "var(--nx-text)", letterSpacing: "-0.01em" }}>
          {row.name}
        </h2>
        {attackUrl ? (
          <a href={attackUrl} target="_blank" rel="noreferrer"
                title={attackTitle}
                data-testid={`xdr-mitre-heatmap-attack-link-${row.external_id}`}
                style={{ fontFamily: "var(--sans)", fontSize: 12, fontWeight: 600,
                            color: "var(--nx-purple)", textDecoration: "none",
                            display: "inline-flex", alignItems: "center", gap: 4 }}>
            View on attack.mitre.org <ExternalLink size={11} />
          </a>
        ) : (
          <span title={attackTitle}
                   data-testid={`xdr-mitre-heatmap-attack-link-${row.external_id}`}
                   style={{ fontFamily: "var(--mono)", fontSize: 11,
                               color: "var(--nx-text-dim)" }}>
            no attack id
          </span>
        )}
      </div>

      {/* Coverage summary — always honest, aggregate labelled */}
      <div className="nx-attn nx-attn-3" style={{ margin: 0 }}>
        <NxKpi label={isSub ? "Direct observations" : "Direct observations"}
                  value={row.observed_count || 0}
                  tone={(row.observed_count || 0) > 0 ? "high" : "medium"} />
        {!isSub && (
          <NxKpi label="Aggregate (self + subs)"
                    value={row.aggregate_count || 0}
                    tone={(row.aggregate_count || 0) > 0 ? "info" : "medium"} />
        )}
        {isSub && (
          <NxKpi label="Parent technique"
                    value={row.parent_id || "—"}
                    tone="info" />
        )}
        <NxKpi label="Incidents"
                  value={incs.length}
                  tone={incs.length > 0 ? "benign" : "medium"} />
      </div>

      {!isSub && (row.sub_total || 0) > 0 && (
        <div>
          <div style={{ fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
                             textTransform: "uppercase", letterSpacing: 0.5,
                             color: "var(--nx-muted)", marginBottom: 8 }}>
            Sub-technique coverage
            <span style={{ marginLeft: 6, color: "var(--nx-muted)",
                                fontWeight: 500, textTransform: "none",
                                letterSpacing: 0 }}>
              — aggregate counts NEVER imply a child is covered.
            </span>
          </div>
          <ul style={{ listStyle: "none", padding: 0, margin: 0,
                             display: "flex", flexDirection: "column", gap: 4 }}>
            {(row.subs || []).map((s) => (
              <li key={s.external_id}
                     style={{ display: "grid",
                                 gridTemplateColumns: "96px 1fr auto",
                                 gap: 10, alignItems: "baseline",
                                 padding: "4px 8px",
                                 background: "var(--nx-surf-inset)",
                                 border: "1px solid var(--nx-bd-quiet)",
                                 borderRadius: 4 }}>
                <span style={{ fontFamily: "var(--mono)", fontSize: 11,
                                    color: s.observed_count > 0
                                      ? "var(--nx-benign)"
                                      : "var(--nx-purple)" }}>
                  {s.external_id}
                </span>
                <span style={{ fontFamily: "var(--sans)", fontSize: 11.5,
                                    color: "var(--nx-text)" }}>
                  {s.name}
                </span>
                <span className="mitre-tech-badge"
                          style={{
                            color: s.observed_count > 0
                              ? "var(--nx-benign)" : "var(--nx-muted)",
                          }}>
                  {s.observed_count > 0
                    ? `${s.observed_count} obs`
                    : "NO EVIDENCE"}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div>
        <div style={{ fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
                          textTransform: "uppercase", letterSpacing: 0.5,
                          color: "var(--nx-muted)", marginBottom: 8 }}>
          Incidents observed
        </div>
        {incs.length === 0 ? (
          <NxEmpty
            title="No evidence yet"
            body="No incident currently observes this technique. Coverage gap — check whether a detection rule exists and whether the telemetry supports it."
          />
        ) : (
          <ul style={{ listStyle: "none", padding: 0, margin: 0,
                             display: "flex", flexDirection: "column", gap: 6 }}>
            {incs.slice(0, 10).map((i) => (
              <li key={i.id}>
                <button
                  type="button"
                  onClick={() => navigate(`/xdr/incidents/${i.id}`)}
                  style={{
                    width: "100%", display: "grid",
                    gridTemplateColumns: "70px 1fr auto",
                    gap: 10, alignItems: "center",
                    padding: "8px 10px", cursor: "pointer",
                    background: "var(--nx-surf-inset)",
                    border: "1px solid var(--nx-bd-quiet)",
                    borderRadius: 6, textAlign: "left",
                  }}
                  data-testid={`xdr-mitre-detail-incident-${i.id}`}
                >
                  <NxPill tone={priorityTone(i.priority?.code)}>
                    {i.priority?.code || "—"}
                  </NxPill>
                  <span style={{ fontFamily: "var(--sans)", fontSize: 12.5,
                                       color: "var(--nx-text)",
                                       overflow: "hidden", textOverflow: "ellipsis",
                                       whiteSpace: "nowrap" }}>
                    {i.name || "(unnamed)"}
                  </span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 11,
                                       color: "var(--nx-muted)" }}>
                    {i.number}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}


function priorityTone(code) {
  const c = String(code || "").toUpperCase();
  if (c === "P1") return "critical";
  if (c === "P2") return "amber";
  if (c === "P3") return "amber";
  if (c === "P4") return "benign";
  return "faint";
}
