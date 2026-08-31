/**
 * XdrMitreHeatmap · Native XDR MITRE ATT&CK · Phase A.3 redesign.
 *
 * Route: `/xdr/intelligence/mitre`
 *
 * Composition — ATT&CK Coverage Intelligence workspace:
 *
 *   Hero + refresh
 *   Coverage attention strip (5 KPIs, real data)
 *   Two-pane workspace:
 *     · Left column   → Tactic Coverage list (14 tactics · bar per
 *                           tactic · expandable to show techniques)
 *     · Right column → Technique Detail panel (selected technique's
 *                           description, detections, incidents, related
 *                           techniques, investigation link)
 *
 * Data honesty guardrails preserved:
 *   • Heat = REAL detection count from authoritative evidence
 *   • Every unobserved technique is an HONEST coverage gap
 *   • No fabricated risk score anywhere
 *
 * Fits inside a 1440px viewport without horizontal overflow.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { RefreshCcw, Search, ExternalLink, ChevronRight, Target } from "lucide-react";
import { useNavigate } from "react-router-dom";

import XdrShell from "@/xdr/XdrShell";
import { NxKpi, NxEmptyBlock as NxEmpty, NxPill } from "@/xdr/nx";
import { listIncidents } from "@/lib/incidentsApi";
import {
  KILL_CHAIN, TECHNIQUES_BY_TACTIC, TECHNIQUE_INDEX,
  DISTINCT_TECHNIQUE_IDS, RULE_TO_TECHNIQUE,
} from "@/xdr/mitre/mitreTactics";

const AUTO_REFRESH_MS = 30_000;


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
  const [incidents, setIncidents] = useState(null);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefresh]  = useState(false);
  const [error, setError]         = useState(null);
  const [q, setQ]                 = useState("");
  const [selected, setSelected]   = useState(null);
  const [openTactic, setOpenTactic] = useState(null); // key
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
      const data = await listIncidents({ limit: 500 });
      setIncidents(data?.incidents || data || []);
      setSynced(new Date().toISOString());
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load incidents.");
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

  // Roll up detections and incidents per technique + per tactic.
  const rollup = useMemo(() => {
    const perTech = {};          // T-id -> { detections, incidents:Set }
    const perTactic = {};        // tactic key -> { detections, techniquesObserved:Set }
    const list = incidents || [];
    for (const inc of list) {
      const ev = inc?.verdict_stage2?.evidence || inc?.evidence || [];
      for (const e of ev) {
        const rid = (e.rule_id || "").toUpperCase();
        const tid = RULE_TO_TECHNIQUE[rid] || e.technique_id;
        if (!tid || !TECHNIQUE_INDEX[tid]) continue;
        const pt = perTech[tid] || { detections: 0, incidents: new Set() };
        pt.detections += 1;
        pt.incidents.add(inc.id);
        perTech[tid] = pt;

        const tactic = TECHNIQUE_INDEX[tid].tactic;
        const pty = perTactic[tactic] || {
          detections: 0, techniquesObserved: new Set(), incidents: new Set(),
        };
        pty.detections += 1;
        pty.techniquesObserved.add(tid);
        pty.incidents.add(inc.id);
        perTactic[tactic] = pty;
      }
    }
    return { perTech, perTactic, incidentsScanned: list.length };
  }, [incidents]);

  const kpis = useMemo(() => {
    const totalTechniques = DISTINCT_TECHNIQUE_IDS.length;
    const mappedTechIds   = new Set(Object.values(RULE_TO_TECHNIQUE));
    const withMappedRule  = [...mappedTechIds].filter((t) => TECHNIQUE_INDEX[t]).length;
    const observed        = Object.keys(rollup.perTech).length;
    const coverage        = totalTechniques ? (observed / totalTechniques) * 100 : 0;
    return {
      totalTechniques, withMappedRule, observed,
      coveragePct: Math.round(coverage * 10) / 10,
      incidentsScanned: rollup.incidentsScanned,
    };
  }, [rollup]);

  const filter = q.trim().toLowerCase();

  return (
    <XdrShell>
      <div className="mitre-page" data-testid="xdr-mitre-page">
        {/* Hero */}
        <header className="mitre-hero" data-testid="xdr-mitre-hero">
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="nx-page-hero-eyebrow">Intelligence · ATT&CK Coverage</div>
            <h1 className="nx-page-hero-title" data-testid="xdr-mitre-heading">
              MITRE ATT&amp;CK Coverage Intelligence
            </h1>
            <div className="nx-page-hero-desc">
              Detection coverage across the ATT&CK matrix — every
              highlighted technique cites the incidents that observed
              it. Unobserved techniques are honest coverage gaps, not
              fabricated risk scores.
            </div>
          </div>
          <div className="mitre-hero-actions">
            <div className="mitre-search">
              <Search size={13} />
              <input
                placeholder="Search technique ID or name…"
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

        {/* Attention strip */}
        <div className="nx-attn nx-attn-5" data-testid="xdr-mitre-kpis">
          <NxKpi
            icon={Target}
            tone="critical"
            label="Coverage"
            value={`${kpis.coveragePct}%`}
            sub={`${kpis.observed}/${kpis.totalTechniques} techniques observed`}
          />
          <NxKpi
            label="Techniques Observed"
            value={kpis.observed}
            tone="high"
            sub="From authoritative evidence"
          />
          <NxKpi
            label="Rules Mapped"
            value={`${kpis.withMappedRule}/${kpis.totalTechniques}`}
            tone="info"
            sub="Techniques with a detection rule"
          />
          <NxKpi
            label="Incidents Scanned"
            value={kpis.incidentsScanned}
            tone="benign"
            sub={`Last synced ${fmtRelative(lastSyncedAt)}`}
          />
          <NxKpi
            label="Coverage Gaps"
            value={kpis.totalTechniques - kpis.observed}
            tone="medium"
            sub="Techniques with no evidence yet"
          />
        </div>

        {loading && <NxEmpty title="Loading matrix…" body="Aggregating evidence from all incidents." />}
        {!loading && error && <NxEmpty title="Failed to load" body={String(error)} />}

        {!loading && !error && (
          <div className="mitre-workspace">
            {/* Left · Tactic coverage list */}
            <section className="mitre-tactic-list" data-testid="xdr-mitre-tactics">
              <div className="mitre-tactic-list-head">
                <span className="mitre-list-title">Tactic Coverage</span>
                <span className="mitre-list-sub">14 tactics · click a tactic to expand</span>
              </div>
              <div className="mitre-tactic-list-body">
                {KILL_CHAIN.map((tactic) => {
                  const techs = TECHNIQUES_BY_TACTIC[tactic.key] || [];
                  const total = techs.length;
                  const pty = rollup.perTactic[tactic.key] || {};
                  const observed = pty.techniquesObserved ? pty.techniquesObserved.size : 0;
                  const dets = pty.detections || 0;
                  const pct = total ? Math.round((observed / total) * 100) : 0;
                  const isOpen = openTactic === tactic.key;
                  const visibleTechs = techs.filter(t =>
                    !filter || t.id.toLowerCase().includes(filter) ||
                                 t.name.toLowerCase().includes(filter));

                  return (
                    <div key={tactic.key} className="mitre-tactic-row"
                            data-testid={`xdr-mitre-tactic-${tactic.key}`}>
                      <button
                        type="button"
                        className={`mitre-tactic-head ${isOpen ? "open" : ""}`}
                        onClick={() => setOpenTactic(isOpen ? null : tactic.key)}
                        data-testid={`xdr-mitre-tactic-toggle-${tactic.key}`}
                      >
                        <ChevronRight
                          size={12}
                          className="mitre-caret"
                          style={{ transform: isOpen ? "rotate(90deg)" : "none" }}
                        />
                        <div className="mitre-tactic-title">
                          <div className="mitre-tactic-label">{tactic.label}</div>
                          <div className="mitre-tactic-meta">
                            <span className="mono">{observed}/{total}</span> techniques ·{" "}
                            <span className="mono">{dets}</span> detections
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
                          {visibleTechs.length === 0 && (
                            <li className="mitre-tech-empty">No matching techniques.</li>
                          )}
                          {visibleTechs.map(t => {
                            const rec = rollup.perTech[t.id];
                            const n = rec?.detections || 0;
                            const isSelected = selected?.id === t.id;
                            return (
                              <li key={t.id}>
                                <button
                                  type="button"
                                  className={`mitre-tech ${isSelected ? "selected" : ""} ${n > 0 ? "observed" : "gap"}`}
                                  onClick={() => setSelected({
                                    ...t, tactic: tactic.key, tacticLabel: tactic.label,
                                    detections: n, incidents: rec ? [...rec.incidents] : [],
                                  })}
                                  data-testid={`xdr-mitre-tech-${t.id}`}
                                >
                                  <span className="mitre-tech-id mono">{t.id}</span>
                                  <span className="mitre-tech-name">{t.name}</span>
                                  <span className={`mitre-tech-count mono ${n > 0 ? "hot" : "cold"}`}>
                                    {n}
                                  </span>
                                </button>
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>

            {/* Right · Technique detail */}
            <section className="mitre-detail" data-testid="xdr-mitre-detail">
              {!selected ? (
                <div className="mitre-detail-empty">
                  <Target size={22} />
                  <h4>Select a technique</h4>
                  <p>Expand a tactic on the left and pick any technique to see its detections, incidents and coverage state.</p>
                </div>
              ) : (
                <TechniqueDetail
                  tech={selected}
                  navigate={navigate}
                  incidentDocs={incidents || []}
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
          color: var(--nx-text); width: 240px;
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
          max-height: 620px;
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
          list-style: none; margin: 0; padding: 8px 16px 12px 44px;
          background: var(--nx-surf-inset);
          display: flex; flex-direction: column;
          gap: 4px;
        }
        .mitre-tech {
          display: grid;
          grid-template-columns: 80px 1fr 36px;
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
        .mitre-tech:hover { border-color: var(--nx-bd-strong); }
        .mitre-tech.selected {
          border-color: var(--nx-purple);
          background: var(--nx-purple-dim);
        }
        .mitre-tech.observed { border-left: 3px solid var(--nx-benign); }
        .mitre-tech.gap { border-left: 3px solid var(--nx-bd-quiet); }
        .mitre-tech-id {
          font-size: 11px; font-weight: 700;
          color: var(--nx-purple);
        }
        .mitre-tech-name {
          font-family: var(--sans); font-size: 11.5px;
          color: var(--nx-text);
          overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        }
        .mitre-tech-count {
          font-size: 11px; font-weight: 800; text-align: right;
        }
        .mitre-tech-count.hot { color: var(--nx-text); }
        .mitre-tech-count.cold { color: var(--nx-muted); }
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
          max-width: 320px;
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


function TechniqueDetail({ tech, navigate, incidentDocs }) {
  // Get real incidents where this technique was observed.
  const incs = useMemo(() => {
    const set = new Set(tech.incidents || []);
    return incidentDocs.filter(i => set.has(i.id));
  }, [tech, incidentDocs]);
  const related = useMemo(() => {
    // Techniques in the same tactic.
    return (TECHNIQUES_BY_TACTIC[tech.tactic] || [])
      .filter(t => t.id !== tech.id)
      .slice(0, 6);
  }, [tech]);

  const attackUrl = `https://attack.mitre.org/techniques/${tech.id.replace(".", "/")}/`;

  return (
    <div data-testid="xdr-mitre-detail-body"
            style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div>
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                        marginBottom: 6 }}>
          <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 800,
                             color: "var(--nx-purple)" }}>{tech.id}</span>
          <NxPill tone="purple">{tech.tacticLabel}</NxPill>
          {tech.detections > 0
            ? <NxPill tone="benign">OBSERVED</NxPill>
            : <NxPill tone="amber">COVERAGE GAP</NxPill>}
        </div>
        <h2 style={{ margin: "0 0 6px",
                          fontFamily: "var(--sans)", fontSize: 20, fontWeight: 700,
                          color: "var(--nx-text)", letterSpacing: "-0.01em" }}>
          {tech.name}
        </h2>
        <a href={attackUrl} target="_blank" rel="noreferrer"
              style={{ fontFamily: "var(--sans)", fontSize: 12, fontWeight: 600,
                          color: "var(--nx-purple)", textDecoration: "none",
                          display: "inline-flex", alignItems: "center", gap: 4 }}>
          View on attack.mitre.org <ExternalLink size={11} />
        </a>
      </div>

      {/* Coverage summary */}
      <div className="nx-attn nx-attn-3" style={{ margin: 0 }}>
        <NxKpi label="Detections"
                  value={tech.detections}
                  tone={tech.detections > 0 ? "high" : "medium"} />
        <NxKpi label="Incidents"
                  value={incs.length}
                  tone={incs.length > 0 ? "info" : "medium"} />
        <NxKpi label="Rules Mapped"
                  value={countMapped(tech.id)}
                  tone={countMapped(tech.id) > 0 ? "benign" : "medium"} />
      </div>

      {/* Incidents that observed this technique */}
      <div>
        <div style={{ fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
                          textTransform: "uppercase", letterSpacing: 0.5,
                          color: "var(--nx-muted)", marginBottom: 8 }}>
          Incidents observed
        </div>
        {incs.length === 0 ? (
          <NxEmpty
            title="No evidence yet"
            body={`This technique has not been observed in any current incident. Coverage gap — investigate whether a detection rule exists and whether telemetry supports it.`}
          />
        ) : (
          <ul style={{ listStyle: "none", padding: 0, margin: 0,
                             display: "flex", flexDirection: "column", gap: 6 }}>
            {incs.slice(0, 8).map(i => (
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

      {/* Related techniques */}
      {related.length > 0 && (
        <div>
          <div style={{ fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
                             textTransform: "uppercase", letterSpacing: 0.5,
                             color: "var(--nx-muted)", marginBottom: 8 }}>
            Related techniques in {tech.tacticLabel}
          </div>
          <ul style={{ listStyle: "none", padding: 0, margin: 0,
                             display: "flex", flexWrap: "wrap", gap: 6 }}>
            {related.map(r => (
              <li key={r.id}>
                <span className="nx-pill nx-pill-faint">
                  <span style={{ fontFamily: "var(--mono)",
                                     color: "var(--nx-purple)" }}>
                    {r.id}
                  </span>
                  {" · "}{r.name}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function countMapped(techId) {
  let n = 0;
  for (const t of Object.values(RULE_TO_TECHNIQUE)) if (t === techId) n += 1;
  return n;
}

function priorityTone(code) {
  const c = String(code || "").toUpperCase();
  if (c === "P1") return "critical";
  if (c === "P2") return "amber";
  if (c === "P3") return "amber";
  if (c === "P4") return "benign";
  return "faint";
}
