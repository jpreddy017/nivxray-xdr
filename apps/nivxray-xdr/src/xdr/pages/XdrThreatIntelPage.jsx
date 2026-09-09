/**
 * XdrThreatIntelPage · `/xdr/intelligence/threat`
 *
 * Wires the EXISTING NivXRay threat-intelligence service into NivXRay XDR.
 * No second TI store, no seeded indicators, no hardcoded counts.
 *
 *   /api/threat-intel/stats         → totals + per-type breakdown
 *   /api/threat-intel/sources       → per-source configured / sync / error
 *   /api/threat-intel/feeds/status  → cached counts per feed
 *   /api/threat-intel/iocs          → indicator search (q, kind, limit)
 *
 * This page replaced a RESERVED placeholder that rendered hardcoded `0`s
 * beneath the sentence "No intelligence sources are configured for this
 * tenant" — while the service held six figures of indicators across
 * configured, actively-syncing sources. Every number here is read from the
 * response; a field the service does not emit renders "—", never 0.
 */
import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Radar, RefreshCcw, Search, AlertTriangle } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";

const KINDS = ["", "ip", "domain", "url", "sha256", "md5", "sha1"];

export default function XdrThreatIntelPage() {
  const [params, setParams] = useSearchParams();
  const [stats, setStats]     = useState(null);
  const [sources, setSources] = useState([]);
  const [feeds, setFeeds]     = useState([]);
  const [rows, setRows]       = useState([]);
  const [total, setTotal]     = useState(null);
  const [err, setErr]         = useState(null);
  const [busy, setBusy]       = useState(false);
  const [q, setQ]             = useState(params.get("q") || "");
  const [kind, setKind]       = useState(params.get("kind") || "");
  const [tick, setTick]       = useState(0);

  useEffect(() => {
    let dead = false;
    (async () => {
      setBusy(true); setErr(null);
      try {
        const [s, src, fs] = await Promise.all([
          api.get("/threat-intel/stats"),
          api.get("/threat-intel/sources"),
          api.get("/threat-intel/feeds/status"),
        ]);
        if (dead) return;
        setStats(s?.data || null);
        setSources(Array.isArray(src?.data) ? src.data : (src?.data?.sources || []));
        setFeeds(fs?.data?.sources || []);
      } catch (x) {
        if (!dead) setErr(x?.response?.data?.detail || x?.message || "load failed");
      } finally { if (!dead) setBusy(false); }
    })();
    return () => { dead = true; };
  }, [tick]);

  useEffect(() => {
    let dead = false;
    (async () => {
      try {
        const r = await api.get("/threat-intel/iocs", {
          params: { limit: 100, ...(q ? { q } : {}), ...(kind ? { kind } : {}) },
        });
        if (dead) return;
        setRows(r?.data?.items || []);
        setTotal(Number.isFinite(r?.data?.total) ? r.data.total : null);
      } catch (x) {
        if (!dead) setErr(x?.response?.data?.detail || x?.message);
      }
    })();
    return () => { dead = true; };
  }, [q, kind, tick]);

  const byType = stats?.by_type || stats?.by_kind || {};

  return (
    <XdrShell>
      <div data-testid="xdr-threat-intel-page">
        <div style={head}>
          <Radar size={16} />
          <h1 className="page-h1" style={{ margin: 0 }}>Threat Intelligence</h1>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" disabled={busy}
                  data-testid="xdr-ti-refresh"
                  onClick={() => setTick((n) => n + 1)}
                  style={{ padding: "6px 12px", fontSize: 12 }}>
            <RefreshCcw size={12} /> Refresh
          </button>
        </div>
        <div style={sub}>
          Stored indicators and feed health from the NivXRay threat-intelligence
          service. Counts are read from the service — never seeded here.
        </div>

        {err && <div style={errBox} data-testid="xdr-ti-error">{err}</div>}

        <div style={grid3}>
          <Stat label="Indicators stored"
                value={fmt(stats?.total)} testid="xdr-ti-stat-total" />
          <Stat label="Configured sources"
                value={sources.length
                         ? `${sources.filter((s) => s.configured).length} of ${sources.length}`
                         : "—"}
                testid="xdr-ti-stat-sources" />
          <Stat label="Sources reporting an error"
                value={sources.length
                         ? String(sources.filter((s) => s.last_error).length)
                         : "—"}
                testid="xdr-ti-stat-errors" />
        </div>

        {Object.keys(byType).length > 0 && (
          <div style={{ ...panel, marginTop: 10 }} data-testid="xdr-ti-by-type">
            <div style={panelH}>Indicators by type</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 14,
                           padding: "8px 10px" }}>
              {Object.entries(byType)
                .sort((a, b) => b[1] - a[1])
                .map(([k, v]) => (
                  <span key={k} className="mono" style={{ fontSize: 11 }}
                        data-testid={`xdr-ti-type-${k}`}>
                    <b>{fmt(v)}</b>{" "}
                    <span style={{ color: "var(--faint)" }}>{k}</span>
                  </span>
                ))}
            </div>
          </div>
        )}

        <div style={{ ...panel, marginTop: 10 }}>
          <div style={panelH}>Sources</div>
          <div style={{ ...row, ...rowH, gridTemplateColumns: srcCols }}>
            <div>Source</div><div>Configured</div><div>Last sync</div>
            <div>Status</div><div>New</div><div>Error</div>
          </div>
          {sources.map((s) => (
            <div key={s.id} style={{ ...row, gridTemplateColumns: srcCols }}
                 data-testid={`xdr-ti-source-${s.id}`}
                 data-configured={String(!!s.configured)}>
              <div>{s.label || s.id}</div>
              <div className="mono" style={{ fontSize: 10 }}>
                {s.configured ? "YES" : "NO"}
              </div>
              <div className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
                {(s.last_sync || "").slice(0, 16).replace("T", " ") || "never"}
              </div>
              <div className="mono" style={{ fontSize: 10 }}>
                {s.last_status || "—"}
              </div>
              <div className="mono" style={{ fontSize: 10 }}>
                {Number.isFinite(s.last_new) ? fmt(s.last_new) : "—"}
              </div>
              <div className="mono" style={{ fontSize: 10,
                                              color: s.last_error
                                                ? "var(--nx-danger, #d64545)"
                                                : "var(--faint)" }}>
                {s.last_error
                  ? <span data-testid={`xdr-ti-source-${s.id}-error`}>
                      <AlertTriangle size={10} /> {String(s.last_error)}
                    </span>
                  : "—"}
              </div>
            </div>
          ))}
          {!busy && sources.length === 0 && (
            <div style={empty} data-testid="xdr-ti-sources-empty">
              /api/threat-intel/sources returned no sources
            </div>
          )}
        </div>

        {feeds.length > 0 && (
          <div style={{ ...panel, marginTop: 10 }} data-testid="xdr-ti-feeds">
            <div style={panelH}>Cached feed volumes</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 14,
                           padding: "8px 10px" }}>
              {feeds.map((f) => (
                <span key={f._id} className="mono" style={{ fontSize: 11 }}
                      data-testid={`xdr-ti-feed-${f._id}`}>
                  <b>{fmt(f.count)}</b>{" "}
                  <span style={{ color: "var(--faint)" }}>{f._id}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        <div style={{ ...panel, marginTop: 10 }}>
          <div style={panelH}>Indicator search</div>
          <div style={{ display: "flex", gap: 6, padding: "8px 10px",
                         alignItems: "center" }}>
            <Search size={12} style={{ color: "var(--faint)" }} />
            <input value={q}
                   onChange={(e) => {
                     setQ(e.target.value);
                     const p = new URLSearchParams(params);
                     e.target.value ? p.set("q", e.target.value) : p.delete("q");
                     setParams(p, { replace: true });
                   }}
                   placeholder="Search stored indicators…"
                   data-testid="xdr-ti-search" style={input} />
            <select value={kind} onChange={(e) => setKind(e.target.value)}
                    data-testid="xdr-ti-kind" style={{ ...input, flex: "0 0 130px" }}>
              {KINDS.map((k) => (
                <option key={k || "all"} value={k}>{k || "all types"}</option>
              ))}
            </select>
          </div>
          <div className="mono" style={countLine} data-testid="xdr-ti-count">
            {total === null
              ? "—"
              : `${rows.length} shown · ${fmt(total)} match${total === 1 ? "" : "es"}`}
          </div>
          <div style={{ ...row, ...rowH, gridTemplateColumns: iocCols }}>
            <div>Type</div><div>Value</div><div>Confidence</div>
            <div>Source</div><div>Last seen</div>
          </div>
          {rows.map((r, i) => (
            <div key={`${r.kind}:${r.value}:${i}`}
                 style={{ ...row, gridTemplateColumns: iocCols }}
                 data-testid={`xdr-ti-ioc-${i}`}>
              <div className="mono" style={{ fontSize: 10 }}>{r.kind}</div>
              <div className="mono" style={{ fontSize: 10.5, wordBreak: "break-all" }}>
                {r.value}
              </div>
              <div className="mono" style={{ fontSize: 10 }}>
                {Number.isFinite(r.confidence) ? r.confidence : "—"}
              </div>
              <div className="mono" style={{ fontSize: 10 }}>{r.source || "—"}</div>
              <div className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
                {(r.last_seen || r.first_seen || "").slice(0, 10) || "—"}
              </div>
            </div>
          ))}
          {rows.length === 0 && (
            <div style={empty} data-testid="xdr-ti-iocs-empty">
              {q || kind
                ? "No stored indicator matches this query"
                : "/api/threat-intel/iocs returned no indicators"}
            </div>
          )}
        </div>
      </div>
    </XdrShell>
  );
}

const fmt = (n) =>
  Number.isFinite(n) ? n.toLocaleString() : "—";

function Stat({ label, value, testid }) {
  return (
    <div data-testid={testid} style={statCard}>
      <div style={statLabel}>{label}</div>
      <div style={statValue}>{value}</div>
    </div>
  );
}

const head = { display: "flex", alignItems: "center", gap: 10, marginBottom: 6 };
const sub = { color: "var(--text-dim)", fontSize: 12, marginBottom: 12,
              maxWidth: 760, lineHeight: 1.6 };
const grid3 = { display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 };
const panel = { border: "1px solid var(--border)", borderRadius: 3,
                overflow: "hidden" };
const panelH = { padding: "7px 10px", fontSize: 10, fontWeight: 800,
                 letterSpacing: ".4px", textTransform: "uppercase",
                 color: "var(--faint)", borderBottom: "1px solid var(--border)" };
const srcCols = "1.4fr .7fr 1.1fr .7fr .6fr 2fr";
const iocCols = ".6fr 2.4fr .8fr .9fr .9fr";
const row = { display: "grid", gap: 8, padding: "6px 10px", fontSize: 11.5,
              borderBottom: "1px solid var(--border)", alignItems: "center" };
const rowH = { fontSize: 9.5, fontWeight: 800, letterSpacing: ".4px",
               textTransform: "uppercase", color: "var(--faint)" };
const empty = { padding: "10px 10px", fontSize: 11, color: "var(--faint)",
                fontFamily: "var(--mono)" };
const countLine = { padding: "0 10px 6px", fontSize: 10.5,
                    color: "var(--faint)" };
const input = { flex: 1, padding: "5px 8px", fontSize: 12 };
const statCard = { border: "1px solid var(--border)", borderRadius: 3,
                   padding: "10px 12px" };
const statLabel = { fontSize: 9.5, fontWeight: 800, letterSpacing: ".4px",
                    textTransform: "uppercase", color: "var(--faint)" };
const statValue = { fontSize: 22, fontWeight: 700, marginTop: 4 };
const errBox = { border: "1px solid var(--nx-danger, #d64545)", borderRadius: 3,
                 padding: "8px 10px", fontSize: 11, marginBottom: 10,
                 fontFamily: "var(--mono)" };
