/**
 * XdrThreatIntelPage · `/xdr/intelligence/threat`  (B4 · nx modernization)
 *
 * Wires the EXISTING NivXRay threat-intelligence service into NivXRay XDR.
 * No second TI store, no seeded indicators, no hardcoded counts.
 *
 *   /api/threat-intel/stats         → totals + per-type breakdown
 *   /api/threat-intel/sources       → per-source configured / sync / error
 *   /api/threat-intel/feeds/status  → cached counts per feed
 *   /api/threat-intel/iocs          → indicator search (q, kind, limit)
 *
 * Surface language is the platform's investigation language: summary →
 * dense operational table → contextual inspection → technical detail on
 * demand. A field the service does not emit renders its named absence,
 * never 0.
 */
import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { AlertTriangle, Radar, RefreshCcw, Search } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvValue, NxInvMetrics,
  ABSENCE, fmtTime,
} from "@/xdr/nx";
import "@/xdr/nx/nx-inv.css";
import "@/xdr/nx/nx-workspace.css";

const KINDS = ["", "ip", "domain", "url", "sha256", "md5", "sha1"];
const fmt = (n) => (Number.isFinite(n) ? n.toLocaleString() : null);

export default function XdrThreatIntelPage() {
  const [params, setParams] = useSearchParams();
  const [stats, setStats]   = useState(null);
  const [sources, setSources] = useState([]);
  const [feeds, setFeeds]   = useState([]);
  const [rows, setRows]     = useState([]);
  const [total, setTotal]   = useState(null);
  const [err, setErr]       = useState(null);
  const [busy, setBusy]     = useState(false);
  const [q, setQ]           = useState(params.get("q") || "");
  const [kind, setKind]     = useState(params.get("kind") || "");
  const [tick, setTick]     = useState(0);
  const [sel, setSel]       = useState(null);
  const [paneTab, setPaneTab] = useState("details");

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
  const selected = useMemo(() => rows.find(
    (r, i) => `${r.kind}:${r.value}:${i}` === sel) || null, [rows, sel]);

  return (
    <XdrShell>
      <div className="inv" data-testid="xdr-threat-intel-page"
           style={{ padding: "12px 16px 24px" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 10,
                      marginBottom: 10, flexWrap: "wrap" }}>
          <Radar size={16} style={{ alignSelf: "center" }} />
          <h1 style={{ margin: 0, fontSize: 19, fontWeight: 700 }}>
            Threat Intelligence
          </h1>
          <span style={{ fontSize: 11, color: "var(--nx-muted, var(--muted))",
                         maxWidth: 700, lineHeight: 1.6 }}>
            Stored indicators and feed health, read from the NivXRay
            threat-intelligence service. Counts are never seeded here, and a
            metric the service does not emit is named, not zeroed.
          </span>
          <button className="inv-chip" disabled={busy}
                  style={{ marginLeft: "auto" }}
                  data-testid="xdr-ti-refresh"
                  onClick={() => setTick((n) => n + 1)}>
            <RefreshCcw size={11} /> Refresh
          </button>
        </div>

        {err && (
          <NxInvEmpty testid="xdr-ti-error"
            title={`${ABSENCE.ERROR} — the intelligence service could not be read`}
            body={typeof err === "object" ? JSON.stringify(err) : String(err)} />
        )}

        <NxInvSection title="Indicator estate"
                      subtitle="what the service holds right now"
                      testid="xdr-ti-summary">
          <NxInvMetrics testid="xdr-ti-stat" items={[
            { key: "total", label: "Indicators stored", value: fmt(stats?.total),
              absent: ABSENCE.NOT_AVAILABLE },
            { key: "sources", label: "Configured sources",
              value: sources.length
                ? `${sources.filter((s) => s.configured).length} of ${sources.length}`
                : null,
              absent: ABSENCE.NOT_AVAILABLE },
            { key: "errors", label: "Sources reporting an error",
              value: sources.length
                ? String(sources.filter((s) => s.last_error).length) : null,
              absent: ABSENCE.NOT_AVAILABLE },
          ]} />
          {Object.keys(byType).length > 0 && (
            <div className="inv-filters" data-testid="xdr-ti-by-type">
              <span className="inv-cov__k">Indicators by type</span>
              {Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([k, v]) => (
                <button key={k} className="inv-chip"
                        aria-pressed={kind === k}
                        onClick={() => setKind(kind === k ? "" : k)}
                        data-testid={`xdr-ti-type-${k}`}>
                  {k}<span className="inv-chip__n">{fmt(v) ?? "—"}</span>
                </button>
              ))}
            </div>
          )}
        </NxInvSection>

        <NxInvSection title="Sources"
                      subtitle="configuration, last sync and the error the source itself reported"
                      testid="xdr-ti-sources-sec">
          <NxInvTable testid="xdr-ti-sources-table" rows={sources}
                      rowKey={(s) => s.id}
                      columns={[
                        { key: "label", label: "Source",
                          render: (s) => <span data-testid={`xdr-ti-source-${s.id}`}
                            data-configured={String(!!s.configured)}>
                            {s.label || s.id}</span> },
                        { key: "configured", label: "Configured", width: 110,
                          render: (s) => (s.configured ? "YES" : "NO") },
                        { key: "last_sync", label: "Last sync", width: 160,
                          render: (s) => <NxInvValue value={fmtTime(s.last_sync)}
                            mono absent="NEVER SYNCED" /> },
                        { key: "last_status", label: "Status", width: 120,
                          render: (s) => <NxInvValue value={s.last_status} mono
                            absent={ABSENCE.NOT_RECORDED} /> },
                        { key: "last_new", label: "New", width: 90, num: true,
                          render: (s) => <NxInvValue value={fmt(s.last_new)}
                            mono absent="—" /> },
                        { key: "last_error", label: "Error reported",
                          render: (s) => (s.last_error
                            ? <span data-testid={`xdr-ti-source-${s.id}-error`}
                                    style={{ color: "var(--nx-critical, #E5484D)" }}>
                                <AlertTriangle size={10}
                                  style={{ verticalAlign: -1, marginRight: 4 }} />
                                {String(s.last_error)}
                              </span>
                            : <span className="inv-tb__na">NO ERROR REPORTED</span>) },
                      ]}
                      empty={<NxInvEmpty testid="xdr-ti-sources-empty"
                        title={busy ? "Reading sources…" : ABSENCE.NO_DATA}
                        body="/api/threat-intel/sources returned no source. No source is invented to fill this table." />} />
        </NxInvSection>

        <NxInvSection title="Indicator search"
          subtitle={total === null
            ? "match count not reported by the service"
            : `${rows.length} shown · ${fmt(total)} match${total === 1 ? "" : "es"}`}
          testid="xdr-ti-search-sec">
          <div className="inv-filters" data-testid="xdr-ti-toolbar">
            <span className="inv-cov__k" style={{ display: "inline-flex",
                    alignItems: "center", gap: 5 }}>
              <Search size={11} />
              <input value={q}
                     onChange={(e) => {
                       setQ(e.target.value);
                       const p = new URLSearchParams(params);
                       if (e.target.value) p.set("q", e.target.value);
                       else p.delete("q");
                       setParams(p, { replace: true });
                     }}
                     placeholder="Search stored indicators…"
                     data-testid="xdr-ti-search"
                     style={{ fontSize: 11, background: "transparent",
                              border: "none", outline: "none", width: 300,
                              color: "var(--nx-text, var(--text))",
                              textTransform: "none", letterSpacing: 0 }} />
            </span>
            <select value={kind} onChange={(e) => setKind(e.target.value)}
                    data-testid="xdr-ti-kind"
                    style={{ fontSize: 10.6, padding: "2px 6px",
                             borderRadius: 3, background: "transparent",
                             color: "var(--nx-text, var(--text))",
                             border: "1px solid var(--nx-bd-quiet, var(--border))" }}>
              {KINDS.map((k) => (
                <option key={k || "all"} value={k}>{k || "all types"}</option>
              ))}
            </select>
            <span className="inv-filters__sp inv-sec__s mono"
                  data-testid="xdr-ti-count">
              {total === null ? "—"
                : `${rows.length} shown · ${fmt(total)} match${total === 1 ? "" : "es"}`}
            </span>
          </div>

          <div className="inv-split" data-testid="xdr-ti-wk"
               data-pane={selected ? "open" : "closed"}>
            <div className="inv-split__t">
              <NxInvTable testid="xdr-ti-iocs-table" rows={rows}
                          rowKey={(r, i) => `${r.kind}:${r.value}:${i}`}
                          onRowClick={(r) => {
                            const i = rows.indexOf(r);
                            setSel(`${r.kind}:${r.value}:${i}`);
                            setPaneTab("details");
                          }}
                          columns={[
                            { key: "kind", label: "Type", width: 96,
                              render: (r) => <span className="mono">{r.kind}</span> },
                            { key: "value", label: "Indicator",
                              render: (r) => <span className="mono"
                                data-testid={`xdr-ti-ioc-${rows.indexOf(r)}`}
                                style={{ wordBreak: "break-all" }}>
                                {r.value}</span> },
                            { key: "confidence", label: "Confidence", width: 110,
                              num: true,
                              render: (r) => (Number.isFinite(r.confidence)
                                ? r.confidence
                                : <span className="inv-tb__na">
                                    {ABSENCE.NOT_EVALUATED}</span>) },
                            { key: "source", label: "Source", width: 150,
                              render: (r) => <NxInvValue value={r.source} mono
                                absent={ABSENCE.NOT_ATTRIBUTED} /> },
                            { key: "last_seen", label: "Last seen", width: 130,
                              render: (r) => <NxInvValue
                                value={(r.last_seen || r.first_seen || "")
                                  .slice(0, 10) || null}
                                mono absent={ABSENCE.NOT_RECORDED} /> },
                          ]}
                          empty={<NxInvEmpty testid="xdr-ti-iocs-empty"
                            title={q || kind
                              ? "No stored indicator matches this query"
                              : ABSENCE.NO_DATA}
                            body={q || kind
                              ? "Clear the query or the type filter to see the stored estate."
                              : "/api/threat-intel/iocs returned no indicator."} />} />
            </div>

            {selected && (
              <div className="inv-split__p" data-testid="xdr-ti-pane">
                <div className="inv-pane__h">
                  <span style={{ minWidth: 0 }}>
                    <div className="inv-pane__k">{selected.kind}</div>
                    <div className="inv-pane__t" data-testid="xdr-ti-pane-title">
                      {selected.value}
                    </div>
                  </span>
                  <button className="inv-chip" style={{ marginLeft: "auto" }}
                          onClick={() => setSel(null)}
                          data-testid="xdr-ti-pane-close">Close</button>
                </div>
                <div className="inv-pane__tabs" role="tablist">
                  {[["details", "Details"], ["technical", "Technical"]]
                    .map(([k, label]) => (
                    <button key={k} className="inv-pane__tab" role="tab"
                            aria-selected={paneTab === k}
                            onClick={() => setPaneTab(k)}
                            data-testid={`xdr-ti-pane-tab-${k}`}>
                      {label}
                    </button>
                  ))}
                </div>
                <div className="inv-pane__b">
                  {paneTab === "details" ? (
                    <dl className="inv-kv">
                      <dt>Type</dt>
                      <dd className="mono">{selected.kind}</dd>
                      <dt>Confidence</dt>
                      <dd className="mono">{Number.isFinite(selected.confidence)
                        ? selected.confidence
                        : <span className="inv-tb__na">
                            {ABSENCE.NOT_EVALUATED}</span>}</dd>
                      <dt>Source</dt>
                      <dd className="mono"><NxInvValue value={selected.source}
                        absent={ABSENCE.NOT_ATTRIBUTED} /></dd>
                      <dt>First seen</dt>
                      <dd className="mono"><NxInvValue
                        value={fmtTime(selected.first_seen)}
                        absent={ABSENCE.NOT_RECORDED} /></dd>
                      <dt>Last seen</dt>
                      <dd className="mono"><NxInvValue
                        value={fmtTime(selected.last_seen)}
                        absent={ABSENCE.NOT_RECORDED} /></dd>
                    </dl>
                  ) : (
                    <pre style={{ margin: 0, fontSize: 10.4,
                                  whiteSpace: "pre-wrap",
                                  wordBreak: "break-all" }}>
                      {JSON.stringify(selected, null, 1)}
                    </pre>
                  )}
                </div>
              </div>
            )}
          </div>
        </NxInvSection>

        {feeds.length > 0 && (
          <NxInvTech label="Technical details · cached feed volumes"
                     testid="xdr-ti-feeds">
            <div className="inv-filters">
              {feeds.map((f) => (
                <span key={f._id} className="inv-chip"
                      style={{ cursor: "default" }}
                      data-testid={`xdr-ti-feed-${f._id}`}>
                  {f._id}<span className="inv-chip__n">{fmt(f.count) ?? "—"}</span>
                </span>
              ))}
            </div>
          </NxInvTech>
        )}
      </div>
    </XdrShell>
  );
}
