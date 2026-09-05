/**
 * XdrFleetFileTrajectoryPage · P1.8
 * "Fleet File Trajectory — Evidence-First Cross-Endpoint File/Artifact
 * Investigation"
 *
 * SCOPE LOCK (owner directive, 2026-09-05):
 *   This page is Cisco Secure Endpoint File-Trajectory parity plus
 *   NivXRay evidence/provenance.  It is NOT Attack Traversal and NOT
 *   Attack Lifecycle — no cross-host causal graph, no lateral-movement
 *   reconstruction, no blast radius, no new correlation engine.  Those
 *   are a separate planned capability documented in
 *   docs/uiux/NIVXRAY_ATTACK_TRAVERSAL_AND_LIFECYCLE.md and they will be
 *   a PROJECTION over the existing IUE/ICE/IKG/VEEE/Security-State
 *   chain, never a second reasoning engine.
 *
 * Forensic terminology rules applied here:
 *   • No "patient zero".  The earliest record is labelled
 *     `? EARLIEST OBSERVED HOST` with the reason stated.
 *   • Observed window ≠ true attack window; the true start/end are
 *     `? UNKNOWN` because telemetry may begin after compromise.
 *   • The same name on N hosts is a COHORT, never a lateral-movement
 *     edge.  Nothing is joined.
 *   • Every view states what is NOT known.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Loader2, FileSearch, ChevronLeft, RefreshCcw, Radar, Fingerprint,
  Layers, Network, Terminal, FileStack, ScrollText, Clock, GitBranch,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { getFileTrajectory, getFleetSpreadIndex } from "@/nivxforge/edrApi";
import { fmtUtc, TELEMETRY_CYAN } from "@/xdr/lib/trajectoryModel";

const PAGE_SIZES = [10, 25, 50];
const TRUTH_BANNER = "NivXForge EDR — LIVE against persisted v2_shadow_observations "
  + "substrate; production endpoint-agent telemetry NOT YET IMPLEMENTED.";

const TABS = [
  { key: "overview",  label: "Overview",       icon: Layers },
  { key: "fleet",     label: "Fleet Activity", icon: Radar },
  { key: "timeline",  label: "Timeline",       icon: Clock },
  { key: "processes", label: "Processes",       icon: Terminal },
  { key: "network",   label: "Network",         icon: Network },
  { key: "artifacts", label: "Artifacts",       icon: FileStack },
  { key: "evidence",  label: "Evidence",        icon: ScrollText },
];

function Metric({ k, v, hint, testid, tone }) {
  return (
    <div className="panel" style={{ padding: 10 }} data-testid={testid}>
      <div style={{ color: "var(--faint)", fontSize: 9, fontWeight: 800,
                    textTransform: "uppercase", letterSpacing: ".4px" }}>{k}</div>
      <div className="mono" style={{ fontSize: 16, marginTop: 4,
                                     color: tone || "var(--text)",
                                     wordBreak: "break-all" }}>{v}</div>
      {hint && (
        <div className="mono" style={{ fontSize: 9, color: "var(--faint)",
                                       marginTop: 3, lineHeight: 1.5 }}>{hint}</div>
      )}
    </div>
  );
}
const Nope = ({ label, ep = "no_evidence", title }) => (
  <span className="nx-ep" data-ep={ep} data-known="true" title={title}>{label}</span>
);
const Panel = ({ title, children, testid, note }) => (
  <section className="panel" style={{ padding: 11 }} data-testid={testid}>
    <div className="section-title" style={{ marginBottom: 7 }}>{title}</div>
    {note && (
      <div className="mono" style={{ fontSize: 9.5, color: "var(--faint)",
                                     lineHeight: 1.6, marginBottom: 7 }}>{note}</div>
    )}
    {children}
  </section>
);

export default function XdrFleetFileTrajectoryPage() {
  const { key: rawKey } = useParams();
  const navigate = useNavigate();
  const decoded = decodeURIComponent(rawKey || "");
  const [keyType, keyValue] = useMemo(() => {
    const i = decoded.indexOf(":");
    if (i > 0 && ["sha256", "name", "path"].includes(decoded.slice(0, i))) {
      return [decoded.slice(0, i), decoded.slice(i + 1)];
    }
    return [/^[a-f0-9]{64}$/i.test(decoded) ? "sha256" : "name", decoded];
  }, [decoded]);

  const [tab, setTab] = useState("overview");
  const [data, setData] = useState(null);
  const [index, setIndex] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState("");
  const [pageSize, setPageSize] = useState(10);
  const [page, setPage] = useState(0);

  const load = useCallback(async () => {
    setLoading(true); setError(null); setPage(0);
    try {
      setData(await getFileTrajectory(keyValue, keyType));
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Lookup failed.");
      setData(null);
    } finally { setLoading(false); }
  }, [keyValue, keyType]);
  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    let cancel = false;
    (async () => {
      try { const r = await getFleetSpreadIndex(); if (!cancel) setIndex(r); }
      catch { /* index is contextual only */ }
    })();
    return () => { cancel = true; };
  }, []);

  const rows = data?.endpoint_rows || [];
  const events = data?.events || [];
  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((r) => (
      (r.hostname || "").toLowerCase().includes(q)
      || (r.device_iid || "").toLowerCase().includes(q)
      || (r.case_refs || []).some((c) => c.toLowerCase().includes(q))
    ));
  }, [rows, filter]);
  const pageRows = filtered.slice(page * pageSize, page * pageSize + pageSize);
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));

  const digests = data?.content_digests || [];
  const ds = data?.digest_state || {};

  /** Per-actor-process rollup — a count, not a lineage claim. */
  const processRows = useMemo(() => {
    const m = new Map();
    for (const e of events) {
      const k = e.process || "◇ no actor recorded";
      const r = m.get(k) || { process: k, images: [], devices: new Set(),
                              events: 0, kinds: {}, users: new Set(),
                              parents: new Set(), mitre: new Set() };
      r.events += 1;
      if (e.process_image && !r.images.includes(e.process_image)) r.images.push(e.process_image);
      if (e.device_iid) r.devices.add(e.hostname || e.device_iid);
      if (e.user) r.users.add(e.user);
      if (e.parent_name) r.parents.add(e.parent_name);
      for (const t of e.mitre || []) r.mitre.add(t);
      r.kinds[e.kind] = (r.kinds[e.kind] || 0) + 1;
      m.set(k, r);
    }
    return Array.from(m.values()).sort((a, b) => b.events - a.events);
  }, [events]);

  const networkEvents = useMemo(
    () => events.filter((e) => String(e.kind || "").startsWith("network")), [events]);
  const artifactRows = useMemo(() => {
    const m = new Map();
    for (const e of events) {
      const targets = [...(e.file_paths || [])];
      if (e.target) targets.push(e.target);
      for (const t of targets) {
        const r = m.get(t) || { target: t, events: 0, devices: new Set(), kinds: {} };
        r.events += 1;
        if (e.device_iid) r.devices.add(e.hostname || e.device_iid);
        r.kinds[e.kind] = (r.kinds[e.kind] || 0) + 1;
        m.set(t, r);
      }
    }
    return Array.from(m.values()).sort((a, b) => b.events - a.events);
  }, [events]);

  const cohortNote = (data?.affected_endpoints || 0) > 1 && keyType !== "sha256";

  return (
    <XdrShell>
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                    flexWrap: "wrap", marginBottom: 4 }}>
        <button className="btn ghost" style={{ padding: "4px 8px" }}
                onClick={() => navigate(-1)} data-testid="fleet-back">
          <ChevronLeft size={12} /> Back
        </button>
        <span className="mono" style={{ display: "flex", gap: 6, alignItems: "center",
                                        fontSize: 9.8, color: "var(--faint)" }}
              data-testid="fleet-breadcrumb">
          <Link to="/xdr" style={{ color: "var(--faint)" }}>Investigator</Link>
          <span>›</span>
          <Link to="/xdr/endpoints" style={{ color: "var(--faint)" }}>Endpoints</Link>
          <span>›</span>
          <span style={{ color: "var(--cyan)" }}>Fleet File Trajectory</span>
        </span>
        <h1 className="page-h1" style={{ margin: 0 }} data-testid="fleet-heading">
          <FileSearch size={14} style={{ color: "var(--mint)",
                                         verticalAlign: "middle", marginRight: 8 }} />
          Fleet File Trajectory
        </h1>
        <span className="mono" style={{ fontSize: 11, color: "var(--cyan)",
                                        wordBreak: "break-all" }}
              data-testid="fleet-key">
          {keyType}: {keyValue}
        </span>
        <div style={{ flex: 1 }} />
        <div style={{ position: "relative" }}>
          <button className="btn" disabled aria-disabled="true"
                  style={{ padding: "4px 10px", fontSize: 10.5, opacity: 0.6,
                           cursor: "not-allowed" }}
                  title={"⊘ ATTACK TRAVERSAL / LIFECYCLE NOT IMPLEMENTED — "
                    + "planned as P2.x Unified Artifact Trajectory & Attack Traversal "
                    + "Projection over IUE/ICE/IKG/VEEE/Security State. Requires the "
                    + "Sensor Foundation (PID/PPID, file digests, sockets, sessions)."}
                  data-testid="fleet-attack-traversal-pivot">
            <GitBranch size={11} /> ⊘ Investigate Attack Traversal
          </button>
        </div>
        <button className="btn" style={{ padding: "4px 10px" }} onClick={load}
                data-testid="fleet-refresh">
          <RefreshCcw size={11} /> Refresh
        </button>
      </div>
      <div className="page-sub" data-testid="fleet-truth-banner">
        Evidence-first cross-endpoint file / artifact investigation · {TRUTH_BANNER}
      </div>

      {loading && (
        <div className="x-empty" data-testid="fleet-loading">
          <Loader2 size={13} className="spin"
                   style={{ verticalAlign: "middle", marginRight: 6 }} />
          Correlating across the fleet …
        </div>
      )}
      {!loading && error && (
        <div className="x-empty" style={{ color: "#ff9494" }}
             data-testid="fleet-error">{String(error)}</div>
      )}

      {!loading && !error && data && (
        <>
          <section className="panel" style={{ padding: 10, marginBottom: 10 }}
                   data-testid="fleet-correlation-contract">
            <div style={{ display: "flex", gap: 10, alignItems: "center",
                          flexWrap: "wrap" }}>
              <span className="nx-ep"
                    data-ep={keyType === "sha256" && ds.content_digests_available
                              ? "evidence_present" : "unknown"}
                    data-known="true">
                {keyType === "sha256"
                  ? (ds.content_digests_available
                      ? "◆ CONTENT-DIGEST KEYED"
                      : "? CONTENT DIGESTS UNAVAILABLE IN SUBSTRATE")
                  : "? PATH/NAME KEYED — CONTENT-BLIND"}
              </span>
              <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)",
                                              lineHeight: 1.7, flex: 1 }}>
                {data.correlation_caveat}
                <br />
                {ds.note} {ds.integrity_note}
              </span>
            </div>
            <div className="mono" style={{ fontSize: 9, color: "var(--faint)",
                                           marginTop: 6 }}>
              matched on:{" "}
              {Object.keys(data.matched_on || {}).length
                ? Object.entries(data.matched_on)
                    .map(([f, n]) => `${f} ×${n}`).join(" · ")
                : "—"}
              {" · "}{data.tenant_boundary}
            </div>
          </section>

          {data.unique_events === 0 ? (
            <div className="x-empty" data-testid="fleet-empty">
              <b>◇ NO OBSERVATIONS FOUND FOR THIS KEY IN THE PERSISTED SUBSTRATE</b>
              <div style={{ marginTop: 4, lineHeight: 1.7 }}>
                Nothing in <span className="mono">v2_shadow_observations</span> matches{" "}
                <span className="mono">{keyType}: {keyValue}</span>. No endpoint is
                synthesised to fill this table.
                {keyType === "sha256" && (
                  <div style={{ marginTop: 6 }}>
                    <span className="mono" style={{ fontSize: 10 }}>
                      This substrate populates no file content digests
                      ({ds.file_artefacts_with_sha256} of 53 file artefacts carry a
                      SHA-256), so a hash-keyed fleet lookup can only ever answer
                      zero here. Use a name-keyed lookup from the Fleet Activity tab.
                    </span>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <>
              <div style={{ display: "flex", gap: 4, marginBottom: 10,
                            flexWrap: "wrap" }}
                   data-testid="fleet-tabs">
                {TABS.map((t) => {
                  const Icon = t.icon;
                  return (
                    <button key={t.key}
                            className={`btn ${tab === t.key ? "primary" : ""}`}
                            style={{ padding: "5px 10px", fontSize: 11 }}
                            onClick={() => setTab(t.key)}
                            data-testid={`fleet-tab-${t.key}`}>
                      <Icon size={11} /> {t.label}
                    </button>
                  );
                })}
              </div>

              {/* ══ OVERVIEW ══════════════════════════════════════ */}
              {tab === "overview" && (
                <div data-testid="fleet-overview">
                  <div style={{ display: "grid",
                                gridTemplateColumns: "repeat(auto-fit,minmax(178px,1fr))",
                                gap: 8, marginBottom: 10 }}
                       data-testid="fleet-metrics">
                    <Metric k="Affected endpoints" v={data.affected_endpoints}
                            hint="distinct authoritative device_iid"
                            tone={TELEMETRY_CYAN} testid="fleet-metric-endpoints" />
                    <Metric k="Unique evidence events" v={data.unique_events}
                            hint="authoritative · event.iid deduplicated"
                            testid="fleet-metric-unique" />
                    <Metric k="Raw observations" v={data.raw_observations}
                            hint="all provenance copies · NOT unique activity"
                            testid="fleet-metric-raw" />
                    <Metric k="Lateral hops"
                            v={<Nope label="◇ NOT ESTABLISHED" />}
                            hint="cross-host causality is out of scope for this view"
                            testid="fleet-metric-hops" />
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr",
                                gap: 8, marginBottom: 10 }}>
                    <Panel title="Observed window" testid="fleet-window"
                           note="Telemetry may begin after compromise, so the observed
                                 window is not the attack window.">
                      <div className="mono" style={{ fontSize: 11 }}>
                        {fmtUtc(new Date(data.first_observed).getTime())} →{" "}
                        {fmtUtc(new Date(data.last_observed).getTime())}
                      </div>
                      <div style={{ marginTop: 8, display: "flex", gap: 8,
                                    flexWrap: "wrap" }}>
                        <Nope label="? TRUE ATTACK START UNKNOWN" ep="unknown" />
                        <Nope label="? TRUE ATTACK END UNKNOWN" ep="unknown" />
                      </div>
                    </Panel>

                    <Panel title="Earliest observed host" testid="fleet-entry-point"
                           note="This is the earliest record in the current evidence
                                 window. It does NOT establish an initial-access host
                                 or a patient zero.">
                      {(data.entry_points || []).length === 0 ? (
                        <Nope label="◇ NOT DETERMINABLE" />
                      ) : (
                        <>
                          <Nope ep="unknown"
                                label={data.entry_points.length > 1
                                  ? `? ${data.entry_points.length} HOSTS TIE ON THE EARLIEST TIMESTAMP — NO SINGLE ORIGIN IS CLAIMED`
                                  : "? EARLIEST OBSERVED HOST — ORIGIN NOT ESTABLISHED"} />
                          <div style={{ marginTop: 6 }}>
                            {data.entry_points.map((p) => (
                              <div key={`${p.device_iid}-${p.first_seen}`}
                                   className="mono" style={{ fontSize: 10.5,
                                                             marginBottom: 4 }}>
                                {p.hostname || "◇ no hostname"}{" "}
                                <span style={{ color: "var(--faint)" }}>
                                  ({p.device_iid || "◇ unbound"})
                                </span>
                                <div style={{ color: "var(--faint)", fontSize: 9.5 }}>
                                  {p.first_seen}
                                </div>
                              </div>
                            ))}
                          </div>
                        </>
                      )}
                    </Panel>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr",
                                gap: 8, marginBottom: 10 }}>
                    <Panel title="Artifact identity" testid="fleet-identity">
                      <div style={{ marginBottom: 6 }}>
                        <div style={{ color: "var(--faint)", fontSize: 9, fontWeight: 800 }}>
                          OBSERVED NAMES
                        </div>
                        <div className="mono" style={{ fontSize: 10.5, marginTop: 2 }}>
                          {(data.observed_names || []).join(", ") || <Nope label="◇ NONE" />}
                        </div>
                      </div>
                      <div style={{ marginBottom: 6 }}>
                        <div style={{ color: "var(--faint)", fontSize: 9, fontWeight: 800 }}>
                          OBSERVED PATHS
                        </div>
                        <div className="mono" style={{ fontSize: 10, marginTop: 2,
                                                       wordBreak: "break-all" }}>
                          {(data.observed_paths || []).slice(0, 6).join(" · ")
                            || <Nope label="◇ NO FILE PATH OBSERVED" />}
                        </div>
                      </div>
                      <div>
                        <div style={{ color: "var(--faint)", fontSize: 9, fontWeight: 800 }}>
                          SHA-256 / SHA-1 / MD5
                        </div>
                        <div className="mono" style={{ fontSize: 10, marginTop: 2 }}>
                          {digests.length
                            ? digests.map((d) => <div key={d}>{d}</div>)
                            : <Nope label="◇ NOT OBSERVED · artefacts.file[].sha256 EMPTY" />}
                          <div style={{ marginTop: 4 }}>
                            <Nope label="◇ SHA-1 NOT OBSERVED" />{" "}
                            <Nope label="◇ MD5 NOT OBSERVED" />
                          </div>
                        </div>
                      </div>
                    </Panel>

                    <Panel title="Created by" testid="fleet-creators"
                           note="Only a create/write observation with a recorded actor
                                 counts as a creator.">
                      {(data.creators || []).length === 0 ? (
                        <Nope label="◇ PARENT CREATOR NOT OBSERVED" />
                      ) : (
                        data.creators.map((c, i) => (
                          <div key={i} className="mono" style={{ fontSize: 10.5,
                                                                 marginBottom: 5 }}>
                            {c.process}
                            <div style={{ color: "var(--faint)", fontSize: 9.5,
                                          wordBreak: "break-all" }}>
                              {c.image || "◇ no image path"}
                            </div>
                            <div style={{ color: "var(--faint)", fontSize: 9.5 }}>
                              {c.observed_on} on {c.hostname || c.device_iid} ·{" "}
                              {c.timestamp}
                            </div>
                          </div>
                        ))
                      )}
                    </Panel>
                  </div>

                  <Panel title="What this view does NOT establish"
                         testid="fleet-unknowns">
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                      <Nope ep="unknown" label="? OBJECTIVE NOT ESTABLISHED"
                            title="No objective is asserted from a family name or a technique tag." />
                      <Nope ep="unknown" label="? INITIAL ACCESS NOT ESTABLISHED" />
                      <Nope label="◇ CROSS-HOST CAUSALITY NOT ESTABLISHED" />
                      <Nope label="◇ LATERAL MOVEMENT NOT ESTABLISHED" />
                      <Nope label="◇ PROCESS LINEAGE UNRESOLVABLE (NO PID/PPID)" />
                      <Nope label="◇ FILE CONTENT IDENTITY UNVERIFIED" />
                      <Nope label="◇ DISPOSITION NOT CARRIED BY THE SUBSTRATE" />
                      <Nope ep="capability_unavailable"
                            label="⊘ ATTACK TRAVERSAL / LIFECYCLE NOT IMPLEMENTED" />
                    </div>
                    <div style={{ marginTop: 9, padding: 9, background: "#0D1218",
                                  border: "1px dashed #212B36", borderRadius: 4 }}
                         data-testid="fleet-traversal-contract">
                      <div className="mono" style={{ fontSize: 9.5,
                                                      color: "var(--faint)",
                                                      fontWeight: 800,
                                                      marginBottom: 5 }}>
                        NAVIGATION CONTRACT · ⊘ Investigate Attack Traversal
                      </div>
                      <div className="mono" style={{ fontSize: 9.5,
                                                     color: "#5D6875",
                                                     lineHeight: 1.8 }}>
                        {["Trace to Origin", "Trace Forward", "Host Traversal",
                          "Process Chain", "Network Traversal", "Identity",
                          "ATT&CK progression", "Attack Lifecycle",
                          "Blast Radius"].map((s) => (
                          <div key={s}>⊘ {s}</div>
                        ))}
                      </div>
                    </div>
                    <div className="mono" style={{ fontSize: 9.5, color: "var(--faint)",
                                                   marginTop: 8, lineHeight: 1.7 }}>
                      Cross-host causal reconstruction (attack traversal, lateral
                      movement, defense evasion, blast radius, attack lifecycle) is a
                      SEPARATE planned capability. It will be a projection over the
                      existing IUE / ICE / IKG / VEEE / Security-State chain — not a
                      second correlation engine — and it requires the Sensor
                      Foundation (PID/PPID, file digests, sockets, sessions) first.
                    </div>
                  </Panel>
                </div>
              )}

              {/* ══ FLEET ACTIVITY ════════════════════════════════ */}
              {tab === "fleet" && (
                <div data-testid="fleet-activity">
                  {cohortNote && (
                    <div className="panel" style={{ padding: 10, marginBottom: 10 }}
                         data-testid="fleet-cohort-notice">
                      <Nope label="◇ COHORT ONLY — LATERAL RELATIONSHIP NOT ESTABLISHED" />
                      <div className="mono" style={{ fontSize: 9.8, color: "var(--faint)",
                                                     marginTop: 6, lineHeight: 1.7 }}>
                        The same name / path is observed on {data.affected_endpoints}{" "}
                        endpoints. That is a cohort, not a transfer: no network
                        connection, artifact transfer, shared session or temporal
                        relationship between these hosts has been established here, so
                        no edge is drawn between them.
                      </div>
                    </div>
                  )}

                  <section className="panel" style={{ padding: 0, marginBottom: 10 }}
                           data-testid="fleet-endpoint-ledger">
                    <div style={{ display: "flex", alignItems: "center", gap: 10,
                                  padding: "7px 10px", borderBottom: "1px solid #212B36",
                                  background: "#11161D", flexWrap: "wrap" }}>
                      <span className="section-title" style={{ margin: 0 }}>
                        Computers with matching activity
                      </span>
                      <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)" }}>
                        {filtered.length} of {rows.length} rows
                      </span>
                      <div style={{ flex: 1 }} />
                      <input value={filter}
                             onChange={(e) => { setFilter(e.target.value); setPage(0); }}
                             placeholder="Filter hostname / device_iid / case…"
                             className="mono"
                             style={{ background: "#0B0F14", border: "1px solid #212B36",
                                      color: "var(--text)", fontSize: 10,
                                      padding: "3px 7px", borderRadius: 3, width: 240 }}
                             data-testid="fleet-ledger-filter" />
                      <select value={pageSize}
                              onChange={(e) => { setPageSize(Number(e.target.value)); setPage(0); }}
                              className="mono"
                              style={{ background: "#0B0F14", border: "1px solid #212B36",
                                       color: "var(--text)", fontSize: 10, padding: "3px 5px" }}
                              data-testid="fleet-ledger-pagesize">
                        {PAGE_SIZES.map((n) => <option key={n} value={n}>{n} / page</option>)}
                      </select>
                    </div>

                    <div style={{ overflowX: "auto" }}>
                      <table className="x-table" data-testid="fleet-ledger-table">
                        <thead>
                          <tr>
                            <th>Endpoint</th>
                            <th>Unique events</th>
                            <th>Raw obs.</th>
                            <th>OS / Platform</th>
                            <th>First seen on device</th>
                            <th>Last seen on device</th>
                            <th style={{ width: 260 }}>Provenance</th>
                            <th style={{ width: 170 }}>Response</th>
                            <th style={{ width: 130, textAlign: "right" }}>Pivot</th>
                          </tr>
                        </thead>
                        <tbody>
                          {pageRows.map((r) => (
                            <tr key={r.device_iid || "unbound"}
                                data-testid={`fleet-ledger-row-${r.device_iid || "unbound"}`}>
                              <td className="mono" style={{ fontSize: 10.5 }}>
                                {r.hostname ? (
                                  <>
                                    {r.hostname}{" "}
                                    <span className="nx-ep" data-ep="unknown" data-known="false">
                                      INFERRED
                                    </span>
                                  </>
                                ) : <Nope label="◇ NO HOSTNAME" />}
                                <div style={{ color: "var(--faint)", fontSize: 9.5 }}>
                                  {r.device_iid || (
                                    <Nope label="◇ UNBOUND — NO DEVICE IDENTITY ON THESE RECORDS" />
                                  )}
                                </div>
                              </td>
                              <td className="mono" style={{ color: "var(--text)" }}>
                                {r.unique_events}
                              </td>
                              <td className="mono" style={{ color: "var(--faint)" }}
                                  title="all provenance copies · not unique activity">
                                {r.raw_observations}
                              </td>
                              <td><Nope label="◇ NOT REPORTED" /></td>
                              <td className="mono" style={{ fontSize: 10 }}>{r.first_seen}</td>
                              <td className="mono" style={{ fontSize: 10 }}>{r.last_seen}</td>
                              <td className="mono" style={{ fontSize: 9.5, maxWidth: 260 }}>
                                {(r.case_refs || []).slice(0, 2).map((c) => (
                                  <div key={c} style={{ marginBottom: 3,
                                                        whiteSpace: "normal",
                                                        wordBreak: "break-all" }}>
                                    {c}
                                    <Nope label="◇ CASE RECORD NOT PERSISTED" />
                                  </div>
                                ))}
                                {(r.case_refs || []).length > 2 && (
                                  <div style={{ color: "var(--faint)" }}>
                                    +{r.case_refs.length - 2} more
                                  </div>
                                )}
                                {(r.providers || []).length > 0 && (
                                  <div style={{ color: "var(--faint)" }}>
                                    via {r.providers.join(", ")}
                                  </div>
                                )}
                              </td>
                              <td>
                                <Nope ep="capability_unavailable"
                                      label="⊘ NO RESPONSE DRIVER"
                                      title="No isolation, quarantine or termination path exists on this platform." />
                              </td>
                              <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                                {r.device_ref ? (
                                  <Link className="btn primary"
                                        style={{ padding: "3px 8px", fontSize: 10 }}
                                        to={`/xdr/endpoints/${encodeURIComponent(r.device_ref)}/trajectory?focus=${encodeURIComponent(keyValue)}`}
                                        data-testid={`fleet-pivot-${r.device_iid || "unbound"}`}>
                                    <Radar size={11} /> Trajectory →
                                  </Link>
                                ) : <Nope label="◇ NO DEVICE TO PIVOT TO" />}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {pages > 1 && (
                      <div style={{ display: "flex", gap: 6, alignItems: "center",
                                    padding: "6px 10px", borderTop: "1px solid #212B36" }}>
                        <button className="btn" style={{ padding: "2px 7px", fontSize: 10 }}
                                disabled={page === 0}
                                onClick={() => setPage((p) => Math.max(0, p - 1))}
                                data-testid="fleet-page-prev">Prev</button>
                        <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
                          page {page + 1} / {pages}
                        </span>
                        <button className="btn" style={{ padding: "2px 7px", fontSize: 10 }}
                                disabled={page + 1 >= pages}
                                onClick={() => setPage((p) => Math.min(pages - 1, p + 1))}
                                data-testid="fleet-page-next">Next</button>
                      </div>
                    )}
                  </section>

                  {index && (
                    <section className="panel" style={{ padding: 0 }}
                             data-testid="fleet-spread-index">
                      <div style={{ padding: "7px 10px", borderBottom: "1px solid #212B36",
                                    background: "#11161D" }}>
                        <Fingerprint size={11} style={{ color: "var(--mint)",
                                                        verticalAlign: "middle",
                                                        marginRight: 6 }} />
                        <span className="section-title" style={{ margin: 0 }}>
                          Fleet spread index
                        </span>{" "}
                        <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)" }}>
                          {index.count} observable artifacts · {index.note}
                        </span>
                      </div>
                      <div style={{ maxHeight: 260, overflow: "auto" }}>
                        <table className="x-table" data-testid="fleet-spread-table">
                          <thead>
                            <tr>
                              <th>Artifact name</th>
                              <th>Endpoints</th>
                              <th>Unique events</th>
                              <th style={{ textAlign: "right" }}>Fleet lookup</th>
                            </tr>
                          </thead>
                          <tbody>
                            {index.rows.slice(0, 60).map((r) => (
                              <tr key={r.name}
                                  style={{ background: r.name.toLowerCase() === keyValue.toLowerCase()
                                            ? "rgba(0,210,211,0.08)" : undefined }}
                                  data-testid={`fleet-spread-row-${r.name}`}>
                                <td className="mono" style={{ fontSize: 10.5 }}>{r.name}</td>
                                <td className="mono"
                                    style={{ color: r.endpoints > 1 ? TELEMETRY_CYAN : "var(--faint)" }}>
                                  {r.endpoints}
                                </td>
                                <td className="mono">{r.unique_events}</td>
                                <td style={{ textAlign: "right" }}>
                                  <Link className="btn" style={{ padding: "2px 7px", fontSize: 9.5 }}
                                        to={`/xdr/intelligence/files/${encodeURIComponent(`name:${r.name}`)}`}
                                        data-testid={`fleet-spread-open-${r.name}`}>
                                    Open →
                                  </Link>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  )}
                </div>
              )}

              {/* ══ TIMELINE ══════════════════════════════════════ */}
              {tab === "timeline" && (
                <section className="panel" style={{ padding: 0 }}
                         data-testid="fleet-event-history">
                  <div style={{ padding: "7px 10px", borderBottom: "1px solid #212B36",
                                background: "#11161D" }}>
                    <span className="section-title" style={{ margin: 0 }}>
                      Fleet timeline
                    </span>{" "}
                    <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)" }}>
                      {events.length} unique evidence events, oldest first · ordering is
                      chronological only and implies no causality
                    </span>
                  </div>
                  <div style={{ maxHeight: 460, overflow: "auto" }}>
                    <table className="x-table" data-testid="fleet-event-table">
                      <thead>
                        <tr>
                          <th style={{ width: 190 }}>Timestamp (UTC)</th>
                          <th>Endpoint</th>
                          <th>Kind</th>
                          <th>Actor</th>
                          <th>Target</th>
                          <th>ATT&amp;CK</th>
                          <th>Disposition</th>
                        </tr>
                      </thead>
                      <tbody>
                        {events.map((e) => (
                          <tr key={e.event_iid}
                              data-testid={`fleet-event-row-${e.event_iid}`}>
                            <td className="mono" style={{ fontSize: 10 }}>{e.timestamp}</td>
                            <td className="mono" style={{ fontSize: 10 }}>
                              {e.device_iid ? (
                                <Link to={`/xdr/endpoints/${encodeURIComponent(e.device_iid)}/trajectory?focus=${encodeURIComponent(keyValue)}`}
                                      style={{ color: "var(--cyan)" }}>
                                  {e.hostname || e.device_iid}
                                </Link>
                              ) : <Nope label="◇ UNBOUND" />}
                            </td>
                            <td className="mono" style={{ fontSize: 10 }}>{e.kind}</td>
                            <td className="mono" style={{ fontSize: 10 }}>
                              {e.process || <Nope label="◇" />}
                            </td>
                            <td className="mono" style={{ fontSize: 10,
                                                          wordBreak: "break-all" }}>
                              {e.target || (e.file_paths || [])[0] || <Nope label="◇" />}
                            </td>
                            <td className="mono" style={{ fontSize: 9.5, color: "#F39C12" }}>
                              {(e.mitre || []).join(", ") || "◇"}
                            </td>
                            <td><Nope ep="unknown" label="? UNKNOWN" /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}

              {/* ══ PROCESSES ═════════════════════════════════════ */}
              {tab === "processes" && (
                <section className="panel" style={{ padding: 0 }}
                         data-testid="fleet-processes">
                  <div style={{ padding: "7px 10px", borderBottom: "1px solid #212B36",
                                background: "#11161D" }}>
                    <span className="section-title" style={{ margin: 0 }}>
                      Actor processes
                    </span>{" "}
                    <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)" }}>
                      {processRows.length} distinct actor names · counts only, no lineage
                      is inferred (PID/PPID are not captured)
                    </span>
                  </div>
                  <table className="x-table" data-testid="fleet-processes-table">
                    <thead>
                      <tr>
                        <th>Actor process</th>
                        <th>Endpoints</th>
                        <th>Unique events</th>
                        <th>Event kinds</th>
                        <th>Users observed</th>
                        <th>Declared parents</th>
                        <th>ATT&amp;CK</th>
                      </tr>
                    </thead>
                    <tbody>
                      {processRows.map((r) => (
                        <tr key={r.process} data-testid={`fleet-process-row-${r.process}`}>
                          <td className="mono" style={{ fontSize: 10.5 }}>
                            {r.process}
                            {r.images.length > 0 && (
                              <div style={{ color: "var(--faint)", fontSize: 9,
                                            wordBreak: "break-all" }}>
                                {r.images[0]}
                              </div>
                            )}
                          </td>
                          <td className="mono">{r.devices.size || "◇"}</td>
                          <td className="mono">{r.events}</td>
                          <td className="mono" style={{ fontSize: 9.5 }}>
                            {Object.entries(r.kinds).map(([k, n]) => `${k} ×${n}`).join(" · ")}
                          </td>
                          <td className="mono" style={{ fontSize: 9.5 }}>
                            {r.users.size ? Array.from(r.users).join(", ")
                                          : <Nope label="◇ NOT CAPTURED" />}
                          </td>
                          <td className="mono" style={{ fontSize: 9.5 }}>
                            {r.parents.size ? (
                              <>
                                {Array.from(r.parents).join(", ")}{" "}
                                <Nope ep="unknown" label="? PARENT NOT OBSERVED" />
                              </>
                            ) : <Nope label="◇ NONE DECLARED" />}
                          </td>
                          <td className="mono" style={{ fontSize: 9.5, color: "#F39C12" }}>
                            {r.mitre.size ? Array.from(r.mitre).join(", ") : "◇"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </section>
              )}

              {/* ══ NETWORK ═══════════════════════════════════════ */}
              {tab === "network" && (
                <section className="panel" style={{ padding: 0 }}
                         data-testid="fleet-network">
                  <div style={{ padding: "7px 10px", borderBottom: "1px solid #212B36",
                                background: "#11161D" }}>
                    <span className="section-title" style={{ margin: 0 }}>
                      Network activity
                    </span>{" "}
                    <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)" }}>
                      {networkEvents.length} observed network events · no PCAP, no flow
                      records, no host-to-host traversal is inferred
                    </span>
                  </div>
                  {networkEvents.length === 0 ? (
                    <div className="x-empty" data-testid="fleet-network-empty">
                      <b>◇ NO NETWORK OBSERVATIONS FOR THIS ARTIFACT</b>
                    </div>
                  ) : (
                    <table className="x-table" data-testid="fleet-network-table">
                      <thead>
                        <tr>
                          <th style={{ width: 190 }}>Timestamp (UTC)</th>
                          <th>Endpoint</th>
                          <th>Actor</th>
                          <th>Remote endpoint</th>
                          <th>Kind</th>
                          <th>Port / protocol</th>
                          <th>ATT&amp;CK</th>
                        </tr>
                      </thead>
                      <tbody>
                        {networkEvents.map((e) => (
                          <tr key={e.event_iid}
                              data-testid={`fleet-network-row-${e.event_iid}`}>
                            <td className="mono" style={{ fontSize: 10 }}>{e.timestamp}</td>
                            <td className="mono" style={{ fontSize: 10 }}>
                              {e.hostname || e.device_iid || <Nope label="◇ UNBOUND" />}
                            </td>
                            <td className="mono" style={{ fontSize: 10 }}>
                              {e.process || <Nope label="◇" />}
                            </td>
                            <td className="mono" style={{ fontSize: 10,
                                                          color: TELEMETRY_CYAN,
                                                          wordBreak: "break-all" }}>
                              {e.target || <Nope label="◇ NOT RECORDED" />}
                            </td>
                            <td className="mono" style={{ fontSize: 10 }}>{e.kind}</td>
                            <td><Nope label="◇ NOT CAPTURED" /></td>
                            <td className="mono" style={{ fontSize: 9.5, color: "#F39C12" }}>
                              {(e.mitre || []).join(", ") || "◇"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </section>
              )}

              {/* ══ ARTIFACTS ═════════════════════════════════════ */}
              {tab === "artifacts" && (
                <section className="panel" style={{ padding: 0 }}
                         data-testid="fleet-artifacts">
                  <div style={{ padding: "7px 10px", borderBottom: "1px solid #212B36",
                                background: "#11161D" }}>
                    <span className="section-title" style={{ margin: 0 }}>
                      Touched artifacts
                    </span>{" "}
                    <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)" }}>
                      {artifactRows.length} distinct recorded targets · file paths,
                      registry keys and remote endpoints as written on the observations
                    </span>
                  </div>
                  {artifactRows.length === 0 ? (
                    <div className="x-empty" data-testid="fleet-artifacts-empty">
                      <b>◇ NO TARGET OBJECTS RECORDED FOR THIS ARTIFACT</b>
                    </div>
                  ) : (
                    <table className="x-table" data-testid="fleet-artifacts-table">
                      <thead>
                        <tr>
                          <th>Target object</th>
                          <th>Endpoints</th>
                          <th>Unique events</th>
                          <th>Event kinds</th>
                          <th>Content digest</th>
                        </tr>
                      </thead>
                      <tbody>
                        {artifactRows.map((r) => (
                          <tr key={r.target}
                              data-testid={`fleet-artifact-row-${r.target}`}>
                            <td className="mono" style={{ fontSize: 10,
                                                          wordBreak: "break-all" }}>
                              {r.target}
                            </td>
                            <td className="mono">{r.devices.size || "◇"}</td>
                            <td className="mono">{r.events}</td>
                            <td className="mono" style={{ fontSize: 9.5 }}>
                              {Object.entries(r.kinds).map(([k, n]) => `${k} ×${n}`).join(" · ")}
                            </td>
                            <td><Nope label="◇ NOT OBSERVED" /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </section>
              )}

              {/* ══ EVIDENCE ══════════════════════════════════════ */}
              {tab === "evidence" && (
                <div data-testid="fleet-evidence">
                  <Panel title="Match basis" testid="fleet-evidence-basis"
                         note="Exactly which persisted fields produced this result set.">
                    <div className="mono" style={{ fontSize: 10.5, lineHeight: 1.8 }}>
                      {Object.entries(data.matched_on || {}).map(([f, n]) => (
                        <div key={f}>
                          <span className="nx-ep" data-ep="evidence_present" data-known="true">
                            ◆ {f}
                          </span>{" "}
                          matched {n} raw observation{n === 1 ? "" : "s"}
                        </div>
                      ))}
                      <div style={{ marginTop: 6 }}>
                        <Nope label="◇ CONTENT DIGEST NOT USED — artefacts.file[].sha256 EMPTY" />
                      </div>
                      <div style={{ marginTop: 4 }}>
                        <Nope ep="unknown"
                              label="? TEMPORAL RELATIONSHIP NOT USED AS A JOIN" />{" "}
                        <Nope ep="unknown" label="? SHARED IDENTITY NOT USED AS A JOIN" />
                      </div>
                    </div>
                  </Panel>

                  <section className="panel" style={{ padding: 0, marginTop: 10 }}
                           data-testid="fleet-evidence-ledger">
                    <div style={{ padding: "7px 10px", borderBottom: "1px solid #212B36",
                                  background: "#11161D" }}>
                      <span className="section-title" style={{ margin: 0 }}>
                        Evidence ledger
                      </span>{" "}
                      <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)" }}>
                        every unique evidence event with its provenance
                      </span>
                    </div>
                    <div style={{ maxHeight: 420, overflow: "auto" }}>
                      <table className="x-table" data-testid="fleet-evidence-table">
                        <thead>
                          <tr>
                            <th>event_iid</th>
                            <th>Endpoint</th>
                            <th>Matched on</th>
                            <th>Raw copies</th>
                            <th style={{ width: 300 }}>Case references</th>
                            <th>Record digest</th>
                          </tr>
                        </thead>
                        <tbody>
                          {events.map((e) => (
                            <tr key={e.event_iid}
                                data-testid={`fleet-evidence-row-${e.event_iid}`}>
                              <td className="mono" style={{ fontSize: 10 }}>
                                {e.event_iid}
                              </td>
                              <td className="mono" style={{ fontSize: 10 }}>
                                {e.hostname || e.device_iid || <Nope label="◇ UNBOUND" />}
                              </td>
                              <td className="mono" style={{ fontSize: 9.5,
                                                            color: "var(--mint)" }}>
                                {e.matched_on}
                              </td>
                              <td className="mono">{e.occurrences}</td>
                              <td className="mono" style={{ fontSize: 9.5,
                                                            maxWidth: 300,
                                                            whiteSpace: "normal",
                                                            wordBreak: "break-all" }}>
                                {(e.case_refs || []).slice(0, 2).join(", ")}
                                {(e.case_refs || []).length > 2
                                  && ` +${e.case_refs.length - 2} more`}
                                <Nope label="◇ CASE RECORDS NOT PERSISTED" />
                              </td>
                              <td className="mono" style={{ fontSize: 9,
                                                            color: "var(--faint)",
                                                            wordBreak: "break-all" }}
                                  title="Digest of the ingested observation record — not a file hash.">
                                {e.input_digest || "◇"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </section>
                </div>
              )}
            </>
          )}
        </>
      )}
    </XdrShell>
  );
}
