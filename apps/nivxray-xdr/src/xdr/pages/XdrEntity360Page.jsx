/**
 * XdrEntity360Page · P1.4 · `/xdr/endpoints/:device`
 *
 * The endpoint entity workspace: a master-detail split with the
 * authoritative identity projection on the left and the investigation
 * surfaces (Overview · Device Trajectory · Endpoint Lanes · Process
 * Ancestry) on the right.
 *
 * ALL temporal state lives here and is shared by the navigator, the
 * lifeline canvas, the compromise band, the events ledger and the lane
 * grids — one window, four synchronised surfaces.
 *
 * Honest State: every identity field is either copied from
 * `v2_shadow_observations` or rendered as an explicit epistemic token.
 * No response action is wired, because no response driver is
 * registered — the controls state that instead of pretending.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  Loader2, HardDrive, ChevronLeft, RefreshCcw, Layers, GitBranch, FileText,
  Wifi, Terminal, Radar,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { useAuth } from "@/lib/auth";
import EndpointLanes from "@/xdr/components/EndpointLanes";
import ProcessAncestryTree from "@/xdr/components/ProcessAncestryTree";
import TrajectoryWorkspace from "@/xdr/components/TrajectoryWorkspace";
import ArtifactContextMenu from "@/xdr/components/ArtifactContextMenu";
import ExportMenu from "@/xdr/components/ExportMenu";
import EndpointActionsMenu from "@/xdr/components/EndpointActionsMenu";
import EndpointDetailsDrawer from "@/xdr/components/EndpointDetailsDrawer";
import StaticAnalysisBridge from "@/xdr/components/StaticAnalysisBridge";
import { compileQuery, searchCorpus } from "@/xdr/components/TrajectoryNavigator";
import TrajectoryFiltersModal, { applyFilters }
  from "@/xdr/components/TrajectoryFiltersModal";
import { getDeviceTrajectory } from "@/nivxforge/edrApi";
import {
  dedupeObservations, compromiseSpans, caseReferences, tsOf, fmtUtc,
  severityTier, TIER_MALICIOUS, GLYPHS,
} from "@/xdr/lib/trajectoryModel";

const WINDOWS = [
  { key: 1, label: "1h" }, { key: 6, label: "6h" }, { key: 24, label: "24h" },
  { key: 168, label: "7d" }, { key: 720, label: "30d" }, { key: 0, label: "All" },
];

const TABS = [
  { key: "overview",   label: "Overview",         icon: Layers },
  { key: "trajectory", label: "Device Trajectory", icon: Radar },
  { key: "lanes",      label: "Endpoint Lanes",    icon: FileText },
  { key: "ancestry",   label: "Process Ancestry",  icon: GitBranch },
];

const RESPONSE_ACTIONS = [
  "Isolate Host", "Quarantine File", "Terminate Process",
  "Take Forensic Snapshot", "Live Query", "Full Scan", "Move to Group",
];

function Field({ k, v }) {
  return (
    <div style={{ marginBottom: 7 }}>
      <div style={{ color: "var(--faint)", fontSize: 9, fontWeight: 800,
                    textTransform: "uppercase", letterSpacing: ".4px" }}>{k}</div>
      <div className="mono" style={{ color: "var(--text-dim)", fontSize: 10.5,
                                     marginTop: 2, wordBreak: "break-all" }}>{v}</div>
    </div>
  );
}
const Nope = ({ label, ep = "no_evidence" }) => (
  <span className="nx-ep" data-ep={ep} data-known="true">{label}</span>
);

export default function XdrEntity360Page({ initialTab = "overview" }) {
  const { user } = useAuth();
  const { device } = useParams();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const deviceRef = decodeURIComponent(device || "");

  const [tab, setTab] = useState(params.get("tab") || initialTab);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [hours, setHours] = useState(0);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // ── shared interaction state ─────────────────────────────────────
  const [selectedId, setSelectedId] = useState(null);
  const [hoverId, setHoverId] = useState(null);
  const [selectedSpanId, setSelectedSpanId] = useState(null);
  const [query, setQuery] = useState("");
  const [selectedDay, setSelectedDay] = useState(null);
  const selectedDayRef = useRef(null);
  const [view, setView] = useState(null);
  const [ctxMenu, setCtxMenu] = useState(null);
  const [staticSubject, setStaticSubject] = useState(null);
  const [filters, setFilters] = useState(() => new Set());
  const [filtersOpen, setFiltersOpen] = useState(false);

  const toggleFilter = useCallback((id) => setFilters((prev) => {
    const next = new Set(prev);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  }), []);

  useEffect(() => { selectedDayRef.current = selectedDay; }, [selectedDay]);

  const load = useCallback(async () => {
    if (!deviceRef) return;
    setLoading(true); setError(null);
    try {
      setData(await getDeviceTrajectory(deviceRef, hours));
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load endpoint entity.");
      setData(null);
    } finally { setLoading(false); }
  }, [deviceRef, hours]);
  useEffect(() => { load(); }, [load]);

  const identity   = data?.identity || null;
  const unresolved = data && identity && identity.resolved === false;
  const incidents  = data?.incidents || [];
  const lanes      = data?.lanes || ["system", "process", "file", "network", "registry"];

  /** Deduped observation set — the same `event.iid` replayed under
   *  several case references is ONE observation, and the replay count
   *  is reported rather than hidden. */
  const events = useMemo(
    () => dedupeObservations(data?.events || []), [data]);
  const rawCount = (data?.events || []).length;

  const extent = useMemo(() => {
    const ts = events.map(tsOf).filter((n) => n !== null);
    if (ts.length) {
      // Auto-fit to the ACTIVITY window: 5% temporal padding, never less
      // than a minute, so a 20-second burst is never squashed into a
      // single vertical slice of an empty 24-hour void.
      const lo = Math.min(...ts), hi = Math.max(...ts);
      const pad = Math.max((hi - lo) * 0.05, 60000);
      return [lo - pad, hi + pad];
    }
    const ws = new Date(data?.window_start || Date.now()).getTime();
    const we = new Date(data?.window_end || Date.now()).getTime();
    return [ws, we];
  }, [events, data?.window_start, data?.window_end]);

  useEffect(() => { setView(extent); }, [extent[0], extent[1]]); // eslint-disable-line react-hooks/exhaustive-deps

  const viewStart = view ? view[0] : extent[0];
  const viewEnd   = view ? view[1] : extent[1];

  const onWindowChange = useCallback((s, e) => {
    let a = Math.min(s, e), b = Math.max(s, e);
    if (b - a < 1000) b = a + 1000;
    if (selectedDayRef.current != null) {
      const d0 = selectedDayRef.current;
      a = Math.max(a, d0);
      b = Math.min(b, d0 + 86400000);
    }
    setView([a, b]);
  }, []);

  const onCenter = useCallback((t) => {
    const span = Math.max(2000, viewEnd - viewStart);
    setView([t - span / 2, t + span / 2]);
  }, [viewStart, viewEnd]);

  const matchedIds = useMemo(() => {
    const c = compileQuery(query);
    if (!c || c.kind === "invalid") return new Set();
    const s = new Set();
    for (const e of events) if (c.test(searchCorpus(e))) s.add(e.id);
    return s;
  }, [query, events]);

  const eventsInView = useMemo(() => {
    const inWindow = events.filter((e) => {
      const t = tsOf(e);
      return t !== null && t >= viewStart && t <= viewEnd;
    });
    return applyFilters(inWindow, filters);
  }, [events, viewStart, viewEnd, filters]);

  const canvasEvents = useMemo(() => (
    query && matchedIds.size > 0
      ? eventsInView.filter((e) => matchedIds.has(e.id))
      : eventsInView
  ), [query, matchedIds, eventsInView]);

  const spans    = useMemo(() => compromiseSpans(eventsInView), [eventsInView]);
  const caseRows = useMemo(() => caseReferences(events), [events]);

  const haloIds = useMemo(() => {
    const s = new Set();
    if (!selectedSpanId) return s;
    const span = spans.find((x) => x.id === selectedSpanId);
    for (const e of span?.events || []) s.add(e.id);
    return s;
  }, [selectedSpanId, spans]);

  const selectedEvent = useMemo(
    () => events.find((e) => e.id === selectedId) || null, [events, selectedId]);
  const cursorTs = selectedEvent ? tsOf(selectedEvent) : null;

  const onSelect = useCallback((e) => setSelectedId(e ? e.id : null), []);
  const onContextMenu = useCallback((evt, at) => setCtxMenu({ evt, at }), []);

  /** Return pivot from Fleet File Trajectory: `?focus=<name|hash>` scopes
   *  the search and selects this device's earliest interaction. */
  const focusParam = params.get("focus");
  const focusApplied = useRef(false);
  useEffect(() => {
    if (!focusParam || focusApplied.current || events.length === 0) return;
    focusApplied.current = true;
    setQuery(focusParam);
    setTab("trajectory");
    const needle = focusParam.toLowerCase();
    const hit = events
      .filter((e) => searchCorpus(e).toLowerCase().includes(needle))
      .sort((a, b) => (tsOf(a) || 0) - (tsOf(b) || 0))[0];
    if (hit) setSelectedId(hit.id);
  }, [focusParam, events]);

  const laneCounts = useMemo(() => {
    const c = {};
    for (const e of eventsInView) c[e.lane] = (c[e.lane] || 0) + 1;
    return c;
  }, [eventsInView]);

  const observedUsers = useMemo(() => Array.from(
    new Set(events.map((e) => e.user).filter(Boolean))), [events]);
  const observedProviders = useMemo(() => Array.from(
    new Set(events.map((e) => e.provider).filter(Boolean))), [events]);
  const maliciousCount = useMemo(
    () => events.filter((e) => severityTier(e) === TIER_MALICIOUS).length, [events]);
  const attributedCount = useMemo(
    () => events.filter((e) => (e.mitre || []).length || (e.labels || []).length).length,
    [events]);

  const authoritative = identity?.identity_confidence === "authoritative";

  // ── Actions ▼ — state-aware, and honest about every state ────────
  // A capability with no registered driver is DISABLED with the reason
  // named. Nothing here simulates execution, and no destructive action
  // is offered while its authorization -> approval -> response-safety ->
  // execution -> verification chain has nothing behind it.
  const NO_RESPONSE_DRIVER =
    "⊘ RESPONSE DRIVER NOT REGISTERED — no isolation, quarantine, scan or "
    + "termination path exists on this platform. The control is disabled "
    + "rather than simulated.";
  const NO_SENSOR =
    "⊘ NO ENDPOINT SENSOR ENROLLED — requires the P1.12 Sensor Foundation. "
    + "Until a sensor reports, there is nothing to diagnose or snapshot.";
  const NO_POLICY_PLANE =
    "⊘ NO POLICY PLANE BOUND — groups and policies are not modelled on this "
    + "platform.";

  const incidentId = identity?.latest_incident_id || null;
  const actionGroups = useMemo(() => [
    { label: "Device actions", items: [
      { id: "scan", label: "Scan", state: "unavailable", reason: NO_RESPONSE_DRIVER },
      { id: "isolate", label: "Isolate endpoint", state: "unavailable",
        reason: `${NO_RESPONSE_DRIVER} Isolation state is UNKNOWN, so neither `
                + "Start nor Release isolation can be offered." },
      { id: "move-group", label: "Move / assign policy", state: "unavailable",
        reason: NO_POLICY_PLANE },
      { id: "diagnose-sensor", label: "Diagnose sensor", state: "unavailable",
        reason: NO_SENSOR },
      { id: "device-details", label: "View endpoint details",
        state: "available", run: () => setDetailsOpen(true) },
    ] },
    { label: "Investigate", items: [
      { id: "trajectory", label: "Device trajectory", state: "available",
        run: () => setTab("trajectory") },
      { id: "entity-360", label: "Entity 360 overview", state: "available",
        run: () => setTab("overview") },
      { id: "process-ancestry", label: "Process ancestry", state: "available",
        run: () => setTab("ancestry") },
      { id: "endpoint-lanes", label: "Endpoint lanes", state: "available",
        run: () => setTab("lanes") },
      { id: "forensic-snapshot", label: "Take forensic snapshot",
        state: "unavailable", reason: NO_SENSOR },
      { id: "live-query", label: "Live query", state: "unavailable",
        reason: "⊘ NO LIVE-QUERY DRIVER REGISTERED — there is no live channel "
                + "to this endpoint, so a query cannot be issued." },
    ] },
    { label: "Response", items: [
      { id: "response-actions", label: "Response actions", state: "unavailable",
        reason: NO_RESPONSE_DRIVER },
      { id: "quarantine-file", label: "Fetch / quarantine file",
        state: "unavailable", reason: NO_RESPONSE_DRIVER },
      { id: "terminate-process", label: "Terminate process",
        state: "unavailable", reason: NO_RESPONSE_DRIVER },
    ] },
    { label: "Pivots / links", items: [
      { id: "events", label: "Events ledger", state: "available",
        run: () => setTab("trajectory") },
      { id: "related-incidents",
        label: incidentId ? "Related incident" : "Related incidents",
        state: incidentId ? "available" : "no_evidence",
        reason: "◇ NO INCIDENT IS BOUND TO THIS ENDPOINT — no incident has "
                + "been promoted from its observations.",
        run: () => navigate(`/xdr/incidents/${incidentId}`) },
      { id: "fleet-file-trajectory", label: "Fleet file trajectory",
        state: "available", run: () => navigate("/xdr/intelligence/files") },
      { id: "spread-watchlist", label: "Spread watchlist",
        state: "available", run: () => navigate("/xdr/endpoints") },
      { id: "audit-log", label: "Device audit log", state: "no_evidence",
        reason: "◇ NO PER-DEVICE AUDIT TRAIL IS RECORDED — the platform audit "
                + "log is tenant-scoped, not device-scoped." },
    ] },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [incidentId, navigate]);

  return (
    <XdrShell>
      {/* ── Breadcrumb ──────────────────────────────────────────── */}
      <div className="mono" style={{ display: "flex", gap: 6, alignItems: "center",
                                     fontSize: 9.8, color: "var(--faint)",
                                     marginBottom: 6 }}
           data-testid="entity360-breadcrumb">
        <Link to="/xdr" style={{ color: "var(--faint)" }}>Investigator</Link>
        <span>›</span>
        <Link to="/xdr/endpoints" style={{ color: "var(--faint)" }}>Endpoints</Link>
        <span>›</span>
        <span style={{ color: "var(--text-dim)" }}>
          Host: {identity?.hostname || deviceRef}
        </span>
        <span>›</span>
        <span style={{ color: "var(--cyan)" }}>
          {TABS.find((t) => t.key === tab)?.label || "Overview"}
        </span>
      </div>

      {/* ── Header ──────────────────────────────────────────────── */}
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                    flexWrap: "wrap", marginBottom: 6 }}
           data-testid="xdr-trajectory-header">
        <button className="btn ghost" style={{ padding: "4px 8px" }}
                onClick={() => navigate("/xdr/endpoints")}
                data-testid="xdr-trajectory-back">
          <ChevronLeft size={12} /> Endpoints
        </button>
        <h1 className="page-h1" style={{ margin: 0 }}
            data-testid="xdr-trajectory-heading">
          <HardDrive size={14} style={{ color: "var(--mint)",
                                        verticalAlign: "middle", marginRight: 8 }} />
          {identity?.hostname || deviceRef}
        </h1>
        {identity?.resolved && (
          <span className="nx-ep"
                data-ep={authoritative ? "evidence_present" : "unknown"}
                data-known={authoritative ? "true" : "false"}
                title={authoritative
                  ? `Authoritative endpoint entity · device_iid=${identity.device_iid}`
                  : "Hostname string with no bound endpoint entity IID — identity is INFERRED"}
                data-testid="xdr-trajectory-identity-badge">
            {authoritative
              ? `◆ AUTHORITATIVE · ${identity.device_iid}`
              : "◇ INFERRED IDENTITY (NO IID)"}
          </span>
        )}
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <button className="btn ghost" style={{ padding: "4px 9px", fontSize: 10.5 }}
                  onClick={() => setDetailsOpen((o) => !o)}
                  aria-expanded={detailsOpen}
                  data-testid="endpoint-details-toggle">
            {detailsOpen ? "Hide details" : "Show details"}
          </button>
          <EndpointActionsMenu groups={actionGroups} />
        </div>
        <span className="mono" style={{ fontSize: 10,
                color: maliciousCount ? "#FF3838" : "var(--faint)" }}
              data-testid="entity360-compromise-count">
          {maliciousCount
            ? `${maliciousCount} compromise event${maliciousCount === 1 ? "" : "s"}`
            : "No compromise events observed"}
        </span>
        <div style={{ flex: 1 }} />
        <div style={{ display: "flex", gap: 4 }}
             data-testid="xdr-trajectory-window-controls">
          {WINDOWS.map((w) => (
            <button key={w.key}
                    className={`btn qf ${hours === w.key ? "primary" : ""}`}
                    onClick={() => setHours(w.key)}
                    data-testid={`xdr-trajectory-window-${w.key}`}>
              {w.label}
            </button>
          ))}
        </div>
        <ExportMenu
          testid="entity360-export"
          basename={`device-${identity?.hostname || deviceRef}`}
          build={() => ({
            surface: "device_trajectory",
            exportedBy: user?.email || null,
            scope: {
              device_ref: deviceRef,
              device_iid: identity?.device_iid || null,
              hostname: identity?.hostname || null,
              identity_confidence: identity?.identity_confidence || null,
              window_selector: hours === 0 ? "all_observed_time" : `last_${hours}h`,
              window_start_utc: new Date(viewStart).toISOString(),
              window_end_utc: new Date(viewEnd).toISOString(),
              active_filters: Array.from(filters),
              search_query: query || null,
              selected_compromise_window: selectedSpanId || null,
              active_tab: tab,
            },
            events: eventsInView,
            counts: {
              unique_events: events.length,
              raw_observations: rawCount,
              unique_events_in_window: eventsInView.length,
              search_matches: matchedIds.size,
              compromise_windows_in_scope: spans.length,
              case_references: caseRows.length,
            },
            notes: [
              "Rows are the observations inside the stated window after the stated filters and search.",
              `${rawCount} raw records collapse to ${events.length} distinct observations (same event.iid replayed across case references); mitre/labels are unioned across copies so no attribution is lost.`,
              "Ordering is chronological only and implies no causality.",
            ],
          })}
        />
        <button className="btn" style={{ padding: "4px 10px" }} onClick={load}
                data-testid="xdr-trajectory-refresh">
          <RefreshCcw size={11} /> Refresh
        </button>
      </div>
      <div className="page-sub" data-testid="xdr-trajectory-subtitle">
        Endpoint Entity 360 · projected from{" "}
        <span style={{ color: "var(--cyan)" }}>v2_shadow_observations</span> ·{" "}
        window <b>{hours === 0 ? "All observed time"
          : `Last ${WINDOWS.find((w) => w.key === hours)?.label || `${hours}h`}`}</b>
        {rawCount > events.length && (
          <> · <span className="mono">{rawCount} records collapse to {events.length}{" "}
            distinct observations (same <code>event.iid</code> replayed across case
            references)</span></>
        )}
      </div>

      {loading && (
        <div className="x-empty" data-testid="xdr-trajectory-loading">
          <Loader2 size={13} className="spin"
                   style={{ verticalAlign: "middle", marginRight: 6 }} />
          Loading endpoint entity …
        </div>
      )}
      {!loading && error && (
        <div className="x-empty" style={{ color: "#ff9494" }}
             data-testid="xdr-trajectory-error">{String(error)}</div>
      )}

      {!loading && !error && unresolved && (
        <section className="panel" style={{ padding: 16 }}
                 data-testid="xdr-trajectory-identity-unresolved">
          <div className="nx-ep" data-ep="capability_unavailable" data-known="true"
               style={{ marginBottom: 8 }}>
            ⊘ ENDPOINT IDENTITY UNRESOLVED
          </div>
          <div style={{ color: "var(--text-dim)", fontSize: 11.5, lineHeight: 1.7 }}>
            No authoritative endpoint entity or observed hostname matches{" "}
            <span className="mono" style={{ color: "var(--text)" }}>{deviceRef}</span>.
            The workspace is not rendered against a synthesised device.
            <div style={{ marginTop: 6 }}>
              <Link to="/xdr/endpoints" style={{ color: "var(--cyan)" }}
                    data-testid="xdr-trajectory-unresolved-inventory">
                Open Endpoint Inventory →
              </Link>
            </div>
          </div>
        </section>
      )}

      {/* ── Master-detail body ──────────────────────────────────── */}
      {!loading && !error && !unresolved && data && (
        <div style={{ display: "grid", gap: 12,
                      gridTemplateColumns: detailsOpen ? "1fr 318px" : "1fr" }}
             data-testid="entity360-split">
          {/* Right-side endpoint context drawer (order: 2) — kept open
              while the analyst works the trajectory. */}
          {detailsOpen ? (
            <div style={{ order: 2, minWidth: 0 }}>
              <EndpointDetailsDrawer
                hostname={identity?.hostname}
                deviceRef={deviceRef}
                identity={identity}
                authoritative={authoritative}
                observedUsers={observedUsers}
                observedProviders={observedProviders}
                onClose={() => setDetailsOpen(false)}
              />
            </div>
          ) : null}

          {/* Tabbed workspace (order: 1 — sits left of the drawer) */}
          <div style={{ minWidth: 0, order: 1 }}>
            <div style={{ display: "flex", gap: 4, marginBottom: 10 }}
                 data-testid="entity360-tabs">
              {TABS.map((t) => {
                const Icon = t.icon;
                return (
                  <button key={t.key}
                          className={`btn ${tab === t.key ? "primary" : ""}`}
                          style={{ padding: "5px 10px", fontSize: 11 }}
                          onClick={() => setTab(t.key)}
                          data-testid={`entity360-tab-${t.key}`}>
                    <Icon size={11} /> {t.label}
                  </button>
                );
              })}
            </div>

            {events.length === 0 && (
              <div className="x-empty" data-testid="xdr-trajectory-empty">
                <b>◇ NO EVIDENCE</b>
                <div style={{ marginTop: 4 }}>
                  {identity?.observation_count
                    ? `${identity.observation_count} observations exist for this device, but none fall inside the selected window. Switch the window to "All".`
                    : `No observations are persisted for ${identity?.hostname || deviceRef}.`}
                </div>
              </div>
            )}

            {events.length > 0 && tab === "overview" && (
              <section data-testid="entity360-overview">
                <div style={{ display: "grid",
                              gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))",
                              gap: 8, marginBottom: 10 }}>
                  {lanes.map((l) => (
                    <div key={l} className="panel" style={{ padding: 10 }}
                         data-testid={`entity360-lane-card-${l}`}>
                      <div style={{ color: "var(--faint)", fontSize: 9,
                                    fontWeight: 800, textTransform: "uppercase",
                                    letterSpacing: ".4px" }}>{l}</div>
                      <div className="mono" style={{ fontSize: 20, color: "var(--text)",
                                                     marginTop: 4 }}>
                        {laneCounts[l] || 0}
                      </div>
                      <div className="mono" style={{ fontSize: 9,
                                                     color: "var(--faint)" }}>
                        in selected window
                      </div>
                    </div>
                  ))}
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr",
                              gap: 10 }}>
                  <div className="panel" style={{ padding: 11 }}
                       data-testid="entity360-compromise-pane">
                    <div className="section-title" style={{ marginBottom: 7 }}>
                      Related Compromise Events
                    </div>
                    {maliciousCount === 0 ? (
                      <div style={{ fontSize: 11, color: "var(--text-dim)",
                                    lineHeight: 1.7 }}>
                        No related compromise events observed.
                        <div style={{ marginTop: 6 }}>
                          <span className="mono" style={{ fontSize: 9.8,
                                                          color: "#F39C12" }}>
                            {attributedCount} observation
                            {attributedCount === 1 ? "" : "s"} carry an ATT&amp;CK
                            technique or label asserted by the ingest adapter —
                            an attribution, not a conviction.
                          </span>
                        </div>
                      </div>
                    ) : (
                      <div className="mono" style={{ fontSize: 11, color: "#FF3838" }}>
                        {maliciousCount} compromise observation
                        {maliciousCount === 1 ? "" : "s"} in the observed span
                      </div>
                    )}
                  </div>

                  <div className="panel" style={{ padding: 11 }}
                       data-testid="entity360-provenance-pane">
                    <div className="section-title" style={{ marginBottom: 7 }}>
                      Provenance
                    </div>
                    <Field k="Substrate" v="v2_shadow_observations" />
                    <Field k="Distinct observations"
                           v={`${events.length} (from ${rawCount} case-scoped records)`} />
                    <Field k="Observed span"
                           v={`${fmtUtc(extent[0])} → ${fmtUtc(extent[1])}`} />
                    <Field k="Case references" v={caseRows.length} />
                  </div>
                </div>

                <div className="panel" style={{ padding: 11, marginTop: 10 }}
                     data-testid="entity360-glyph-legend">
                  <div className="section-title" style={{ marginBottom: 7 }}>
                    Canvas glyph legend
                  </div>
                  <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                    {Object.entries(GLYPHS).map(([k, g]) => (
                      <span key={k} className="mono"
                            style={{ fontSize: 10, color: "var(--text-dim)" }}>
                        <span style={{ color: g.color }}>{g.sym}</span> {g.tag} ·{" "}
                        {g.label}
                      </span>
                    ))}
                  </div>
                </div>
              </section>
            )}

            {events.length > 0 && tab === "trajectory" && (
              <TrajectoryWorkspace
                deviceRef={deviceRef}
                events={events}
                eventsInView={eventsInView}
                canvasEvents={canvasEvents}
                matchedIds={matchedIds}
                query={query}
                onQueryChange={setQuery}
                selectedDay={selectedDay}
                onSelectDay={(ms) => { setSelectedDay(ms); setView([ms, ms + 86400000]); }}
                viewStart={viewStart}
                viewEnd={viewEnd}
                onWindowChange={onWindowChange}
                onCenter={onCenter}
                selectedId={selectedId}
                selectedEvent={selectedEvent}
                onSelect={onSelect}
                hoverId={hoverId}
                onHover={setHoverId}
                spans={spans}
                caseRows={caseRows}
                incidents={incidents}
                selectedSpanId={selectedSpanId}
                onSelectSpan={setSelectedSpanId}
                haloIds={haloIds}
                onContextMenu={onContextMenu}
                onStaticAnalysis={(e) => setStaticSubject(e)}
                cursorTs={cursorTs}
                filterCount={filters.size}
                onOpenFilters={() => setFiltersOpen(true)}
              />
            )}

            {events.length > 0 && tab === "lanes" && (
              <div data-testid="entity360-lanes">
                <div className="mono" style={{ fontSize: 9.8, color: "var(--faint)",
                                               marginBottom: 6 }}>
                  synced to the shared window · {fmtUtc(viewStart)} → {fmtUtc(viewEnd)}
                </div>
                <EndpointLanes events={eventsInView}
                               onSelect={(e) => { setSelectedId(e.id); setTab("trajectory"); }} />
              </div>
            )}

            {events.length > 0 && tab === "ancestry" && (
              <div data-testid="entity360-ancestry">
                <div className="mono" style={{ fontSize: 9.8, color: "var(--faint)",
                                               marginBottom: 6 }}>
                  synced to the shared window · {fmtUtc(viewStart)} → {fmtUtc(viewEnd)}
                </div>
                <ProcessAncestryTree events={eventsInView} />
              </div>
            )}
          </div>
        </div>
      )}

      {ctxMenu && (
        <ArtifactContextMenu
          evt={ctxMenu.evt}
          at={ctxMenu.at}
          onClose={() => setCtxMenu(null)}
          onSearch={(q) => { setQuery(q); setTab("trajectory"); }}
          onSelect={onSelect}
          onStaticAnalysis={(e) => setStaticSubject(e)}
        />
      )}

      {filtersOpen && (
        <TrajectoryFiltersModal
          active={filters}
          onToggle={toggleFilter}
          onClear={() => setFilters(new Set())}
          onClose={() => setFiltersOpen(false)}
        />
      )}

      {staticSubject && (
        <StaticAnalysisBridge
          event={staticSubject}
          onClose={() => setStaticSubject(null)}
        />
      )}
    </XdrShell>
  );
}
