/**
 * GATE 11 · Events — the estate-wide endpoint event explorer.
 *
 * Every filter, the sort and the pagination are executed by the server;
 * the console holds one page at a time and a keyset cursor. Coverage is
 * REPORTED from what the estate actually delivered (the activity facet),
 * so an activity class with no events is shown as not observed rather
 * than silently missing.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Bookmark, ChevronDown, Link2, RefreshCw, Search, Trash2, X }
  from "lucide-react";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { createSavedView, deleteSavedView, getEvent, getEventFacets,
         getSavedView, listEvents, listSavedViews }
  from "@/nivxforge/managementApi";
import { Ago, Kpi, NA, OpsTable, Refusal, Skeleton, StateChip }
  from "@/nivxforge/components/OpsPrimitives";
import { apiErrorText } from "@/xdr/nx/apiError";
import "@/nivxforge/nvf-ops.css";

const WINDOWS = [{ h: 1, l: "1h" }, { h: 24, l: "24h" },
                 { h: 168, l: "7d" }, { h: 720, l: "30d" }];

const DETECTIONS = [
  { v: "", l: "Any detection outcome" },
  { v: "matched", l: "Matched" },
  { v: "evaluated_no_match", l: "Evaluated · no match" },
  { v: "not_evaluated", l: "Not evaluated" },
  { v: "not_recorded", l: "Not recorded" },
];

function EventPane({ rawId, onClose }) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    let live = true;
    setData(null); setErr(null);
    getEvent(rawId)
      .then((d) => { if (live) setData(d); })
      .catch((e) => { if (live) setErr(apiErrorText(e, "event unavailable")); });
    return () => { live = false; };
  }, [rawId]);

  const ev = data?.event;
  return (
    <aside className="ctx-pane" data-testid="edr-event-pane">
      <div className="ph">
        <div>
          <div className="h" data-testid="edr-event-pane-id">{rawId}</div>
          {ev ? (
            <div style={{ marginTop: 6 }}>
              <StateChip token={ev.detection?.outcome}
                         testid="edr-event-pane-detection" />
            </div>
          ) : null}
        </div>
        <button className="btn" onClick={onClose}
                data-testid="edr-event-pane-close"><X size={11} /></button>
      </div>
      {err ? <Refusal title="Event unavailable" body={err}
                      testid="edr-event-pane-error" /> : null}
      {!data && !err ? <Skeleton rows={6} testid="edr-event-pane-loading" />
        : null}
      {ev ? (
        <>
          <div className="ctx-sec">
            <div className="section-title">Attribution</div>
            <div className="kv">
              <span className="k">Computer</span>
              <span className="v">{ev.hostname || <NA label="NOT RESOLVED" />}</span>
              <span className="k">Endpoint</span>
              <span className="v mono">{ev.endpoint_ref || <NA />}</span>
              <span className="k">Activity</span>
              <span className="v">{ev.activity
                ? <StateChip token={ev.activity} /> : <NA label="NOT STAMPED" />}</span>
              <span className="k">Operation</span>
              <span className="v">{ev.operation || <NA />}</span>
              <span className="k">Trust</span>
              <span className="v"><StateChip token={ev.trust_state} /></span>
              <span className="k">Connector</span>
              <span className="v mono">{ev.sensor_version || <NA />}</span>
              <span className="k">Observed</span>
              <span className="v">{ev.event_time
                ? <Ago iso={ev.event_time} /> : <NA label="NOT REPORTED" />}</span>
              <span className="k">Ingested</span>
              <span className="v"><Ago iso={ev.ingest_time} /></span>
              <span className="k">Payload sha256</span>
              <span className="v mono" style={{ wordBreak: "break-all" }}>
                {ev.payload_sha256}
              </span>
            </div>
          </div>

          <div className="ctx-sec">
            <div className="section-title">Detection</div>
            <div className="basis" data-testid="edr-event-detection-basis">
              {ev.detection?.reason || ev.detection?.basis}
            </div>
          </div>

          <div className="ctx-sec">
            <div className="section-title">Verbatim payload</div>
            <pre className="cmd" data-testid="edr-event-payload"
                 style={{ whiteSpace: "pre-wrap", maxHeight: 260,
                          overflow: "auto" }}>{ev.payload}</pre>
            <div className="basis">{data.immutability}</div>
          </div>

          <div className="ctx-sec">
            <div className="section-title">
              Derivations ({(ev.derivations || []).length})
            </div>
            {(ev.derivations || []).length
              ? (ev.derivations || []).map((d, i) => (
                  <div className="ci-row" key={i}
                       data-testid={`edr-event-derivation-${i}`}>
                    <StateChip token={d.outcome || d.parser_state} />
                    <span className="basis">{d.reason
                      || `${d.parser_name || "parser"} ${d.parser_version || ""}`}</span>
                  </div>))
              : <NA label="NO DERIVATION RECORDED" />}
          </div>
        </>
      ) : null}
    </aside>
  );
}

/**
 * A saved view stores the QUERY, never the results: opening one re-queries
 * the evidence the operator is currently authorised for. The URL carries
 * only a view id — no filters, no tokens, no evidence — and the tenant
 * predicate is applied server-side when it is resolved.
 */
function SavedViews({ views, activeId, onOpen, onSave, onDelete, onClear }) {
  const [name, setName] = useState("");
  const [shared, setShared] = useState(false);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const active = views.find((v) => v.view_id === activeId);

  return (
    <div className="ops-toolbar" data-testid="edr-events-saved-views">
      <Bookmark size={11} />
      <select value={activeId || ""} data-testid="edr-saved-view-select"
              onChange={(e) => (e.target.value
                ? onOpen(e.target.value) : onClear())}>
        <option value="">No saved view — ad hoc query</option>
        {views.map((v) => (
          <option key={v.view_id} value={v.view_id}>
            {v.name}{v.shared ? " · shared" : ""}
            {v.is_owner ? "" : ` (${v.owner})`}
          </option>))}
      </select>
      {active ? (
        <>
          <button className="btn" data-testid="edr-saved-view-share"
                  onClick={() => {
                    const url = window.location.origin + active.deep_link;
                    navigator.clipboard?.writeText(url);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}>
            <Link2 size={11} /> {copied ? "Link copied" : "Copy link"}
          </button>
          {active.is_owner ? (
            <button className="btn" data-testid="edr-saved-view-delete"
                    onClick={() => onDelete(active.view_id)}>
              <Trash2 size={11} /> Delete
            </button>
          ) : null}
        </>
      ) : null}
      <div className="spacer" />
      <input value={name} placeholder="Save these filters as…"
             onChange={(e) => setName(e.target.value)}
             data-testid="edr-saved-view-name" />
      <label className="basis" style={{ display: "flex", alignItems: "center",
                                        gap: 5 }}>
        <input type="checkbox" checked={shared} style={{ minWidth: 0 }}
               onChange={(e) => setShared(e.target.checked)}
               data-testid="edr-saved-view-shared" />
        shareable
      </label>
      <button className="btn mint" disabled={busy || name.trim().length < 2}
              data-testid="edr-saved-view-save"
              onClick={async () => {
                setBusy(true);
                try { await onSave(name.trim(), shared); setName(""); }
                finally { setBusy(false); }
              }}>
        {busy ? "Saving…" : "Save view"}
      </button>
    </div>
  );
}

export default function EdrEventsPage() {
  const [search, setSearch] = useSearchParams();
  const [views, setViews] = useState([]);
  const [activeView, setActiveView] = useState(search.get("view") || null);
  const [hours, setHours] = useState(24);
  const [activity, setActivity] = useState("");
  const [detection, setDetection] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  const [sort, setSort] = useState("desc");

  const [facets, setFacets] = useState(null);
  const [pages, setPages] = useState([]);
  const [cursor, setCursor] = useState(null);
  const [meta, setMeta] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);
  const [selected, setSelected] = useState(null);

  const params = useMemo(() => {
    const p = { hours, limit: 50, sort };
    if (activity) p.activity = activity;
    if (detection) p.detection = detection;
    if (endpoint) p.endpoint_id = endpoint;
    if (term && term.length >= 2) p.q = term;
    return p;
  }, [hours, activity, detection, endpoint, term, sort]);

  const load = useCallback((append = false, cur = null) => {
    setLoading(true); setErr(null);
    listEvents(cur ? { ...params, cursor: cur } : params)
      .then((d) => {
        setMeta(d);
        setCursor(d.next_cursor);
        setPages((prev) => (append ? [...prev, ...d.events] : d.events));
      })
      .catch((e) => setErr(apiErrorText(e, "events unavailable")))
      .finally(() => setLoading(false));
  }, [params]);

  useEffect(() => { load(false, null); }, [load]);

  const loadViews = useCallback(() => {
    listSavedViews("events").then((d) => setViews(d.views || []))
      .catch(() => setViews([]));
  }, []);
  useEffect(loadViews, [loadViews]);

  // Resolving a deep link is a SERVER call: the tenant predicate is
  // applied there, which is why a shared URL cannot reach another
  // customer's evidence.
  const openView = useCallback((viewId) => {
    getSavedView(viewId)
      .then((v) => {
        const f = v.filters || {};
        setActivity(f.activity || "");
        setDetection(f.detection || "");
        setEndpoint(f.endpoint_id || "");
        setQ(f.q || "");
        setTerm(f.q || "");
        setSort(v.sort || "desc");
        if (v.time?.mode === "RELATIVE" && v.time?.hours) {
          setHours(v.time.hours);
        }
        setActiveView(viewId);
        setErr(null);
        const next = new URLSearchParams(search);
        next.set("view", viewId);
        setSearch(next, { replace: true });
      })
      .catch((e) => {
        setActiveView(null);
        setErr(apiErrorText(e, "saved view unavailable"));
      });
  }, [search, setSearch]);

  useEffect(() => {
    const fromUrl = search.get("view");
    if (fromUrl && fromUrl !== activeView) openView(fromUrl);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search.get("view")]);

  const saveView = async (name, shared) => {
    try {
      const filters = {};
      if (activity) filters.activity = activity;
      if (detection) filters.detection = detection;
      if (endpoint) filters.endpoint_id = endpoint;
      if (term) filters.q = term;
      const v = await createSavedView({
        name, surface: "events", filters, sort, columns: [],
        time: { mode: "RELATIVE", hours }, shared });
      loadViews();
      setActiveView(v.view_id);
      const next = new URLSearchParams(search);
      next.set("view", v.view_id);
      setSearch(next, { replace: true });
    } catch (e) {
      setErr(apiErrorText(e, "view refused"));
    }
  };

  const removeView = async (viewId) => {
    try { await deleteSavedView(viewId); } catch (e) {
      setErr(apiErrorText(e, "delete refused")); return;
    }
    loadViews();
    clearView();
  };

  const clearView = () => {
    setActiveView(null);
    const next = new URLSearchParams(search);
    next.delete("view");
    setSearch(next, { replace: true });
  };

  useEffect(() => {
    let live = true;
    getEventFacets(hours)
      .then((d) => { if (live) setFacets(d); })
      .catch(() => { if (live) setFacets(null); });
    return () => { live = false; };
  }, [hours]);

  const columns = useMemo(() => [
    { key: "ingest_time", label: "Ingested", width: 92,
      render: (r) => <Ago iso={r.ingest_time} /> },
    { key: "hostname", label: "Computer", width: 180,
      render: (r) => (
        <span title={r.endpoint_ref}>
          {r.hostname || <NA label="NOT RESOLVED" />}
        </span>) },
    { key: "activity", label: "Activity", width: 96,
      render: (r) => (r.activity
        ? <StateChip token={r.activity} />
        : <NA label="NOT STAMPED" />) },
    { key: "operation", label: "Operation", width: 140,
      render: (r) => <span className="mono">{r.operation || <NA />}</span> },
    { key: "detection", label: "Detection", width: 150,
      sortValue: (r) => r.detection?.outcome,
      render: (r) => (
        <StateChip token={String(r.detection?.outcome || "")
          .replace("DETECTION_", "")}
                   title={r.detection?.reason || r.detection?.basis} />) },
    { key: "payload_preview", label: "Evidence", cls: "mono",
      render: (r) => (
        <span title={r.payload_preview}>
          {r.payload_preview.slice(0, 110)}
          {r.payload_truncated ? "…" : ""}
        </span>) },
  ], []);

  const notObserved = facets?.activity_not_observed || [];

  return (
    <NivXForgeConsole activeTab="events">
      <div className="ops-head">
        <div>
          <span className="eyebrow">Operations</span>
          <h1 className="ttl">Events</h1>
          <div className="sub">
            Estate-wide endpoint events, authenticated and attributed at
            ingest. Filtering, sorting and pagination are executed
            <strong> server-side</strong> over the immutable event store.
          </div>
        </div>
        <div className="spacer" />
        <div className="ops-actions">
          <button className="btn" onClick={() => load(false, null)}
                  data-testid="edr-events-refresh">
            <RefreshCw size={11} /> Refresh
          </button>
          <button className="btn"
                  onClick={() => setSort((s) => (s === "desc" ? "asc" : "desc"))}
                  data-testid="edr-events-sort-toggle">
            {sort === "desc" ? "Newest first" : "Oldest first"}
          </button>
        </div>
      </div>

      {facets ? (
        <div className="kpi-rail" data-testid="edr-events-kpis">
          <Kpi label={`Events · ${WINDOWS.find((w) => w.h === hours)?.l}`}
               value={facets.total_events} testid="edr-kpi-events" />
          <Kpi label="Matched detections"
               value={facets.detection?.DETECTION_MATCHED ?? 0}
               tone={facets.detection?.DETECTION_MATCHED ? "red" : undefined}
               testid="edr-kpi-matched" />
          <Kpi label="Reporting computers" value={facets.endpoints?.length ?? 0}
               testid="edr-kpi-reporting" />
          <Kpi label="Activity classes observed"
               value={Object.keys(facets.activity || {}).length}
               title={`Not observed: ${notObserved.join(", ") || "none"}`}
               testid="edr-kpi-activity-classes" />
        </div>
      ) : null}

      <SavedViews views={views} activeId={activeView} onOpen={openView}
                  onSave={saveView} onDelete={removeView}
                  onClear={clearView} />

      <div className="ops-toolbar" data-testid="edr-events-toolbar">
        <div className="seg">
          {WINDOWS.map((w) => (
            <button key={w.h} data-on={hours === w.h}
                    onClick={() => setHours(w.h)}
                    data-testid={`edr-events-window-${w.h}`}>{w.l}</button>
          ))}
        </div>
        <select value={activity} onChange={(e) => setActivity(e.target.value)}
                data-testid="edr-events-activity-filter">
          <option value="">All activity</option>
          {(facets?.activity_classes_known || []).map((a) => (
            <option key={a} value={a} disabled={!(facets?.activity || {})[a]}>
              {a}{(facets?.activity || {})[a]
                ? ` (${facets.activity[a]})` : " · NOT OBSERVED"}
            </option>))}
        </select>
        <select value={detection} onChange={(e) => setDetection(e.target.value)}
                data-testid="edr-events-detection-filter">
          {DETECTIONS.map((d) => (
            <option key={d.v} value={d.v}>{d.l}</option>))}
        </select>
        <select value={endpoint} onChange={(e) => setEndpoint(e.target.value)}
                data-testid="edr-events-endpoint-filter">
          <option value="">All computers</option>
          {(facets?.endpoints || []).map((e) => (
            <option key={e.endpoint_ref} value={e.endpoint_ref}>
              {e.hostname || e.endpoint_ref} ({e.count})
            </option>))}
        </select>
        <div className="ops-search">
          <Search size={11} />
          <input value={q} placeholder="Search the verbatim payload…"
                 onChange={(e) => setQ(e.target.value)}
                 onKeyDown={(e) => { if (e.key === "Enter") setTerm(q); }}
                 data-testid="edr-events-search" />
          <button className="btn" onClick={() => setTerm(q)}
                  data-testid="edr-events-search-apply">Apply</button>
        </div>
        <div className="spacer" />
        <span className="ops-count" data-testid="edr-events-count">
          {pages.length} loaded
        </span>
      </div>

      {err ? <Refusal title="Events unavailable" body={err}
                      testid="edr-events-refusal" /> : null}

          {!facets?.total_events && !pages.length ? (
            <div className="basis" data-testid="edr-events-empty-tenant"
                 style={{ marginBottom: 8 }}>
              THIS CUSTOMER DELIVERED NO EVENTS IN THIS WINDOW.
              {" "}{facets?.endpoints?.length
                ? "Computers are enrolled but none reported inside this window."
                : "No computer has reported into this customer at all."}
              {" "}Check the CUSTOMER selector in the header if you expected an
              existing estate: evidence recorded for one customer is never
              readable from another.
            </div>
          ) : null}
          {notObserved.length && facets?.total_events ? (
        <div className="basis" data-testid="edr-events-coverage"
             style={{ marginBottom: 8 }}>
          Collection coverage — NOT OBSERVED in this window:
          {" "}{notObserved.join(", ")}. {meta?.coverage}
        </div>
      ) : null}

      <div className={selected ? "ops-split" : undefined}>
        <div>
          {loading && !pages.length
            ? <Skeleton rows={8} testid="edr-events-loading" />
            : (
              <>
                <OpsTable columns={columns} rows={pages}
                          rowKey={(r) => r.raw_id}
                          selectedKey={selected}
                          onSelect={(r) => setSelected(r.raw_id)}
                          testid="edr-events-table" />
                {!pages.length && !loading ? (
                  <div className="basis" data-testid="edr-events-empty">
                    NO EVENTS matched these filters in this window. This is an
                    empty result for the filters you set — it is not a
                    statement that the estate observed nothing.
                  </div>
                ) : null}
                {cursor ? (
                  <button className="btn mint" style={{ marginTop: 10 }}
                          disabled={loading}
                          onClick={() => load(true, cursor)}
                          data-testid="edr-events-load-more">
                    <ChevronDown size={11} />
                    {loading ? "Loading…" : "Load more"}
                  </button>
                ) : null}
              </>
            )}
        </div>
        {selected ? (
          <EventPane rawId={selected} onClose={() => setSelected(null)} />
        ) : null}
      </div>
    </NivXForgeConsole>
  );
}
