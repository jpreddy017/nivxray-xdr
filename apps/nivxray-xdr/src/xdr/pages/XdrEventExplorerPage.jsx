/**
 * Event Explorer · the estate-wide analyst event surface.
 *
 * Source-agnostic by construction: the table and the API speak canonical
 * vocabulary, so Windows, Sysmon, auditd, Zeek, M365, CloudTrail, firewall,
 * DNS, proxy, VPN, EDR, identity and application sources appear here under
 * the same contract as their DSMs land.
 *
 * The inspection pane preserves the transformation chain and keeps each
 * stage distinguishable:
 *   Raw Event → Parsed Fields → Normalized Event → Canonical Evidence
 *             → Detection → Incident
 * The rendered raw record is immutable source evidence.
 */
import React, { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import XdrShell from "@/xdr/XdrShell";
import { NxDataTable, NxFlyout, NxPageShell, NxTabs } from "@/xdr/nx";
import {
  Fact, Section, StateChip,
} from "@/xdr/datasources/windows/WindowsPrimitives";
import {
  getEventDetail, getEventFacets, measured, searchEvents,
} from "@/xdr/datasources/windows/windowsApi";
import "@/xdr/datasources/windows/windows.css";

const FILTERS = [
  { key: "q", label: "Search" },
  { key: "host", label: "Host" },
  { key: "channel", label: "Channel / source" },
  { key: "event_id", label: "Event ID" },
  { key: "user", label: "User" },
  { key: "process", label: "Process" },
];

const PANE_TABS = [
  { key: "summary", label: "Summary" },
  { key: "fields", label: "Fields" },
  { key: "raw", label: "Raw" },
  { key: "normalized", label: "Normalized" },
  { key: "canonical", label: "Canonical Evidence" },
  { key: "relationships", label: "Relationships" },
  { key: "detection", label: "Detection" },
  { key: "provenance", label: "Provenance" },
];

const KV = ({ data, testid }) => (
  <table className="wx-kv" data-testid={testid}>
    <tbody>
      {Object.entries(data || {}).map(([k, v]) => (
        <tr key={k}>
          <td>{k}</td>
          <td>{v === null || v === undefined || v === ""
            ? <span className="wx-dim">—</span>
            : (typeof v === "object" ? JSON.stringify(v) : String(v))}</td>
        </tr>))}
      {Object.keys(data || {}).length === 0 && (
        <tr><td colSpan={2} className="wx-dim">NOT AVAILABLE</td></tr>)}
    </tbody>
  </table>
);

function EventPane({ eventId, onClose, onPivot }) {
  const [tab, setTab] = useState("summary");
  const [state, setState] = useState({ loading: true, data: null, error: null });
  useEffect(() => {
    if (!eventId) return;
    setTab("summary");
    setState({ loading: true, data: null, error: null });
    getEventDetail(eventId)
      .then((d) => setState({ loading: false, data: d, error: null }))
      .catch((e) => setState({ loading: false, data: null, error: e.message }));
  }, [eventId]);

  if (!eventId) return null;
  const d = state.data;
  const sum = d?.summary;

  return (
    <NxFlyout open title={sum?.event_type || "Event"} eyebrow={eventId}
              onClose={onClose} width={780} testid="ev-pane">
      <div className="wx-pane">
        {state.loading && <p className="wx-dim">loading…</p>}
        {state.error && <p className="wx-attn">{state.error}</p>}
        {d && (
          <>
            <Section title="Transformation chain"
                     note="Each stage is a separate fact with its own evidence reference. A stage that did not happen says so."
                     testid="ev-chain">
              <table className="wx-kv">
                <tbody>
                  {d.chain.map((st) => (
                    <tr key={st.stage}>
                      <td>{st.stage}</td>
                      <td>
                        <StateChip value={st.state} />{" "}
                        {st.evidence_ref && <span className="wx-tag">{st.evidence_ref}</span>}
                        {st.reason && <div className="wx-dim">{st.reason}</div>}
                      </td>
                    </tr>))}
                </tbody>
              </table>
            </Section>

            <NxTabs tabs={PANE_TABS} active={tab} onChange={setTab}
                    testid="ev-pane-tabs" />

            {tab === "summary" && (
              <div className="wx-facts" data-testid="ev-pane-summary">
                <Fact label="Time" value={sum.time} reason={sum.time_basis} />
                <Fact label="Time source" value={sum.time_source} />
                <Fact label="Host" value={sum.host} />
                <Fact label="Channel / source" value={sum.channel || sum.source_product} />
                <Fact label="Provider" value={sum.provider} />
                <Fact label="Event ID" value={sum.source_event_id} />
                <Fact label="Activity" value={sum.event_type} />
                <Fact label="User" value={sum.user} />
                <Fact label="Process" value={sum.process} />
                <Fact label="Command line" value={sum.process_command_line} />
                <Fact label="Process attribution" value={sum.process_attribution} />
                <Fact label="Level" value={sum.level} />
                <Fact label="DSM" value={sum.dsm_id} />
                <Fact label="Detection" value={<StateChip value={sum.detection.state} />} />
              </div>
            )}
            {tab === "fields" && <KV data={d.fields} testid="ev-pane-fields" />}
            {tab === "raw" && (
              <div data-testid="ev-pane-raw">
                <p className="wx-section-note">{d.raw.immutability_note}</p>
                {d.raw.xml
                  ? <pre className="wx-xml">{d.raw.xml}</pre>
                  : <KV data={d.raw.document} />}
              </div>
            )}
            {tab === "normalized" && <KV data={d.normalized} testid="ev-pane-normalized" />}
            {tab === "canonical" && (
              <pre className="wx-xml" data-testid="ev-pane-canonical">
                {JSON.stringify(d.canonical, null, 2)}
              </pre>
            )}
            {tab === "relationships" && (
              <div data-testid="ev-pane-relationships">
                <div className="wx-facts">
                  <Fact label="Host" value={d.relationships.host} />
                  <Fact label="User" value={d.relationships.user} />
                  <Fact label="Process" value={d.relationships.process} />
                  <Fact label="Process GUID" value={d.relationships.process_guid} />
                </div>
                <div className="wx-tags">
                  {d.relationships.pivots.map((p) => (
                    <button type="button" key={`${p.kind}-${p.value}`}
                            className="wx-btn"
                            data-testid={`ev-pivot-${p.kind}`}
                            onClick={() => onPivot(p.query)}>
                      {p.kind}: {p.value}
                    </button>))}
                </div>
              </div>
            )}
            {tab === "detection" && (
              <div data-testid="ev-pane-detection">
                <StateChip value={d.detection.state} />
                {d.detection.matches.map((m) => (
                  <Section key={m.rule_id} title={m.rule_name || m.rule_id}>
                    <div className="wx-facts">
                      <Fact label="Rule" value={m.rule_id} />
                      <Fact label="Severity" value={m.severity} />
                      <Fact label="Declaration" value={m.declaration_state} />
                      <Fact label="Citation" value={m.citation_completeness} />
                      <Fact label="Evidence ref" value={m.evidence_ref} />
                    </div>
                  </Section>))}
                {d.detection.matches.length === 0 && (
                  <p className="wx-section-note">
                    this evidence was evaluated and no deployed rule matched.
                    That is an evaluation outcome, not a gap
                  </p>)}
              </div>
            )}
            {tab === "provenance" && (
              <pre className="wx-xml" data-testid="ev-pane-provenance">
                {JSON.stringify(d.provenance, null, 2)}
              </pre>
            )}
          </>
        )}
      </div>
    </NxFlyout>
  );
}

export default function XdrEventExplorerPage() {
  const [params, setParams] = useSearchParams();
  const [draft, setDraft] = useState(() =>
    Object.fromEntries(FILTERS.map((f) => [f.key, params.get(f.key) || ""])));
  const [state, setState] = useState({ loading: true, data: null, error: null });
  const [facets, setFacets] = useState(null);
  const [selected, setSelected] = useState(null);

  const run = useCallback((query) => {
    setState({ loading: true, data: null, error: null });
    const active = Object.fromEntries(
      Object.entries(query).filter(([, v]) => v !== "" && v != null));
    searchEvents({ ...active, limit: 200 })
      .then((d) => setState({ loading: false, data: d, error: null }))
      .catch((e) => setState({ loading: false, data: null, error: e.message }));
  }, []);

  useEffect(() => {
    const current = Object.fromEntries(
      FILTERS.map((f) => [f.key, params.get(f.key) || ""]));
    setDraft(current);
    run(current);
  }, [params, run]);

  useEffect(() => { getEventFacets().then(setFacets).catch(() => setFacets(null)); }, []);

  const apply = (next) => setParams(Object.fromEntries(
    Object.entries(next).filter(([, v]) => v !== "" && v != null)));

  const rows = state.data?.rows || [];
  const columns = [
    { key: "time", label: "Time", value: (r) => r.time,
      render: (r) => (
        <span className="wx-mono" title={`${r.time_basis || ""} · ${r.time_source || ""}`}>
          {r.time || "—"}
        </span>) },
    { key: "host", label: "Host", value: (r) => r.host || "",
      render: (r) => (r.host || <span className="wx-dim">—</span>) },
    { key: "channel", label: "Channel / source",
      value: (r) => r.channel || r.source_product || "",
      render: (r) => (
        <span title={r.source_vendor || ""}>
          {r.channel || r.source_product || <span className="wx-dim">—</span>}
        </span>) },
    { key: "provider", label: "Provider", value: (r) => r.provider || "",
      render: (r) => (r.provider || <span className="wx-dim">—</span>) },
    { key: "event_id", label: "Event ID / type",
      value: (r) => r.source_event_id || "",
      render: (r) => (
        <span>
          <span className="wx-mono">{r.source_event_id || "—"}</span>
          <div className="wx-dim">{r.event_type}</div>
        </span>) },
    { key: "user", label: "User", value: (r) => r.user || "",
      render: (r) => (r.user || <span className="wx-dim">—</span>) },
    { key: "process", label: "Process", value: (r) => r.process || "",
      render: (r) => (
        <span title={r.process_command_line || ""}>
          {r.process || <span className="wx-dim">—</span>}
        </span>) },
    { key: "activity", label: "Activity", value: (r) => r.event_type },
    { key: "level", label: "Level", value: (r) => r.level || "",
      render: (r) => measured(r.level) },
    { key: "detection", label: "Detection",
      value: (r) => r.detection.count,
      render: (r) => (
        <span title={(r.detection.rules || []).join(", ")}>
          <StateChip value={r.detection.state} />
          {r.detection.count > 0 && <strong> {r.detection.count}</strong>}
        </span>) },
    { key: "evidence", label: "Evidence", value: (r) => r.evidence_ref,
      render: (r) => <span className="wx-tag">{r.dsm_id || "—"}</span> },
  ];

  return (
    <XdrShell>
      <NxPageShell eyebrow="Investigate" title="Event Explorer"
                   description="Estate-wide canonical events, from every source with a DSM"
                   testid="ev-page">
        <div className="wx-filters" data-testid="ev-filters">
          {FILTERS.map((f) => (
            <label className="wx-filter" key={f.key}>
              <span>{f.label}</span>
              <input value={draft[f.key] || ""}
                     data-testid={`ev-filter-${f.key}`}
                     placeholder={f.key === "q" ? "host, user, process, script text" : ""}
                     onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })}
                     onKeyDown={(e) => { if (e.key === "Enter") apply(draft); }} />
            </label>))}
          <button type="button" className="wx-btn" data-testid="ev-apply"
                  onClick={() => apply(draft)}>Search</button>
          <button type="button" className="wx-btn" data-testid="ev-clear"
                  onClick={() => apply({})}>Clear</button>
        </div>

        {facets && (
          <p className="wx-section-note" data-testid="ev-facets">
            {facets.channels.length} channel(s) · {facets.hosts.length} host(s) ·{" "}
            {facets.dsm_ids.length} DSM(s) have produced canonical evidence in this tenant
          </p>
        )}

        <NxDataTable columns={columns} rows={rows} loading={state.loading}
                     error={state.error} onRefresh={() => run(draft)}
                     pageSize={50} rowKey={(r) => r.event_id}
                     searchPlaceholder="Filter loaded rows"
                     onRowClick={(r) => setSelected(r.event_id)}
                     emptyTitle="No canonical event matches this query"
                     emptyHint="This table reads canonical evidence only. An empty result is an empty result — nothing is populated from fixtures"
                     testid="ev-table" />

        {state.data && (
          <p className="wx-section-note">
            {rows.length} of {measured(state.data.total)} matching canonical events ·{" "}
            {state.data.source_agnostic_note}
          </p>
        )}

        <EventPane eventId={selected} onClose={() => setSelected(null)}
                   onPivot={(q) => { setSelected(null); apply({ ...q }); }} />
      </NxPageShell>
    </XdrShell>
  );
}
