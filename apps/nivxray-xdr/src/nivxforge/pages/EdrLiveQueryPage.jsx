/**
 * NivXForge EDR · Live Query.
 *
 * Version one asks one read-only question — which running processes match this
 * exact name on this computer, now — and every answer carries the question and
 * the target beside it, so an analyst can see exactly what was checked.
 *
 * A query id is a response-plane command id, so the id shown on a selected
 * computer is the id in Dashboard history: one record, two doors.
 */
import { Loader2, RefreshCw, Terminal } from "lucide-react";
import React, { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { listQueries, liveQuery, queryResult } from "@/nivxforge/edrApi";

const utc = (iso, len = 19) => {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().replace("T", " ").slice(0, len) + "Z"; }
  catch { return String(iso); }
};

const TONE = {
  COMPLETED_WITH_MATCHES: "var(--mint, #3fae7d)",
  COMPLETED_NO_MATCHES: "var(--cyan, #39b7c4)",
  QUEUED: "var(--muted, #8a9199)",
  RUNNING: "var(--cyan, #39b7c4)",
  FAILED: "var(--red, #d05353)",
  CAPABILITY_UNAVAILABLE: "var(--amber, #d08700)",
  TIMED_OUT: "var(--amber, #d08700)",
};

const LABEL = {
  COMPLETED_WITH_MATCHES: "Answered · matches",
  COMPLETED_NO_MATCHES: "Answered · no matches",
  QUEUED: "Queued",
  RUNNING: "Running",
  FAILED: "Failed",
  CAPABILITY_UNAVAILABLE: "Capability unavailable",
  TIMED_OUT: "Timed out",
};

const Status = ({ status, testid = "lq-status" }) => (
  <span data-testid={testid} data-status={status}
        style={{ color: TONE[status] || "inherit", fontSize: 11.5,
                 letterSpacing: ".04em", textTransform: "uppercase" }}>
    {LABEL[status] || status}
  </span>
);

export default function EdrLiveQueryPage() {
  const [params, setParams] = useSearchParams();
  const device = params.get("device") || "";
  const openQuery = params.get("query") || "";

  const [name, setName] = useState(params.get("name") || "");
  const [list, setList] = useState(null);
  const [q, setQ] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const refresh = useCallback(() => {
    listQueries(device || undefined)
      .then(setList)
      .catch((e) => setErr(e?.response?.data?.detail || e.message));
  }, [device]);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    if (!openQuery) { setQ(null); return; }
    let live = true;
    const tick = () => queryResult(openQuery)
      .then((d) => { if (live) setQ(d); })
      .catch((e) => { if (live) setErr(e?.response?.data?.detail || e.message); });
    tick();
    const t = setInterval(tick, 5000);
    return () => { live = false; clearInterval(t); };
  }, [openQuery]);

  useEffect(() => {
    if (q && !["QUEUED", "RUNNING"].includes(q.status)) refresh();
  }, [q?.status]);   // eslint-disable-line react-hooks/exhaustive-deps

  const ask = async (e) => {
    e?.preventDefault?.();
    if (!device || !name.trim()) return;
    setBusy(true); setErr(null);
    try {
      // Each request collects fresh on the endpoint; a previous answer is
      // never reused, because "now" changes.
      const d = await liveQuery(device, name.trim());
      setParams({ device, name: name.trim(), query: d.query_id }, { replace: true });
      refresh();
    } catch (e2) {
      setErr(e2?.response?.data?.detail || e2.message);
    } finally { setBusy(false); }
  };

  return (
    <NivXForgeConsole active="live-query">
      <div data-testid="edr-live-query-page" style={{ padding: "28px 34px", maxWidth: 1400 }}>
        <h1 style={{ fontSize: 22, letterSpacing: "-.01em", margin: 0 }}>Live Query</h1>
        <p style={{ maxWidth: 900, marginTop: 8, fontSize: 13, lineHeight: 1.7, opacity: 0.78 }}
           data-testid="edr-live-query-basis">
          One read-only question, answered by the endpoint when it claims the query:
          <b> which running processes match this exact name on this computer now</b>.
          Stored telemetry is never searched — polling records when a process was
          first observed, which cannot say what is running at this moment.
        </p>

        {device ? (
          <form onSubmit={ask} style={{ display: "flex", gap: 10, alignItems: "center",
                                        margin: "18px 0 6px", flexWrap: "wrap" }}>
            <input value={name} onChange={(e) => setName(e.target.value)}
                   data-testid="lq-name" aria-label="Process name"
                   placeholder="Process name, e.g. mongod" className="mono"
                   style={{ maxWidth: 320, fontSize: 12.5 }} />
            <button type="submit" className="x-btn" disabled={busy || !name.trim()}
                    data-testid="lq-run">
              {busy ? <Loader2 size={13} className="x-spin" /> : <Terminal size={13} />}
              {" "}Ask this computer
            </button>
            <span className="mono" style={{ fontSize: 12, opacity: 0.75 }}
                  data-testid="lq-target">{device}</span>
          </form>
        ) : (
          <p className="x-empty" data-testid="lq-no-device" style={{ marginTop: 18 }}>
            Open a computer to ask it a question: Computers → select → Actions → Live Query.
            History for every computer in this customer is below.
          </p>
        )}

        {err && <div className="x-error" data-testid="edr-live-query-error">{String(
          err?.reason || err?.error || err)}</div>}

        {q && (
          <section data-testid="lq-result" data-query-id={q.query_id} data-status={q.status}
                   style={{ marginTop: 20, border: "1px solid rgba(128,128,128,.22)",
                            borderRadius: 12, padding: "16px 18px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
              <div>
                <div style={{ fontSize: 10.5, letterSpacing: ".06em", textTransform: "uppercase", opacity: 0.6 }}>
                  Query
                </div>
                <div className="mono" data-testid="lq-query-id" style={{ fontSize: 13 }}>{q.query_id}</div>
              </div>
              <Status status={q.status} />
            </div>

            {/* The question and the target, beside the answer. */}
            <div data-testid="lq-asked" style={{ marginTop: 10, fontSize: 12.5, lineHeight: 1.8 }}>
              <div style={{ opacity: 0.75 }}>{q.question}</div>
              <div className="mono">
                name <b>{q.process_name}</b> · on <b>{q.endpoint_id}</b>
                {q.name_truncated && (
                  <span data-testid="lq-truncated" style={{ color: "var(--amber, #d08700)" }}>
                    {" "}· compared as {q.name_compared}
                  </span>
                )}
              </div>
              {q.match_basis && (
                <div style={{ fontSize: 11.5, opacity: 0.65 }} data-testid="lq-match-basis">{q.match_basis}</div>
              )}
            </div>

            <p style={{ fontSize: 12, opacity: 0.75, marginTop: 10 }} data-testid="lq-meaning">
              {q.status_meaning}
            </p>

            <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 16px",
                         fontSize: 12.5, margin: "12px 0 0" }}>
              {[["Requested by", q.requested_by],
                ["Requested (UTC)", utc(q.requested_at)],
                ["Collected (UTC)", utc(q.collected_at)],
                ["Matches", q.match_count == null ? "—" : String(q.match_count)],
                ["Processes examined", q.processes_examined == null ? "—" : String(q.processes_examined)],
                ["Sensor", q.sensor_version || "—"]].map(([k, v]) => (
                  <React.Fragment key={k}>
                    <dt style={{ opacity: 0.6 }}>{k}</dt>
                    <dd className="mono" style={{ margin: 0 }}>{v || "—"}</dd>
                  </React.Fragment>))}
            </dl>

            {q.rows?.length ? (
              <table className="mono" data-testid="lq-rows"
                     style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, marginTop: 14 }}>
                <thead>
                  <tr style={{ textAlign: "left", opacity: 0.6, fontSize: 11 }}>
                    <th style={{ padding: "4px 14px 6px 0" }}>PID</th>
                    <th style={{ padding: "4px 14px 6px 0" }}>Name</th>
                    <th style={{ padding: "4px 0 6px 0" }}>Path</th>
                  </tr>
                </thead>
                <tbody>
                  {q.rows.map((r, i) => (
                    <tr key={`${r.pid}-${i}`} data-testid={`lq-row-${i}`}
                        style={{ borderTop: "1px solid rgba(128,128,128,.14)" }}>
                      <td style={{ padding: "4px 14px 4px 0" }}>{r.pid}</td>
                      <td style={{ padding: "4px 14px 4px 0" }}>{r.name || "—"}</td>
                      <td style={{ padding: "4px 0" }}>
                        {r.path || <span style={{ opacity: 0.6 }}>
                          not readable{r.path_unavailable ? ` · ${r.path_unavailable}` : ""}
                        </span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="x-empty" data-testid="lq-rows-empty" style={{ marginTop: 14 }}>
                {q.status === "COMPLETED_NO_MATCHES"
                  ? `Nothing on ${q.endpoint_id} is running under ${q.process_name} right now. The endpoint answered; this is not a failure, and stored telemetry was not searched to fill it in.`
                  : q.status_meaning}
              </div>
            )}

            {q.not_observed?.length > 0 && (
              <p style={{ fontSize: 11.5, opacity: 0.62, marginTop: 10 }} data-testid="lq-not-observed">
                Not collected by this query: {q.not_observed.join(" · ")}.
              </p>
            )}
          </section>
        )}

        <section style={{ marginTop: 26 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <h2 style={{ fontSize: 13, letterSpacing: ".04em", textTransform: "uppercase", opacity: 0.7, margin: 0 }}>
              History{device ? " · this computer" : ""}
            </h2>
            <button className="x-btn" onClick={refresh} data-testid="edr-live-query-refresh"
                    style={{ fontSize: 11.5 }}><RefreshCw size={12} /> Refresh</button>
          </div>
          {!list ? (
            <div className="x-empty" data-testid="edr-live-query-loading">Reading query history…</div>
          ) : !list.queries.length ? (
            <div className="x-empty" data-testid="edr-live-query-empty">
              No live query has been run in this customer. The read succeeded and
              returned nothing.
            </div>
          ) : (
            <table data-testid="edr-live-query-history"
                   style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5, marginTop: 10 }}>
              <thead>
                <tr style={{ textAlign: "left", opacity: 0.6, fontSize: 11 }}>
                  <th style={{ padding: "6px 14px 8px 0" }}>Requested (UTC)</th>
                  <th style={{ padding: "6px 14px 8px 0" }}>Query</th>
                  <th style={{ padding: "6px 14px 8px 0" }}>Name asked</th>
                  <th style={{ padding: "6px 14px 8px 0" }}>Computer</th>
                  <th style={{ padding: "6px 14px 8px 0" }}>Matches</th>
                  <th style={{ padding: "6px 0 8px 0" }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {list.queries.map((r, i) => (
                  <tr key={r.query_id} data-testid={`edr-live-query-history-row-${i}`}
                      data-query-id={r.query_id}
                      onClick={() => setParams({ ...(device ? { device } : {}),
                                                 query: r.query_id }, { replace: true })}
                      style={{ borderTop: "1px solid rgba(128,128,128,.14)", cursor: "pointer",
                               background: r.query_id === openQuery ? "rgba(57,183,196,.08)" : "transparent" }}>
                    <td className="mono" style={{ padding: "6px 14px 6px 0" }}>{utc(r.requested_at)}</td>
                    <td className="mono" style={{ padding: "6px 14px 6px 0" }}>{r.query_id}</td>
                    <td className="mono" style={{ padding: "6px 14px 6px 0" }}>{r.process_name}</td>
                    <td className="mono" style={{ padding: "6px 14px 6px 0" }}>{r.endpoint_id}</td>
                    <td className="mono" style={{ padding: "6px 14px 6px 0" }}>
                      {r.match_count == null ? "—" : r.match_count}
                    </td>
                    <td style={{ padding: "6px 0" }}>
                      <Status status={r.status} testid={`edr-live-query-history-status-${i}`} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {list?.collection_basis && (
            <p style={{ fontSize: 11.5, opacity: 0.6, marginTop: 10, maxWidth: 920 }}
               data-testid="edr-live-query-collection-basis">
              {list.collection_basis} A query with no answer after {list.timeout_seconds}s is
              reported as timed out rather than left reading as though it were still running.
            </p>
          )}
        </section>
      </div>
    </NivXForgeConsole>
  );
}
