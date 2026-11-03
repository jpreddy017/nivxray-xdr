/**
 * NivXForge EDR · Forensic Snapshots.
 *
 * One job is one command on the response plane, so the job id an analyst sees
 * here is the same id the computer's Actions menu returns — the two entry
 * points open the same job, they do not create parallel records.
 *
 * Every status is shown with what it MEANS, because the distinctions are the
 * point: a capture that ran and returned nothing is not a failure, and a job
 * with no answer yet is not a statement about the endpoint.
 */
import { Camera, Loader2, RefreshCw } from "lucide-react";
import React, { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { listSnapshots, requestSnapshot, snapshotJob } from "@/nivxforge/edrApi";

const utc = (iso, len = 19) => {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().replace("T", " ").slice(0, len) + "Z"; }
  catch { return String(iso); }
};

const TONE = {
  COMPLETED_WITH_ROWS: "var(--mint, #3fae7d)",
  COMPLETED_ZERO_ROWS: "var(--cyan, #39b7c4)",
  QUEUED: "var(--muted, #8a9199)",
  RUNNING: "var(--cyan, #39b7c4)",
  FAILED: "var(--red, #d05353)",
  CAPABILITY_UNAVAILABLE: "var(--amber, #d08700)",
  TIMED_OUT: "var(--amber, #d08700)",
};

const LABEL = {
  COMPLETED_WITH_ROWS: "Completed · rows returned",
  COMPLETED_ZERO_ROWS: "Completed · zero rows",
  QUEUED: "Queued",
  RUNNING: "Running",
  FAILED: "Failed",
  CAPABILITY_UNAVAILABLE: "Capability unavailable",
  TIMED_OUT: "Timed out",
};

const Status = ({ status, testid = "snapshot-status" }) => (
  <span data-testid={testid} data-status={status}
        style={{ color: TONE[status] || "inherit", fontSize: 11.5,
                 letterSpacing: ".04em", textTransform: "uppercase" }}>
    {LABEL[status] || status}
  </span>
);

const Rows = ({ job }) => {
  if (!job.rows?.length) {
    return (
      <div className="x-empty" data-testid="snapshot-rows-empty">
        {job.status === "COMPLETED_ZERO_ROWS"
          ? "The capture ran and returned no rows. That is an empty result, not a failure — and stored telemetry was not used to fill it in."
          : job.status_meaning}
      </div>
    );
  }
  return (
    <table className="mono" data-testid="snapshot-rows"
           style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
      <thead>
        <tr style={{ textAlign: "left", opacity: 0.6, fontSize: 11 }}>
          <th style={{ padding: "4px 14px 6px 0" }}>PID</th>
          <th style={{ padding: "4px 14px 6px 0" }}>Name</th>
          <th style={{ padding: "4px 0 6px 0" }}>Path</th>
        </tr>
      </thead>
      <tbody>
        {job.rows.map((r, i) => (
          <tr key={`${r.pid}-${i}`} data-testid={`snapshot-row-${i}`}
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
  );
};

export default function EdrForensicsPage() {
  const [params, setParams] = useSearchParams();
  const device = params.get("device") || "";
  const openJob = params.get("job") || "";

  const [list, setList] = useState(null);
  const [job, setJob] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const refresh = useCallback(() => {
    listSnapshots(device || undefined)
      .then(setList)
      .catch((e) => setErr(e?.response?.data?.detail || e.message));
  }, [device]);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    if (!openJob) { setJob(null); return; }
    let live = true;
    const tick = () => snapshotJob(openJob)
      .then((d) => { if (live) setJob(d); })
      .catch((e) => { if (live) setErr(e?.response?.data?.detail || e.message); });
    tick();
    // A queued or running job is polled until it answers; nothing is assumed
    // about the endpoint while it has not.
    const t = setInterval(tick, 5000);
    return () => { live = false; clearInterval(t); };
  }, [openJob]);

  useEffect(() => {
    if (job && !["QUEUED", "RUNNING"].includes(job.status)) refresh();
  }, [job?.status]);   // eslint-disable-line react-hooks/exhaustive-deps

  const take = async () => {
    if (!device) return;
    setBusy(true); setErr(null);
    try {
      const d = await requestSnapshot(device, "requested from Forensic Snapshots");
      setParams({ device, job: d.job_id }, { replace: true });
      refresh();
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    } finally { setBusy(false); }
  };

  return (
    <NivXForgeConsole active="forensics">
      <div data-testid="edr-forensics-page" style={{ padding: "28px 34px", maxWidth: 1400 }}>
        <h1 style={{ fontSize: 22, letterSpacing: "-.01em", margin: 0 }}>Forensic Snapshots</h1>
        <p style={{ maxWidth: 880, marginTop: 8, fontSize: 13, lineHeight: 1.7, opacity: 0.78 }}
           data-testid="edr-forensics-basis">
          A point-in-time read of what is running on one endpoint, taken by the sensor
          when the job is claimed. Stored telemetry is never used to answer a snapshot:
          polling records when a process was first observed, which cannot establish the
          set that existed at capture time.
        </p>

        {device && (
          <div style={{ display: "flex", gap: 10, alignItems: "center", margin: "18px 0 6px" }}>
            <button className="x-btn" onClick={take} disabled={busy}
                    data-testid="snapshot-request-btn">
              {busy ? <Loader2 size={13} className="x-spin" /> : <Camera size={13} />}
              {" "}Request forensic snapshot
            </button>
            <span className="mono" style={{ fontSize: 12, opacity: 0.75 }}
                  data-testid="snapshot-target">{device}</span>
          </div>
        )}

        {err && <div className="x-error" data-testid="edr-forensics-error">{String(
          err?.reason || err?.error || err)}</div>}

        {job && (
          <section data-testid="snapshot-job" data-job-id={job.job_id} data-status={job.status}
                   style={{ marginTop: 20, border: "1px solid rgba(128,128,128,.22)",
                            borderRadius: 12, padding: "16px 18px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
              <div>
                <div style={{ fontSize: 10.5, letterSpacing: ".06em", textTransform: "uppercase", opacity: 0.6 }}>
                  Job
                </div>
                <div className="mono" data-testid="snapshot-job-id" style={{ fontSize: 13 }}>{job.job_id}</div>
              </div>
              <div><Status status={job.status} /></div>
            </div>
            <p style={{ fontSize: 12, opacity: 0.75, marginTop: 8 }} data-testid="snapshot-job-meaning">
              {job.status_meaning}
            </p>
            <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 16px",
                         fontSize: 12.5, margin: "12px 0 0" }}>
              {[["Requested by", job.requested_by],
                ["Endpoint", job.endpoint_id],
                ["Requested (UTC)", utc(job.requested_at)],
                ["Capture start (UTC)", utc(job.capture_started_at)],
                ["Capture finish (UTC)", utc(job.capture_finished_at)],
                ["Rows", job.row_count == null ? "—" : String(job.row_count)],
                ["Sensor", job.sensor_version || "—"]].map(([k, v]) => (
                  <React.Fragment key={k}>
                    <dt style={{ opacity: 0.6 }}>{k}</dt>
                    <dd className="mono" style={{ margin: 0 }}>{v || "—"}</dd>
                  </React.Fragment>))}
            </dl>
            {job.not_observed?.length > 0 && (
              <p style={{ fontSize: 11.5, opacity: 0.65, marginTop: 10 }} data-testid="snapshot-not-observed">
                Not collected by this capture: {job.not_observed.join(" · ")}.
              </p>
            )}
            {job.sections?.length > 0 && (
              <div data-testid="snapshot-sections" style={{ marginTop: 14 }}>
                <div style={{ fontSize: 10.5, letterSpacing: ".06em", textTransform: "uppercase",
                              opacity: 0.6, marginBottom: 6 }}>
                  What this snapshot covers
                </div>
                <ul style={{ margin: 0, padding: 0, listStyle: "none", fontSize: 12.5,
                             display: "grid", gap: 3 }}>
                  {job.sections.map((s) => (
                    <li key={s.section} data-testid={`snapshot-section-${s.section.replace(/\s+/g, "-").toLowerCase()}`}
                        data-state={s.state}
                        style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
                      <span style={{ width: 210, color: s.state === "COLLECTED"
                        ? "var(--mint, #3fae7d)" : "inherit",
                        opacity: s.state === "COLLECTED" ? 1 : 0.55 }}>
                        {s.state === "COLLECTED" ? "▪" : "▫"} {s.section}
                        {s.rows != null ? ` · ${s.rows}` : ""}
                      </span>
                      <span style={{ opacity: 0.6 }}>{s.note}</span>
                    </li>
                  ))}
                </ul>
                {job.retention_note && (
                  <p style={{ fontSize: 11.5, opacity: 0.6, marginTop: 8, maxWidth: 820 }}
                     data-testid="snapshot-retention">{job.retention_note}</p>
                )}
              </div>
            )}
            <div style={{ marginTop: 14 }}><Rows job={job} /></div>
          </section>
        )}

        <section style={{ marginTop: 26 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <h2 style={{ fontSize: 13, letterSpacing: ".04em", textTransform: "uppercase", opacity: 0.7, margin: 0 }}>
              History{device ? " · this computer" : ""}
            </h2>
            <button className="x-btn" onClick={refresh} data-testid="edr-forensics-refresh"
                    style={{ fontSize: 11.5 }}><RefreshCw size={12} /> Refresh</button>
            {device && (
              <button className="x-btn" data-testid="edr-forensics-all"
                      onClick={() => setParams(openJob ? { job: openJob } : {}, { replace: true })}
                      style={{ fontSize: 11.5 }}>Show all computers</button>
            )}
          </div>
          {!list ? (
            <div className="x-empty" data-testid="edr-forensics-loading">Reading snapshot history…</div>
          ) : !list.jobs.length ? (
            <div className="x-empty" data-testid="edr-forensics-empty">
              No forensic snapshot has been requested in this customer. The read succeeded
              and returned nothing.
            </div>
          ) : (
            <table data-testid="edr-forensics-history"
                   style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5, marginTop: 10 }}>
              <thead>
                <tr style={{ textAlign: "left", opacity: 0.6, fontSize: 11 }}>
                  <th style={{ padding: "6px 14px 8px 0" }}>Requested (UTC)</th>
                  <th style={{ padding: "6px 14px 8px 0" }}>Job</th>
                  <th style={{ padding: "6px 14px 8px 0" }}>Computer</th>
                  <th style={{ padding: "6px 14px 8px 0" }}>Requester</th>
                  <th style={{ padding: "6px 14px 8px 0" }}>Rows</th>
                  <th style={{ padding: "6px 0 8px 0" }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {list.jobs.map((j, i) => (
                  <tr key={j.job_id} data-testid={`edr-forensics-history-row-${i}`}
                      data-job-id={j.job_id}
                      onClick={() => setParams({ ...(device ? { device } : {}), job: j.job_id },
                                               { replace: true })}
                      style={{ borderTop: "1px solid rgba(128,128,128,.14)", cursor: "pointer",
                               background: j.job_id === openJob ? "rgba(57,183,196,.08)" : "transparent" }}>
                    <td className="mono" style={{ padding: "6px 14px 6px 0" }}>{utc(j.requested_at)}</td>
                    <td className="mono" style={{ padding: "6px 14px 6px 0" }}>{j.job_id}</td>
                    <td className="mono" style={{ padding: "6px 14px 6px 0" }}>{j.endpoint_id}</td>
                    <td style={{ padding: "6px 14px 6px 0" }}>{j.requested_by || "—"}</td>
                    <td className="mono" style={{ padding: "6px 14px 6px 0" }}>
                      {j.row_count == null ? "—" : j.row_count}
                    </td>
                    <td style={{ padding: "6px 0" }}><Status status={j.status}
                                 testid={`edr-forensics-history-status-${i}`} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {list?.collection_basis && (
            <p style={{ fontSize: 11.5, opacity: 0.6, marginTop: 10, maxWidth: 900 }}
               data-testid="edr-forensics-collection-basis">
              {list.collection_basis} A job with no answer after {list.timeout_seconds}s is
              reported as timed out rather than left reading as though it were still running.
            </p>
          )}
        </section>
      </div>
    </NivXForgeConsole>
  );
}
