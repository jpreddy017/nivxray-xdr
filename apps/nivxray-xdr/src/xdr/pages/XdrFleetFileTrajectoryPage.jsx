/**
 * XdrFleetFileTrajectoryPage · P1.8 · `/xdr/intelligence/files/:key`
 *
 * Multi-endpoint artifact spread — the fleet counterpart to Device
 * Trajectory.  `:key` is `sha256:<hex>`, `name:<leaf>` or `path:<path>`.
 *
 * Honest State, restated on the page itself:
 *   • Counting: `event.iid` is deduplicated first, provenance unioned.
 *     UNIQUE EVIDENCE EVENTS is authoritative; RAW OBSERVATIONS is
 *     labelled raw so nobody mistakes replayed case copies for activity.
 *   • `event.raw.sha256` equals the record's `input_sha256` on every
 *     document — it digests the observation, not a file — and
 *     `artefacts.file[].sha256` is empty throughout, so content-digest
 *     correlation is impossible here and NAME/PATH correlation is
 *     labelled as inference-free but content-blind.
 *   • No synthetic endpoints. Zero matches renders a zero state.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Loader2, FileSearch, ChevronLeft, RefreshCcw, Radar, Fingerprint,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { getFileTrajectory, getFleetSpreadIndex } from "@/nivxforge/edrApi";
import { fmtUtc, shortHash, TELEMETRY_CYAN } from "@/xdr/lib/trajectoryModel";

const PAGE_SIZES = [10, 25, 50];
const TRUTH_BANNER = "NivXForge EDR — LIVE against persisted v2_shadow_observations "
  + "substrate; production endpoint-agent telemetry NOT YET IMPLEMENTED.";

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
const Nope = ({ label, ep = "no_evidence" }) => (
  <span className="nx-ep" data-ep={ep} data-known="true">{label}</span>
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
      try {
        const r = await getFleetSpreadIndex();
        if (!cancel) setIndex(r);
      } catch { /* index is contextual only */ }
    })();
    return () => { cancel = true; };
  }, []);

  const rows = data?.endpoint_rows || [];
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

  return (
    <XdrShell>
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                    flexWrap: "wrap", marginBottom: 4 }}>
        <button className="btn ghost" style={{ padding: "4px 8px" }}
                onClick={() => navigate(-1)}
                data-testid="fleet-back">
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
        <button className="btn" style={{ padding: "4px 10px" }} onClick={load}
                data-testid="fleet-refresh">
          <RefreshCcw size={11} /> Refresh
        </button>
      </div>
      <div className="page-sub" data-testid="fleet-truth-banner">{TRUTH_BANNER}</div>

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
          {/* ── correlation contract ─────────────────────────────── */}
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
                      zero here. Use a name-keyed lookup from the index below.
                    </span>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <>
              {/* ── fleet metrics ─────────────────────────────────── */}
              <div style={{ display: "grid",
                            gridTemplateColumns: "repeat(auto-fit,minmax(178px,1fr))",
                            gap: 8, marginBottom: 10 }}
                   data-testid="fleet-metrics">
                <Metric k="Affected endpoints" v={data.affected_endpoints}
                        hint="distinct authoritative device_iid"
                        tone={TELEMETRY_CYAN}
                        testid="fleet-metric-endpoints" />
                <Metric k="Unique evidence events" v={data.unique_events}
                        hint="authoritative · event.iid deduplicated"
                        testid="fleet-metric-unique" />
                <Metric k="Raw observations" v={data.raw_observations}
                        hint="all provenance copies · NOT unique activity"
                        testid="fleet-metric-raw" />
                <Metric k="First observed (fleet)" v={fmtUtc(new Date(data.first_observed).getTime())}
                        testid="fleet-metric-first" />
                <Metric k="Last observed (fleet)" v={fmtUtc(new Date(data.last_observed).getTime())}
                        testid="fleet-metric-last" />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr",
                            gap: 8, marginBottom: 10 }}>
                <section className="panel" style={{ padding: 10 }}
                         data-testid="fleet-identity">
                  <div className="section-title" style={{ marginBottom: 7 }}>
                    Artifact identity
                  </div>
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
                </section>

                <section className="panel" style={{ padding: 10 }}
                         data-testid="fleet-entry-point">
                  <div className="section-title" style={{ marginBottom: 7 }}>
                    Entry point
                  </div>
                  {(data.entry_points || []).length === 0 ? (
                    <Nope label="◇ NOT DETERMINABLE" />
                  ) : (
                    <>
                      {data.entry_points.length > 1 && (
                        <div className="nx-ep" data-ep="unknown" data-known="true"
                             style={{ display: "block", marginBottom: 6 }}>
                          ? {data.entry_points.length} ENDPOINTS TIE ON THE EARLIEST
                          TIMESTAMP — NO SINGLE ENTRY POINT IS CLAIMED
                        </div>
                      )}
                      {data.entry_points.map((p) => (
                        <div key={`${p.device_iid}-${p.first_seen}`}
                             className="mono" style={{ fontSize: 10.5, marginBottom: 4 }}>
                          {p.hostname || "◇ no hostname"}{" "}
                          <span style={{ color: "var(--faint)" }}>
                            ({p.device_iid || "◇ unbound"})
                          </span>
                          <div style={{ color: "var(--faint)", fontSize: 9.5 }}>
                            {p.first_seen}
                          </div>
                        </div>
                      ))}
                    </>
                  )}
                </section>

                <section className="panel" style={{ padding: 10 }}
                         data-testid="fleet-creators">
                  <div className="section-title" style={{ marginBottom: 7 }}>
                    Created by
                  </div>
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
                </section>
              </div>

              {/* ── computers with matching activity ─────────────── */}
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
                                <span className="nx-ep" data-ep="no_evidence" data-known="true">
                                  ◇ UNBOUND — NO DEVICE IDENTITY ON THESE RECORDS
                                </span>
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
                                <span className="nx-ep" data-ep="no_evidence"
                                      data-known="true"
                                      style={{ display: "block", marginTop: 1 }}
                                      title="The observation substrate carries this case_id, but no incident record exists for it.">
                                  ◇ CASE RECORD NOT PERSISTED
                                </span>
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
                            <span className="nx-ep" data-ep="capability_unavailable"
                                  data-known="true"
                                  style={{ display: "inline-block", maxWidth: "100%" }}
                                  title="No isolation, quarantine or termination path exists on this platform.">
                              ⊘ NO RESPONSE DRIVER
                            </span>
                          </td>
                          <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                            {r.device_ref ? (
                              <Link className="btn primary"
                                    style={{ padding: "3px 8px", fontSize: 10 }}
                                    to={`/xdr/endpoints/${encodeURIComponent(r.device_ref)}/trajectory?focus=${encodeURIComponent(keyValue)}`}
                                    data-testid={`fleet-pivot-${r.device_iid || "unbound"}`}>
                                <Radar size={11} /> Trajectory →
                              </Link>
                            ) : (
                              <span className="nx-ep" data-ep="no_evidence" data-known="true">
                                ◇ NO DEVICE TO PIVOT TO
                              </span>
                            )}
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

              {/* ── chronological fleet event history ───────────── */}
              <section className="panel" style={{ padding: 0, marginBottom: 10 }}
                       data-testid="fleet-event-history">
                <div style={{ padding: "7px 10px", borderBottom: "1px solid #212B36",
                              background: "#11161D" }}>
                  <span className="section-title" style={{ margin: 0 }}>
                    Fleet event history
                  </span>{" "}
                  <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)" }}>
                    {data.events.length} unique evidence events, oldest first
                  </span>
                </div>
                <div style={{ maxHeight: 320, overflow: "auto" }}>
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
                      {data.events.map((e) => (
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
                          <td>
                            <span className="nx-ep" data-ep="unknown" data-known="true">
                              ? UNKNOWN
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}

          {/* ── fleet spread index ───────────────────────────────── */}
          {index && (
            <section className="panel" style={{ padding: 0 }}
                     data-testid="fleet-spread-index">
              <div style={{ padding: "7px 10px", borderBottom: "1px solid #212B36",
                            background: "#11161D" }}>
                <Fingerprint size={11} style={{ color: "var(--mint)",
                                                verticalAlign: "middle", marginRight: 6 }} />
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
        </>
      )}
    </XdrShell>
  );
}
