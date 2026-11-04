import React, { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { getIndexedFileObservations, getFileObservations } from "./fileEvidenceApi";
import { TENANT_BOUND_EVENT } from "@/lib/tenant";
import "./file-evidence.css";
import FileTimeline from "./FileTimeline";
import Icon from "./TrajectoryIcon";
import { chronological, eventKey, readComputerPage } from "./trajectoryModel.mjs";

const day = 86400000;
const iso = (ms) => new Date(ms).toISOString().slice(0, 16);
const utcMillis = (text) => Date.parse(`${text}:00Z`);
const validMillis = (value) => Number.isFinite(value) && value > 0 && value <= 253402300799000;

export default function FileEvidence({ endpointId, endpointIds, computers = [], indexSearch }) {
  const [params, setParams] = useSearchParams();
  const [end] = useState(() => Math.floor(Date.now() / 60000) * 60000);
  const startParam = Number(indexSearch?.time_start || params.get("t0")), endParam = Number(indexSearch?.time_end || params.get("t1"));
  const [start, setStart] = useState(() => iso(validMillis(startParam) ? startParam : end - 30 * day));
  const [finish, setFinish] = useState(() => iso(validMillis(endParam) ? endParam : end));
  const [kind, setKind] = useState(() => indexSearch?.key_type || params.get("file_key_type") || (endpointIds ? "sha256" : "path"));
  const [key, setKey] = useState(() => indexSearch?.key || (endpointIds && !/^[a-f0-9]{64}$/i.test(params.get("file_key") || "") ? "" : params.get("file_key")) || "");
  const [eventFilter, setEventFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [ascending, setAscending] = useState(true);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState(null);
  const [rows, setRows] = useState([]), [data, setData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState(""), [busy, setBusy] = useState(false);
  const [request, setRequest] = useState({ number: 0, cursor: null });
  const generation = useRef(0);
  const detailsHeading = useRef(null), lastInspect = useRef(null);
  useEffect(() => { if (selected) detailsHeading.current?.focus(); }, [selected]);

  // A different endpoint must never display the previous endpoint's evidence.
  useEffect(() => {
    generation.current += 1;
    setRows([]); setData(null); setSelected(null); setError(""); setBusy(false);
    setQuery(null);
  }, [endpointId]);

  useEffect(() => {
    const clear = () => {
      generation.current += 1;
      setRows([]); setData(null); setSelected(null); setQuery(null);
      setBusy(false); setError("");
    };
    window.addEventListener(TENANT_BOUND_EVENT, clear);
    return () => window.removeEventListener(TENANT_BOUND_EVENT, clear);
  }, []);

  const load = () => {
    if (endpointIds && (kind !== "sha256" || !/^[a-f0-9]{64}$/i.test(key))) {
      setError("Choose SHA-256 and enter a complete hash to search across computers."); return;
    }
    setPage(0);
    const a = utcMillis(start), b = utcMillis(finish);
    if (!Number.isFinite(a) || !Number.isFinite(b) || a >= b || b - a > 31 * day) {
      setError("Choose an increasing UTC window of at most 31 days."); return;
    }
    if (kind === "sha256" && key && !/^[a-f0-9]{64}$/i.test(key)) {
      setError("Enter a complete SHA-256 content hash."); return;
    }
    generation.current += 1;
    setRows([]); setData(null); setSelected(null); setError("");
    setQuery({ ...(endpointIds ? { endpoint_ids: endpointIds } : { endpoint_id: endpointId }), time_start: a, time_end: b,
               key_type: kind, key, limit: 100 });
    setRequest((r) => ({ number: r.number + 1, cursor: null }));
    const next = new URLSearchParams(params);
    next.set("t0", String(a)); next.set("t1", String(b));
    next.set("file_key_type", kind);
    if (key) next.set("file_key", key); else next.delete("file_key");
    setParams(next, { replace: true });
  };

  useEffect(() => { if (indexSearch) load(); }, [indexSearch]); // query supplied by global discovery

  useEffect(() => {
    if (!query) return undefined;
    const controller = new AbortController();
    const ticket = generation.current;
    setBusy(true); setError("");
    readComputerPage(indexSearch ? getIndexedFileObservations : getFileObservations, query, controller.signal, request.cursor)
      .then((value) => {
        if (controller.signal.aborted || ticket !== generation.current) return;
        setData((old) => {
          if (!request.cursor || !old) return value;
          const issues = { ...(old.issues || {}) };
          for (const [k, n] of Object.entries(value.issues || {})) issues[k] = (issues[k] || 0) + n;
          return { ...value, issues };
        });
        setRows((old) => [...new Map((request.cursor ? [...old, ...(value.observations || [])] : value.observations || [])
          .map((r) => { const row = { ...r, endpoint_id: r.endpoint_id || endpointId }; return [eventKey(row), row]; })).values()]);
      })
      .catch((e) => {
        if (controller.signal.aborted || ticket !== generation.current) return;
        setError(e.response?.status === 403 ? "You are not authorized to view this endpoint's evidence."
          : e.response?.status === 404 ? "This backend does not yet provide File Trajectory."
          : e.response?.data?.detail || e.message || "File evidence could not be loaded. Retry the request.");
      })
      .finally(() => { if (!controller.signal.aborted && ticket === generation.current) setBusy(false); });
    return () => controller.abort();
  }, [query, request]);

  const trajectory = selected?.trajectory_url || (query ? `/edr/computers/${encodeURIComponent(selected?.endpoint_id || endpointId)}/trajectory?t0=${query.time_start}&t1=${query.time_end}` : "");
  const ordered = chronological(rows).filter((r) => (!actionFilter || r.action === actionFilter) &&
    [r.path, r.name, r.writer_image, r.endpoint_id, r.hashes?.sha256].some((v) => String(v || "").toLowerCase().includes(eventFilter.toLowerCase())));
  if (!ascending) ordered.reverse();
  const visible = ordered.slice(page * pageSize, (page + 1) * pageSize);
  const exportRows = () => {
    const blob = new Blob([JSON.stringify({ window: data?.window || { start_ms: query.time_start, end_ms: query.time_end }, coverage: "LOADED_OBSERVATIONS_ONLY", observations: ordered }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob), a = document.createElement("a");
    a.href = url; a.download = "file-trajectory-evidence.json"; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return (
    <section className="ft-evidence" aria-label="File Trajectory" data-testid="edr-file-evidence">
      <div className="ft-section-head"><h2><Icon name="timeline" />File Trajectory</h2><div className="ft-tools">
        <button className="btn" disabled={!query || busy} onClick={load}>Refresh</button>
        <button className="btn" disabled={!rows.length} onClick={exportRows}>Export loaded evidence</button>
        <button className="btn" onClick={async () => { try { await navigator.clipboard.writeText(window.location.href); setNotice("Investigation link copied."); } catch { setNotice("Copy the investigation URL from the address bar."); } }}>Copy link</button>
      </div></div><p role="status">{notice}</p>
      <p>Recorded file activity for the selected computers. This view does not enumerate its current disk contents.</p>
      <form className="ft-query" onSubmit={(e) => { e.preventDefault(); load(); }}>
        <label>Start (UTC)<input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} required /></label>
        <label>End (UTC, exclusive)<input type="datetime-local" value={finish} onChange={(e) => setFinish(e.target.value)} required /></label>
        <label>Match by<select value={kind} onChange={(e) => setKind(e.target.value)}>
          {indexSearch && <><option value="auto">Auto detect</option><option value="sha1">SHA-1</option><option value="md5">MD5</option></>}<option value="path">Exact path</option><option value="name">Exact name</option><option value="sha256">SHA-256 content hash</option>
        </select></label>
        <label className="ft-key">{endpointIds ? "SHA-256 (required across computers)" : "File filter (optional)"}<input value={key} maxLength={4096} onChange={(e) => setKey(e.target.value)} placeholder={endpointIds ? "Enter 64 hexadecimal characters" : "Leave empty to inspect recorded files"} /></label>
        <button className="btn" type="submit" disabled={busy || (!endpointId && !endpointIds?.length)}>Search observations</button>
      </form>
      {error ? <div role="alert" className="ft-error">{String(error)}</div> : null}
      {busy ? <p role="status">Reading file evidence…</p> : null}
      {data?.state === "ENDPOINT_NOT_RESOLVED" ? <p role="alert">Endpoint identity or permission could not be resolved. This is not an empty file history.</p> : null}
      {data && data.state !== "ENDPOINT_NOT_RESOLVED" ? <>
        <p role="status">{rows.length} observations loaded · {indexSearch ? (data.complete ? "all matching indexed evidence loaded" : "more matching indexed evidence available") : (data.complete ? "scan reached the end" : "more source records remain")}.</p>
        <p className="ft-coverage">{indexSearch ? "Evidence is limited to index coverage shown above. Missing hashes and verdicts remain unknown. Timeline and history show loaded evidence." : "Coverage has not been proven. A missing hash is unknown; no detection verdict is inferred. Timeline and history show loaded evidence chronologically; continue scanning to retrieve more."}</p>
        {!rows.length ? <p>{data.next_cursor ? "No file matches in this scan page. Continue scanning before concluding there are no matches."
          : "No matching file observations found in the scanned records. This does not prove that no file activity occurred."}</p> : null}
        {Object.keys(data.issues || {}).length ? <p>Some source records could not be interpreted or timed and were excluded. Coverage is incomplete.</p> : null}
        <FileTimeline key={`${query.time_start}:${query.time_end}`} rows={rows} endpointId={endpointId} computers={computers} selected={selected}
          start={query.time_start} end={query.time_end}
          onSelect={(row, button) => { lastInspect.current = button; setSelected(row); }} />
        <div className="ft-section-head"><h3><Icon name="history" />Event History</h3><div className="ft-tools">
        <label>Search loaded events <input value={eventFilter} onChange={(e) => { setEventFilter(e.target.value); setPage(0); }} placeholder="Path, hash, process or computer" /></label>
        <label>Event type <select aria-label="Event type" value={actionFilter} onChange={(e) => { setActionFilter(e.target.value); setPage(0); }}><option value="">All events</option>{[...new Set(rows.map((r) => r.action).filter(Boolean))].map((a) => <option key={a}>{a}</option>)}</select></label>
        </div></div>
        <div className="ft-results" data-has-selection={Boolean(selected)}>
        <div className="ft-table-wrap"><table>
          <caption>File observations within the selected UTC window</caption>
          <thead><tr><th aria-sort={ascending ? "ascending" : "descending"}><button className="ft-sort" onClick={() => { setAscending(!ascending); setPage(0); }}>Observed (UTC) {ascending ? "↑" : "↓"}</button></th><th>Computer</th><th>File / path</th><th>Action</th><th>Content identity</th><th>Details</th></tr></thead>
          <tbody>{visible.map((row) => <tr key={eventKey(row)} data-selected={selected && eventKey(selected) === eventKey(row)}>
            <td>{row.observed_at}</td><td>{computers.find((c) => c.endpoint_id === row.endpoint_id)?.hostname || row.endpoint_id}</td><td className="ft-path">{row.path}</td><td>{row.action || "Not reported"}</td>
            <td>{row.hashes?.sha256 || (Object.keys(row.hashes || {}).length ? "Other source hash" : "Hash not observed")}</td>
            <td><button className="btn" onClick={(e) => { lastInspect.current = e?.currentTarget; setSelected(row); }} aria-label={`Inspect ${row.name || row.path}`}>Inspect</button>{row.trajectory_url && <><br /><Link to={row.trajectory_url}>Matching event in Device Trajectory</Link></>}</td>
          </tr>)}</tbody>
        </table>{!ordered.length && <p className="ft-empty">No loaded events match these filters.</p>}</div>
        <div className="ft-pagination"><span>{ordered.length} matching loaded events</span><label>Rows <select value={pageSize} onChange={(e) => { setPageSize(Number(e.target.value)); setPage(0); }}>{[25,50,100].map((n) => <option key={n}>{n}</option>)}</select></label><button className="btn" disabled={!page} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page + 1} of {Math.max(1, Math.ceil(ordered.length / pageSize))}</span><button className="btn" disabled={(page + 1) * pageSize >= ordered.length} onClick={() => setPage(page + 1)}>Next</button></div>
        {data.next_cursor ? <button className="btn" disabled={busy} onClick={() => setRequest((r) => ({ number: r.number + 1, cursor: data.next_cursor }))}>Continue scanning</button> : null}
        {selected ? <aside className="ft-details" aria-label="Selected file observation">
          <h3 ref={detailsHeading} tabIndex={-1}>{selected.name || "File observation"}</h3>
          <dl>{Object.entries({ Path: selected.path, Action: selected.action,
            "Observed (UTC)": selected.observed_at, "Identity basis": selected.identity_basis,
            "SHA-256": selected.hashes?.sha256, "Source-stated process": selected.writer_image,
            "Process GUID": selected.writer_process_guid, "Process PID (not unique identity)": selected.writer_pid,
            "Evidence type": selected.evidence_type, "Observed image": selected.process_image, "Command line": selected.command_line, "Writer basis": selected.writer_basis, Signer: selected.signer,
            "Size (bytes)": selected.size, Source: selected.source,
            "Evidence reference": selected.evidence_ref, "Observation record": selected.record_id,
            Assessment: selected.assessment }).map(([label, value]) => <React.Fragment key={label}>
              <dt>{label}</dt><dd>{value ?? "Not observed"}{value === "" ? "Not observed" : ""}</dd>
            </React.Fragment>)}</dl>
          <Link to={trajectory}>{selected?.trajectory_url ? "Open matching event in Device Trajectory" : "Open Device Trajectory in this window"}</Link>
          <button className="btn" onClick={() => { setSelected(null); lastInspect.current?.focus(); }}>Close details</button>
        </aside> : null}
        </div>
      </> : null}
    </section>
  );
}

