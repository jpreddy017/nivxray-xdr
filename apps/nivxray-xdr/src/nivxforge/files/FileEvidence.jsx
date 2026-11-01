import React, { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { getFileObservations } from "./fileEvidenceApi";
import { TENANT_BOUND_EVENT } from "@/lib/tenant";
import "./file-evidence.css";

const day = 86400000;
const iso = (ms) => new Date(ms).toISOString().slice(0, 16);
const utcMillis = (text) => Date.parse(`${text}:00Z`);
const validMillis = (value) => Number.isFinite(value) && value > 0 && value <= 253402300799000;

export default function FileEvidence({ endpointId }) {
  const [params, setParams] = useSearchParams();
  const [end] = useState(() => Math.floor(Date.now() / 60000) * 60000);
  const startParam = Number(params.get("t0")), endParam = Number(params.get("t1"));
  const [start, setStart] = useState(() => iso(validMillis(startParam) ? startParam : end - 30 * day));
  const [finish, setFinish] = useState(() => iso(validMillis(endParam) ? endParam : end));
  const [kind, setKind] = useState(() => params.get("file_key_type") || "path");
  const [key, setKey] = useState(() => params.get("file_key") || "");
  const [query, setQuery] = useState(null);
  const [rows, setRows] = useState([]), [data, setData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState(""), [busy, setBusy] = useState(false);
  const [request, setRequest] = useState({ number: 0, cursor: null });
  const generation = useRef(0);

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
    const a = utcMillis(start), b = utcMillis(finish);
    if (!Number.isFinite(a) || !Number.isFinite(b) || a >= b || b - a > 31 * day) {
      setError("Choose an increasing UTC window of at most 31 days."); return;
    }
    if (kind === "sha256" && key && !/^[a-f0-9]{64}$/i.test(key)) {
      setError("Enter a complete SHA-256 content hash."); return;
    }
    generation.current += 1;
    setRows([]); setData(null); setSelected(null); setError("");
    setQuery({ endpoint_id: endpointId, time_start: a, time_end: b,
               key_type: kind, key, limit: 100 });
    setRequest((r) => ({ number: r.number + 1, cursor: null }));
    const next = new URLSearchParams(params);
    next.set("t0", String(a)); next.set("t1", String(b));
    next.set("file_key_type", kind);
    if (key) next.set("file_key", key); else next.delete("file_key");
    setParams(next, { replace: true });
  };

  useEffect(() => {
    if (!query) return undefined;
    const controller = new AbortController();
    const ticket = generation.current;
    setBusy(true); setError("");
    getFileObservations({ ...query, cursor: request.cursor || undefined }, controller.signal)
      .then((value) => {
        if (controller.signal.aborted || ticket !== generation.current) return;
        setData(value);
        setRows((old) => request.cursor ? [...old, ...(value.observations || [])] : value.observations || []);
      })
      .catch((e) => {
        if (controller.signal.aborted || ticket !== generation.current) return;
        setError(e.response?.status === 403 ? "You are not authorized to view this endpoint's evidence."
          : e.response?.status === 404 ? "This backend does not yet provide File Trajectory."
          : e.response?.data?.detail || "File evidence could not be loaded. Retry the request.");
      })
      .finally(() => { if (!controller.signal.aborted && ticket === generation.current) setBusy(false); });
    return () => controller.abort();
  }, [query, request]);

  const trajectory = query ? `/edr/computers/${encodeURIComponent(endpointId)}/trajectory?t0=${query.time_start}&t1=${query.time_end}` : "";
  return (
    <section className="ft-evidence" aria-label="File Trajectory" data-testid="edr-file-evidence">
      <h2>File Trajectory</h2>
      <p>Recorded file activity for this computer. This view does not enumerate its current disk contents.</p>
      <form className="ft-query" onSubmit={(e) => { e.preventDefault(); load(); }}>
        <label>Start (UTC)<input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} required /></label>
        <label>End (UTC, exclusive)<input type="datetime-local" value={finish} onChange={(e) => setFinish(e.target.value)} required /></label>
        <label>Match by<select value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="path">Exact path</option><option value="name">Exact name</option><option value="sha256">SHA-256 content hash</option>
        </select></label>
        <label className="ft-key">File filter (optional)<input value={key} maxLength={4096} onChange={(e) => setKey(e.target.value)} placeholder="Leave empty to inspect recorded files" /></label>
        <button className="btn" type="submit" disabled={!endpointId}>Search observations</button>
      </form>
      {error ? <div role="alert" className="ft-error">{String(error)}</div> : null}
      {busy ? <p role="status">Reading file evidence…</p> : null}
      {data?.state === "ENDPOINT_NOT_RESOLVED" ? <p role="alert">Endpoint identity or permission could not be resolved. This is not an empty file history.</p> : null}
      {data && data.state !== "ENDPOINT_NOT_RESOLVED" ? <>
        <p role="status">{rows.length} observations loaded · {data.complete ? "scan reached the end" : "more source records remain"}.</p>
        <p>Coverage has not been proven. A missing hash is unknown; no detection verdict is inferred. Records appear in receipt-record order, not event-time order.</p>
        {!rows.length ? <p>{data.next_cursor ? "No file matches in this scan page. Continue scanning before concluding there are no matches."
          : "No matching file observations found in the scanned records. This does not prove that no file activity occurred."}</p> : null}
        {Object.keys(data.issues || {}).length ? <p>Some file records have unresolved timestamps and were excluded from this time-window view.</p> : null}
        <div className="ft-table-wrap"><table>
          <caption>File observations within the selected UTC window</caption>
          <thead><tr><th>Observed (UTC)</th><th>File / path</th><th>Action</th><th>Content identity</th><th>Details</th></tr></thead>
          <tbody>{rows.map((row) => <tr key={row.record_id}>
            <td>{row.observed_at}</td><td className="ft-path">{row.path}</td><td>{row.action || "Not reported"}</td>
            <td>{row.hashes?.sha256 || (Object.keys(row.hashes || {}).length ? "Other source hash" : "Hash not observed")}</td>
            <td><button className="btn" onClick={() => setSelected(row)} aria-label={`Inspect ${row.name || row.path}`}>Inspect</button></td>
          </tr>)}</tbody>
        </table></div>
        {data.next_cursor ? <button className="btn" disabled={busy} onClick={() => setRequest((r) => ({ number: r.number + 1, cursor: data.next_cursor }))}>Continue scanning</button> : null}
        {selected ? <aside className="ft-details" aria-label="Selected file observation">
          <h3>{selected.name || "File observation"}</h3>
          <dl>{Object.entries({ Path: selected.path, Action: selected.action,
            "Observed (UTC)": selected.observed_at, "Identity basis": selected.identity_basis,
            "SHA-256": selected.hashes?.sha256, "Source-stated process": selected.writer_image,
            "Process GUID": selected.writer_process_guid, "Process PID (not unique identity)": selected.writer_pid,
            "Writer basis": selected.writer_basis, Signer: selected.signer,
            "Size (bytes)": selected.size, Source: selected.source,
            "Evidence reference": selected.evidence_ref, "Observation record": selected.record_id,
            Assessment: selected.assessment }).map(([label, value]) => <React.Fragment key={label}>
              <dt>{label}</dt><dd>{value ?? "Not observed"}{value === "" ? "Not observed" : ""}</dd>
            </React.Fragment>)}</dl>
          <Link to={trajectory}>Open Device Trajectory in this window</Link>
          <button className="btn" onClick={() => setSelected(null)}>Close details</button>
        </aside> : null}
      </> : null}
    </section>
  );
}
