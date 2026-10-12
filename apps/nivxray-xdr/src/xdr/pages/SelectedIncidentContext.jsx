import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getIncident, getIncidentCanonicalEvidence } from "@/lib/incidentsApi";
import { activeTenant, TENANT_BOUND_EVENT } from "@/lib/tenant";
import NxFlyout from "@/xdr/nx/NxFlyout";

const absent = "Not recorded";
export const incidentTabHref = (id, tab) => `/xdr/incidents/${encodeURIComponent(id)}?tab=${tab}`;
const denied = (error) => [401, 403, 404].includes(error?.response?.status);

// Only the selected incident is read; endpoint authorization remains authoritative.
export async function readIncidentContext(id) {
  try {
    const incident = await getIncident(id);
    if (incident?.id !== id) return { state: "unavailable" };
    try {
      const evidence = await getIncidentCanonicalEvidence(id);
      if (evidence?.incident_id !== id || !Array.isArray(evidence.rows)) return { state: "ready", incident, evidenceState: "unavailable" };
      return { state: "ready", incident, evidenceState: "ready", evidence };
    } catch (error) {
      if (denied(error)) return { state: "denied" };
      return { state: "ready", incident, evidenceState: "error" };
    }
  } catch (error) { return { state: denied(error) ? "denied" : "error" }; }
}

export function requestIncidentContext(id, publish) {
  let live = true;
  const tenant = activeTenant();
  readIncidentContext(id).then((value) => {
    if (live && activeTenant() === tenant) publish(value);
  });
  return () => { live = false; };
}

export function IncidentContextDetails({ result, id }) {
  if (result.state !== "ready") return <p role={result.state === "loading" ? "status" : "alert"}>
    {{ loading: "Loading selected incident…", denied: "Selected incident is not available to this session. No incident details are shown.", error: "Selected incident could not load. Close and preview again to retry.", unavailable: "Selected incident data is not available." }[result.state]}</p>;
  const { incident, evidence, evidenceState } = result;
  return <>
    <dl className="cc-context__facts">
      <dt>Incident ID</dt><dd>{id}</dd>
      <dt>Priority</dt><dd>{incident.priority?.label || incident.priority || absent}</dd>
      <dt>Status</dt><dd>{incident.state?.replace(/_/g, " ") || absent}</dd>
      <dt>Tenant</dt><dd>{incident.tenant || absent}</dd>
      <dt>Reported owner</dt><dd>{incident.assignee || absent}</dd>
      <dt>Updated</dt><dd>{incident.updated_at || absent}</dd>
    </dl>
    <section aria-labelledby="cc-context-evidence"><h3 id="cc-context-evidence">Evidence context</h3>
      {evidenceState === "ready" ? <>
        <p>{evidence.rows.length ? `${evidence.rows.length} canonical evidence reference(s) returned.` : "No canonical evidence references returned."}</p>
        <p className="cc-context__hint">References can include unavailable records. Open Evidence to inspect record availability and provenance.</p>
      </> : <p role="status">{evidenceState === "error" ? "Evidence context could not load." : "Evidence context is not available."}</p>}
    </section>
    <nav className="cc-context__pivots" aria-label="Selected incident investigation views">
      {["story", "timeline", "evidence"].map((tab) => <Link key={tab} className="cc-pq__open" to={incidentTabHref(id, tab)}>Open {tab[0].toUpperCase() + tab.slice(1)}</Link>)}
    </nav>
    <p className="cc-context__hint">Read-only snapshot. Investigation views load the current authorized record. Closing this preview preserves queue search, sort and page.</p>
  </>;
}

export default function SelectedIncidentContext({ id, onClose }) {
  const [result, setResult] = useState({ state: "loading" });
  const [loadedId, setLoadedId] = useState(null);
  useEffect(() => {
    let live = true;
    const tenant = activeTenant();
    setResult({ state: "loading" }); setLoadedId(null);
    const clear = () => { live = false; setResult({ state: "loading" }); setLoadedId(null); onClose(); };
    const storage = (event) => { if (["nvx_tenant", "nvx_token", null].includes(event.key)) clear(); };
    const scopeTimer = setInterval(() => { if (activeTenant() !== tenant) clear(); }, 250);
    window.addEventListener(TENANT_BOUND_EVENT, clear);
    window.addEventListener("storage", storage);
    const cancel = requestIncidentContext(id, (value) => {
      if (live) { setLoadedId(id); setResult(value); }
    });
    return () => { live = false; cancel(); clearInterval(scopeTimer); window.removeEventListener(TENANT_BOUND_EVENT, clear); window.removeEventListener("storage", storage); };
  }, [id, onClose]);
  const current = loadedId === id ? result : { state: "loading" };
  return <NxFlyout open manageFocus onClose={onClose} title={current.state === "ready" ? current.incident.name || "Selected incident" : "Selected incident"}
    eyebrow="Investigation context" width={480} testid="cc-incident-context">
    <div className="cc-context" aria-busy={current.state === "loading"}><IncidentContextDetails result={current} id={id} /></div>
  </NxFlyout>;
}
