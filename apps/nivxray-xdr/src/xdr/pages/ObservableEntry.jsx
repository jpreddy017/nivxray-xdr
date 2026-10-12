import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search } from "lucide-react";
import { useAccess } from "@/xdr/access/AccessProvider";

export const OBSERVABLE_TYPES = [
  ["hostname", "Hostname"], ["endpoint", "Endpoint ID"], ["sha256", "SHA-256"],
  ["ip", "IP address"], ["rule", "Rule ID"], ["incident", "Incident reference"],
  ["process", "Process name or ID"], ["evidence", "Evidence ID"],
];
export function observableError(type, value) {
  const term = value.trim();
  if (!OBSERVABLE_TYPES.some(([key]) => key === type)) return "This observable type has no supported search index.";
  if (!term) return "Enter an observable to search.";
  if (type === "sha256" && !/^[a-f0-9]{64}$/i.test(term)) return "Enter a SHA-256 hash containing 64 hexadecimal characters.";
  if (/^https?:\/\//i.test(term) || /^[^\s@]+@[^\s@]+$/.test(term)) return "URL and email searches are unavailable. Choose a supported identifier.";
  return null;
}
export const evidenceSearchHref = value => `/xdr/hunting?${new URLSearchParams({ q: value.trim() })}`;

export default function ObservableEntry() {
  const navigate = useNavigate();
  const access = useAccess();
  const allowed = access.can("threat_hunting.read");
  const [term, setTerm] = useState("");
  const [type, setType] = useState("hostname");
  const [error, setError] = useState(null);
  return <section className="cc-card" aria-labelledby="evidence-entry-title" style={{ marginTop: 16 }}>
    <div className="cc-card__h"><h2 id="evidence-entry-title" className="cc-card__t" style={{ margin: 0 }}>Search Evidence</h2></div>
    <div className="cc-card__b">
      <p id="observable-help" style={{ marginTop: 0 }}>Start with an observable. Search internal records across your authorized customers, then open a record in its existing workspace.</p>
      <form onSubmit={event => {
        event.preventDefault();
        if (allowed !== true) return;
        const issue = observableError(type, term);
        setError(issue);
        if (!issue) navigate(evidenceSearchHref(term));
      }} style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "end" }}>
        <label style={{ display: "grid", gap: 6 }}>Identifier type
          <select className="nx-btn" value={type} onChange={e => { setType(e.target.value); setError(null); }}>
            {OBSERVABLE_TYPES.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
          </select>
        </label>
        <label style={{ display: "grid", gap: 6, flex: "1 1 260px", minWidth: 0 }}>Observable
          <input value={term} onChange={e => { setTerm(e.target.value); setError(null); }}
            aria-describedby="observable-help observable-limits observable-feedback" aria-invalid={!!error}
            className="nx-btn" style={{ width: "100%", boxSizing: "border-box", textAlign: "left" }}
            placeholder="Enter an identifier…" data-testid="investigate-observable" />
        </label>
        <button className="nx-btn" type="submit" disabled={allowed !== true || !term.trim()}><Search size={14} aria-hidden="true" /> Search Evidence</button>
      </form>
      <p id="observable-feedback" role="status">{error || (allowed === false ? "Evidence search requires Hunting access." : allowed !== true ? "Evidence search authorization is unavailable." : "Results open in Hunting. No match is not a benign verdict.")}</p>
      <p id="observable-limits" style={{ color: "var(--nx-muted, var(--muted))", marginBottom: 0 }}>Domain, URL, email, identity and vulnerability searches are unavailable. Hostname search matches endpoint inventory; it does not search DNS telemetry. Search accepts identifiers, not a query language.</p>
    </div>
  </section>;
}
