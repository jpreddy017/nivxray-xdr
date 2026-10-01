/**
 * ClosureTab · Layer 3.
 *
 * Prepares the closure workspace: shows the four-state lifecycle
 * position, the state-history transcript, and a Closure form that
 * (a) invokes the existing /api/incidents/:id/state PATCH endpoint
 * to record a resolved/closed transition with a mandatory note.
 * The Phase-3 policy engine will later require closure reasons,
 * dispositions and root-cause tagging; the UI is designed with those
 * fields present but tolerant when the backend does not yet enforce
 * them.
 */
import React, { useState } from "react";
import { Check, Loader2 } from "lucide-react";

import { transitionIncidentState, LIFECYCLE_TRANSITIONS }
  from "@/lib/incidentsApi";

const CLOSURE_DISPOSITIONS = [
  "TRUE_POSITIVE",
  "FALSE_POSITIVE",
  "BENIGN_TRUE_POSITIVE",
  "INFORMATIONAL",
  "DUPLICATE",
];

const ROOT_CAUSES = [
  "USER_ACTION",       "PHISHING",        "COMPROMISED_ACCOUNT",
  "MALWARE",           "MISCONFIGURATION","POLICY_VIOLATION",
  "AUTHORIZED_ACTIVITY","OTHER",
];

export default function ClosureTab({ incident, onUpdated }) {
  const state = incident.state || "new";
  const canResolve = LIFECYCLE_TRANSITIONS[state]?.includes("resolved");
  const canClose   = LIFECYCLE_TRANSITIONS[state]?.includes("closed");

  const [disposition, setDisposition] = useState("");
  const [rootCause, setRootCause]     = useState("");
  const [note, setNote]               = useState("");
  const [busy, setBusy]               = useState(null);
  const [err, setErr]                 = useState(null);
  const [ok, setOk]                   = useState(null);

  const submit = async (target) => {
    if (busy) return;
    if (!note.trim()) {
      setErr("Please provide a closure note before resolving/closing.");
      return;
    }
    setBusy(target); setErr(null); setOk(null);
    // Include disposition + root cause in the note so they persist
    // as free-text context until Phase-3 promotes them to structured
    // fields.  Zero backend fabrication — the backend just stores
    // whatever note we send.
    const parts = [];
    if (disposition) parts.push(`disposition=${disposition}`);
    if (rootCause)   parts.push(`root_cause=${rootCause}`);
    parts.push(`note=${note.trim()}`);
    const composedNote = parts.join(" · ");
    try {
      const updated = await transitionIncidentState(incident.id, target, composedNote);
      onUpdated?.(updated);
      setOk(`Incident marked ${target.toUpperCase()}.`);
      setNote("");
    } catch (e) {
      setErr(e?.response?.data?.detail?.error
        || e?.response?.data?.detail
        || e?.message || "Closure failed.");
    } finally { setBusy(null); }
  };

  return (
    <div data-testid="xdr-record-closure">
      <div className="rl-section">
        <div className="rl-section-title">Current lifecycle state</div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span className="rl-state ok" style={{ padding: "3px 9px", fontSize: 11 }}>
            {(state || "new").toUpperCase().replace("_", " ")}
          </span>
          <span style={{ fontSize: 11.5, color: "var(--rl-muted)" }}>
            {state === "closed"
              ? "This incident has been closed."
              : state === "resolved"
                ? "This incident is resolved · closure is available."
                : "Choose a disposition and root cause below to close."}
          </span>
        </div>
      </div>

      <div className="rl-section">
        <div className="rl-section-title">Closure inputs (Phase-3 preview)</div>
        <div className="rl-kv" style={{ gap: 10 }}>
          <span className="k">Disposition</span>
          <select
            className="rl-btn"
            style={{ padding: "5px 8px", background: "var(--rl-surface)",
                     color: "var(--rl-text)", fontWeight: 500 }}
            value={disposition}
            onChange={e => setDisposition(e.target.value)}
            data-testid="xdr-record-closure-disposition"
          >
            <option value="">Select…</option>
            {CLOSURE_DISPOSITIONS.map(d => (
              <option key={d} value={d}>{d.replace(/_/g, " ")}</option>
            ))}
          </select>

          <span className="k">Root cause</span>
          <select
            className="rl-btn"
            style={{ padding: "5px 8px", background: "var(--rl-surface)",
                     color: "var(--rl-text)", fontWeight: 500 }}
            value={rootCause}
            onChange={e => setRootCause(e.target.value)}
            data-testid="xdr-record-closure-root-cause"
          >
            <option value="">Select…</option>
            {ROOT_CAUSES.map(r => (
              <option key={r} value={r}>{r.replace(/_/g, " ")}</option>
            ))}
          </select>

          <span className="k">Closure note</span>
          <textarea
            className="rl-note-input"
            style={{ minHeight: 90 }}
            placeholder="Summarise investigation outcome, containment actions, evidence considered…"
            value={note}
            onChange={e => setNote(e.target.value)}
            data-testid="xdr-record-closure-note"
          />
        </div>
        <div style={{ fontSize: 10.5, color: "var(--rl-faint)",
                        fontFamily: "var(--rs-mono)", marginTop: 8 }}>
          Disposition + root cause are stored in the transition note
          until Phase 3 promotes them to structured columns.
        </div>
      </div>

      <div className="rl-section">
        <div className="rl-section-title">Actions</div>
        {err && <div className="rl-error" data-testid="xdr-record-closure-error">{String(err)}</div>}
        {ok  && <div className="rl-state ok" style={{ padding: "6px 10px",
                                                          display: "inline-block",
                                                          fontFamily: "var(--rs-sans)",
                                                          fontSize: 12 }}
                      data-testid="xdr-record-closure-ok">
          <Check size={12} style={{ display: "inline", verticalAlign: "-2px", marginRight: 4 }} />
          {ok}
        </div>}
        <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
          <button
            type="button"
            className="rl-btn"
            disabled={!canResolve || !!busy}
            onClick={() => submit("resolved")}
            data-testid="xdr-record-closure-resolve"
            title={canResolve ? "Mark incident resolved" : "Not reachable from current state"}
          >
            {busy === "resolved" && <Loader2 size={12} className="rl-spin" />}
            Mark Resolved
          </button>
          <button
            type="button"
            className="rl-btn primary"
            disabled={!canClose || !!busy}
            onClick={() => submit("closed")}
            data-testid="xdr-record-closure-close"
            title={canClose ? "Close incident" : "Not reachable from current state"}
          >
            {busy === "closed" && <Loader2 size={12} className="rl-spin" />}
            Close Incident
          </button>
        </div>
      </div>
    </div>
  );
}
