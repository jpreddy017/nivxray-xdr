/**
 * ClosureTab · how this incident was concluded.
 *
 * Drives the real lifecycle endpoint (`PATCH /api/incidents/:id/state`)
 * with a mandatory note. Disposition and root cause are NOT structured
 * backend columns in this build — they are composed into the transition
 * note, and the tab says so instead of implying a schema that does not
 * exist.
 *
 * Rebuilt on `xdr/nx` form primitives: the legacy `rl-*` classes had no
 * stylesheet on these routes, which left the labels, the selects and the
 * closure note as unstyled text in a broken inline row.
 */
import React, { useState } from "react";
import { Check, Info, Loader2, TriangleAlert } from "lucide-react";

import { transitionIncidentState, LIFECYCLE_TRANSITIONS }
  from "@/lib/incidentsApi";
import { apiErrorText } from "@/xdr/nx/apiError";
import "@/xdr/nx/nx-form.css";

const CLOSURE_DISPOSITIONS = [
  "TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_TRUE_POSITIVE",
  "INFORMATIONAL", "DUPLICATE",
];

const ROOT_CAUSES = [
  "USER_ACTION", "PHISHING", "COMPROMISED_ACCOUNT", "MALWARE",
  "MISCONFIGURATION", "POLICY_VIOLATION", "AUTHORIZED_ACTIVITY", "OTHER",
];

const pretty = (v) => String(v || "").replace(/_/g, " ");

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
      setErr("A closure note is required — the transition is recorded with it.");
      return;
    }
    setBusy(target); setErr(null); setOk(null);
    const parts = [];
    if (disposition) parts.push(`disposition=${disposition}`);
    if (rootCause)   parts.push(`root_cause=${rootCause}`);
    parts.push(`note=${note.trim()}`);
    try {
      const updated = await transitionIncidentState(incident.id, target,
        parts.join(" · "));
      onUpdated?.(updated);
      setOk(`Incident marked ${target.toUpperCase()}.`);
      setNote("");
    } catch (e) {
      setErr(e?.response?.data?.detail?.error
        || apiErrorText(e, "The transition was refused."));
    } finally { setBusy(null); }
  };

  const stateNote = state === "closed"
    ? "This incident is closed."
    : state === "resolved"
      ? "This incident is resolved — closure is available."
      : "Record a disposition, a root cause and a note to conclude it.";

  return (
    <div data-testid="xdr-record-closure">
      <div className="nx-actions" style={{ paddingBottom: 0 }}>
        <span className="nx-label">Current lifecycle state</span>
        <span className="inv-chip" style={{ cursor: "default",
                fontWeight: 800 }}
              data-testid="xdr-record-closure-state">
          {pretty(state).toUpperCase()}
        </span>
        <span className="nx-help">{stateNote}</span>
      </div>

      <div className="nx-form nx-form--2">
        <div className="nx-field">
          <label className="nx-label" htmlFor="xdr-closure-disposition">
            Disposition
          </label>
          <select id="xdr-closure-disposition" className="nx-select"
                  value={disposition}
                  onChange={(e) => setDisposition(e.target.value)}
                  data-testid="xdr-record-closure-disposition">
            <option value="">Select a disposition…</option>
            {CLOSURE_DISPOSITIONS.map((d) => (
              <option key={d} value={d}>{pretty(d)}</option>
            ))}
          </select>
        </div>

        <div className="nx-field">
          <label className="nx-label" htmlFor="xdr-closure-root-cause">
            Root cause
          </label>
          <select id="xdr-closure-root-cause" className="nx-select"
                  value={rootCause}
                  onChange={(e) => setRootCause(e.target.value)}
                  data-testid="xdr-record-closure-root-cause">
            <option value="">Select a root cause…</option>
            {ROOT_CAUSES.map((r) => (
              <option key={r} value={r}>{pretty(r)}</option>
            ))}
          </select>
        </div>

        <div className="nx-field nx-field--wide">
          <label className="nx-label" htmlFor="xdr-closure-note">
            Closure note<span className="nx-req">*</span>
          </label>
          <textarea id="xdr-closure-note" className="nx-textarea"
                    placeholder="Investigation outcome, containment actions taken, evidence considered, anything the next analyst must know…"
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    data-testid="xdr-record-closure-note" />
          <span className="nx-help">
            The note is mandatory: it is what the platform records on the
            transition.
          </span>
        </div>
      </div>

      <div className="nx-alert" data-testid="xdr-record-closure-contract">
        <Info size={13} style={{ flex: "0 0 auto", marginTop: 2 }} />
        <span>
          Disposition and root cause are <b>not structured columns</b> in this
          build — they are composed into the transition note exactly as shown,
          and nothing else about them is stored or reported.
        </span>
      </div>

      {err && (
        <div className="nx-alert nx-alert--error" style={{ marginTop: 10 }}
             data-testid="xdr-record-closure-error">
          <TriangleAlert size={13} style={{ flex: "0 0 auto", marginTop: 2 }} />
          <span>{String(err)}</span>
        </div>
      )}
      {ok && (
        <div className="nx-alert nx-alert--ok" style={{ marginTop: 10 }}
             data-testid="xdr-record-closure-ok">
          <Check size={13} style={{ flex: "0 0 auto", marginTop: 2 }} />
          <span>{ok}</span>
        </div>
      )}

      <div className="nx-actions">
        <button type="button" className="nx-btn"
                disabled={!canResolve || !!busy}
                onClick={() => submit("resolved")}
                data-testid="xdr-record-closure-resolve"
                title={canResolve ? "Mark this incident resolved"
                  : `Not reachable from ${pretty(state).toUpperCase()}`}>
          {busy === "resolved" && <Loader2 size={12} className="rl-spin" />}
          Mark Resolved
        </button>
        <button type="button" className="nx-btn nx-btn--primary"
                disabled={!canClose || !!busy}
                onClick={() => submit("closed")}
                data-testid="xdr-record-closure-close"
                title={canClose ? "Close this incident"
                  : `Not reachable from ${pretty(state).toUpperCase()}`}>
          {busy === "closed" && <Loader2 size={12} className="rl-spin" />}
          Close Incident
        </button>
        {!canResolve && !canClose && (
          <span className="nx-help">
            No lifecycle transition is available from{" "}
            {pretty(state).toUpperCase()}.
          </span>
        )}
      </div>
    </div>
  );
}
