/**
 * NivXForge EDR · Response Verification (P0-F.6).
 *
 * This panel is an EVIDENCE surface, not a success indicator. It renders
 * the authoritative `edr_response_commands` record produced by P0-F.5 and
 * holds no opinion of its own: the "what does this prove?" verdict comes
 * from the backend (`proof`), so an EXECUTED command cannot be painted as
 * a completed one here or anywhere else.
 *
 * Three honesty rules:
 *   1. Only VERIFIED backed by a post-action probe is shown as proven.
 *      EXECUTED renders as A SENSOR CLAIM.
 *   2. A row marked VERIFIED with no probe is an INTEGRITY FAULT, shown
 *      as an alarm — never as a success.
 *   3. Anything the response plane does not capture (approval, policy)
 *      renders ⊘ with the reason. It is never left blank and never
 *      invented.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, ChevronDown, ChevronRight, ChevronsDown,
         ChevronsUp } from "lucide-react";
import api from "@/lib/api";

const STATE_EP = {
  VERIFIED: "evidence_present",
  EXECUTED: "unknown",
  DISPATCHED: "unknown",
  REQUESTED: "no_evidence",
  VERIFICATION_FAILED: "capability_unavailable",
  FAILED: "capability_unavailable",
  CAPABILITY_UNAVAILABLE: "capability_unavailable",
  REFUSED: "capability_unavailable",
};

const NOT_REPORTED = "◇ not reported";

const Field = ({ label, value, note, testid, wide }) => (
  <div data-testid={testid} style={{ minWidth: wide ? 320 : 150,
                                     maxWidth: wide ? 620 : 260 }}>
    <div style={{ color: "var(--faint)", fontSize: 8.5, fontWeight: 800,
                  letterSpacing: ".4px", textTransform: "uppercase" }}>
      {label}
    </div>
    <div className="mono" style={{
      fontSize: 10, marginTop: 2, wordBreak: "break-all", lineHeight: 1.5,
      color: value === null || value === undefined || value === ""
        ? "var(--faint)" : "var(--text)" }}>
      {value === null || value === undefined || value === ""
        ? NOT_REPORTED : String(value)}
    </div>
    {note && (
      <div style={{ color: "#8C5A5A", fontSize: 9, marginTop: 2,
                    lineHeight: 1.5 }}>{note}</div>
    )}
  </div>
);

const Block = ({ title, children, testid }) => (
  <div data-testid={testid} style={{ marginTop: 12 }}>
    <div style={{ fontSize: 8.5, fontWeight: 800, letterSpacing: ".6px",
                  textTransform: "uppercase", color: "var(--cyan)",
                  borderBottom: "1px solid #17202A", paddingBottom: 4 }}>
      {title}
    </div>
    <div style={{ display: "flex", gap: 18, flexWrap: "wrap",
                  marginTop: 8 }}>{children}</div>
  </div>
);

const Stat = ({ label, value, ep, testid }) => (
  <div data-testid={testid}>
    <div style={{ color: "var(--faint)", fontSize: 8.5, fontWeight: 800,
                  textTransform: "uppercase", letterSpacing: ".4px" }}>
      {label}
    </div>
    <span className="nx-ep" data-ep={ep} data-known="true"
          style={{ fontSize: 11, marginTop: 3, display: "inline-block" }}>
      {value}
    </span>
  </div>
);

function Timeline({ history }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {(history || []).map((h, i) => (
        <div key={i} data-testid={`edr-response-history-${i}`}
             style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
          <span className="nx-ep" data-ep={STATE_EP[h.state] || "unknown"}
                data-known="true" style={{ fontSize: 9, minWidth: 168 }}>
            {h.state}
          </span>
          <span className="mono" style={{ fontSize: 9.5,
                                          color: "var(--text-dim)" }}>
            {h.at}
          </span>
          <span className="mono" style={{ fontSize: 9.5,
                                          color: "var(--cyan)" }}>
            {h.actor || NOT_REPORTED}
          </span>
          {h.reason && (
            <span style={{ fontSize: 9.5, color: "var(--faint)",
                           lineHeight: 1.5 }}>{h.reason}</span>
          )}
        </div>
      ))}
    </div>
  );
}

function ActionRecord({ r }) {
  const t = r.target || {};
  const sensor = r.sensor_result || null;
  const v = r.verification || null;
  const probe = (v && v.probe) || null;
  return (
    <div data-testid={`edr-response-record-${r.command_id}`}
         style={{ padding: "4px 10px 16px", background: "#080C10",
                  borderTop: "1px solid #141C24" }}>
      <Block title="Authorisation" testid={`edr-response-auth-${r.command_id}`}>
        <Field label="Requested by" value={r.requested_by}
               testid={`edr-response-requested-by-${r.command_id}`} />
        <Field label="Approved by" value=""
               note="⊘ NO APPROVAL STEP EXISTS in this response plane yet — this action was authorised by the requester's own permissions only."
               testid={`edr-response-approved-by-${r.command_id}`} wide />
        <Field label="Policy / playbook" value=""
               note="⊘ NO POLICY BOUND — this command was raised directly, not by an automated response policy."
               testid={`edr-response-policy-${r.command_id}`} wide />
        <Field label="Reason given" value={r.reason} wide
               testid={`edr-response-reason-${r.command_id}`} />
      </Block>

      {r.action === "KILL_PROCESS" ? (
        <Block title="Target process identity"
               testid={`edr-response-target-${r.command_id}`}>
          <Field label="Endpoint" value={r.endpoint_id}
                 testid={`edr-response-endpoint-${r.command_id}`} />
          <Field label="PID" value={t.pid}
                 testid={`edr-response-pid-${r.command_id}`} />
          <Field label="Start ticks (identity)" value={t.observed_start_ticks}
                 note={t.observed_start_ticks === undefined
                   ? "a pid without a start identity cannot name a process"
                   : null}
                 testid={`edr-response-start-ticks-${r.command_id}`} />
          <Field label="Identity basis" value={t.identity_basis}
                 testid={`edr-response-identity-basis-${r.command_id}`} />
          <Field label="Start time" value={t.observed_start_time} />
          <Field label="Image path" value={t.observed_image_path} wide />
          <Field label="Command line" value={t.observed_command_line} wide
                 testid={`edr-response-cmdline-${r.command_id}`} />
          <Field label="User" value={t.observed_user} />
          <Field label="Process iid" value={t.process_iid} />
          <Field label="Raw evidence" value={t.evidence_raw_id} />
          <Field label="Canonical evidence"
                 value={t.evidence_canonical_event_id} />
        </Block>
      ) : (
        <Block title="Target" testid={`edr-response-target-${r.command_id}`}>
          <Field label="Endpoint" value={r.endpoint_id}
                 testid={`edr-response-endpoint-${r.command_id}`} />
          <div style={{ alignSelf: "center" }}>
            <span className="nx-ep" data-ep="unknown" data-known="true"
                  style={{ fontSize: 9.5 }}
                  data-testid={`edr-response-not-process-${r.command_id}`}>
              ⊘ NOT A PROCESS ACTION — this action targets the endpoint
              itself, so there is no process identity to bind
            </span>
          </div>
        </Block>
      )}

      <Block title="Lifecycle · every transition, actor and timestamp"
             testid={`edr-response-lifecycle-${r.command_id}`}>
        <Timeline history={r.history} />
      </Block>

      <Block title="Sensor claim (NOT proof)"
             testid={`edr-response-sensor-${r.command_id}`}>
        {sensor ? (
          <>
            <Field label="Outcome reported" value={sensor.outcome} />
            <Field label="At" value={sensor.at} />
            <Field label="Detail" value={sensor.detail} wide />
            <Field label="Sensor evidence"
                   value={JSON.stringify(sensor.evidence || {})} wide />
          </>
        ) : (
          <span className="nx-ep" data-ep="no_evidence" data-known="true"
                style={{ fontSize: 9.5 }}>
            ◇ THE ENDPOINT HAS REPORTED NOTHING
          </span>
        )}
      </Block>

      <Block title="Independent verification · post-action endpoint evidence"
             testid={`edr-response-verification-${r.command_id}`}>
        {v ? (
          <>
            <Field label="Method" value={v.method}
                   testid={`edr-response-verify-method-${r.command_id}`} />
            <Field label="At" value={v.at} />
            <Field label="Finding" value={v.finding} wide
                   testid={`edr-response-finding-${r.command_id}`} />
            {probe && Object.entries(probe)
              .filter(([k]) => k !== "method" && k !== "detail")
              .map(([k, val]) => (
                <Field key={k} label={k.replace(/_/g, " ")}
                       value={val === null
                         ? "∅ nothing at that pid to read"
                         : String(val)}
                       testid={`edr-response-probe-${k}-${r.command_id}`} />
              ))}
          </>
        ) : (
          <span className="nx-ep" data-ep="capability_unavailable"
                data-known="true" style={{ fontSize: 9.5 }}>
            ⊘ NO POST-ACTION EVIDENCE — nothing about the effect is proven
          </span>
        )}
      </Block>

      <Block title="Final result" testid={`edr-response-result-${r.command_id}`}>
        <div>
          <span className="nx-ep"
                data-ep={r.proof?.integrity_alarm ? "capability_unavailable"
                  : r.proof?.success_claimed ? "evidence_present" : "unknown"}
                data-known="true" style={{ fontSize: 10.5 }}
                data-testid={`edr-response-proof-${r.command_id}`}>
            {r.proof?.integrity_alarm && (
              <AlertTriangle size={10} style={{ marginRight: 4,
                                                verticalAlign: -1 }} />
            )}
            {r.proof?.proof || "UNKNOWN"}
          </span>
          <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6,
                        maxWidth: 760, lineHeight: 1.6 }}>
            {r.proof?.meaning}
          </div>
          <div className="mono" style={{ fontSize: 9, color: "var(--cyan)",
                                         marginTop: 6 }}>
            command_id {r.command_id} · engine {r.engine_id || NOT_REPORTED}
          </div>
        </div>
      </Block>
    </div>
  );
}

export default function EdrResponseBody({ refreshNonce = 0 }) {
  const [data, setData] = useState(null);
  const [endpoint, setEndpoint] = useState("");
  const [stateFilter, setStateFilter] = useState("");
  const [open, setOpen] = useState({});
  const [err, setErr] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadedAt, setLoadedAt] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    return api.get("/edr/response/actions"
                   + (endpoint ? `?endpoint_id=${endpoint}` : ""))
      .then(({ data: d }) => {
        setData(d); setErr(null); setLoadedAt(new Date().toISOString());
      })
      .catch((x) => setErr(x?.response?.data?.detail?.reason
                           || x?.message || String(x)))
      .finally(() => setLoading(false));
  }, [endpoint]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (refreshNonce) load(); }, [refreshNonce, load]);

  const rows = useMemo(
    () => (data?.commands || []).filter(
      (r) => !stateFilter || r.state === stateFilter),
    [data, stateFilter]);

  const anyOpen = Object.values(open).some(Boolean);
  const masterToggle = () => setOpen(anyOpen ? {}
    : Object.fromEntries(rows.map((r) => [r.command_id, true])));

  if (err) {
    return (
      <div style={{ padding: 14 }} data-testid="edr-response-error">
        <span className="nx-ep" data-ep="capability_unavailable"
              data-known="true">⊘ RESPONSE RECORD UNREACHABLE</span>
        <div style={{ marginTop: 6, fontSize: 10.5, color: "var(--faint)" }}>
          {err} — no action state is shown rather than a stale one.
        </div>
      </div>
    );
  }
  if (!data) {
    return <div style={{ padding: 14, fontSize: 11, color: "var(--faint)" }}
                data-testid="edr-response-loading">
             Reading the response record…
           </div>;
  }

  const st = data.by_state || {};
  const awaiting = (st.EXECUTED || 0) + (st.DISPATCHED || 0);

  return (
    <div style={{ padding: "10px 12px 20px" }} data-testid="edr-response">
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap",
                    alignItems: "center", marginBottom: 12 }}>
        <Stat label="Actions on record" value={data.count}
              ep={data.count ? "evidence_present" : "no_evidence"}
              testid="edr-response-total" />
        <Stat label="Verified by evidence" value={data.verified_count || 0}
              ep={data.verified_count ? "evidence_present" : "no_evidence"}
              testid="edr-response-verified" />
        <Stat label="Claimed, not verified" value={awaiting}
              ep={awaiting ? "unknown" : "no_evidence"}
              testid="edr-response-awaiting" />
        <Stat label="Refused / failed"
              value={(st.FAILED || 0) + (st.VERIFICATION_FAILED || 0)
                     + (st.REFUSED || 0)}
              ep="capability_unavailable" testid="edr-response-failed" />
        <Stat label="Capability unavailable"
              value={st.CAPABILITY_UNAVAILABLE || 0}
              ep="capability_unavailable" testid="edr-response-unavailable" />
        <Stat label="Integrity alarms" value={data.integrity_alarms || 0}
              ep={data.integrity_alarms ? "capability_unavailable"
                                        : "evidence_present"}
              testid="edr-response-integrity-alarms" />
      </div>

      <div style={{ display: "flex", gap: 8, alignItems: "center",
                    flexWrap: "wrap", marginBottom: 10 }}>
        <input className="mono" value={endpoint} placeholder="endpoint_id filter"
               onChange={(e) => setEndpoint(e.target.value.trim())}
               data-testid="edr-response-endpoint-filter"
               style={{ background: "#0C1116", border: "1px solid #212B36",
                        color: "var(--text)", padding: "5px 9px",
                        fontSize: 10.5, borderRadius: 3, width: 260 }} />
        <select className="mono" value={stateFilter}
                onChange={(e) => setStateFilter(e.target.value)}
                data-testid="edr-response-state-filter"
                style={{ background: "#0C1116", border: "1px solid #212B36",
                         color: "var(--text)", padding: "5px 9px",
                         fontSize: 10.5, borderRadius: 3 }}>
          <option value="">all lifecycle states</option>
          {Object.keys(STATE_EP).map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <button className="btn ghost" onClick={masterToggle}
                data-testid="edr-response-master-toggle"
                data-state={anyOpen ? "expanded" : "collapsed"}
                style={{ fontSize: 10, padding: "4px 9px" }}>
          {anyOpen ? <ChevronsUp size={11} style={{ marginRight: 5,
                                                    verticalAlign: -1 }} />
                   : <ChevronsDown size={11} style={{ marginRight: 5,
                                                      verticalAlign: -1 }} />}
          {anyOpen ? "Drill up (collapse all)" : "Drill down (expand all)"}
        </button>
        <span className="mono" data-testid="edr-response-loaded-at"
              style={{ fontSize: 9, color: "var(--faint)" }}>
          {loading ? "reloading …"
           : loadedAt ? `read at ${loadedAt}` : "not yet read"}
        </span>
      </div>

      <div style={{ fontSize: 10, color: "var(--faint)", lineHeight: 1.6,
                    maxWidth: 940, marginBottom: 12 }}
           data-testid="edr-response-acceptance-rule">
        {data.note} A request is not an outcome and a sensor's own report is
        not proof: only a record whose post-action probe re-read the target
        on the endpoint is shown as verified.
      </div>

      {data.truncated && (
        <div style={{ marginBottom: 12 }}
             data-testid="edr-response-truncated">
          <span className="nx-ep" data-ep="unknown" data-known="true"
                style={{ fontSize: 9.5 }}>
            <AlertTriangle size={10} style={{ marginRight: 4,
                                              verticalAlign: -1 }} />
            SHOWING {data.count} OF {data.total_count} RECORDS — narrow the
            scope with the endpoint filter; the older records are retained,
            not lost
          </span>
        </div>
      )}

      {rows.length === 0 ? (
        <div data-testid="edr-response-empty">
          <span className="nx-ep" data-ep="no_evidence" data-known="true">
            ◇ NO RESPONSE ACTIONS ON RECORD
          </span>
          <div style={{ marginTop: 6, fontSize: 10.5, color: "var(--faint)" }}>
            No endpoint action has been requested for this scope. That is an
            absence of actions, not an absence of risk.
          </div>
        </div>
      ) : (
        <div style={{ border: "1px solid #17202A", borderRadius: 4 }}>
          {rows.map((r) => (
            <div key={r.command_id}
                 data-testid={`edr-response-row-${r.command_id}`}>
              <div onClick={() => setOpen((o) => ({ ...o,
                                                    [r.command_id]: !o[r.command_id] }))}
                   data-testid={`edr-response-toggle-${r.command_id}`}
                   style={{ display: "flex", gap: 12, alignItems: "center",
                            padding: "7px 10px", cursor: "pointer",
                            borderBottom: "1px solid #141C24",
                            flexWrap: "wrap" }}>
                {open[r.command_id] ? <ChevronDown size={12} />
                                    : <ChevronRight size={12} />}
                <span className="nx-ep"
                      data-ep={r.proof?.integrity_alarm
                        ? "capability_unavailable"
                        : STATE_EP[r.state] || "unknown"}
                      data-known="true"
                      data-testid={`edr-response-state-${r.command_id}`}
                      style={{ fontSize: 9, minWidth: 168 }}>
                  {r.state}
                </span>
                <span className="mono" style={{ fontSize: 10.5,
                                                color: "var(--text)",
                                                minWidth: 150 }}>
                  {r.action}
                </span>
                <span className="mono" style={{ fontSize: 9.5,
                                                color: "var(--cyan)" }}>
                  {r.endpoint_id}
                </span>
                <span className="mono" style={{ fontSize: 9.5,
                                                color: "var(--text-dim)" }}>
                  {r.target?.pid
                    ? `pid ${r.target.pid} · ${r.target.observed_image_path
                        || "image not reported"}`
                    : "no process target"}
                </span>
                <span className="mono" style={{ fontSize: 9.5,
                                                color: "var(--faint)" }}>
                  {r.requested_by} · {r.requested_at}
                </span>
              </div>
              {open[r.command_id] && <ActionRecord r={r} />}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
