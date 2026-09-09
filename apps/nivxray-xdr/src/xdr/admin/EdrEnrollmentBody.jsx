/**
 * NivXForge EDR · Endpoint Enrolment (P0-A.2).
 *
 * Owner-locked minimal scope: generate a one-time token, show it exactly
 * once, TTL, single-use status, enrolled endpoints, credential status,
 * revoke. Nothing larger — the endpoint drawer absorbs the identity and
 * health detail later.
 *
 * Two honesty rules this panel exists to hold:
 *   1. A secret is displayed once, in the response that created it, and is
 *      never persisted here or fetched again.
 *   2. enrollment_state, credential_state and sensor_state are rendered as
 *      THREE columns. An ENROLLED endpoint with an ACTIVE credential that
 *      has never reported reads ENROLLED_NEVER_REPORTED — it must never
 *      look like a healthy, reporting sensor.
 */
import React, { useCallback, useEffect, useState } from "react";
import { AlertTriangle, ChevronDown, ChevronRight, ChevronsDown,
         ChevronsUp, Copy, KeyRound, ShieldOff } from "lucide-react";
import api from "@/lib/api";

const epOf = (s) =>
  s === "ENROLLED" || s === "ACTIVE" || s === "REPORTING" ? "evidence_present"
  : s === "REVOKED" ? "capability_unavailable"
  : s === "ENROLLED_NEVER_REPORTED" || s === "SILENT" ? "unknown"
  : "no_evidence";

export default function EdrEnrollmentBody({ refreshNonce = 0 }) {
  const [endpoints, setEndpoints] = useState(null);
  const [tokens, setTokens] = useState([]);
  const [rejections, setRejections] = useState(null);
  const [minted, setMinted] = useState(null);   // never persisted
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadedAt, setLoadedAt] = useState(null);
  const [open, setOpen] = useState({});          // endpoint_id → expanded
  const [sections, setSections] = useState({    // section → expanded
    endpoints: true, tokens: true, rejections: true });
  const toggleSection = (k) =>
    setSections((s) => ({ ...s, [k]: !s[k] }));

  // One master control for the whole surface: every section AND every
  // endpoint row, drilled down or drilled up together.
  const anyOpen = Object.values(sections).some(Boolean)
                  || Object.values(open).some(Boolean);
  const masterToggle = () => {
    if (anyOpen) {
      setSections({ endpoints: false, tokens: false, rejections: false });
      setOpen({});
    } else {
      setSections({ endpoints: true, tokens: true, rejections: true });
      setOpen(Object.fromEntries(
        (endpoints || []).map((e) => [e.endpoint_id, true])));
    }
  };

  const load = useCallback(() => {
    setLoading(true);
    return Promise.all([
      api.get("/edr/enrollment/endpoints"),
      api.get("/edr/enrollment/tokens"),
      api.get("/edr/enrollment/rejections?limit=20"),
    ]).then(([e, t, r]) => {
      setEndpoints(e.data.endpoints || []);
      setTokens(t.data.tokens || []);
      setRejections(r.data);
      setErr(null);
      setLoadedAt(new Date().toISOString());
    }).catch((x) => setErr(x?.response?.data?.detail?.reason
                           || x?.message || String(x)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);
  // The page header's Refresh bumps this, so that button reloads the live
  // enrolment state instead of doing nothing.
  useEffect(() => { if (refreshNonce) load(); }, [refreshNonce, load]);

  const mint = async () => {
    setBusy(true); setErr(null); setCopied(false);
    try {
      const { data } = await api.post("/edr/enrollment/tokens",
                                      { label: label || null });
      setMinted(data);
      setLabel("");
      load();
    } catch (x) {
      setErr(x?.response?.data?.detail?.reason || x?.message || String(x));
    } finally { setBusy(false); }
  };

  const act = async (endpointId, what) => {
    setBusy(true); setErr(null);
    try {
      const body = what === "revoke"
        ? { reason: "revoked from the enrolment console" } : {};
      const { data } = await api.post(
        `/edr/enrollment/endpoints/${endpointId}/${what}`, body);
      if (data.agent_credential) setMinted(data);
      load();
    } catch (x) {
      setErr(x?.response?.data?.detail?.reason || x?.message || String(x));
    } finally { setBusy(false); }
  };

  return (
    <div style={{ padding: "10px 12px 20px" }} data-testid="edr-enrollment">
      {err && (
        <div style={{ border: "1px solid #4A1F1F", background: "#1A0B0B",
                      padding: "7px 10px", borderRadius: 4, marginBottom: 10,
                      fontSize: 10.5, color: "#D08A8A" }}
             data-testid="edr-enrollment-error">{err}</div>
      )}

      {/* ── mint ───────────────────────────────────────────── */}
      <div style={{ display: "flex", gap: 8, alignItems: "center",
                    marginBottom: 12, flexWrap: "wrap" }}>
        <input className="mono" value={label} placeholder="label (optional)"
               onChange={(e) => setLabel(e.target.value)}
               data-testid="edr-enrollment-label-input"
               style={{ background: "#0C1116", border: "1px solid #212B36",
                        color: "var(--text)", padding: "5px 9px", fontSize: 10.5,
                        borderRadius: 3, width: 240 }} />
        <button className="btn" disabled={busy} onClick={mint}
                data-testid="edr-enrollment-mint-btn"
                style={{ fontSize: 10.5, padding: "5px 11px" }}>
          <KeyRound size={11} style={{ marginRight: 5, verticalAlign: -1 }} />
          Generate one-time token
        </button>
        <button className="btn ghost" onClick={masterToggle}
                data-testid="edr-enrollment-master-toggle"
                data-state={anyOpen ? "expanded" : "collapsed"}
                title="Drill the whole surface down or up — every section and every endpoint row"
                style={{ fontSize: 10, padding: "4px 9px" }}>
          {anyOpen
            ? <ChevronsUp size={11} style={{ marginRight: 5,
                                             verticalAlign: -1 }} />
            : <ChevronsDown size={11} style={{ marginRight: 5,
                                               verticalAlign: -1 }} />}
          {anyOpen ? "Drill up (collapse all)" : "Drill down (expand all)"}
        </button>
        <span className="mono" data-testid="edr-enrollment-loaded-at"
              style={{ fontSize: 9, color: "var(--faint)" }}>
          {loading ? "reloading …"
           : loadedAt ? `read at ${loadedAt}` : "not yet read"}
        </span>
      </div>

      {minted && (
        <div style={{ border: "1px solid #1F4A3A", background: "#081A14",
                      padding: "10px 12px", borderRadius: 4, marginBottom: 14,
                      maxWidth: 760 }}
             data-testid="edr-enrollment-secret-panel">
          <div style={{ fontSize: 8.5, fontWeight: 800, letterSpacing: ".5px",
                        textTransform: "uppercase", color: "var(--faint)" }}>
            {minted.enrollment_token ? "Enrolment token" : "Agent credential"}
            {" "}— shown once
          </div>
          <div className="mono" style={{ fontSize: 11, color: "var(--cyan)",
                                         wordBreak: "break-all", margin: "6px 0" }}
               data-testid="edr-enrollment-secret-value">
            {minted.enrollment_token || minted.agent_credential}
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center",
                        flexWrap: "wrap" }}>
            <button className="btn" style={{ fontSize: 10, padding: "3px 9px" }}
                    data-testid="edr-enrollment-copy-btn"
                    onClick={async () => {
                      await navigator.clipboard.writeText(
                        minted.enrollment_token || minted.agent_credential);
                      setCopied(true);
                    }}>
              <Copy size={10} style={{ marginRight: 4, verticalAlign: -1 }} />
              {copied ? "Copied" : "Copy"}
            </button>
            <button className="btn ghost"
                    style={{ fontSize: 10, padding: "3px 9px" }}
                    data-testid="edr-enrollment-dismiss-btn"
                    onClick={() => { setMinted(null); setCopied(false); }}>
              Dismiss
            </button>
            {minted.ttl_seconds && (
              <span className="mono" style={{ fontSize: 9.5,
                                              color: "var(--faint)" }}>
                single-use · TTL {minted.ttl_seconds}s · expires{" "}
                {minted.expires_at}
              </span>
            )}
          </div>
          <div style={{ fontSize: 10, color: "#D6A84A", marginTop: 7,
                        lineHeight: 1.6 }}>
            {minted.warning}
          </div>
          {minted.honesty_note && (
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 4,
                          lineHeight: 1.6 }}>
              {minted.honesty_note}
            </div>
          )}
        </div>
      )}

      {/* ── enrolled endpoints ─────────────────────────────── */}
      <Section title="Enrolled endpoints" id="endpoints"
               open={sections.endpoints} onToggle={toggleSection}
               count={endpoints ? endpoints.length : null}
               right={endpoints && endpoints.length > 0 && (
                 <button className="btn ghost"
                         data-testid="edr-enrollment-expand-all-btn"
                         style={{ fontSize: 9, padding: "2px 8px" }}
                         onClick={() => setOpen(
                           Object.keys(open).some((k) => open[k])
                             ? {}
                             : Object.fromEntries(endpoints.map(
                                 (e) => [e.endpoint_id, true])))}>
                   {Object.keys(open).some((k) => open[k])
                     ? "Collapse all" : "Expand all"}
                 </button>)} />
      {sections.endpoints && endpoints && endpoints.length === 0 && (
        <div style={{ fontSize: 10.5, color: "var(--faint)", padding: "6px 0",
                      lineHeight: 1.7, maxWidth: 700 }}
             data-testid="edr-enrollment-empty">
          <span className="nx-ep" data-ep="no_evidence" data-known="true">
            ◇ NO ENDPOINT ENROLLED
          </span>
          <div style={{ marginTop: 5 }}>
            No endpoint has enrolled yet. Generate a one-time token above and
            present it from an agent. This is the honest state, not an error —
            nothing is fabricated to fill the table.
          </div>
        </div>
      )}
      {sections.endpoints && endpoints && endpoints.length > 0 && (
        <table className="mono" style={{ width: "100%", borderCollapse:
                "collapse", fontSize: 10, marginBottom: 16 }}>
          <thead>
            <tr style={{ color: "var(--faint)", textAlign: "left" }}>
              {["Endpoint", "Enrolment", "Credential", "Sensor", "Trusted",
                "Events", "Last telemetry", ""].map((h) => (
                <th key={h} style={{ padding: "4px 7px", fontSize: 8.5,
                                     fontWeight: 800, letterSpacing: ".4px",
                                     textTransform: "uppercase",
                                     borderBottom: "1px solid #212B36",
                                     whiteSpace: "nowrap" }}>{h}</th>))}
            </tr>
          </thead>
          <tbody>
            {endpoints.map((e) => (
              <React.Fragment key={e.endpoint_id}>
              <tr style={{ borderBottom: open[e.endpoint_id]
                             ? "none" : "1px solid #161D24",
                           cursor: "pointer" }}
                  onClick={() => setOpen((o) => ({ ...o,
                    [e.endpoint_id]: !o[e.endpoint_id] }))}
                  data-testid={`edr-enrollment-row-${e.endpoint_id}`}
                  data-expanded={open[e.endpoint_id] ? "true" : "false"}>
                <td style={{ padding: "5px 7px" }}>
                  <div style={{ display: "flex", gap: 6,
                                alignItems: "flex-start" }}>
                    <button className="btn ghost"
                            aria-expanded={!!open[e.endpoint_id]}
                            title={open[e.endpoint_id]
                                   ? "Collapse" : "Expand"}
                            data-testid={`edr-enrollment-toggle-${e.endpoint_id}`}
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setOpen((o) => ({ ...o,
                                [e.endpoint_id]: !o[e.endpoint_id] }));
                            }}
                            style={{ padding: "0 2px", lineHeight: 1,
                                     border: "none", background: "none" }}>
                      {open[e.endpoint_id]
                        ? <ChevronDown size={11} />
                        : <ChevronRight size={11} />}
                    </button>
                    <div>
                      <div style={{ color: "var(--text)" }}>
                        {e.hostname || (
                          <span className="nx-ep" data-ep="no_evidence"
                                data-known="true" style={{ fontSize: 8.5 }}>
                            ◇ NO HOSTNAME REPORTED
                          </span>)}
                      </div>
                      <div style={{ color: "var(--faint)", fontSize: 9 }}>
                        {e.endpoint_id} · {e.platform || "◇ platform unknown"}
                      </div>
                    </div>
                  </div>
                </td>
                {["enrollment_state", "credential_state", "sensor_state"]
                  .map((k) => (
                    <td key={k} style={{ padding: "5px 7px", whiteSpace: "nowrap" }}>
                      <span className="nx-ep" data-ep={epOf(e[k])}
                            data-known="true" style={{ fontSize: 8.5 }}
                            data-testid={`edr-enrollment-${k}-${e.endpoint_id}`}>
                        {e[k]}
                      </span>
                    </td>))}
                <td style={{ padding: "5px 7px", maxWidth: 220 }}>
                  <span className="nx-ep"
                        data-ep={e.trust?.telemetry_trusted
                                 ? "evidence_present" : "capability_unavailable"}
                        data-known="true" style={{ fontSize: 8.5 }}
                        data-testid={`edr-enrollment-trusted-${e.endpoint_id}`}>
                    {e.trust?.telemetry_trusted ? "TRUSTED" : "NOT TRUSTED"}
                  </span>
                  <div style={{ color: "var(--faint)", fontSize: 9, marginTop: 2,
                                whiteSpace: "normal", lineHeight: 1.5 }}>
                    {e.trust?.reason}
                  </div>
                </td>
                <td style={{ padding: "5px 7px", color: "var(--text-dim)" }}>
                  {e.event_count}
                </td>
                <td style={{ padding: "5px 7px", color: "var(--text-dim)",
                             fontSize: 9 }}>
                  {e.last_telemetry_at || "◇ never"}
                </td>
                <td style={{ padding: "5px 7px", whiteSpace: "nowrap" }}>
                  <button className="btn ghost" disabled={busy}
                          style={{ fontSize: 9, padding: "2px 7px",
                                   marginRight: 4 }}
                          onClick={(ev) => { ev.stopPropagation();
                                             act(e.endpoint_id, "rotate"); }}
                          data-testid={`edr-enrollment-rotate-${e.endpoint_id}`}>
                    Rotate
                  </button>
                  <button className="btn ghost" disabled={busy}
                          style={{ fontSize: 9, padding: "2px 7px",
                                   color: "#D08A8A" }}
                          onClick={(ev) => { ev.stopPropagation();
                                             act(e.endpoint_id, "revoke"); }}
                          data-testid={`edr-enrollment-revoke-${e.endpoint_id}`}>
                    Revoke
                  </button>
                </td>
              </tr>
              {open[e.endpoint_id] && (
                <tr style={{ borderBottom: "1px solid #161D24" }}>
                  <EndpointDetail e={e} />
                </tr>
              )}
              </React.Fragment>))}
          </tbody>
        </table>
      )}

      {/* ── tokens ─────────────────────────────────────────── */}
      <Section title="Enrolment tokens" id="tokens" open={sections.tokens}
               onToggle={toggleSection} count={tokens.length} />
      {!sections.tokens ? null : tokens.length === 0 ? (
        <div style={{ fontSize: 10.5, color: "var(--faint)", padding: "4px 0" }}
             data-testid="edr-enrollment-tokens-empty">
          No token has been minted.
        </div>
      ) : (
        <table className="mono" style={{ width: "100%", borderCollapse:
                "collapse", fontSize: 10, marginBottom: 16 }}>
          <thead>
            <tr style={{ color: "var(--faint)", textAlign: "left" }}>
              {["Token", "State", "Single use", "TTL", "Expires", "Issued by",
                "Used"].map((h) => (
                <th key={h} style={{ padding: "4px 7px", fontSize: 8.5,
                                     fontWeight: 800, letterSpacing: ".4px",
                                     textTransform: "uppercase",
                                     borderBottom: "1px solid #212B36",
                                     whiteSpace: "nowrap" }}>{h}</th>))}
            </tr>
          </thead>
          <tbody>
            {tokens.map((t) => (
              <tr key={t.token_id} style={{ borderBottom: "1px solid #161D24" }}
                  data-testid={`edr-enrollment-token-${t.token_id}`}>
                <td style={{ padding: "5px 7px" }}>
                  <div style={{ color: "var(--text)" }}>
                    {t.label || <span style={{ color: "var(--faint)" }}>
                      (no label)</span>}
                  </div>
                  <div style={{ color: "var(--faint)", fontSize: 9 }}>
                    {t.token_id} · plaintext not retrievable
                  </div>
                </td>
                <td style={{ padding: "5px 7px" }}>
                  <span className="nx-ep"
                        data-ep={t.state === "PENDING" ? "unknown"
                                 : t.state === "USED" ? "evidence_present"
                                 : "capability_unavailable"}
                        data-known="true" style={{ fontSize: 8.5 }}>
                    {t.state}
                  </span>
                </td>
                <td style={{ padding: "5px 7px", color: "var(--text-dim)" }}>
                  yes
                </td>
                <td style={{ padding: "5px 7px", color: "var(--text-dim)" }}>
                  {t.ttl_seconds}s
                </td>
                <td style={{ padding: "5px 7px", color: "var(--text-dim)",
                             fontSize: 9 }}>{t.expires_at}</td>
                <td style={{ padding: "5px 7px", color: "var(--text-dim)",
                             fontSize: 9 }}>{t.issued_by}</td>
                <td style={{ padding: "5px 7px", color: "var(--text-dim)",
                             fontSize: 9 }}>{t.used_at || "—"}</td>
              </tr>))}
          </tbody>
        </table>
      )}

      {/* ── rejected sensor alarm ──────────────────────────── */}
      <Section title="Rejected sensor alarm" id="rejections"
               open={sections.rejections} onToggle={toggleSection}
               count={rejections?.summary?.total_rejections ?? null} />
      {sections.rejections && rejections && (
        <>
          <div style={{ display: "flex", gap: 8, alignItems: "flex-start",
                        border: "1px solid #4A3A16", background: "#1A1508",
                        padding: "8px 10px", borderRadius: 4,
                        margin: "4px 0 10px", maxWidth: 900 }}
               data-testid="edr-enrollment-rejection-note">
            <AlertTriangle size={13} style={{ color: "#E8B931", flexShrink: 0,
                                              marginTop: 1 }} />
            <div style={{ fontSize: 10.5, lineHeight: 1.6,
                          color: "var(--text-dim)" }}>
              {rejections.summary.revoked_agent_still_transmitting} of{" "}
              {rejections.summary.total_rejections} refused attempts came from an
              agent that HAD standing and lost it ·{" "}
              {rejections.summary.distinct_source_ips} source IPs ·{" "}
              {rejections.summary.distinct_credential_fingerprints} credential
              fingerprints
              <div style={{ color: "var(--faint)", marginTop: 3 }}>
                {rejections.summary.isolation}
              </div>
            </div>
          </div>
          {rejections.rejections.length === 0 ? (
            <div style={{ fontSize: 10.5, color: "var(--faint)" }}
                 data-testid="edr-enrollment-rejections-empty">
              No refused ingest attempt recorded.
            </div>
          ) : (
            <table className="mono" style={{ width: "100%", borderCollapse:
                    "collapse", fontSize: 10 }}>
              <thead>
                <tr style={{ color: "var(--faint)", textAlign: "left" }}>
                  {["Observed", "Signal", "Severity", "Source IP",
                    "Credential fp", "Tenant", "Eligibility"].map((h) => (
                    <th key={h} style={{ padding: "4px 7px", fontSize: 8.5,
                                         fontWeight: 800, letterSpacing: ".4px",
                                         textTransform: "uppercase",
                                         borderBottom: "1px solid #212B36",
                                         whiteSpace: "nowrap" }}>{h}</th>))}
                </tr>
              </thead>
              <tbody>
                {rejections.rejections.map((r) => (
                  <tr key={r.rejection_id}
                      style={{ borderBottom: "1px solid #161D24" }}
                      data-testid={`edr-rejection-${r.rejection_id}`}>
                    <td style={{ padding: "5px 7px", color: "var(--text-dim)",
                                 fontSize: 9 }}>{r.observed_at}</td>
                    <td style={{ padding: "5px 7px", maxWidth: 300 }}>
                      <div style={{ color: "var(--text)" }}>{r.code}</div>
                      <div style={{ color: "var(--faint)", fontSize: 9,
                                    whiteSpace: "normal", lineHeight: 1.5 }}>
                        {r.reason}
                      </div>
                    </td>
                    <td style={{ padding: "5px 7px" }}>
                      <span className="nx-ep"
                            data-ep={r.severity === "HIGH"
                                     ? "capability_unavailable" : "unknown"}
                            data-known="true" style={{ fontSize: 8.5 }}>
                        <ShieldOff size={9} style={{ marginRight: 3,
                                                     verticalAlign: -1 }} />
                        {r.severity}
                      </span>
                    </td>
                    <td style={{ padding: "5px 7px", color: "var(--text-dim)" }}>
                      {r.source_ip || "◇ unknown"}
                    </td>
                    <td style={{ padding: "5px 7px", color: "var(--cyan)",
                                 fontSize: 9 }}>
                      {r.credential_fingerprint || "◇ none presented"}
                    </td>
                    <td style={{ padding: "5px 7px", color: "var(--text-dim)",
                                 fontSize: 9 }}>
                      {r.tenant_id || r.tenant_resolution}
                    </td>
                    <td style={{ padding: "5px 7px" }}>
                      <span className="nx-ep" data-ep="capability_unavailable"
                            data-known="true" style={{ fontSize: 8.5 }}>
                        {r.evidence_eligibility}
                      </span>
                    </td>
                  </tr>))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}

const Section = ({ title, count, right = null, id = null, open = true,
                   onToggle = null }) => (
  <div style={{ display: "flex", alignItems: "center", gap: 8,
                margin: "14px 0 6px" }}>
    {onToggle && (
      <button className="btn ghost" aria-expanded={open}
              title={open ? "Collapse section" : "Expand section"}
              data-testid={`edr-enrollment-section-toggle-${id}`}
              onClick={() => onToggle(id)}
              style={{ padding: "0 2px", lineHeight: 1, border: "none",
                       background: "none" }}>
        {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
      </button>
    )}
    <div data-testid={id ? `edr-enrollment-section-${id}` : undefined}
         data-expanded={open ? "true" : "false"}
         onClick={onToggle ? () => onToggle(id) : undefined}
         style={{ fontSize: 8.5, fontWeight: 800, letterSpacing: ".5px",
                  textTransform: "uppercase", color: "var(--text-dim)",
                  cursor: onToggle ? "pointer" : "default" }}>
      {title}
    </div>
    {count !== null && count !== undefined && (
      <div className="mono" style={{ fontSize: 9, color: "var(--faint)" }}>
        {count}
      </div>
    )}
    <div style={{ flex: 1, height: 1, background: "#1A222B" }} />
    {right}
  </div>
);

const Field = ({ k, v, mono = true, testid }) => (
  <div>
    <div style={{ fontSize: 8, fontWeight: 800, letterSpacing: ".4px",
                  textTransform: "uppercase", color: "var(--faint)" }}>
      {k}
    </div>
    <div className={mono ? "mono" : undefined} data-testid={testid}
         style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 2,
                  wordBreak: "break-all", lineHeight: 1.5 }}>
      {v === null || v === undefined || v === ""
        ? <span style={{ color: "var(--faint)" }}>◇ not reported</span>
        : String(v)}
    </div>
  </div>
);

/**
 * The drill-down. It adds NO new claim: every field is copied from the
 * enrolment record, and anything the endpoint has not reported renders
 * `◇ not reported` rather than a blank that could read as a zero.
 */
const EndpointDetail = ({ e }) => (
  <td colSpan={8} style={{ padding: "2px 7px 12px 30px",
                           background: "#0A0E13" }}
      data-testid={`edr-enrollment-detail-${e.endpoint_id}`}>
    <div style={{ display: "grid", gap: "12px 22px",
                  gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
                  border: "1px solid #161D24", borderRadius: 4,
                  padding: "10px 12px", maxWidth: 1100 }}>
      <Field k="Endpoint id (platform-minted)" v={e.endpoint_id}
             testid={`edr-enrollment-detail-id-${e.endpoint_id}`} />
      <Field k="Hostname (reported by agent)" v={e.hostname} />
      <Field k="Device iid" v={e.device_iid} />
      <Field k="Platform" v={e.platform} />
      <Field k="Sensor version" v={e.sensor_version} />
      <Field k="Credential id" v={e.credential_id} />
      <Field k="Enrolled at" v={e.enrolled_at} />
      <Field k="Revoked at" v={e.revoked_at} />
      <Field k="Last seen" v={e.last_seen} />
      <Field k="Last telemetry at" v={e.last_telemetry_at} />
      <Field k="Raw events attributed" v={e.event_count} />
      <Field k="Tenant" v={e.tenant_id} />
    </div>
    <div style={{ display: "flex", gap: 14, flexWrap: "wrap",
                  marginTop: 8, alignItems: "center" }}>
      <a className="btn ghost" href={`/xdr/endpoints/${e.endpoint_id}`}
         data-testid={`edr-enrollment-pivot-${e.endpoint_id}`}
         style={{ fontSize: 9, padding: "2px 8px",
                  textDecoration: "none" }}>
        Open device trajectory
      </a>
      <span style={{ fontSize: 9.5, color: "var(--faint)", lineHeight: 1.6,
                     maxWidth: 720 }}>
        Trust is the three lifecycles read together — {e.trust?.reason}.
        Enrolment is not evidence of visibility: an endpoint can be
        trusted to send and have sent nothing. No secret is retrievable
        here; a credential is shown once, at the moment it is issued.
      </span>
    </div>
  </td>
);
