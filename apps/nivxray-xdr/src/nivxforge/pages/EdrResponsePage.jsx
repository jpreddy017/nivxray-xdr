/**
 * NivXForge EDR · Response  ·  `/edr/response`
 *
 * P0-2A. A NATIVE EDR operational surface — not the XDR admin view
 * copied across. It creates no response state and holds no lifecycle of
 * its own; it renders two existing authorities without merging them:
 *
 *   NivXForge EDR   `/api/edr/response/actions`   owns endpoint
 *                   EXECUTION and VERIFICATION. Its `state` + `proof`
 *                   are the truth about what happened on the endpoint.
 *   XDR orchestration `/api/xdr/respond/*`        owns request,
 *                   approval, dispatch and per-action capability truth.
 *
 * The invariants it is built to make unrenderable:
 *
 *   REQUEST ACCEPTED ≠ DISPATCHED ≠ EXECUTED ≠ VERIFIED
 *
 * `VERIFIED` is displayed ONLY when the EDR's own proof block confirms
 * it. A `VERIFIED` state without proof is shown as executed-unproven, a
 * stub action can never read as executed, and there is no generic green
 * "Success" anywhere on this page.
 */
import React, { useEffect, useState } from "react";
import { ShieldOff, RefreshCw, AlertTriangle } from "lucide-react";

import NivXForgeConsole, { useIncidentContext } from "@/nivxforge/NivXForgeConsole";
import { EndpointNotResolved, notResolved,
         ENDPOINT_NOT_RESOLVED } from "@/nivxforge/components/EndpointNotResolved";
import {
  listEndpointCommands, getResponseCatalogue,
  getResponseEngineHealth, getPendingApprovals,
} from "@/nivxforge/edrApi";

// EDR state → what the operator may be told. Nothing collapses to "ok".
const STATE_UI = {
  REQUESTED:              ["Requested",              "faint"],
  AUTHORIZED:             ["Approved · not dispatched", "amber"],
  DISPATCHED:             ["Dispatched",             "cyan"],
  CLAIMED:                ["Executing",              "cyan"],
  EXECUTING:              ["Executing",              "cyan"],
  EXECUTED:               ["Executed · unproven",    "amber"],
  VERIFIED:               ["Verified",               "mint"],
  VERIFICATION_FAILED:    ["Verification failed",    "red"],
  FAILED:                 ["Failed",                 "red"],
  TIMED_OUT:              ["Timed out",              "red"],
  EXPIRED:                ["Expired",                "red"],
  CAPABILITY_UNAVAILABLE: ["Blocked · environment",  "faint"],
  REJECTED:               ["Rejected",               "red"],
};

const TONE = { mint: "var(--mint)", cyan: "var(--cyan)", amber: "var(--amber)",
               red: "var(--red, #FF6B6B)", faint: "var(--faint)" };

export default function EdrResponsePage() {
  const ctx = useIncidentContext();
  const [data, setData] = useState(null);
  const [cat, setCat] = useState(null);
  const [engine, setEngine] = useState(null);
  const [pending, setPending] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(true);

  const load = React.useCallback(() => {
    setBusy(true);
    const q = ctx.device ? { endpoint_id: ctx.device } : {};
    Promise.all([
      listEndpointCommands(q).catch((e) => { setErr(e.message); return null; }),
      getResponseCatalogue().catch(() => null),
      getResponseEngineHealth().catch((e) => ({ reachable: false,
        state: "UNAVAILABLE", error: e?.response?.data?.detail || e.message })),
      getPendingApprovals().catch(() => null),
    ]).then(([d, c, h, p]) => {
      setData(d); setCat(c); setEngine(h); setPending(p); setBusy(false);
    });
  }, [ctx.device]);

  useEffect(load, [load]);

  const rows = data?.commands || [];
  const unresolvedEndpoint = notResolved(data);
  const real = (cat?.actions || []).filter((a) => a.dispatch_mode === "REAL_PRODUCT_API");
  const stub = (cat?.actions || []).filter((a) => a.dispatch_mode !== "REAL_PRODUCT_API");

  return (
    <NivXForgeConsole activeTab="response">
      <h1 className="page-h1" data-testid="edr-response-heading">Endpoint Response</h1>
      <div className="page-sub">
        NivXRay EDR performs and verifies endpoint actions. Request,
        approval and dispatch are owned by the NivXRay XDR orchestration
        plane — this surface reports both, and claims neither on the
        other's behalf.
      </div>

      {/* ── orchestration plane availability ── */}
      <div className="panel" style={{ padding: 12, marginBottom: 12 }}
           data-testid="edr-response-engine-state">
        <div style={{ display: "flex", gap: 18, flexWrap: "wrap", alignItems: "center" }}>
          <Fact label="Orchestration plane"
                value={engine?.reachable ? "Reachable" : "UNAVAILABLE"}
                tone={engine?.reachable ? "mint" : "red"}
                testid="edr-response-engine-reachable" />
          <Fact label="Real product actions" value={real.length}
                tone={real.length ? "mint" : "faint"} />
          <Fact label="Non-operational (stub)" value={stub.length} tone="faint"
                testid="edr-response-stub-count" />
          <Fact label="Awaiting approval"
                value={pending ? (pending.count ?? (pending.rows || []).length) : "—"}
                tone="amber" testid="edr-response-pending-count" />
          <Fact label="Verified on record" value={data?.verified_count ?? "—"}
                tone="mint" />
          <Fact label="Integrity alarms" value={data?.integrity_alarms ?? "—"}
                tone={data?.integrity_alarms ? "red" : "faint"} />
          <button className="btn" onClick={load} data-testid="edr-response-refresh">
            <RefreshCw size={11} /> Refresh
          </button>
        </div>
        {!engine?.reachable && (
          <div style={{ marginTop: 8, fontSize: 11, color: TONE.red }}
               data-testid="edr-response-engine-unavailable">
            <AlertTriangle size={11} style={{ verticalAlign: -2 }} />{" "}
            The response orchestration plane is unavailable, so no new action can be
            requested, approved or dispatched. Existing endpoint records below remain
            authoritative. This is not a partial success.
          </div>
        )}
        {!!stub.length && (
          <div style={{ marginTop: 8, fontSize: 10.5, color: "var(--faint)" }}
               data-testid="edr-response-stub-note">
            {stub.length} catalogued actions have no product adapter
            (STUB_NO_SIDE_EFFECT) and are non-operational — they can never
            report executed or verified: {stub.map((a) => a.action_id).join(", ")}
          </div>
        )}
        <div style={{ marginTop: 8, fontSize: 10.5, color: "var(--amber)" }}
             data-testid="edr-response-enforcement-blocked">
          Endpoint network enforcement is BLOCKED_ENVIRONMENT in this deployment
          (CAP_NET_ADMIN unavailable), so real isolation and its independent
          verification cannot be performed here. Commands reading
          “Blocked · environment” are recording that honestly.
        </div>
      </div>

      {err && <div className="panel" style={{ padding: 12, color: TONE.red }}
                   data-testid="edr-response-error">{String(err)}</div>}

      <div className="section-title" style={{ marginBottom: 8 }}>
        Endpoint Commands
        <span style={{ marginLeft: 8, fontSize: 11, color: "var(--muted)" }}
              data-testid="edr-response-row-count">
          {busy ? "loading…"
           : unresolvedEndpoint ? ENDPOINT_NOT_RESOLVED
           : `${rows.length} of ${data?.total_count ?? rows.length}`}
          {ctx.device ? ` · endpoint ${ctx.device}` : " · all endpoints in scope"}
        </span>
      </div>

      {!busy && unresolvedEndpoint && (
        <EndpointNotResolved supplied={ctx.device} payload={data}
                             testid="edr-response-not-resolved" />
      )}

      {!busy && !unresolvedEndpoint && !rows.length && (
        <div className="panel" style={{ padding: 14, color: "var(--faint)", fontSize: 12 }}
             data-testid="edr-response-empty">
          No endpoint command records in scope. This is an absence of commands,
          not a statement that any endpoint is contained.
        </div>
      )}

      <div style={{ display: "grid", gap: 8 }} data-testid="edr-response-commands">
        {rows.map((c) => <CommandCard key={c.command_id} c={c} />)}
      </div>
    </NivXForgeConsole>
  );
}

function Fact({ label, value, tone = "cyan", testid }) {
  return (
    <div data-testid={testid}>
      <div style={{ fontSize: 9.5, letterSpacing: ".4px", textTransform: "uppercase",
                    color: "var(--faint)", fontWeight: 800 }}>{label}</div>
      <div style={{ fontSize: 13, fontWeight: 700, color: TONE[tone] }}>{value}</div>
    </div>
  );
}

function CommandCard({ c }) {
  const [label, tone] = STATE_UI[c.state] || [c.state || "Unknown", "faint"];
  const proof = c.proof || {};
  // The EDR grades proof with a TOKEN, not a boolean: only
  // `VERIFIED_BY_POST_ACTION_EVIDENCE` means the effect was proven, and
  // an integrity alarm withdraws the claim regardless of the grade.
  const proven = proof.proof === "VERIFIED_BY_POST_ACTION_EVIDENCE"
                 && !proof.integrity_alarm;
  const shown = (c.state === "VERIFIED" && !proven)
    ? ["Executed · proof missing", "amber"] : [label, tone];

  return (
    <div className="panel" style={{ padding: 12 }}
         data-testid={`edr-response-cmd-${c.command_id}`}>
      <div style={{ display: "flex", justifyContent: "space-between",
                    alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <ShieldOff size={13} style={{ color: TONE[shown[1]] }} />
          <span style={{ fontSize: 13, fontWeight: 800 }}>{c.action}</span>
          <span style={{ fontSize: 10, fontFamily: "monospace", color: "var(--faint)" }}>
            {c.command_id}
          </span>
        </div>
        <span style={{ fontSize: 10.5, fontWeight: 800, letterSpacing: ".3px",
                       textTransform: "uppercase", color: TONE[shown[1]] }}
              data-testid={`edr-response-state-${c.command_id}`}>
          {shown[0]}
        </span>
      </div>

      <div style={{ marginTop: 8, display: "grid", gap: 6,
                    gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))" }}>
        <Kv k="Endpoint"      v={c.endpoint_id} mono />
        <Kv k="Customer"      v={c.tenant_id} />
        <Kv k="Requested by"  v={c.requested_by} />
        <Kv k="Requested at"  v={c.requested_at} />
        <Kv k="Approved by"   v={(c.authorisation || {}).authorised_by} />
        <Kv k="Approved at"   v={c.authorised_at} />
        <Kv k="Dispatched at" v={c.dispatched_at} />
        <Kv k="Executed at"   v={c.executed_at} />
        <Kv k="Verified at"   v={c.verified_at} />
        <Kv k="Correlation"   v={c.engine_id} mono />
      </div>

      <div style={{ marginTop: 8, fontSize: 11, lineHeight: 1.55 }}
           data-testid={`edr-response-proof-${c.command_id}`}>
        <span style={{ color: "var(--faint)", fontWeight: 800, fontSize: 9.5,
                       letterSpacing: ".4px", textTransform: "uppercase" }}>
          Verification
        </span>
        <div style={{ color: proven ? TONE.mint : TONE.amber }}>
          {proven ? "Proven by post-action evidence"
                : `Not proven — ${proof.proof || proof.meaning || "no verification evidence"}`}
        </div>
        {proof.integrity_alarm && (
          <div style={{ color: TONE.red, fontSize: 10.5, fontWeight: 700 }}
               data-testid={`edr-response-integrity-${c.command_id}`}>
            INTEGRITY ALARM — the sensor's claim conflicts with the evidence;
            this action is not treated as proven.
          </div>
        )}
        {c.verification && (
          <div style={{ color: "var(--muted)", fontSize: 10.5 }}>
            {typeof c.verification === "string"
              ? c.verification
              : JSON.stringify(c.verification).slice(0, 220)}
          </div>
        )}
        {(c.sensor_result || {}).error && (
          <div style={{ color: TONE.red, fontSize: 10.5 }}>
            Failure: {String((c.sensor_result || {}).error).slice(0, 200)}
          </div>
        )}
        {c.reason && (
          <div style={{ color: "var(--faint)", fontSize: 10.5 }}>Reason: {c.reason}</div>
        )}
      </div>
    </div>
  );
}

function Kv({ k, v, mono }) {
  return (
    <div>
      <div style={{ fontSize: 9, letterSpacing: ".4px", textTransform: "uppercase",
                    color: "var(--faint)", fontWeight: 800 }}>{k}</div>
      <div style={{ fontSize: 11, color: v ? "var(--text)" : "var(--faint)",
                    fontFamily: mono ? "monospace" : "inherit" }}>
        {v || "Not recorded"}
      </div>
    </div>
  );
}
