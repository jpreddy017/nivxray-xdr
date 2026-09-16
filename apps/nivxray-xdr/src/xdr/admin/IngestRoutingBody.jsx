/**
 * Admin › Ingest Routing (D21) — READ-ONLY routing visibility.
 *
 * Shows the routing decisions the authenticated ingest boundary already
 * made: which collector delivered, what it declared, what it was
 * authorized for, which DSM was selected, and — when refused — the exact
 * reason code. It is a window, not a control: this panel issues GET
 * requests only and cannot alter a routing decision.
 *
 * Tenant scope is decided by the backend from the verified session. The
 * panel never sends a tenant header or a tenant parameter.
 */
import React, { useCallback, useEffect, useState } from "react";
import { RefreshCw, Search, ShieldOff, ShieldCheck } from "lucide-react";

import api from "@/lib/api";

const RESULTS = ["", "ACCEPTED", "BLOCKED", "NOT_EVALUATED"];
const AUTHORITIES = [
  ["", "any authority"],
  ["AUTHENTICATED_COLLECTOR_DECLARATION", "declared (ingest boundary)"],
  ["CONTENT_RESOLVED_INTERNAL_CALLER_NOT_INGEST_PATH", "internal caller"],
];
const COLS = "150px 104px 170px 200px 170px 210px 1fr";
const cell = { overflow: "hidden", textOverflow: "ellipsis",
               whiteSpace: "nowrap" };

const tone = (delivery) =>
  delivery === "ACCEPTED" ? "var(--mint)"
    : delivery === "BLOCKED" ? "#f87171" : "var(--amber)";

function Tile({ label, value, testid, color }) {
  return (
    <div data-testid={testid}
         style={{ border: "1px solid var(--border)", borderRadius: 3,
                  padding: "6px 10px", minWidth: 118,
                  background: "var(--panel2)" }}>
      <div style={{ fontSize: 9.5, letterSpacing: .4, color: "var(--faint)",
                    textTransform: "uppercase" }}>{label}</div>
      <div className="mono" style={{ fontSize: 16, color: color || "var(--text)" }}>
        {value}
      </div>
    </div>
  );
}

export default function IngestRoutingBody({ refreshNonce = 0 }) {
  const [rows, setRows] = useState([]);
  const [scope, setScope] = useState(null);
  const [summary, setSummary] = useState(null);
  const [open, setOpen] = useState(null);
  const [state, setState] = useState({ loading: true, err: null });
  const [q, setQ] = useState({ result: "", reason_code: "", collector_id: "",
                               declared_source: "", selected_dsm_id: "",
                               routing_authority: "" });
  const [nonce, setNonce] = useState(0);

  const load = useCallback(async () => {
    setState({ loading: true, err: null });
    const params = Object.fromEntries(
      Object.entries(q).filter(([, v]) => v && String(v).trim()));
    try {
      const [d, s] = await Promise.all([
        api.get("/xdr/ingest/routing/deliveries", { params }),
        api.get("/xdr/ingest/routing/summary"),
      ]);
      setRows(d?.data?.rows || []);
      setScope(d?.data?.tenant_scope || null);
      setSummary(s?.data || null);
      setState({ loading: false, err: null });
    } catch (e) {
      setRows([]);
      setState({ loading: false,
                 err: e?.response?.data?.detail || e?.message
                      || "routing visibility fetch failed" });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce, refreshNonce]);

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [nonce, refreshNonce]);

  return (
    <div data-testid="xdr-ingest-routing-body">
      {/* ── scope + counts ───────────────────────────────── */}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap",
                    alignItems: "stretch", marginBottom: 10 }}>
        <Tile label="Accepted" testid="xdr-routing-tile-accepted"
              color="var(--mint)"
              value={summary?.accepted?.total ?? "—"} />
        <Tile label="Refused" testid="xdr-routing-tile-refused"
              color="#f87171"
              value={summary?.refused?.total ?? "—"} />
        <Tile label="Reason codes" testid="xdr-routing-tile-reasons"
              value={Object.keys(summary?.refused?.by_reason_code || {}).length} />
        <div data-testid="xdr-routing-scope"
             style={{ border: "1px dashed var(--border)", borderRadius: 3,
                      padding: "6px 10px", flex: 1, minWidth: 260 }}>
          <div style={{ fontSize: 9.5, color: "var(--faint)",
                        textTransform: "uppercase", letterSpacing: .4 }}>
            Tenant scope
          </div>
          <div className="mono" style={{ fontSize: 11, color: "var(--cyan)" }}>
            {scope?.basis || "—"}
            {scope?.tenant_ids ? ` · ${scope.tenant_ids.join(", ")}`
                               : " · all authorized tenants"}
          </div>
          <div style={{ fontSize: 10, color: "var(--faint)" }}>
            {scope?.header_note}
          </div>
        </div>
      </div>

      {/* ── filters ──────────────────────────────────────── */}
      <div style={{ display: "flex", alignItems: "center", gap: 8,
                    flexWrap: "wrap", marginBottom: 8 }}>
        <select value={q.result} data-testid="xdr-routing-filter-result"
                onChange={(e) => setQ((s) => ({ ...s, result: e.target.value }))}
                style={{ padding: "3px 8px", fontSize: 11, borderRadius: 3,
                         border: "1px solid var(--border)",
                         background: "var(--panel2)", color: "var(--text)",
                         fontFamily: "var(--mono)" }}>
          {RESULTS.map((r) => (
            <option key={r || "any"} value={r}>{r || "any result"}</option>
          ))}
        </select>
        <select value={q.routing_authority}
                data-testid="xdr-routing-filter-authority"
                onChange={(e) => setQ((s) => ({ ...s,
                                                routing_authority: e.target.value }))}
                style={{ padding: "3px 8px", fontSize: 11, borderRadius: 3,
                         border: "1px solid var(--border)",
                         background: "var(--panel2)", color: "var(--text)",
                         fontFamily: "var(--mono)" }}>
          {AUTHORITIES.map(([v, label]) => (
            <option key={v || "any"} value={v}>{label}</option>
          ))}
        </select>
        {["reason_code", "collector_id", "declared_source",
          "selected_dsm_id"].map((k) => (
          <input key={k} placeholder={k} value={q[k]}
                 data-testid={`xdr-routing-filter-${k}`}
                 onChange={(e) => setQ((s) => ({ ...s, [k]: e.target.value }))}
                 onKeyDown={(e) => e.key === "Enter" && setNonce((n) => n + 1)}
                 style={{ padding: "3px 8px", fontSize: 11, width: 150,
                          border: "1px solid var(--border)", borderRadius: 3,
                          background: "var(--panel2)", color: "var(--text)",
                          fontFamily: "var(--mono)" }} />
        ))}
        <button className="btn" data-testid="xdr-routing-search"
                onClick={() => setNonce((n) => n + 1)}
                style={{ padding: "3px 10px", fontSize: 11 }}>
          <Search size={11} /> Search
        </button>
        <button className="btn ghost" data-testid="xdr-routing-refresh"
                onClick={() => setNonce((n) => n + 1)}
                style={{ padding: "3px 10px", fontSize: 11 }}>
          <RefreshCw size={11} /> Refresh
        </button>
      </div>

      {state.loading && (
        <div style={{ fontSize: 11, color: "var(--faint)" }}
             data-testid="xdr-routing-loading">
          Loading routing decisions…
        </div>
      )}
      {state.err && (
        <div data-testid="xdr-routing-error"
             style={{ padding: 8, borderRadius: 3, marginBottom: 8,
                      border: "1px dashed var(--amber)", color: "var(--amber)",
                      fontSize: 11, fontFamily: "var(--mono)" }}>
          ROUTING VISIBILITY UNAVAILABLE · {String(state.err)}
        </div>
      )}
      {!state.loading && !state.err && rows.length === 0 && (
        <div data-testid="xdr-routing-empty"
             style={{ padding: 10, fontSize: 11, color: "var(--faint)",
                      fontFamily: "var(--mono)" }}>
          NO ROUTING DECISIONS FOR THIS SCOPE AND FILTER
        </div>
      )}

      {rows.length > 0 && (
        <div data-testid="xdr-routing-rows"
             style={{ border: "1px solid var(--border)", borderRadius: 3,
                      overflow: "hidden" }}>
          <div className="mono"
               style={{ display: "grid", gridTemplateColumns: COLS, gap: 6,
                        padding: "4px 8px", background: "var(--panel2)",
                        fontSize: 10, color: "var(--faint)",
                        textTransform: "uppercase" }}>
            <div>Received</div><div>Result</div><div>Collector</div>
            <div>Declared → DSM</div><div>Reason code</div>
            <div>Authorization</div><div>Evidence</div>
          </div>
          {rows.map((r, i) => (
            <React.Fragment key={r.trace_id || i}>
              <div className="mono"
                   data-testid={`xdr-routing-row-${r.trace_id || i}`}
                   onClick={() => setOpen(open === i ? null : i)}
                   style={{ display: "grid", gridTemplateColumns: COLS,
                            gap: 6, padding: "4px 8px", fontSize: 11,
                            cursor: "pointer", color: "var(--text-dim)",
                            borderTop: "1px solid var(--border)" }}>
                <div style={cell}>
                  {String(r.at || "").slice(0, 19).replace("T", " ")}
                </div>
                <div style={{ ...cell, color: tone(r.delivery) }}>
                  {r.delivery === "ACCEPTED"
                    ? <ShieldCheck size={10} /> : <ShieldOff size={10} />}
                  {" "}{r.delivery}
                </div>
                <div style={cell} title={r.collector_id}>
                  {r.collector_id || "—"}
                </div>
                <div style={{ ...cell, color: "var(--cyan)" }}
                     title={`${r.declared_source || "no declaration"} → ${r.selected_dsm_id || "none"}`}>
                  {(r.declared_source || "NO DECLARATION")}
                  {" → "}{r.selected_dsm_id || "—"}
                </div>
                <div style={{ ...cell,
                              color: r.reason_code ? "#f87171" : "var(--faint)" }}>
                  {r.reason_code || "—"}
                </div>
                <div style={{ ...cell, fontSize: 10 }}
                     title={r.authorization_relationship}>
                  {(r.authorization_relationship || "").replace(
                    "DECLARED_SOURCE_", "").replace(
                    "NOT_APPLICABLE_NO_AUTHENTICATED_COLLECTOR",
                    "NO AUTHENTICATED COLLECTOR")}
                </div>
                <div style={{ ...cell, fontSize: 10, color: "var(--faint)" }}
                     title={r.evidence_ref || "refused — no evidence"}>
                  {r.evidence_ref
                    ? r.evidence_ref.split("/").pop()
                    : "none (refused)"}
                </div>
              </div>
              {open === i && (
                <div data-testid={`xdr-routing-detail-${r.trace_id || i}`}
                     className="mono"
                     style={{ padding: "8px 10px", fontSize: 10.5,
                              lineHeight: 1.7, color: "var(--text-dim)",
                              background: "var(--panel2)",
                              borderTop: "1px solid var(--border)" }}>
                  <div>tenant: <b>{r.tenant_id}</b> · authority:{" "}
                    <b>{r.routing_authority}</b> · shape:{" "}
                    <b>{r.payload_shape || "—"}</b> · method:{" "}
                    <b>{r.collection_method || "—"}</b></div>
                  <div>collector allowlist:{" "}
                    {(r.collector_authorized_sources || []).join(", ")
                      || "none registered"}</div>
                  <div>trace: {r.trace_id || "—"} · source_event_id:{" "}
                    {r.source_event_id || "—"}</div>
                  <div style={{ color: "var(--amber)" }}>{r.reason}</div>
                  {r.payload_keys && (
                    <div>payload keys: {r.payload_keys.join(", ")}</div>
                  )}
                  {r.payload_excerpt && (
                    <div>excerpt: {r.payload_excerpt}</div>
                  )}
                  {r.evidence_ref_absent_reason && (
                    <div style={{ color: "var(--faint)" }}>
                      {r.evidence_ref_absent_reason}
                    </div>
                  )}
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      )}

      <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--faint)",
                    fontFamily: "var(--mono)" }}
           data-testid="xdr-routing-provenance-note">
        source: <span style={{ color: "var(--cyan)" }}>
          GET /api/xdr/ingest/routing/deliveries
        </span>{" "}+{" "}
        <span style={{ color: "var(--cyan)" }}>/summary</span> · accepted
        decisions read from <b>xdr_canonical_evidence.provenance.routing</b>,
        refusals from <b>xdr_ingest_routing_blocks.routing</b> · read-only:
        this surface is not a routing authority and cannot change a decision ·
        tenant scope comes from the verified session, never a header.
      </div>
    </div>
  );
}
