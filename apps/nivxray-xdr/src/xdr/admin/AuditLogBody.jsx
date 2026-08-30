/**
 * Admin › Audit Log — P0-1 read surface.
 *
 * Live-reads GET /api/xdr/audit-log with filter query params and shows
 * chain-verification status.  NEVER fabricates events; when the base
 * API returns 503 (storage unavailable) the panel renders honestly.
 */
import React, { useEffect, useState } from "react";
import { ShieldCheck, RefreshCw, Search } from "lucide-react";

import api from "@/lib/api";


export default function AuditLogBody() {
  const [rows, setRows] = useState([]);
  const [state, setState] = useState({ loading: true, err: null });
  const [chain, setChain] = useState(null);
  const [q, setQ] = useState({ action: "", resource_kind: "",
                                                     principal_id: "", outcome: "" });
  const [refresh, setR] = useState(0);

  const fetch = async () => {
    setState({ loading: true, err: null });
    const params = Object.fromEntries(
      Object.entries(q).filter(([, v]) => v && v.trim())
    );
    try {
      const r = await api.get("/api/xdr/audit-log", { params });
      const events = r?.data?.data?.events || [];
      setRows(events);
      setState({ loading: false, err: null });
    } catch (e) {
      setRows([]);
      setState({ loading: false, err: e?.response?.data?.detail
                                        || e?.message || "audit-log fetch failed" });
    }
  };

  const verifyChain = async () => {
    try {
      const r = await api.get("/api/xdr/audit-log/verify/chain");
      setChain(r?.data?.data || null);
    } catch (e) {
      setChain({ status: "unavailable",
                       reason: e?.response?.data?.detail || e?.message });
    }
  };

  useEffect(() => { fetch(); /* eslint-disable-next-line */ }, [refresh]);

  const chainColor =
      chain?.status === "valid"        ? "var(--mint)"
    : chain?.status === "chain_broken" ? "#f87171"
                                                        : "var(--faint)";

  return (
    <div data-testid="xdr-audit-log-body">
      <div style={{ display: "flex", alignItems: "center",
                       gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
        {["action", "resource_kind", "principal_id", "outcome"].map((k) => (
          <input key={k} placeholder={k}
                     data-testid={`xdr-audit-filter-${k}`}
                     value={q[k]}
                     onChange={(e) => setQ((s) => ({ ...s, [k]: e.target.value }))}
                     onKeyDown={(e) => e.key === "Enter" && setR((n) => n + 1)}
                     style={{ padding: "3px 8px", fontSize: 11,
                                 border: "1px solid var(--border)",
                                 borderRadius: 3, background: "var(--panel2)",
                                 color: "var(--text)", fontFamily: "var(--mono)",
                                 width: 140 }} />
        ))}
        <button className="btn" onClick={() => setR((n) => n + 1)}
                  data-testid="xdr-audit-refresh"
                  style={{ padding: "3px 10px", fontSize: 11 }}>
          <Search size={11} /> Search
        </button>
        <span style={{ flex: 1 }} />
        <button className="btn ghost" onClick={verifyChain}
                  data-testid="xdr-audit-verify"
                  style={{ padding: "3px 10px", fontSize: 11 }}>
          <ShieldCheck size={11} /> Verify chain
        </button>
        {chain && (
          <span className="mono" data-testid="xdr-audit-chain-status"
                    style={{ fontSize: 10, padding: "2px 6px",
                                border: `1px solid ${chainColor}`,
                                color: chainColor, borderRadius: 3 }}>
            chain: {chain.status} · {chain.checked ?? 0} checked
          </span>
        )}
      </div>

      {state.loading && (
        <div style={{ fontSize: 11, color: "var(--faint)" }}>
          Loading audit log…
        </div>
      )}
      {state.err && (
        <div style={{ padding: 8, borderRadius: 3, marginBottom: 8,
                          border: "1px dashed var(--amber)",
                          color: "var(--amber)", fontSize: 11,
                          fontFamily: "var(--mono)" }}
                data-testid="xdr-audit-error">
          AUDIT LOG UNAVAILABLE · {state.err}
        </div>
      )}
      {!state.loading && !state.err && rows.length === 0 && (
        <div style={{ padding: 10, fontSize: 11, color: "var(--faint)",
                          fontFamily: "var(--mono)" }}
                data-testid="xdr-audit-empty">
          NO AUDIT EVENTS RECORDED YET
        </div>
      )}
      {rows.length > 0 && (
        <div data-testid="xdr-audit-rows"
                style={{ border: "1px solid var(--border)",
                            borderRadius: 3, overflow: "hidden" }}>
          <div className="mono" style={{ display: "grid",
                                                        gridTemplateColumns: "140px 140px 140px 100px 1fr 90px",
                                                        gap: 6, padding: "4px 8px",
                                                        background: "var(--panel2)",
                                                        fontSize: 10, color: "var(--faint)",
                                                        textTransform: "uppercase" }}>
            <div>Time</div><div>Actor</div><div>Action</div>
            <div>Outcome</div><div>Resource</div><div>Sig</div>
          </div>
          {rows.map((r) => (
            <div key={r.id} className="mono"
                    data-testid={`xdr-audit-row-${r.id}`}
                    style={{ display: "grid",
                                gridTemplateColumns: "140px 140px 140px 100px 1fr 90px",
                                gap: 6, padding: "4px 8px", fontSize: 11,
                                color: "var(--text-dim)",
                                borderTop: "1px solid var(--border)" }}>
              <div>{r.at?.slice(0, 19).replace("T", " ")}</div>
              <div>{r.principal_id}</div>
              <div style={{ color: "var(--cyan)" }}>{r.action}</div>
              <div style={{ color: r.outcome === "SUCCESS"
                                    ? "var(--mint)" : "#f87171" }}>
                {r.outcome}
              </div>
              <div>{r.resource_kind} · {r.resource_id}</div>
              <div style={{ color: "var(--faint)" }}>
                {(r.sig || "").slice(0, 10)}…
              </div>
            </div>
          ))}
        </div>
      )}
      <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--faint)",
                       fontFamily: "var(--mono)" }}>
        source: <span style={{ color: "var(--cyan)" }}>
          GET /api/xdr/audit-log
        </span>{" "}· append-only · HMAC-signed chain ·
        tenant-scoped by X-Tenant-Id header.
      </div>
    </div>
  );
}
