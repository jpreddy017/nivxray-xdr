/**
 * X3 · EDR → XDR · Linked XDR Incidents.
 *
 * The operational endpoint plane states which XDR incidents reference
 * the endpoint on screen, and opens them — without leaving the
 * trajectory to go and look. Read-only projection of
 * `GET /api/edr/endpoints/{id}/linked-incidents`; it creates and grades
 * nothing.
 *
 * No linked incident is a REAL answer and is rendered as one: an
 * absence of correlation is not a verdict of clean.
 */
import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronDown, ExternalLink } from "lucide-react";

import api from "@/lib/api";

export default function LinkedXdrIncidents({ device, incidentId }) {
  const [data, setData] = useState(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!device) return undefined;
    let live = true;
    api.get(`/edr/endpoints/${encodeURIComponent(device)}/linked-incidents`)
      .then(({ data: d }) => { if (live) setData(d); })
      .catch(() => { if (live) setData({ state: "UNAVAILABLE",
                                         incidents: [], count: 0 }); });
    return () => { live = false; };
  }, [device]);

  if (!device || !data) return null;
  const rows = data.incidents || [];

  return (
    <div style={{ position: "relative" }} data-testid="edr-linked-xdr">
      <button onClick={() => setOpen((v) => !v)}
              data-testid="edr-linked-xdr-toggle"
              data-state={data.state}
              data-count={data.count || 0}
              title="XDR incidents that reference this endpoint"
              style={{ display: "flex", alignItems: "center", gap: 6,
                       fontSize: 10.4, padding: "4px 9px", borderRadius: 2,
                       cursor: "pointer", background: "var(--panel)",
                       border: "1px solid var(--border)",
                       color: rows.length ? "var(--cyan, #22B8CF)"
                         : "var(--muted)" }}>
          Linked XDR Incidents: {data.count || 0}
          <ChevronDown size={11} />
      </button>

      {open && (
        <div data-testid="edr-linked-xdr-menu"
             style={{ position: "absolute", top: "calc(100% + 5px)",
                      right: 0, width: 420, zIndex: 1300,
                      background: "var(--panel)",
                      border: "1px solid var(--border)", borderRadius: 4,
                      boxShadow: "0 18px 48px rgba(0,0,0,.5)",
                      overflow: "hidden" }}>
          <div style={{ fontSize: 9.2, letterSpacing: .7, padding: "7px 11px",
                        textTransform: "uppercase", color: "var(--muted)",
                        borderBottom: "1px solid var(--border)" }}>
            XDR incidents referencing this endpoint
          </div>
          {rows.length === 0 && (
            <div data-testid="edr-linked-xdr-none"
                 data-state={data.state}
                 style={{ padding: "10px 11px", fontSize: 10.6,
                          color: "var(--muted)", lineHeight: 1.6 }}>
              {data.state === "ENDPOINT_NOT_RESOLVED" ? (
                <>
                  <b style={{ color: "var(--amber)" }}>
                    ENDPOINT_NOT_RESOLVED
                  </b>
                  {" — "}
                  {data.reason || `no endpoint you are authorised for
                    resolves to this reference`}
                  {". No incident is reported either way."}
                </>
              ) : (data.message || `No XDR incident references this
                endpoint. That is an absence of a correlated incident,
                not a verdict of clean.`)}
            </div>
          )}
          {rows.map((r) => (
            <Link key={r.incident_id} to={r.href}
                  data-testid={`edr-linked-incident-${r.incident_id}`}
                  data-current={r.incident_id === incidentId || undefined}
                  style={{ display: "block", padding: "8px 11px",
                           textDecoration: "none", color: "var(--text)",
                           borderBottom: "1px solid var(--border)",
                           background: r.incident_id === incidentId
                             ? "rgba(34,184,207,.08)" : "transparent" }}>
              <div style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
                <span className="mono" style={{ fontSize: 10.6,
                                                fontWeight: 700 }}>
                  {r.incident_number || r.incident_id}
                </span>
                <span style={{ flex: 1, fontSize: 10.4,
                               color: "var(--muted)", overflow: "hidden",
                               textOverflow: "ellipsis",
                               whiteSpace: "nowrap" }}>
                  {r.title || "◇ no title recorded"}
                </span>
                <ExternalLink size={9} style={{ opacity: .6 }} />
              </div>
              <div className="mono" style={{ fontSize: 9.2, marginTop: 2,
                                             color: "var(--faint)" }}>
                {r.verdict || "◇ verdict not recorded"} ·{" "}
                {r.detection_count} detection(s)
                {r.rule_ids?.length ? ` · ${r.rule_ids.join(", ")}` : ""} ·{" "}
                customer {r.tenant_id} · matched on {r.matched_on}
              </div>
            </Link>
          ))}
          <div style={{ fontSize: 9, color: "var(--faint)",
                        padding: "6px 11px" }}>
            basis: {data.basis || "workspace_cases.endpoint_campaign"}
          </div>
        </div>
      )}
    </div>
  );
}
