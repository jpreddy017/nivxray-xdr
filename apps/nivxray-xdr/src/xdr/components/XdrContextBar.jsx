/**
 * X1 · Global XDR context bar — breadcrumbs + the context that must
 * never be lost when an analyst moves between planes.
 *
 *   NivXRay XDR › NivXForge EDR › Device Trajectory
 *   [ CUSTOMER default ] [ ENDPOINT dev_… ] [ INCIDENT INC0000… ] [ EDR PLANE ]
 *
 * It states context; it never grants it. Every chip is read from the
 * URL the server already authorised or from the session context the
 * server resolved, so the bar cannot widen anybody's visibility.
 */
import React, { useEffect, useState } from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { ChevronRight } from "lucide-react";

import { getSessionContext } from "@/nivxforge/edrApi";

/** Route → breadcrumb trail. Deterministic, no fetch, no guessing. */
const TRAILS = [
  [/^\/xdr\/search/, ["Search"]],
  [/^\/xdr\/incidents\/[^/]+/, ["Incidents", "Incident workspace"]],
  [/^\/xdr\/incidents/, ["Incidents"]],
  [/^\/xdr\/investigations\/[^/]+/, ["Investigate", "Investigation workspace"]],
  [/^\/xdr\/investigations/, ["Investigate"]],
  [/^\/xdr\/evidence-explorer/, ["Investigate", "Evidence Explorer"]],
  [/^\/xdr\/endpoints\/[^/]+\/trajectory/,
   ["Assets", "Endpoints", "Entity trajectory"]],
  [/^\/xdr\/endpoints\/[^/]+/, ["Assets", "Endpoints", "Endpoint"]],
  [/^\/xdr\/endpoints/, ["Assets", "Endpoints"]],
  [/^\/xdr\/fleet-file-trajectory/, ["Investigate", "Fleet File Trajectory"]],
  [/^\/xdr\/intelligence\/mitre/, ["Intelligence", "MITRE ATT&CK"]],
  [/^\/xdr\/intelligence/, ["Intelligence"]],
  [/^\/xdr\/respond/, ["Automate"]],
  [/^\/xdr\/detections/, ["Detection engineering"]],
  [/^\/xdr\/rule-studio/, ["Detection engineering", "Rule Studio"]],
  [/^\/xdr\/admin/, ["Administration"]],
  [/^\/xdr\/assets/, ["Assets"]],
  [/^\/xdr\/edr\/device-trajectory/,
   ["NivXRay EDR", "Device Trajectory"]],
  [/^\/edr\/detections/, ["NivXRay EDR", "Detections"]],
  [/^\/edr\/process-tree/, ["NivXRay EDR", "Process Tree"]],
  [/^\/edr\/campaign-story/, ["NivXRay EDR", "Campaign Story"]],
  [/^\/edr\/device-trajectory/, ["NivXRay EDR", "Device Trajectory"]],
  [/^\/edr\/files/, ["NivXRay EDR", "Files"]],
  [/^\/edr\/network/, ["NivXRay EDR", "Network"]],
  [/^\/edr\/hunting/, ["NivXRay EDR", "Threat Hunting"]],
  [/^\/edr\/forensics/, ["NivXRay EDR", "Forensics"]],
  [/^\/edr\/live-query/, ["NivXRay EDR", "Live Query"]],
  [/^\/edr\/response/, ["NivXRay EDR", "Response"]],
  [/^\/edr\/trajectory/, ["NivXRay EDR", "Device Trajectory (legacy)"]],
  [/^\/edr/, ["NivXRay EDR"]],
];

const Chip = ({ k, v, testid, tone }) => (
  <span data-testid={testid}
        style={{ display: "inline-flex", gap: 6, alignItems: "baseline",
                 border: "1px solid var(--border)", borderRadius: 3,
                 padding: "2px 7px", fontSize: 10,
                 background: "var(--panel)",
                 color: tone || "var(--text)" }}>
    <span style={{ fontSize: 8.6, letterSpacing: .7, color: "var(--muted)",
                   textTransform: "uppercase" }}>{k}</span>
    <span className="mono" style={{ maxWidth: 260, overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    whiteSpace: "nowrap" }}>{v}</span>
  </span>
);

export default function XdrContextBar() {
  const { pathname } = useLocation();
  const [params] = useSearchParams();
  const [sess, setSess] = useState(null);

  useEffect(() => {
    // `/xdr/rbac/session-context` answers inside an {ok, data} envelope;
    // edrApi.getSessionContext already unwraps it and is the one place
    // that knows how.
    getSessionContext().then(setSess).catch(() => setSess(null));
  }, []);

  if (pathname === "/login") return null;
  const trail = (TRAILS.find(([re]) => re.test(pathname)) || [null, []])[1];
  const plane = pathname.startsWith("/edr")
    || pathname.startsWith("/xdr/edr") ? "NIVXFORGE_EDR" : "NIVXRAY_XDR";

  const device = params.get("device") || params.get("endpoint_id");
  const incident = params.get("incident_id") || params.get("incident");
  const raw = params.get("raw_event_id");
  const cev = params.get("canonical_event_id");
  const proc = params.get("process_iid");
  const cust = sess?.active_customer;
  const custLabel = cust?.value
    || (cust?.basis === "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER"
      ? "ALL CUSTOMERS" : "◇ NOT RESOLVED");

  return (
    <div data-testid="xdr-context-bar"
         data-plane={plane}
         data-customer={cust?.value || ""}
         data-device={device || ""}
         data-incident={incident || ""}
         style={{ display: "flex", alignItems: "center", gap: 8,
                  flexWrap: "wrap", padding: "6px 14px",
                  borderBottom: "1px solid var(--border)",
                  background: "var(--bg-soft, var(--panel))" }}>
      <nav data-testid="xdr-breadcrumbs"
           style={{ display: "flex", alignItems: "center", gap: 4,
                    fontSize: 10.6, color: "var(--muted)" }}>
        <Link to="/xdr" style={{ color: "var(--muted)",
                                 textDecoration: "none" }}>
          NivXRay XDR
        </Link>
        {trail.map((seg, i) => (
          <span key={seg} style={{ display: "flex", alignItems: "center",
                                   gap: 4 }}>
            <ChevronRight size={10} style={{ opacity: .5 }} />
            <span style={{ color: i === trail.length - 1
              ? "var(--text)" : "var(--muted)" }}
                  data-testid={`xdr-crumb-${i}`}>
              {seg}
            </span>
          </span>
        ))}
      </nav>
      <span style={{ flex: 1 }} />
      <Chip k="Customer" v={custLabel} testid="xdr-ctx-customer" />
      {device && <Chip k="Endpoint" v={device} testid="xdr-ctx-endpoint" />}
      {incident && (
        <Link to={`/xdr/incidents/${encodeURIComponent(incident)}`}
              style={{ textDecoration: "none" }}>
          <Chip k="Incident" v={incident} testid="xdr-ctx-incident"
                tone="var(--cyan)" />
        </Link>
      )}
      {(raw || cev) && (
        <Chip k="Evidence" v={raw || cev} testid="xdr-ctx-evidence" />
      )}
      {proc && <Chip k="Process" v={proc} testid="xdr-ctx-process" />}
      <Chip k="Plane" v={plane === "NIVXFORGE_EDR"
        ? "NivXRay EDR" : "XDR investigation"} testid="xdr-ctx-plane" />
    </div>
  );
}
