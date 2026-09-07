/**
 * NivXForgeConsole — the NivXForge EDR product plane.
 *
 * Owner-locked hierarchy (2026-09-07 · P0-F.13.3):
 *   NivXRay XDR shell  →  NivXForge EDR plane  →  capability
 *
 * The EDR plane is NOT a standalone application. It renders INSIDE
 * `XdrShell`, so global search, the global product navigation
 * (including Administration), the customer/tenant pill, notifications
 * and the user context are the platform's — never re-implemented here.
 * This console owns only the endpoint sub-navigation.
 *
 * Device Trajectory points at the canonical AMP renderer. The XDR
 * case-context trajectory stays where it belongs, on Entity 360.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import {
  LayoutGrid, ShieldAlert, Radar, GitBranch, FileText, Wifi,
  Search, Camera, Terminal, ArrowRightLeft,
  ArrowLeft,
  BookOpen, Monitor } from "lucide-react";

import { NivxrayMark } from "@/components/brand/NivxrayBrand";
import XdrShell from "@/xdr/XdrShell";
import { getEdrEntryContext } from "./edrApi";
import "./nivxforge.css";

const TABS = [
  { key: "overview",       label: "Overview",         icon: LayoutGrid,      to: "/edr" },
  { key: "computers",      label: "Computers",        icon: Monitor,         to: "/xdr/endpoints" },
  { key: "detections",     label: "Detections",       icon: ShieldAlert,     to: "/edr/detections" },
  // P0-F.13.3 · ONE canonical Device Trajectory in the operational EDR
  // navigation — the AMP renderer. The XDR case-context projection is
  // reachable from XDR → Endpoint / Entity 360, not duplicated here.
  { key: "device-trajectory", label: "Device Trajectory", icon: Radar,       to: "/xdr/edr/device-trajectory" },
  { key: "process-tree",   label: "Process Tree",     icon: GitBranch,       to: "/edr/process-tree" },
  { key: "campaign-story", label: "Campaign Story",   icon: BookOpen,        to: "/edr/campaign-story" },
  { key: "files",          label: "Files",            icon: FileText,        to: "/edr/files" },
  { key: "network",        label: "Network",          icon: Wifi,            to: "/edr/network" },
  { key: "hunting",        label: "Threat Hunting",   icon: Search,          to: "/edr/hunting" },
  { key: "forensics",      label: "Forensics",        icon: Camera,          to: "/edr/forensics" },
  { key: "live-query",     label: "Live Query",       icon: Terminal,        to: "/edr/live-query" },
  { key: "response",       label: "Response",         icon: ArrowRightLeft,  to: "/edr/response" },
];

/** Incident-context nav hints from the URL. The browser may NAME an
 *  incident; only the server decides whether it may be seen and what it
 *  actually references (`GET /api/edr/context`). */
export function useIncidentContext() {
  const [params] = useSearchParams();
  const incident_id = params.get("incident_id") || params.get("incident") || null;
  return {
    incident_id,
    device:  params.get("device")  || null,
    tenant:  params.get("tenant")  || null,
    user:    params.get("user")    || null,
    time:    params.get("time")    || null,
  };
}

/** Server-validated "Opened from Incident …" banner.
 *
 *  Tenant context (who owns the data) and investigation context (why
 *  the analyst is here) are separate facts, so they are labelled
 *  separately. The customer shown is the one the SERVER read off the
 *  incident — not the one the URL claimed. */
export function IncidentContextBanner() {
  const ctx = useIncidentContext();
  const [srv, setSrv] = useState(null);

  useEffect(() => {
    if (!ctx.incident_id) { setSrv(null); return undefined; }
    let live = true;
    getEdrEntryContext(ctx.device, ctx.incident_id)
      .then((d) => { if (live) setSrv(d); })
      .catch(() => { if (live) setSrv({ errors: ["CONTEXT_UNAVAILABLE"] }); });
    return () => { live = false; };
  }, [ctx.incident_id, ctx.device]);

  if (!ctx.incident_id) return null;
  const inv = srv?.investigation || null;
  const ref = inv?.endpoint_reference?.state;
  const err = (srv?.errors || [])[0];

  return (
    <div className="ctx-banner" data-testid="edr-incident-context-banner"
         data-entry-context={srv?.entry_context || "PENDING"}
         data-endpoint-reference={ref || ""}>
      <span>
        <span className="k">Opened from Incident</span>
        <span className="v">{inv?.incident_number || ctx.incident_id}</span>
      </span>
      {inv?.tenant_id && (
        <span><span className="k">Customer</span>
          <span className="v">{inv.tenant_id}</span></span>
      )}
      {inv?.verdict && (
        <span><span className="k">Verdict</span>
          <span className="v">{inv.verdict}</span></span>
      )}
      {inv?.detection_count > 0 && (
        <span><span className="k">Detections</span>
          <span className="v">{inv.detection_count}
            {inv.rule_ids?.length ? ` · ${inv.rule_ids.join(", ")}` : ""}
          </span></span>
      )}
      {ctx.device && (
        <span><span className="k">Device</span>
          <span className="v">{srv?.endpoint?.hostname || ctx.device}</span></span>
      )}
      {ref === "ENDPOINT_NOT_REFERENCED_BY_INCIDENT" && (
        <span data-testid="edr-context-mismatch">
          <span className="k">Reference</span>
          <span className="v">
            ◇ this incident does not reference this endpoint
          </span>
        </span>
      )}
      {err && (
        <span data-testid="edr-context-error" data-error-code={err}>
          <span className="k">Context</span>
          <span className="v">◇ {err}</span>
        </span>
      )}
      <Link
        to={inv?.href || `/xdr/incidents/${encodeURIComponent(ctx.incident_id)}`}
        className="ret"
        data-testid="edr-return-to-incident"
      >
        <ArrowLeft size={11} /> Return to Incident
      </Link>
    </div>
  );
}

export default function NivXForgeConsole({ activeTab, children }) {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [params] = useSearchParams();

  const active = useMemo(() => {
    if (activeTab) return activeTab;
    // Derive active tab from pathname (works for /edr/trajectory too).
    const match = TABS.find((t) => t.to === pathname || (t.to !== "/edr" && pathname.startsWith(t.to)));
    return match?.key || "overview";
  }, [activeTab, pathname]);

  const propagate = (to) => {
    // Preserve incident context when navigating between EDR pages.
    const carry = new URLSearchParams();
    ["incident_id", "device", "tenant", "user", "time"].forEach((k) => {
      const v = params.get(k);
      if (v) carry.set(k, v);
    });
    const qs = carry.toString();
    return qs ? `${to}?${qs}` : to;
  };

  return (
    <XdrShell flush>
      <div className="nvf-console nvf-embedded" data-testid="nivxforge-console">
        <div className="body">
          <aside className="sidebar" data-testid="nvf-sidebar">
            <Link to="/edr" className="brand" data-testid="nvf-brand">
              <NivxrayMark size={20} boxed={false} />
              NIVXFORGE <span className="accent">EDR</span>
            </Link>
            <div className="nav-title">Endpoint plane</div>
            {TABS.map((t) => {
              const Icon = t.icon;
              const isActive = t.key === active;
              return (
                <button
                  key={t.key}
                  className={`nav-item ${isActive ? "active" : ""}`}
                  onClick={() => navigate(propagate(t.to))}
                  data-active={isActive || undefined}
                  data-testid={`nvf-nav-${t.key}`}
                >
                  <span className="ic"><Icon size={13} /></span>
                  {t.label}
                </button>
              );
            })}
          </aside>
          <main className="main" data-testid="nvf-main">
            <IncidentContextBanner />
            {children}
          </main>
        </div>
      </div>
    </XdrShell>
  );
}
