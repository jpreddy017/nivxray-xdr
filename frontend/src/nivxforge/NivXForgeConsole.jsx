/**
 * NivXForgeConsole — the complete NivXForge EDR product shell.
 *
 * Owner-locked hierarchy (2026-08-29):
 *   NivXRay XDR  →  Incident  →  Telemetry Console  →  Investigation
 *
 * This is the "Telemetry Console" layer for the EDR domain.  It has
 * its own top bar, its own left sub-nav (10 tabs), and — when opened
 * from an Incident — a persistent "Return to Incident" banner.
 *
 * The Device Trajectory tab links out to the existing standalone
 * `/edr/trajectory` implementation.  We do NOT duplicate the
 * trajectory canvas inside this console.
 */
import React, { useMemo } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import {
  LayoutGrid, ShieldAlert, Radar, GitBranch, FileText, Wifi,
  Search, Camera, Terminal, ArrowRightLeft,
  ArrowLeft,
} from "lucide-react";

import { useAuth } from "@/lib/auth";
import "./nivxforge.css";

const TABS = [
  { key: "overview",       label: "Overview",         icon: LayoutGrid,      to: "/edr" },
  { key: "detections",     label: "Detections",       icon: ShieldAlert,     to: "/edr/detections" },
  { key: "trajectory",     label: "Device Trajectory", icon: Radar,           to: "/edr/trajectory" },
  { key: "process-tree",   label: "Process Tree",     icon: GitBranch,       to: "/edr/process-tree" },
  { key: "files",          label: "Files",            icon: FileText,        to: "/edr/files" },
  { key: "network",        label: "Network",          icon: Wifi,            to: "/edr/network" },
  { key: "hunting",        label: "Threat Hunting",   icon: Search,          to: "/edr/hunting" },
  { key: "forensics",      label: "Forensics",        icon: Camera,          to: "/edr/forensics" },
  { key: "live-query",     label: "Live Query",       icon: Terminal,        to: "/edr/live-query" },
  { key: "response",       label: "Response",         icon: ArrowRightLeft,  to: "/edr/response" },
];

/** Read incident-context nav hints from the URL (owner rule #25 —
 *  the backend does NOT trust these for authorization). */
export function useIncidentContext() {
  const [params] = useSearchParams();
  const incident_id = params.get("incident_id") || null;
  return {
    incident_id,
    device:  params.get("device")  || null,
    tenant:  params.get("tenant")  || null,
    user:    params.get("user")    || null,
    time:    params.get("time")    || null,
  };
}

/** Persistent "Opened from Incident …" banner.  Renders only when
 *  the current URL carries an `incident_id` — the analyst always sees
 *  the return path back to the operational parent. */
export function IncidentContextBanner() {
  const ctx = useIncidentContext();
  if (!ctx.incident_id) return null;
  return (
    <div className="ctx-banner" data-testid="edr-incident-context-banner">
      <span><span className="k">Opened from Incident</span> <span className="v">{ctx.incident_id}</span></span>
      {ctx.device && <span><span className="k">Device</span> <span className="v">{ctx.device}</span></span>}
      {ctx.tenant && <span><span className="k">Customer</span> <span className="v">{ctx.tenant}</span></span>}
      {ctx.user   && <span><span className="k">User</span> <span className="v">{ctx.user}</span></span>}
      {ctx.time   && <span><span className="k">Time</span> <span className="v">{ctx.time}</span></span>}
      <Link
        to={`/xdr/incidents/${encodeURIComponent(ctx.incident_id)}`}
        className="ret"
        data-testid="edr-return-to-incident"
      >
        <ArrowLeft size={11} /> Return to Incident
      </Link>
    </div>
  );
}

export default function NivXForgeConsole({ activeTab, children }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [params] = useSearchParams();

  const initials = (user?.email || "?").slice(0, 2).toUpperCase();

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
    <div className="nvf-console" data-testid="nivxforge-console">
      <div className="topbar">
        <Link to="/xdr" className="brand" data-testid="nvf-brand">
          <span className="mark">F</span>
          NIVXFORGE <span className="accent">EDR</span>
        </Link>
        <div className="top-actions">
          <span className="tier-pill" title="Endpoint telemetry console (NivXRay XDR)">
            NIVXRAY XDR · ENDPOINT
          </span>
          <button
            className="user-chip"
            onClick={logout}
            title={`${user?.email || ""} · Logout`}
            data-testid="nvf-user-logout"
          >
            {initials}
          </button>
        </div>
      </div>

      <div className="body">
        <aside className="sidebar" data-testid="nvf-sidebar">
          <div className="nav-title">NivXForge EDR</div>
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
  );
}
