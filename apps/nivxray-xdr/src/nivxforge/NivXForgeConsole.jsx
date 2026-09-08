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
import WorkspaceLaunch from "@/components/WorkspaceLaunch";
import { isCrossOrigin, productHref,
         productMode } from "@/productOrigins";
import XdrContextBar from "@/xdr/components/XdrContextBar";
import { useAuth } from "@/lib/auth";
import { getEdrEntryContext, getSessionContext } from "./edrApi";
import "./nivxforge.css";

const TABS = [
  { key: "overview",       label: "Overview",         icon: LayoutGrid,      to: "/edr" },
  { key: "detections",     label: "Detections",       icon: ShieldAlert,     to: "/edr/detections" },
  // P0-F.13.3 · ONE canonical Device Trajectory in the operational EDR
  // navigation — the AMP renderer. The XDR case-context projection is
  // reachable from XDR → Endpoint / Entity 360, not duplicated here.
  // P0-W.F-2 · the nav now addresses the CANONICAL EDR route directly.
  // `/xdr/edr/device-trajectory` remains a permanent context-preserving
  // redirect (D-2) for external deep links, but the EDR product no
  // longer routes its own primary navigation through the XDR namespace.
  { key: "device-trajectory", label: "Device Trajectory", icon: Radar,       to: "/edr/device-trajectory" },
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

  const { user, logout } = useAuth();
  const [sess, setSess] = useState(null);
  const [theme, setTheme] = useState(() => {
    try {
      return window.localStorage.getItem("nx.theme") === "light"
        ? "light" : "dark";
    } catch { return "dark"; }
  });

  useEffect(() => {
    let live = true;
    getSessionContext().then((d) => { if (live) setSess(d); })
      .catch(() => { if (live) setSess(null); });
    const onTheme = (e) => setTheme(e.detail === "light" ? "light" : "dark");
    window.addEventListener("nx-theme", onTheme);
    return () => { live = false;
      window.removeEventListener("nx-theme", onTheme); };
  }, []);

  // One theme truth across both products — shared service, not a copy.
  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    try { window.localStorage.setItem("nx.theme", next); } catch { /* ok */ }
    document.documentElement.setAttribute("data-nx-theme", next);
    window.dispatchEvent(new CustomEvent("nx-theme", { detail: next }));
  };

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

  /** Y1 · D-1 · NivXForge EDR is its OWN product console.
   *
   *  It no longer renders inside `XdrShell`: the two products have
   *  separate identity, chrome and navigation, and integrate through
   *  explicit pivots. The theme, session context and auth are SHARED
   *  platform services — not duplicated. */
  return (
    <div className={`nvf-console nvf-product theme-${theme}`}
         data-nx-theme={theme}
         data-testid="nivxforge-console"
         data-product="NIVXFORGE_EDR">
      <div className="topbar" data-testid="nvf-topbar">
        <Link to="/edr" className="brand" data-testid="nvf-product-brand">
          <NivxrayMark size={20} boxed={false} />
          NIVXFORGE <span className="accent">EDR</span>
        </Link>
        <span className="mono" data-testid="nvf-product-tagline"
              style={{ fontSize: 9.4, letterSpacing: .8, opacity: .55,
                       textTransform: "uppercase" }}>
          Endpoint detection &amp; response
        </span>
        <span style={{ flex: 1 }} />
        <span className="pill" data-testid="nvf-customer-pill"
              data-customer={sess?.active_customer?.value || ""}
              title="Customer scope resolved by the server">
          <span className="k">Customer</span>
          <span className="v">
            {sess?.active_customer?.value
              || (sess?.active_customer?.basis
                === "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER"
                ? "ALL CUSTOMERS" : "◇ NOT RESOLVED")}
          </span>
        </span>
        {/* EDR → XDR product pivot. Resolved through `productOrigins` so
            it becomes an absolute cross-origin URL the moment XDR gets
            its own hostname, and stays an in-app route while both
            products share one deployment. Context travels in the query
            contract, which is why it survives the split. */}
        <button className="btn ghost" data-testid="nvf-open-in-xdr"
                data-pivot-mode={productMode("xdr")}
                data-pivot-href={productHref("xdr", params.get("incident_id")
                  ? `/xdr/incidents/${params.get("incident_id")}`
                  : "/xdr")}
                onClick={() => {
                  const path = params.get("incident_id")
                    ? `/xdr/incidents/${params.get("incident_id")}`
                    : "/xdr";
                  if (isCrossOrigin("xdr")) {
                    window.location.assign(productHref("xdr", path));
                  } else {
                    navigate(path);
                  }
                }}
                title={isCrossOrigin("xdr")
                  ? `Investigate in NivXRay XDR (${productHref("xdr", "/xdr")})`
                  : "Investigate in NivXRay XDR"}>
          Investigate in NivXRay XDR
        </button>
        {/* EDR → Workspace hand-off. A SEPARATE frontend at its own
            origin, so it opens in a new tab and is never routed to. */}
        <WorkspaceLaunch testid="nvf-open-workspace" />
        <button className="btn ghost" data-testid="nvf-theme-toggle"
                onClick={toggleTheme} title="Light / dark">
          {theme === "dark" ? "Light" : "Dark"}
        </button>
        <span className="mono" data-testid="nvf-user"
              style={{ fontSize: 10, opacity: .7 }}>
          {user?.email || "—"}
        </span>
        <button className="btn ghost" data-testid="nvf-logout"
                onClick={logout}>Sign out</button>
      </div>
      <div className="nvf-console nvf-embedded">
        <div className="body">
          <aside className="sidebar" data-testid="nvf-sidebar">
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
            <XdrContextBar />
            <IncidentContextBanner />
            {children}
          </main>
        </div>
      </div>
    </div>
  );
}
