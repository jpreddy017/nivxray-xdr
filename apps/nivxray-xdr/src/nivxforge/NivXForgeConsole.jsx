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
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import {
  LayoutGrid, ShieldAlert, Radar, GitBranch, FileText, Wifi,
  Search, Camera, Terminal, ArrowRightLeft,
  ArrowLeft, Download, List, ScrollText, SlidersHorizontal, ShieldOff,
  BookOpen, Monitor } from "lucide-react";

import { NivxrayMark } from "@/components/brand/NivxrayBrand";
import WorkspaceLaunch from "@/components/WorkspaceLaunch";
import { isCrossOrigin, productHref,
         productMode } from "@/productOrigins";
import XdrContextBar from "@/xdr/components/XdrContextBar";
import { useAuth } from "@/lib/auth";
// Product identity comes from the shared BRANDS table, never a literal: the
// EDR console previously hard-coded "NIVXFORGE EDR" in its own chrome, which
// is why the authenticated EDR host still showed the old product name after
// the login page was fixed.
import { brandFor } from "@/productScope";

import { getEdrEntryContext, getSessionContext } from "./edrApi";
import CustomerAuthorityUnavailable from "./components/CustomerAuthorityUnavailable";
import CustomerContext from "./components/CustomerContext";
import CustomerPicker from "./components/CustomerPicker";
import {
  authorizedCustomers, CONTROL_CONTEXT_ONLY, CONTROL_SWITCHABLE,
  contentGateFor, customerControlFor, customerLabel, GATE_FAILED, GATE_RENDER,
  isPlatformPrincipal, serverCustomer,
} from "./tenantContext";
import {
  activeTenant, bindServerTenant, sealTenantAuthority, serverBoundTenant,
  setActiveTenant, TENANT_BOUND_EVENT,
} from "@/lib/tenant";
import "./nivxforge.css";
import "./nvf-ops.css";

const EDR_BRAND = brandFor("edr");

/**
 * The PERMANENT NivXForge EDR information architecture.
 *
 * Every destination the product will own is present, so the console never
 * hides the shape of the product. A capability that is not implemented in
 * this wave is rendered DISABLED with its reason — it is never an enabled
 * link into a page that looks functional.
 */
const NAV = [
  { title: "Operations", items: [
    { key: "overview",    label: "Dashboard",   icon: LayoutGrid, to: "/edr" },
    { key: "computers",   label: "Computers",   icon: Monitor,
      to: "/edr/computers" },
    { key: "detections",  label: "Detections",  icon: ShieldAlert,
      to: "/edr/detections" },
    { key: "events",      label: "Events",      icon: List,
      to: "/edr/events" },
  ] },
  { title: "Investigate", items: [
    { key: "device-trajectory", label: "Device Trajectory", icon: Radar,
      to: "/edr/device-trajectory" },
    { key: "process-tree",   label: "Process Tree",   icon: GitBranch,
      to: "/edr/process-tree" },
    { key: "campaign-story", label: "Campaign Story", icon: BookOpen,
      to: "/edr/campaign-story" },
    { key: "hunting", label: "Hunt", icon: Search,
      reason: "Endpoint hunting over the raw evidence store is not "
        + "implemented in this wave." },
    { key: "files", label: "Files", icon: FileText,
      reason: "The sensor does not collect file-system observation yet, so "
        + "there is no file evidence to present." },
    { key: "network", label: "Network", icon: Wifi,
      reason: "Endpoint-observed connections and DNS are not collected by "
        + "the current sensor." },
    { key: "forensics", label: "Forensics", icon: Camera,
      reason: "No forensic collection capability exists on the endpoint "
        + "sensor yet." },
    { key: "live-query", label: "Live Query", icon: Terminal,
      reason: "Live query requires an endpoint execution channel with "
        + "approval, which is not implemented." },
  ] },
  { title: "Respond", items: [
    { key: "response", label: "Response", icon: ArrowRightLeft,
      to: "/edr/response" },
    { key: "policies", label: "Policies", icon: SlidersHorizontal,
      to: "/edr/policies" },
    { key: "exclusions", label: "Exclusions", icon: ShieldOff,
      to: "/edr/exclusions" },
  ] },
  { title: "Management", items: [
    { key: "downloads", label: "Downloads", icon: Download,
      to: "/edr/management/downloads" },
    { key: "audit", label: "Audit", icon: ScrollText,
      to: "/edr/audit" },
  ] },
];

const TABS = NAV.flatMap((s) => s.items).filter((i) => i.to);

/** Incident-context nav hints from the URL. The browser may NAME an
 *  incident; only the server decides whether it may be seen and what it
 *  actually references (`GET /api/edr/context`). */
export function useIncidentContext() {
  const [params] = useSearchParams();
  const incident_id = params.get("incident_id") || params.get("incident") || null;
  // P0-FIX-4A · a page renders BEFORE the console that binds the tenant,
  // so it subscribes to the binding instead of reading the URL once.
  const [boundTenant, setBoundTenant] = useState(() => serverBoundTenant());
  useEffect(() => {
    const onBound = (e) => setBoundTenant(e?.detail || serverBoundTenant());
    window.addEventListener(TENANT_BOUND_EVENT, onBound);
    setBoundTenant(serverBoundTenant());
    return () => window.removeEventListener(TENANT_BOUND_EVENT, onBound);
  }, []);
  return {
    incident_id,
    device:  params.get("device")  || null,
    // P0-FIX-4A · the customer a page displays is the one the SERVER bound
    // this principal to. The URL may still carry `tenant` for a principal
    // that may legitimately switch, but it never overrides the binding.
    tenant:  boundTenant || params.get("tenant") || null,
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
      {/* EXPLICIT cross-product pivot: the analyst arrived from a NivXRay
          XDR incident, so this returns THERE. It is labelled as leaving
          the product (↗) because ordinary EDR navigation must never end
          up in XDR silently. */}
      <Link
        to={inv?.href || `/xdr/incidents/${encodeURIComponent(ctx.incident_id)}`}
        className="ret"
        data-testid="edr-return-to-incident"
      >
        <ArrowLeft size={11} /> Return to NivXRay XDR incident ↗
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
  const [sessState, setSessState] = useState("loading");
  const [sessAttempt, setSessAttempt] = useState(0);
  const [tenant, setTenant] = useState(() => activeTenant());
  const tenants = useMemo(() => {
    const named = (sess?.customers || []).map((c) => c.customer);
    const scoped = sess?.tenant_scope?.tenant_ids || [];
    return Array.from(new Set([...scoped, ...named])).filter(Boolean);
  }, [sess]);

  // P0-FIX-4A · the SERVER decides whether this principal has a customer
  // to choose at all. `active_customer.basis` is the authority; no role
  // name is inspected here.
  const control = useMemo(() => customerControlFor(sess), [sess]);
  const bound = useMemo(() => serverCustomer(sess), [sess]);
  const boundLabel = useMemo(() => customerLabel(sess), [sess]);

  // P0-FIX-4B · tenant-bound content is gated on the AUTHORITY, not on
  // whether a request happened to come back.
  const gate = useMemo(() => contentGateFor(sessState, control),
                       [sessState, control]);
  const retryAuthority = useCallback(() => {
    setSessState("loading");
    setSess(null);
    setSessAttempt((n) => n + 1);
  }, []);

  // A principal the server resolved to exactly ONE customer has no choice
  // to make: the console binds the server's answer and stops honouring
  // `?tenant=` or a stale `nvx_tenant`. It invents a tenant for nobody.
  //
  // The binding is taken DURING RENDER, not in an effect, because the page
  // below this console reads the acting customer on its first render — an
  // effect would let that first render see the stale browser value.
  useMemo(() => {
    // Fail closed FIRST: an unresolvable authority seals the acting tenant
    // so no browser value (`?tenant=`, `nvx_tenant`, "default", the first
    // tenant, the previous selection) can act as a customer.
    if (gate === GATE_FAILED) return sealTenantAuthority();
    if (control === CONTROL_CONTEXT_ONLY && bound) {
      return bindServerTenant(bound, { switchable: false });
    }
    if (control === CONTROL_SWITCHABLE) {
      return bindServerTenant(null, { switchable: true });
    }
    return null;
  }, [gate, control, bound]);

  useEffect(() => {
    if (gate === GATE_FAILED) {
      // Never keep displaying the customer the browser last claimed.
      setTenant(null);
    } else if (control === CONTROL_CONTEXT_ONLY && bound) {
      setTenant(bound);
    } else if (control === CONTROL_SWITCHABLE) {
      // Only now may a deep link's `?tenant=` become the selection: the
      // SERVER said this principal has more than one customer. The server
      // still re-authorises the value on every request.
      const fromUrl = (params.get("tenant") || "").trim();
      if (fromUrl && fromUrl !== activeTenant()) setActiveTenant(fromUrl);
      setTenant(activeTenant());
    }
  }, [gate, control, bound, params]);

  // WAVE UI-1 · the Cisco Secure Endpoint console is LIGHT-FIRST, and the
  // benchmark for this product is that console — so NivXForge EDR opens
  // light when the analyst has expressed no preference. A stored
  // preference (either value) always wins, and NivXRay XDR keeps its own
  // dark default: this changes the EDR product's default only.
  const [theme, setTheme] = useState(() => {
    try {
      const stored = window.localStorage.getItem("nx.theme");
      if (stored === "light" || stored === "dark") return stored;
      return "light";
    } catch { return "light"; }
  });

  useEffect(() => {
    let live = true;
    getSessionContext()
      .then((d) => { if (live) { setSess(d); setSessState("ready"); } })
      .catch(() => { if (live) { setSess(null); setSessState("error"); } });
    const onTheme = (e) => setTheme(e.detail === "light" ? "light" : "dark");
    window.addEventListener("nx-theme", onTheme);
    return () => { live = false;
      window.removeEventListener("nx-theme", onTheme); };
  }, [sessAttempt]);

  // The document root carries the theme too, so surfaces outside this
  // console (the `body` canvas, portalled overlays) follow the same
  // choice on FIRST paint — not only after the toggle is pressed.
  useEffect(() => {
    document.documentElement.setAttribute("data-nx-theme", theme);
  }, [theme]);

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
    // P0-FIX-4A · `tenant` is only carried for a principal the server says
    // may switch. A bound principal never re-attaches it.
    const keys = control === CONTROL_SWITCHABLE
      ? ["incident_id", "device", "tenant", "user", "time"]
      : ["incident_id", "device", "user", "time"];
    keys.forEach((k) => {
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
          {EDR_BRAND.wordmark.replace(/ EDR$/, "")}{" "}
          <span className="accent">{EDR_BRAND.suffix}</span>
        </Link>
        <span className="mono" data-testid="nvf-product-tagline"
              style={{ fontSize: 9.4, letterSpacing: .8, opacity: .55,
                       textTransform: "uppercase" }}>
          Endpoint detection &amp; response
        </span>
        <span style={{ flex: 1 }} />
        {control === CONTROL_SWITCHABLE
          ? <CustomerPicker customers={authorizedCustomers(sess)}
                            withEvidence={tenants}
                            platform={isPlatformPrincipal(sess)} />
          : <CustomerContext
              label={gate === GATE_FAILED ? null : boundLabel}
              tenantId={gate === GATE_FAILED ? null : (bound || tenant)}
              basis={gate === GATE_FAILED
                ? "AUTHORITY_UNAVAILABLE"
                : sess?.active_customer?.basis} />}
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
          Investigate in NivXRay XDR ↗
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
            {NAV.map((section) => (
              <React.Fragment key={section.title}>
                <div className="nav-title">{section.title}</div>
                {section.items.map((t) => {
                  const Icon = t.icon;
                  if (!t.to) {
                    return (
                      <button key={t.key} className="nav-item disabled"
                              disabled title={t.reason}
                              data-testid={`nvf-nav-${t.key}`}
                              data-state="NOT_IMPLEMENTED">
                        <span className="ic"><Icon size={13} /></span>
                        {t.label}
                        <span className="chip"
                              style={{ marginLeft: "auto", fontSize: 8,
                                       padding: "0 4px" }}>N/I</span>
                      </button>
                    );
                  }
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
              </React.Fragment>
            ))}
          </aside>
          <main className="main" data-testid="nvf-main">
            <XdrContextBar />
            <IncidentContextBanner />
            {/* P0-FIX-4A · no tenant-bound page fetch fires until the
                SERVER has resolved which customer this principal acts as.
                Before this gate a hostile `?tenant=` or a stale
                `nvx_tenant` could be attached to the first paint's
                requests — refused by the backend, but it left the console
                showing another customer's refusal. If the session context
                itself fails we render anyway rather than trap the
                analyst. */}
            {gate === GATE_RENDER ? children : null}
            {gate === GATE_FAILED
              ? <CustomerAuthorityUnavailable onRetry={retryAuthority}
                                              retrying={false} />
              : null}
            {gate !== GATE_RENDER && gate !== GATE_FAILED
              ? <div className="mono" data-testid="nvf-tenant-resolving"
                     style={{ padding: "18px 2px", fontSize: 11,
                              color: "var(--muted)" }}>
                  resolving customer authority…
                </div>
              : null}
          </main>
        </div>
      </div>
    </div>
  );
}
