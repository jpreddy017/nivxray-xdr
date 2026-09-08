/**
 * XdrShell — NivXRay XDR platform shell (`/xdr/*`).
 *
 * Owner-locked guardrails (2026-08-29):
 *   • Top bar is UTILITY ONLY — brand · global search · tenant ·
 *     notifications · user.  NO product navigation in the top bar.
 *   • The left sidebar owns product navigation.  Section tree matches
 *     the owner spec (Workspace / Operations / Investigations /
 *     Intelligence / Exposure / Data / Administration).
 *   • Every sidebar entry either navigates to an in-XDR route (/xdr/*)
 *     or opens the existing NivXRay capability in a NEW BROWSER TAB.
 *     We NEVER duplicate an existing capability inside /xdr.
 *   • `/analyst` remains untouched — the Workspace entry deep-links
 *     to it as an external tab.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  LayoutGrid, LayoutDashboard, AlertOctagon, User as UserIcon, ArrowRightLeft,
  Search, FolderSearch, Fingerprint,
  Radar, Globe, Bug, Grid3x3, BookOpen, Terminal,
  Boxes, ShieldOff, Route, KeyRound, Layers,
  Database, Plug, HardDrive, Cpu, Wifi, Sliders, Activity as ActivityIcon,
  Filter, Shuffle, Zap, Users, Webhook, HeartPulse, CheckSquare,
  ExternalLink, Bell, HelpCircle, Lock, ShieldAlert, ChevronDown,
  ChevronRight,
} from "lucide-react";

import { useAuth } from "@/lib/auth";
import { getSessionContext } from "@/nivxforge/edrApi";
import { NivxrayMark } from "@/components/brand/NivxrayBrand";
import WorkspaceLaunch from "@/components/WorkspaceLaunch";
import XdrContextBar from "@/xdr/components/XdrContextBar";
import "./xdr-console.css";
import "./nx/nx-epistemic.css";
import "./nx/nx-tokens.css";
import "./nx/nx-theme.css";
import { NxDensityProvider } from "./nx";

// Phase 2 · theme is DARK by default; light is a preserved toggle.
const NX_THEME_KEY = "nx.theme";
function readTheme() {
  try {
    const v = window.localStorage.getItem(NX_THEME_KEY);
    return v === "light" ? "light" : "dark";
  } catch { return "dark"; }
}

// ── Sidebar tree · owner-locked ────────────────────────────────────
// key      – unique id (used for active highlighting + data-testid)
// label    – exact label rendered
// icon     – lucide icon
// to       – route target
// external – true → opens in a new browser tab (reserved / not yet native)
// disabled – true → row rendered but not clickable ("Not available")
// reserved – true → routes to native XDR reserved placeholder
//              (transitional: capability will be built native in a
//              later slice; currently surfaces an honest state,
//              never a deep-link back into the base NivXRay UI).
// Round 38.4 · Two top-level product areas — INVESTIGATOR (analyst
// runtime) and ADMINISTRATION (platform + engineering + governance).
// Each item still carries the ``section`` sub-group it belongs to.
// Rendering (below) walks ``SIDEBAR_AREAS`` and groups items by
// section within each area.
const SIDEBAR = [
  // ── INVESTIGATOR ────────────────────────────────────────────
  {
    area: "investigator",
    section: "Workspace",
    items: [
      // "Analyst Workspace" removed: it linked externally to `/analyst`,
      // which has no application — the SPA catch-all sent that new tab
      // straight back to /xdr. A control that pretends to open another
      // product and silently returns you to this one is a dead control,
      // and Incidents is the analyst's real destination.
      //
      // 2026-09-08: the real NivXMachines Workspace (AutoInvestigate /
      // Decoder / Analyze / Lab) now has a hand-off — but it is a
      // SEPARATE frontend deployment at its own origin, so it cannot be
      // a rail route. It lives in the top bar as
      // `components/WorkspaceLaunch.jsx`, which opens a new tab only
      // when a Workspace origin is actually configured. This section
      // stays empty on purpose.
    ],
  },
  {
    area: "investigator",
    section: "Command Center",
    items: [
      { key: "mss-dashboard", label: "MSS Dashboard", icon: LayoutDashboard, to: "/xdr/mss-dashboard",
        title: "SOC command center · triage lenses · analyst workload · customer operations · auto-investigation status · detection & MITRE overview" },
    ],
  },
  {
    area: "investigator",
    section: "Operations",
    items: [
      { key: "incidents",  label: "Incidents",  icon: AlertOctagon,   to: "/xdr/incidents",
        title: "Primary analyst work surface · investigation-aware incident queue" },
      { key: "my-queue",   label: "My Queue",   icon: UserIcon,       to: "/xdr/incidents?mine=1" },
      { key: "sla-aging",  label: "SLA / Aging", icon: ArrowRightLeft, disabled: true,
        title: "SLA & aging dashboard — arrives in Phase 3" },
      { key: "response",   label: "Response",   icon: ArrowRightLeft, disabled: true,
        title: "Cross-incident Response Center — arrives in Phase 8" },
    ],
  },
  {
    area: "investigator",
    section: "Investigations",
    items: [
      { key: "investigations", label: "Investigation Workspace", icon: FolderSearch,
        to: "/xdr/investigations",
        title: "Cross-case investigation workspace · IKG-driven causal investigation canvas" },
      { key: "evidence-explorer", label: "Evidence Explorer", icon: Search,
        to: "/xdr/evidence-explorer",
        title: "Cross-case evidence explorer · extracted artifacts · hash chains · decoded payloads" },
      { key: "entity-search", label: "Global Search", icon: Fingerprint,
        to: "/xdr/search",
        title: "Unified search across incidents, endpoints, detections and canonical evidence" },
      { key: "attack-story-rollup", label: "Attack Story Rollup", icon: Fingerprint,
        disabled: true, title: "Cross-case attack-story rollup — arrives in Phase 5+ (distinct from per-incident Attack Story)" },
    ],
  },
  {
    area: "investigator",
    section: "Intelligence",
    items: [
      { key: "ti",       label: "Threat Intelligence",  icon: Globe,
        disabled: true,
        title: "Native XDR Threat Intelligence · STIX/TAXII + OSINT · arrives in Round P1.0 · Intelligence Planes" },
      { key: "ioc",      label: "IOC Intelligence",     icon: Bug,
        disabled: true,
        title: "Native XDR IOC Intelligence · arrives in Round P1.0 · Intelligence Planes" },
      { key: "command",  label: "Command Intelligence", icon: Terminal,
        disabled: true,
        title: "Native XDR Command Intelligence · arrives in Round P1.0 · Intelligence Planes" },
      { key: "malware",  label: "Malware Intelligence", icon: Bug,
        disabled: true,
        title: "Native XDR Malware Intelligence · arrives in Round P1.0 · Intelligence Planes" },
      { key: "mitre",    label: "MITRE ATT&CK",         icon: Grid3x3,
        to: "/xdr/intelligence/mitre",
        title: "Native XDR MITRE ATT&CK heatmap · powered by authoritative NivXRay incident evidence" },
      { key: "kb",       label: "Knowledge Base",       icon: BookOpen,
        to: "/xdr/kb",
        title: "Investigation guides · detection guidance · runbooks · SOPs · threat actor knowledge" },
    ],
  },
  {
    area: "investigator",
    section: "Telemetry",
    items: [
      { key: "telemetry-studio",  label: "Telemetry Studio",  icon: Sliders,
        to: "/xdr/admin/telemetry-studio",
        title: "Inspect real telemetry · analyst investigation/query surface" },
      { key: "telemetry-health",  label: "Telemetry Health",  icon: ActivityIcon,
        to: "/xdr/admin/telemetry-health",
        title: "Per-source telemetry health · are we receiving the right security telemetry?" },
    ],
  },
  {
    area: "investigator",
    section: "Exposure",
    items: [
      // The information architecture stays COMPLETE: a capability that
      // belongs to NivXRay XDR is reachable and states honestly that it
      // is not operational, instead of being a dead disabled row.
      { key: "assets",          label: "Endpoints",       icon: Boxes,
        to: "/xdr/endpoints",
        title: "Endpoint inventory — the operational asset class" },
      { key: "assets-identity", label: "Identity / Users", icon: UserIcon,
        to: "/xdr/assets/identity",
        title: "Not implemented — no identity source is ingested" },
      { key: "assets-network",  label: "Network Assets",  icon: Wifi,
        to: "/xdr/assets/network",
        title: "Not implemented — no network inventory source is ingested" },
      { key: "vulnerabilities", label: "Vulnerabilities", icon: ShieldOff, disabled: true },
      { key: "exposure",        label: "Vulnerability Exposure", icon: ShieldAlert,
        to: "/xdr/exposure",
        title: "CVE / NVD / KEV / EPSS · asset ↔ software ↔ CVE correlation" },
      { key: "attack-paths",    label: "Attack Paths",    icon: Route,
        to: "/xdr/assets/attack-paths",
        title: "Not implemented — needs identity, network and exposure graphs" },
      { key: "critical-assets", label: "Critical Assets", icon: KeyRound,
        to: "/xdr/assets/critical",
        title: "Not implemented — no asset criticality source is declared" },
    ],
  },
  {
    area: "investigator",
    section: "Detect",
    items: [
      { key: "rule-studio", label: "Rule Studio", icon: Layers,
        to: "/xdr/rule-studio",
        title: "Authoring · edit · test · validate · simulate detections" },
      { key: "detection-registry", label: "Detection Registry", icon: Radar,
        to: "/xdr/admin/detection-registry",
        title: "AUTHORITATIVE detection-content inventory · single source of truth" },
      { key: "correlation-rules", label: "Correlation Rules", icon: Radar,
        to: "/xdr/admin/correlation-rules",
        title: "Stateful event-stream correlation engine · analyst read/trace + author" },
      { key: "detections", label: "Detection Engineering", icon: Radar,
        to: "/xdr/detections",
        title: "Engineering / debugging / testing of detection execution" },
    ],
  },
  {
    area: "investigator",
    section: "Respond",
    items: [
      { key: "playbooks", label: "Playbooks", icon: Zap,
        to: "/xdr/respond/playbooks",
        title: "Executable response workflows · defines WHAT action is executed" },
      { key: "automation-rules", label: "Automation Rules", icon: ArrowRightLeft,
        to: "/xdr/respond/automation-rules",
        title: "WHEN → THEN rules that trigger playbooks" },
      { key: "approvals", label: "Approvals Queue", icon: CheckSquare,
        to: "/xdr/respond/approvals",
        title: "Peer-approval queue for pending Response Engine executions" },
    ],
  },
  // ── ADMINISTRATION ──────────────────────────────────────────
  // Configuration, connections, governance and management of NivXRay
  // itself.  Detection AUTHORING lives under Investigator (Detect
  // section); only detection-rule INVENTORY / lifecycle governance
  // lives here.  Same principle for Response.
  {
    area: "administration",
    section: "Administration",
    items: [
      { key: "integrations",      label: "Integrations",      icon: Plug,          to: "/xdr/admin/integrations" },
      { key: "data-sources",      label: "Data Sources",      icon: HardDrive,     to: "/xdr/admin/data-sources" },
      { key: "collectors",        label: "Collectors",        icon: Cpu,           to: "/xdr/admin/collectors" },
      { key: "agents",            label: "Agents",            icon: Wifi,          to: "/xdr/admin/agents" },
      { key: "parsers",           label: "Parsers",           icon: Filter,        to: "/xdr/admin/parsers" },
      { key: "normalization",     label: "Normalization",     icon: Shuffle,       to: "/xdr/admin/normalization" },
      { key: "sdl",               label: "Security Data Lake", icon: Database,     disabled: true,
        title: "Security Data Lake — arrives in a later slice" },
      { key: "detection-rules",   label: "Detection Rules",   icon: Zap,           to: "/xdr/admin/detection-rules",
        title: "Governance / configuration inventory of deployed detection rules · lifecycle · ownership · schedules" },
      { key: "response-policies", label: "Response Policies", icon: ArrowRightLeft, to: "/xdr/admin/response-policies",
        title: "Defines what response actions are ALLOWED · executed via Respond › Playbooks" },
      { key: "response-strategies", label: "Response Strategies", icon: Layers, to: "/xdr/admin/response-strategies",
        title: "Threat-Family → Response Strategy knowledge · not an engine" },
      { key: "users-roles",       label: "Users / Roles",     icon: Users,         to: "/xdr/admin/users-roles" },
      { key: "api-webhooks",      label: "API / Webhooks",    icon: Webhook,       to: "/xdr/admin/api-webhooks" },
    ],
  },
  {
    area: "administration",
    section: "System",
    items: [
      { key: "platform-health",   label: "Platform Health",   icon: HeartPulse,    to: "/xdr/admin/platform-health",
        title: "Is NivXRay itself operational? · derived from real infrastructure" },
      { key: "docs",     label: "Documentation",        icon: BookOpen,
        to: "/xdr/docs",
        title: "How does NivXRay work? · API docs · configuration · architecture" },
    ],
  },
];

const SIDEBAR_AREAS = [
  { area: "investigator",   label: "Investigator"    },
  { area: "administration", label: "Administration" },
];

// ═══════════════════════════════════════════════════════════════════
// Y1 · RAIL · information-architecture correction (Y0 gap V-1/V-2/V-14)
//
// The reference rail is EIGHT primary destinations, each expanding to
// indented children — not 45 flat rows under uppercase group headers.
// This is a structural correction, so the primaries are declared here
// and the children are REUSED from the existing definitions above by
// key: no route, label, icon or capability state is retyped, and
// nothing is invented.
// ═══════════════════════════════════════════════════════════════════
const ITEM_BY_KEY = Object.fromEntries(
  SIDEBAR.flatMap((g) => g.items.map((i) => [i.key, i])));

const RAIL = [
  { key: "control-center", label: "Control Center", icon: LayoutDashboard,
    to: "/xdr/mss-dashboard",
    children: ["telemetry-studio", "telemetry-health",
               "platform-health"] },
  { key: "incidents-primary", label: "Incidents", icon: AlertOctagon,
    to: "/xdr/incidents",
    children: ["my-queue", "sla-aging", "response"] },
  { key: "investigate", label: "Investigate", icon: FolderSearch,
    to: "/xdr/investigations",
    children: ["entity-search", "evidence-explorer",
               "attack-story-rollup"] },
  { key: "intelligence", label: "Intelligence", icon: Globe,
    to: "/xdr/intelligence/threat",
    children: ["ioc", "command", "malware", "mitre", "kb"] },
  { key: "automate", label: "Automate", icon: Zap,
    to: "/xdr/respond/playbooks",
    children: ["automation-rules", "approvals", "rule-studio",
               "detection-registry", "correlation-rules", "detections"] },
  { key: "assets-primary", label: "Assets", icon: Boxes,
    to: "/xdr/endpoints",
    children: ["assets-identity", "assets-network", "vulnerabilities",
               "exposure", "attack-paths", "critical-assets"] },
  { key: "client-management", label: "Client Management", icon: Users,
    to: "/xdr/admin/users-roles",
    children: ["users-roles", "response-policies",
               "response-strategies"] },
  { key: "administration", label: "Administration", icon: Sliders,
    to: "/xdr/admin",
    children: ["integrations", "data-sources", "collectors", "agents",
               "parsers", "normalization", "sdl", "detection-rules",
               "api-webhooks", "docs"] },
];

// Determine which sidebar entry is currently active based on location.
function useActiveKey() {
  const { pathname, search } = useLocation();
  return useMemo(() => {
    if (pathname === "/xdr")                     return "incidents";
    if (pathname.startsWith("/xdr/mss-dashboard")) return "mss-dashboard";
    if (pathname.startsWith("/xdr/incidents")) {
      return search.includes("mine=1") ? "my-queue" : "incidents";
    }
    if (pathname.startsWith("/xdr/admin")) {
      // /xdr/admin (Overview) → highlight nothing in the OUTER sidebar
      //   (the inner admin nav handles the Overview highlight).
      // /xdr/admin/:section → highlight the matching Administration
      //   sidebar item; the sidebar's Admin section uses the exact
      //   :section string as its `key`.
      const key = pathname.split("/")[3];
      return key || null;
    }
    if (pathname.startsWith("/xdr/investigations")) return "investigations";
    if (pathname.startsWith("/xdr/evidence-explorer")) return "evidence-explorer";
    if (pathname.startsWith("/xdr/intelligence/")) {
      const key = pathname.split("/")[3];
      // Sidebar keys are authoritative — URL keys map back to them.
      const map = { threat: "ti", iocs: "ioc", command: "command",
                     malware: "malware", mitre: "mitre", kb: "kb" };
      return map[key] || null;
    }
    return null;
  }, [pathname, search]);
}

export default function XdrShell({ children, flush = false }) {
  const { user, logout } = useAuth();
  const activeKey = useActiveKey();
  const navigate  = useNavigate();
  const [expanded, setExpanded] = useState({});
  const { pathname } = useLocation();
  const [q, setQ] = useState("");
  const [theme, setTheme] = useState(readTheme);
  const [sess, setSess] = useState(null);
  const [custOpen, setCustOpen] = useState(false);

  useEffect(() => {
    let live = true;
    getSessionContext()
      .then((d) => { if (live) setSess(d); })
      .catch(() => { if (live) setSess({ error: true }); });
    return () => { live = false; };
  }, []);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    try { window.localStorage.setItem(NX_THEME_KEY, next); } catch { /* non-fatal */ }
    // One theme truth across the shell and the embedded EDR consoles.
    window.dispatchEvent(new CustomEvent("nx-theme", { detail: next }));
  };
  useEffect(() => {
    const onTheme = (e) => setTheme(e.detail === "light" ? "light" : "dark");
    window.addEventListener("nx-theme", onTheme);
    return () => window.removeEventListener("nx-theme", onTheme);
  }, []);

  /** The customer is an AUTHORISATION fact resolved by the server. The
   *  pill used to print the analyst's e-mail, which is not a tenant. */
  const active = sess?.active_customer || null;
  const customers = sess?.customers || [];
  const tenantLabel = active?.value
    ? active.value
    : (active?.basis === "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER"
        ? "ALL CUSTOMERS" : "◇ NOT RESOLVED");

  /** Focus mode: the Device Trajectory workspace is a full-width
   *  investigation console, so the product nav leaves the layout. */
  const focusMode = /^\/xdr\/endpoints\/[^/]+/.test(pathname)
                    || pathname.startsWith("/xdr/intelligence/files/")
                    || pathname.startsWith("/xdr/edr/")
                    || pathname.startsWith("/edr");
  const [navOverlay, setNavOverlay] = useState(false);
  useEffect(() => { setNavOverlay(false); }, [pathname]);

  const handleSearch = (e) => {
    e.preventDefault();
    const term = q.trim();
    if (!term) return;
    // X2 · one unified search surface across every authoritative store,
    // not the incident queue's local filter.
    navigate(`/xdr/search?q=${encodeURIComponent(term)}`);
  };

  const openExternal = (to) => window.open(to, "_blank", "noopener,noreferrer");

  return (
    <NxDensityProvider>
    <div className="xdr-console"
          data-nx-theme={theme}
          data-testid="xdr-shell">
      {/* ── Top bar (utility only) ────────────────────────── */}
      <div className="topbar">
        {focusMode && (
          <button
            onClick={() => setNavOverlay((v) => !v)}
            title={navOverlay ? "Hide navigation" : "Show navigation (overlay)"}
            aria-label="Toggle product navigation"
            style={{ background: "transparent", border: "none",
                     color: "var(--nav-text-dim)", cursor: "pointer",
                     fontSize: 15, padding: "0 10px 0 0" }}
            data-testid="xdr-sidebar-toggle"
          >
            ☰
          </button>
        )}
        <Link to="/xdr" className="brand" data-testid="xdr-brand">
          <NivxrayMark size={26} boxed={false} />
          NIVXRAY <span className="accent">XDR</span>
        </Link>

        <form className="top-search" onSubmit={handleSearch} data-testid="xdr-topbar-search-form">
          <Search size={12} />
          <input
            placeholder="Search incidents, endpoints, detections, rules, evidence, processes…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            data-testid="xdr-topbar-search"
          />
        </form>

        <div className="top-actions">
          {/* XDR → NivXMachines Workspace hand-off. The Workspace
              frontend is deployed separately at its own origin and calls
              this same backend, so it opens in a new tab and is never
              routed to from here. */}
          <WorkspaceLaunch testid="xdr-open-workspace" />
          {/* No notification service exists in this build, so no bell is
              painted: a bell that never rings is a lie. Help points at
              the real Knowledge Base. */}
          <button
            className="btn ghost" style={{ padding: 6 }}
            onClick={() => navigate("/xdr/kb")}
            title="Knowledge Base · investigation guides, detection guidance, runbooks"
            data-testid="xdr-help"
          >
            <HelpCircle size={13} />
          </button>
          <button
            className="nx-theme-toggle"
            onClick={toggleTheme}
            title={theme === "dark"
              ? "Switch to light mode (analytical / print-export)"
              : "Switch to dark mode (tactical console)"}
            aria-label="Toggle colour theme"
            data-testid="xdr-theme-toggle"
            data-theme-state={theme}
          >
            {theme === "dark" ? "◐ DARK" : "◑ LIGHT"}
          </button>

          {/* Customer / organisation cluster — the console's identity
              anchor, in the Cisco position: icon · org over principal ·
              chevron. It replaces the initials chip, which said nothing
              a tenant name does not say better. */}
          <div style={{ position: "relative" }}>
            <button
              onClick={() => setCustOpen((v) => !v)}
              title="Active customer / organisation · resolved by the server from your authorisation scope"
              data-testid="xdr-tenant-pill"
              data-active-customer={active?.value || ""}
              data-customer-basis={active?.basis || ""}
              aria-expanded={custOpen}
              style={{ display: "flex", alignItems: "center", gap: 8,
                       background: "transparent", border: "none",
                       cursor: "pointer", padding: "2px 2px 2px 6px",
                       color: "var(--text)" }}
            >
              <UserIcon size={16} style={{ opacity: .8 }} />
              <span style={{ display: "flex", flexDirection: "column",
                             alignItems: "flex-start", lineHeight: 1.15,
                             maxWidth: 180 }}>
                <span style={{ fontSize: 11.5, fontWeight: 700,
                               whiteSpace: "nowrap", overflow: "hidden",
                               textOverflow: "ellipsis", maxWidth: 180 }}>
                  {tenantLabel}
                </span>
                <span style={{ fontSize: 10, color: "var(--muted)",
                               whiteSpace: "nowrap", overflow: "hidden",
                               textOverflow: "ellipsis", maxWidth: 180 }}
                      data-testid="xdr-principal">
                  {user?.email || "—"}
                </span>
              </span>
              <ChevronDown size={13} style={{ opacity: .7 }} />
            </button>
            {custOpen && (
              <div data-testid="xdr-customer-menu"
                   style={{ position: "absolute", top: "calc(100% + 6px)",
                            right: 0, width: 300, zIndex: 1200,
                            background: "var(--panel)",
                            border: "1px solid var(--border)",
                            borderRadius: 6, padding: 0,
                            overflow: "hidden",
                            boxShadow: "0 18px 48px rgba(0,0,0,.5)" }}>
                <div style={{ fontSize: 9.2, letterSpacing: .7,
                              textTransform: "uppercase",
                              padding: "8px 12px 6px",
                              color: "var(--muted)",
                              borderBottom: "1px solid var(--border)" }}>
                  Customer
                </div>
                {customers.length === 0 && (
                  <div style={{ fontSize: 11, padding: "10px 12px",
                                color: "var(--faint)" }}>
                    ◇ no customer is resolvable from your scope
                  </div>
                )}
                <div style={{ maxHeight: 260, overflowY: "auto" }}>
                  {customers.map((c) => (
                    <div key={c.customer} role="button" tabIndex={0}
                         onClick={() => { setCustOpen(false);
                                          navigate(c.queue_href); }}
                         onKeyDown={(e) => { if (e.key === "Enter") {
                           setCustOpen(false); navigate(c.queue_href); } }}
                         data-testid={`xdr-customer-${c.customer}`}
                         style={{ display: "flex", alignItems: "baseline",
                                  gap: 10, width: "100%", cursor: "pointer",
                                  padding: "7px 12px", fontSize: 11.5,
                                  color: "var(--text)" }}>
                      <span style={{ flex: 1, minWidth: 0,
                                     overflow: "hidden",
                                     textOverflow: "ellipsis",
                                     whiteSpace: "nowrap" }}>
                        {c.customer}
                      </span>
                      <span className="mono" style={{ fontSize: 10,
                              color: "var(--faint)", flex: "0 0 auto" }}>
                        {c.open_incidents} open
                      </span>
                    </div>
                  ))}
                </div>
                <button
                  onClick={logout}
                  data-testid="xdr-user-logout"
                  style={{ display: "flex", width: "100%", gap: 8,
                           alignItems: "center", cursor: "pointer",
                           padding: "8px 12px", fontSize: 11.5,
                           background: "transparent", border: "none",
                           borderTop: "1px solid var(--border)",
                           color: "var(--text-dim)" }}>
                  <Lock size={11} /> Sign out
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Body ──────────────────────────────────────────── */}
      <div className="body">
        {focusMode && navOverlay && (
          <div className="nav-scrim" onClick={() => setNavOverlay(false)}
               data-testid="xdr-sidebar-scrim" />
        )}
        <aside className={`sidebar${focusMode
                  ? (navOverlay ? " nav-overlay" : " nav-hidden") : ""}`}
               data-testid="xdr-sidebar"
               aria-hidden={focusMode && !navOverlay ? "true" : "false"}>
          {RAIL.map((primary) => {
            const kids = (primary.children || [])
              .map((k) => ITEM_BY_KEY[k]).filter(Boolean);
            const childActive = kids.some((k) => k.key === activeKey);
            const isActive = primary.key === activeKey
              || activeKey === primary.children?.[0]
              || (primary.to && pathname === primary.to);
            const open = expanded[primary.key] ?? (childActive || isActive);
            const PIcon = primary.icon;
            return (
              <div key={primary.key}
                   data-testid={`xdr-rail-${primary.key}`}
                   data-open={open || undefined}>
                <div className={`nav-item${isActive || childActive
                        ? " active" : ""}`}
                     data-active={isActive || childActive || undefined}
                     data-testid={`xdr-nav-${primary.key}`}
                     title={primary.title || undefined}
                     style={{ cursor: "pointer" }}
                     onClick={() => navigate(primary.to)}>
                  <span className="ic"><PIcon size={13} /></span>
                  {primary.label}
                  {kids.length > 0 && (
                    <span className="ext"
                          data-testid={`xdr-rail-toggle-${primary.key}`}
                          title={open ? "Collapse" : "Expand"}
                          onClick={(e) => { e.stopPropagation();
                            setExpanded((v) => ({ ...v,
                              [primary.key]: !open })); }}>
                      {open ? <ChevronDown size={11} />
                            : <ChevronRight size={11} />}
                    </span>
                  )}
                </div>
                {open && kids.map((item) => {
                  const Icon = item.icon;
                  const active = item.key === activeKey;
                  const testId = `xdr-nav-${item.key}`;
                  const common = { key: item.key, "data-testid": testId,
                                   style: { paddingLeft: 34 } };
                  if (item.disabled) {
                    return (
                      <button {...common} className="nav-item disabled"
                              disabled
                              title={item.title
                                || "Not available in this slice"}>
                        <span className="ic"><Icon size={12} /></span>
                        {item.label}
                      </button>
                    );
                  }
                  if (item.external) {
                    return (
                      <button {...common} className="nav-item"
                              onClick={() => openExternal(item.to)}
                              title={item.title
                                || `Opens ${item.to} in a new browser tab`}>
                        <span className="ic"><Icon size={12} /></span>
                        {item.label}
                        <span className="ext"><ExternalLink size={10} /></span>
                      </button>
                    );
                  }
                  return (
                    <button {...common}
                            className={`nav-item ${active ? "active" : ""}`}
                            onClick={() => navigate(item.to || item.reserved)}
                            data-active={active || undefined}
                            title={item.title || undefined}>
                      <span className="ic"><Icon size={12} /></span>
                      {item.label}
                      {item.reserved && (
                        <span className="ext"
                              title="Reserved · native XDR placeholder">
                          <Lock size={9} />
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            );
          })}
        </aside>
        <main className={`main${flush ? " flush" : ""}`} data-testid="xdr-main">
          {/* X1 · one context bar for every plane: breadcrumbs plus the
              customer / endpoint / incident / evidence context that must
              survive a pivot. It states context, never grants it. */}
          <XdrContextBar />
          {children}
        </main>
      </div>
    </div>
    </NxDensityProvider>
  );
}
