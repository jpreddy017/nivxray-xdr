/**
 * XdrShell — NivXRay XDR platform shell (`/xdr/*`).
 *
 * B2-NAV · ONE permanent navigation rail built around ANALYST WORKFLOWS,
 * not around the engines underneath them:
 *
 *   Control Center · Incidents · Investigate · Hunting · Intelligence ·
 *   Automate · Assets · Data Sources · Reports · Client Management ·
 *   Administration
 *
 * Structural rules (owner-locked):
 *   • Every primary has a real landing page — no parent is a pure
 *     accordion and no rail row is a promise ("arrives in Phase N").
 *   • Children are CAPABILITIES of their parent workflow, never
 *     duplicates of another primary. Nothing was deleted to simplify
 *     the rail: every retired row's route still resolves, and App.jsx
 *     keeps a compatibility redirect where a route moved.
 *   • Top bar is UTILITY ONLY — brand · global hunt · Scope Navigator ·
 *     help · theme. No product navigation, no external navigation
 *     (PR-XDR-0): a rail row may never open another frontend or tab.
 *   • Tenant scope is NOT a shell concern to compute. The Scope
 *     Navigator asks the server (`/api/xdr/scope/*`) and renders only
 *     what it determined.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  LayoutDashboard, AlertOctagon, User as UserIcon,
  Search, FolderSearch, Fingerprint, FileText,
  Radar, Globe, Bug, Grid3x3, BookOpen, Terminal,
  Boxes, ShieldAlert, Route, KeyRound, Layers,
  Plug, HardDrive, Cpu, Wifi, Sliders, Activity as ActivityIcon,
  Filter, Shuffle, Zap, Users, Webhook, HeartPulse, CheckSquare,
  ArrowRightLeft, HelpCircle, Lock, ChevronDown, ChevronRight,
} from "lucide-react";

import { useAccess } from "@/xdr/access/AccessProvider";
import { NivxrayMark } from "@/components/brand/NivxrayBrand";
import WorkspaceLaunch from "@/components/WorkspaceLaunch";
import XdrContextBar from "@/xdr/components/XdrContextBar";
import XdrRibbon from "@/xdr/components/XdrRibbon";
import XdrScopeNavigator from "@/xdr/components/XdrScopeNavigator";
import NxErrorBoundary from "@/xdr/nx/NxErrorBoundary";
import "./xdr-console.css";
import "./nx/nx-epistemic.css";
import "./nx/nx-tokens.css";
import "./nx/nx-theme.css";
import { NxDensityProvider } from "./nx";

// Cisco XDR ships LIGHT as its default colour theme (Auto / Light / Dark
// are the three published options). NivXRay XDR matches that default; the
// user's explicit choice still wins and persists.
const NX_THEME_KEY = "nx.theme";
function readTheme() {
  try {
    const v = window.localStorage.getItem(NX_THEME_KEY);
    return v === "dark" ? "dark" : "light";
  } catch { return "light"; }
}

// ═══════════════════════════════════════════════════════════════════
// The rail. `key` is the data-testid suffix and the active-state id.
// `requires` is checked against EFFECTIVE PERMISSIONS (three-valued:
// false hides, true shows, null — contract unavailable — shows, because
// the backend 403 is the authority, not the browser).
// ═══════════════════════════════════════════════════════════════════
const NAV = [
  {
    key: "control-center", label: "Control Center", icon: LayoutDashboard,
    to: "/xdr/control-center",
    title: "What needs attention right now · priority work · tenants "
         + "affected · security, telemetry and response condition",
    children: [],
  },
  {
    key: "incidents", label: "Incidents", icon: AlertOctagon,
    to: "/xdr/incidents",
    requires: ["incidents.read", "alerts.read"],
    title: "The analyst's primary work surface · investigation-aware queue",
    children: [
      { key: "my-queue", label: "My Queue", icon: UserIcon,
        to: "/xdr/incidents?mine=1",
        title: "Incidents assigned to you" },
      { key: "detections", label: "Detections", icon: Radar,
        to: "/xdr/detections",
        title: "Individual security findings derived from telemetry and evidence" },
    ],
  },
  {
    key: "investigate", label: "Investigate", icon: FolderSearch,
    to: "/xdr/investigations",
    requires: ["investigations.read", "evidence.read"],
    title: "Causal investigation workspace · attack story · timeline · "
         + "evidence · entities",
    children: [
      { key: "evidence-explorer", label: "Evidence Explorer", icon: Search,
        to: "/xdr/evidence-explorer",
        title: "Cross-case evidence · extracted artifacts · hash chains · "
             + "decoded payloads" },
    ],
  },
  {
    key: "hunting", label: "Hunting", icon: Fingerprint,
    to: "/xdr/hunting",
    title: "Analyst-initiated interrogation of the authoritative stores",
    children: [
      // The analyst event experience (Program H) is not built yet. Until it
      // is, this row goes DIRECTLY to the surface that really holds the
      // environment event stream and says so in its label — it no longer
      // bounces through `/xdr/activities` into a page whose section reads
      // "Administration".
      { key: "telemetry-studio", label: "Environment Activity · Telemetry Studio",
        icon: Sliders,
        to: "/xdr/admin/telemetry-studio",
        title: "Environment activity · real telemetry to query and pivot from · lives under Administration in this build" },
    ],
  },
  {
    key: "intelligence", label: "Intelligence", icon: Globe,
    to: "/xdr/intelligence/threat",
    requires: ["intel.read"],
    title: "Stored indicators, enrichment, decode fabric and ATT&CK coverage",
    children: [
      { key: "ioc", label: "IOC Intelligence", icon: Bug,
        to: "/xdr/intelligence/iocs" },
      { key: "command", label: "Command Intelligence", icon: Terminal,
        to: "/xdr/intelligence/command" },
      { key: "malware", label: "Malware Intelligence", icon: Bug,
        to: "/xdr/intelligence/malware" },
      { key: "mitre", label: "MITRE ATT&CK", icon: Grid3x3,
        to: "/xdr/intelligence/mitre" },
      { key: "kb", label: "Knowledge Base", icon: BookOpen, to: "/xdr/kb" },
    ],
  },
  {
    key: "automate", label: "Automate", icon: Zap,
    to: "/xdr/respond/playbooks",
    requires: ["playbooks.read", "response.read", "response.recommend",
               "response.execute", "response.approve"],
    title: "Response automation and detection content · WHAT runs, WHEN it "
         + "runs, and who approved it",
    children: [
      { key: "automation-rules", label: "Automation Rules", icon: ArrowRightLeft,
        to: "/xdr/respond/automation-rules" },
      { key: "approvals", label: "Approvals Queue", icon: CheckSquare,
        to: "/xdr/respond/approvals" },
      { key: "rule-studio", label: "Rule Studio", icon: Layers,
        to: "/xdr/rule-studio" },
      { key: "detection-registry", label: "Detection Registry", icon: Radar,
        to: "/xdr/admin/detection-registry" },
      { key: "correlation-rules", label: "Correlation Rules", icon: Radar,
        to: "/xdr/admin/correlation-rules" },
    ],
  },
  {
    key: "assets", label: "Assets", icon: Boxes,
    to: "/xdr/assets",
    title: "Endpoint, identity and network inventory · exposure",
    children: [
      { key: "assets-identity", label: "Identity / Users", icon: UserIcon,
        to: "/xdr/assets/identity" },
      { key: "assets-network", label: "Network Assets", icon: Wifi,
        to: "/xdr/assets/network" },
      { key: "exposure", label: "Vulnerability Exposure", icon: ShieldAlert,
        to: "/xdr/exposure" },
      { key: "attack-paths", label: "Attack Paths", icon: Route,
        to: "/xdr/assets/attack-paths" },
      { key: "critical-assets", label: "Critical Assets", icon: KeyRound,
        to: "/xdr/assets/critical" },
    ],
  },
  {
    key: "data-sources", label: "Data Sources", icon: HardDrive,
    to: "/xdr/data-sources",
    requires: ["data_sources.read", "collectors.read"],
    title: "Telemetry onboarding and per-source health",
    children: [
      { key: "collectors", label: "Collectors", icon: Cpu,
        to: "/xdr/admin/collectors" },
      { key: "agents", label: "Agents", icon: Wifi, to: "/xdr/admin/agents" },
      { key: "parsers", label: "Parsers", icon: Filter,
        to: "/xdr/admin/parsers" },
      { key: "normalization", label: "Normalization", icon: Shuffle,
        to: "/xdr/admin/normalization" },
      { key: "telemetry-health", label: "Telemetry Health", icon: ActivityIcon,
        to: "/xdr/admin/telemetry-health" },
    ],
  },
  {
    key: "reports", label: "Reports", icon: FileText,
    to: "/xdr/reports",
    title: "Deterministic investigation reports and their PDF projection",
    children: [],
  },
  {
    key: "clients", label: "Client Management", icon: Users,
    to: "/xdr/clients",
    title: "The tenant estate your identity is authorized to operate",
    children: [
      { key: "users-roles", label: "Users / Roles", icon: Users,
        to: "/xdr/admin/users-roles" },
    ],
  },
  {
    key: "administration", label: "Administration", icon: Sliders,
    to: "/xdr/admin",
    requires: ["platform.read", "platform.admin", "api_keys.read",
               "webhooks.read", "secrets.read", "audit.read",
               "parsers.read", "normalization.read", "extensions.read"],
    title: "Configuration, connections, governance and platform state",
    children: [
      { key: "integrations", label: "Integrations", icon: Plug,
        to: "/xdr/admin/integrations" },
      // `Detection Rules → /xdr/admin/detection-rules` was REMOVED: that key
      // is not an admin section and the row landed on "Unknown admin
      // section". Detection content is owned by Automate (Rule Studio ·
      // Detection Registry · Correlation Rules) and nothing was lost — a
      // second row to the same destination would only split the IA.
      { key: "response-policies", label: "Response Policies",
        icon: ArrowRightLeft, to: "/xdr/admin/response-policies" },
      { key: "response-strategies", label: "Response Strategies", icon: Layers,
        to: "/xdr/admin/response-strategies" },
      { key: "api-webhooks", label: "API / Webhooks", icon: Webhook,
        to: "/xdr/admin/api-webhooks" },
      { key: "platform-health", label: "Platform Health", icon: HeartPulse,
        to: "/xdr/admin/platform-health" },
      { key: "docs", label: "Documentation", icon: BookOpen, to: "/xdr/docs" },
    ],
  },
];

/** Every navigable row, flattened once, longest path first. */
const FLAT = NAV.flatMap((p) => [
  { key: p.key, to: p.to, parent: p.key },
  ...(p.children || []).map((c) => ({ key: c.key, to: c.to, parent: p.key })),
]).map((e) => ({ ...e, path: (e.to || "").split("?")[0],
                 query: (e.to || "").split("?")[1] || "" }))
  .sort((a, b) => b.path.length - a.path.length);

/** Which rail row owns this URL. One resolver, no per-route special cases. */
function useActive() {
  const { pathname, search } = useLocation();
  return useMemo(() => {
    const hit = FLAT.find((e) => {
      if (!e.path) return false;
      if (pathname !== e.path && !pathname.startsWith(`${e.path}/`)) return false;
      if (e.query) return search.includes(e.query);
      return true;
    });
    // A row carrying a query discriminator (My Queue) must not win the
    // bare path, and the bare path must not win when the discriminator
    // is present.
    if (hit && !hit.query) {
      const q = FLAT.find((e) => e.path === hit.path && e.query
                                 && search.includes(e.query));
      if (q) return { key: q.key, parent: q.parent };
    }
    return hit ? { key: hit.key, parent: hit.parent } : { key: null, parent: null };
  }, [pathname, search]);
}

export default function XdrShell({ children, flush = false }) {
  const access = useAccess();
  const active = useActive();
  const navigate = useNavigate();
  const [expanded, setExpanded] = useState({});
  const { pathname } = useLocation();
  const [q, setQ] = useState("");
  const [theme, setTheme] = useState(readTheme);

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

  /** Focus mode: full-width investigation consoles drop the product nav. */
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
    navigate(`/xdr/hunting?q=${encodeURIComponent(term)}`);
  };

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

        <form className="top-search" onSubmit={handleSearch}
              data-testid="xdr-topbar-search-form">
          <Search size={12} />
          <input
            placeholder="Hunt an observable — hostname · SHA-256 · IP · rule · incident · process…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            data-testid="xdr-topbar-search"
          />
        </form>

        <div className="top-actions">
          {/* XDR → NivXMachines Workspace hand-off. Separate deployment at
              its own origin, so it opens in a new tab and is never a rail
              route. */}
          <WorkspaceLaunch testid="xdr-open-workspace" />
          {/* No notification service exists in this build, so no bell is
              painted: a bell that never rings is a lie. */}
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

          {/* Scope Navigator · EffectiveScope = Requested ∩ Authorized.
              Fault containment ONLY: if the control itself fails to render
              the rail survives and the pill states the failure. It grants
              no tenant, unlocks no incident scope and hides no denial. */}
          <NxErrorBoundary fallback={(err) => (
            <span data-testid="xdr-scope-navigator-error"
                  title={String(err?.message || err)}
                  style={{ display: "inline-flex", alignItems: "center",
                           gap: 6, fontSize: 11, fontWeight: 700,
                           color: "var(--muted)" }}>
              <Lock size={13} style={{ opacity: .8 }} />
              SCOPE CONTROL ERROR · NO SCOPE GRANTED
            </span>
          )}>
            <XdrScopeNavigator />
          </NxErrorBoundary>
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
          {NAV.filter((primary) => {
            if (!primary.requires) return true;
            return access.canAny(primary.requires) !== false;
          }).map((primary) => {
            const kids = primary.children || [];
            const isActive = active.parent === primary.key;
            const selfActive = active.key === primary.key;
            const open = expanded[primary.key] ?? isActive;
            const PIcon = primary.icon;
            return (
              <div key={primary.key}
                   data-testid={`xdr-rail-${primary.key}`}
                   data-open={open || undefined}>
                <div className={`nav-item${isActive ? " active" : ""}`}
                     data-active={selfActive || undefined}
                     data-section-active={isActive || undefined}
                     data-testid={`xdr-nav-${primary.key}`}
                     title={primary.title || undefined}
                     role="button" tabIndex={0}
                     style={{ cursor: "pointer" }}
                     onKeyDown={(e) => { if (e.key === "Enter") navigate(primary.to); }}
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
                  const on = active.key === item.key;
                  return (
                    <button key={item.key}
                            data-testid={`xdr-nav-${item.key}`}
                            style={{ paddingLeft: 34 }}
                            className={`nav-item ${on ? "active" : ""}`}
                            onClick={() => navigate(item.to)}
                            data-active={on || undefined}
                            title={item.title || undefined}>
                      <span className="ic"><Icon size={12} /></span>
                      {item.label}
                    </button>
                  );
                })}
              </div>
            );
          })}
        </aside>
        <main className={`main${flush ? " flush" : ""}`} data-testid="xdr-main">
          {/* One context bar for every plane: breadcrumbs plus the
              customer / endpoint / incident / evidence context that must
              survive a pivot. It states context, never grants it. */}
          <XdrContextBar />
          {children}
        </main>
        {/* Cisco XDR's persistent ribbon: pinned to the bottom of the
            viewport on every page, expanded by default, collapsible to a
            floating button, vertically resizable from its top edge. */}
        <XdrRibbon />
      </div>
    </div>
    </NxDensityProvider>
  );
}
