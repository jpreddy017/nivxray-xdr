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
import React, { useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  LayoutGrid, LayoutDashboard, AlertOctagon, User as UserIcon, ArrowRightLeft,
  Search, FolderSearch, Fingerprint,
  Radar, Globe, Bug, Grid3x3, BookOpen, Terminal,
  Boxes, ShieldOff, Route, KeyRound, Layers,
  Database, Plug, HardDrive, Cpu, Wifi, Sliders, Activity as ActivityIcon,
  Filter, Shuffle, Zap, Users, Webhook, HeartPulse, CheckSquare,
  ExternalLink, Bell, HelpCircle, Lock, ShieldAlert,
} from "lucide-react";

import { useAuth } from "@/lib/auth";
import { NivxrayMark } from "@/components/brand/NivxrayBrand";
import "./xdr-console.css";

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
const SIDEBAR = [
  {
    section: "Workspace",
    items: [
      { key: "workspace", label: "Workspace (Analyst)", icon: LayoutGrid,
        to: "/analyst", external: true,
        title: "Opens the existing NivXRay Analyst Workspace in a new tab" },
    ],
  },
  {
    section: "Detect",
    items: [
      { key: "rule-studio", label: "Rule Studio", icon: Layers,
        to: "/xdr/rule-studio",
        title: "Authoritative authoring layer · 9 lanes · lifecycle · 11-check Regression Gate" },
      { key: "detection-registry", label: "Detection Registry", icon: Radar,
        to: "/xdr/admin/detection-registry",
        title: "AUTHORITATIVE detection-content registry · single source of truth for every rule NivXRay executes" },
      { key: "correlation-rules", label: "Correlation Rules", icon: Radar,
        to: "/xdr/admin/correlation-rules",
        title: "Stateful event-stream correlation engine · 13 operators · emits evidence, never verdicts · absorbed into Rule Studio lane" },
      { key: "detections", label: "Detection Engineering", icon: Radar,
        to: "/xdr/detections",
        title: "Sigma-compatible authoring workstation · rules authored here promote to the Detection Registry" },
    ],
  },
  {
    section: "Command Center",
    items: [
      { key: "mss-dashboard", label: "MSS Dashboard", icon: LayoutDashboard, to: "/xdr/mss-dashboard",
        title: "SOC command center · triage lenses · analyst workload · customer operations · auto-investigation status · detection & MITRE overview" },
    ],
  },
  {
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
    section: "Investigations",
    items: [
      { key: "investigations", label: "Investigation Workspace", icon: FolderSearch,
        disabled: true, title: "Native XDR investigation workspace — arrives in Phase 5" },
      { key: "evidence-explorer", label: "Evidence Explorer", icon: Search,
        disabled: true, title: "Cross-case Evidence Explorer — arrives in Phase 5" },
      { key: "entity-search", label: "Entity Search", icon: Fingerprint,
        disabled: true, title: "Cross-case entity search — arrives in Phase 6" },
      { key: "attack-story", label: "Attack Story", icon: Fingerprint,
        disabled: true, title: "Deterministic attack-story projection — arrives in Phase 5" },
    ],
  },
  {
    section: "Intelligence",
    items: [
      { key: "ti",       label: "Threat Intelligence",  icon: Globe,
        reserved: "/xdr/intelligence/threat",
        title: "Native XDR Threat Intelligence — arrives in a later slice" },
      { key: "ioc",      label: "IOC Intelligence",     icon: Bug,
        reserved: "/xdr/intelligence/iocs",
        title: "Native XDR IOC Intelligence — arrives in a later slice" },
      { key: "command",  label: "Command Intelligence", icon: Terminal,
        reserved: "/xdr/intelligence/command",
        title: "Native XDR Command Intelligence — arrives in Slice 14" },
      { key: "malware",  label: "Malware Intelligence", icon: Bug,
        reserved: "/xdr/intelligence/malware",
        title: "Native XDR Malware Intelligence — arrives in a later slice" },
      { key: "mitre",    label: "MITRE ATT&CK",         icon: Grid3x3,
        to: "/xdr/intelligence/mitre",
        title: "Native XDR MITRE ATT&CK heatmap · powered by authoritative NivXRay incident evidence" },
      { key: "kb",       label: "Knowledge Base",       icon: BookOpen,
        to: "/xdr/kb",
        title: "Native XDR Knowledge Base · consumes /api/kb" },
      { key: "docs",     label: "Documentation",        icon: BookOpen,
        to: "/xdr/docs",
        title: "Native XDR Documentation · consumes /api/docs" },
      { key: "exposure", label: "Vulnerability Exposure", icon: ShieldAlert,
        to: "/xdr/exposure",
        title: "CVE / NVD / KEV / EPSS · asset ↔ software ↔ CVE correlation" },
    ],
  },
  {
    section: "Respond",
    items: [
      { key: "playbooks", label: "Playbooks", icon: Zap,
        to: "/xdr/respond/playbooks",
        title: "Reusable response workflows · design-only until the Response Engine is wired" },
      { key: "automation-rules", label: "Automation Rules", icon: ArrowRightLeft,
        to: "/xdr/respond/automation-rules",
        title: "WHEN → THEN rules that invoke playbooks · design-only until Response Engine is wired" },
      { key: "approvals", label: "Approvals Queue", icon: CheckSquare,
        to: "/xdr/respond/approvals",
        title: "Peer-approval queue for pending Response Engine executions" },
    ],
  },
  {
    section: "Exposure",
    items: [
      { key: "assets",          label: "Assets",          icon: Boxes,    disabled: true },
      { key: "vulnerabilities", label: "Vulnerabilities", icon: ShieldOff, disabled: true },
      { key: "exposure",        label: "Exposure",        icon: Layers,   disabled: true },
      { key: "attack-paths",    label: "Attack Paths",    icon: Route,    disabled: true },
      { key: "critical-assets", label: "Critical Assets", icon: KeyRound, disabled: true },
    ],
  },
  {
    section: "Data",
    items: [
      { key: "sdl", label: "Security Data Lake", icon: Database, disabled: true,
        title: "Security Data Lake — arrives in a later slice" },
    ],
  },
  {
    section: "Administration",
    items: [
      { key: "integrations",      label: "Integrations",      icon: Plug,          to: "/xdr/admin/integrations" },
      { key: "data-sources",      label: "Data Sources",      icon: HardDrive,     to: "/xdr/admin/data-sources" },
      { key: "collectors",        label: "Collectors",        icon: Cpu,           to: "/xdr/admin/collectors" },
      { key: "agents",            label: "Agents",            icon: Wifi,          to: "/xdr/admin/agents" },
      { key: "telemetry-studio",  label: "Telemetry Studio",  icon: Sliders,       to: "/xdr/admin/telemetry-studio" },
      { key: "telemetry-health",  label: "Telemetry Health",  icon: ActivityIcon,  to: "/xdr/admin/telemetry-health" },
      { key: "parsers",           label: "Parsers",           icon: Filter,        to: "/xdr/admin/parsers" },
      { key: "normalization",     label: "Normalization",     icon: Shuffle,       to: "/xdr/admin/normalization" },
      { key: "detection-rules",   label: "Detection Rules",   icon: Zap,           to: "/xdr/admin/detection-rules" },
      { key: "response-policies", label: "Response Policies", icon: ArrowRightLeft, to: "/xdr/admin/response-policies" },
      { key: "users-roles",       label: "Users / Roles",     icon: Users,         to: "/xdr/admin/users-roles" },
      { key: "api-webhooks",      label: "API / Webhooks",    icon: Webhook,       to: "/xdr/admin/api-webhooks" },
      { key: "platform-health",   label: "Platform Health",   icon: HeartPulse,    to: "/xdr/admin/platform-health" },
    ],
  },
];

// Determine which sidebar entry is currently active based on location.
function useActiveKey() {
  const { pathname, search } = useLocation();
  return useMemo(() => {
    if (pathname === "/xdr")                     return "incidents";
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

export default function XdrShell({ children }) {
  const { user, logout } = useAuth();
  const activeKey = useActiveKey();
  const navigate  = useNavigate();
  const { pathname } = useLocation();
  const [q, setQ] = useState("");

  const initials = (user?.email || "?").slice(0, 2).toUpperCase();
  const tenant   = user?.tenant || user?.email || "default";

  const handleSearch = (e) => {
    e.preventDefault();
    const term = q.trim();
    if (!term) return;
    navigate(`/xdr/incidents?q=${encodeURIComponent(term)}`);
  };

  const openExternal = (to) => window.open(to, "_blank", "noopener,noreferrer");

  return (
    <div className="xdr-console"
          data-testid="xdr-shell">
      {/* ── Top bar (utility only) ────────────────────────── */}
      <div className="topbar">
        <Link to="/xdr" className="brand" data-testid="xdr-brand">
          <NivxrayMark size={26} boxed={false} />
          NIVXRAY <span className="accent">XDR</span>
        </Link>

        <form className="top-search" onSubmit={handleSearch} data-testid="xdr-topbar-search-form">
          <Search size={12} />
          <input
            placeholder="Search incidents, hosts, users, hashes, IOCs…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            data-testid="xdr-topbar-search"
          />
        </form>

        <div className="top-actions">
          <span className="tier-pill" data-testid="xdr-tenant-pill" title="Active tenant / workspace">
            TENANT · {String(tenant).toUpperCase().slice(0, 24)}
          </span>
          <button
            className="btn ghost" style={{ padding: 6 }}
            title="Notifications" data-testid="xdr-notifications"
          >
            <Bell size={13} />
          </button>
          <button
            className="btn ghost" style={{ padding: 6 }}
            title="Help" data-testid="xdr-help"
          >
            <HelpCircle size={13} />
          </button>
          <button
            className="user-chip"
            onClick={logout}
            title={`${user?.email || ""} · Logout`}
            data-testid="xdr-user-logout"
          >
            {initials}
          </button>
        </div>
      </div>

      {/* ── Body ──────────────────────────────────────────── */}
      <div className="body">
        <aside className="sidebar" data-testid="xdr-sidebar">
          {SIDEBAR.map((group) => (
            <div key={group.section}>
              <div className="nav-title">{group.section}</div>
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = item.key === activeKey;
                const testId = `xdr-nav-${item.key}`;
                if (item.disabled) {
                  return (
                    <button
                      key={item.key}
                      className="nav-item disabled"
                      title={item.title || "Not available in this slice"}
                      disabled
                      data-testid={testId}
                    >
                      <span className="ic"><Icon size={13} /></span>
                      {item.label}
                    </button>
                  );
                }
                if (item.external) {
                  return (
                    <button
                      key={item.key}
                      className="nav-item"
                      onClick={() => openExternal(item.to)}
                      data-testid={testId}
                      title={item.title || `Opens ${item.to} in a new browser tab`}
                    >
                      <span className="ic"><Icon size={13} /></span>
                      {item.label}
                      <span className="ext"><ExternalLink size={10} /></span>
                    </button>
                  );
                }
                return (
                  <button
                    key={item.key}
                    className={`nav-item ${isActive ? "active" : ""}`}
                    onClick={() => navigate(item.to || item.reserved)}
                    data-active={isActive || undefined}
                    data-testid={testId}
                    title={item.title || undefined}
                  >
                    <span className="ic"><Icon size={13} /></span>
                    {item.label}
                    {item.reserved && (
                      <span className="ext" title="Reserved · native XDR placeholder">
                        <Lock size={9} />
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </aside>
        <main className="main" data-testid="xdr-main">
          {children}
        </main>
      </div>
    </div>
  );
}
