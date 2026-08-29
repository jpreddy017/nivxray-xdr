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
  LayoutGrid, AlertOctagon, User as UserIcon, ArrowRightLeft,
  Search, FolderSearch, Fingerprint,
  Radar, Globe, Bug, Grid3x3, BookOpen, Terminal,
  Boxes, ShieldOff, Route, KeyRound, Layers,
  Database, Plug, HardDrive, Cpu, Wifi, Sliders, Activity as ActivityIcon,
  Filter, Shuffle, Zap, Users, Webhook, HeartPulse,
  ExternalLink, Bell, HelpCircle,
} from "lucide-react";

import { useAuth } from "@/lib/auth";
import { NivxrayMark } from "@/components/brand/NivxrayBrand";
import "./xdr-console.css";

// ── Sidebar tree · owner-locked ────────────────────────────────────
// key      – unique id (used for active highlighting + data-testid)
// label    – exact label rendered
// icon     – lucide icon
// to       – route target
// external – true → opens in a new browser tab (no duplication)
// disabled – true → row rendered but not clickable ("Not available")
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
    section: "Operations",
    items: [
      { key: "dashboard",  label: "Dashboard",  icon: LayoutGrid,     to: "/xdr" },
      { key: "incidents",  label: "Incidents",  icon: AlertOctagon,   to: "/xdr/incidents" },
      { key: "my-queue",   label: "My Queue",   icon: UserIcon,       to: "/xdr/incidents?mine=1" },
      { key: "response",   label: "Response",   icon: ArrowRightLeft, disabled: true,
        title: "Response console — arrives in a later slice" },
    ],
  },
  {
    section: "Investigations",
    items: [
      { key: "investigations", label: "Investigations", icon: FolderSearch,
        to: "/investigations", external: true },
      { key: "evidence-explorer", label: "Evidence Explorer", icon: Search,
        to: "/evidence-explorer", external: true },
      { key: "entity-search", label: "Entity Search", icon: Fingerprint,
        disabled: true, title: "Cross-case entity search — later slice" },
    ],
  },
  {
    section: "Intelligence",
    items: [
      { key: "ti",       label: "Threat Intelligence",  icon: Globe,   to: "/threat-intel", external: true },
      { key: "ioc",      label: "IOC Intelligence",     icon: Bug,     to: "/threat-intel?tab=iocs", external: true },
      { key: "cmd",      label: "Command Intelligence", icon: Terminal, to: "/analyze", external: true },
      { key: "malware",  label: "Malware Intelligence", icon: Bug,     to: "/documents", external: true },
      { key: "mitre",    label: "MITRE ATT&CK",         icon: Grid3x3, to: "/heatmap", external: true },
      { key: "kb",       label: "Knowledge Base",       icon: BookOpen, to: "/kb", external: true },
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
      { key: "integrations",     label: "Integrations",      icon: Plug,       to: "/admin", external: true },
      { key: "data-sources",     label: "Data Sources",      icon: HardDrive,  disabled: true },
      { key: "collectors",       label: "Collectors",        icon: Cpu,        disabled: true },
      { key: "agents",           label: "Agents",            icon: Wifi,       disabled: true },
      { key: "telemetry-studio", label: "Telemetry Studio",  icon: Sliders,    disabled: true },
      { key: "telemetry-health", label: "Telemetry Health",  icon: ActivityIcon, disabled: true },
      { key: "parsers",          label: "Parsers",           icon: Filter,     disabled: true },
      { key: "normalization",    label: "Normalization",     icon: Shuffle,    disabled: true },
      { key: "detection-rules",  label: "Detection Rules",   icon: Zap,        to: "/admin/models", external: true },
      { key: "response-policies", label: "Response Policies", icon: ArrowRightLeft, disabled: true },
      { key: "users-roles",      label: "Users / Roles",     icon: Users,      to: "/admin", external: true },
      { key: "api-webhooks",     label: "API / Webhooks",    icon: Webhook,    disabled: true },
      { key: "platform-health",  label: "Platform Health",   icon: HeartPulse, to: "/platform", external: true },
    ],
  },
];

// Determine which sidebar entry is currently active based on location.
function useActiveKey() {
  const { pathname, search } = useLocation();
  return useMemo(() => {
    if (pathname === "/xdr")                     return "dashboard";
    if (pathname.startsWith("/xdr/incidents")) {
      return search.includes("mine=1") ? "my-queue" : "incidents";
    }
    return null;
  }, [pathname, search]);
}

export default function XdrShell({ children }) {
  const { user, logout } = useAuth();
  const activeKey = useActiveKey();
  const navigate  = useNavigate();
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
    <div className="xdr-console" data-testid="xdr-shell">
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
                    onClick={() => navigate(item.to)}
                    data-active={isActive || undefined}
                    data-testid={testId}
                  >
                    <span className="ic"><Icon size={13} /></span>
                    {item.label}
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
