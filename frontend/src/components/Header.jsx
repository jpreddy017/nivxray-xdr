import { Link, useLocation } from "react-router-dom";
import { useState } from "react";
import Logo from "@/components/Logo";
import ChangePasswordModal from "@/components/ChangePasswordModal";
import NavDropdown from "@/components/NavDropdown";
import NavTabs from "@/components/NavTabs";
import CorpusHealthPill from "@/components/CorpusHealthPill";
import { useAuth } from "@/lib/auth";
import {
  LogOut, LayoutGrid, Cog, Sparkles, Beaker, Terminal, BookOpen,
  KeyRound, Rss, TestTube, GraduationCap, Grid, Wrench, Library, Gauge, FolderOpen,
  BarChart3, Battery, Upload, ShieldCheck, Zap, History as HistoryIcon,
} from "lucide-react";

export default function Header() {
  const { user, logout } = useAuth();
  const loc = useLocation();
  const isAdmin = user?.role === "admin";
  const [cpOpen, setCpOpen] = useState(false);

  // Primary tabs — always visible, high-usage. Routed via NavTabs
  // (variant="nav") so all pages inherit the DetectFlow design system.
  //
  // 2026-02 · Nav Consolidation (owner directive) — INVESTIGATE tab
  // removed. Investigation is a *mode* of the Workspace, not a separate
  // page. HISTORY is a full-page investigation listing; restoring a
  // case returns to the Workspace with full state rehydrated.

  const primary = [
    { key: "workspace",   href: "/",              label: "WORKSPACE",   icon: LayoutGrid, testId: "nav-workspace" },
    // XDR removed from the Workspace nav (OWNER LOCK · Phase 1 ·
    // REMOVE_LEGACY_XDR). NivXRay XDR is its own product, promoted to
    // xdr.nivxforge.com in Phase 2. This item was already a dead link:
    // `/xdr` has no route in this app (the shell lives in
    // /app/apps/nivxray-xdr), so the catch-all bounced it back to `/`.
    // Removing it removes a broken promise, not a capability. The real
    // cross-product launcher is Phase 4 work.
    { key: "history",     href: "/history",       label: "HISTORY",     icon: HistoryIcon, testId: "nav-history", title: "Investigation history · restore any past case with full state" },
    // INVESTIGATIONS removed from the Workspace nav (OWNER LOCK · Phase 1 ·
    // Q1 = A · REMOVE_LEGACY_INVESTIGATIONS). Nav removal ONLY — the
    // `/investigations`, `/investigations/:id`, `/investigations/:id/replay`
    // and `/investigation-summary` ROUTES stay live because four retained
    // Workspace workflows land on them: Correlate, Find Related, the History
    // drilldown and Quick Open. Investigations is no longer a standalone
    // product section in the Workspace; the investigation capability is
    // untouched.
    // Trajectory retired from top-level nav (Phase A.5 · item 3.7 · 2026-02-16).
    { key: "batch",       href: "/batch-test",    label: "BATCH",       icon: TestTube,   testId: "nav-batch-test" },
    { key: "heatmap",     href: "/heatmap",       label: "HEATMAP",     icon: Grid,       testId: "nav-heatmap" },
    // X-LAB (DEV) removed (OWNER LOCK · Phase 1 · Q2 = A). It pointed at
    // `/nivxforge/x-lab`, a route deleted on 2026-08-11, and `/nivxforge/*`
    // product exposure is removed from the Workspace entirely.
  ];

  // Grouped: analysis tools (secondary usage)
  const toolsItems = [
    { to: "/analyze",      label: "Command Analyzer", icon: Terminal, testId: "nav-command-analyzer" },
    { to: "/threat-model", label: "Threat Model",     icon: Terminal, testId: "nav-threat-model" },
  ];

  // Grouped: reference / knowledge + learning (open to all end-users)
  const learnItems = [
    { to: "/lab",     label: "Practice Lab",   icon: GraduationCap, testId: "nav-lab" },
    { to: "/learner", label: "Learner",        icon: GraduationCap, testId: "nav-learner" },
    { to: "/kb",      label: "Knowledge Base", icon: BookOpen,      testId: "nav-knowledge-base" },
    { to: "/docs",    label: "Docs",           icon: BookOpen,      testId: "nav-docs" },
  ];

  // Grouped: admin (admin-only, occasional usage)
  const adminItems = [
    { to: "/admin",                 label: "Admin Panel",    icon: Cog,            testId: "nav-admin" },
    { to: "/documents",             label: "Documents",      icon: FolderOpen,     testId: "nav-documents" },
    { to: "/admin/training-inbox",  label: "Training Inbox", icon: Rss,            testId: "nav-training-inbox" },
    { to: "/admin/models",          label: "Model Studio",   icon: Sparkles,       testId: "nav-model-studio" },
    { to: "/admin/samples",         label: "Sample Library", icon: Beaker,         testId: "nav-sample-library" },
  ];

  return (
    <header
      className="brut-border"
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "10px 18px",
        borderTop: "none",
        borderLeft: "none",
        borderRight: "none",
        background: "var(--surface)",
        position: "sticky",
        top: 0,
        zIndex: 20,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        <Link to="/" data-testid="brand-link" style={{ display: "flex", alignItems: "center", gap: 10, color: "var(--text)", textDecoration: "none" }}>
          <Logo size={22} />
          <div style={{ lineHeight: 1 }}>
            <div style={{ fontFamily: "Chivo", fontWeight: 900, fontSize: 15, letterSpacing: "0.14em" }}>
              NIVX<span style={{ color: "var(--accent)" }}>RAY</span>
            </div>
            <div className="mono" style={{ fontSize: 9, color: "var(--text-mute)", letterSpacing: "0.14em", marginTop: 2 }}>
              DECODER / THREAT-LAB
            </div>
          </div>
        </Link>
        <CorpusHealthPill />
        <span style={{ color: "var(--border-strong)" }}>│</span>

        <nav
          data-testid="nav-shell"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 4,
            padding: 4,
            borderRadius: 10,
            background: "linear-gradient(160deg, rgba(15,23,42,0.72), rgba(2,6,23,0.62))",
            border: "1px solid rgba(148,163,184,0.14)",
            backdropFilter: "blur(14px) saturate(150%)",
            WebkitBackdropFilter: "blur(14px) saturate(150%)",
            boxShadow: "inset 0 1px 0 rgba(255,255,255,0.03), 0 4px 18px rgba(2,6,23,0.35)",
            flexWrap: "nowrap",
          }}
        >
          <NavTabs
            items={primary}
            variant="nav"
            size="sm"
            tone="accent"
            framed={false}
            testId="nav-primary"
            ariaLabel="Primary navigation"
            style={{ padding: 0, background: "transparent", border: "none", boxShadow: "none", flexWrap: "nowrap" }}
          />

          <span aria-hidden style={{
            width: 1, height: 20,
            background: "rgba(148,163,184,0.18)",
            margin: "0 2px",
            flexShrink: 0,
          }} />

          <NavDropdown label="TOOLS"    icon={Wrench}  items={toolsItems} testId="nav-tools" />
          <NavDropdown label="LEARN"    icon={Library} items={learnItems} testId="nav-learn" />
          {isAdmin && (
            <NavDropdown label="ADMIN" icon={Cog} items={adminItems} testId="nav-admin-menu" />
          )}
        </nav>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        {user ? (
          <>
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }} data-testid="header-user-email">
              {user?.email}
            </div>
            <button
              data-testid="header-change-password-btn"
              className="nvx-btn sm ghost"
              onClick={() => setCpOpen(true)}
              title="Rotate your password"
            >
              <KeyRound size={13} /> PASSWORD
            </button>
            <button data-testid="header-logout-btn" className="nvx-btn sm" onClick={logout}>
              <LogOut size={13} /> LOGOUT
            </button>
          </>
        ) : (
          <Link
            to="/login"
            data-testid="header-login-link"
            className="nvx-btn sm"
            style={{ textDecoration: "none" }}
          >
            LOGIN
          </Link>
        )}
      </div>
      <ChangePasswordModal open={cpOpen} onClose={() => setCpOpen(false)} />
    </header>
  );
}
