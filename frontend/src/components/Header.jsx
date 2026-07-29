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
  BarChart3, Battery, Radar, Upload, ShieldCheck, Zap,
} from "lucide-react";

export default function Header() {
  const { user, logout } = useAuth();
  const loc = useLocation();
  const isAdmin = user?.role === "admin";
  const [cpOpen, setCpOpen] = useState(false);

  // Primary tabs — always visible, high-usage. Routed via NavTabs
  // (variant="nav") so all pages inherit the DetectFlow design system.
  // Admin-only tools (INGEST · VALIDATION · BENCHMARK · BATTERY) live
  // inside Admin → quick-links (see AdminPage.jsx).
  const primary = [
    { key: "workspace",  href: "/",           label: "WORKSPACE",  icon: LayoutGrid, testId: "nav-workspace" },
    { key: "trajectory", href: "/v2/trajectory", label: "TRAJECTORY", icon: Radar,   testId: "nav-trajectory" },
    { key: "batch",      href: "/batch-test", label: "BATCH",      icon: TestTube,   testId: "nav-batch-test" },
    { key: "heatmap",    href: "/heatmap",    label: "HEATMAP",    icon: Grid,       testId: "nav-heatmap" },
    { key: "documents",  href: "/documents",  label: "DOCUMENTS",  icon: FolderOpen, testId: "nav-documents" },
    { key: "nivxforge",  href: "/nivxforge",  label: "LAB",        icon: Radar,      testId: "nav-nivxforge" },
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
