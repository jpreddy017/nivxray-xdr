import { Link, useLocation } from "react-router-dom";
import Logo from "@/components/Logo";
import { useAuth } from "@/lib/auth";
import { LogOut, LayoutGrid, Cog, Radar, Sparkles } from "lucide-react";

export default function Header() {
  const { user, logout } = useAuth();
  const loc = useLocation();
  const isAdmin = user?.role === "admin";

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
        <span style={{ color: "var(--border-strong)" }}>│</span>
        <nav style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <Link
            to="/"
            data-testid="nav-workspace"
            className={`nvx-btn sm ghost ${loc.pathname === "/" ? "" : ""}`}
            style={{ color: loc.pathname === "/" ? "var(--accent)" : "var(--text-dim)" }}
          >
            <LayoutGrid size={13} /> WORKSPACE
          </Link>
          {isAdmin && (
            <Link
              to="/admin"
              data-testid="nav-admin"
              className={`nvx-btn sm ghost`}
              style={{ color: loc.pathname === "/admin" ? "var(--accent)" : "var(--text-dim)" }}
            >
              <Cog size={13} /> ADMIN
            </Link>
          )}
          {isAdmin && (
            <Link
              to="/admin/models"
              data-testid="nav-model-studio"
              className={`nvx-btn sm ghost`}
              style={{ color: loc.pathname.startsWith("/admin/models") ? "var(--accent)" : "var(--text-dim)" }}
            >
              <Sparkles size={13} /> MODEL STUDIO
            </Link>
          )}
        </nav>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }} data-testid="header-user-email">
          {user?.email}
        </div>
        <button data-testid="header-logout-btn" className="nvx-btn sm" onClick={logout}>
          <LogOut size={13} /> LOGOUT
        </button>
      </div>
    </header>
  );
}
