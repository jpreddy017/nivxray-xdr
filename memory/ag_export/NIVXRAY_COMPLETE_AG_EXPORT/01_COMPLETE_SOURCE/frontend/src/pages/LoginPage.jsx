import { useState } from "react";
import { useNavigate, Navigate } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import Logo from "@/components/Logo";
import { LogIn, Terminal } from "lucide-react";

export default function LoginPage() {
  const { login, user } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState("admin@nivxray.com");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  if (user) return <Navigate to="/" replace />;

  const onSubmit = async (e) => {
    e.preventDefault();
    setErr("");
    setLoading(true);
    try {
      await login(email, password);
      nav("/", { replace: true });
    } catch (e2) {
      setErr(e2?.response?.data?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="nvx-login-grid"
      style={{
        minHeight: "100vh",
        background: "var(--bg)",
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        position: "relative",
      }}
    >
      {/* left decorative pane */}
      <aside
        className="nvx-login-aside"
        style={{
          position: "relative",
          overflow: "hidden",
          borderRight: "1px solid var(--border)",
          padding: 40,
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
        }}
      >
        <div
          style={{
            position: "absolute",
            inset: 0,
            backgroundImage:
              "url(https://images.unsplash.com/photo-1631375937044-6dd5beac01d2?crop=entropy&cs=srgb&fm=jpg&q=85&ixlib=rb-4.1.0)",
            backgroundSize: "cover",
            backgroundPosition: "center",
            opacity: 0.12,
            filter: "grayscale(60%)",
          }}
        />
        <div style={{ position: "relative", display: "flex", alignItems: "center", gap: 12 }}>
          <Logo size={28} />
          <div style={{ fontFamily: "Chivo", fontWeight: 900, fontSize: 20, letterSpacing: "0.16em" }}>
            NIVX<span style={{ color: "var(--accent)" }}>RAY</span>
          </div>
        </div>

        <div style={{ position: "relative", maxWidth: 520 }}>
          <div className="mono" style={{ color: "var(--warn)", fontSize: 10, letterSpacing: "0.24em", marginBottom: 18 }}>
            /// SECURE ANALYST TERMINAL — v1.0
          </div>
          <h1
            style={{
              fontFamily: "Chivo",
              fontWeight: 900,
              fontSize: 46,
              lineHeight: 1.05,
              margin: 0,
              letterSpacing: "-0.01em",
            }}
          >
            Decode. Enrich. <br />
            <span style={{ color: "var(--accent)" }}>Attribute.</span>
          </h1>
          <p className="mono" style={{ marginTop: 20, color: "var(--text-dim)", fontSize: 13, lineHeight: 1.7 }}>
            A DFIR-grade payload triage lab. Chain 40+ decoders, auto-solve
            nested encodings, and produce MITRE ATT&amp;CK maps, YARA hits,
            OSINT-enriched IOCs and analyst-ready reports in a single pass.
          </p>
        </div>

        <div className="mono" style={{ position: "relative", color: "var(--text-mute)", fontSize: 10, letterSpacing: "0.2em" }}>
          NIVXRAY // NIVX FORGE PROJECT // {new Date().getFullYear()}
        </div>
      </aside>

      {/* right login form */}
      <main style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 40 }}>
        <form
          onSubmit={onSubmit}
          data-testid="login-form"
          className="brut-border"
          style={{
            width: "100%",
            maxWidth: 380,
            background: "var(--surface)",
            padding: 32,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 22 }}>
            <Terminal size={18} color="var(--accent)" />
            <span className="mono" style={{ fontSize: 11, letterSpacing: "0.22em", color: "var(--accent)" }}>
              AUTHENTICATE
            </span>
          </div>

          <label className="mono" style={{ fontSize: 10, letterSpacing: "0.2em", color: "var(--text-mute)" }}>
            EMAIL
          </label>
          <input
            data-testid="login-email-input"
            className="nvx-input"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            style={{ marginTop: 6, marginBottom: 16 }}
          />

          <label className="mono" style={{ fontSize: 10, letterSpacing: "0.2em", color: "var(--text-mute)" }}>
            PASSWORD
          </label>
          <input
            data-testid="login-password-input"
            className="nvx-input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{ marginTop: 6, marginBottom: 20 }}
          />

          {err && (
            <div
              className="mono"
              data-testid="login-error"
              style={{
                color: "var(--high)",
                fontSize: 11,
                border: "1px solid var(--high)",
                padding: "8px 10px",
                background: "rgba(217,108,108,0.08)",
                marginBottom: 16,
              }}
            >
              ✗ {err}
            </div>
          )}

          <button
            type="submit"
            data-testid="login-submit-btn"
            disabled={loading}
            className="nvx-btn primary"
            style={{ width: "100%", justifyContent: "center" }}
          >
            <LogIn size={14} />
            {loading ? "AUTHENTICATING..." : "ENTER TERMINAL"}
          </button>

          <div
            className="mono"
            style={{
              marginTop: 18,
              fontSize: 10,
              color: "var(--text-mute)",
              lineHeight: 1.6,
              letterSpacing: "0.05em",
            }}
          >
            Default admin{" "}
            <span style={{ color: "var(--text-dim)" }}>admin@nivxray.com</span> — the credential was set at
            initial deployment. Change it via the Admin panel.
          </div>
        </form>
      </main>
    </div>
  );
}
