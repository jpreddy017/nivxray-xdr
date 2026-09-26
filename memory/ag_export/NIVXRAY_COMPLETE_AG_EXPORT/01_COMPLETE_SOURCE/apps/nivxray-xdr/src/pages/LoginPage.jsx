/**
 * NivXRay XDR standalone login page.
 *
 * Same NivXRay identity: the token stored in localStorage["nvx_token"]
 * is shared with the base NivXRay application on the same origin, so
 * a user only needs to authenticate once.
 */
import React, { useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import { NivxrayLockup } from "@/components/brand/NivxrayBrand";

export default function LoginPage() {
  const { login } = useAuth();
  const navigate  = useNavigate();
  const [params]  = useSearchParams();
  const returnTo  = params.get("returnTo") || "/xdr";

  const [email, setEmail]   = useState("");
  const [pw, setPw]         = useState("");
  const [busy, setBusy]     = useState(false);
  const [err, setErr]       = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      await login(email, pw);
      navigate(returnTo || "/xdr", { replace: true });
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "Login failed.");
    } finally { setBusy(false); }
  };

  return (
    <div style={{
      minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center",
      background: "#0A0C11",
    }}>
      <form
        onSubmit={submit}
        style={{
          width: 380, background: "#11141C", border: "1px solid #212736",
          borderRadius: 8, padding: 22, boxShadow: "0 20px 60px rgba(0,0,0,.5)",
        }}
        data-testid="xdr-login-form"
      >
        <div style={{ marginBottom: 18 }}>
          <NivxrayLockup size={40} />
        </div>

        <label style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: ".4px", color: "#78808F", fontWeight: 700 }}>
          Email
        </label>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="username"
          required
          style={inputStyle}
          data-testid="xdr-login-email"
        />

        <label style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: ".4px", color: "#78808F", fontWeight: 700, marginTop: 12, display: "block" }}>
          Password
        </label>
        <input
          type="password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          autoComplete="current-password"
          required
          style={inputStyle}
          data-testid="xdr-login-password"
        />

        {err && (
          <div
            style={{ marginTop: 12, color: "#ff9494", fontSize: 12 }}
            data-testid="xdr-login-error"
          >
            {String(err)}
          </div>
        )}

        <button
          type="submit"
          disabled={busy}
          style={{
            marginTop: 18, width: "100%", padding: "10px 12px",
            background: "#2A2145", color: "#9B7BF0",
            border: "1px solid #9B7BF0", borderRadius: 6,
            fontWeight: 800, fontSize: 12, letterSpacing: ".4px",
            textTransform: "uppercase", cursor: busy ? "wait" : "pointer",
          }}
          data-testid="xdr-login-submit"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>

        <div style={{ marginTop: 14, fontSize: 10.5, color: "#78808F" }}>
          Signed in? You can also open <a href="/" style={{ color: "#3FC1E8", textDecoration: "underline" }}>NivXRay Workspace</a>.
        </div>
      </form>
    </div>
  );
}

const inputStyle = {
  width: "100%", marginTop: 6, padding: "8px 10px",
  background: "#0D1016", color: "#E7E9EF",
  border: "1px solid #212736", borderRadius: 5,
  fontSize: 12.5, fontFamily: "inherit", outline: "none",
};
