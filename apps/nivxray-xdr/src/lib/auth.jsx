/**
 * NivXRay XDR standalone auth context.
 *
 * Reuses the existing `POST /api/auth/login` endpoint.  Token is
 * kept in `localStorage["nvx_token"]` — the SAME key the base
 * NivXRay app uses — so a user signed into either app is signed
 * into both on the same origin without any handshake between the
 * bundles.  We never re-implement login server-side.
 */
import React, { createContext, useContext, useEffect, useState } from "react";
import api from "@/lib/api";
import { sessionChanged, securitySnapshot, subscribeSecurity } from "./securityState";
import { resetServerTenant } from "./tenant";

const AuthCtx = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let generation = 0;
    const load = async () => {
      const ticket = ++generation;
      setUser(null);
      if (!localStorage.getItem("nvx_token")) { setLoading(false); return; }
      setLoading(true);
      try {
        const response = await api.get("/auth/me");
        if (ticket === generation) setUser(response.data);
      } catch {
        if (ticket === generation) setUser(null);
      } finally { if (ticket === generation) setLoading(false); }
    };
    load();
    const unsubscribe = subscribeSecurity(() => {
      const reason = securitySnapshot().reason;
      if (reason === "session" || reason === "expired") load();
    });
    return () => { ++generation; unsubscribe(); };
  }, []);

  const login = async (email, password) => {
    const r = await api.post("/auth/login", { email, password });
    localStorage.setItem("nvx_token", r.data.access_token);
    localStorage.setItem("nvx_email", r.data.email);
    resetServerTenant();
    sessionChanged();
  };

  const logout = () => {
    localStorage.removeItem("nvx_token");
    localStorage.removeItem("nvx_email");
    resetServerTenant();
    sessionChanged();
    setUser(null);
    window.location.href = "/login";
  };

  return (
    <AuthCtx.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthCtx.Provider>
  );
}

export const useAuth = () => useContext(AuthCtx);
