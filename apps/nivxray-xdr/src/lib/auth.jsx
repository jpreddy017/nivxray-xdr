/**
 * NivXRay XDR standalone auth context.
 *
 * Reuses the existing `POST /api/auth/login` endpoint.  Token is
 * kept in `localStorage["nvx_token"]` — the SAME key the base
 * NivXRay app uses — so a user signed into either app is signed
 * into both on the same origin without any handshake between the
 * bundles.  We never re-implement login server-side.
 */
import { createContext, useContext, useEffect, useState } from "react";
import api from "@/lib/api";

const AuthCtx = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("nvx_token");
    const email = localStorage.getItem("nvx_email");
    if (!token) { setLoading(false); return; }
    api.get("/auth/me")
      .then((r) => setUser(r.data))
      .catch(() => {
        localStorage.removeItem("nvx_token");
        localStorage.removeItem("nvx_email");
      })
      .finally(() => setLoading(false));
    if (email && !user) setUser({ email });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = async (email, password) => {
    const r = await api.post("/auth/login", { email, password });
    localStorage.setItem("nvx_token", r.data.access_token);
    localStorage.setItem("nvx_email", r.data.email);
    const me = await api.get("/auth/me");
    setUser(me.data);
  };

  const logout = () => {
    localStorage.removeItem("nvx_token");
    localStorage.removeItem("nvx_email");
    setUser(null);
    window.location.href = "/xdr/login";
  };

  return (
    <AuthCtx.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthCtx.Provider>
  );
}

export const useAuth = () => useContext(AuthCtx);
