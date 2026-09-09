// `React` must be imported explicitly: this app builds with the CLASSIC
// JSX runtime (vite.config.js · jsxRuntime: "classic"), so JSX compiles
// to React.createElement and needs React in scope. Omitting it builds
// cleanly and then crashes the whole app at runtime with
// "React is not defined".
import React, { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { PRODUCT_SCOPE, isForeignPath, productOfPath } from "@/productScope";

/**
 * Blocks the other product from ever rendering on this deployment.
 *
 * How it recovers, and why it needs no origin variable: the correct
 * destination for a foreign path is ALREADY encoded in the proven
 * host-conditional redirects in `vercel.json`. Those are server rules,
 * so all this guard has to do is force one full page load of the SAME
 * url — the edge then redirects to the right hostname. That keeps the
 * redirect table as the single source of truth for cross-host targets
 * and avoids setting REACT_APP_XDR_URL / _EDR_URL, which must stay
 * unset until each product is runtime-verified.
 *
 * Loop-safe: the reload is attempted at most once per path. If the edge
 * has no rule for this host (a preview host where a scope was set by
 * mistake), the second pass renders an explicit notice instead of
 * reloading forever — and never renders the wrong product.
 */
const LABEL = { xdr: "NivXRay XDR", edr: "NivXRay EDR" };

function WrongProductHost({ pathname }) {
  const wanted = productOfPath(pathname);
  return (
    <div
      data-testid="wrong-product-host"
      style={{
        minHeight: "70vh", display: "flex", alignItems: "center",
        justifyContent: "center", padding: "48px 24px",
        fontFamily: "'IBM Plex Mono', monospace", color: "#e2e8f0",
      }}
    >
      <div style={{ maxWidth: 560, borderLeft: "2px solid #f59e0b", paddingLeft: 20 }}>
        <div
          data-testid="wrong-product-host-title"
          style={{
            fontSize: 11, letterSpacing: "0.18em", color: "#f59e0b",
            textTransform: "uppercase", marginBottom: 14,
          }}
        >
          wrong product host
        </div>
        <p style={{ fontSize: 14, lineHeight: 1.65, margin: "0 0 14px" }}>
          This deployment serves <strong>{LABEL[PRODUCT_SCOPE]}</strong>.
          {" "}
          <code style={{ color: "#93c5fd" }}>{pathname}</code> belongs to
          {" "}
          <strong>{LABEL[wanted] || "another product"}</strong>, which runs on
          its own hostname.
        </p>
        <p style={{ fontSize: 12, lineHeight: 1.7, margin: 0, color: "#94a3b8" }}>
          Nothing was loaded from the other product. Open
          {" "}<strong>{LABEL[wanted] || "it"}</strong>{" "}
          from its own address.
        </p>
      </div>
    </div>
  );
}

export default function ProductScopeGuard({ children }) {
  const { pathname } = useLocation();
  const foreign = isForeignPath(pathname);

  useEffect(() => {
    if (!foreign) return;
    const key = `nvx_scope_bounce:${pathname}`;
    try {
      if (sessionStorage.getItem(key)) return;   // already tried — show notice
      sessionStorage.setItem(key, "1");
    } catch {
      return;                                    // no storage → do not risk a loop
    }
    window.location.replace(window.location.href);
  }, [foreign, pathname]);

  if (foreign) return <WrongProductHost pathname={pathname} />;
  return children;
}
