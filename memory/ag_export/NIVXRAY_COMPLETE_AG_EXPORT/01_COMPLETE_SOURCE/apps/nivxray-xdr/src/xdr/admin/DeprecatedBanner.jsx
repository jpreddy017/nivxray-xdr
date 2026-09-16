/**
 * Standard deprecation banner rendered above legacy admin bodies
 * that have been superseded by an authoritative surface (P1 Detection
 * Surface Consolidation).  The banner is deliberately loud — analysts
 * must NEVER treat a legacy surface as source-of-truth.
 */
import React from "react";
import { AlertTriangle, ArrowRight } from "lucide-react";
import { useNavigate } from "react-router-dom";


export default function DeprecatedBanner({ authoritativeKey, authoritativeLabel,
                                                                          rationale }) {
  const nav = useNavigate();
  return (
    <div data-testid="deprecated-banner"
              style={{ display: "flex", alignItems: "center", gap: 10,
                              padding: "10px 12px", marginBottom: 14,
                              border: "1px solid var(--amber)",
                              background: "rgba(245,158,11,.08)",
                              borderRadius: 3, fontFamily: "var(--mono)",
                              fontSize: 11.5 }}>
      <AlertTriangle size={16} style={{ color: "var(--amber)",
                                                              flexShrink: 0 }} />
      <div style={{ flex: 1 }}>
        <div style={{ color: "var(--amber)", fontWeight: 700,
                              letterSpacing: ".3px" }}>
          DEPRECATED · legacy surface
        </div>
        <div style={{ color: "var(--text-dim)", marginTop: 2, lineHeight: 1.5 }}>
          {rationale}
        </div>
      </div>
      <button className="btn"
                   data-testid="deprecated-goto-authoritative"
                   onClick={() => nav(`/xdr/admin/${authoritativeKey}`)}
                   style={{ padding: "4px 10px", fontSize: 11,
                                   whiteSpace: "nowrap" }}>
        Go to {authoritativeLabel} <ArrowRight size={11} />
      </button>
    </div>
  );
}
