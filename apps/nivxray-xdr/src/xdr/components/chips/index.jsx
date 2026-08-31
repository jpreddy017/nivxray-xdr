/**
 * NivXRay · Layer 2 · Reusable chip primitives
 *
 * Six chip families for the Analyst Operations experience.  Reused
 * by the Incident Queue (Layer 2) and Incident Record (Layer 3).
 *
 * Design decisions (Defender + SIR-inspired · NivXRay identity):
 *   · Filled pills for Priority + Verdict (strong signal, first read)
 *   · Filled uppercase badges for Severity (compact, Defender-style)
 *   · Outlined pills for State (lifecycle-neutral)
 *   · Dashed outlined pills for Side-state (semantic "waiting")
 *   · Small outlined tags for Domain (never fabricated · only when data present)
 *
 * All chips use monospace numerics and 700-weight labels for scannability.
 */
import React from "react";

const P_TONE = {
  P1: { fg: "#ffffff", bg: "#dc2626", label: "P1" },
  P2: { fg: "#ffffff", bg: "#ea580c", label: "P2" },
  P3: { fg: "#1f2937", bg: "#facc15", label: "P3" },
  P4: { fg: "#ffffff", bg: "#16a34a", label: "P4" },
  P5: { fg: "#ffffff", bg: "#6b7280", label: "P5" },
};

const S_TONE = {
  critical: { fg: "#7f1d1d", bg: "#fecaca", bd: "#dc2626", label: "CRITICAL" },
  high:     { fg: "#7c2d12", bg: "#fed7aa", bd: "#ea580c", label: "HIGH"     },
  medium:   { fg: "#713f12", bg: "#fef3c7", bd: "#eab308", label: "MEDIUM"   },
  low:      { fg: "#14532d", bg: "#bbf7d0", bd: "#22c55e", label: "LOW"      },
  info:     { fg: "#1e3a8a", bg: "#dbeafe", bd: "#3b82f6", label: "INFO"     },
  unknown:  { fg: "#374151", bg: "#e5e7eb", bd: "#9ca3af", label: "UNKNOWN"  },
};

const V_TONE = {
  malicious:  { fg: "#ffffff", bg: "#b91c1c", label: "MALICIOUS"  },
  suspicious: { fg: "#7c2d12", bg: "#fdba74", label: "SUSPICIOUS" },
  benign:     { fg: "#14532d", bg: "#86efac", label: "BENIGN"     },
  unknown:    { fg: "#374151", bg: "#d1d5db", label: "UNKNOWN"    },
};

const ST_TONE = {
  new:            "#2563eb",
  triaged:        "#0891b2",
  investigating:  "#eab308",
  containment:    "#f97316",
  eradication:    "#dc2626",
  recovery:       "#16a34a",
  resolved:       "#059669",
  closed:         "#6b7280",
  in_progress:    "#eab308",   // legacy
  on_hold:        "#e11d48",   // legacy
};

const SIDE_STATE_TONE = {
  waiting_customer: "#a855f7",
  waiting_evidence: "#2563eb",
  waiting_vendor:   "#f59e0b",
};

const DOMAIN_TONE = {
  EDR:      "#dc2626", NDR:      "#3b82f6", ITDR:     "#a855f7",
  EMAIL:    "#f59e0b", IDENTITY: "#8b5cf6", CLOUD:    "#0891b2",
  NETWORK:  "#059669", ENDPOINT: "#e11d48", CTEM:     "#f97316",
};

// ── Priority (filled pill) ─────────────────────────────────────────
export function PriorityChip({ code }) {
  const t = P_TONE[code];
  if (!t) return <span style={dashStyle}>—</span>;
  return (
    <span style={{ ...pillBase, color: t.fg, background: t.bg, minWidth: 30 }}
             data-testid={`chip-priority-${code}`}>
      {t.label}
    </span>
  );
}

// ── Severity (filled badge · uppercase) ────────────────────────────
export function SeverityChip({ value }) {
  const k = String(value || "unknown").toLowerCase();
  const t = S_TONE[k] || S_TONE.unknown;
  return (
    <span style={{ ...badgeBase, color: t.fg, background: t.bg,
                     border: `1px solid ${t.bd}` }}
             data-testid={`chip-severity-${k}`}>
      {t.label}
    </span>
  );
}

// ── Verdict (filled pill) ──────────────────────────────────────────
export function VerdictChip({ value }) {
  const k = String(value || "unknown").toLowerCase();
  const t = V_TONE[k] || V_TONE.unknown;
  return (
    <span style={{ ...pillBase, color: t.fg, background: t.bg }}
             data-testid={`chip-verdict-${k}`}>
      {t.label}
    </span>
  );
}

// ── State (outlined pill) ──────────────────────────────────────────
export function StateChip({ value }) {
  const k = String(value || "new").toLowerCase();
  const c = ST_TONE[k] || "#6b7280";
  return (
    <span style={{ ...outlinedPill, color: c, borderColor: c }}
             data-testid={`chip-state-${k}`}>
      {k.replace(/_/g, " ").toUpperCase()}
    </span>
  );
}

// ── Side-state (dashed outlined pill) ──────────────────────────────
export function SideStateChip({ value }) {
  if (!value) return null;
  const k = String(value).toLowerCase();
  const c = SIDE_STATE_TONE[k] || "#a855f7";
  return (
    <span style={{ ...outlinedPill, color: c, borderColor: c,
                     borderStyle: "dashed" }}
             data-testid={`chip-side-state-${k}`}>
      {k.replace(/_/g, " ").toUpperCase()}
    </span>
  );
}

// ── Domain tag (small outlined) ────────────────────────────────────
export function DomainTag({ value }) {
  if (!value) return null;
  const k = String(value).toUpperCase();
  const c = DOMAIN_TONE[k] || "#6b7280";
  return (
    <span style={{ ...tagBase, color: c, borderColor: c }}
             data-testid={`chip-domain-${k}`}>
      {k}
    </span>
  );
}


const pillBase = {
  display: "inline-flex", alignItems: "center", justifyContent: "center",
  padding: "2px 8px", borderRadius: 999,
  fontFamily: "var(--mono, ui-monospace, monospace)",
  fontSize: 10.5, fontWeight: 800, letterSpacing: 0.5,
  lineHeight: 1.4, whiteSpace: "nowrap",
};

const badgeBase = {
  display: "inline-flex", alignItems: "center", justifyContent: "center",
  padding: "1px 7px", borderRadius: 3,
  fontFamily: "var(--mono, ui-monospace, monospace)",
  fontSize: 10, fontWeight: 800, letterSpacing: 0.5,
  lineHeight: 1.4, whiteSpace: "nowrap",
};

const outlinedPill = {
  display: "inline-flex", alignItems: "center", justifyContent: "center",
  padding: "1px 8px", borderRadius: 999,
  border: "1px solid",
  fontFamily: "var(--mono, ui-monospace, monospace)",
  fontSize: 10, fontWeight: 700, letterSpacing: 0.6,
  lineHeight: 1.4, background: "transparent", whiteSpace: "nowrap",
};

const tagBase = {
  display: "inline-flex", alignItems: "center", justifyContent: "center",
  padding: "0px 6px", borderRadius: 2,
  border: "1px solid",
  fontFamily: "var(--mono, ui-monospace, monospace)",
  fontSize: 9, fontWeight: 700, letterSpacing: 0.6,
  lineHeight: 1.4, background: "transparent",
  whiteSpace: "nowrap", marginRight: 3,
};

const dashStyle = { color: "#9ca3af",
                       fontFamily: "var(--mono, ui-monospace, monospace)",
                       fontSize: 11 };
