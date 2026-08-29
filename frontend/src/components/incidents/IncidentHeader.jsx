/**
 * IncidentHeader — Slice 1 canonical Incident header.
 *
 * Shows: number · name · severity chip · priority chip · verdict
 * pill · assignee.  All values are derived from the /api/incidents/:id
 * projection — never fabricated.
 */
import React from "react";
import { ShieldAlert, User, Building2, Clock } from "lucide-react";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

const SEVERITY_TONE = {
  malicious:  { fg: "#fca5a5", bg: "rgba(239,68,68,0.14)",  ring: "rgba(239,68,68,0.55)" },
  suspicious: { fg: "#fcd34d", bg: "rgba(245,158,11,0.14)", ring: "rgba(245,158,11,0.55)" },
  benign:     { fg: "#86efac", bg: "rgba(34,197,94,0.14)",  ring: "rgba(34,197,94,0.55)" },
  unknown:    { fg: "rgba(148,163,184,0.9)", bg: "rgba(148,163,184,0.10)",
                  ring: "rgba(148,163,184,0.35)" },
};
const PRIORITY_TONE = {
  P1: { fg: "#fecaca", bg: "rgba(239,68,68,0.18)",  ring: "rgba(239,68,68,0.55)" },
  P2: { fg: "#fdba74", bg: "rgba(249,115,22,0.18)", ring: "rgba(249,115,22,0.55)" },
  P3: { fg: "#fcd34d", bg: "rgba(245,158,11,0.18)", ring: "rgba(245,158,11,0.55)" },
  P4: { fg: "#86efac", bg: "rgba(34,197,94,0.18)",  ring: "rgba(34,197,94,0.55)" },
  P5: { fg: "rgba(148,163,184,0.95)", bg: "rgba(148,163,184,0.12)",
          ring: "rgba(148,163,184,0.35)" },
};

function Pill({ tone, children, testId, big }) {
  return (
    <span
      data-testid={testId}
      style={{
        display: "inline-flex", alignItems: "center", gap: 6,
        padding: big ? "6px 12px" : "3px 10px",
        borderRadius: 6,
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        fontSize: big ? 12 : 10, letterSpacing: "0.12em",
        textTransform: "uppercase",
        color: tone.fg, background: tone.bg,
        border: `1px solid ${tone.ring}`,
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

function fmtDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toISOString().replace("T", " ").slice(0, 16) + "Z";
  } catch { return iso; }
}

export default function IncidentHeader({ incident }) {
  const sevTone = SEVERITY_TONE[incident?.severity] || SEVERITY_TONE.unknown;
  const prioTone = PRIORITY_TONE[incident?.priority?.code] || PRIORITY_TONE.P5;
  const stage2 = incident?.verdict_stage2 || null;

  return (
    <section
      data-testid={T.header}
      style={{
        padding: "20px 22px",
        border: "1px solid rgba(148,163,184,0.14)",
        borderRadius: 12,
        background: "linear-gradient(160deg, rgba(15,23,42,0.78), rgba(2,6,23,0.62))",
        boxShadow: "0 6px 22px rgba(2,6,23,0.4), inset 0 1px 0 rgba(255,255,255,0.03)",
      }}
    >
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "flex-start",
                      justifyContent: "space-between", gap: 20 }}>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{
            display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap",
          }}>
            <span
              data-testid={T.headerNumber}
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 12, letterSpacing: "0.18em",
                color: "rgba(148,163,184,0.85)",
              }}
            >
              {incident?.number || "INC-—"}
            </span>
            <Pill tone={prioTone} testId={T.headerPriority} big>
              {incident?.priority?.code} · {incident?.priority?.label}
            </Pill>
            <Pill tone={sevTone} testId={T.headerSeverity}>
              <ShieldAlert size={12} />
              {incident?.severity || "unknown"}
            </Pill>
          </div>
          <h1
            data-testid={T.headerName}
            style={{
              margin: "10px 0 0",
              fontFamily: "Chivo, ui-sans-serif, system-ui",
              fontSize: 28, fontWeight: 800, letterSpacing: "-0.01em",
              wordBreak: "break-word",
            }}
          >
            {incident?.name || "(unnamed incident)"}
          </h1>

          {/* Verdict pill — only rendered when Stage-2 has actually run. */}
          {stage2 && (
            <div
              data-testid={T.headerVerdict}
              style={{
                marginTop: 10,
                display: "inline-flex", gap: 10, alignItems: "center",
                padding: "6px 10px", borderRadius: 6,
                fontFamily: "JetBrains Mono, monospace", fontSize: 11,
                color: "rgba(226,232,240,0.9)",
                background: "rgba(2,6,23,0.6)",
                border: "1px solid rgba(148,163,184,0.18)",
              }}
            >
              <span style={{ opacity: 0.7 }}>STAGE-2 VERDICT</span>
              <span style={{ color: sevTone.fg, fontWeight: 700 }}>
                {stage2.label?.toUpperCase()}
              </span>
              <span style={{ opacity: 0.6 }}>·</span>
              <span>confidence {stage2.confidence_bucket}</span>
              <span style={{ opacity: 0.6 }}>·</span>
              <span>risk {stage2.risk_score}</span>
            </div>
          )}
        </div>

        <div style={{
          display: "flex", flexDirection: "column", gap: 6, minWidth: 240,
          fontFamily: "JetBrains Mono, monospace", fontSize: 11,
          color: "rgba(203,213,225,0.85)",
        }}>
          <Field icon={User} label="ASSIGNEE" testId={T.headerAssignee}>
            {incident?.assignee || "—"}
          </Field>
          <Field icon={Building2} label="TENANT">
            {incident?.tenant || "default"}
          </Field>
          <Field icon={Clock} label="UPDATED">
            {fmtDate(incident?.updated_at)}
          </Field>
        </div>
      </div>
    </section>
  );
}

function Field({ icon: Icon, label, children, testId }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <Icon size={12} style={{ color: "rgba(148,163,184,0.7)" }} />
      <span style={{ color: "rgba(148,163,184,0.7)",
                       letterSpacing: "0.12em", minWidth: 78 }}>
        {label}
      </span>
      <span data-testid={testId} style={{ color: "#e2e8f0" }}>{children}</span>
    </div>
  );
}
