/**
 * InvestigationThreatSummaryCard — Phase 4 · P1.
 *
 * Consolidated threat summary at the Investigation level. Aggregates
 * verdict / risk / MITRE / IOCs / artifact types across all member cases.
 */
import { ShieldAlert, Target, Globe, Fingerprint } from "lucide-react";

const VERDICT_TONE = {
  Malicious:  { fg: "#f87171", bg: "rgba(248,113,113,0.10)", bd: "rgba(248,113,113,0.35)" },
  Suspicious: { fg: "#fbbf24", bg: "rgba(251,191,36,0.10)", bd: "rgba(251,191,36,0.35)" },
  Partial:    { fg: "#fbbf24", bg: "rgba(251,191,36,0.10)", bd: "rgba(251,191,36,0.35)" },
  Benign:     { fg: "#86efac", bg: "rgba(34,197,94,0.10)",  bd: "rgba(34,197,94,0.35)" },
  Unknown:    { fg: "#94a3b8", bg: "rgba(148,163,184,0.10)", bd: "rgba(148,163,184,0.35)" },
};

export default function InvestigationThreatSummaryCard({ summary, onOpenEvidence }) {
  if (!summary) return null;
  const tone = VERDICT_TONE[summary.verdict] || VERDICT_TONE.Unknown;
  const iocsCount = totalIocs(summary.iocs);
  return (
    <div data-testid="investigation-threat-summary"
         style={{
           background: "linear-gradient(160deg, rgba(15,23,42,0.85), rgba(2,6,23,0.7))",
           border: "1px solid rgba(148,163,184,0.16)",
           borderRadius: 12, padding: 16,
         }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
        <div style={{ fontFamily: "JetBrains Mono, monospace",
                      fontSize: 10, letterSpacing: "0.14em",
                      textTransform: "uppercase", color: "#64748b" }}>
          Investigation Threat Summary · Aggregated
        </div>
        <div style={{ flex: 1 }} />
        <span data-testid="verdict-chip"
              style={{ padding: "4px 10px", borderRadius: 4,
                       fontSize: 11, fontWeight: 700,
                       fontFamily: "JetBrains Mono, monospace",
                       letterSpacing: "0.08em", textTransform: "uppercase",
                       background: tone.bg, color: tone.fg,
                       border: `1px solid ${tone.bd}` }}>
          {summary.verdict || "Unknown"}
        </span>
        {summary.risk_score > 0 && (
          <span data-testid="risk-chip"
                style={{ padding: "4px 10px", borderRadius: 4,
                         fontSize: 11, fontWeight: 700,
                         fontFamily: "JetBrains Mono, monospace",
                         letterSpacing: "0.08em",
                         background: "rgba(139,92,246,0.14)", color: "#c4b5fd",
                         border: "1px solid rgba(139,92,246,0.35)" }}>
            RISK {summary.risk_score}
          </span>
        )}
      </div>

      <div style={{ display: "grid", gap: 14,
                    gridTemplateColumns: "repeat(4, minmax(0, 1fr))" }}>
        <Stat icon={<Target size={14} />} label="Cases"
              value={summary.case_count} tone="cyan" />
        <Stat icon={<ShieldAlert size={14} />} label="MITRE"
              value={summary.mitre_count} tone="amber" />
        <Stat icon={<Globe size={14} />} label="IOCs"
              value={iocsCount} tone="cyan" />
        <Stat icon={<Fingerprint size={14} />} label="Artifacts"
              value={(summary.artifact_types || []).length}
              hint={(summary.artifact_types || []).join(", ").toUpperCase()}
              tone="violet" />
      </div>

      {(summary.mitre || []).length > 0 && (
        <div style={{ marginTop: 14 }}>
          <SectionLabel>MITRE Techniques</SectionLabel>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}
               data-testid="mitre-chips">
            {summary.mitre.slice(0, 12).map(m => (
              <button key={m.id}
                    data-testid={`mitre-chip-${m.id}`}
                    onClick={() => onOpenEvidence?.(m)}
                    disabled={!onOpenEvidence}
                    title={onOpenEvidence
                             ? `${m.technique || ""} — click for evidence drill-down`
                             : `${m.technique || ""} — used by ${(m.sources || []).length} case(s)`}
                    style={{ padding: "2px 8px", fontSize: 10,
                             background: "rgba(245,158,11,0.10)",
                             color: "#fcd34d",
                             border: "1px solid rgba(245,158,11,0.30)",
                             borderRadius: 3,
                             cursor: onOpenEvidence ? "pointer" : "default",
                             fontFamily: "JetBrains Mono, monospace" }}>
                {m.id}
              </button>
            ))}
            {summary.mitre.length > 12 && (
              <span style={{ padding: "2px 8px", fontSize: 10, color: "#64748b" }}>
                +{summary.mitre.length - 12} more
              </span>
            )}
          </div>
        </div>
      )}

      {iocsCount > 0 && (
        <div style={{ marginTop: 14, display: "grid",
                      gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                      gap: 12 }}>
          <IocList label="URLs"    items={summary.iocs?.urls} />
          <IocList label="Domains" items={summary.iocs?.domains} />
          <IocList label="IPs"     items={summary.iocs?.ips} />
          <IocList label="SHA-256" items={summary.iocs?.sha256} mono />
        </div>
      )}
    </div>
  );
}

function Stat({ icon, label, value, hint, tone }) {
  const map = {
    cyan:   { fg: "#67e8f9", ring: "rgba(6,182,212,0.30)" },
    amber:  { fg: "#fcd34d", ring: "rgba(245,158,11,0.30)" },
    violet: { fg: "#c4b5fd", ring: "rgba(139,92,246,0.30)" },
  };
  const c = map[tone] || map.cyan;
  return (
    <div style={{ padding: 12, borderRadius: 8,
                  background: "rgba(2,6,23,0.6)",
                  border: `1px solid ${c.ring}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, color: c.fg,
                    fontSize: 10, letterSpacing: "0.12em",
                    textTransform: "uppercase",
                    fontFamily: "JetBrains Mono, monospace" }}>
        {icon}{label}
      </div>
      <div style={{ marginTop: 6, fontSize: 22, fontWeight: 700,
                    color: "#e2e8f0",
                    fontFamily: "JetBrains Mono, monospace" }}>
        {value ?? 0}
      </div>
      {hint && (
        <div style={{ marginTop: 3, fontSize: 10, color: "#64748b",
                      fontFamily: "JetBrains Mono, monospace",
                      overflow: "hidden", textOverflow: "ellipsis",
                      whiteSpace: "nowrap" }}
             title={hint}>
          {hint}
        </div>
      )}
    </div>
  );
}

function IocList({ label, items, mono }) {
  if (!items || !items.length) return null;
  return (
    <div>
      <SectionLabel>{label} · {items.length}</SectionLabel>
      <div style={{ marginTop: 4, display: "flex", flexDirection: "column",
                    gap: 3, maxHeight: 140, overflowY: "auto" }}>
        {items.slice(0, 8).map(v => (
          <div key={v}
               style={{ fontSize: 11,
                        fontFamily: mono ? "JetBrains Mono, monospace" : "ui-sans-serif",
                        color: "#cbd5e1",
                        overflow: "hidden", textOverflow: "ellipsis",
                        whiteSpace: "nowrap" }}
               title={v}>
            {v}
          </div>
        ))}
        {items.length > 8 && (
          <div style={{ fontSize: 10, color: "#64748b", fontStyle: "italic" }}>
            +{items.length - 8} more…
          </div>
        )}
      </div>
    </div>
  );
}

function SectionLabel({ children }) {
  return (
    <div style={{ fontFamily: "JetBrains Mono, monospace",
                  fontSize: 10, letterSpacing: "0.12em",
                  textTransform: "uppercase", color: "#64748b" }}>
      {children}
    </div>
  );
}

function totalIocs(iocs) {
  if (!iocs) return 0;
  return Object.values(iocs).reduce((a, v) =>
    a + (Array.isArray(v) ? v.length : 0), 0);
}
