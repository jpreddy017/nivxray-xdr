/**
 * Investigation · Overview tab — verdict + MITRE + IOCs + fingerprint.
 * Presentation only; consumes the existing summary + fingerprint payloads.
 */
import InvestigationThreatSummaryCard from
  "@/components/investigation/InvestigationThreatSummaryCard";

const VERDICT_TONE = {
  clean:      { fg: "#86efac", bg: "rgba(134,239,172,0.08)", bd: "rgba(134,239,172,0.35)" },
  suspicious: { fg: "#fbbf24", bg: "rgba(251,191,36,0.10)",  bd: "rgba(251,191,36,0.35)" },
  malicious:  { fg: "#f87171", bg: "rgba(248,113,113,0.10)", bd: "rgba(248,113,113,0.35)" },
};

export default function OverviewTab({ inv, summary, fp, onOpenEvidence }) {
  const v = (summary?.verdict || "").toLowerCase();
  const tone = VERDICT_TONE[v] || VERDICT_TONE.suspicious;
  return (
    <div data-testid="tab-panel-overview" style={{ display: "grid", gap: 16 }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr",
                    gap: 12 }}>
        <MetricCard
          testid="metric-verdict" label="Verdict"
          value={(summary?.verdict || "—").toUpperCase()}
          tone={tone} big />
        <MetricCard
          testid="metric-risk" label="Risk score"
          value={summary?.risk_score ?? "—"} />
        <MetricCard
          testid="metric-fingerprint" label="Attack fingerprint"
          value={fp?.hash ? `${fp.hash.slice(0, 12)}…` : "—"}
          mono />
      </div>

      {summary && (
        <InvestigationThreatSummaryCard
          summary={summary}
          onOpenEvidence={onOpenEvidence} />
      )}

      {inv?.description && (
        <section style={sec}>
          <SectionTitle>Investigation notes</SectionTitle>
          <div style={{ marginTop: 6, color: "#cbd5e1", fontSize: 13 }}>
            {inv.description}
          </div>
        </section>
      )}
    </div>
  );
}

function MetricCard({ testid, label, value, tone, big, mono }) {
  return (
    <div data-testid={testid}
         style={{
           background: tone?.bg || "rgba(2,6,23,0.55)",
           border: `1px solid ${tone?.bd || "#1f2b3f"}`,
           borderRadius: 10, padding: "14px 18px" }}>
      <div style={{ fontSize: 10, letterSpacing: "0.16em",
                    textTransform: "uppercase", color: "#94a3b8" }}>
        {label}
      </div>
      <div style={{ marginTop: 6, fontSize: big ? 22 : 18, fontWeight: 700,
                    color: tone?.fg || "#e2e8f0",
                    fontFamily: mono ? "ui-monospace, monospace" : undefined }}>
        {value}
      </div>
    </div>
  );
}

const sec = { background: "rgba(2,6,23,0.55)", border: "1px solid #1f2b3f",
              borderRadius: 10, padding: "14px 18px" };

function SectionTitle({ children }) {
  return (
    <div style={{ fontSize: 11, letterSpacing: "0.16em",
                  textTransform: "uppercase", color: "#94a3b8" }}>
      {children}
    </div>
  );
}
