// DT-I1C Activity Details sections (namespaced). Renders the dt-i1.view.v1 view model truthfully.
import { SECTION_TITLES } from "./activityView.mjs";

const STATE_STYLE = {
  AVAILABLE: { bg: "#E0F2FE", fg: "#075985" },
  EMPTY: { bg: "#F1F5F9", fg: "#475569" },
  UNKNOWN: { bg: "#FEF3C7", fg: "#92400E" },
  UNAVAILABLE: { bg: "#FEF3C7", fg: "#92400E" },
  NOT_WIRED: { bg: "#F1F5F9", fg: "#64748B" },
};

function Item({ item }) {
  return (
    <div className="text-[10px] font-mono break-all py-0.5" style={{ color: "#0F172A" }}>
      {Object.entries(item).filter(([, v]) => v !== null && v !== undefined && v !== "")
        .map(([k, v]) => (
          <span key={k} className="mr-2">
            <span style={{ color: "#64748B" }}>{k}:</span> {Array.isArray(v) ? v.join(", ") : String(v)}
          </span>
        ))}
    </div>
  );
}

function SectionBlock({ s }) {
  const st = STATE_STYLE[s.state] || STATE_STYLE.UNKNOWN;
  return (
    <div className="mt-3" data-testid={`ad-section-${s.key}`}>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-[9px] tracking-[1.5px] font-bold uppercase" style={{ color: "#64748B" }}>
          {SECTION_TITLES[s.key] || s.key}
        </span>
        <span className="text-[8px] px-1 rounded font-bold" data-testid={`ad-state-${s.key}`}
              style={{ background: st.bg, color: st.fg }}>{s.state}</span>
      </div>
      {s.key === "mitre" ? (
        <div className="flex flex-wrap gap-1">
          {s.items.map((m) => (
            <span key={m.technique} data-testid={`ad-mitre-${m.technique}`}
                  title={m.attribution}
                  className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold"
                  style={m.style === "threat" ? { background: "#FEE2E2", color: "#B91C1C" }
                                              : { background: "#F1F5F9", color: "#334155" }}>
              {m.technique}
            </span>
          ))}
        </div>
      ) : s.items.map((it, i) => <Item key={i} item={it} />)}
      {s.statements.map((t) => (
        <div key={t} className="text-[10px] italic" style={{ color: "#475569" }}>{t}</div>
      ))}
    </div>
  );
}

export function ActivityDetailsSections({ view }) {
  if (!view) return null;
  return (
    <div className="mt-4 pt-3 border-t" style={{ borderColor: "#E2E8F0" }} data-testid="activity-details-sections">
      <div className="flex items-center gap-2">
        <span className="text-[9px] tracking-[1.5px] font-bold" style={{ color: "#64748B" }}>MACHINE ASSESSMENT</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded font-bold" data-testid="ad-machine-assessment"
              style={{ background: "#F1F5F9", color: "#334155" }}>{view.machine_assessment}</span>
        <span className="text-[9px] tracking-[1.5px] font-bold ml-2" style={{ color: "#64748B" }}>ANALYST</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded font-bold" data-testid="ad-analyst-disposition"
              style={{ background: "#F1F5F9", color: "#334155" }}>
          {view.analyst_disposition?.value || "NOT SET"}
        </span>
      </div>
      {view.sections.filter((s) => s.key !== "observation").map((s) => <SectionBlock key={s.key} s={s} />)}
    </div>
  );
}
