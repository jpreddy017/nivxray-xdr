/**
 * Investigation Summary — deterministic analyst brief.
 *
 * Renders the output of ``POST /api/investigation/summary``:
 *   1. Classification + Confidence + Overall Assessment
 *   2. Observed Behaviors (evidence-backed)
 *   3. Inferred Objectives (behavior → likely attacker goal)
 *   4. Kill Chain lanes (behavior-driven, NOT command-driven)
 *   5. MITRE ATT&CK Techniques
 *   6. Attack Story (per kill-chain phase)
 *   7. Recommendations (deterministic hunt / detection list)
 *   8. Investigation Conclusion
 *
 * Opened via the "OPEN INVESTIGATION SUMMARY" button in the workspace
 * Investigation Results panel.  Reads the input from URL param or
 * sessionStorage.
 */
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "@/lib/api";

const TONE = {
  "Reconnaissance":       { fg: "#67e8f9", bg: "rgba(103,232,249,0.10)", bd: "rgba(103,232,249,0.35)" },
  "Delivery":             { fg: "#c084fc", bg: "rgba(192,132,252,0.10)", bd: "rgba(192,132,252,0.35)" },
  "Execution":            { fg: "#fbbf24", bg: "rgba(251,191,36,0.10)",  bd: "rgba(251,191,36,0.35)"  },
  "Defense Evasion":      { fg: "#fb923c", bg: "rgba(251,146,60,0.10)",  bd: "rgba(251,146,60,0.35)"  },
  "Credential Access":    { fg: "#f472b6", bg: "rgba(244,114,182,0.10)", bd: "rgba(244,114,182,0.35)" },
  "Discovery":            { fg: "#7ee3c9", bg: "rgba(126,227,201,0.10)", bd: "rgba(126,227,201,0.35)" },
  "Lateral Movement":     { fg: "#a78bfa", bg: "rgba(167,139,250,0.10)", bd: "rgba(167,139,250,0.35)" },
  "Command and Control":  { fg: "#f87171", bg: "rgba(248,113,113,0.10)", bd: "rgba(248,113,113,0.35)" },
  "Actions on Objectives":{ fg: "#f43f5e", bg: "rgba(244,63,94,0.10)",   bd: "rgba(244,63,94,0.35)"   },
  "Impact":               { fg: "#dc2626", bg: "rgba(220,38,38,0.10)",   bd: "rgba(220,38,38,0.35)"   },
};
const _tone = (p) => TONE[p] || { fg: "#94a3b8", bg: "rgba(148,163,184,0.10)", bd: "rgba(148,163,184,0.35)" };

export default function InvestigationSummaryPage() {
  const navigate = useNavigate();
  const [text, setText]       = useState("");
  const [data, setData]       = useState(null);
  const [err, setErr]         = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Prefer localStorage (survives across tabs — the workspace opens
    // this page in a new tab so sessionStorage would be empty).
    // Fallback to sessionStorage for same-tab navigation.
    const seed = (typeof window !== "undefined" &&
      (localStorage.getItem("nivx.investigation.text") ||
       sessionStorage.getItem("nivx.investigation.text"))) || "";
    setText(seed);
    if (!seed) {
      setErr("No input available. Open this page from the Workspace via the OPEN INVESTIGATION SUMMARY button.");
      setLoading(false);
      return;
    }
    api.post("/investigation/summary", { text: seed })
       .then((r) => setData(r.data))
       .catch((e) => setErr(String(e?.response?.data?.detail || e?.message || e)))
       .finally(() => setLoading(false));
  }, []);

  if (loading) return <Page><Loading /></Page>;
  if (err)     return <Page><Err msg={err} onBack={() => navigate("/")} /></Page>;
  if (!data)   return <Page><Err msg="No summary produced." onBack={() => navigate("/")} /></Page>;

  const cls   = data.classification || {};
  const conf  = data.confidence     || {};
  const lanes = data.kill_chain_lanes || {};
  const mitre = data.mitre_techniques || [];
  const obs   = data.observed_behaviors || [];

  return (
    <Page>
      <TopBar onBack={() => navigate("/")} />

      {/* 1 · Classification card */}
      <div style={sx.header} data-testid="summary-classification-card">
        <div style={sx.klabel}>CLASSIFICATION</div>
        <div style={{ ...sx.klabelValue, color: _tone(cls.tier === "High" ? "Impact" : "Execution").fg }}>
          {cls.label || "Unknown"}
        </div>
        <div style={{ display: "flex", gap: 24, marginTop: 12 }}>
          <div>
            <div style={sx.klabel}>CONFIDENCE</div>
            <div style={{ ...sx.klabelValue, fontSize: 20 }}>{conf.tier} <span style={{ color: "#64748b" }}>({conf.score}%)</span></div>
          </div>
          <div>
            <div style={sx.klabel}>BEHAVIORS</div>
            <div style={sx.klabelValue}>{obs.length}</div>
          </div>
          <div>
            <div style={sx.klabel}>KILL-CHAIN LANES</div>
            <div style={sx.klabelValue}>{Object.keys(lanes).length}</div>
          </div>
          <div>
            <div style={sx.klabel}>MITRE TECHNIQUES</div>
            <div style={sx.klabelValue}>{mitre.length}</div>
          </div>
        </div>
      </div>

      {/* 2 · Overall Assessment */}
      <Card title="OVERALL ASSESSMENT" testid="summary-assessment">
        <p style={sx.paragraph}>{data.overall_assessment}</p>
      </Card>

      {/* 3 · Observed Behaviors */}
      <Card title={`OBSERVED BEHAVIORS · ${obs.length}`} testid="summary-observed">
        {obs.map((b) => {
          const t = _tone(b.kill_chain?.[0]);
          return (
          <div key={b.id} data-testid={`observed-${b.id}`}
               style={{ padding: 10, borderLeft: `3px solid ${t.fg}`, background: t.bg, marginBottom: 8, borderRadius: 4 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
              <div style={{ color: t.fg, fontWeight: 600, fontSize: 14 }}>{b.title}</div>
              <div style={sx.chipsRight}>
                {b.kill_chain?.map((p) => <span key={p} style={{ ...sx.chip, background: t.bg, color: t.fg, borderColor: t.bd }}>{p}</span>)}
                {b.mitre_techniques?.map((m) => <span key={m} style={sx.mitreChip}>{m}</span>)}
                <span style={sx.confChip}>conf {Math.round(b.confidence * 100)}%</span>
              </div>
            </div>
            <div style={sx.desc}>{b.description}</div>
            {b.evidence?.length > 0 && (
              <ul style={sx.evList}>
                {b.evidence.slice(0, 5).map((e, i) => (
                  <li key={i} style={sx.evItem}>
                    <span style={{ color: "#94a3b8", marginRight: 6 }}>{e.location || "—"}</span>
                    <code style={sx.code}>{e.text}</code>
                  </li>
                ))}
              </ul>
            )}
          </div>
          );
        })}
      </Card>

      {/* 4 · Inferred Objectives */}
      <Card title="INFERRED OBJECTIVES" testid="summary-inferred">
        <ul style={sx.bullets}>
          {(data.inferred_objectives || []).map((o, i) => <li key={i} style={sx.bullet}>{o}</li>)}
        </ul>
      </Card>

      {/* 5 · Kill Chain Lanes (behavior-driven, one card per lane) */}
      <Card title="KILL CHAIN · BEHAVIOR-DRIVEN LANES" testid="summary-lanes">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 10 }}>
          {Object.entries(lanes).map(([phase, bs]) => {
            const t = _tone(phase);
            return (
              <div key={phase} data-testid={`lane-${phase}`}
                   style={{ padding: 10, border: `1px solid ${t.bd}`, background: t.bg, borderRadius: 6 }}>
                <div style={{ color: t.fg, fontWeight: 700, letterSpacing: "0.12em", fontSize: 11, marginBottom: 6 }}>{phase.toUpperCase()}</div>
                {bs.map((b) => (
                  <div key={b.id} style={sx.laneItem}>
                    <div style={{ color: "#e2e8f0", fontSize: 13 }}>{b.title}</div>
                    <div style={{ display: "flex", gap: 4, marginTop: 3, flexWrap: "wrap" }}>
                      {b.mitre?.map((m) => <span key={m} style={sx.mitreChipSm}>{m}</span>)}
                      <span style={sx.confChipSm}>{Math.round(b.confidence * 100)}%</span>
                    </div>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </Card>

      {/* 6 · MITRE ATT&CK */}
      <Card title={`MITRE ATT&CK TECHNIQUES · ${mitre.length}`} testid="summary-mitre">
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {mitre.map((m) => (
            <a key={m.id} href={`https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/`}
               target="_blank" rel="noreferrer" style={sx.mitreLink}>
              {m.id} <span style={{ color: "#64748b" }}>· {m.evidence_count} evidence</span>
            </a>
          ))}
        </div>
      </Card>

      {/* 7 · Attack Story */}
      <Card title="ATTACK STORY" testid="summary-story">
        <ol style={sx.story}>
          {(data.attack_story || []).map((s, i) => (
            <li key={i} style={sx.storyItem} dangerouslySetInnerHTML={{ __html:
              s.replace(/\*\*(.+?)\*\*/g, '<strong style="color:#7ee3c9">$1</strong>') }} />
          ))}
        </ol>
      </Card>

      {/* 8 · Recommendations */}
      <Card title={`RECOMMENDATIONS · ${(data.recommendations || []).length}`} testid="summary-recommendations">
        <ol style={sx.bullets}>
          {(data.recommendations || []).map((r, i) => (
            <li key={i} style={sx.bullet}
                dangerouslySetInnerHTML={{ __html: r.replace(/`([^`]+)`/g,
                  '<code style="background:rgba(103,232,249,0.10); padding:1px 5px; border-radius:3px; color:#67e8f9">$1</code>') }} />
          ))}
        </ol>
      </Card>

      {/* 9 · Conclusion */}
      <Card title="INVESTIGATION CONCLUSION" testid="summary-conclusion">
        <p style={{ ...sx.paragraph, color: "#e2e8f0", fontSize: 15 }}>{data.conclusion}</p>
      </Card>
    </Page>
  );
}

const Page   = ({ children }) => <div style={sx.page}>{children}</div>;
const Loading = () => <div style={{ padding: 40, color: "#94a3b8" }}>Composing investigation summary…</div>;
const Err     = ({ msg, onBack }) => <div style={{ padding: 40 }}><div style={{ color: "#f87171", marginBottom: 12 }}>{msg}</div><button className="nvx-btn" onClick={onBack}>← BACK TO WORKSPACE</button></div>;
const TopBar  = ({ onBack }) => (
  <div style={sx.topbar}>
    <button className="nvx-btn ghost" onClick={onBack} data-testid="btn-back-workspace">← BACK TO WORKSPACE</button>
    <span style={{ color: "#94a3b8", letterSpacing: "0.16em", fontSize: 11 }}>DETERMINISTIC · NO LLM · POWERED BY BEHAVIOR GRAPH</span>
  </div>
);
const Card = ({ title, children, testid }) => (
  <div data-testid={testid} style={sx.card}>
    <div style={sx.cardHeader}>{title}</div>
    <div style={sx.cardBody}>{children}</div>
  </div>
);

const sx = {
  page:       { padding: "24px 32px", maxWidth: 1200, margin: "0 auto", color: "#cbd5e1" },
  topbar:     { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 },
  header:     { padding: 20, borderRadius: 8, background: "linear-gradient(135deg, rgba(126,227,201,0.10), rgba(103,232,249,0.06))",
                border: "1px solid rgba(126,227,201,0.35)", marginBottom: 16 },
  klabel:     { color: "#64748b", fontSize: 10, letterSpacing: "0.18em", marginBottom: 4 },
  klabelValue:{ color: "#e2e8f0", fontSize: 24, fontWeight: 700 },
  card:       { marginTop: 14, border: "1px solid #1f2b3f", borderRadius: 6, overflow: "hidden" },
  cardHeader: { padding: "10px 14px", background: "rgba(2,6,23,0.6)", color: "#7ee3c9",
                letterSpacing: "0.20em", fontSize: 11, borderBottom: "1px solid #1f2b3f" },
  cardBody:   { padding: 14, background: "rgba(2,6,23,0.35)" },
  paragraph:  { margin: 0, fontSize: 14, lineHeight: 1.6, color: "#cbd5e1" },
  bullets:    { margin: 0, paddingLeft: 20 },
  bullet:     { marginBottom: 6, fontSize: 13, lineHeight: 1.5, color: "#cbd5e1" },
  chipsRight: { display: "flex", gap: 4, flexWrap: "wrap", alignItems: "center" },
  chip:       { fontSize: 10, padding: "2px 6px", borderRadius: 3, border: "1px solid", letterSpacing: "0.10em" },
  mitreChip:  { fontSize: 10, padding: "2px 6px", background: "rgba(103,232,249,0.10)", color: "#67e8f9", border: "1px solid rgba(103,232,249,0.35)", borderRadius: 3, fontFamily: "JetBrains Mono, monospace" },
  mitreChipSm:{ fontSize: 9,  padding: "1px 5px", background: "rgba(103,232,249,0.10)", color: "#67e8f9", border: "1px solid rgba(103,232,249,0.35)", borderRadius: 3, fontFamily: "JetBrains Mono, monospace" },
  confChip:   { fontSize: 10, padding: "2px 6px", background: "rgba(126,227,201,0.10)", color: "#7ee3c9", border: "1px solid rgba(126,227,201,0.35)", borderRadius: 3 },
  confChipSm: { fontSize: 9,  padding: "1px 5px", background: "rgba(126,227,201,0.10)", color: "#7ee3c9", border: "1px solid rgba(126,227,201,0.35)", borderRadius: 3 },
  desc:       { fontSize: 12, color: "#94a3b8", marginTop: 4 },
  evList:     { margin: "6px 0 0", padding: 0, listStyle: "none" },
  evItem:     { fontSize: 11, marginTop: 3, fontFamily: "JetBrains Mono, monospace" },
  code:       { background: "rgba(0,0,0,0.4)", padding: "1px 5px", borderRadius: 3, color: "#e2e8f0" },
  laneItem:   { padding: "6px 0", borderTop: "1px solid rgba(255,255,255,0.05)" },
  mitreLink:  { fontSize: 12, padding: "4px 10px", background: "rgba(103,232,249,0.08)", color: "#67e8f9",
                border: "1px solid rgba(103,232,249,0.35)", borderRadius: 4, fontFamily: "JetBrains Mono, monospace",
                textDecoration: "none" },
  story:      { margin: 0, paddingLeft: 22, counterReset: "s" },
  storyItem:  { marginBottom: 6, fontSize: 13, lineHeight: 1.6, color: "#cbd5e1" },
};
