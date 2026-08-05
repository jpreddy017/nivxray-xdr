/**
 * Inline Attack Story — renders IMMEDIATELY in the Workspace using
 * the preprocessor stages that came back with the DIE envelope.
 * No tab switching, no route change.  Analyst sees the timeline
 * right below the Input Understanding panel.
 *
 * Every stage shows:
 *   · Objective (one-line "what this stage accomplishes")
 *   · MITRE ids
 *   · Evidence bullets
 *   · Commonly observed in (families / actor sets)
 *   · Confidence band
 *   · Child stages (if any)
 */
import { Target, Fingerprint, ShieldAlert, Users, ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";

const TACTIC_TONE = {
  "Initial Access":       { fg: "#c084fc", bd: "rgba(192,132,252,0.35)", bg: "rgba(192,132,252,0.10)" },
  "Discovery":            { fg: "#67e8f9", bd: "rgba(103,232,249,0.35)", bg: "rgba(103,232,249,0.10)" },
  "Execution":            { fg: "#fbbf24", bd: "rgba(251,191,36,0.35)",  bg: "rgba(251,191,36,0.10)" },
  "Persistence":          { fg: "#a78bfa", bd: "rgba(167,139,250,0.35)", bg: "rgba(167,139,250,0.10)" },
  "Defense Evasion":      { fg: "#fb923c", bd: "rgba(251,146,60,0.35)",  bg: "rgba(251,146,60,0.10)" },
  "Credential Access":    { fg: "#f472b6", bd: "rgba(244,114,182,0.35)", bg: "rgba(244,114,182,0.10)" },
  "Lateral Movement":     { fg: "#fbbf24", bd: "rgba(251,191,36,0.35)",  bg: "rgba(251,191,36,0.10)" },
  "Command and Control":  { fg: "#f87171", bd: "rgba(248,113,113,0.35)", bg: "rgba(248,113,113,0.10)" },
  "Exfiltration":         { fg: "#fb7185", bd: "rgba(251,113,133,0.35)", bg: "rgba(251,113,133,0.10)" },
  "Impact":               { fg: "#f87171", bd: "rgba(248,113,113,0.45)", bg: "rgba(248,113,113,0.12)" },
};

export default function InlineAttackStory({ preprocessor }) {
  // Bump this counter to force all StoryStage instances to re-read
  // their persisted open/closed state — powers Expand-All / Collapse-All.
  const [openTick, setOpenTick] = useState(0);
  if (!preprocessor || !preprocessor.stages || !preprocessor.stages.length) {
    return null;
  }
  const stages = preprocessor.stages;
  const bulkSet = (val) => {
    stages.forEach((s) => {
      if (s.id) {
        try { localStorage.setItem(`nvx.story.stage.${s.id}`, val); }
        catch {}
      }
    });
    setOpenTick((t) => t + 1);
  };

  return (
    <section data-testid="inline-attack-story" style={{
      background: "linear-gradient(180deg, rgba(15,23,42,0.9), rgba(2,6,23,0.9))",
      border: "1px solid #1f2b3f", borderRadius: 12,
      padding: "16px 18px", marginBottom: 14,
    }}>
      <div style={{ display: "flex", alignItems: "center",
                    justifyContent: "space-between", marginBottom: 12 }}>
        <div>
          <div style={tagline}>ATTACK STORY</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: "#e2e8f0",
                        marginTop: 2 }}>
            {stages.length} stage{stages.length === 1 ? "" : "s"} · deterministic timeline
          </div>
        </div>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <button data-testid="story-expand-all"
                  onClick={() => bulkSet("1")}
                  style={storyBtn}>
            EXPAND ALL
          </button>
          <button data-testid="story-collapse-all"
                  onClick={() => bulkSet("0")}
                  style={storyBtn}>
            COLLAPSE ALL
          </button>
          <span style={{ fontSize: 11, color: "#94a3b8",
                         fontFamily: "JetBrains Mono, monospace",
                         marginLeft: 8 }}>
            Deterministic · no LLM
          </span>
        </div>
      </div>

      <div style={{ display: "grid", gap: 10 }}>
        {stages.map((s, i) => (
          <StoryStage key={`${s.id || i}-${openTick}`}
                      stage={s} index={i + 1} />
        ))}
      </div>
    </section>
  );
}

function StoryStage({ stage, index }) {
  // All stages default to COLLAPSED so the panel stays compact and
  // the analyst drills-down only into what they need.  Persist the
  // open/closed state per stage id in localStorage so navigating
  // away and back keeps the analyst's choice.
  const persistKey = stage.id ? `nvx.story.stage.${stage.id}` : null;
  const [open, setOpen] = useState(() => {
    try {
      if (!persistKey) return false;
      const raw = localStorage.getItem(persistKey);
      return raw === "1";
    } catch { return false; }
  });
  const toggle = () => {
    setOpen((cur) => {
      const next = !cur;
      try { if (persistKey) localStorage.setItem(persistKey, next ? "1" : "0"); }
      catch {}
      return next;
    });
  };
  const tone = TACTIC_TONE[stage.tactic] || TACTIC_TONE["Discovery"];
  const conf = Math.round((stage.confidence || 0) * 100);
  const confTone = conf >= 85 ? "#86efac" : conf >= 65 ? "#fbbf24" : "#fb923c";

  return (
    <div data-testid={`story-stage-${index}`} style={{
      background: tone.bg, border: `1px solid ${tone.bd}`,
      borderRadius: 10, padding: "10px 14px",
    }}>
      {/* ── Header row ─────────────────────────────────────── */}
      <div onClick={toggle} style={{
        display: "flex", alignItems: "center", gap: 10, cursor: "pointer",
      }}>
        {open ? <ChevronDown size={16} color={tone.fg} />
              : <ChevronRight size={16} color={tone.fg} />}
        <div style={{
          padding: "2px 8px", borderRadius: 4,
          fontSize: 11, fontWeight: 700, letterSpacing: "0.06em",
          color: "#0b1220", background: tone.fg,
          fontFamily: "JetBrains Mono, monospace",
        }}>
          STAGE {index}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 15, fontWeight: 700, color: "#e2e8f0" }}>
            {stage.title}
          </div>
          {stage.objective && (
            <div style={{ marginTop: 2, fontSize: 12, color: "#cbd5e1",
                          lineHeight: 1.45 }}>
              {stage.objective}
            </div>
          )}
        </div>
        {stage.tactic && (
          <div style={{
            padding: "2px 8px", fontSize: 10, letterSpacing: "0.08em",
            textTransform: "uppercase", color: tone.fg,
            border: `1px solid ${tone.bd}`, borderRadius: 4,
            fontFamily: "JetBrains Mono, monospace",
          }}>
            {stage.tactic}
          </div>
        )}
        <div style={{
          fontSize: 12, fontWeight: 700, color: confTone,
          fontFamily: "JetBrains Mono, monospace",
        }}>
          {conf}%
        </div>
      </div>

      {/* ── Expanded content ───────────────────────────────── */}
      {open && (
        <div style={{ marginTop: 10, display: "grid",
                      gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          {stage.mitre && stage.mitre.length > 0 && (
            <StageBlock title="MITRE ATT&CK" icon={Fingerprint}>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {stage.mitre.map((m) => (
                  <span key={m} style={mitreBadge}>{m}</span>
                ))}
              </div>
            </StageBlock>
          )}
          {stage.evidence && stage.evidence.length > 0 && (
            <StageBlock title="Evidence" icon={ShieldAlert}>
              <ul style={bulletList}>
                {stage.evidence.map((e, i) => (
                  <li key={i} style={bullet}>
                    <span style={{ color: "#67e8f9" }}>›</span>{" "}
                    <span style={{ fontFamily: "JetBrains Mono, monospace",
                                   fontSize: 11.5, color: "#cbd5e1" }}
                          dangerouslySetInnerHTML={{ __html:
                            String(e).replace(
                              /`([^`]+)`/g,
                              '<code style="background:rgba(103,232,249,0.10); padding:1px 5px; border-radius:3px; color:#67e8f9">$1</code>'
                            ) }}
                    />
                  </li>
                ))}
              </ul>
            </StageBlock>
          )}
          {stage.commonly_observed_in && stage.commonly_observed_in.length > 0 && (
            <StageBlock title="Commonly Observed In" icon={Users}>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {stage.commonly_observed_in.slice(0, 8).map((n) => (
                  <span key={n} style={obsBadge}>{n}</span>
                ))}
              </div>
              <div style={{ marginTop: 4, fontSize: 10, color: "#64748b",
                            fontStyle: "italic" }}>
                Not attribution — historical prevalence only.
              </div>
            </StageBlock>
          )}
          {stage.raw_excerpt && (
            <StageBlock title="Raw Excerpt" icon={Target}>
              <div style={{
                fontFamily: "JetBrains Mono, monospace", fontSize: 11.5,
                color: "#cbd5e1", background: "rgba(2,6,23,0.55)",
                border: "1px solid #1f2b3f", borderRadius: 6,
                padding: "6px 10px", whiteSpace: "pre-wrap", wordBreak: "break-word",
                maxHeight: 90, overflow: "auto",
              }}>
                {stage.raw_excerpt}
              </div>
              {stage.line_number ? (
                <div style={{ marginTop: 3, fontSize: 10, color: "#64748b",
                              fontFamily: "JetBrains Mono, monospace" }}>
                  line {stage.line_number} · {stage.kind}
                  {stage.command_family ? ` · ${stage.command_family}` : ""}
                </div>
              ) : null}
            </StageBlock>
          )}
        </div>
      )}
    </div>
  );
}

function StageBlock({ title, icon: Icon, children }) {
  return (
    <div>
      <div style={{
        display: "inline-flex", alignItems: "center", gap: 6,
        fontSize: 9, letterSpacing: "0.16em", textTransform: "uppercase",
        color: "#94a3b8", fontFamily: "JetBrains Mono, monospace",
        marginBottom: 4,
      }}>
        {Icon ? <Icon size={11} /> : null}{title}
      </div>
      {children}
    </div>
  );
}

const tagline = {
  fontSize: 9, letterSpacing: "0.22em", textTransform: "uppercase",
  color: "#67e8f9", fontFamily: "JetBrains Mono, monospace",
};

const mitreBadge = {
  padding: "1px 6px", fontSize: 10, fontWeight: 700,
  color: "#67e8f9", background: "rgba(103,232,249,0.10)",
  border: "1px solid rgba(103,232,249,0.35)",
  borderRadius: 4, fontFamily: "JetBrains Mono, monospace",
};

const obsBadge = {
  padding: "1px 6px", fontSize: 10,
  color: "#cbd5e1", background: "rgba(148,163,184,0.10)",
  border: "1px solid rgba(148,163,184,0.30)",
  borderRadius: 4,
};

const bulletList = { margin: 0, padding: 0, listStyle: "none",
                     display: "grid", gap: 3 };
const bullet = { display: "flex", gap: 4, lineHeight: 1.5 };
const storyBtn = {
  padding: "3px 8px", fontSize: 10, fontWeight: 700,
  letterSpacing: "0.1em",
  color: "#67e8f9", background: "rgba(103,232,249,0.08)",
  border: "1px solid rgba(103,232,249,0.35)",
  borderRadius: 4, cursor: "pointer",
  fontFamily: "JetBrains Mono, monospace",
};
