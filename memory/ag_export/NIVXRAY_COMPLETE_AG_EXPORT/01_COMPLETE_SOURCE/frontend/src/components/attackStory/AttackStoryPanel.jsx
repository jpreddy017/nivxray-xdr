/**
 * AttackStoryPanel — Phase B.3 + B.7 · 2026-02-16 pm-late.
 *
 * Renders the DIE chain + Attack Intent Engine output for a case as
 * the primary analyst narrative on the Story tab.
 *
 * Sections (owner-locked):
 *   1. Attack Phase Summary  — Primary Objective + Confidence
 *                              + Attack Progress bar
 *                              + Observed Phases · Missing Phases
 *   2. Attack Story (chain)  — Numbered steps ①②③ · tactic badge
 *                              · DKP "Commonly observed in" chip
 *                              · every step opens EvidenceModal.
 */
import { useEffect, useState } from "react";
import api from "@/lib/api";
import { ChevronRight } from "lucide-react";

const TACTIC_TONE = {
  "Discovery":            { fg: "#7dd3fc", bd: "rgba(56,189,248,0.35)", bg: "rgba(56,189,248,0.10)" },
  "Execution":            { fg: "#fcd34d", bd: "rgba(251,191,36,0.35)", bg: "rgba(251,191,36,0.10)" },
  "Persistence":          { fg: "#c4b5fd", bd: "rgba(167,139,250,0.35)", bg: "rgba(167,139,250,0.10)" },
  "Privilege Escalation": { fg: "#fda4af", bd: "rgba(244,114,182,0.35)", bg: "rgba(244,114,182,0.10)" },
  "Defense Evasion":      { fg: "#fdba74", bd: "rgba(251,146,60,0.35)", bg: "rgba(251,146,60,0.10)" },
  "Impair Defenses":      { fg: "#fdba74", bd: "rgba(251,146,60,0.35)", bg: "rgba(251,146,60,0.10)" },
  "Credential Access":    { fg: "#fca5a5", bd: "rgba(248,113,113,0.35)", bg: "rgba(248,113,113,0.10)" },
  "Lateral Movement":     { fg: "#93c5fd", bd: "rgba(96,165,250,0.35)",  bg: "rgba(96,165,250,0.10)" },
  "Collection":           { fg: "#a7f3d0", bd: "rgba(52,211,153,0.35)",  bg: "rgba(52,211,153,0.10)" },
  "Command and Control":  { fg: "#67e8f9", bd: "rgba(34,211,238,0.35)",  bg: "rgba(34,211,238,0.10)" },
  "Exfiltration":         { fg: "#fca5a5", bd: "rgba(248,113,113,0.35)", bg: "rgba(248,113,113,0.10)" },
  "Impact":               { fg: "#f87171", bd: "rgba(239,68,68,0.40)",   bg: "rgba(239,68,68,0.10)" },
  "Uncategorised":        { fg: "#94a3b8", bd: "rgba(148,163,184,0.30)", bg: "rgba(148,163,184,0.08)" },
};

const CIRCLED = ["①","②","③","④","⑤","⑥","⑦","⑧","⑨","⑩",
                 "⑪","⑫","⑬","⑭","⑮","⑯","⑰","⑱","⑲","⑳"];

function circledIndex(i) {
  if (typeof i === "string" && i.includes(".")) {
    const [parent, child] = i.split(".");
    return `${CIRCLED[Number(parent) - 1] || `(${parent})`}.${child}`;
  }
  const n = Number(i);
  return CIRCLED[n - 1] || `(${n})`;
}

export default function AttackStoryPanel({ caseId, onOpenEvidence }) {
  const [env, setEnv] = useState(null);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!caseId) return;
    setLoading(true); setErr("");
    api.get(`/die/case/${caseId}`).then(r => {
      if (r.data?.envelope) setEnv(r.data.envelope);
      else setErr(r.data?.error || "no envelope");
    }).catch(e => setErr(e?.response?.data?.detail || e.message))
      .finally(() => setLoading(false));
  }, [caseId]);

  if (!caseId) return null;
  if (loading) return <div style={{ color: "#94a3b8", padding: 12, fontSize: 12 }}>Analysing chain…</div>;
  if (err)     return <div data-testid="attack-story-error" style={{ color: "#94a3b8", padding: 12, fontSize: 12 }}>Attack Story unavailable · {err}</div>;
  if (!env)    return null;

  const chain  = env.chain;
  const intent = chain?.attack_intent || env.attack_intent;

  return (
    <div data-testid="attack-story-panel" style={{ display: "grid", gap: 14 }}>
      {intent && <PhaseSummary intent={intent} />}
      {chain?.steps?.length ? (
        <ChainList steps={chain.steps}
                   onOpenEvidence={onOpenEvidence} />
      ) : (
        <SingleStepFallback env={env} onOpenEvidence={onOpenEvidence} />
      )}
    </div>
  );
}

// ─── Attack Phase Summary ─────────────────────────────────────────
function PhaseSummary({ intent }) {
  const conf = Math.round((intent.confidence || 0) * 100);
  const prog = Math.round((intent.progress   || 0) * 100);
  return (
    <section data-testid="attack-phase-summary"
             style={{ background: "rgba(2,6,23,0.55)",
                      border: "1px solid #1f2b3f", borderRadius: 12,
                      padding: 18 }}>
      <div style={{ fontSize: 10, letterSpacing: "0.18em",
                    textTransform: "uppercase", color: "#94a3b8" }}>
        Overall Assessment
      </div>
      <div style={{ display: "grid",
                    gridTemplateColumns: "minmax(0,1fr) 90px 160px",
                    gap: 16, alignItems: "center", marginTop: 6 }}>
        <div>
          <div style={{ fontSize: 10, letterSpacing: "0.16em",
                        textTransform: "uppercase", color: "#94a3b8" }}>
            Primary Objective
          </div>
          <div data-testid="attack-story-objective"
               style={{ fontSize: 22, fontWeight: 700, color: "#e2e8f0",
                        marginTop: 4 }}>
            {intent.objective}
          </div>
        </div>
        <div>
          <div style={{ fontSize: 10, color: "#94a3b8" }}>Confidence</div>
          <div data-testid="attack-story-confidence"
               style={{ fontSize: 22, fontWeight: 700, color: "#86efac" }}>
            {conf}%
          </div>
        </div>
        <div>
          <div style={{ fontSize: 10, color: "#94a3b8" }}>Attack Progress</div>
          <div style={{ marginTop: 4, height: 10, background: "#0a1526",
                        border: "1px solid #1f2b3f", borderRadius: 4,
                        overflow: "hidden" }}>
            <div data-testid="attack-story-progress"
                 style={{ width: `${prog}%`, height: "100%",
                          background: "linear-gradient(90deg,#38bdf8,#f87171)" }} />
          </div>
          <div style={{ fontSize: 10, color: "#94a3b8", marginTop: 3 }}>{prog}%</div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr",
                    gap: 14, marginTop: 14 }}>
        <PhaseList label="Observed phases" testid="phase-observed"
                   items={intent.observed_phases || []}
                   toneKind="observed" />
        <PhaseList label="Missing"          testid="phase-missing"
                   items={intent.missing_phases || []}
                   toneKind="missing" />
      </div>

      {intent.evidence?.length > 0 && (
        <div style={{ marginTop: 14 }}>
          <div style={{ fontSize: 10, letterSpacing: "0.16em",
                        textTransform: "uppercase", color: "#94a3b8" }}>
            Evidence
          </div>
          <ul data-testid="attack-story-evidence"
              style={{ margin: "6px 0 0", paddingLeft: 18, color: "#cbd5e1",
                       fontSize: 12 }}>
            {intent.evidence.slice(0, 8).map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </div>
      )}

      {intent.mitre?.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontSize: 10, letterSpacing: "0.16em",
                        textTransform: "uppercase", color: "#94a3b8" }}>
            MITRE ATT&CK
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 }}>
            {intent.mitre.map(m => (
              <span key={m} data-testid={`attack-story-mitre-${m}`}
                    style={{ padding: "2px 6px", fontSize: 11,
                             background: "rgba(245,158,11,0.10)",
                             color: "#fcd34d",
                             border: "1px solid rgba(245,158,11,0.30)",
                             borderRadius: 3,
                             fontFamily: "ui-monospace, monospace" }}>
                {m}
              </span>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

function PhaseList({ label, items, testid, toneKind }) {
  return (
    <div>
      <div style={{ fontSize: 10, letterSpacing: "0.16em",
                    textTransform: "uppercase", color: "#94a3b8" }}>
        {label}
      </div>
      <div data-testid={testid}
           style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 }}>
        {items.length === 0 && <span style={{ color: "#64748b", fontSize: 11 }}>—</span>}
        {items.map(t => {
          const tone = TACTIC_TONE[t] || TACTIC_TONE.Uncategorised;
          const isMissing = toneKind === "missing";
          return (
            <span key={t}
                  style={{ padding: "2px 8px", fontSize: 11,
                           background: isMissing ? "rgba(15,23,42,0.4)" : tone.bg,
                           color: isMissing ? "#64748b" : tone.fg,
                           border: `1px solid ${isMissing ? "#1f2b3f" : tone.bd}`,
                           borderRadius: 3,
                           fontFamily: "ui-monospace, monospace" }}>
              {isMissing ? `□ ${t}` : `✓ ${t}`}
            </span>
          );
        })}
      </div>
    </div>
  );
}

// ─── Chain (Attack Story) ────────────────────────────────────────
function ChainList({ steps, onOpenEvidence }) {
  return (
    <section data-testid="attack-story-chain"
             style={{ background: "rgba(2,6,23,0.55)",
                      border: "1px solid #1f2b3f", borderRadius: 12,
                      padding: 18 }}>
      <div style={{ fontSize: 10, letterSpacing: "0.18em",
                    textTransform: "uppercase", color: "#94a3b8",
                    marginBottom: 12 }}>
        Attack Chain · {steps.length} step{steps.length === 1 ? "" : "s"}
      </div>
      <div style={{ display: "grid", gap: 6 }}>
        {steps.map((s) => (
          <ChainStep key={s.index} step={s} onOpenEvidence={onOpenEvidence} />
        ))}
      </div>
    </section>
  );
}

function ChainStep({ step, onOpenEvidence }) {
  const tone = TACTIC_TONE[step.intent] || TACTIC_TONE.Uncategorised;
  const isChild = typeof step.index === "string" && step.index.includes(".");
  const dkp = (step.dkp_matches || [])[0];
  const families = dkp?.families?.length ? dkp.families
                    : (dkp?.malware_uses || []).slice(0, 5);

  return (
    <div data-testid={`attack-story-step-${step.index}`}
         onClick={() => onOpenEvidence?.({
           source: `Attack Story · Step ${step.index}`,
           title:  step.summary || step.text,
           rule_description: step.intent,
           mitre: (step.techniques || []).map(t => t.id),
           evidence_refs: step.dkp_matches || [],
           raw: step,
         })}
         role="button" tabIndex={0}
         onKeyDown={(e) => { if (e.key === "Enter") e.currentTarget.click(); }}
         style={{ display: "grid",
                  gridTemplateColumns: "40px 160px minmax(0, 1fr)",
                  gap: 12, alignItems: "flex-start",
                  padding: "10px 12px",
                  paddingLeft: isChild ? 30 : 12,
                  background: "#0a1526",
                  border: `1px solid ${tone.bd}`,
                  borderLeft: `3px solid ${tone.fg}`,
                  borderRadius: 8, cursor: "pointer",
                  transition: "background 0.15s ease" }}
         onMouseEnter={(e) => e.currentTarget.style.background = "#13233d"}
         onMouseLeave={(e) => e.currentTarget.style.background = "#0a1526"}>
      <div style={{ fontSize: 20, color: tone.fg,
                    fontFamily: "ui-monospace, monospace" }}>
        {circledIndex(step.index)}
      </div>
      <div>
        <div style={{ padding: "2px 8px",
                      display: "inline-block", fontSize: 10,
                      background: tone.bg, color: tone.fg,
                      border: `1px solid ${tone.bd}`,
                      borderRadius: 3, letterSpacing: "0.06em",
                      fontFamily: "ui-monospace, monospace" }}>
          {step.intent}
        </div>
        {dkp && (
          <div style={{ marginTop: 6, fontSize: 11, color: "#e2e8f0",
                        fontWeight: 600 }}>
            {dkp.name}
          </div>
        )}
      </div>
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: 12, color: "#e2e8f0",
                      fontFamily: "ui-monospace, monospace",
                      overflow: "hidden", textOverflow: "ellipsis",
                      whiteSpace: "nowrap" }}
             title={step.text}>
          {step.text}
        </div>
        {families.length > 0 && (
          <div style={{ marginTop: 4, fontSize: 10, color: "#94a3b8" }}>
            Commonly observed in:{" "}
            <span style={{ color: "#cbd5e1" }}>
              {families.slice(0, 6).join(" · ")}
            </span>
          </div>
        )}
        {step.techniques?.length > 0 && (
          <div style={{ marginTop: 4, display: "flex", flexWrap: "wrap", gap: 4 }}>
            {step.techniques.slice(0, 4).map(t => (
              <span key={t.id}
                    style={{ padding: "1px 6px", fontSize: 9,
                             background: "rgba(245,158,11,0.10)",
                             color: "#fcd34d",
                             border: "1px solid rgba(245,158,11,0.25)",
                             borderRadius: 3,
                             fontFamily: "ui-monospace, monospace" }}>
                {t.id}
              </span>
            ))}
          </div>
        )}
      </div>
      <ChevronRight size={14} color="#64748b"
                    style={{ gridColumn: 4, alignSelf: "center" }} />
    </div>
  );
}

function SingleStepFallback({ env, onOpenEvidence }) {
  const dkp = (env.dkp_matches || [])[0];
  const families = dkp?.families?.length ? dkp.families
                    : (dkp?.malware_uses || []).slice(0, 5);
  return (
    <section data-testid="attack-story-single"
             style={{ background: "rgba(2,6,23,0.55)",
                      border: "1px solid #1f2b3f", borderRadius: 12,
                      padding: 18 }}>
      <div style={{ fontSize: 10, letterSpacing: "0.18em",
                    textTransform: "uppercase", color: "#94a3b8" }}>
        Attack Story
      </div>
      <div style={{ marginTop: 6, fontSize: 13, color: "#cbd5e1" }}>
        Single-step input · {(env.techniques || []).length} techniques ·{" "}
        {(env.dkp_matches || []).length} DKP hit(s)
      </div>
      {dkp && (
        <div style={{ marginTop: 10 }}>
          <button onClick={() => onOpenEvidence?.({
                    source: "Attack Story", title: dkp.name,
                    rule_id: dkp.id, rule_description: dkp.intent,
                    mitre: dkp.mitre, raw: dkp,
                  })}
                  style={{ background: "transparent", border: "none",
                           padding: 0, cursor: "pointer",
                           color: "#e2e8f0", fontWeight: 600, fontSize: 14 }}>
            {dkp.name} →
          </button>
          {families.length > 0 && (
            <div style={{ marginTop: 4, fontSize: 11, color: "#94a3b8" }}>
              Commonly observed in:{" "}
              <span style={{ color: "#cbd5e1" }}>{families.join(" · ")}</span>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
