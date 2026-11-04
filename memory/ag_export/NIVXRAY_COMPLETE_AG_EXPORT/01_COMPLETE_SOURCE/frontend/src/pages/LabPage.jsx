/**
 * LabPage — /lab · Analyst Practice Lab (Narrative Mode)
 *
 * v1.3.1 (Feb 2026): shifted from strict MITRE T-code memorisation to a
 * free-form analyst write-up. The analyst explains what the command does,
 * the impact, and their recommendations. Claude grades on a 100-pt rubric
 * (understanding 40 · impact 30 · recommendations 30) and the expected
 * MITRE codes are shown POST-submit as learning material — not as a quiz.
 *
 * Backend endpoints:
 *   GET  /api/lab/challenge              — pull a challenge (answer hidden)
 *   POST /api/lab/attempt/narrative      — grade write-up via Claude
 *   GET  /api/lab/me                     — my stats + recent attempts
 *   GET  /api/lab/leaderboard            — top-20 scorers
 */
import { useEffect, useState } from "react";
import Header from "@/components/Header";
import PageHeader from "@/components/PageHeader";
import api from "@/lib/api";
import {
  GraduationCap, Trophy, Zap, Target, RefreshCw, Check, X, Award, Flame,
  Sparkles, BookOpen, ShieldAlert, Wrench,
} from "lucide-react";

const DIFFICULTIES = [
  { key: "",       label: "Any" },
  { key: "easy",   label: "Easy" },
  { key: "medium", label: "Medium" },
  { key: "hard",   label: "Hard" },
];

const DIFFICULTY_COLOR = { easy: "#10b981", medium: "#f59e0b", hard: "#ef4444" };

export default function LabPage() {
  const [difficulty, setDifficulty] = useState("");
  const [ch,      setCh]      = useState(null);
  const [busy,    setBusy]    = useState(false);
  const [err,     setErr]     = useState(null);
  const [understanding,   setUnderstanding]   = useState("");
  const [impact,          setImpact]          = useState("");
  const [recommendations, setRecommendations] = useState("");
  const [result,  setResult]  = useState(null);
  const [me,      setMe]      = useState(null);
  const [board,   setBoard]   = useState([]);

  const loadMe = async () => {
    try { const r = await api.get("/lab/me"); setMe(r.data); } catch (_) {}
  };
  const loadBoard = async () => {
    try { const r = await api.get("/lab/leaderboard"); setBoard(r.data?.leaderboard || []); } catch (_) {}
  };
  useEffect(() => { loadMe(); loadBoard(); }, []);

  const newChallenge = async () => {
    setBusy(true); setErr(null); setResult(null);
    setUnderstanding(""); setImpact(""); setRecommendations("");
    try {
      const r = await api.get("/lab/challenge", { params: difficulty ? { difficulty } : {} });
      setCh(r.data);
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    } finally { setBusy(false); }
  };

  const submit = async () => {
    if (!ch) return;
    if (!understanding.trim() && !impact.trim() && !recommendations.trim()) {
      setErr("Please write at least one section before submitting.");
      return;
    }
    setBusy(true); setErr(null);
    try {
      const r = await api.post("/lab/attempt/narrative", {
        challenge_id:    ch.challenge_id,
        understanding, impact, recommendations,
      });
      setResult(r.data);
      loadMe(); loadBoard();
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    } finally { setBusy(false); }
  };

  const stats = me?.stats || {};
  const grading = busy && ch && !result;

  return (
    <div data-testid="lab-page">
      <Header />
      <main style={{ maxWidth: 1400, margin: "0 auto", padding: "16px 24px" }}>
        <PageHeader
          testId="lab-hero"
          eyebrow="Analyst Practice Lab · Narrative Mode · v1.3.1"
          title="Analyst Practice Lab"
          subtitle="Write your analysis in plain English. Claude grades on tradecraft understanding, impact, and recommendations — MITRE codes are revealed as learning material after you submit."
          icon={GraduationCap}
          tone="accent"
          rightSlot={
            <div style={{ display: "flex", gap: 8, alignItems: "center" }} data-testid="lab-hud">
              <StatChip icon={<Flame size={14} />}  label="Streak"    value={stats.streak || 0}       color="#f97316" />
              <StatChip icon={<Trophy size={14} />} label="Best"      value={stats.best_streak || 0}  color="#eab308" />
              <StatChip icon={<Award size={14} />}  label="Total XP"  value={stats.total_score || 0}  color="#7ee3c9" />
              <StatChip icon={<Target size={14} />} label="Perfect"   value={stats.total_perfect || 0} color="#a855f7" />
            </div>
          }
        />

        {err && (
          <div className="nvx-card" style={{ marginBottom: 12, borderColor: "#ef4444" }}>
            <div className="nvx-card-body" style={{ color: "#fecaca", fontSize: 12 }} data-testid="lab-error">
              {err}
            </div>
          </div>
        )}

        {/* Difficulty picker + start */}
        <div className="nvx-card" style={{ marginBottom: 12 }}>
          <div className="nvx-card-head">
            <div className="nvx-card-title">Pick a challenge</div>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              {DIFFICULTIES.map(d => (
                <button
                  key={d.key}
                  onClick={() => setDifficulty(d.key)}
                  data-testid={`lab-difficulty-${d.key || "any"}`}
                  className="nvx-btn xs ghost"
                  style={{
                    borderColor: difficulty === d.key ? "var(--accent)" : undefined,
                    color:       difficulty === d.key ? "var(--accent)" : "var(--text-dim)",
                  }}>
                  {d.label}
                </button>
              ))}
              <button onClick={newChallenge} disabled={busy}
                      data-testid="lab-new-challenge"
                      className="nvx-btn sm primary">
                <Zap size={12} /> {ch ? "NEW CHALLENGE" : "START"}
              </button>
            </div>
          </div>
        </div>

        {/* Challenge + narrative form */}
        {ch && (
          <div className="nvx-card" style={{ marginBottom: 12 }} data-testid="lab-challenge">
            <div className="nvx-card-head">
              <div className="nvx-card-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {ch.title || ch.challenge_id}
                <span style={{
                  padding: "2px 8px",
                  background: `${DIFFICULTY_COLOR[ch.difficulty] || "#6b7280"}22`,
                  color: DIFFICULTY_COLOR[ch.difficulty] || "#6b7280",
                  border: `1px solid ${DIFFICULTY_COLOR[ch.difficulty] || "#6b7280"}`,
                  fontFamily: "JetBrains Mono", fontSize: 10, borderRadius: 3,
                  textTransform: "uppercase", letterSpacing: "0.06em",
                }} data-testid="lab-challenge-difficulty">
                  {ch.difficulty}
                </span>
              </div>
              <span style={{ fontSize: 11, color: "var(--text-dim)" }} data-testid="lab-challenge-id">
                {ch.challenge_id}
              </span>
            </div>
            <div className="nvx-card-body">
              <div style={{ marginBottom: 8, fontSize: 11, color: "var(--text-dim)" }}>THE PAYLOAD</div>
              <pre style={{
                background: "var(--bg-deep)", border: "1px solid var(--border)",
                padding: 10, borderRadius: 4, fontSize: 12, color: "var(--text)",
                whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0,
              }} data-testid="lab-payload">{ch.input}</pre>

              {/* Narrative form */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginTop: 14 }}>
                <NarrativeField
                  testid="lab-understanding-input"
                  icon={<BookOpen size={12} />}
                  label="1. What does this command do?"
                  hint="Explain each flag/binary. Is it downloading, executing, encoding, persisting?"
                  value={understanding} onChange={setUnderstanding}
                  disabled={!!result || grading}
                />
                <NarrativeField
                  testid="lab-impact-input"
                  icon={<ShieldAlert size={12} />}
                  label="2. Impact & risk"
                  hint="What happens if this runs on a corporate endpoint? Severity? Blast radius?"
                  value={impact} onChange={setImpact}
                  disabled={!!result || grading}
                />
                <NarrativeField
                  testid="lab-recommendations-input"
                  icon={<Wrench size={12} />}
                  label="3. Recommendations"
                  hint="Detections (EDR/SIEM), containment steps, hardening. Be specific."
                  value={recommendations} onChange={setRecommendations}
                  disabled={!!result || grading}
                />
              </div>

              {!result && (
                <div style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 10 }}>
                  <button onClick={submit} disabled={busy}
                          data-testid="lab-submit-btn" className="nvx-btn sm primary">
                    <Sparkles size={12} /> {grading ? "GRADING WITH CLAUDE…" : "SUBMIT ANALYSIS"}
                  </button>
                  <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
                    Rubric: understanding /40 · impact /30 · recommendations /30 · perfect ≥ 85
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* AI grade + reveal */}
        {result && (
          <div className="nvx-card" style={{ marginBottom: 12,
                borderColor: result.perfect ? "#7ee3c9" : (result.score >= 60 ? "#f59e0b" : "#ef4444") }}
               data-testid="lab-result">
            <div className="nvx-card-head">
              <div className="nvx-card-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {result.perfect
                  ? <><Check size={14} color="#7ee3c9" /> Excellent write-up · {result.score}/{result.max_score} XP · Streak {result.streak}</>
                  : <><Sparkles size={14} color="#f59e0b" /> {result.score}/{result.max_score} XP · Keep going</>}
              </div>
              <button onClick={newChallenge} className="nvx-btn xs primary" data-testid="lab-next-btn">
                <RefreshCw size={11} /> NEXT CHALLENGE
              </button>
            </div>
            <div className="nvx-card-body">
              {/* Rubric bars */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 12 }}>
                <RubricBar label="Understanding" score={result.understanding_score} max={40} icon={<BookOpen size={11} />} />
                <RubricBar label="Impact"        score={result.impact_score}        max={30} icon={<ShieldAlert size={11} />} />
                <RubricBar label="Recommendations" score={result.recommendations_score} max={30} icon={<Wrench size={11} />} />
              </div>

              {/* AI feedback */}
              {result.feedback && (
                <div style={{
                  padding: 10, marginBottom: 12,
                  background: "rgba(126,227,201,0.06)", border: "1px solid #7ee3c955",
                  borderRadius: 4, fontSize: 12, color: "var(--text)",
                }} data-testid="lab-ai-feedback">
                  <div style={{ fontSize: 10, color: "#7ee3c9", marginBottom: 4, letterSpacing: "0.08em" }}>
                    CLAUDE&apos;S FEEDBACK
                  </div>
                  {result.feedback}
                </div>
              )}

              {/* Strengths / gaps */}
              {(result.strengths?.length || result.gaps?.length) ? (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
                  <ListCard title="Strengths" items={result.strengths} color="#7ee3c9" icon={<Check size={11} />} testid="lab-strengths" />
                  <ListCard title="Gaps"      items={result.gaps}      color="#f59e0b" icon={<X size={11} />}     testid="lab-gaps" />
                </div>
              ) : null}

              {/* MITRE reveal (learning material) */}
              {(result.expected_mitre_enriched?.length || result.expected_lolbins?.length) ? (
                <div style={{
                  padding: 10, background: "var(--bg-deep)",
                  border: "1px solid var(--border)", borderRadius: 4,
                }} data-testid="lab-mitre-reveal">
                  <div style={{ fontSize: 10, color: "var(--text-dim)", marginBottom: 8, letterSpacing: "0.08em" }}>
                    REFERENCE ATT&amp;CK MAPPING (learn — not scored)
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 8 }}>
                    {(result.expected_mitre_enriched || []).map(m => (
                      <span key={m.id} data-testid={`lab-mitre-chip-${m.id}`}
                            title={m.tactic}
                            style={{
                              padding: "3px 8px", background: "rgba(168,85,247,0.12)",
                              border: "1px solid #a855f7", color: "#e9d5ff",
                              fontFamily: "JetBrains Mono", fontSize: 10, borderRadius: 3,
                            }}>
                        <strong>{m.id}</strong>{m.name ? ` · ${m.name}` : ""}
                      </span>
                    ))}
                  </div>
                  {result.expected_lolbins?.length > 0 && (
                    <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
                      LOLBins:{" "}
                      {result.expected_lolbins.map(l => (
                        <span key={l} style={{
                          padding: "2px 6px", background: "rgba(245,158,11,0.14)",
                          border: "1px solid #f59e0b55", color: "#fcd34d",
                          fontFamily: "JetBrains Mono", fontSize: 10, borderRadius: 3,
                          marginRight: 4,
                        }}>{l}</span>
                      ))}
                    </div>
                  )}
                  {result.expected_severity && (
                    <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6 }}>
                      Expected severity: <strong style={{ color: "var(--text)" }}>{result.expected_severity}</strong>
                    </div>
                  )}
                </div>
              ) : null}
            </div>
          </div>
        )}

        {/* Leaderboard */}
        {board.length > 0 && (
          <div className="nvx-card" data-testid="lab-leaderboard">
            <div className="nvx-card-head">
              <div className="nvx-card-title" style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <Trophy size={14} /> Leaderboard
              </div>
            </div>
            <div className="nvx-card-body" style={{ padding: 0, overflowX: "auto" }}>
              <table className="mono" style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                <thead>
                  <tr style={{ background: "var(--bg-deep)", textAlign: "left" }}>
                    {["#","Analyst","XP","Perfect","Best Streak","Current Streak"].map(h => (
                      <th key={h} style={{ padding: "8px 10px", color: "var(--text-dim)",
                                            borderBottom: "1px solid var(--border)" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {board.slice(0, 20).map((b, i) => (
                    <tr key={b.user_email} data-testid={`lab-leaderboard-row-${i}`}
                        style={{ borderBottom: "1px solid var(--border)" }}>
                      <td style={{ padding: "6px 10px", color: "var(--text-mute)" }}>{i + 1}</td>
                      <td style={{ padding: "6px 10px", color: "var(--text)" }}>{b.user_email}</td>
                      <td style={{ padding: "6px 10px", color: "#7ee3c9", fontWeight: 600 }}>{b.total_score || 0}</td>
                      <td style={{ padding: "6px 10px", color: "#a855f7" }}>{b.total_perfect || 0}</td>
                      <td style={{ padding: "6px 10px", color: "#eab308" }}>{b.best_streak || 0}</td>
                      <td style={{ padding: "6px 10px", color: "#f97316" }}>{b.streak || 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

// ─── UI helpers ──────────────────────────────────────────────────────────

function NarrativeField({ testid, icon, label, hint, value, onChange, disabled }) {
  return (
    <div>
      <label style={{ fontSize: 11, color: "var(--text-dim)", display: "flex", alignItems: "center", gap: 4 }}>
        {icon} {label}
      </label>
      <textarea
        data-testid={testid}
        value={value}
        onChange={e => onChange(e.target.value)}
        disabled={disabled}
        placeholder={hint}
        rows={7}
        style={{
          width: "100%",
          padding: "8px 10px",
          background: "var(--bg-deep)",
          border: "1px solid var(--border)",
          color: "var(--text)",
          fontFamily: "JetBrains Mono",
          fontSize: 11,
          lineHeight: 1.55,
          borderRadius: 4,
          marginTop: 4,
          resize: "vertical",
          minHeight: 130,
        }}
      />
    </div>
  );
}

function StatChip({ icon, label, value, color }) {
  return (
    <div data-testid={`lab-stat-${label.toLowerCase().replace(" ", "-")}`}
         style={{
      display: "flex", alignItems: "center", gap: 6,
      padding: "4px 10px", background: "var(--surface-mute)",
      border: `1px solid ${color}55`, borderRadius: 3,
      fontFamily: "JetBrains Mono", fontSize: 11,
    }}>
      <span style={{ color }}>{icon}</span>
      <span style={{ color: "var(--text-dim)" }}>{label}</span>
      <span style={{ color, fontWeight: 700 }}>{value}</span>
    </div>
  );
}

function RubricBar({ label, score, max, icon }) {
  const pct = Math.max(0, Math.min(100, Math.round(((score || 0) / max) * 100)));
  const color = pct >= 80 ? "#7ee3c9" : pct >= 50 ? "#f59e0b" : "#ef4444";
  return (
    <div data-testid={`lab-rubric-${label.toLowerCase()}`}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--text-dim)", marginBottom: 4 }}>
        <span style={{ display: "flex", alignItems: "center", gap: 4 }}>{icon} {label}</span>
        <span style={{ color, fontFamily: "JetBrains Mono", fontWeight: 700 }}>{score || 0}/{max}</span>
      </div>
      <div style={{ height: 6, background: "var(--bg-deep)", border: "1px solid var(--border)", borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, transition: "width .35s ease" }} />
      </div>
    </div>
  );
}

function ListCard({ title, items, color, icon, testid }) {
  return (
    <div data-testid={testid} style={{
      padding: 10, border: `1px solid ${color}55`,
      background: `${color}0f`, borderRadius: 4,
    }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 6, fontSize: 11,
        color, fontWeight: 700, marginBottom: 6, letterSpacing: "0.06em",
      }}>
        {icon} {title.toUpperCase()}
      </div>
      {items?.length ? (
        <ul style={{ margin: 0, paddingLeft: 16, fontSize: 11, color: "var(--text)", lineHeight: 1.55 }}>
          {items.map((it, i) => <li key={i}>{String(it)}</li>)}
        </ul>
      ) : (
        <div style={{ fontSize: 11, color: "var(--text-dim)" }}>—</div>
      )}
    </div>
  );
}
