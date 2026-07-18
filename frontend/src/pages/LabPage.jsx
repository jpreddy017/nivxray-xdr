/**
 * LabPage — /lab · Analyst Practice Lab
 *
 * Turns NivXRay into a teaching platform. Analysts get a random payload
 * from the gold corpus, guess the MITRE T-IDs / LOLBins / severity, and
 * see how they scored. Streaks + XP make it stick.
 *
 * Backend endpoints:
 *   GET  /api/lab/challenge      — pull a challenge (answer hidden)
 *   POST /api/lab/attempt        — grade the guess + persist score
 *   GET  /api/lab/me             — my stats + recent attempts
 *   GET  /api/lab/leaderboard    — top-20 scorers
 *   GET  /api/lab/reveal/{id}    — full expected answer (post-attempt)
 */
import { useEffect, useState } from "react";
import Header from "@/components/Header";
import api from "@/lib/api";
import {
  GraduationCap, Trophy, Zap, Target, RefreshCw, Check, X, Eye, Award, Flame,
} from "lucide-react";

const DIFFICULTIES = [
  { key: "",       label: "Any" },
  { key: "easy",   label: "Easy" },
  { key: "medium", label: "Medium" },
  { key: "hard",   label: "Hard" },
];

const SEVERITIES = ["", "Informational", "Low", "Medium", "High", "Critical", "Benign"];

const DIFFICULTY_COLOR = { easy: "#10b981", medium: "#f59e0b", hard: "#ef4444" };

export default function LabPage() {
  const [difficulty, setDifficulty] = useState("");
  const [ch,   setCh]   = useState(null);      // current challenge
  const [busy, setBusy] = useState(false);
  const [err,  setErr]  = useState(null);
  const [mitreGuess,    setMitreGuess]    = useState("");
  const [lolbinsGuess,  setLolbinsGuess]  = useState("");
  const [sevGuess,      setSevGuess]      = useState("");
  const [result, setResult] = useState(null);   // grading response
  const [reveal, setReveal] = useState(null);   // full expected answer
  const [me,     setMe]     = useState(null);
  const [board,  setBoard]  = useState([]);

  const loadMe = async () => {
    try {
      const r = await api.get("/lab/me");
      setMe(r.data);
    } catch (_) {}
  };
  const loadBoard = async () => {
    try {
      const r = await api.get("/lab/leaderboard");
      setBoard(r.data?.leaderboard || []);
    } catch (_) {}
  };
  useEffect(() => { loadMe(); loadBoard(); }, []);

  const newChallenge = async () => {
    setBusy(true); setErr(null); setResult(null); setReveal(null);
    setMitreGuess(""); setLolbinsGuess(""); setSevGuess("");
    try {
      const r = await api.get("/lab/challenge", { params: difficulty ? { difficulty } : {} });
      setCh(r.data);
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    } finally { setBusy(false); }
  };

  const submit = async () => {
    if (!ch) return;
    setBusy(true); setErr(null);
    try {
      const guessMitre = mitreGuess.split(/[,\s]+/).map(s => s.trim()).filter(Boolean);
      const guessLolbins = lolbinsGuess.split(/[,\s]+/).map(s => s.trim()).filter(Boolean);
      const r = await api.post("/lab/attempt", {
        challenge_id: ch.challenge_id,
        guess_mitre: guessMitre,
        guess_lolbins: guessLolbins,
        guess_severity: sevGuess,
      });
      setResult(r.data);
      // Auto-reveal after submission
      const rv = await api.get(`/lab/reveal/${ch.challenge_id}`);
      setReveal(rv.data);
      loadMe();
      loadBoard();
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    } finally { setBusy(false); }
  };

  const stats = me?.stats || {};

  return (
    <div data-testid="lab-page">
      <Header />
      <main style={{ maxWidth: 1400, margin: "0 auto", padding: "16px 24px" }}>
        <div style={{ marginBottom: 14, display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: 12 }}>
          <div>
            <h1 style={{ fontSize: 22, margin: 0, color: "var(--text)", display: "flex", alignItems: "center", gap: 8 }}>
              <GraduationCap size={20} /> Analyst Practice Lab
            </h1>
            <p style={{ margin: "4px 0 0", fontSize: 12, color: "var(--text-dim)" }}>
              Random payload from the NivXRay Gold Corpus. Guess the tradecraft. Build the streak.
            </p>
          </div>
          {/* Personal HUD */}
          <div style={{ display: "flex", gap: 12, alignItems: "center" }} data-testid="lab-hud">
            <StatChip icon={<Flame size={14} />}  label="Streak"    value={stats.streak || 0}       color="#f97316" />
            <StatChip icon={<Trophy size={14} />} label="Best"      value={stats.best_streak || 0}  color="#eab308" />
            <StatChip icon={<Award size={14} />}  label="Total XP"  value={stats.total_score || 0}  color="#7ee3c9" />
            <StatChip icon={<Target size={14} />} label="Perfect"   value={stats.total_perfect || 0} color="#a855f7" />
          </div>
        </div>

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

        {/* Challenge card */}
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

              {/* Guess form */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 200px", gap: 10, marginTop: 12 }}>
                <div>
                  <label style={{ fontSize: 11, color: "var(--text-dim)" }}>Your MITRE T-IDs (comma-separated)</label>
                  <input
                    data-testid="lab-mitre-input"
                    value={mitreGuess} onChange={e => setMitreGuess(e.target.value)}
                    disabled={!!result}
                    placeholder="e.g. T1059.001, T1027.010"
                    style={inputStyle} />
                </div>
                <div>
                  <label style={{ fontSize: 11, color: "var(--text-dim)" }}>LOLBins (comma-separated)</label>
                  <input
                    data-testid="lab-lolbins-input"
                    value={lolbinsGuess} onChange={e => setLolbinsGuess(e.target.value)}
                    disabled={!!result}
                    placeholder="e.g. powershell.exe, certutil.exe"
                    style={inputStyle} />
                </div>
                <div>
                  <label style={{ fontSize: 11, color: "var(--text-dim)" }}>Severity</label>
                  <select
                    data-testid="lab-severity-input"
                    value={sevGuess} onChange={e => setSevGuess(e.target.value)}
                    disabled={!!result}
                    style={{ ...inputStyle, height: 30 }}>
                    {SEVERITIES.map(s => <option key={s} value={s}>{s || "— select —"}</option>)}
                  </select>
                </div>
              </div>
              {!result && (
                <div style={{ marginTop: 12 }}>
                  <button onClick={submit} disabled={busy}
                          data-testid="lab-submit-btn" className="nvx-btn sm primary">
                    <Target size={12} /> SUBMIT GUESS
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Result card */}
        {result && reveal && (
          <div className="nvx-card" style={{ marginBottom: 12,
                borderColor: result.perfect ? "#7ee3c9" : "#f59e0b" }}
               data-testid="lab-result">
            <div className="nvx-card-head">
              <div className="nvx-card-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {result.perfect
                  ? <><Check size={14} color="#7ee3c9" /> Perfect! +{result.score} XP · Streak {result.streak}</>
                  : <><Eye size={14} color="#f59e0b" /> Partial — {result.score}/{result.max_score} XP</>}
              </div>
              <button onClick={newChallenge} className="nvx-btn xs primary" data-testid="lab-next-btn">
                <RefreshCw size={11} /> NEXT CHALLENGE
              </button>
            </div>
            <div className="nvx-card-body" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
              <ResultBox label="MITRE T-IDs"
                         pass={result.mitre_pass}
                         got={result.got.mitre} expected={result.expected.mitre} />
              <ResultBox label="LOLBins"
                         pass={result.lolbin_pass}
                         got={result.got.lolbins} expected={result.expected.lolbins} />
              <ResultBox label="Severity"
                         pass={result.severity_pass}
                         got={[result.got.severity]}
                         expected={[result.expected.severity]} />
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

const inputStyle = {
  width: "100%",
  padding: "6px 8px",
  background: "var(--bg-deep)",
  border: "1px solid var(--border)",
  color: "var(--text)",
  fontFamily: "JetBrains Mono",
  fontSize: 11,
  borderRadius: 4,
  marginTop: 4,
};

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

function ResultBox({ label, pass, got, expected }) {
  return (
    <div style={{
      padding: 10, border: `1px solid ${pass ? "#7ee3c9" : "#ef4444"}`,
      background: pass ? "rgba(126,227,201,0.06)" : "rgba(239,68,68,0.06)",
      borderRadius: 4,
    }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 6, fontSize: 11,
        color: pass ? "#7ee3c9" : "#ef4444", fontWeight: 700, marginBottom: 6,
      }}>
        {pass ? <Check size={12} /> : <X size={12} />} {label}
      </div>
      <div style={{ fontSize: 10, color: "var(--text-dim)" }}>
        <div>You: <span style={{ color: "var(--text)" }}>{(got || []).filter(Boolean).join(", ") || "—"}</span></div>
        <div>Expected: <span style={{ color: "var(--text)" }}>{(expected || []).filter(Boolean).join(", ") || "—"}</span></div>
      </div>
    </div>
  );
}
