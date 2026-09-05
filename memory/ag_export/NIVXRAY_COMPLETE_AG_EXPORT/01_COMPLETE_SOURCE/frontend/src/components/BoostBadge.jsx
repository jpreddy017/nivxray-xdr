import { useState } from "react";
import { Zap, ChevronDown, ChevronRight, ThumbsUp, ThumbsDown,
         X, Info, RotateCw } from "lucide-react";
import api from "@/lib/api";

/**
 * BoostBadge — visualizes the Learning Feedback Loop.
 *
 * Props:
 *   boost      : object   — from /api/decode/smart's `boost` field
 *   boostHit   : boolean  — did the actual chain match the boosted one?
 *   engine     : string   — actual engine that won (magic|smart|custom_recipe|...)
 *   onRerun    : (opts) => void  — called to re-run with disable_boost etc.
 *
 * Shows source (history/kb/default), signal kind, confidence,
 * the boosted chain vs the actual chain, and 👍/👎/DISABLE controls.
 */
export default function BoostBadge({ boost, boostHit, engine, onRerun }) {
  const [expanded, setExpanded] = useState(false);
  const [voted, setVoted] = useState(null);   // "up" | "down" | null
  const [voting, setVoting] = useState(false);

  if (!boost) return null;

  const enabled = !!boost.enabled;
  const source = boost.source || "default";
  const conf = Math.round((boost.confidence || 0) * 100);
  const kind = boost.signal_kind || "unknown";

  const SRC_META = {
    history: { colour: "var(--accent)", label: "YOUR HISTORY", tip: "Boosted from a chain that succeeded on similar payloads in your investigations." },
    kb:      { colour: "var(--warn)",   label: "KB ARCHETYPE", tip: "Boosted from a Knowledge-Base archetype matching this payload's signal kind." },
    default: { colour: "var(--text-mute)", label: "BUILT-IN PRIOR", tip: "No user history yet — using the built-in heuristic prior for this signal kind." },
  };
  const meta = SRC_META[source] || SRC_META.default;

  const castVote = async (up) => {
    if (!boost.chain?.length) return;
    setVoting(true);
    try {
      await api.post("/learning/feedback", { chain: boost.chain, up });
      setVoted(up ? "up" : "down");
    } catch (_) {}
    finally { setVoting(false); }
  };

  const rerunWithout = () => onRerun && onRerun({ disable_boost: true });

  const hitColour = boostHit ? "var(--accent)" : "var(--warn)";

  return (
    <div className="brut-border" style={{
      background: "var(--surface)", padding: 0, marginBottom: 10,
      fontFamily: "JetBrains Mono", fontSize: 11,
    }} data-testid="boost-badge">
      {/* SUMMARY BAR */}
      <div
        style={{
          padding: "8px 12px", display: "flex", alignItems: "center", gap: 10,
          cursor: "pointer", borderBottom: expanded ? "1px solid var(--border)" : "none",
        }}
        onClick={() => setExpanded((v) => !v)}
        data-testid="boost-badge-toggle">
        <Zap size={13} color={meta.colour} />
        <span style={{ color: meta.colour, fontWeight: 700, letterSpacing: "0.14em" }}>
          BOOSTED
        </span>
        <span style={{ color: "var(--text-mute)" }}>·</span>
        <span title={meta.tip} style={{ color: meta.colour, letterSpacing: "0.08em" }}>
          {meta.label}
        </span>
        <span style={{ color: "var(--text-mute)" }}>·</span>
        <span style={{ color: "var(--text-dim)" }}>kind: <b>{kind}</b></span>
        <span style={{ color: "var(--text-mute)" }}>·</span>
        <span style={{ color: "var(--text-dim)" }}>conf: <b>{conf}%</b></span>
        <span style={{ flex: 1 }} />
        {enabled && (
          <span style={{
            padding: "2px 8px", background: boostHit ? "rgba(74,168,144,0.16)" : "rgba(230,195,74,0.16)",
            color: hitColour, border: `1px solid ${hitColour}`,
            fontSize: 10, letterSpacing: "0.14em", fontWeight: 700,
          }} data-testid="boost-hit-badge">
            {boostHit ? "✓ HIT" : "◇ MISS"}
          </span>
        )}
        {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </div>

      {/* DETAIL PANEL */}
      {expanded && (
        <div style={{ padding: "10px 12px" }} data-testid="boost-badge-details">
          <Row label="BOOSTED CHAIN">
            {boost.chain?.length ? (
              <ChainPills chain={boost.chain} colour={meta.colour} />
            ) : <span style={{ color: "var(--text-mute)" }}>(none)</span>}
          </Row>

          {!boostHit && engine && (
            <Row label="ACTUAL WINNER">
              <span style={{ color: "var(--text-dim)" }}>engine=<b style={{ color: "var(--warn)" }}>{engine}</b> — did not match the boost</span>
            </Row>
          )}

          {boost.alternatives?.length ? (
            <Row label="ALTERNATIVES">
              {boost.alternatives.slice(0, 4).map((a, i) => (
                <div key={i} style={{ marginTop: 4, display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ color: "var(--text-mute)", fontSize: 10 }}>#{i + 2}</span>
                  <ChainPills chain={a.chain} colour="var(--text-dim)" />
                  <span style={{ color: "var(--text-mute)", fontSize: 10 }}>· {a.source} · score {a.score}</span>
                </div>
              ))}
            </Row>
          ) : null}

          {/* Actions row */}
          <div style={{ marginTop: 10, display: "flex", gap: 6, flexWrap: "wrap" }}>
            <button className="nvx-btn sm ghost"
                    onClick={() => castVote(true)}
                    disabled={voting || voted === "up"}
                    data-testid="btn-boost-thumbs-up"
                    style={voted === "up" ? { color: "var(--accent)", borderColor: "var(--accent)" } : null}>
              <ThumbsUp size={11} /> HELPFUL
            </button>
            <button className="nvx-btn sm ghost"
                    onClick={() => castVote(false)}
                    disabled={voting || voted === "down"}
                    data-testid="btn-boost-thumbs-down"
                    style={voted === "down" ? { color: "var(--high)", borderColor: "var(--high)" } : null}>
              <ThumbsDown size={11} /> NOT HELPFUL
            </button>
            <button className="nvx-btn sm ghost"
                    onClick={rerunWithout}
                    data-testid="btn-boost-disable-rerun"
                    title="Re-run Smart Decode with boost disabled">
              <RotateCw size={11} /> RE-RUN NO-BOOST
            </button>
            <div style={{ flex: 1 }} />
            <span style={{ color: "var(--text-mute)", fontSize: 10 }} title={meta.tip}>
              <Info size={10} style={{ verticalAlign: "middle" }} /> {meta.tip}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}


function Row({ label, children }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{
        color: "var(--text-mute)", fontSize: 9, letterSpacing: "0.2em", marginBottom: 3,
      }}>
        {label}
      </div>
      <div>{children}</div>
    </div>
  );
}


function ChainPills({ chain, colour }) {
  return (
    <span style={{ display: "inline-flex", flexWrap: "wrap", alignItems: "center", gap: 4 }}>
      {(chain || []).map((op, i) => (
        <span key={i} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
          <span style={{
            padding: "2px 8px", background: "var(--inset)",
            border: `1px solid ${colour}`, color: colour,
            fontSize: 10, letterSpacing: "0.08em",
          }}>{op}</span>
          {i < chain.length - 1 && (
            <span style={{ color: "var(--text-mute)" }}>→</span>
          )}
        </span>
      ))}
    </span>
  );
}
