import { useEffect, useState } from "react";
import { ThumbsUp, ThumbsDown, MessageSquare, Loader2 } from "lucide-react";
import api from "@/lib/api";

/**
 * PlaybookFeedback — 👍/👎 widget attached to an AI-investigation job.
 *
 * Wires into POST/GET /api/analyze/{jobId}/feedback. Toggling is allowed —
 * flipping a vote automatically reverses the previous counters on every
 * playbook that was attributed to the job (full audit trail preserved).
 *
 * Props:
 *   jobId    (required)      — id of the completed analyze_async job
 *   compact  (optional)      — dense rendering for card headers
 *   testidPrefix (optional)  — override for data-testid strings
 */
export default function PlaybookFeedback({ jobId, compact = false, testidPrefix = "playbook-feedback" }) {
  const [state, setState] = useState({ vote: "none", reason: "", playbooks_used: [], loaded: false });
  const [busy, setBusy] = useState(false);
  const [showReason, setShowReason] = useState(false);
  const [reasonDraft, setReasonDraft] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!jobId) return;
    let ok = true;
    (async () => {
      try {
        const r = await api.get(`/analyze/${jobId}/feedback`);
        if (!ok) return;
        setState({
          vote: r.data.vote || "none",
          reason: r.data.reason || "",
          playbooks_used: r.data.playbooks_used || [],
          history: r.data.history || [],
          loaded: true,
        });
        setReasonDraft(r.data.reason || "");
      } catch (e) {
        if (!ok) return;
        setState((s) => ({ ...s, loaded: true }));
      }
    })();
    return () => { ok = false; };
  }, [jobId]);

  const submit = async (vote) => {
    if (!jobId || busy) return;
    setBusy(true); setErr("");
    try {
      // If user re-clicks the same vote → retract (vote:"none")
      const nextVote = state.vote === vote ? "none" : vote;
      const r = await api.post(`/analyze/${jobId}/feedback`, {
        vote: nextVote,
        reason: nextVote === "none" ? "" : reasonDraft,
      });
      setState((s) => ({
        ...s,
        vote: r.data.vote,
        reason: nextVote === "none" ? "" : reasonDraft,
      }));
      if (nextVote === "none") { setShowReason(false); setReasonDraft(""); }
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    } finally {
      setBusy(false);
    }
  };

  const saveReason = async () => {
    if (!jobId || busy || state.vote === "none") return;
    setBusy(true); setErr("");
    try {
      await api.post(`/analyze/${jobId}/feedback`, { vote: state.vote, reason: reasonDraft });
      setState((s) => ({ ...s, reason: reasonDraft }));
      setShowReason(false);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    } finally {
      setBusy(false);
    }
  };

  if (!jobId) return null;

  const disabled = busy || !state.loaded;
  const upActive = state.vote === "up";
  const downActive = state.vote === "down";
  const hasPlaybooks = (state.playbooks_used || []).length > 0;

  const btnStyle = (active, activeColor) => ({
    display: "inline-flex", alignItems: "center", gap: 6,
    fontFamily: "var(--font-mono, monospace)", fontSize: compact ? 10 : 11,
    letterSpacing: "0.12em", textTransform: "uppercase",
    padding: compact ? "4px 8px" : "6px 10px",
    border: `1px solid ${active ? activeColor : "var(--line, #333)"}`,
    background: active ? `${activeColor}22` : "transparent",
    color: active ? activeColor : "var(--text-dim, #999)",
    cursor: disabled ? "wait" : "pointer",
    transition: "all 140ms ease",
    borderRadius: 2,
  });

  return (
    <div data-testid={`${testidPrefix}-widget`} style={{
      display: "flex", flexDirection: "column", gap: compact ? 4 : 8,
      alignItems: "flex-start",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        {!compact && (
          <span className="mono" style={{
            fontSize: 10, color: "var(--text-dim, #999)", letterSpacing: "0.18em",
            textTransform: "uppercase",
          }}>
            Playbook feedback
          </span>
        )}
        <button
          data-testid={`${testidPrefix}-up`}
          disabled={disabled}
          onClick={() => submit("up")}
          style={btnStyle(upActive, "var(--good, #4ade80)")}
          title={hasPlaybooks
            ? `Boost ${state.playbooks_used.map(p => p.name).join(" + ")}`
            : "No playbook was applied to this investigation"}
        >
          {busy && upActive ? <Loader2 size={11} className="spin" /> : <ThumbsUp size={11} />}
          {upActive ? "BOOSTED" : "HELPFUL"}
        </button>
        <button
          data-testid={`${testidPrefix}-down`}
          disabled={disabled}
          onClick={() => submit("down")}
          style={btnStyle(downActive, "var(--high, #f87171)")}
          title={hasPlaybooks
            ? `De-boost ${state.playbooks_used.map(p => p.name).join(" + ")}`
            : "No playbook was applied to this investigation"}
        >
          {busy && downActive ? <Loader2 size={11} className="spin" /> : <ThumbsDown size={11} />}
          {downActive ? "PENALIZED" : "MISS"}
        </button>
        {(upActive || downActive) && (
          <button
            data-testid={`${testidPrefix}-reason-toggle`}
            onClick={() => setShowReason((s) => !s)}
            style={{
              display: "inline-flex", alignItems: "center", gap: 5,
              fontFamily: "var(--font-mono, monospace)", fontSize: 10,
              letterSpacing: "0.12em", textTransform: "uppercase",
              padding: "4px 8px", border: "1px dashed var(--line, #333)",
              background: "transparent", color: "var(--text-dim, #999)",
              cursor: "pointer", borderRadius: 2,
            }}
            title="Attach a short reason (stored in the audit log)"
          >
            <MessageSquare size={10} /> {state.reason ? "EDIT REASON" : "+ REASON"}
          </button>
        )}
        {!compact && hasPlaybooks && (
          <span className="mono" style={{
            fontSize: 10, color: "var(--text-dim, #999)", opacity: 0.7,
          }}>
            attributes to {state.playbooks_used.length} playbook{state.playbooks_used.length === 1 ? "" : "s"}
          </span>
        )}
      </div>

      {showReason && (
        <div style={{ display: "flex", gap: 6, alignItems: "center", width: "100%", maxWidth: 480 }}>
          <input
            data-testid={`${testidPrefix}-reason-input`}
            value={reasonDraft}
            onChange={(e) => setReasonDraft(e.target.value)}
            placeholder={downActive
              ? "What did the playbook miss? (e.g. 'skipped LZMA layer')"
              : "What worked well? (e.g. 'nailed the family attribution')"}
            style={{
              flex: 1, fontFamily: "var(--font-mono, monospace)", fontSize: 11,
              padding: "5px 8px", background: "var(--panel, #111)",
              color: "var(--text, #eee)", border: "1px solid var(--line, #333)",
              borderRadius: 2,
            }}
          />
          <button
            data-testid={`${testidPrefix}-reason-save`}
            onClick={saveReason}
            disabled={busy}
            style={{
              fontFamily: "var(--font-mono, monospace)", fontSize: 10,
              letterSpacing: "0.15em", textTransform: "uppercase",
              padding: "5px 10px", border: "1px solid var(--accent, #f97316)",
              color: "var(--accent, #f97316)", background: "transparent",
              cursor: "pointer", borderRadius: 2,
            }}
          >
            SAVE
          </button>
        </div>
      )}

      {!compact && state.reason && !showReason && (
        <div className="mono" style={{
          fontSize: 10.5, color: "var(--text-dim, #999)",
          fontStyle: "italic", opacity: 0.85,
        }} data-testid={`${testidPrefix}-reason-display`}>
          &laquo;{state.reason}&raquo;
        </div>
      )}
      {err && (
        <div className="mono" style={{ fontSize: 10, color: "var(--high, #f87171)" }}
             data-testid={`${testidPrefix}-error`}>
          {err}
        </div>
      )}
    </div>
  );
}
