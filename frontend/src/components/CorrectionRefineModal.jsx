/**
 * CorrectionRefineModal — lightweight "This is wrong / Teach NivXRay"
 * flow. Opens next to any wrong finding on any surface (Threat-Model,
 * Decode, Chain, IOC panel, MITRE table, LOLBAS row, family badge, risk
 * verdict, mitigation, detection, or free-form analyst note).
 *
 * Ships the correction to POST /api/corrections and (when auto_rerun is
 * true) calls the supplied onRerun() callback so the parent page can
 * immediately re-analyze with the correction applied.
 *
 * Props:
 *   open         — controlled visibility
 *   onClose()    — dismiss
 *   surface      — one of the 10 allowed surfaces (see backend)
 *   wrongFinding — {kind, value?, field?} — what's wrong
 *   inputText    — the original payload/diagram (for hash-key matching)
 *   defaultTags  — pre-filled tag chips
 *   onRerun()    — parent's re-analyze callback (fires after submit
 *                  when auto_rerun is checked)
 *
 * All buttons + selects carry data-testid values so the testing agent
 * can drive the flow.
 */
import { useState } from "react";
import { X, Send, ShieldCheck, Users, Globe, Lock } from "lucide-react";
import api from "../lib/api";

const SCOPES = [
  { id: "private", label: "Private", desc: "Only you see it", icon: Lock },
  { id: "team",    label: "Team",    desc: "Shared with all analysts (auto-approve)", icon: Users },
  { id: "global",  label: "Global",  desc: "Global — requires admin approval", icon: Globe },
];

const WRONGNESS_HINTS = {
  threat_model: ["Wrong MITRE mapping", "Missing threat", "Wrong asset type", "Wrong mitigation"],
  decode:       ["Wrong decode chain", "Missed encoding layer", "Wrong output"],
  chain:        ["Wrong stage ordering", "Missing stage", "Wrong per-stage engine"],
  ioc:          ["False positive URL/IP/domain", "Missing IOC", "Wrong IOC type"],
  lolbas:       ["Wrong LOLBIN attribution", "Missing LOLBIN"],
  family:       ["Wrong malware family", "Missing family"],
  risk:         ["Wrong verdict", "Wrong risk score"],
  detection:    ["Wrong detection rule", "Missing rule"],
  mitigation:   ["Wrong mitigation", "Missing mitigation"],
  note:         ["Wrong analyst note text"],
};


export default function CorrectionRefineModal({
  open, onClose,
  surface, wrongFinding = {}, inputText = "",
  defaultTags = [],
  onRerun,
}) {
  const [prompt, setPrompt]   = useState("");
  const [tags, setTags]       = useState((defaultTags || []).join(", "));
  const [scope, setScope]     = useState("team");
  const [autoRerun, setAutoRerun] = useState(true);
  const [busy, setBusy]       = useState(false);
  const [err, setErr]         = useState(null);
  const [ok, setOk]           = useState(null);

  if (!open) return null;

  const submit = async () => {
    if (!prompt.trim() || prompt.trim().length < 8) {
      setErr("Please provide a correction of at least 8 characters.");
      return;
    }
    setBusy(true); setErr(null);
    try {
      const tagList = tags.split(",").map((t) => t.trim().toLowerCase())
                        .filter(Boolean).slice(0, 10);
      const r = await api.post("/corrections", {
        surface, wrong_finding: wrongFinding,
        correct_prompt: prompt.trim(),
        tags: tagList, scope,
        input_text: inputText || undefined,
      });
      const d = r.data || {};
      const c = d.correction || {};
      setOk(`Saved · id=${c.id} · v${c.version} · status=${c.status} · conf=${c.confidence}`);
      if (autoRerun && typeof onRerun === "function") {
        try { await onRerun({ correctionId: c.id }); } catch {}
      }
      setTimeout(() => { onClose?.(); setOk(null); setPrompt(""); }, 1400);
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "Failed to save correction");
    } finally {
      setBusy(false);
    }
  };

  const hints = WRONGNESS_HINTS[surface] || [];

  return (
    <div
      data-testid="correction-refine-modal"
      style={{
        position: "fixed", inset: 0, zIndex: 200,
        background: "rgba(0,0,0,0.72)", backdropFilter: "blur(3px)",
        display: "flex", alignItems: "center", justifyContent: "center",
        padding: 20,
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose?.(); }}
    >
      <div style={{
        background: "var(--panel)", borderWidth: 1, borderStyle: "solid",
        borderColor: "var(--border)", borderRadius: 4, padding: 18,
        width: 520, maxWidth: "100%", color: "var(--text)",
        fontFamily: "JetBrains Mono",
      }}>
        <div style={{ display: "flex", justifyContent: "space-between",
                      alignItems: "center", marginBottom: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8,
                        color: "var(--warn)", letterSpacing: "0.20em",
                        fontSize: 11, fontWeight: 700 }}>
            <ShieldCheck size={13} /> TEACH NIVXRAY · REFINE FINDING
          </div>
          <button className="nvx-btn sm ghost" onClick={onClose}
                  data-testid="correction-modal-close">
            <X size={12} />
          </button>
        </div>

        {/* Context row */}
        <div style={{ fontSize: 10.5, color: "var(--text-mute)", marginBottom: 8 }}>
          <div>Surface: <span style={{ color: "var(--accent)" }}>{surface}</span></div>
          <div>Wrong finding: <span style={{ color: "var(--high)" }}>
            {wrongFinding?.kind || "?"}={String(wrongFinding?.value ?? "n/a")}
          </span></div>
          {hints.length > 0 && (
            <div style={{ marginTop: 4 }}>
              Common cases: <em style={{ color: "var(--text-dim)" }}>{hints.join(" · ")}</em>
            </div>
          )}
        </div>

        <label style={{ fontSize: 10, letterSpacing: "0.14em",
                        color: "var(--text-mute)", display: "block", marginTop: 8 }}>
          CORRECT INTERPRETATION
        </label>
        <textarea
          className="nvx-textarea"
          data-testid="correction-prompt-input"
          rows={5}
          placeholder="Explain the correct interpretation. Example: 'Redis is an in-memory cache, not an auth surface — map to T1005 instead of T1078.'"
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          style={{ fontSize: 11, minHeight: 90 }}
        />

        <div style={{ display: "flex", gap: 10, marginTop: 8 }}>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 10, letterSpacing: "0.14em", color: "var(--text-mute)" }}>
              TAGS (comma-separated)
            </label>
            <input
              className="nvx-textarea"
              data-testid="correction-tags-input"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="redis, cache, api-gateway"
              style={{ fontSize: 11, height: 32 }}
            />
          </div>
        </div>

        <label style={{ fontSize: 10, letterSpacing: "0.14em",
                        color: "var(--text-mute)", display: "block", marginTop: 10 }}>
          SCOPE
        </label>
        <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
          {SCOPES.map((s) => {
            const Icon = s.icon;
            const on = s.id === scope;
            return (
              <button
                key={s.id}
                type="button"
                data-testid={`correction-scope-${s.id}`}
                className={"nvx-btn sm " + (on ? "" : "ghost")}
                onClick={() => setScope(s.id)}
                style={{ flex: 1, padding: "5px 8px", fontSize: 10 }}
                title={s.desc}
              >
                <Icon size={10} /> {s.label}
              </button>
            );
          })}
        </div>

        <label style={{ display: "flex", alignItems: "center", gap: 6,
                        marginTop: 10, fontSize: 10.5, color: "var(--text-mute)" }}>
          <input
            type="checkbox"
            data-testid="correction-auto-rerun"
            checked={autoRerun}
            onChange={(e) => setAutoRerun(e.target.checked)}
          />
          Auto re-run analysis after saving (recommended)
        </label>

        {err && (
          <div data-testid="correction-error" style={{ marginTop: 8, padding: 6, fontSize: 10,
                        color: "var(--high)", background: "rgba(255,90,90,0.10)" }}>
            {String(err)}
          </div>
        )}
        {ok && (
          <div data-testid="correction-ok" style={{ marginTop: 8, padding: 6, fontSize: 10,
                        color: "var(--accent)", background: "rgba(74,168,144,0.10)" }}>
            {ok}
          </div>
        )}

        <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, marginTop: 12 }}>
          <button className="nvx-btn sm ghost" onClick={onClose}
                  data-testid="correction-cancel">CANCEL</button>
          <button className="nvx-btn sm" onClick={submit} disabled={busy}
                  data-testid="correction-submit">
            <Send size={11} /> {busy ? "SAVING…" : "SAVE CORRECTION"}
          </button>
        </div>
      </div>
    </div>
  );
}
