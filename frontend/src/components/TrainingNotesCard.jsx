import { useEffect, useState } from "react";
import api from "@/lib/api";
import { Plus, Trash2, Check, X, Save, GraduationCap, Sparkles } from "lucide-react";

/**
 * TrainingNotesCard
 * -----------------
 * Admin-page quick-add + inline list for GLOBAL TRAINING NOTES.
 *
 * Backed by the `admin_models` collection with `kind=training_note`.
 * Notes marked `enabled=true` are PREPENDED to every AI investigation
 * system prompt (above playbooks) via `compose_playbook_prompt_with_meta`
 * on the backend. Feedback-weighted — analyst 👍/👎 votes reorder priority
 * for future prompts.
 */
export default function TrainingNotesCard() {
  const [notes, setNotes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [body, setBody] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const r = await api.get("/admin/models?kind=training_note");
      setNotes(r.data || []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const create = async () => {
    if (!name.trim() || !body.trim()) {
      setSaveMsg("ERROR: title and body are required");
      return;
    }
    setSaving(true);
    setSaveMsg("");
    try {
      await api.post("/admin/models", {
        kind: "training_note",
        name: name.trim(),
        enabled: true,
        config: { body: body.trim() },
      });
      setSaveMsg("Saved · will be prepended to next AI investigation");
      setName("");
      setBody("");
      await load();
    } catch (e) {
      setSaveMsg("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setSaving(false);
    }
  };

  const toggle = async (n) => {
    await api.put(`/admin/models/${n.id}`, { enabled: !n.enabled });
    await load();
  };

  const remove = async (n) => {
    if (!window.confirm(`Delete training note "${n.name}"?`)) return;
    await api.delete(`/admin/models/${n.id}`);
    await load();
  };

  return (
    <section className="brut-border" style={{ background: "var(--surface)" }} data-testid="training-notes-card">
      {/* Header */}
      <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <GraduationCap size={16} style={{ color: "#7ee3c9" }} />
        <div style={{ flex: 1 }}>
          <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "#7ee3c9" }}>
            ▸ AI TRAINING NOTES
          </div>
          <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 4, lineHeight: 1.5 }}>
            Always-on global directives PREPENDED to every AI investigation. Feedback-weighted — 👍/👎 on
            any investigation adjusts a note&apos;s priority for future prompts. No fine-tuning required.
          </div>
        </div>
        <span className="mono" style={{ fontSize: 10, color: "var(--text-mute)", padding: "3px 8px", border: "1px solid var(--border)" }}>
          {notes.filter((n) => n.enabled).length} ACTIVE · {notes.length} TOTAL
        </span>
      </div>

      {/* Quick-add form */}
      <div style={{ padding: 16, borderBottom: "1px solid var(--border)" }}>
        <div className="mono" style={{ fontSize: 10, letterSpacing: "0.16em", color: "var(--text-mute)", marginBottom: 4, textTransform: "uppercase" }}>
          Title
        </div>
        <input
          className="brut-input"
          style={{ width: "100%", fontFamily: "JetBrains Mono, monospace", fontSize: 12, marginBottom: 10 }}
          placeholder="e.g. Defang all URLs · Treat T1218.011 as critical · Cite decoded evidence"
          value={name}
          onChange={(e) => setName(e.target.value)}
          data-testid="training-note-title-input"
        />
        <div className="mono" style={{ fontSize: 10, letterSpacing: "0.16em", color: "var(--text-mute)", marginBottom: 4, textTransform: "uppercase" }}>
          Directive
        </div>
        <textarea
          className="brut-input"
          style={{ width: "100%", minHeight: 120, fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}
          placeholder={"E.g.:\n- ALWAYS defang URLs in the final report (hxxp:// instead of http://)\n- Prioritize the shellcode disassembly in the verdict when a Cobalt Strike stager is detected\n- Never claim a payload is benign without at least one decoded layer of evidence\n- Our SOC treats T1218.011 rundll32 as CRITICAL even without a network IOC"}
          value={body}
          onChange={(e) => setBody(e.target.value)}
          data-testid="training-note-body-input"
        />
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 10, gap: 8, flexWrap: "wrap" }}>
          <div className="mono" style={{ fontSize: 10, color: saveMsg.startsWith("ERROR") ? "var(--high)" : "var(--accent)" }} data-testid="training-note-save-msg">
            {saveMsg}
          </div>
          <button
            className="nvx-btn primary"
            onClick={create}
            disabled={saving || !name.trim() || !body.trim()}
            data-testid="training-note-save-btn"
          >
            <Save size={12} /> {saving ? "SAVING…" : "SAVE & ACTIVATE"}
          </button>
        </div>
      </div>

      {/* Existing notes list */}
      <div style={{ padding: 12 }}>
        {loading ? (
          <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", padding: 10 }}>Loading…</div>
        ) : notes.length === 0 ? (
          <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", padding: 10 }}>
            No training notes yet. Paste your first directive above.
          </div>
        ) : (
          <div style={{ display: "grid", gap: 8 }}>
            {notes.map((n) => (
              <div
                key={n.id}
                className="brut-border"
                style={{ padding: 12, background: "var(--bg)", opacity: n.enabled ? 1 : 0.55 }}
                data-testid={`training-note-row-${n.id}`}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 10, marginBottom: 6 }}>
                  <div style={{ flex: 1 }}>
                    <div className="mono" style={{ fontSize: 12, color: "var(--text)", fontWeight: 600, letterSpacing: "0.02em" }}>
                      {n.name}
                    </div>
                    <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 4, lineHeight: 1.6, whiteSpace: "pre-wrap" }}>
                      {(n.config?.body || "").slice(0, 260)}
                      {(n.config?.body || "").length > 260 ? "…" : ""}
                    </div>
                    <div className="mono" style={{ fontSize: 9, color: "var(--text-mute)", marginTop: 6, letterSpacing: "0.08em" }}>
                      <Sparkles size={9} style={{ verticalAlign: "middle", marginRight: 4 }} />
                      WEIGHT {n.feedback_weight ?? 0} · 👍 {n.feedback_pos ?? 0} · 👎 {n.feedback_neg ?? 0} · USED {n.usage_count ?? 0}×
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button
                      className={`nvx-btn ${n.enabled ? "primary" : "ghost"}`}
                      onClick={() => toggle(n)}
                      title={n.enabled ? "Disable" : "Enable"}
                      data-testid={`training-note-toggle-${n.id}`}
                    >
                      {n.enabled ? <Check size={11} /> : <X size={11} />}
                    </button>
                    <button
                      className="nvx-btn ghost"
                      onClick={() => remove(n)}
                      title="Delete"
                      data-testid={`training-note-delete-${n.id}`}
                    >
                      <Trash2 size={11} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
