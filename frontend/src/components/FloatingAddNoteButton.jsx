import { useState } from "react";
import { useAuth } from "@/lib/auth";
import { useLocation } from "react-router-dom";
import api from "@/lib/api";
import { GraduationCap, X, Save } from "lucide-react";

/**
 * FloatingAddNoteButton
 * ---------------------
 * Global floating button (bottom-right) visible on every authenticated page.
 * Opens a lightweight modal that creates a new global training note via
 * `POST /admin/models` with `kind=training_note`. Admin-only.
 *
 * Suppressed on /login (unauthenticated) and non-admin roles.
 */
export default function FloatingAddNoteButton() {
  const { user } = useAuth();
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [body, setBody] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  if (!user || user.role !== "admin") return null;
  if (pathname === "/login") return null;

  const save = async () => {
    if (!name.trim() || !body.trim()) {
      setError("Both title and body are required");
      return;
    }
    setSaving(true);
    setError("");
    try {
      await api.post("/admin/models", {
        kind: "training_note",
        name: name.trim(),
        enabled: true,
        config: { body: body.trim() },
      });
      setName("");
      setBody("");
      setOpen(false);
    } catch (e) {
      setError(e?.response?.data?.detail || e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      {/* Floating trigger */}
      <button
        onClick={() => setOpen(true)}
        className="nvx-btn primary"
        style={{
          position: "fixed",
          right: 24,
          bottom: 24,
          zIndex: 60,
          padding: "12px 18px",
          borderRadius: 0,
          boxShadow: "0 6px 20px rgba(0,0,0,0.35)",
          fontSize: 12,
          letterSpacing: "0.14em",
        }}
        title="Add global AI training note (always-on directive)"
        data-testid="floating-add-training-note-btn"
      >
        <GraduationCap size={13} /> + TRAINING NOTE
      </button>

      {/* Modal */}
      {open && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 100,
            background: "rgba(0,0,0,0.65)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 20,
          }}
          onClick={(e) => { if (e.target === e.currentTarget) setOpen(false); }}
          data-testid="training-note-modal-backdrop"
        >
          <div
            className="brut-border"
            style={{ width: "100%", maxWidth: 640, background: "var(--surface)", padding: 20 }}
            data-testid="training-note-modal"
          >
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <GraduationCap size={16} style={{ color: "#7ee3c9" }} />
                <div>
                  <div className="mono" style={{ fontSize: 12, letterSpacing: "0.2em", color: "#7ee3c9" }}>
                    NEW TRAINING NOTE
                  </div>
                  <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 2 }}>
                    Prepended to every AI investigation · feedback-weighted
                  </div>
                </div>
              </div>
              <button className="nvx-btn ghost" onClick={() => setOpen(false)} data-testid="training-note-modal-close">
                <X size={12} />
              </button>
            </div>

            {/* Fields */}
            <div className="mono" style={{ fontSize: 10, letterSpacing: "0.16em", color: "var(--text-mute)", marginBottom: 4, textTransform: "uppercase" }}>
              Title
            </div>
            <input
              className="brut-input"
              style={{ width: "100%", fontFamily: "JetBrains Mono, monospace", fontSize: 12, marginBottom: 12 }}
              placeholder="e.g. Defang all URLs · Cite decoded evidence"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
              data-testid="floating-training-note-title"
            />

            <div className="mono" style={{ fontSize: 10, letterSpacing: "0.16em", color: "var(--text-mute)", marginBottom: 4, textTransform: "uppercase" }}>
              Directive
            </div>
            <textarea
              className="brut-input"
              style={{ width: "100%", minHeight: 160, fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}
              placeholder={"E.g.:\n- ALWAYS defang URLs (hxxp://) in the final report\n- Never claim a payload is benign without decoded evidence\n- Treat T1218.011 rundll32 as CRITICAL even without a network IOC"}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              data-testid="floating-training-note-body"
            />

            {/* Footer */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 14, gap: 8 }}>
              <div className="mono" style={{ fontSize: 10, color: "var(--high)" }} data-testid="floating-training-note-error">
                {error}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="nvx-btn ghost" onClick={() => setOpen(false)}>
                  CANCEL
                </button>
                <button
                  className="nvx-btn primary"
                  onClick={save}
                  disabled={saving || !name.trim() || !body.trim()}
                  data-testid="floating-training-note-save"
                >
                  <Save size={12} /> {saving ? "SAVING…" : "SAVE & ACTIVATE"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
