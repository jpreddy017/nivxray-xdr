/**
 * NotesTab · Layer 3 · analyst notes surface.
 *
 * No incident-scoped notes API exists yet; notes/attachments are on
 * the Phase-3 lifecycle roadmap.  This tab renders an honest empty
 * state today with a working local draft composer so analysts can
 * still capture context, and clearly signals when the backend contract
 * lands the drafts will be posted through the real API.
 *
 * We keep drafts in localStorage per-incident so an analyst doesn't
 * lose work on refresh — this is UI-only and never claims to be a
 * persisted note.
 */
import React, { useEffect, useState } from "react";
import { Send } from "lucide-react";

const key = (id) => `xdr.record.notes.draft.${id}`;

export default function NotesTab({ incident }) {
  const iid = incident?.id;
  const [draft, setDraft] = useState("");
  const [savedAt, setSavedAt] = useState(null);

  useEffect(() => {
    if (!iid) return;
    try { setDraft(localStorage.getItem(key(iid)) || ""); } catch (_) { /* noop */ }
  }, [iid]);

  const save = () => {
    try {
      localStorage.setItem(key(iid), draft);
      setSavedAt(new Date().toLocaleTimeString());
    } catch (_) { /* noop */ }
  };

  return (
    <div data-testid="xdr-record-notes">
      <div className="rl-section">
        <div className="rl-section-title">Analyst notes</div>
        <div className="rl-empty" data-testid="xdr-record-notes-empty">
          NOT AVAILABLE — an incident-scoped notes API arrives with
          the Phase-3 lifecycle engine.  Use the draft composer below
          to capture context; drafts are stored locally in your browser
          until the API is wired up.
          <span className="kbd">/api/incidents/:id/notes · reserved · Phase 3</span>
        </div>
      </div>

      <div className="rl-section">
        <div className="rl-section-title">Local draft (stored in your browser)</div>
        <textarea
          className="rl-note-input"
          placeholder="Write triage context, hypotheses, next steps…"
          value={draft}
          onChange={e => setDraft(e.target.value)}
          data-testid="xdr-record-notes-textarea"
        />
        <div style={{ display: "flex", alignItems: "center", gap: 12,
                        marginTop: 8, fontSize: 11, color: "var(--rl-muted)" }}>
          <button
            type="button"
            className="rl-btn primary"
            onClick={save}
            disabled={!draft.trim()}
            data-testid="xdr-record-notes-save-draft"
          >
            <Send size={12} /> Save draft locally
          </button>
          {savedAt && (
            <span data-testid="xdr-record-notes-saved-at">
              Draft saved at {savedAt}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
