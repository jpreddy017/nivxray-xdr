/**
 * NotesTab · analyst notes.
 *
 * There is no incident-scoped notes API in this build, so this tab
 * captures a LOCAL draft and says so plainly. It never claims a note was
 * persisted to the platform, and the reserved API path is shown as a code
 * token on its own line rather than trailing a sentence off the viewport.
 *
 * Rebuilt on `xdr/nx` form primitives: the legacy `rl-*` classes it used
 * have no stylesheet on these routes, so labels rendered as naked text,
 * the composer collapsed to a few characters wide and muted colours
 * resolved to nothing.
 */
import React, { useEffect, useState } from "react";
import { Info, Save } from "lucide-react";

import { ABSENCE } from "@/xdr/nx";
import "@/xdr/nx/nx-form.css";

const key = (id) => `xdr.record.notes.draft.${id}`;

export default function NotesTab({ incident }) {
  const iid = incident?.id;
  const [draft, setDraft] = useState("");
  const [savedAt, setSavedAt] = useState(null);

  useEffect(() => {
    if (!iid) return;
    try { setDraft(localStorage.getItem(key(iid)) || ""); } catch { /* noop */ }
    setSavedAt(null);
  }, [iid]);

  const save = () => {
    try {
      localStorage.setItem(key(iid), draft);
      setSavedAt(new Date().toLocaleTimeString());
    } catch { /* noop */ }
  };

  return (
    <div data-testid="xdr-record-notes">
      <div className="nx-alert" data-testid="xdr-record-notes-empty"
           style={{ marginTop: 12 }}>
        <Info size={13} style={{ flex: "0 0 auto", marginTop: 2 }} />
        <span>
          <b>{ABSENCE.NOT_AVAILABLE}</b> — this platform has no incident-scoped
          notes API, so nothing you write here is stored on the platform. The
          composer below keeps a draft in <b>your browser only</b> so triage
          context is not lost on refresh.
          <div style={{ marginTop: 6 }}>
            <span className="nx-code">/api/incidents/:id/notes</span>
            {" "}
            <span className="nx-help">reserved · Phase 3 lifecycle engine</span>
          </div>
        </span>
      </div>

      <div className="nx-form">
        <div className="nx-field nx-field--wide">
          <label className="nx-label" htmlFor="xdr-notes-draft">
            Local draft · stored in your browser
          </label>
          <textarea id="xdr-notes-draft" className="nx-textarea"
                    placeholder="Triage context, hypotheses, what you checked, what to do next…"
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    data-testid="xdr-record-notes-textarea" />
          <span className="nx-help">
            A draft is not a note. It is not attributed, not audited and not
            visible to anyone else — it disappears if this browser profile is
            cleared.
          </span>
        </div>
      </div>

      <div className="nx-actions" style={{ paddingTop: 0 }}>
        <button type="button" className="nx-btn nx-btn--primary"
                onClick={save} disabled={!draft.trim()}
                data-testid="xdr-record-notes-save-draft">
          <Save size={12} /> Save draft locally
        </button>
        {savedAt && (
          <span className="nx-help" data-testid="xdr-record-notes-saved-at">
            Draft saved at {savedAt}
          </span>
        )}
      </div>
    </div>
  );
}
