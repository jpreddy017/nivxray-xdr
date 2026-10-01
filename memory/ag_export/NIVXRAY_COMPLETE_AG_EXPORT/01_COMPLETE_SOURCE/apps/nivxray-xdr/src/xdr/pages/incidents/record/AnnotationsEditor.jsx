/**
 * Round 18.6 · AnnotationsEditor
 * ──────────────────────────────
 * Analyst overlay editor for the four incident-detail sections:
 *   executive · technical · supporting_evidence · recommendations
 *
 * Contract:
 *   · Analyst annotations NEVER rewrite deterministic composer prose
 *     or evidence-derived recommendations.  They are a parallel
 *     overlay stored in `xdr_analyst_annotations` with
 *     origin=ANALYST.
 *   · Every row surfaces its author + timestamp so the audit trail
 *     is visible directly in the UI.
 *   · Retire is soft-delete only.  The retired document persists in
 *     the audit trail — the analyst sees "retired" style.
 */
import React, { useState } from "react";
import { Pencil, Plus, X, Save, CheckCircle2, User } from "lucide-react";
import api from "@/lib/api";


const KIND_LABEL = {
  note:         "Note",
  finding:      "Finding",
  override:     "Override",
  custom_reco:  "Custom recommendation",
};


export default function AnnotationsEditor({
  incidentId, section, annotations, defaultKind = "finding",
  onChange, targetId = null, allowedKinds = null,
  compact = false,
}) {
  const [adding, setAdding]   = useState(false);
  const [draft,  setDraft]    = useState({ kind: defaultKind, text: "" });
  const [busy,   setBusy]     = useState(false);
  const [editing, setEditing] = useState(null);   // ann_id

  const kinds = allowedKinds || Object.keys(KIND_LABEL);

  const create = async () => {
    if (!draft.text.trim()) return;
    setBusy(true);
    try {
      const r = await api.post(
        `/admin/content-supply-chain/incidents/${incidentId}/annotations`,
        { section, kind: draft.kind, target_id: targetId,
          payload: { text: draft.text.trim() } });
      if (r.data.ok) {
        setDraft({ kind: defaultKind, text: "" });
        setAdding(false);
        onChange?.();
      }
    } finally { setBusy(false); }
  };

  const save = async (ann, text) => {
    setBusy(true);
    try {
      const r = await api.patch(
        `/admin/content-supply-chain/incidents/${incidentId}/annotations/${ann.id}`,
        { payload: { ...(ann.payload || {}), text } });
      if (r.data.ok) { setEditing(null); onChange?.(); }
    } finally { setBusy(false); }
  };

  const retire = async (ann) => {
    if (!window.confirm(
      "Retire this analyst finding? The document is preserved in the "
      + "audit trail but stops surfacing in the incident view."
    )) return;
    setBusy(true);
    try {
      const r = await api.delete(
        `/admin/content-supply-chain/incidents/${incidentId}/annotations/${ann.id}`,
        { data: { reason: "analyst retired" } });
      if (r.data.ok) onChange?.();
    } finally { setBusy(false); }
  };

  const filtered = (annotations || []).filter(a =>
    !targetId ? !a.target_id : a.target_id === targetId);

  return (
    <div data-testid={`ann-editor-${section}${targetId ? "-" + targetId : ""}`}
              style={{ marginTop: compact ? 4 : 10 }}>
      {filtered.length > 0 && (
        <div style={{ borderLeft: "2px solid #a78bfa",
                            paddingLeft: 8, marginBottom: 6 }}>
          {filtered.map((a) => (
            <AnnRow key={a.id} a={a}
                          editing={editing === a.id}
                          onEdit={() => setEditing(a.id)}
                          onCancel={() => setEditing(null)}
                          onSave={(t) => save(a, t)}
                          onRetire={() => retire(a)}
                          busy={busy} />
          ))}
        </div>
      )}

      {!adding && (
        <button data-testid={`ann-add-${section}${targetId ? "-" + targetId : ""}`}
                    onClick={() => setAdding(true)}
                    style={btnAdd}>
          <Plus size={11} /> Add analyst {defaultKind === "custom_reco"
            ? "recommendation" : (defaultKind === "override"
              ? "override" : "finding")}
        </button>
      )}
      {adding && (
        <div style={{ marginTop: 4, padding: 6,
                            border: "1px solid #a78bfa",
                            borderRadius: 3,
                            background: "rgba(167,139,250,0.05)" }}>
          <div style={{ display: "flex", gap: 6, marginBottom: 4,
                              alignItems: "center" }}>
            <label style={lbl}>KIND</label>
            <select value={draft.kind}
                        onChange={(e) => setDraft({...draft, kind: e.target.value})}
                        data-testid={`ann-kind-${section}`}
                        style={inp}>
              {kinds.map(k => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}
            </select>
          </div>
          <textarea data-testid={`ann-text-${section}`}
                          value={draft.text}
                          onChange={(e) => setDraft({...draft, text: e.target.value})}
                          rows={compact ? 2 : 3}
                          placeholder="Analyst finding (evidence-backed reasoning)…"
                          style={{...inp, width: "100%", resize: "vertical",
                                        fontFamily: "var(--sans)", fontSize: 12}} />
          <div style={{ marginTop: 4, display: "flex", gap: 6 }}>
            <button data-testid={`ann-save-${section}`}
                        onClick={create} disabled={busy || !draft.text.trim()}
                        style={btnPrimary}>
              <Save size={11} /> Save
            </button>
            <button onClick={() => { setAdding(false);
                                                    setDraft({ kind: defaultKind,
                                                                     text: "" }); }}
                        style={btnGhost}>
              <X size={11} /> Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}


function AnnRow({ a, editing, onEdit, onCancel, onSave, onRetire, busy }) {
  const [text, setText] = useState(a.payload?.text || "");
  if (editing) {
    return (
      <div data-testid={`ann-editing-${a.id}`}
                style={{ padding: 6, marginBottom: 6,
                                border: "1px solid #a78bfa", borderRadius: 3 }}>
        <textarea value={text}
                        onChange={(e) => setText(e.target.value)}
                        rows={3}
                        style={{...inp, width: "100%", resize: "vertical",
                                        fontFamily: "var(--sans)", fontSize: 12}} />
        <div style={{ marginTop: 4, display: "flex", gap: 6 }}>
          <button onClick={() => onSave(text)}
                        disabled={busy || !text.trim()}
                        style={btnPrimary}
                        data-testid={`ann-save-edit-${a.id}`}>
            <Save size={11} /> Save
          </button>
          <button onClick={onCancel} style={btnGhost}>
            <X size={11} /> Cancel
          </button>
        </div>
      </div>
    );
  }
  return (
    <div data-testid={`ann-row-${a.id}`}
              style={{ padding: "4px 0", display: "flex", gap: 8,
                              alignItems: "flex-start", fontSize: 12,
                              color: "var(--text-dim)", lineHeight: 1.5 }}>
      <span style={{ display: "inline-flex", alignItems: "center",
                          gap: 3, padding: "1px 6px", borderRadius: 2,
                          background: "rgba(167,139,250,0.15)",
                          border: "1px solid #a78bfa",
                          color: "#a78bfa", fontFamily: "var(--mono)",
                          fontSize: 9, fontWeight: 700,
                          whiteSpace: "nowrap" }}>
        <User size={8} /> ANALYST · {(KIND_LABEL[a.kind] || a.kind).toUpperCase()}
      </span>
      <div style={{ flex: 1 }}>
        <div>{a.payload?.text || "—"}</div>
        <div style={{ fontFamily: "var(--mono)", fontSize: 10,
                            color: "var(--faint)", marginTop: 2 }}>
          {a.author} · {a.updated_at?.slice(0, 19).replace("T", " ")}
          {a.history?.length ? ` · edited ${a.history.length}×` : ""}
        </div>
      </div>
      <button onClick={onEdit} style={btnIcon}
                    data-testid={`ann-edit-${a.id}`}
                    title="Edit">
        <Pencil size={10} />
      </button>
      <button onClick={onRetire} style={btnIcon}
                    data-testid={`ann-retire-${a.id}`}
                    title="Retire">
        <X size={10} />
      </button>
    </div>
  );
}


const inp = {
  padding: "2px 6px", fontFamily: "var(--mono)", fontSize: 11,
  background: "var(--panel)", color: "var(--text)",
  border: "1px solid var(--border)", borderRadius: 2,
};
const lbl = { fontFamily: "var(--mono)", fontSize: 10,
                    color: "var(--faint)", fontWeight: 700 };
const btnAdd = {
  padding: "3px 8px", fontSize: 10, fontFamily: "var(--mono)",
  color: "#a78bfa", background: "transparent",
  border: "1px dashed #a78bfa", borderRadius: 2, cursor: "pointer",
  display: "inline-flex", alignItems: "center", gap: 4,
};
const btnPrimary = {
  padding: "3px 10px", fontSize: 10, fontFamily: "var(--mono)",
  color: "var(--mint)", background: "transparent",
  border: "1px solid var(--mint)", borderRadius: 2, cursor: "pointer",
  display: "inline-flex", alignItems: "center", gap: 4,
};
const btnGhost = {
  padding: "3px 10px", fontSize: 10, fontFamily: "var(--mono)",
  color: "var(--faint)", background: "transparent",
  border: "1px solid var(--border)", borderRadius: 2, cursor: "pointer",
  display: "inline-flex", alignItems: "center", gap: 4,
};
const btnIcon = {
  padding: "2px 4px", background: "transparent",
  border: "none", color: "var(--faint)", cursor: "pointer",
};
