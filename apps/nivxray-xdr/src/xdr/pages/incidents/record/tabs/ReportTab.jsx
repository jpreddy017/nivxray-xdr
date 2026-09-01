/**
 * Round 37 · Investigation Report tab.
 *
 * Four-section structured report:
 *   1. Executive Summary       — Auto + Analyst editable
 *   2. Technical Summary  🔒   — 100 % evidence-derived, read-only
 *   3. Supporting Evidence     — Auto cards + analyst notes
 *   4. Recommendations         — Auto + Analyst editable
 *
 * All content is composed by the backend Report service; the tab is
 * a thin renderer with add/edit/delete affordances for analyst
 * blocks in the three writable sections.
 */
import React, { useEffect, useState } from "react";
import { Loader2, Lock, Sparkles, Pencil, Plus, Trash2, X,
           FileText, Shield, ClipboardList, ListChecks } from "lucide-react";
import api from "@/lib/api";

const PROV_ICON = {
  lock:     { Icon: Lock,      color: "#64748b" },
  sparkle:  { Icon: Sparkles,  color: "#7c3aed" },
  pencil:   { Icon: Pencil,    color: "#0d9488" },
};

function ProvBadge({ label, icon, size = 10 }) {
  const P = PROV_ICON[icon] || PROV_ICON.sparkle;
  const Icon = P.Icon;
  return (
    <span style={{
             display: "inline-flex", alignItems: "center", gap: 4,
             fontSize: size, letterSpacing: 0.4,
             color: P.color, textTransform: "uppercase",
             fontWeight: 600, background: "#f8fafc",
             border: "1px solid #e2e8f0",
             borderRadius: 2, padding: "1px 6px",
           }}
           data-testid="xdr-report-prov-badge">
      <Icon size={size} /> {label}
    </span>
  );
}

function SectionHeader({ n, icon: Icon, title, subtitle, badge }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10,
                       marginBottom: 12 }}>
      <div style={{ background: "#0f172a", color: "#e2e8f0",
                        width: 34, height: 34, borderRadius: 4,
                        display: "flex", alignItems: "center",
                        justifyContent: "center", fontSize: 12,
                        fontWeight: 700 }}>
        {String(n).padStart(2, "0")}
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: "#0f172a",
                          textTransform: "uppercase", letterSpacing: 0.4,
                          display: "flex", alignItems: "center", gap: 6 }}>
          {Icon && <Icon size={14} />} {title}
        </div>
        <div style={{ fontSize: 11, color: "#64748b" }}>{subtitle}</div>
      </div>
      {badge}
    </div>
  );
}

// ── SYSTEM block card ─────────────────────────────────────────────
function SystemBlock({ block, onDelete }) {
  return (
    <div style={{
            border: "1px solid #e2e8f0", borderRadius: 4,
            background: "#fff", padding: 10, marginBottom: 8,
          }}
          data-testid={`xdr-report-block-${block.block_id}`}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8,
                          marginBottom: 4 }}>
        {block.title && (
          <div style={{ fontSize: 13, fontWeight: 700, color: "#0f172a" }}>
            {block.priority && (
              <span style={{ background: "#7c3aed", color: "#fff",
                                fontSize: 10, fontWeight: 700,
                                padding: "1px 6px", borderRadius: 2,
                                marginRight: 6 }}>
                {block.priority}
              </span>
            )}
            {block.title}
          </div>
        )}
        <div style={{ marginLeft: "auto" }}>
          <ProvBadge label={block.provenance}
                          icon={block.provenance_icon} />
        </div>
      </div>
      <div style={{ fontSize: 12, color: "#334155", whiteSpace: "pre-wrap",
                        lineHeight: 1.5 }}>
        {block.content}
      </div>
      {block.evidence_refs && block.evidence_refs.length > 0 && (
        <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap",
                            gap: 4 }}>
          {block.evidence_refs.map(r => (
            <span key={r} className="mono"
                   style={{ fontSize: 10, color: "#64748b",
                               background: "#f1f5f9", padding: "1px 5px",
                               borderRadius: 2 }}>
              {r}
            </span>
          ))}
        </div>
      )}
      {block.deletable && onDelete && (
        <button onClick={() => onDelete(block)}
                 title="Remove from report (does not touch canonical evidence)"
                 style={{ marginTop: 6, fontSize: 10, color: "#dc2626",
                             background: "transparent", border: 0,
                             cursor: "pointer", padding: 0 }}
                 data-testid={`xdr-report-block-remove-${block.block_id}`}>
          <Trash2 size={10} style={{ verticalAlign: "-1px", marginRight: 3 }} />
          Remove from report
        </button>
      )}
    </div>
  );
}

// ── ANALYST block card ────────────────────────────────────────────
function AnalystBlock({ block, onEdit, onDelete }) {
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(block.content);
  return (
    <div style={{
            border: "1px solid #14b8a6", borderRadius: 4,
            background: "#f0fdfa", padding: 10, marginBottom: 8,
          }}
          data-testid={`xdr-report-analyst-block-${block.block_id}`}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8,
                          marginBottom: 4 }}>
        {block.title && (
          <div style={{ fontSize: 13, fontWeight: 700, color: "#0f172a" }}>
            {block.priority && (
              <span style={{ background: "#14b8a6", color: "#fff",
                                fontSize: 10, fontWeight: 700,
                                padding: "1px 6px", borderRadius: 2,
                                marginRight: 6 }}>
                {block.priority}
              </span>
            )}
            {block.title}
          </div>
        )}
        <span style={{ fontSize: 10, color: "#64748b" }}>
          {block.author_email}
        </span>
        <div style={{ marginLeft: "auto" }}>
          <ProvBadge label={block.provenance}
                          icon={block.provenance_icon || "pencil"} />
        </div>
      </div>
      {editing ? (
        <div>
          <textarea value={text} onChange={e => setText(e.target.value)}
                       style={{ width: "100%", minHeight: 70,
                                   fontSize: 12, padding: 6,
                                   borderRadius: 3, border: "1px solid #14b8a6",
                                   background: "#fff",
                                   fontFamily: "inherit" }} />
          <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
            <button onClick={() => { onEdit(block, text); setEditing(false); }}
                     style={{ background: "#14b8a6", color: "#fff",
                                 border: 0, padding: "3px 10px", fontSize: 11,
                                 borderRadius: 2, cursor: "pointer" }}>
              Save
            </button>
            <button onClick={() => { setText(block.content); setEditing(false); }}
                     style={{ background: "transparent", color: "#64748b",
                                 border: 0, fontSize: 11, cursor: "pointer" }}>
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <div style={{ fontSize: 12, color: "#0f172a", whiteSpace: "pre-wrap",
                          lineHeight: 1.5 }}>
          {block.content}
        </div>
      )}
      {!editing && (
        <div style={{ marginTop: 6, display: "flex", gap: 10, fontSize: 10 }}>
          {block.editable && (
            <button onClick={() => setEditing(true)}
                     style={{ background: "transparent", border: 0,
                                 color: "#0d9488", cursor: "pointer", padding: 0 }}>
              <Pencil size={10} style={{ verticalAlign: "-1px", marginRight: 3 }} />
              Edit
            </button>
          )}
          {block.deletable && (
            <button onClick={() => onDelete(block)}
                     style={{ background: "transparent", border: 0,
                                 color: "#dc2626", cursor: "pointer", padding: 0 }}>
              <Trash2 size={10} style={{ verticalAlign: "-1px", marginRight: 3 }} />
              Delete
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ── Add-Block affordance ──────────────────────────────────────────
function AddBlock({ section, onAdd }) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  if (!open) {
    return (
      <button onClick={() => setOpen(true)}
               style={{ background: "transparent", color: "#7c3aed",
                           border: "1px dashed #7c3aed", borderRadius: 3,
                           padding: "5px 10px", fontSize: 11, cursor: "pointer",
                           marginTop: 4 }}
               data-testid={`xdr-report-add-${section}`}>
        <Plus size={11} style={{ verticalAlign: "-2px", marginRight: 4 }} />
        Add {section === "recommendations" ? "recommendation"
              : section === "supporting_evidence" ? "evidence"
              : "note"}
      </button>
    );
  }
  return (
    <div style={{ border: "1px solid #7c3aed", borderRadius: 4,
                       padding: 8, marginTop: 6, background: "#faf5ff" }}
          data-testid={`xdr-report-add-form-${section}`}>
      <input placeholder="Title (optional)" value={title}
              onChange={e => setTitle(e.target.value)}
              style={{ width: "100%", padding: "4px 6px", fontSize: 12,
                          border: "1px solid #c4b5fd", borderRadius: 2,
                          marginBottom: 6, background: "#fff" }} />
      <textarea placeholder="Analyst content…"
                    value={content} onChange={e => setContent(e.target.value)}
                    style={{ width: "100%", minHeight: 60, padding: 6,
                                fontSize: 12, border: "1px solid #c4b5fd",
                                borderRadius: 2, background: "#fff",
                                fontFamily: "inherit" }} />
      <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
        <button onClick={() => { onAdd({ title, content });
                                             setTitle(""); setContent("");
                                             setOpen(false); }}
                 disabled={!content.trim()}
                 style={{ background: "#7c3aed", color: "#fff",
                             border: 0, padding: "3px 10px", fontSize: 11,
                             borderRadius: 2,
                             cursor: content.trim() ? "pointer" : "not-allowed",
                             opacity: content.trim() ? 1 : 0.5 }}>
          Save
        </button>
        <button onClick={() => { setOpen(false); setTitle(""); setContent(""); }}
                 style={{ background: "transparent", color: "#64748b",
                             border: 0, fontSize: 11, cursor: "pointer" }}>
          Cancel
        </button>
      </div>
    </div>
  );
}


// ── Technical Summary renderer (structured, read-only) ────────────
function TechnicalSummary({ tech }) {
  if (!tech || !tech.groups || tech.groups.length === 0) {
    return (
      <div style={{ padding: 20, textAlign: "center", color: "#64748b",
                        fontSize: 12 }}
            data-testid="xdr-report-technical-empty">
        No evidence-derived technical facts available for this incident.
      </div>
    );
  }
  return (
    <div style={{
            background: "#fafbfc", border: "1px solid #e2e8f0",
            borderRadius: 4, padding: 12,
          }}
          data-testid="xdr-report-technical">
      {tech.groups.map(g => (
        <div key={g.name} style={{ marginBottom: 12 }}
              data-testid={`xdr-report-tech-group-${g.name.replace(/\s+/g, "-")}`}>
          <div style={{ fontSize: 12, fontWeight: 700, color: "#0f172a",
                            textTransform: "uppercase", letterSpacing: 0.4,
                            marginBottom: 4, borderBottom: "1px solid #e2e8f0",
                            paddingBottom: 3 }}>
            {g.name}
          </div>
          <table style={{ width: "100%", fontSize: 12 }}>
            <tbody>
              {g.rows.map((r, i) => (
                <tr key={i}>
                  <td style={{ color: "#64748b", padding: "2px 8px 2px 0",
                                    minWidth: 180, verticalAlign: "top" }}>
                    {r.label}
                  </td>
                  <td className="mono" style={{ color: "#0f172a",
                                                              wordBreak: "break-all",
                                                              padding: "2px 0" }}>
                    {String(r.value)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}


// ── The full tab ──────────────────────────────────────────────────
export default function ReportTab({ incident }) {
  const [report, setReport]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const analystEmail = incident?.assignee_email
                                 || incident?.user_email
                                 || "analyst@nivxray.local";

  const reload = async () => {
    if (!incident?.id) return;
    setLoading(true); setError(null);
    try {
      const { data } = await api.get(`/incidents/${incident.id}/report`);
      setReport(data);
    } catch (e) { setError(e?.message || String(e)); }
    finally { setLoading(false); }
  };

  useEffect(() => { reload(); }, [incident?.id]);   // eslint-disable-line

  const addBlock = async (section, { title, content, priority, kind }) => {
    if (!content?.trim()) return;
    await api.post(`/incidents/${incident.id}/report/blocks`,
                          { section, title, content, priority, kind,
                            author_email: analystEmail });
    await reload();
  };

  const editBlock = async (block, newContent) => {
    await api.patch(`/incidents/${incident.id}/report/blocks/${block.block_id}`,
                            { content: newContent, author_email: analystEmail });
    await reload();
  };

  const deleteBlock = async (block) => {
    await api.delete(`/incidents/${incident.id}/report/blocks/${block.block_id}`);
    await reload();
  };

  if (loading) return (
    <div className="rl-loading" data-testid="xdr-report-loading">
      <Loader2 size={12} className="rl-spin" style={{ verticalAlign: "-2px", marginRight: 6 }} />
      COMPOSING REPORT…
    </div>
  );
  if (error) return <div className="rl-error">{String(error)}</div>;
  if (!report) return null;

  const s = report.sections || {};
  const es = s.executive_summary || {};
  const ss = s.supporting_evidence || {};
  const rs = s.recommendations || {};

  return (
    <div style={{ padding: 16, background: "#fff", color: "#0f172a" }}
          data-testid="xdr-record-report">
      {/* Header */}
      <div style={{
              display: "flex", alignItems: "flex-start",
              justifyContent: "space-between",
              paddingBottom: 12, borderBottom: "2px solid #0f172a",
              marginBottom: 16,
            }}
            data-testid="xdr-report-header">
        <div>
          <div style={{ fontSize: 11, letterSpacing: 0.6,
                            color: "#64748b", textTransform: "uppercase",
                            fontWeight: 600 }}>
            NivXRay Investigation Report
          </div>
          <div style={{ fontSize: 20, fontWeight: 700, marginTop: 2 }}>
            {report.header?.title || report.incident_id}
          </div>
          <div style={{ display: "flex", gap: 12, marginTop: 4,
                             fontSize: 11, color: "#334155" }}>
            <span>Incident · <b>{report.incident_id}</b></span>
            {report.header?.host && <span>Host · <b>{report.header.host}</b></span>}
            {report.header?.detection && (
              <span>Detection · <b className="mono">{report.header.detection}</b></span>
            )}
            {report.header?.priority && (
              <span>Priority · <b>{report.header.priority}</b></span>
            )}
            {report.header?.verdict && (
              <span>Verdict · <b>{report.header.verdict}</b></span>
            )}
          </div>
        </div>
        <div style={{ fontSize: 10, color: "#64748b" }}>
          Generated {new Date(report.generated_at).toLocaleString()}
        </div>
      </div>

      {/* 1 · Executive Summary */}
      <div style={{ marginBottom: 32 }} data-testid="xdr-report-section-exec">
        <SectionHeader n={1} icon={FileText}
                              title="Executive Summary"
                              subtitle="System-generated assessment · Analyst editable"
                              badge={<ProvBadge label="Editable" icon="pencil" />} />
        {es.system_blocks?.map(b => (
          <SystemBlock key={b.block_id} block={b}
                              onDelete={b.deletable ? deleteBlock : undefined} />
        ))}
        {es.analyst_blocks?.map(b => (
          <AnalystBlock key={b.block_id} block={b}
                                 onEdit={editBlock} onDelete={deleteBlock} />
        ))}
        <AddBlock section="executive_summary"
                       onAdd={(x) => addBlock("executive_summary", x)} />
      </div>

      {/* 2 · Technical Summary — 100% evidence-derived */}
      <div style={{ marginBottom: 32 }} data-testid="xdr-report-section-tech">
        <SectionHeader n={2} icon={Shield}
                              title="Technical Summary"
                              subtitle="100% evidence-derived · Analyst read-only"
                              badge={<ProvBadge label="Evidence-derived · Read-only"
                                                       icon="lock" />} />
        <TechnicalSummary tech={s.technical_summary} />
      </div>

      {/* 3 · Supporting Evidence */}
      <div style={{ marginBottom: 32 }} data-testid="xdr-report-section-supp">
        <SectionHeader n={3} icon={ClipboardList}
                              title="Supporting Evidence"
                              subtitle="Evidence cards · Analyst notes"
                              badge={<ProvBadge label="Editable" icon="pencil" />} />
        <div style={{ fontSize: 11, color: "#64748b", fontWeight: 600,
                          textTransform: "uppercase", letterSpacing: 0.3,
                          marginBottom: 6 }}>
          NivXRay Evidence
        </div>
        {(ss.system_blocks || []).map(b => (
          <SystemBlock key={b.block_id} block={b}
                              onDelete={b.deletable ? deleteBlock : undefined} />
        ))}
        <div style={{ fontSize: 11, color: "#64748b", fontWeight: 600,
                          textTransform: "uppercase", letterSpacing: 0.3,
                          marginTop: 12, marginBottom: 6 }}>
          Analyst Notes
        </div>
        {(ss.analyst_blocks || []).map(b => (
          <AnalystBlock key={b.block_id} block={b}
                                 onEdit={editBlock} onDelete={deleteBlock} />
        ))}
        <AddBlock section="supporting_evidence"
                       onAdd={(x) => addBlock("supporting_evidence", x)} />
      </div>

      {/* 4 · Recommendations */}
      <div style={{ marginBottom: 32 }} data-testid="xdr-report-section-reco">
        <SectionHeader n={4} icon={ListChecks}
                              title="Recommendations"
                              subtitle="Auto-generated + analyst-authored"
                              badge={<ProvBadge label="Editable" icon="pencil" />} />
        <div style={{ fontSize: 11, color: "#64748b", fontWeight: 600,
                          textTransform: "uppercase", letterSpacing: 0.3,
                          marginBottom: 6 }}>
          NivXRay Recommendations
        </div>
        {(rs.system_blocks || []).map(b => (
          <SystemBlock key={b.block_id} block={b}
                              onDelete={b.deletable ? deleteBlock : undefined} />
        ))}
        <div style={{ fontSize: 11, color: "#64748b", fontWeight: 600,
                          textTransform: "uppercase", letterSpacing: 0.3,
                          marginTop: 12, marginBottom: 6 }}>
          Analyst Recommendations
        </div>
        {(rs.analyst_blocks || []).map(b => (
          <AnalystBlock key={b.block_id} block={b}
                                 onEdit={editBlock} onDelete={deleteBlock} />
        ))}
        <AddBlock section="recommendations"
                       onAdd={(x) => addBlock("recommendations", x)} />
      </div>

      {/* Provenance footnote */}
      <div style={{ fontSize: 10, color: "#64748b", textAlign: "center",
                        borderTop: "1px solid #e2e8f0", paddingTop: 8 }}>
        NivXRay Report Contract v1 · Analyst edits never modify canonical
        evidence · Technical Summary is 100 % evidence-derived.
      </div>
    </div>
  );
}
