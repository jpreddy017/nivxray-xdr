/**
 * EvidenceModal — Phase A.5 · item 3.5 (Universal Evidence Drill-down).
 *
 * Owner-locked (2026-02-16): one shared evidence viewer reachable from
 * every analyst surface — Investigation Replay · Compare Cases ·
 * Confidence Provenance · Timeline · MITRE · Fingerprint · future
 * Attack Story. Reads exclusively from existing SSOT data — no backend
 * changes required.
 *
 * Descriptor shape (any subset is OK · nothing is required):
 *   {
 *     title,           source, rule_id, rule_description,
 *     contribution, weight, hit_count,
 *     artifact:      { type, sha256, size, name },
 *     analyzer:      "pe" | "office" | ...,
 *     recovered_child: { type, sha256, depth },
 *     mitre:         ["T1059.001", "T1027", ...],
 *     evidence_refs: [ { kind, code, provenance, ...} ],
 *     timeline_ref:  { kind, code, ts },
 *     related:       [ { kind, sha256, label } ],
 *     raw:           <any JSON>          // shown in the "Raw" tab
 *   }
 */
import { useEffect, useState } from "react";
import { X, ChevronRight } from "lucide-react";

const COL = {
  panel:  "#0f1a2c",  border: "#1f2b3f",
  muted:  "#94a3b8",  text:   "#e5e7eb",
  accent: "#38bdf8",  good:   "#86efac",
};

export function EvidenceModal({ descriptor, onClose }) {
  const [tab, setTab] = useState("chain");

  useEffect(() => {
    if (!descriptor) return;
    const h = (e) => { if (e.key === "Escape") onClose?.(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [descriptor, onClose]);

  if (!descriptor) return null;

  return (
    <div data-testid="evidence-modal"
         onClick={onClose}
         style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)",
                  zIndex: 999, display: "flex", justifyContent: "center",
                  alignItems: "center" }}>
      <div onClick={(e) => e.stopPropagation()}
           style={{ background: COL.panel, border: `1px solid ${COL.border}`,
                    borderRadius: 12, padding: 22, minWidth: 700,
                    maxWidth: 900, maxHeight: "82vh", overflowY: "auto",
                    color: COL.text }}>
        <ModalHeader d={descriptor} onClose={onClose} />
        <TabBar tab={tab} setTab={setTab} />
        {tab === "chain" && <EvidenceChain d={descriptor} />}
        {tab === "raw"   && <RawView       d={descriptor} />}
      </div>
    </div>
  );
}

function ModalHeader({ d, onClose }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between",
                  alignItems: "flex-start", marginBottom: 14 }}>
      <div>
        <div style={{ fontSize: 11, color: COL.muted, letterSpacing: "0.16em",
                      textTransform: "uppercase" }}>
          {d.source || "Evidence"}
        </div>
        <div data-testid="evidence-modal-title"
             style={{ fontSize: 18, marginTop: 3, fontWeight: 600 }}>
          {d.title || d.rule_id || "Evidence"}
        </div>
        {d.rule_description && (
          <div style={{ color: COL.muted, fontSize: 12, marginTop: 3,
                        maxWidth: 700 }}>{d.rule_description}</div>
        )}
      </div>
      <button data-testid="evidence-modal-close"
              onClick={onClose}
              style={{ background: "transparent", border: "none",
                       color: COL.muted, cursor: "pointer",
                       padding: 4 }}>
        <X size={20} />
      </button>
    </div>
  );
}

function TabBar({ tab, setTab }) {
  const btn = (id, label) => (
    <button data-testid={`evidence-modal-tab-${id}`}
            onClick={() => setTab(id)}
            style={{ background: "transparent",
                     color: tab === id ? COL.accent : COL.muted,
                     border: "none", borderBottom: tab === id
                                                 ? `2px solid ${COL.accent}`
                                                 : `2px solid transparent`,
                     padding: "6px 12px", fontSize: 13, cursor: "pointer",
                     fontWeight: tab === id ? 600 : 400 }}>
      {label}
    </button>
  );
  return (
    <div style={{ display: "flex", gap: 4, borderBottom: `1px solid ${COL.border}`,
                  marginBottom: 14 }}>
      {btn("chain", "Evidence Chain")}
      {btn("raw",   "Raw JSON")}
    </div>
  );
}

// ─── Evidence chain (link view) ─────────────────────────────────────
function EvidenceChain({ d }) {
  const rows = [
    d.rule_id && { label: "Rule", value: d.rule_id, sub: d.rule_description },
    d.contribution != null && {
      label: "Contribution",
      value: `+${d.contribution}`,
      sub: `weight ${d.weight ?? "—"} · ${d.hit_count ?? "—"} evidence hit(s)`,
    },
    d.evidence_refs?.length && {
      label: "Evidence Refs",
      value: `${d.evidence_refs.length} ref(s)`,
      children: d.evidence_refs.slice(0, 6).map((ref, i) => (
        <div key={i} style={{ fontFamily: "ui-monospace, monospace",
                              fontSize: 11, color: COL.muted,
                              marginTop: 4 }}>
          {JSON.stringify(ref)}
        </div>
      )),
    },
    d.artifact && {
      label: "Artifact",
      value: `${d.artifact.type ?? "artifact"}${
                d.artifact.size ? ` · ${d.artifact.size} bytes` : ""}`,
      sub: d.artifact.sha256
             ? `sha256 ${d.artifact.sha256}`
             : d.artifact.name,
    },
    d.analyzer && {
      label: "Analyzer",
      value: d.analyzer,
    },
    d.recovered_child && {
      label: "Recovered Child",
      value: `${d.recovered_child.type ?? "child"} · depth ${
                d.recovered_child.depth ?? "—"}`,
      sub: d.recovered_child.sha256
             ? `sha256 ${d.recovered_child.sha256}` : null,
    },
    d.mitre?.length && {
      label: "MITRE",
      value: d.mitre.join(" · "),
    },
    d.timeline_ref && {
      label: "Timeline",
      value: `${d.timeline_ref.kind ?? ""} · ${d.timeline_ref.code ?? ""}`,
      sub: d.timeline_ref.ts,
    },
    d.related?.length && {
      label: "Related",
      value: `${d.related.length} node(s)`,
      children: d.related.slice(0, 6).map((r, i) => (
        <div key={i} style={{ fontSize: 12, color: COL.muted, marginTop: 3 }}>
          <ChevronRight size={12} style={{ verticalAlign: "-2px",
                                            marginRight: 4 }} />
          {r.label || r.kind || "—"}{" "}
          {r.sha256 && (
            <span style={{ fontFamily: "ui-monospace, monospace",
                           color: COL.muted }}>
              · {r.sha256.slice(0, 16)}…
            </span>
          )}
        </div>
      )),
    },
  ].filter(Boolean);

  if (rows.length === 0) {
    return (
      <div style={{ color: COL.muted, fontSize: 13 }}>
        No structured evidence available for this item.
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {rows.map((row, i) => (
        <div key={i}
             data-testid={`evidence-row-${row.label.toLowerCase().replace(/\s+/g,"-")}`}
             style={{ display: "grid",
                      gridTemplateColumns: "170px 1fr",
                      gap: 12, padding: "10px 12px",
                      background: "#0a1526", borderRadius: 8,
                      border: `1px solid ${COL.border}` }}>
          <div style={{ fontSize: 11, color: COL.muted, letterSpacing: "0.14em",
                        textTransform: "uppercase", paddingTop: 2 }}>
            {row.label}
          </div>
          <div>
            <div style={{ fontFamily: "ui-monospace, monospace",
                          fontSize: 13, wordBreak: "break-all" }}>
              {row.value}
            </div>
            {row.sub && (
              <div style={{ color: COL.muted, fontSize: 11, marginTop: 3,
                            fontFamily: "ui-monospace, monospace",
                            wordBreak: "break-all" }}>{row.sub}</div>
            )}
            {row.children}
          </div>
        </div>
      ))}
    </div>
  );
}

function RawView({ d }) {
  const raw = d.raw ?? d;
  return (
    <pre data-testid="evidence-modal-raw"
         style={{ fontFamily: "ui-monospace, monospace", fontSize: 11,
                  background: "#0a1526", padding: 12, borderRadius: 8,
                  border: `1px solid ${COL.border}`, color: COL.text,
                  overflowX: "auto", whiteSpace: "pre-wrap",
                  wordBreak: "break-word" }}>
      {JSON.stringify(raw, null, 2)}
    </pre>
  );
}

// ─── Convenience hook — one-liner from any consumer ─────────────────
export function useEvidenceModal() {
  const [d, setD] = useState(null);
  return {
    open:  (descriptor) => setD(descriptor),
    close: () => setD(null),
    modal: <EvidenceModal descriptor={d} onClose={() => setD(null)} />,
  };
}

export default EvidenceModal;
