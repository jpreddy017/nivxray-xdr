/**
 * ADR-0009 · <CIMInvestigation>
 *
 * Read-only rendering of the Canonical Investigation Model (the
 * `investigation` field on `/api/decode/smart` and `/api/v2/auto-investigate`
 * responses). Renders 11 sections top-to-bottom per ADR-0009 §2.5:
 *
 *   1. Executive
 *   2. Stages Executed (adaptive-pipeline transparency)
 *   3. Assessments
 *   4. Evidence
 *   5. Timeline
 *   6. Entities
 *   7. Relationships
 *   8. Threat Intel
 *   9. ATT&CK
 *  10. Decode Chain
 *  11. Unknowns  · deterministically generated data-gap list
 *      Recommendations (rendered inline with unknowns)
 */
import React from "react";
import CIMSection from "./CIMSection";

const S = {
  wrap: { marginTop: 12 },
  row: { display: "flex", flexWrap: "wrap", gap: 10 },
  metric: {
    minWidth: 160, padding: "10px 12px",
    background: "var(--bg, #020617)", border: "1px solid var(--border, #1e293b)",
    borderRadius: 6,
  },
  metricLabel: {
    fontSize: 10, letterSpacing: "0.2em", textTransform: "uppercase",
    color: "var(--text-secondary, #94a3b8)", fontFamily: "ui-monospace",
  },
  metricValue: {
    fontSize: 16, marginTop: 4, fontWeight: 700, color: "var(--text, #e2e8f0)",
    fontFamily: "ui-monospace",
  },
  chip: {
    display: "inline-flex", alignItems: "center", gap: 6, padding: "3px 8px",
    borderRadius: 10, fontSize: 11, border: "1px solid var(--border, #1e293b)",
    color: "var(--text, #e2e8f0)", fontFamily: "ui-monospace",
  },
  chipOK: { borderColor: "rgba(34,197,94,0.5)", color: "#4ade80" },
  chipSkip: { borderColor: "rgba(148,163,184,0.5)", color: "#94a3b8" },
  chipFail: { borderColor: "rgba(248,113,113,0.6)", color: "#f87171" },
  row2: { display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 },
  bullet: {
    padding: "6px 0", borderTop: "1px solid var(--border, #1e293b)",
    color: "var(--text, #e2e8f0)", fontFamily: "ui-monospace", fontSize: 12,
    display: "flex", justifyContent: "space-between", gap: 12,
  },
  bulletMeta: { color: "var(--text-secondary, #94a3b8)", fontSize: 11 },
  confidence: {
    display: "inline-block", padding: "1px 6px", borderRadius: 8, fontSize: 10,
    letterSpacing: "0.08em", textTransform: "uppercase",
    border: "1px solid var(--border, #1e293b)", color: "var(--text-secondary, #94a3b8)",
    fontFamily: "ui-monospace", marginLeft: 6,
  },
  code: {
    background: "var(--bg, #020617)", border: "1px solid var(--border, #1e293b)",
    borderRadius: 4, padding: "1px 5px", fontFamily: "ui-monospace", fontSize: 11,
    color: "var(--accent, #7dd3fc)",
  },
};

const CONFIDENCE_COLOR = {
  Confirmed: "#4ade80",
  "Strongly Inferred": "#7dd3fc",
  Possible: "#fbbf24",
  Unknown: "#94a3b8",
};

function ConfidenceBadge({ value }) {
  const color = CONFIDENCE_COLOR[value] || "#94a3b8";
  return (
    <span
      style={{ ...S.confidence, borderColor: color, color }}
      data-testid="cim-confidence-badge"
    >
      {value || "Unknown"}
    </span>
  );
}

function stageChipStyle(status) {
  if (status === "completed") return { ...S.chip, ...S.chipOK };
  if (status === "skipped") return { ...S.chip, ...S.chipSkip };
  return { ...S.chip, ...S.chipFail };
}

function stageSymbol(status) {
  if (status === "completed") return "✓";
  if (status === "skipped") return "skipped";
  if (status === "failed") return "✗";
  return "!";
}

export function CIMInvestigation({ investigation }) {
  if (!investigation) return null;
  const inv = investigation;

  return (
    <div style={S.wrap} data-testid="cim-investigation">
      {/* 1 · EXECUTIVE */}
      <CIMSection kind="executive" title="Executive · Headline">
        <div style={S.row}>
          <div style={S.metric} data-testid="cim-executive-verdict">
            <div style={S.metricLabel}>Verdict</div>
            <div style={S.metricValue}>{inv.executive?.verdict || "—"}</div>
            <ConfidenceBadge value={inv.executive?.confidence} />
          </div>
          {inv.executive?.family && (
            <div style={S.metric} data-testid="cim-executive-family">
              <div style={S.metricLabel}>Family</div>
              <div style={S.metricValue}>{inv.executive.family}</div>
            </div>
          )}
          {inv.executive?.category && (
            <div style={S.metric} data-testid="cim-executive-category">
              <div style={S.metricLabel}>Category</div>
              <div style={S.metricValue}>{inv.executive.category}</div>
            </div>
          )}
          {inv.executive?.evidence_quality && (
            <div style={S.metric} data-testid="cim-executive-evidence-quality">
              <div style={S.metricLabel}>Evidence Quality</div>
              <div style={S.metricValue}>{inv.executive.evidence_quality}</div>
            </div>
          )}
        </div>
        {inv.executive?.summary && (
          <div
            style={{ marginTop: 12, color: "var(--text, #e2e8f0)", fontSize: 13, lineHeight: 1.5 }}
            data-testid="cim-executive-summary"
          >
            {inv.executive.summary}
          </div>
        )}
      </CIMSection>

      {/* 2 · STAGES EXECUTED */}
      <CIMSection
        kind="stages"
        title="Stages Executed · Adaptive Pipeline"
        count={`${(inv.stages_executed || []).length} stage(s)`}
        isEmpty={!inv.stages_executed?.length}
        emptyText="No stages recorded."
      >
        <div style={S.row2}>
          {(inv.stages_executed || []).map((st, i) => (
            <span
              key={`${st.name}-${i}`}
              style={stageChipStyle(st.status)}
              data-testid={`cim-stage-${st.name}`}
            >
              {stageSymbol(st.status)} · {st.name}
              {st.reason && <span style={S.bulletMeta}> · {st.reason}</span>}
            </span>
          ))}
        </div>
      </CIMSection>

      {/* 3 · ASSESSMENTS */}
      <CIMSection
        kind="assessments"
        title="Assessments · Every conclusion is evidence-backed"
        count={`${(inv.assessments || []).length} assessment(s)`}
        isEmpty={!inv.assessments?.length}
        emptyText="No assessments produced."
      >
        {(inv.assessments || []).map((a) => (
          <div key={a.id} style={S.bullet} data-testid={`cim-assessment-${a.id}`}>
            <div>
              <span style={S.code}>{a.id}</span>{" "}
              <strong>{a.statement}</strong>
              <ConfidenceBadge value={a.confidence} />
              {a.rationale && (
                <div style={{ ...S.bulletMeta, marginTop: 4 }}>{a.rationale}</div>
              )}
            </div>
            <div style={S.bulletMeta}>
              {(a.evidence || []).map((e) => (
                <span key={e} style={{ ...S.code, marginLeft: 4 }}>{e}</span>
              ))}
            </div>
          </div>
        ))}
      </CIMSection>

      {/* 4 · EVIDENCE */}
      <CIMSection
        kind="evidence"
        title="Evidence · First-class objects"
        count={`${(inv.evidence || []).length} evidence record(s)`}
        isEmpty={!inv.evidence?.length}
      >
        {(inv.evidence || []).map((e) => (
          <div key={e.id} style={S.bullet} data-testid={`cim-evidence-${e.id}`}>
            <div>
              <span style={S.code}>{e.id}</span>{" "}
              <span style={S.bulletMeta}>{e.type}</span>{" "}
              <span>{e.normalized_value || e.raw_value}</span>
              <ConfidenceBadge value={e.confidence} />
            </div>
            <div style={S.bulletMeta}>
              {(e.supports || []).length > 0 && (
                <>supports: {(e.supports || []).map((a) => (
                  <span key={a} style={{ ...S.code, marginLeft: 4 }}>{a}</span>
                ))}</>
              )}
            </div>
          </div>
        ))}
      </CIMSection>

      {/* 5 · TIMELINE */}
      <CIMSection
        kind="timeline"
        title="Timeline"
        count={`${(inv.timeline || []).length} fact(s)`}
        isEmpty={!inv.timeline?.length}
        emptyText="No temporal facts extracted from the supplied artifact."
      >
        {(inv.timeline || []).map((t) => (
          <div key={t.id} style={S.bullet} data-testid={`cim-timeline-${t.id}`}>
            <div>
              <span style={S.code}>{t.at || "—"}</span> · {t.text}
            </div>
          </div>
        ))}
      </CIMSection>

      {/* 6 · ENTITIES */}
      <CIMSection
        kind="entities"
        title="Entities"
        count={`${(inv.entities || []).length} entit${(inv.entities || []).length === 1 ? "y" : "ies"}`}
        isEmpty={!inv.entities?.length}
      >
        {(inv.entities || []).map((e) => (
          <div key={e.id} style={S.bullet} data-testid={`cim-entity-${e.id}`}>
            <div>
              <span style={S.code}>{e.id}</span>{" "}
              <span style={S.bulletMeta}>{e.kind}</span>{" "}
              {e.normalized_value || e.value}
              {e.role && <span style={{ marginLeft: 6, ...S.bulletMeta }}>· {e.role}</span>}
            </div>
          </div>
        ))}
      </CIMSection>

      {/* 7 · RELATIONSHIPS */}
      <CIMSection
        kind="relationships"
        title="Relationships"
        count={`${(inv.relationships || []).length} edge(s)`}
        isEmpty={!inv.relationships?.length}
        emptyText="No entity-relationships recorded."
      >
        {(inv.relationships || []).map((r) => (
          <div key={r.id} style={S.bullet} data-testid={`cim-rel-${r.id}`}>
            <span style={S.code}>{r.source}</span>
            {" — "}<span style={S.bulletMeta}>{r.kind}</span>{" — "}
            <span style={S.code}>{r.target}</span>
          </div>
        ))}
      </CIMSection>

      {/* 8 · THREAT INTEL */}
      <CIMSection
        kind="threat-intel"
        title="Threat Intel"
        count={`${(inv.threat_intel || []).length} hit(s)`}
        isEmpty={!inv.threat_intel?.length}
        emptyText="No threat-intel corroboration."
      >
        {(inv.threat_intel || []).map((h) => (
          <div key={h.id} style={S.bullet} data-testid={`cim-ti-${h.id}`}>
            <div>
              <span style={S.code}>{h.id}</span>{" "}
              <span style={S.bulletMeta}>{h.provider}</span>{" · "}
              <strong>{h.label}</strong>
            </div>
          </div>
        ))}
      </CIMSection>

      {/* 9 · ATT&CK */}
      <CIMSection
        kind="attack"
        title="ATT&CK · Deduplicated"
        count={`${(inv.attack || []).length} technique(s)`}
        isEmpty={!inv.attack?.length}
      >
        <div style={S.row2}>
          {(inv.attack || []).map((t) => (
            <span
              key={t.id}
              style={S.chip}
              data-testid={`cim-attack-${t.id}`}
              title={t.name || t.id}
            >
              {t.id}
              {t.name && <span style={S.bulletMeta}> · {t.name}</span>}
            </span>
          ))}
        </div>
      </CIMSection>

      {/* 10 · DECODE CHAIN (capability, not a button) */}
      <CIMSection
        kind="decode-chain"
        title="Decode Chain · Capability, not an action"
        count={`${(inv.decode_chain || []).length} layer(s)`}
        isEmpty={!inv.decode_chain?.length}
        emptyText="Input required no decoding."
      >
        {(inv.decode_chain || []).map((l, i) => (
          <div key={i} style={S.bullet} data-testid={`cim-decode-layer-${i}`}>
            <div>
              <span style={S.code}>L{l.idx}</span>{" "}
              <span style={S.bulletMeta}>{l.op}</span>
              {l.preview && (
                <div style={{ marginTop: 4, fontSize: 11, color: "var(--text-secondary,#94a3b8)" }}>
                  {l.preview.slice(0, 200)}
                  {l.preview.length > 200 ? "…" : ""}
                </div>
              )}
            </div>
          </div>
        ))}
      </CIMSection>

      {/* 11 · UNKNOWNS (deterministic) */}
      <CIMSection
        kind="unknowns"
        title="Unknowns · Deterministically generated"
        count={`${(inv.unknowns || []).length} gap(s)`}
        isEmpty={!inv.unknowns?.length}
        emptyText="No known data gaps."
      >
        {(inv.unknowns || []).map((u) => (
          <div key={u.id} style={S.bullet} data-testid={`cim-unknown-${u.id}`}>
            <div>
              <span style={S.code}>{u.id}</span>{" "}
              <span style={S.bulletMeta}>{u.rule_id}</span>
              <div style={{ marginTop: 4 }}>{u.text}</div>
            </div>
          </div>
        ))}
      </CIMSection>

      {/* RECOMMENDATIONS · shown below unknowns */}
      <CIMSection
        kind="recommendations"
        title="Recommendations · Evidence-backed"
        count={`${(inv.recommendations || []).length} action(s)`}
        isEmpty={!inv.recommendations?.length}
      >
        {(inv.recommendations || []).map((r) => (
          <div key={r.id} style={S.bullet} data-testid={`cim-rec-${r.id}`}>
            <div>
              <span style={S.code}>{r.id}</span>{" "}
              <span style={S.bulletMeta}>{r.kind}</span>{" · "}
              <strong>{r.text}</strong>
              <div style={S.bulletMeta}>
                {(r.evidence || []).map((e) => (
                  <span key={e} style={{ ...S.code, marginLeft: 4 }}>{e}</span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </CIMSection>
    </div>
  );
}

export default CIMInvestigation;
