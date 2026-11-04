/**
 * Attack Story · shared Replay primitives (Phase A.5 · item 3.7).
 *
 * Extracted from the retired `InvestigationReplayPage.jsx` so that
 * Replay lives as ONE mode inside the Attack Story container while
 * the deep-link `/investigations/:id/replay` continues to work
 * (via 301-style client redirect).
 *
 * Every primitive is a pure component — feed CEM · Fingerprint ·
 * Provenance, get a scrubber-driven walkthrough back. Zero backend
 * coupling.
 */
import { Play, ArrowRight } from "lucide-react";

export const COL = {
  bg: "var(--bg,#0b1220)", panel: "#0f1a2c", border: "#1f2b3f",
  muted: "#94a3b8", accent: "#38bdf8", good: "#86efac",
  warn: "#fbbf24", bad: "#f87171", text: "#e5e7eb",
};

// ─── Deterministic step assembly (pure) ───────────────────────────
export function buildSteps(cem, fp, prov) {
  if (!cem) return [];
  const traces     = cem.traces || {};
  const canonArts  = cem.canonical_artifacts || [];
  const kids       = cem.child_artifacts || [];
  const mitre      = cem.mitre || [];
  const findings   = (cem.events || []).filter(e => e.kind === "analyzer.finding");
  const timeline   = (cem.events || []).map(e => ({kind: e.kind, code: e.code}));
  const verdict    = cem.verdict || {};

  const S = [];
  S.push({
    id: "input", label: "Input", kind: "input",
    detail: `${cem.input_provenance?.kind || "input"} · ${
              (cem.input_provenance?.byte_size ?? "—")} bytes`,
    descriptor: { source: "Pipeline · Input",
                  title: "Deterministic Input",
                  raw: cem.input_provenance },
  });
  S.push({
    id: "detection", label: "Detection", kind: "detection",
    detail: `terminal_state = ${cem.convergence?.terminal_state}`,
    descriptor: { source: "Pipeline · Detection",
                  title: "Convergence",
                  raw: cem.convergence },
  });
  if (traces.recipe?.length) {
    S.push({
      id: "decode", label: "Decode", kind: "decode",
      detail: `${traces.recipe.length} recipe step(s)`,
      descriptor: { source: "Pipeline · Decode",
                    title: "Decode Recipe",
                    raw: { recipe: traces.recipe,
                           transformation_trace: traces.transformation_trace,
                           decision_trace: traces.decision_trace } },
    });
  }
  canonArts.forEach((a, i) => {
    S.push({
      id: `artifact-${i}`, label: `Recovered ${a.type || "artifact"}`,
      kind: "artifact",
      detail: `sha256 ${(a.sha256 || "").slice(0, 12)}…`,
      descriptor: { source: "Pipeline · Recovered Artifact",
                    title: `Canonical ${a.type || "artifact"}`,
                    artifact: a, raw: a },
    });
  });
  kids.forEach((c, i) => {
    S.push({
      id: `child-${i}`, label: `Child · ${c.type || "artifact"}`,
      kind: "child",
      detail: `depth ${c.depth} · analyzer ${c.routed_artifact_type || "—"}`,
      descriptor: { source: "Pipeline · Recursive Child",
                    title: `Recursive Child · ${c.type}`,
                    recovered_child: c, raw: c },
    });
  });
  if (findings.length) {
    S.push({
      id: "analyzer", label: "Analyzer Findings", kind: "analyzer",
      detail: `${findings.length} finding(s)`,
      descriptor: { source: "Pipeline · Analyzer",
                    title: "Analyzer Findings",
                    evidence_refs: findings, raw: findings },
    });
  }
  if (mitre.length) {
    S.push({
      id: "mitre", label: "MITRE Mapping", kind: "mitre",
      detail: mitre.map(m => m.id).join(" · "),
      descriptor: { source: "Pipeline · MITRE ATT&CK",
                    title: "MITRE Techniques",
                    mitre: mitre.map(m => m.id), raw: mitre },
    });
  }
  if (timeline.length) {
    S.push({
      id: "timeline", label: "Timeline", kind: "timeline",
      detail: `${timeline.length} event(s)`,
      descriptor: { source: "Pipeline · Timeline",
                    title: "Event Timeline",
                    raw: timeline },
    });
  }
  if (fp?.hash) {
    S.push({
      id: "fingerprint", label: "Attack Fingerprint", kind: "fingerprint",
      detail: `hash ${fp.hash.slice(0, 12)}…`,
      descriptor: { source: "Pipeline · Attack Fingerprint",
                    title: "Attack DNA", raw: fp },
    });
  }
  if (prov?.provenance_hash) {
    S.push({
      id: "provenance", label: "Confidence Provenance", kind: "provenance",
      detail: `${prov.rules?.length || 0} rules · derived ${
                prov.derived?.verdict}·${prov.derived?.risk_score}`,
      descriptor: { source: "Pipeline · Confidence Provenance",
                    title: "Why did the engine reach this verdict?",
                    raw: prov },
    });
  }
  S.push({
    id: "verdict", label: "Final Verdict", kind: "verdict",
    detail: `${verdict.verdict || prov?.derived?.verdict || "—"} · risk ${
              verdict.risk_score ?? prov?.derived?.risk_score ?? "—"}`,
    descriptor: { source: "Pipeline · Verdict", title: "Final Verdict",
                  raw: { recorded: verdict, derived: prov?.derived } },
  });
  return S;
}

// ─── UI primitives ────────────────────────────────────────────────
export function Scrubber({ steps, idx, onIdx }) {
  return (
    <div data-testid="replay-scrubber"
         style={{ background: COL.panel, border: `1px solid ${COL.border}`,
                  borderRadius: 12, padding: 16 }}>
      <input type="range" min={0} max={Math.max(0, steps.length - 1)} value={idx}
             data-testid="replay-scrubber-input"
             onChange={(e) => onIdx(Number(e.target.value))}
             style={{ width: "100%", accentColor: COL.accent }} />
      <div style={{ display: "flex", justifyContent: "space-between",
                    marginTop: 6, fontSize: 12, color: COL.muted,
                    fontFamily: "ui-monospace, monospace" }}>
        <span>step {idx + 1} / {steps.length}</span>
        <span>{steps[idx]?.label}</span>
      </div>
    </div>
  );
}

export function StepDetail({ step, openEvidence }) {
  if (!step) return null;
  return (
    <div data-testid={`replay-step-detail-${step.id}`}
         style={{ marginTop: 16, background: COL.panel,
                  border: `1px solid ${COL.border}`, borderRadius: 12,
                  padding: 22 }}>
      <div style={{ fontSize: 11, color: COL.muted, letterSpacing: "0.16em",
                    textTransform: "uppercase" }}>
        {step.kind}
      </div>
      <div style={{ fontSize: 22, marginTop: 6, fontWeight: 600 }}>
        {step.label}
      </div>
      <div style={{ marginTop: 8, color: COL.text,
                    fontFamily: "ui-monospace, monospace", fontSize: 13 }}>
        {step.detail}
      </div>
      <button data-testid="replay-open-evidence"
              onClick={() => openEvidence(step.descriptor)}
              style={{ marginTop: 16, background: COL.accent, color: "#052437",
                       border: "none", borderRadius: 8, padding: "8px 14px",
                       fontWeight: 600, cursor: "pointer" }}>
        Show Evidence →
      </button>
    </div>
  );
}

export function PipelineFlow({ steps, idx, onIdx }) {
  return (
    <div data-testid="replay-flow"
         style={{ marginTop: 16, background: COL.panel,
                  border: `1px solid ${COL.border}`, borderRadius: 12,
                  padding: 16, display: "flex", flexWrap: "wrap",
                  gap: 8, alignItems: "center" }}>
      {steps.map((s, i) => (
        <div key={s.id} style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <button data-testid={`replay-flow-step-${s.id}`}
                  onClick={() => onIdx(i)}
                  style={{ padding: "6px 10px", borderRadius: 8,
                           background: i === idx ? COL.accent : "#0a1526",
                           color: i === idx ? "#052437" : COL.text,
                           border: `1px solid ${i === idx ? COL.accent : COL.border}`,
                           cursor: "pointer", fontSize: 12,
                           fontFamily: "ui-monospace, monospace" }}>
            {s.label}
          </button>
          {i < steps.length - 1 && <ArrowRight size={12} color={COL.muted} />}
        </div>
      ))}
    </div>
  );
}

// Icon export so consumers can render the story title.
export { Play };
