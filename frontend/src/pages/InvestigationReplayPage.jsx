/**
 * InvestigationReplayPage — Phase A.5 · item 3.4.
 *
 * Owner-locked step-through analyst view of the complete deterministic
 * pipeline. Zero backend changes — reads exclusively from existing
 * SSOT endpoints:
 *    GET /api/correlations/cem/{case_id}
 *    GET /api/correlations/fingerprint/{case_id}
 *    GET /api/correlations/provenance/{case_id}
 *
 * Pipeline stages (deterministic order):
 *   Input → Detection → Extraction → Decode → Recovered Artifact →
 *   Analyzer → MITRE → Timeline → Threat Summary → Fingerprint →
 *   Provenance → Verdict
 *
 * Every step card is clickable → opens the shared <EvidenceModal>.
 */
import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import Header from "@/components/Header";
import api from "@/lib/api";
import { useEvidenceModal } from "@/components/EvidenceModal";
import {
  Play, ArrowRight, Radar, ShieldCheck, Cpu, Layers, GitBranch,
} from "lucide-react";

const COL = { bg: "var(--bg,#0b1220)", panel: "#0f1a2c", border: "#1f2b3f",
              muted: "#94a3b8", accent: "#38bdf8", good: "#86efac",
              warn: "#fbbf24", bad: "#f87171", text: "#e5e7eb" };

export default function InvestigationReplayPage() {
  const { id: caseId } = useParams();
  const [cem, setCem] = useState(null);
  const [fp,  setFp]  = useState(null);
  const [prov, setProv] = useState(null);
  const [err, setErr] = useState("");
  const [stepIdx, setStepIdx] = useState(0);
  const evi = useEvidenceModal();

  useEffect(() => {
    (async () => {
      try {
        const [c, f, p] = await Promise.all([
          api.get(`/correlations/cem/${caseId}`),
          api.get(`/correlations/fingerprint/${caseId}`),
          api.get(`/correlations/provenance/${caseId}`),
        ]);
        setCem(c.data?.cem);
        setFp(f.data?.fingerprint);
        setProv(p.data?.confidence_provenance);
      } catch (e) {
        setErr(e?.response?.data?.detail || e.message || String(e));
      }
    })();
  }, [caseId]);

  const steps = useMemo(() => buildSteps(cem, fp, prov), [cem, fp, prov]);
  const currentStep = steps[stepIdx];

  return (
    <div data-testid="investigation-replay-page"
         style={{ minHeight: "100vh", background: COL.bg, color: COL.text }}>
      <Header />
      <div style={{ maxWidth: 1400, margin: "0 auto", padding: "28px 24px" }}>
        <Title caseId={caseId} />
        {err && (
          <div data-testid="replay-error"
               style={{ marginTop: 16, padding: 12, borderRadius: 8,
                        background: "#3a1d1d", color: COL.bad }}>{err}</div>
        )}
        {!cem && !err && (
          <div style={{ color: COL.muted, marginTop: 24 }}>
            Loading investigation from the SSOT…
          </div>
        )}
        {cem && steps.length > 0 && (
          <>
            <Scrubber steps={steps} idx={stepIdx} onIdx={setStepIdx} />
            <StepDetail step={currentStep} openEvidence={evi.open} />
            <PipelineFlow steps={steps} idx={stepIdx} onIdx={setStepIdx} />
          </>
        )}
      </div>
      {evi.modal}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Step assembly — pure function on SSOT payloads.
// ─────────────────────────────────────────────────────────────────
function buildSteps(cem, fp, prov) {
  if (!cem) return [];
  const traces = cem.traces || {};
  const canonArts  = cem.canonical_artifacts || [];
  const kids       = cem.child_artifacts || [];
  const mitre      = cem.mitre || [];
  const findings   = (cem.events || []).filter(e => e.kind === "analyzer.finding");
  const timeline   = (cem.events || []).map(e => ({kind: e.kind, code: e.code}));
  const verdict    = cem.verdict || {};

  const S = [];
  S.push({
    id: "input", label: "Input",
    kind: "input",
    detail: `${cem.input_provenance?.kind || "input"} · ${
              (cem.input_provenance?.byte_size ?? "—")} bytes`,
    descriptor: { source: "Pipeline · Input",
                  title: "Deterministic Input",
                  raw: cem.input_provenance },
  });
  S.push({
    id: "detection", label: "Detection",
    kind: "detection",
    detail: `terminal_state = ${cem.convergence?.terminal_state}`,
    descriptor: { source: "Pipeline · Detection",
                  title: "Convergence",
                  raw: cem.convergence },
  });
  if (traces.recipe?.length) {
    S.push({
      id: "decode", label: "Decode",
      kind: "decode",
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
      id: "analyzer", label: "Analyzer Findings",
      kind: "analyzer",
      detail: `${findings.length} finding(s)`,
      descriptor: { source: "Pipeline · Analyzer",
                    title: "Analyzer Findings",
                    evidence_refs: findings, raw: findings },
    });
  }
  if (mitre.length) {
    S.push({
      id: "mitre", label: "MITRE Mapping",
      kind: "mitre",
      detail: mitre.map(m => m.id).join(" · "),
      descriptor: { source: "Pipeline · MITRE ATT&CK",
                    title: "MITRE Techniques",
                    mitre: mitre.map(m => m.id), raw: mitre },
    });
  }
  if (timeline.length) {
    S.push({
      id: "timeline", label: "Timeline",
      kind: "timeline",
      detail: `${timeline.length} event(s)`,
      descriptor: { source: "Pipeline · Timeline",
                    title: "Event Timeline",
                    raw: timeline },
    });
  }
  if (fp?.hash) {
    S.push({
      id: "fingerprint", label: "Attack Fingerprint",
      kind: "fingerprint",
      detail: `hash ${fp.hash.slice(0, 12)}…`,
      descriptor: { source: "Pipeline · Attack Fingerprint",
                    title: "Attack DNA",
                    raw: fp },
    });
  }
  if (prov?.provenance_hash) {
    S.push({
      id: "provenance", label: "Confidence Provenance",
      kind: "provenance",
      detail: `${prov.rules?.length || 0} rules · derived ${
                prov.derived?.verdict}·${prov.derived?.risk_score}`,
      descriptor: { source: "Pipeline · Confidence Provenance",
                    title: "Why did the engine reach this verdict?",
                    raw: prov },
    });
  }
  S.push({
    id: "verdict", label: "Final Verdict",
    kind: "verdict",
    detail: `${verdict.verdict || prov?.derived?.verdict || "—"} · risk ${
              verdict.risk_score ?? prov?.derived?.risk_score ?? "—"}`,
    descriptor: { source: "Pipeline · Verdict",
                  title: "Final Verdict",
                  raw: { recorded: verdict, derived: prov?.derived } },
  });
  return S;
}

// ─── UI Bits ────────────────────────────────────────────────────────
function Title({ caseId }) {
  return (
    <div style={{ display: "flex", gap: 14, alignItems: "center",
                  marginBottom: 20 }}>
      <div style={{ background: "#0e223b", padding: 10, borderRadius: 10 }}>
        <Play size={24} color={COL.accent} />
      </div>
      <div>
        <h1 data-testid="replay-page-title"
            style={{ fontSize: 26, margin: 0, letterSpacing: -0.3 }}>
          Investigation Replay
        </h1>
        <div style={{ color: COL.muted, fontSize: 13, marginTop: 2 }}>
          Deterministic pipeline step-through ·{" "}
          <span style={{ fontFamily: "ui-monospace, monospace" }}>
            {caseId?.slice(0, 16)}…
          </span>
        </div>
      </div>
    </div>
  );
}

function Scrubber({ steps, idx, onIdx }) {
  return (
    <div data-testid="replay-scrubber"
         style={{ background: COL.panel, border: `1px solid ${COL.border}`,
                  borderRadius: 12, padding: 16 }}>
      <input type="range" min={0} max={steps.length - 1} value={idx}
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

function StepDetail({ step, openEvidence }) {
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

function PipelineFlow({ steps, idx, onIdx }) {
  return (
    <div data-testid="replay-flow"
         style={{ marginTop: 16, background: COL.panel,
                  border: `1px solid ${COL.border}`, borderRadius: 12,
                  padding: 16, display: "flex", flexWrap: "wrap",
                  gap: 8, alignItems: "center" }}>
      {steps.map((s, i) => (
        <div key={s.id} style={{ display: "flex", alignItems: "center",
                                  gap: 6 }}>
          <button data-testid={`replay-flow-step-${s.id}`}
                  onClick={() => onIdx(i)}
                  style={{ padding: "6px 10px", borderRadius: 8,
                           background: i === idx ? COL.accent : "#0a1526",
                           color: i === idx ? "#052437" : COL.text,
                           border: `1px solid ${i === idx ? COL.accent
                                                           : COL.border}`,
                           cursor: "pointer", fontSize: 12,
                           fontFamily: "ui-monospace, monospace" }}>
            {s.label}
          </button>
          {i < steps.length - 1 && (
            <ArrowRight size={12} color={COL.muted} />
          )}
        </div>
      ))}
    </div>
  );
}
