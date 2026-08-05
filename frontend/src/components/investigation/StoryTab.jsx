/**
 * Investigation · Story tab — the deterministic narrative.
 *
 * Owner-locked (2026-02-16): Replay + Timeline + Trajectory + Decision
 * Trace collapse into ONE synchronized experience. Reads exclusively
 * from case-scoped SSOT endpoints. Zero backend coupling.
 *
 * Sections:
 *   1. Scrubber        — jump to any step
 *   2. Step detail     — current step's descriptor + evidence handoff
 *   3. Pipeline flow   — click-to-jump breadcrumb of every step
 *   4. Timeline strip  — chronological synopsis of CEM events
 *   5. Trajectory link — open the full swimlane canvas
 */
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import api from "@/lib/api";
import {
  buildSteps, Scrubber, StepDetail, PipelineFlow, COL,
} from "@/components/attackStory/ReplayPrimitives";
import { GitBranch, ExternalLink } from "lucide-react";

export default function StoryTab({ caseId, openEvidence, initialStep = 0 }) {
  const [cem, setCem]   = useState(null);
  const [fp,  setFp]    = useState(null);
  const [prov, setProv] = useState(null);
  const [err, setErr]   = useState("");
  const [stepIdx, setStepIdx] = useState(initialStep);

  useEffect(() => {
    if (!caseId) return;
    setErr("");
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

  const events = (cem?.events || []).slice(0, 40);

  return (
    <div data-testid="tab-panel-story" style={{ display: "grid", gap: 14 }}>
      {err && (
        <div data-testid="story-error"
             style={{ padding: 12, borderRadius: 8,
                      background: "#3a1d1d", color: COL.bad }}>{err}</div>
      )}
      {!cem && !err && (
        <div style={{ color: COL.muted, padding: 24 }}>
          Loading story from the SSOT…
        </div>
      )}
      {cem && steps.length > 0 && (
        <>
          <Scrubber steps={steps} idx={stepIdx} onIdx={setStepIdx} />
          <StepDetail step={currentStep} openEvidence={openEvidence} />
          <PipelineFlow steps={steps} idx={stepIdx} onIdx={setStepIdx} />

          <section data-testid="story-timeline"
                   style={{ background: COL.panel,
                            border: `1px solid ${COL.border}`,
                            borderRadius: 12, padding: 16 }}>
            <SectionTitle>Timeline synopsis</SectionTitle>
            <div style={{ marginTop: 8, display: "flex", gap: 8,
                          flexWrap: "wrap" }}>
              {events.length === 0 && (
                <span style={{ color: COL.muted, fontSize: 12 }}>
                  No timeline events emitted.
                </span>
              )}
              {events.map((e, i) => (
                <button key={i}
                        data-testid={`story-timeline-event-${i}`}
                        onClick={() => openEvidence({
                          source: "Story · Timeline",
                          title:  e.code || e.kind,
                          rule_description: e.summary || e.kind,
                          timeline_ref: { kind: e.kind, code: e.code, ts: e.ts },
                          raw: e,
                        })}
                        style={{ padding: "4px 8px", fontSize: 11,
                                 background: "#0a1526",
                                 color: COL.text,
                                 border: `1px solid ${COL.border}`,
                                 borderRadius: 6, cursor: "pointer",
                                 fontFamily: "ui-monospace, monospace" }}
                        title={e.summary || e.code}>
                  {e.kind}
                </button>
              ))}
            </div>
          </section>

          <Link to={`/v2/trajectory/${caseId}`}
                data-testid="story-open-trajectory"
                style={{ display: "inline-flex", gap: 8, alignItems: "center",
                         padding: "10px 14px", background: COL.panel,
                         border: `1px solid ${COL.border}`, borderRadius: 10,
                         color: COL.accent, textDecoration: "none",
                         width: "fit-content" }}>
            <GitBranch size={14} />
            Open full Trajectory canvas
            <ExternalLink size={12} />
          </Link>
        </>
      )}
    </div>
  );
}

function SectionTitle({ children }) {
  return (
    <div style={{ fontSize: 11, letterSpacing: "0.16em",
                  textTransform: "uppercase", color: "#94a3b8" }}>
      {children}
    </div>
  );
}
