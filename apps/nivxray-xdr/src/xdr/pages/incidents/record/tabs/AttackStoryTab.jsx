/**
 * AttackStoryTab · Round 33 · Evidence-backed 14-stage AttackFlow.
 *
 * Consumes `GET /api/incidents/{id}/attack-story` (Round 33 backend).
 * Renders the deterministic 14-stage Attack Cycle with the
 * four-state grammar OBSERVED · SUPPORTED · POSSIBLE · NOT_OBSERVED
 * plus the evidence-backed narrative sentences.
 *
 * Never fabricates a stage: NOT_OBSERVED stages render as honest
 * empty markers.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Loader2 } from "lucide-react";

import api from "@/lib/api";
import GatewayNarrationPanel from "@/xdr/design/GatewayNarrationPanel";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvMetrics,
  NxInvValue, ABSENCE,
} from "@/xdr/nx";


const STATE_MARK = {
  OBSERVED:     "●",
  SUPPORTED:    "◐",
  POSSIBLE:     "○",
  NOT_OBSERVED: "—",
};

const STATE_TONE = {
  OBSERVED:     "observed",
  SUPPORTED:    "supported",
  POSSIBLE:     "possible",
  NOT_OBSERVED: "notobs",
};


export default function AttackStoryTab({ incident }) {
  const [story, setStory] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!incident?.id) return undefined;
    let cancelled = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const { data } = await api.get(`/incidents/${incident.id}/attack-story`);
        if (!cancelled) setStory(data);
      } catch (e) {
        if (!cancelled) setError(e?.message || String(e));
      } finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  const counts = story?.counts || {};

  const flow = story?.flow || [];
  const sentences = story?.narrative?.sentences || [];
  const exec_summary = story?.narrative?.executive_summary;
  const observedFlow = flow.filter((f) => f.state !== "NOT_OBSERVED");

  // Engine states, in analyst language. The exact value stays on the row.
  const STATE_TEXT = {
    OBSERVED: "Observed · direct evidence",
    SUPPORTED: "Supported · correlated",
    POSSIBLE: "Possible · technique only",
    NOT_OBSERVED: "Not observed",
  };

  if (loading) return (
    <div className="inv" data-testid="xdr-record-attack-story-loading">
      <NxInvSection title="Attack story" subtitle="reconstructing from evidence…">
        <div className="inv-empty">Reading the authoritative attack story…</div>
      </NxInvSection>
    </div>
  );

  if (error && !story) return (
    <div className="inv" data-testid="xdr-record-attack-story-error">
      <NxInvSection title="Attack story">
        <NxInvEmpty
          title="Attack progression unavailable"
          body="No evidence-backed attack sequence could be read for this incident."
          points={[String(typeof error === "object"
            ? (error.reason || error.error || JSON.stringify(error)) : error)]} />
      </NxInvSection>
    </div>
  );

  return (
    <div className="inv" data-testid="xdr-record-attack-story">
      <NxInvSection
        title="What we believe happened"
        subtitle="composed only from governed evidence"
        testid="xdr-record-attack-story-header">
        <div className="inv-sec__b--pad" style={{ fontSize: 12.5,
              lineHeight: 1.7, maxWidth: 900 }}>
          {exec_summary || (
            <span className="inv-tb__na">
              No evidence-backed narrative has been composed for this incident.
            </span>
          )}
        </div>
        <NxInvMetrics testid="xdr-record-attack-story-metrics" items={[
          { key: "observed", label: "Observed",
            value: counts.stages_observed || null,
            absent: ABSENCE.NOT_OBSERVED, sub: "direct evidence" },
          { key: "supported", label: "Supported",
            value: counts.stages_supported || null,
            absent: ABSENCE.NOT_OBSERVED, sub: "correlated" },
          { key: "possible", label: "Possible",
            value: counts.stages_possible || null,
            absent: ABSENCE.NOT_OBSERVED, sub: "technique in graph" },
          { key: "not-observed", label: "Unobserved stages",
            value: counts.stages_not_observed || null,
            absent: ABSENCE.NOT_EVALUATED, sub: "stated gap" },
        ]} />
      </NxInvSection>

      <NxInvSection
        title="Attack progression"
        subtitle={observedFlow.length
          ? `${observedFlow.length} stage(s) with evidence`
          : "no stage carries evidence yet"}
        testid="xdr-record-attack-story-flow-sec">
        <NxInvTable
          testid="xdr-record-attack-story-flow"
          rows={observedFlow}
          rowKey={(r) => r.index}
          columns={[
            { key: "index", label: "#", width: 40, num: true },
            { key: "stage", label: "Stage" },
            { key: "state", label: "Assessment", width: 190,
              render: (r) => STATE_TEXT[r.state] || r.state },
            { key: "techniques", label: "Techniques", width: 200,
              render: (r) => (r.techniques?.length
                ? <span className="mono">{r.techniques.join(", ")}</span>
                : <span className="inv-tb__na">{ABSENCE.NOT_OBSERVED}</span>) },
            { key: "finding_ids", label: "Findings", width: 90, num: true,
              render: (r) => (r.finding_ids?.length
                ? r.finding_ids.length
                : <span className="inv-tb__na">none</span>) },
            { key: "evidence_refs", label: "Evidence", width: 100, num: true,
              render: (r) => (r.evidence_refs?.length
                ? r.evidence_refs.length
                : <span className="inv-tb__na">{ABSENCE.EVIDENCE_INCOMPLETE}</span>) },
          ]}
          detail={(r) => (
            <dl className="inv-kv">
              <dt>Stage</dt><dd>{r.stage}</dd>
              <dt>Assessment</dt><dd>{STATE_TEXT[r.state] || r.state}</dd>
              <dt>Techniques</dt>
              <dd className="mono">
                <NxInvValue value={(r.techniques || []).join(", ")}
                            absent={ABSENCE.NOT_OBSERVED} />
              </dd>
              <dt>Evidence references</dt>
              <dd className="mono">
                <NxInvValue value={(r.evidence_refs || []).join(", ")}
                            absent={ABSENCE.EVIDENCE_INCOMPLETE} />
              </dd>
              <dt>Engine state</dt><dd className="mono">{r.state}</dd>
            </dl>
          )}
          empty={
            <NxInvEmpty
              testid="xdr-record-attack-story-empty"
              title="Attack progression unavailable"
              body="No evidence-backed attack sequence has been established for this incident. NivXRay will not assemble a story it cannot cite."
              points={[
                `Stages evaluated: ${flow.length || ABSENCE.NOT_EVALUATED}`,
                "Observed activity is on the Timeline tab; the evidence itself is on the Evidence tab.",
                "Unresolved gaps stay unresolved — a plausible stage is never promoted to an observed one.",
              ]} />
          } />
      </NxInvSection>

      {sentences.length > 0 && (
        <NxInvSection title="Evidence-backed narrative"
                      subtitle="each sentence cites what produced it"
                      testid="xdr-record-attack-story-narrative">
          <div className="inv-sec__b--pad">
            {sentences.map((s, i) => (
              <div key={i} data-testid={`xdr-record-attack-story-sentence-${i}`}
                   style={{ padding: "8px 10px", marginBottom: 8,
                            borderLeft: "3px solid var(--nx-accent, #7c3aed)",
                            background: "var(--nx-surf-inset, rgba(127,127,127,.06))",
                            fontSize: 12.5, lineHeight: 1.65 }}>
                <div>{s.text}</div>
                {(s.evidence_refs?.length > 0 || s.finding_ids?.length > 0) && (
                  <div className="mono" style={{ fontSize: 10.4, marginTop: 4,
                        color: "var(--nx-muted, var(--muted))" }}>
                    {s.evidence_refs?.length > 0
                      && `Evidence: ${s.evidence_refs.slice(0, 3).join(", ")}`}
                    {s.evidence_refs?.length > 0 && s.finding_ids?.length > 0 && " · "}
                    {s.finding_ids?.length > 0
                      && `Findings: ${s.finding_ids.length}`}
                  </div>
                )}
              </div>
            ))}
          </div>
        </NxInvSection>
      )}

      <NxInvSection title="Technical reasoning"
                    subtitle="narration provider, stage machine and unobserved stages"
                    testid="xdr-record-attack-story-tech-sec">
        <NxInvTech label="Narration gateway output"
                   testid="xdr-record-attack-story-narration-tech">
          <GatewayNarrationPanel
            incidentId={incident?.id}
            endpoint="/narration/incident/{id}/attack-story"
            eyebrow="NARRATION GATEWAY · ATTACK STORY"
            title="Evidence-backed attack story narration"
            testidPrefix="xdr-attack-story-narration" />
        </NxInvTech>
        <NxInvTech label={`Unobserved stages (${
          flow.length - observedFlow.length})`}
                   testid="xdr-record-attack-story-unobserved">
          <div className="mono" style={{ fontSize: 10.8, lineHeight: 1.7 }}>
            {flow.filter((f) => f.state === "NOT_OBSERVED")
                 .map((f) => `${f.index} · ${f.stage}`).join("   |   ")
             || "every evaluated stage carries evidence"}
          </div>
        </NxInvTech>
      </NxInvSection>
    </div>
  );
}
