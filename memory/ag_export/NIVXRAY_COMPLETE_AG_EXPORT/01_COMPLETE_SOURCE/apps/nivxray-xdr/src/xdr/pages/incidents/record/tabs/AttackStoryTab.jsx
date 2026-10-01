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

  if (loading) return (
    <div className="rl-loading" data-testid="xdr-record-attack-story-loading">
      <Loader2 size={12} className="rl-spin" style={{ verticalAlign: "-2px", marginRight: 6 }} />
      LOADING ATTACK STORY…
    </div>
  );

  if (error && !story) return (
    <div className="rl-error" data-testid="xdr-record-attack-story-error">
      {String(error)}
    </div>
  );

  const flow = story?.flow || [];
  const sentences = story?.narrative?.sentences || [];
  const exec_summary = story?.narrative?.executive_summary;

  return (
    <div data-testid="xdr-record-attack-story">
      {/* Phase 1.5 · Attack Story narration migrated to the
              NivXRay XDR Narration Gateway.  Governed context
              (evidence ids, technique ids, verdict, severity,
              confidence) is inherited verbatim; only wording
              varies across providers. */}
      <GatewayNarrationPanel
        incidentId  = {incident?.id}
        endpoint    = "/narration/incident/{id}/attack-story"
        eyebrow     = "NIVXRAY XDR NARRATION GATEWAY · ATTACK STORY"
        title       = "Evidence-Backed Attack Story Narration"
        testidPrefix= "xdr-attack-story-narration"
      />

      <div className="rl-ai-status observed"
            data-testid="xdr-record-attack-story-header">
        <div className="badge"><span>ATTACK STORY · 14-STAGE FLOW</span></div>
        <div className="txt">
          <h5>Evidence-Backed Attack Progression</h5>
          <p>{exec_summary || "No governed evidence composed yet."}</p>
        </div>
      </div>

      <div className="rl-metric-grid" style={{ marginBottom: 12 }}>
        <div className={`rl-metric ${counts.stages_observed > 0 ? "ok" : "na"}`}
              data-testid="xdr-record-attack-story-metric-observed">
          <div className="k">OBSERVED</div>
          <div className="v">{counts.stages_observed ?? "—"}</div>
          <div className="sub">direct evidence</div>
        </div>
        <div className={`rl-metric ${counts.stages_supported > 0 ? "info" : "na"}`}
              data-testid="xdr-record-attack-story-metric-supported">
          <div className="k">SUPPORTED</div>
          <div className="v">{counts.stages_supported ?? "—"}</div>
          <div className="sub">correlation / inference</div>
        </div>
        <div className={`rl-metric ${counts.stages_possible > 0 ? "amber" : "na"}`}
              data-testid="xdr-record-attack-story-metric-possible">
          <div className="k">POSSIBLE</div>
          <div className="v">{counts.stages_possible ?? "—"}</div>
          <div className="sub">technique in IKG</div>
        </div>
        <div className={`rl-metric na`}
              data-testid="xdr-record-attack-story-metric-not-observed">
          <div className="k">NOT OBSERVED</div>
          <div className="v">{counts.stages_not_observed ?? "—"}</div>
          <div className="sub">honest gap</div>
        </div>
      </div>

      <div className="rl-section">
        <div className="rl-section-title">14-Stage AttackFlow</div>
        <table className="rl-table" data-testid="xdr-record-attack-story-flow">
          <thead><tr>
            <th style={{ width: 32 }}></th>
            <th style={{ width: 40 }}>#</th>
            <th>Stage</th>
            <th style={{ width: 130 }}>State</th>
            <th style={{ width: 220 }}>Techniques</th>
            <th style={{ width: 100 }}>Findings</th>
            <th style={{ width: 100 }}>Evidence</th>
          </tr></thead>
          <tbody>
            {flow.map((s) => (
              <tr key={s.stage}
                   className={`rl-attack-row-${STATE_TONE[s.state]}`}
                   data-testid={`xdr-record-attack-story-stage-${s.index}`}>
                <td className="mono" style={{ fontSize: 16, opacity: s.state === "NOT_OBSERVED" ? 0.35 : 1 }}>
                  {STATE_MARK[s.state]}
                </td>
                <td className="mono">{s.index}</td>
                <td style={{ fontWeight: s.state !== "NOT_OBSERVED" ? 500 : 400,
                              opacity: s.state === "NOT_OBSERVED" ? 0.55 : 1 }}>
                  {s.stage}
                </td>
                <td className="mono">{s.state}</td>
                <td className="mono" style={{ fontSize: 12 }}>
                  {s.techniques.length ? s.techniques.join(", ") : "—"}
                </td>
                <td className="mono">{s.finding_ids.length || "—"}</td>
                <td className="mono">{s.evidence_refs.length || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {sentences.length > 0 && (
        <div className="rl-section" style={{ marginTop: 16 }}>
          <div className="rl-section-title">Evidence-backed narrative</div>
          <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
            {sentences.map((s, i) => (
              <li key={i}
                   data-testid={`xdr-record-attack-story-sentence-${i}`}
                   style={{ padding: "8px 12px",
                              borderLeft: "3px solid var(--rl-purple)",
                              marginBottom: 8, background: "rgba(0,0,0,0.02)" }}>
                <div style={{ fontWeight: 500 }}>{s.text}</div>
                {(s.evidence_refs.length > 0 || s.finding_ids.length > 0) && (
                  <div style={{ opacity: 0.6, fontSize: 11, marginTop: 4 }}>
                    {s.evidence_refs.length > 0 &&
                      `Evidence: ${s.evidence_refs.slice(0, 3).join(", ")}`}
                    {s.evidence_refs.length > 0 && s.finding_ids.length > 0 && " · "}
                    {s.finding_ids.length > 0 &&
                      `Findings: ${s.finding_ids.length}`}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
