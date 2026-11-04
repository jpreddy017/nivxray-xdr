/**
 * IncidentVerdictExplainability · S3-B.
 *
 * Seven analyst questions, answered only from authoritative reads:
 *
 *   what is the verdict        → `/incidents/:id/summary` ·
 *                                `deterministic_verdict` (the incident's OWN
 *                                verdict authority — no second verdict is
 *                                computed here)
 *   why did we reach it        → causal analysis ·
 *                                `verdicts.device.evidence_breakdown[]` +
 *                                `explainability.positive.reasons[]`
 *   what argues against a      → causal analysis ·
 *   stronger conclusion          `explainability.negative_patterns[]` and,
 *                                per hypothesis, the engine's own
 *                                `…/investigation/explain/{pattern}`
 *   what is missing / not      → `/incidents/:id/summary` ·
 *   observed                     `evidence_gaps[]`
 *   how confident              → the verdict authority's `confidence`
 *   how complete               → NO authoritative measure exists in this
 *                                build, so it reads NOT AVAILABLE with the
 *                                reason. It is NEVER derived from confidence.
 *
 * Locked semantics:
 *   NOT OBSERVED ≠ ABSENT · NOT AVAILABLE ≠ CLEAN ·
 *   NO REPUTATION RESULT ≠ BENIGN · MISSING TELEMETRY ≠ NEGATIVE EVIDENCE ·
 *   CONFIDENCE ≠ ANALYSIS COMPLETENESS.
 * Negative evidence (a required behaviour the engine looked for and did not
 * find) and missing visibility (telemetry the platform does not have) are
 * rendered as two SEPARATE groups, from two different authorities, and are
 * never merged. A claim with no cited event is labelled by its real
 * authority instead of being presented as an observed fact.
 */
import React, { useEffect, useMemo, useState } from "react";

import { NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvMetrics,
         NxState, NxChip, NxSkeleton, ABSENCE } from "@/xdr/nx";
import { apiErrorText } from "@/xdr/nx/apiError";
import { getIncidentSummary, getIncidentCausalAnalysis,
         getIncidentVerdictHypothesis } from "@/lib/incidentsApi";

const signalLabel = (s) => String(s || "")
  .toLowerCase().replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

const BAND_TONE = { malicious: "malicious", suspicious: "suspicious",
                    benign: "benign", informational: "neutral",
                    clean: "benign", unknown: "neutral" };

/* ── why this verdict ───────────────────────────────────────────── */
function Supports({ breakdown, reasons, testid }) {
  const rows = [];
  breakdown.forEach((b, i) => rows.push({
    _k: `ev-${i}`,
    _events: b.events || [],
    _processes: b.processes || [],
    claim: signalLabel(b.signal),
    detail: b.reason || <span className="inv-tb__na">{ABSENCE.NOT_RECORDED}</span>,
    weight: b.effective_weight ?? b.weight ?? null,
    basis: (b.events || []).length
      ? <NxState value="EVIDENCE_CITED" size="sm" />
      : <NxState value="ENGINE_DERIVED" size="sm" />,
  }));
  // reasons the engine states WITHOUT an evidence reference (e.g. coverage
  // statements) are kept, but labelled by what they actually are.
  reasons.filter((r) => r.kind !== "evidence").forEach((r, i) => rows.push({
    _k: `rs-${i}`,
    _events: [],
    _processes: [],
    claim: r.text || ABSENCE.NOT_RECORDED,
    detail: r.detail || <span className="inv-tb__na">{ABSENCE.NOT_RECORDED}</span>,
    weight: r.weight ?? null,
    basis: <span data-nx-state="NO_EVENT_CITED">
             <NxChip tone="not_connected" variant="dashed" size="sm">
               {String(r.kind || "statement")} statement · no event cited
             </NxChip>
           </span>,
  }));
  if (!rows.length) {
    return <NxInvEmpty
      title="No reason was recorded for this verdict"
      body="The causal analysis cites no contributing signal for this incident."
      points={["An unexplained verdict is not a benign verdict."]}
      testid={`${testid}-empty`} />;
  }
  return (
    <NxInvTable
      testid={testid} rowKey={(r) => r._k} rows={rows}
      columns={[
        { key: "claim", label: "Supports the current verdict", width: "18rem" },
        { key: "detail", label: "What the engine recorded" },
        { key: "weight", label: "Weight", width: "6rem", num: true },
        { key: "basis", label: "Basis", width: "13rem" },
      ]}
      detail={(r) => (
        <div style={{ display: "grid", gap: 6, fontSize: 11.5 }}
             data-testid={`${testid}-prov-${r._k}`}>
          <div>
            <b>Supporting evidence</b>{" "}
            {r._events.length
              ? `${r._events.length} recorded event frame(s)`
              : "no event frame is cited for this claim — it is the engine's "
                + "own statement, not an observation"}
          </div>
          <NxInvTech label="Technical details">
            <div className="mono" style={{ fontSize: 11 }}>
              <div>events · {r._events.join(", ") || "—"}</div>
              <div>entities · {r._processes.join(", ") || "—"}</div>
              <div>read from · verdicts.device.evidence_breakdown[] /
                explainability.positive.reasons[]</div>
            </div>
          </NxInvTech>
        </div>
      )} />
  );
}

/* ── what limits a stronger conclusion · one hypothesis ─────────── */
function Hypothesis({ incidentId, pattern, testid }) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    if (!open || data || err) return;
    getIncidentVerdictHypothesis(incidentId, pattern.id)
      .then(setData)
      .catch((e) => setErr(apiErrorText(e)));
  }, [open, data, err, incidentId, pattern.id]);

  const absent = [...((data?.reasons) || [])]
    .filter((r) => r.kind === "missing");
  const present = [...((data?.have_required) || []),
                   ...((data?.have_supporting) || [])];

  return (
    <div data-testid={testid} data-open={open || undefined}
         style={{ borderBottom: "1px solid var(--nx-divider)",
                  padding: "6px 0" }}>
      <button type="button" className="nx-dt-btn"
              data-testid={`${testid}-toggle`}
              onClick={() => setOpen((v) => !v)}>
        {open ? "▾" : "▸"} Why not {pattern.label}?
      </button>
      {open && (
        <div style={{ display: "grid", gap: 6, padding: "8px 0 4px" }}>
          {err && (
            <div data-testid={`${testid}-refused`}
                 style={{ display: "grid", gap: 6 }}>
              <NxState value="NOT_AUTHORIZED" size="sm" />
              <span style={{ fontSize: 11.5 }}>{err}</span>
            </div>
          )}
          {!err && !data && <NxSkeleton height={10} />}
          {data && (
            <>
              <div style={{ fontSize: 12 }}
                   data-testid={`${testid}-line`}
                   data-matches={String(!!data.matches)}>
                <b>{data.verdict_line || ABSENCE.NOT_RECORDED}</b>
              </div>
              {present.length > 0 && (
                <div style={{ fontSize: 11.5 }}
                     data-testid={`${testid}-present`}>
                  Observed for this hypothesis:{" "}
                  {present.map((p) => signalLabel(p)).join(" · ")}
                </div>
              )}
              <ul style={{ margin: 0, paddingLeft: 16, fontSize: 11.5 }}
                  data-testid={`${testid}-absent`}>
                {absent.length
                  ? absent.map((r, i) => (
                      <li key={i}>
                        <NxChip tone="not_connected" variant="dashed" size="sm">
                          NOT OBSERVED
                        </NxChip>{" "}{r.text}
                      </li>))
                  : <li>{ABSENCE.NOT_RECORDED}</li>}
              </ul>
              <div style={{ fontSize: 11, color: "var(--nx-text-dim)" }}>
                A behaviour the engine looked for and did not find is
                <b> NOT OBSERVED</b> — it is not proof the behaviour did not
                happen, and it is not the same thing as telemetry the
                platform does not have.
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

/* ── visibility and evidence gaps ───────────────────────────────── */
function Gaps({ gaps, testid }) {
  const notObserved = gaps.filter((g) => g.state === "no_matching_evidence");
  const unavailable = gaps.filter((g) => g.state !== "no_matching_evidence");
  const Block = ({ items, kind, title, note, state }) => (
    <div style={{ display: "grid", gap: 6 }}>
      <div style={{ fontSize: 11.5, fontWeight: 600 }}>{title}</div>
      {items.length === 0
        ? <span className="inv-tb__na">{ABSENCE.NOT_RECORDED}</span>
        : items.map((g, i) => (
            <div key={i} data-testid={`${testid}-${kind}-${i}`}
                 data-nx-state={g.state}
                 style={{ display: "flex", gap: 8, alignItems: "baseline",
                          flexWrap: "wrap", fontSize: 11.5 }}>
              <NxState value={state} size="sm" />
              <b>{g.claim}</b>
              <span style={{ color: "var(--nx-text-dim)" }}>{g.reason}</span>
              {(g.searched || []).length > 0 && (
                <span className="mono" style={{ fontSize: 10.5 }}>
                  searched · {g.searched.join(", ")}
                </span>
              )}
            </div>))}
      <div style={{ fontSize: 11, color: "var(--nx-text-dim)" }}>{note}</div>
    </div>
  );
  return (
    <div style={{ display: "grid", gap: 14 }} data-testid={testid}>
      <Block items={notObserved} kind="notobserved" state="NOT_OBSERVED"
             title="Searched · not observed"
             note="The capability ran and found nothing. Absence of evidence
                   is not evidence of absence — and it is not a clean
                   verdict." />
      <Block items={unavailable} kind="unavailable" state="NOT_CONFIGURED"
             title="Visibility gaps · telemetry not available"
             note="This telemetry does not reach NivXRay for this tenant, so
                   the question could not be asked at all. Missing telemetry
                   is NOT negative evidence." />
    </div>
  );
}

/* ── the surface ────────────────────────────────────────────────── */
export default function IncidentVerdictExplainability({ incident }) {
  const id = incident?.id;
  const [sum, setSum] = useState(null);
  const [eng, setEng] = useState(null);
  const [engErr, setEngErr] = useState(null);
  const [sumErr, setSumErr] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    let live = true;
    setLoading(true);
    Promise.allSettled([getIncidentSummary(id), getIncidentCausalAnalysis(id)])
      .then(([s, e]) => {
        if (!live) return;
        if (s.status === "fulfilled") setSum(s.value);
        else setSumErr(apiErrorText(s.reason));
        if (e.status === "fulfilled") setEng(e.value);
        else setEngErr(apiErrorText(e.reason));
        setLoading(false);
      });
    return () => { live = false; };
  }, [id]);

  const model = useMemo(() => {
    const v = sum?.deterministic_verdict || null;
    const assoc = eng?.engine_association || {};
    const device = (eng?.verdicts || {}).device || {};
    return {
      verdict: v,
      gaps: sum?.evidence_gaps || [],
      assoc,
      associated: assoc.state === "ASSOCIATED",
      breakdown: device.evidence_breakdown || [],
      reasons: ((eng?.explainability || {}).positive || {}).reasons || [],
      patterns: (eng?.explainability || {}).negative_patterns || [],
      engineBand: device.band || null,
      engineConfidence: device.confidence ?? null,
      engineScore: device.score ?? null,
    };
  }, [sum, eng]);

  if (!id) return null;
  if (loading) {
    return (
      <NxInvSection title="Verdict explainability"
                    testid="incident-verdict-explainability">
        <div className="inv-sec__b--pad"
             data-testid="incident-verdict-explainability-loading">
          <NxSkeleton height={12} />
        </div>
      </NxInvSection>
    );
  }

  const v = model.verdict;
  return (
    <div data-testid="incident-verdict-explainability"
         data-nx-state={model.assoc.state || "NOT_AVAILABLE"}>
      <NxInvSection
        title="Verdict explainability"
        subtitle="what we concluded, why, what limits it, and what we could not see"
        testid="incident-verdict-explainability-sec">
        <div className="inv-sec__b--pad" style={{ display: "grid", gap: 14 }}>
          <div style={{ display: "flex", gap: 10, alignItems: "center",
                        flexWrap: "wrap" }}
               data-testid="incident-verdict-explainability-verdict">
            {v?.label
              ? <NxChip tone={BAND_TONE[String(v.label).toLowerCase()]
                              || "neutral"} variant="filled">
                  {String(v.label).toUpperCase()}
                </NxChip>
              : <NxState value="NOT_EVALUATED" size="sm" />}
            <NxInvMetrics items={[
              { key: "risk", label: "Risk", value: v?.risk_score ?? null },
              { key: "confidence", label: "Confidence",
                value: v?.confidence ?? null,
                absent: ABSENCE.NOT_AVAILABLE },
              { key: "completeness", label: "Analysis completeness",
                value: null,
                absent: ABSENCE.NOT_AVAILABLE,
                sub: "no completeness measure is recorded by the platform" },
              { key: "signals", label: "Contributing signals",
                value: v?.contributing_signals ?? null },
            ]} testid="incident-verdict-explainability-metrics" />
          </div>
          <div style={{ fontSize: 11, color: "var(--nx-text-dim)" }}>
            Confidence is how strongly the evidence supports this conclusion.
            It is <b>not</b> a statement that the analysis is complete — the
            two are independent, and completeness is not derived from
            confidence.
          </div>
          {sumErr && (
            <div data-testid="incident-verdict-explainability-verdict-refused">
              <NxState value="NOT_AUTHORIZED" size="sm" /> {sumErr}
            </div>
          )}
          <NxInvTech label="Technical details"
                     testid="incident-verdict-explainability-tech">
            <div className="mono" style={{ fontSize: 11 }}>
              <div>verdict · {v?.engine || "—"} ({v?.provenance || "—"})</div>
              <div>causal analysis · {model.assoc.state || "—"} via{" "}
                {model.assoc.authority || "—"}</div>
              <div>causal assessment · band {model.engineBand || "—"} ·
                score {model.engineScore ?? "—"} ·
                confidence {model.engineConfidence ?? "—"}</div>
            </div>
          </NxInvTech>
        </div>
      </NxInvSection>

      <NxInvSection title="Why this verdict"
                    subtitle="every reason the engine recorded, with the basis it rests on"
                    testid="incident-verdict-explainability-supports-sec">
        <div className="inv-sec__b--pad">
          {model.associated
            ? <Supports breakdown={model.breakdown} reasons={model.reasons}
                        testid="incident-verdict-explainability-supports" />
            : <div style={{ display: "grid", gap: 8 }}
                   data-testid="incident-verdict-explainability-not-associated">
                <NxState value={engErr ? "NOT_AUTHORIZED" : "NOT_ASSOCIATED"}
                         size="sm" />
                <NxInvEmpty
                  title="Causal explanation not available for this incident"
                  body={engErr || model.assoc.reason
                        || "The causal engine holds no analysis for this incident."}
                  points={["The verdict above stands on its own authority.",
                           "No causal explanation is NOT a benign finding."]}
                  testid="incident-verdict-explainability-not-associated-empty" />
              </div>}
        </div>
      </NxInvSection>

      {model.associated && (
        <NxInvSection
          title="Evidence limiting a stronger conclusion"
          subtitle="the hypotheses the engine itself tests — a behaviour it looked for and did not find"
          testid="incident-verdict-explainability-limits-sec">
          <div className="inv-sec__b--pad">
            {model.patterns.length
              ? model.patterns.map((p) => (
                  <Hypothesis key={p.id} incidentId={id} pattern={p}
                              testid={`incident-verdict-explainability-hypothesis-${p.id}`} />))
              : <NxInvEmpty
                  title="The engine tests no hypothesis for this incident"
                  body="No alternative classification is available to argue against."
                  testid="incident-verdict-explainability-limits-empty" />}
          </div>
        </NxInvSection>
      )}

      <NxInvSection
        title="Visibility and evidence gaps"
        subtitle="what was searched and not found, kept separate from what we cannot see at all"
        testid="incident-verdict-explainability-gaps-sec">
        <div className="inv-sec__b--pad">
          {model.gaps.length
            ? <Gaps gaps={model.gaps}
                    testid="incident-verdict-explainability-gaps" />
            : <NxInvEmpty
                title="No gap is recorded for this incident"
                body="The platform records neither an unmatched search nor a missing telemetry domain for this incident."
                testid="incident-verdict-explainability-gaps-empty" />}
        </div>
      </NxInvSection>
    </div>
  );
}
