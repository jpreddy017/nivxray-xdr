/**
 * Timeline · the investigation timeline.
 *
 * ONE chronological table over every authoritative time-bearing fact this
 * platform holds for the incident:
 *
 *   · reconstructed attack milestones  (`GET /api/incidents/{id}/attack-story`)
 *   · lifecycle transitions            (`incident.state_history`)
 *   · observed evidence events         (`…/trajectory/device` frames · S3-C)
 *   · causal attack milestones         (causal analysis `story[]` · S3-C)
 *
 * Nothing is merged that does not carry its own timestamp, and no row is
 * synthesised to make the timeline look busier. Device Trajectory is
 * mounted underneath this tab as engine depth by the workspace, so the
 * analyst never leaves the investigation to replay the endpoint.
 *
 * Time fidelity: activity time, sensor observation time and ingestion time
 * are DIFFERENT facts. Where a record carries more than one they are
 * reported separately in the expanded row and never flattened.
 *
 * S3-C · a causal milestone has NO clock of its own. It is positioned by the
 * ACTIVITY TIME of the evidence event it cites, and that is stated in the
 * row. A milestone citing no time-bearing evidence is NOT given the nearest
 * timestamp to make it fit — it is listed, unpositioned, underneath the
 * chronology. Ingest time is never shown as activity time.
 */
import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import ActivityTab from "@/components/incidents/tabs/ActivityTab";
import EvidenceInspector from "@/xdr/components/EvidenceInspector";
import api from "@/lib/api";
import { getIncidentCausalAnalysis,
         getIncidentDeviceTrajectory } from "@/lib/incidentsApi";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvFilters, NxInvTech,
  NxInvValue, NxChip, NxState, ABSENCE, fmtTime,
} from "@/xdr/nx";
import { apiErrorText } from "@/xdr/nx/apiError";

const CATEGORIES = [
  { key: "process",   label: "Process",   match: /process|exec|command|parent|child/i },
  { key: "file",      label: "File",      match: /file|artifact|hash|write|drop/i },
  { key: "network",   label: "Network",   match: /network|dns|http|c2|beacon|socket|ip/i },
  { key: "registry",  label: "Registry",  match: /registry|regkey|persistence/i },
  { key: "identity",  label: "Identity",  match: /identity|user|account|logon|credential|privilege/i },
  { key: "system",    label: "System",    match: /system|service|driver|boot|wmi|scheduled/i },
  { key: "lifecycle", label: "Lifecycle", match: /^lifecycle$/i },
];

function categorise(text, explicit) {
  if (explicit) {
    const hit = CATEGORIES.find((c) => c.key === String(explicit).toLowerCase());
    if (hit) return hit.key;
  }
  const hay = String(text || "");
  const hit = CATEGORIES.find((c) => c.key !== "lifecycle" && c.match.test(hay));
  return hit ? hit.key : null;
}

const LANE_CATEGORY = { process: "process", file: "file", network: "network",
                        registry: "registry", user: "identity",
                        identity: "identity", system: "system",
                        service: "system" };

const TACTIC_LABEL = (t) => String(t || "").replace(/_/g, " ")
  .replace(/^./, (c) => c.toUpperCase());

export default function TimelineTab({ incident }) {
  const [story, setStory] = useState(null);
  const [storyErr, setStoryErr] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState([]);
  const [params, setParams] = useSearchParams();
  const focus = params.get("focus");

  // S3-C · the causal analysis and the evidence frames it cites.
  const [causal, setCausal] = useState(null);
  const [frames, setFrames] = useState(null);
  const [causalErr, setCausalErr] = useState(null);

  useEffect(() => {
    if (!incident?.id) return undefined;
    let live = true;
    setCausalErr(null);
    Promise.allSettled([getIncidentCausalAnalysis(incident.id),
                        getIncidentDeviceTrajectory(incident.id)])
      .then(([c, t]) => {
        if (!live) return;
        if (c.status === "fulfilled") setCausal(c.value);
        else setCausalErr(apiErrorText(c.reason));
        if (t.status === "fulfilled") setFrames(t.value);
      });
    return () => { live = false; };
  }, [incident?.id]);

  useEffect(() => {
    if (!incident?.id) return undefined;
    let live = true;
    setLoading(true); setStoryErr(null);
    api.get(`/incidents/${encodeURIComponent(incident.id)}/attack-story`)
      .then(({ data }) => { if (live) setStory(data); })
      .catch((e) => {
        if (live) setStoryErr(e?.response?.data?.detail?.reason
          || apiErrorText(e, "unavailable"));
      })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [incident?.id]);

  const associated = (causal?.engine_association || {}).state === "ASSOCIATED";

  /** S3-C · frame_iid → the frame's own authoritative clocks. */
  const frameById = useMemo(() => {
    const m = new Map();
    (frames?.frames || []).forEach((f) => m.set(f.frame_iid, f));
    return m;
  }, [frames]);

  const { rows, unpositioned } = useMemo(() => {
    const out = [];
    const orphanMilestones = [];
    const steps = story?.steps || story?.story?.steps
      || incident?.attack_story?.steps || [];
    steps.forEach((s, i) => {
      const activity = s.summary || s.title || s.stage || s.description;
      out.push({
        id: `step-${i}`,
        at: s.time || s.timestamp || s.at || s.observed_at || null,
        observed_at: s.observed_at || null,
        ingested_at: s.ingested_at || null,
        entity: s.entity || s.host || s.process || s.device || null,
        activity,
        category: categorise(`${s.stage} ${activity}`, s.category || s.lane),
        source: s.source || s.detection_source || story?.engine || null,
        detection: s.technique || s.rule_id || null,
        evidence: s.evidence_id || s.evidence_ref
          || (Array.isArray(s.evidence_ids) ? s.evidence_ids.join(", ") : null),
        kind: "Attack milestone",
        raw: s,
      });
    });

    // ── S3-C · observed evidence events (each carries its own clocks) ──
    (frames?.frames || []).forEach((f) => {
      const p = f.provenance || {};
      out.push({
        id: `fr-${f.frame_iid}`,
        at: f.ts || null,
        observed_at: p.sensor_observed_at || p.observed_at || null,
        ingested_at: p.ingested_at || null,
        entity: f.process?.label || f.device?.label || f.user?.label || null,
        activity: f.label || f.action || null,
        category: LANE_CATEGORY[f.lane] || categorise(f.label, f.lane),
        source: p.source || p.origin || null,
        detection: (f.mitre || []).join(", ") || null,
        evidence: (f.evidence_ids || []).join(", ") || null,
        kind: "Observed event",
        rowKind: "event",
        frame: f,
        raw: f,
      });
    });

    // ── S3-C · causal milestones, positioned by the CITED event's time ──
    if (associated) {
      ((causal?.story) || []).forEach((s, i) => {
        const cited = (s.frame_iids || []).map((iid) => frameById.get(iid))
          .filter(Boolean);
        const times = cited.map((f) => f.ts).filter(Boolean).sort();
        const anchorFrame = cited.find((f) => f.ts === times[0]) || cited[0]
          || null;
        const p = anchorFrame?.provenance || {};
        const row = {
          id: `m-${s.idx ?? i}`,
          at: times[0] || null,
          timeFrom: times[0]
            ? `activity time of the cited evidence event ${anchorFrame.frame_iid}`
            : null,
          observed_at: p.sensor_observed_at || p.observed_at || null,
          ingested_at: p.ingested_at || null,
          entity: anchorFrame?.process?.label || null,
          activity: s.text || null,
          category: anchorFrame
            ? (LANE_CATEGORY[anchorFrame.lane] || null)
            : categorise(s.text, null),
          source: p.source || null,
          detection: (s.signals || []).join(", ") || null,
          evidence: (s.frame_iids || []).join(", ") || null,
          kind: "Causal milestone",
          rowKind: "milestone",
          tactic: s.tactic || null,
          citedFrames: cited,
          frameIids: s.frame_iids || [],
          raw: s,
        };
        if (row.at) out.push(row);
        else orphanMilestones.push(row);
      });
    }

    (incident?.state_history || []).forEach((h, i) => {
      out.push({
        id: `lc-${i}`,
        at: h.at || h.ts || null,
        entity: h.by || h.actor || null,
        activity: `Incident moved ${h.from || "—"} → ${h.to || "—"}`,
        category: "lifecycle",
        source: "Analyst action",
        detection: null,
        evidence: null,
        note: h.note || h.reason || null,
        kind: "Lifecycle transition",
        raw: h,
      });
    });
    out.sort((a, b) => {
      const ta = Date.parse(a.at || "") || 0;
      const tb = Date.parse(b.at || "") || 0;
      return tb - ta;
    });
    return { rows: out, unpositioned: orphanMilestones };
  }, [story, incident, causal, frames, frameById, associated]);

  const counts = useMemo(() => {
    const c = {};
    rows.forEach((r) => { if (r.category) c[r.category] = (c[r.category] || 0) + 1; });
    return c;
  }, [rows]);

  const visible = filters.length === 0
    ? rows : rows.filter((r) => filters.includes(r.category));

  // S3-C · a milestone handed over from the Story view is expanded by
  // `openKey` — bring it into view as well.
  useEffect(() => {
    if (!focus || !rows.length) return;
    const el = document.querySelector('[data-focus="true"]');
    if (el) el.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [focus, rows.length]);

  const columns = [
    { key: "at", label: "Time", width: 158,
      render: (r) => <NxInvValue value={fmtTime(r.at)} mono
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "entity", label: "Entity", width: 190,
      render: (r) => <NxInvValue value={r.entity} mono
                                 absent={ABSENCE.NOT_ATTRIBUTED} /> },
    { key: "activity", label: "Activity",
      render: (r) => (r.rowKind === "milestone"
        ? (
          <div style={{ display: "grid", gap: 3 }}
               data-testid={`inv-timeline-milestone-${r.id}`}>
            <span style={{ display: "flex", gap: 6, alignItems: "center",
                           flexWrap: "wrap" }}>
              <NxChip tone="suspicious" variant="filled" size="sm">
                ATTACK MILESTONE{r.tactic ? ` · ${TACTIC_LABEL(r.tactic)}` : ""}
              </NxChip>
              <button type="button" className="nx-dt-btn"
                      data-testid={`inv-timeline-to-story-${r.id}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        const next = new URLSearchParams(params);
                        next.set("tab", "story");
                        next.set("focus", r.id);
                        setParams(next);
                      }}>
                Show in story
              </button>
            </span>
            <NxInvValue value={r.activity} absent={ABSENCE.NOT_RECORDED} />
          </div>)
        : <NxInvValue value={r.activity} absent={ABSENCE.NOT_RECORDED} />) },
    { key: "category", label: "Category", width: 92,
      render: (r) => (r.category
        ? (CATEGORIES.find((c) => c.key === r.category)?.label || r.category)
        : <span className="inv-tb__na">NOT CATEGORISED</span>) },
    { key: "source", label: "Source", width: 150,
      render: (r) => <NxInvValue value={r.source} mono
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "detection", label: "Detection", width: 110,
      render: (r) => <NxInvValue value={r.detection} mono
                                 absent={ABSENCE.NOT_OBSERVED} /> },
    { key: "evidence", label: "Evidence", width: 130,
      render: (r) => <NxInvValue value={r.evidence} mono
                                 absent={ABSENCE.EVIDENCE_INCOMPLETE} /> },
  ];

  const detail = (r) => (
    <div style={{ display: "grid", gap: 8 }}>
      <dl className="inv-kv">
        <dt>Record</dt><dd>{r.kind}</dd>
        <dt>Activity time</dt>
        <dd className="mono"><NxInvValue value={fmtTime(r.at)}
                                         absent={ABSENCE.NOT_RECORDED} /></dd>
        {r.rowKind === "milestone" && (
          <>
            <dt>Position</dt>
            <dd data-testid={`inv-timeline-timebasis-${r.id}`}>
              {r.timeFrom
                ? `A milestone has no clock of its own — it is positioned by the ${r.timeFrom}.`
                : "No time-bearing evidence is cited. This milestone is NOT placed in the chronology."}
            </dd>
          </>
        )}
        <dt>Sensor observed</dt>
        <dd className="mono"><NxInvValue value={fmtTime(r.observed_at)}
                                         absent={ABSENCE.NOT_RECORDED} /></dd>
        <dt>Ingested</dt>
        <dd className="mono"><NxInvValue value={fmtTime(r.ingested_at)}
                                         absent={ABSENCE.NOT_RECORDED} /></dd>
        {r.note && <><dt>Note</dt><dd>{r.note}</dd></>}
        <dt>Evidence reference</dt>
        <dd className="mono"><NxInvValue value={r.evidence}
                                         absent={ABSENCE.EVIDENCE_INCOMPLETE} /></dd>
        {(r.frame?.provenance || r.citedFrames?.[0]?.provenance) && (
          <>
            <dt>Evidence chain</dt>
            <dd className="mono" style={{ fontSize: 11 }}>
              {(() => {
                const f = r.frame || r.citedFrames?.[0];
                const p = f.provenance || {};
                return [
                  `event ${f.frame_iid}`,
                  (f.evidence_ids || []).length
                    ? `canonical ${f.evidence_ids.join(", ")}` : null,
                  p.normalizer ? `normalizer ${p.normalizer}` : null,
                  p.source ? `source ${p.source}` : null,
                  p.origin ? `origin ${p.origin}` : null,
                  p.ingest_job_id ? `ingest job ${p.ingest_job_id}` : null,
                ].filter(Boolean).join("  →  ");
              })()}
            </dd>
          </>
        )}
      </dl>
      {r.rowKind === "milestone" && r.citedFrames?.length > 0 && (
        <div data-testid={`inv-timeline-inspect-${r.id}`}>
          <EvidenceInspector incidentId={incident?.id} kind="event"
                             refId={r.citedFrames[0].frame_iid} embedded />
        </div>
      )}
    </div>
  );

  return (
    <div className="inv" data-testid="xdr-record-timeline">
      <NxInvSection
        title="Investigation timeline"
        subtitle={loading ? "reading the authoritative records…"
          : `${visible.length} of ${rows.length} record(s)`}
        testid="inv-timeline">
        <NxInvFilters testid="inv-timeline-filters" active={filters}
                      onChange={setFilters}
                      options={CATEGORIES.map((c) => ({ key: c.key,
                        label: c.label, count: counts[c.key] || 0 }))} />
        <NxInvTable testid="inv-timeline-table" columns={columns}
                    rows={visible} rowKey={(r) => r.id} detail={detail}
                    openKey={focus || undefined}
                    empty={
                      <NxInvEmpty
                        testid="inv-timeline-empty"
                        title={rows.length === 0
                          ? "No time-stamped activity has been established for this incident"
                          : "No record matches the selected categories"}
                        body={rows.length === 0
                          ? "A timeline is built only from records that carry their own timestamp. This incident has neither a reconstructed attack sequence nor a recorded lifecycle transition yet."
                          : "Clear the category filters to see every record."}
                        points={rows.length === 0 ? [
                          "Device Trajectory below replays the endpoint event stream when an endpoint identity is bound to this incident.",
                          "Evidence that carries no time is reported under the Evidence tab, not invented here.",
                        ] : []} />
                    } />
        <NxInvTech label="Technical details · timeline sources"
                   testid="inv-timeline-tech">
          <dl className="inv-kv">
            <dt>Attack-story read</dt>
            <dd className="mono">
              GET /api/incidents/{incident?.id}/attack-story
              {storyErr ? ` — ${typeof storyErr === "object"
                ? JSON.stringify(storyErr) : storyErr}` : " — ok"}
            </dd>
            <dt>Causal milestones</dt>
            <dd className="mono">
              causal analysis · {(causal?.engine_association || {}).state
                || "not read"}
              {causalErr ? ` — ${causalErr}` : ""} ·{" "}
              {((causal?.story) || []).length} milestone(s)
            </dd>
            <dt>Evidence events</dt>
            <dd className="mono">
              device trajectory frames · {(frames?.frames || []).length} frame(s)
              · each positioned by its own <b>ts</b>, with
              provenance.ingested_at reported separately
            </dd>
            <dt>Lifecycle read</dt>
            <dd className="mono">
              incident.state_history · {(incident?.state_history || []).length} entry(ies)
            </dd>
          </dl>
        </NxInvTech>
      </NxInvSection>

      {unpositioned.length > 0 && (
        <NxInvSection
          title="Milestones with no authoritative activity time"
          subtitle="recorded by the causal analysis, deliberately NOT placed in the chronology"
          testid="inv-timeline-unpositioned-sec">
          <div className="inv-sec__b--pad" style={{ display: "grid", gap: 8 }}>
            {unpositioned.map((r) => (
              <div key={r.id} data-testid={`inv-timeline-unpositioned-${r.id}`}
                   style={{ display: "flex", gap: 8, alignItems: "baseline",
                            flexWrap: "wrap", fontSize: 11.5 }}>
                <NxState value="NOT_RECORDED" size="sm" />
                <NxChip tone="suspicious" variant="tinted" size="sm">
                  {r.tactic ? TACTIC_LABEL(r.tactic) : "Milestone"}
                </NxChip>
                <span>{r.activity || ABSENCE.NOT_RECORDED}</span>
              </div>))}
            <div style={{ fontSize: 11, color: "var(--nx-text-dim)" }}>
              These milestones cite no time-bearing evidence. NivXRay will not
              borrow the nearest event's timestamp to make them fit, and it
              will not present an ingestion time as an activity time.
            </div>
          </div>
        </NxInvSection>
      )}

      <NxInvSection title="Canonical activity inventory"
                    subtitle="every observation NivXRay holds for the entities in this incident"
                    testid="xdr-record-timeline-activity">
        <div className="inv-sec__b--pad">
          <ActivityTab incident={incident} />
        </div>
      </NxInvSection>
    </div>
  );
}
