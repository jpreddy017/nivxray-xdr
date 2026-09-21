/**
 * IncidentStoryDepth · S3-A.
 *
 * The analytical depth the causal engine already produced, promoted INTO the
 * incident's Story view. This is deliberately NOT the engine workspace
 * embedded again: it answers three analyst questions and then gets out of the
 * way, with the engine's own collapsed panels remaining underneath for the
 * analyst who wants the full instrument.
 *
 *   L1  what happened, in order        → sequential attack milestones
 *                                        + observed attack stages
 *   L2  what it happened to / between  → causal anchor entities
 *                                        + relationship intelligence
 *   L3  why we can say that            → per-row provenance (the exact
 *                                        field each fact was read from)
 *
 * Product laws held here:
 *   · NOT ASSOCIATED ≠ BENIGN. When the server says no causal analysis is
 *     associated with this incident, this surface renders ONE compact state
 *     carrying the server's own reason — no zeros, no empty chart, no empty
 *     attack chain, and no implication that nothing happened.
 *   · A stage with no evidence reads NOT OBSERVED. A missing stage is never
 *     completed to make a tidy kill chain.
 *   · No relationship without evidence: an edge that cites no event is
 *     rendered as DERIVED, visibly, and never as established fact.
 *   · Nothing is computed here that the server did not state. Counts come
 *     from the engine's own `stats`; a fact the engine did not record reads
 *     NOT RECORDED.
 *   · Implementation vocabulary (store names, node ids, edge types, engine
 *     versions) stays under Technical details.
 */
import React, { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvMetrics,
         NxState, NxChip, NxEntity, NxSkeleton, ABSENCE } from "@/xdr/nx";
import { apiErrorText } from "@/xdr/nx/apiError";
import { getIncidentCausalAnalysis } from "@/lib/incidentsApi";
import { pivotsFor } from "./investigationPivots";

/* ── vocabulary ─────────────────────────────────────────────────── */
const TACTIC_LABEL = {
  reconnaissance: "Reconnaissance",
  resource_development: "Resource development",
  initial_access: "Initial access",
  execution: "Execution",
  persistence: "Persistence",
  privilege_escalation: "Privilege escalation",
  defense_evasion: "Defence evasion",
  credential_access: "Credential access",
  discovery: "Discovery",
  lateral_movement: "Lateral movement",
  collection: "Collection",
  command_and_control: "Command and control",
  exfiltration: "Exfiltration",
  impact: "Impact",
};
const tacticLabel = (t) => TACTIC_LABEL[t]
  || String(t || "").replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

/** Engine relationship type → what an analyst reads. */
const REL_LABEL = {
  spawned: "spawned",
  executed_by: "executed by",
  connected_to: "connected to",
  resolved_to: "resolved to",
  wrote: "wrote",
  read: "read",
  loaded: "loaded",
  authenticated_as: "authenticated as",
  hosted_on: "observed on",
  part_of: "part of",
  maps_to: "maps to",
  contributes_to: "contributes to",
  rollup_of: "rolls up",
};
const relLabel = (t) => REL_LABEL[t] || String(t || "related").replace(/_/g, " ");

/** Relationships that describe BEHAVIOUR an analyst investigates. The rest
 *  are structural bookkeeping and are kept, but under a disclosure. */
const BEHAVIOURAL = new Set(["spawned", "executed_by", "connected_to",
                             "resolved_to", "wrote", "read", "loaded",
                             "authenticated_as"]);

/** Engine node types that are real entities. `incident`, `verdict`,
 *  `technique`, `chain` and `event` are analysis objects, not anchors. */
const ANCHOR_TYPES = new Set(["process", "device", "user", "file", "hash",
                              "ip", "domain", "url", "command", "registry",
                              "service", "host"]);

const TONE_BY_SEVERITY = { critical: "critical", high: "high",
                           medium: "medium", low: "low",
                           informational: "neutral", info: "neutral" };

const slug = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-")
  .replace(/^-|-$/g, "").slice(0, 40);

/* ── the honest unavailable state ───────────────────────────────── */
function NotAssociated({ reason, readFrom, testid }) {
  return (
    <div data-testid={testid} data-nx-state="NOT_ASSOCIATED"
         style={{ display: "grid", gap: 8 }}>
      <NxState value="NOT_ASSOCIATED" size="sm" />
      <NxInvEmpty
        title="Causal analysis not available for this incident"
        body={reason || "The causal engine holds no analysis for this incident."}
        points={[
          "This is an absence of engine analysis — NOT a finding that the "
          + "activity was benign, and not a statement that nothing happened.",
          "The incident's own evidence, detections, timeline and response "
          + "record are unaffected and remain authoritative.",
        ]}
        testid={`${testid}-empty`} />
      {readFrom && (
        <NxInvTech label="Technical details" testid={`${testid}-tech`}>
          <div className="mono" style={{ fontSize: 11 }}>
            association read from <b>{readFrom}</b>
          </div>
        </NxInvTech>
      )}
    </div>
  );
}

/* ── L1 · sequential attack milestones ──────────────────────────── */
function Milestones({ story, nodeById, testid }) {
  const [params, setParams] = useSearchParams();
  const focus = params.get("focus");
  const toTimeline = (key) => {
    const next = new URLSearchParams(params);
    next.set("tab", "timeline");
    next.set("focus", key);
    setParams(next);
  };
  if (!story.length) {
    return <NxInvEmpty
      title="No milestone was recorded for this incident"
      body="The causal engine is associated with this incident but recorded no ordered step for it."
      points={["An empty milestone sequence is not a benign verdict."]}
      testid={`${testid}-empty`} />;
  }
  const columns = [
    { key: "n", label: "#", width: "3rem", num: true },
    { key: "what", label: "What happened" },
    { key: "stage", label: "Stage", width: "11rem" },
    { key: "entity", label: "Entity", width: "14rem" },
    { key: "why", label: "Why it is a milestone", width: "15rem" },
    { key: "when", label: "First observed", width: "12rem" },
    { key: "go", label: "", width: "9rem" },
  ];
  const rows = story.map((s, i) => {
    const procs = (s.process_iids || []).map((iid) => nodeById.get(iid))
      .filter(Boolean);
    const first = procs.map((p) => p?.attrs?.first_seen).filter(Boolean)[0];
    const signals = s.signals || [];
    const key = `m-${s.idx ?? i}`;
    return {
      _k: key,
      _s: s,
      _first: first,
      n: (s.idx ?? i) + 1,
      what: s.text || <span className="inv-tb__na">{ABSENCE.NOT_RECORDED}</span>,
      stage: s.tactic
        ? <NxChip tone={TONE_BY_SEVERITY[s.severity] || "neutral"}
                  variant="tinted" size="sm">{tacticLabel(s.tactic)}</NxChip>
        : <span className="inv-tb__na">{ABSENCE.NOT_ATTRIBUTED}</span>,
      entity: procs.length
        ? <NxEntity kind="process" value={procs[0].label}
                    secondary={procs.length > 1
                      ? `+${procs.length - 1} more` : null} />
        : <span className="inv-tb__na">{ABSENCE.NOT_ATTRIBUTED}</span>,
      why: signals.length
        ? <span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
            {signals.map((g) => (
              <NxChip key={g} tone="suspicious" variant="tinted" size="sm">
                {String(g).toLowerCase().replace(/_/g, " ")}
              </NxChip>
            ))}
          </span>
        : <span className="inv-tb__na">{ABSENCE.NOT_RECORDED}</span>,
      when: first || <span className="inv-tb__na">{ABSENCE.NOT_RECORDED}</span>,
      go: (
        <button type="button" className="nx-dt-btn"
                data-testid={`${testid}-to-timeline-${key}`}
                onClick={(e) => { e.stopPropagation(); toTimeline(key); }}>
          Show on timeline
        </button>),
    };
  });
  return (
    <NxInvTable columns={columns} rows={rows} rowKey={(r) => r._k}
                testid={testid} openKey={focus || undefined}
                detail={(r) => (
                  <div style={{ display: "grid", gap: 6, fontSize: 11.5 }}
                       data-testid={`${testid}-prov-${r.n}`}>
                    <div>
                      <b>Supporting evidence</b>{" "}
                      {(r._s.frame_iids || []).length
                        ? `${r._s.frame_iids.length} recorded event frame(s)`
                        : ABSENCE.NOT_RECORDED}
                      {r._s.evidence_ref
                        ? ` · ${r._s.evidence_ref}` : ""}
                    </div>
                    <NxInvTech label="Technical details">
                      <div className="mono" style={{ fontSize: 11 }}>
                        <div>step · story[{r._s.idx}]</div>
                        <div>stage · story[].tactic = {String(r._s.tactic)}</div>
                        <div>signals · story[].signals</div>
                        <div>event frames · story[].frame_iids =
                          {" "}{(r._s.frame_iids || []).join(", ") || "—"}</div>
                        <div>entities · story[].process_iids =
                          {" "}{(r._s.process_iids || []).join(", ") || "—"}</div>
                        <div>first observed · read from the cited entity's
                          {" "}first_seen ={" "}{r._first || "NOT RECORDED"}</div>
                      </div>
                    </NxInvTech>
                  </div>
                )} />
  );
}

/* ── L1b · observed attack stages ───────────────────────────────── */
function Stages({ killChain, testid }) {
  if (!killChain.length) return null;
  const covered = killChain.filter((k) => k.covered).length;
  return (
    <div style={{ display: "grid", gap: 8 }} data-testid={testid}>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {killChain.map((k) => (
          <span key={k.tactic} data-testid={`${testid}-${slug(k.tactic)}`}
                data-covered={k.covered ? "true" : "false"}
                title={k.covered
                  ? `${(k.techniques || []).join(", ")}`
                  : "No evidence places this incident in this stage"}>
            <NxChip tone={k.covered ? "suspicious" : "not_connected"}
                    variant={k.covered ? "tinted" : "dashed"} size="sm">
              {tacticLabel(k.tactic)}
              {k.covered && (k.techniques || []).length
                ? ` · ${k.techniques.join(", ")}` : ""}
            </NxChip>
          </span>
        ))}
      </div>
      <div style={{ fontSize: 11, color: "var(--nx-text-dim)" }}>
        {covered} of {killChain.length} stages are placed by evidence. A stage
        drawn dashed is <b>NOT OBSERVED</b> — it is not a statement that the
        activity did not happen, only that no evidence places this incident
        there.
      </div>
    </div>
  );
}

/* ── L2 · causal anchor entities ────────────────────────────────── */
function Anchors({ anchors, unnamed, incident, testid }) {
  const navigate = useNavigate();
  if (!anchors.length) {
    return <NxInvEmpty
      title="No causal anchor entity was recorded"
      body="The causal analysis for this incident cites no entity of a class this console can anchor on."
      testid={`${testid}-empty`} />;
  }
  const columns = [
    { key: "entity", label: "Anchor", width: "22rem" },
    { key: "cls", label: "Class", width: "8rem" },
    { key: "rel", label: "Relationships", width: "8rem", num: true },
    { key: "first", label: "First observed", width: "12rem" },
    { key: "pivots", label: "Investigate" },
  ];
  const rows = anchors.map((a) => ({
    _k: a.id,
    entity: <NxEntity kind={a.kind} value={a.label}
                      testid={`${testid}-entity-${slug(a.label)}`} />,
    cls: a.kind,
    rel: a.degree,
    first: a.first_seen
      || <span className="inv-tb__na">{ABSENCE.NOT_RECORDED}</span>,
    pivots: a.pivots.length
      ? <span style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {a.pivots.map((p) => (
            <button key={p.to} type="button" className="inv-chip"
                    title={p.why}
                    data-testid={`${testid}-pivot-${slug(a.label)}-${slug(p.label)}`}
                    onClick={() => navigate(p.to)}>
              {p.label}
            </button>
          ))}
        </span>
      : <span className="inv-tb__na">{ABSENCE.NOT_AVAILABLE}</span>,
  }));
  return (
    <div style={{ display: "grid", gap: 8 }}>
      <NxInvTable columns={columns} rows={rows} rowKey={(r) => r._k}
                  testid={testid} />
      {unnamed > 0 && (
        <div style={{ fontSize: 11, color: "var(--nx-text-dim)" }}
             data-testid={`${testid}-unnamed`}>
          {unnamed} anchor node(s) carry no recorded identity of their own and
          are not rendered as named entities — an anchor is never given a
          borrowed name.
        </div>
      )}
    </div>
  );
}

/* ── L2b · relationship intelligence ────────────────────────────── */
function Relationships({ edges, testid }) {
  if (!edges.length) {
    return <NxInvEmpty
      title="No relationship was recorded"
      body="The causal analysis for this incident records no relationship between entities."
      testid={`${testid}-empty`} />;
  }
  const behavioural = edges.filter((e) => e.behavioural);
  const structural = edges.filter((e) => !e.behavioural);
  const Row = ({ e, i, kind }) => (
    <div key={`${kind}-${i}`}
         data-testid={`${testid}-${kind}-${i}`}
         data-nx-state={e.evidence ? "EVIDENCE_CITED" : "ENGINE_DERIVED"}
         style={{ display: "flex", alignItems: "center", gap: 8,
                  flexWrap: "wrap", padding: "5px 0",
                  borderBottom: "1px solid var(--nx-divider)" }}>
      <NxEntity kind={e.sourceKind} value={e.sourceLabel} />
      <span style={{ fontSize: 11, color: "var(--nx-text-dim)" }}>
        —{relLabel(e.type)}→
      </span>
      <NxEntity kind={e.targetKind} value={e.targetLabel} />
      <NxState value={e.evidence ? "EVIDENCE_CITED" : "ENGINE_DERIVED"}
               size="sm" />
    </div>
  );
  return (
    <div style={{ display: "grid", gap: 8 }} data-testid={testid}>
      {behavioural.length > 0
        ? behavioural.map((e, i) => <Row key={`b${i}`} e={e} i={i} kind="rel" />)
        : (
          <div style={{ fontSize: 11.5, color: "var(--nx-text-dim)" }}
               data-testid={`${testid}-no-behavioural`}>
            No behavioural relationship (spawn · connect · write · load ·
            authenticate) is recorded for this incident. The relationships
            below are structural.
          </div>
        )}
      <div style={{ fontSize: 11, color: "var(--nx-text-dim)" }}>
        A relationship marked <b>Derived · no event cited</b> is the engine's
        own inference and is not rendered as established fact.
      </div>
      {structural.length > 0 && (
        <NxInvTech label={`Structural relationships (${structural.length})`}
                   testid={`${testid}-structural`}>
          {structural.map((e, i) => <Row key={`s${i}`} e={e} i={i}
                                         kind="struct" />)}
        </NxInvTech>
      )}
    </div>
  );
}

/* ── the surface ────────────────────────────────────────────────── */
export default function IncidentStoryDepth({ incident }) {
  const id = incident?.id;
  const [data, setData] = useState(null);
  const [state, setState] = useState("loading");
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!id) return;
    let live = true;
    setState("loading");
    getIncidentCausalAnalysis(id)
      .then((d) => { if (live) { setData(d); setState("ready"); } })
      .catch((e) => {
        if (!live) return;
        setError(apiErrorText(e));
        setState("error");
      });
    return () => { live = false; };
  }, [id]);

  const model = useMemo(() => {
    if (!data) return null;
    const ikg = data.ikg || {};
    const nodes = ikg.nodes || [];
    const edges = ikg.edges || [];
    const nodeById = new Map(nodes.map((n) => [n.id, n]));
    const degree = new Map();
    edges.forEach((e) => {
      degree.set(e.source, (degree.get(e.source) || 0) + 1);
      degree.set(e.target, (degree.get(e.target) || 0) + 1);
    });

    // an anchor whose label is the case id carries no identity of its own
    const caseId = data.case_id;
    let unnamed = 0;
    const anchors = [];
    nodes.forEach((n) => {
      if (!ANCHOR_TYPES.has(n.type)) return;
      if (!n.label || n.label === caseId) { unnamed += 1; return; }
      const kind = n.type === "host" ? "device" : n.type;
      anchors.push({
        id: n.id, kind, label: n.label,
        degree: degree.get(n.id) || 0,
        first_seen: n.attrs?.first_seen || null,
        pivots: pivotsFor({ kind, value: n.label, id: n.id }, incident),
      });
    });
    anchors.sort((a, b) => b.degree - a.degree);

    const isEvent = (nid) => (nodeById.get(nid)?.type === "event");
    const rel = edges.map((e) => {
      const s = nodeById.get(e.source);
      const t = nodeById.get(e.target);
      const cited = isEvent(e.source) || isEvent(e.target)
        || Object.keys(e.attrs || {}).some((k) =>
             /evid|frame|event|observ/i.test(k));
      return {
        type: e.type,
        behavioural: BEHAVIOURAL.has(e.type),
        evidence: cited,
        sourceKind: s?.type === "host" ? "device" : (s?.type || "unknown"),
        targetKind: t?.type === "host" ? "device" : (t?.type || "unknown"),
        sourceLabel: (s?.label && s.label !== caseId) ? s.label : s?.type,
        targetLabel: (t?.label && t.label !== caseId) ? t.label : t?.type,
      };
    });
    rel.sort((a, b) => (b.behavioural - a.behavioural)
                       || (b.evidence - a.evidence));

    return {
      assoc: data.engine_association || {},
      story: [...(data.story || [])].sort((a, b) => (a.idx ?? 0) - (b.idx ?? 0)),
      killChain: (data.attack_mapping || {}).kill_chain || [],
      nodeById, anchors, unnamed, rel,
      stats: ikg.stats || {},
      engineVersion: data.engine_version || {},
    };
  }, [data, incident]);

  if (!id) return null;

  if (state === "loading") {
    return (
      <NxInvSection title="Causal analysis"
                    subtitle="milestones · anchors · relationships"
                    testid="incident-story-depth">
        <div className="inv-sec__b--pad"
             data-testid="incident-story-depth-loading">
          <NxSkeleton height={12} />
          <NxSkeleton height={12} style={{ marginTop: 8, width: "70%" }} />
        </div>
      </NxInvSection>
    );
  }

  if (state === "error") {
    return (
      <NxInvSection title="Causal analysis" testid="incident-story-depth">
        <div className="inv-sec__b--pad">
          <div data-testid="incident-story-depth-refused"
               style={{ display: "grid", gap: 8 }}>
            <NxState value="NOT_AUTHORIZED" size="sm" />
            <NxInvEmpty
              title="Causal analysis could not be read for this incident"
              body={error}
              points={["This is a refusal or an error — not a finding about "
                       + "the incident."]}
              testid="incident-story-depth-refused-empty" />
          </div>
        </div>
      </NxInvSection>
    );
  }

  const assocState = model.assoc.state || null;
  if (assocState !== "ASSOCIATED") {
    return (
      <NxInvSection title="Causal analysis"
                    subtitle="the engine's own statement about this incident"
                    testid="incident-story-depth">
        <div className="inv-sec__b--pad">
          <NotAssociated reason={model.assoc.reason}
                         readFrom={model.assoc.read_from}
                         testid="incident-story-depth-not-associated" />
        </div>
      </NxInvSection>
    );
  }

  const stats = model.stats;
  const citedEdges = model.rel.filter((e) => e.evidence).length;

  return (
    <div data-testid="incident-story-depth" data-nx-state={assocState}>
      <NxInvSection
        title="Attack milestones"
        subtitle="the ordered steps the causal analysis recorded for this incident"
        actions={<NxState value="ASSOCIATED" size="sm" />}
        testid="incident-story-depth-milestones-sec">
        <div className="inv-sec__b--pad" style={{ display: "grid", gap: 12 }}>
          <NxInvMetrics items={[
            { key: "milestones", label: "Milestones",
              value: model.story.length },
            { key: "entities", label: "Entities", value: stats.nodes ?? null },
            { key: "relationships", label: "Relationships",
              value: stats.edges ?? null },
            { key: "cited", label: "Evidence-cited relationships",
              value: citedEdges },
          ]} testid="incident-story-depth-metrics" />
          <Milestones story={model.story} nodeById={model.nodeById}
                      testid="incident-story-depth-milestones" />
          <Stages killChain={model.killChain}
                  testid="incident-story-depth-stages" />
        </div>
      </NxInvSection>

      <NxInvSection
        title="Causal anchors"
        subtitle="the entities this analysis is anchored on — pivot where the platform can honestly offer one"
        testid="incident-story-depth-anchors-sec">
        <div className="inv-sec__b--pad">
          <Anchors anchors={model.anchors} unnamed={model.unnamed}
                   incident={incident}
                   testid="incident-story-depth-anchors" />
        </div>
      </NxInvSection>

      <NxInvSection
        title="Relationship intelligence"
        subtitle="how those entities relate, and whether an event was cited for it"
        testid="incident-story-depth-relationships-sec">
        <div className="inv-sec__b--pad" style={{ display: "grid", gap: 10 }}>
          <Relationships edges={model.rel}
                         testid="incident-story-depth-relationships" />
          <NxInvTech label="Technical details"
                     testid="incident-story-depth-tech">
            <div className="mono" style={{ fontSize: 11 }}>
              <div>association · {assocState} via{" "}
                {model.assoc.authority} (read from {model.assoc.read_from})</div>
              <div>entities by class ·{" "}
                {JSON.stringify(stats.by_node_type || {})}</div>
              <div>relationships by type ·{" "}
                {JSON.stringify(stats.by_edge_type || {})}</div>
              <div>engine versions · {JSON.stringify(model.engineVersion)}</div>
            </div>
          </NxInvTech>
        </div>
      </NxInvSection>
    </div>
  );
}
