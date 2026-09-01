/**
 * MitreTabV2 · Round 29 (Round 24.9 grammar).
 * ---------------------------------------------------------------
 * The migrated MITRE surface.  Renders ONLY what the incident's
 * evidence substantiates — never what ATT&CK says could have
 * happened.
 *
 * Data source (unchanged):
 *   GET /admin/content-supply-chain/incidents/:id/attack-chain-graph
 *
 * This surface is a PROJECTION of the incident/evidence model.  It
 * MUST NOT introduce its own intelligence — the traversal chain
 * (Canonical → Correlation → Mapping) is what the tab renders.  If
 * a layer is not present in the collected evidence, the layer is
 * explicitly marked absent, never fabricated.
 *
 * Composition contract:
 *   <Entity>        → the observed technique (kind="rule")
 *   <EvidenceState> → confidence truth-state (closed enum)
 *   <Provenance>    → derivation chain per technique
 *   <Relationship>  → witnessed edge between two techniques
 *                     (parent → sub-technique, shared entity/evidence)
 *   <Action>        → open on attack.mitre.org (external reference)
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCcw, ExternalLink } from "lucide-react";

import api from "@/lib/api";
import Entity from "@/xdr/design/Entity";
import EvidenceState from "@/xdr/design/EvidenceState";
import Provenance from "@/xdr/design/Provenance";
import Relationship from "@/xdr/design/Relationship";
import Action, { ActionGroup } from "@/xdr/design/Action";
import "@/xdr/design/tokens.css";


/** Map the backend's confidence enum → closed EvidenceState value.
 *
 *   CONFIRMED             → observed   (evidence witnessed the technique)
 *   SUPPORTED             → supported  (corroborated but not direct)
 *   INSUFFICIENT_EVIDENCE → missing    (partial signal, not enough)
 *   NOT_OBSERVED          → unavailable (explicitly absent from evidence)
 *   UNKNOWN               → missing    (state itself is unknown)
 */
function stateForConfidence(conf) {
  switch (conf) {
    case "CONFIRMED":              return { state: "observed",    reason: null };
    case "SUPPORTED":              return { state: "supported",   reason: null };
    case "INSUFFICIENT_EVIDENCE":  return { state: "missing",     reason: "INSUFFICIENT_EVIDENCE" };
    case "NOT_OBSERVED":           return { state: "unavailable", reason: "NOT_OBSERVED" };
    default:                        return { state: "missing",     reason: String(conf || "UNKNOWN") };
  }
}


/** Parent technique id for a sub-technique node.  `T1059.003` → `T1059`.
 *  Returns null when the node id has no sub-technique component. */
function parentTechniqueId(id) {
  if (!id || typeof id !== "string") return null;
  const dot = id.indexOf(".");
  return dot > 0 ? id.slice(0, dot) : null;
}


/** Build the per-technique provenance chain from a node's traversal chain.
 *  Never fabricates a layer — a missing layer is `present: false`. */
function chainForNode(n) {
  const t = n?.traversal_chain || {};
  const telemetry = (n.telemetry_sources && n.telemetry_sources.length)
    ? n.telemetry_sources.join(", ")
    : null;
  const canonical = t.canonical_event_id
    || (Array.isArray(n.source_refs) && n.source_refs[0]) || null;
  const correlate = (Array.isArray(t.correlation_match_ids)
                        && t.correlation_match_ids.length)
    ? `${t.correlation_match_ids.length} match(es)` : null;
  const mapping = n.id || null;   // the MITRE technique id itself
  return [
    { layer: "telemetry", value: telemetry,  present: !!telemetry },
    { layer: "canonical", value: canonical,  present: !!canonical },
    { layer: "correlate", value: correlate,  present: !!correlate },
    { layer: "mapping",   value: mapping,    present: !!mapping },
  ];
}


export default function MitreTabV2({ incident }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr]         = useState(null);

  const load = useCallback(async () => {
    if (!incident?.id) return;
    setLoading(true); setErr(null);
    try {
      const r = await api.get(
        `/admin/content-supply-chain/incidents/${incident.id}/attack-chain-graph`);
      setData(r.data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "unavailable");
    } finally { setLoading(false); }
  }, [incident?.id]);

  useEffect(() => { load(); }, [load]);

  // Only render nodes whose confidence is evidence-backed.  UNKNOWN /
  // NOT_OBSERVED nodes are counted, not drawn — otherwise the surface
  // would fabricate "coverage" from mere hypothesis.
  const nodes = Array.isArray(data?.nodes) ? data.nodes : [];
  const edges = Array.isArray(data?.edges) ? data.edges : [];
  const evidenceBacked = useMemo(() => nodes.filter(
    (n) => n.confidence === "CONFIRMED" || n.confidence === "SUPPORTED"
        || n.confidence === "INSUFFICIENT_EVIDENCE"), [nodes]);
  const suppressed = nodes.length - evidenceBacked.length;

  // Index for looking up entity blocks when rendering relationships.
  const byId = useMemo(() => {
    const m = {};
    nodes.forEach((n) => { m[n.id] = n; });
    return m;
  }, [nodes]);

  // Sub-technique → parent inferred edges (only rendered when both
  // sides are evidence-backed).  These are relationship VIEWS derived
  // from the id grammar, never added to the underlying evidence model.
  const parentEdges = useMemo(() => {
    const out = [];
    evidenceBacked.forEach((n) => {
      const pid = parentTechniqueId(n.id);
      if (pid && byId[pid]) {
        out.push({
          id:         `parent:${pid}->${n.id}`,
          source:     pid,
          target:     n.id,
          confidence: byId[pid].confidence,
          via:        "sub-technique of",
          kind:       "sub_technique",
        });
      }
    });
    return out;
  }, [evidenceBacked, byId]);

  // Corroborating relationships surfaced by the backend graph.  We
  // keep only those whose BOTH ends made it into the evidence-backed
  // node set.
  const evidenceIds = new Set(evidenceBacked.map((n) => n.id));
  const witnessedEdges = edges.filter((e) =>
    evidenceIds.has(e.source) && evidenceIds.has(e.target));

  const bandSource = incident?.id
    ? `GET /incidents/${incident.id}/attack-chain-graph`
    : `GET /incidents/…/attack-chain-graph`;

  return (
    <div className="evops evops-canvas" data-testid="mitre-tab-v2">
      <div className="evops-band">
        <div>
          <div className="evops-band__eyebrow">Incident › MITRE ATT&amp;CK</div>
          <div className="evops-band__title">Evidence-substantiated techniques</div>
        </div>
        <div className="evops-band__spacer" />
        <div className="evops-band__source">{bandSource}</div>
        <Action label="Refresh" icon={RefreshCcw} onRun={load}
                testid="mitre-v2-refresh" />
      </div>

      {loading && (
        <div className="evops-hint" data-testid="mitre-v2-loading">
          Loading evidence-substantiated ATT&amp;CK mapping …
        </div>
      )}

      {!loading && err && (
        <div className="evops-empty" data-testid="mitre-v2-error">
          <div className="evops-empty__title">Mapping unavailable</div>
          <div className="evops-empty__reason">{String(err)}</div>
        </div>
      )}

      {!loading && !err && evidenceBacked.length === 0 && (
        <div className="evops-empty" data-testid="mitre-v2-empty">
          <div className="evops-empty__title">
            No evidence-backed ATT&amp;CK mapping
          </div>
          <div className="evops-empty__reason">
            The incident's collected evidence does not substantiate any
            ATT&amp;CK technique. NivXRay does not fabricate coverage
            from hypothesis — the analyst view for this incident is
            deliberately empty until real evidence supports a mapping.
          </div>
          {suppressed > 0 && (
            <div className="evops-empty__hint"
                 data-testid="mitre-v2-suppressed-hint">
              {suppressed} hypothetical technique{suppressed === 1 ? "" : "s"}
              {" "}suppressed · not observed in this incident's evidence.
            </div>
          )}
        </div>
      )}

      {!loading && !err && evidenceBacked.length > 0 && (
        <>
          <TechniqueRoster
            nodes={evidenceBacked}
            suppressed={suppressed}
          />
          <RelationshipsSection
            byId={byId}
            parentEdges={parentEdges}
            witnessedEdges={witnessedEdges}
          />
        </>
      )}

      <ContractNote note={data?.honesty_note} />
    </div>
  );
}


/* -----------------------------------------------------------------
 * Technique roster — one section-row per evidence-backed technique.
 * Uses <Entity> for identity, <EvidenceState> for confidence,
 * <Provenance> for the derivation chain, <Action> for the external
 * reference link (attack.mitre.org).
 * ----------------------------------------------------------------- */
function TechniqueRoster({ nodes, suppressed }) {
  return (
    <div className="evops-section" data-testid="mitre-v2-roster">
      <div className="evops-section__head">
        <span className="evops-section__eyebrow">
          Evidence-backed techniques
        </span>
        <span className="evops-section__count">{nodes.length}</span>
        <span className="evops-section__spacer" />
        {suppressed > 0 && (
          <EvidenceState
            state="suppressed"
            label={`${suppressed} suppressed`}
            reason="NOT_OBSERVED · UNKNOWN"
            testid="mitre-v2-suppressed-chip"
          />
        )}
      </div>

      {nodes.map((n) => {
        const conf = stateForConfidence(n.confidence);
        const chain = chainForNode(n);
        const attackHref =
          `https://attack.mitre.org/techniques/${n.id.replace(".", "/")}/`;
        return (
          <div
            key={n.id}
            className="evops-section evops-section--sub"
            data-testid={`mitre-v2-technique-${n.id}`}
          >
            <div className="evops-section__head">
              <Entity
                kind="rule"
                name={n.object_name || n.id}
                id={n.id}
                testid={`mitre-v2-entity-${n.id}`}
              />
              <div className="evops-section__spacer" />
              <EvidenceState
                state={conf.state}
                reason={conf.reason}
                testid={`mitre-v2-conf-${n.id}`}
              />
              <ActionGroup>
                <Action
                  label="View on attack.mitre.org"
                  icon={ExternalLink}
                  capability="cap-full"
                  onRun={() => window.open(attackHref, "_blank",
                                          "noopener,noreferrer")}
                  testid={`mitre-v2-ext-${n.id}`}
                />
              </ActionGroup>
            </div>
            <div className="evops-hint" style={{ marginTop: 8 }}
                 data-testid={`mitre-v2-why-${n.id}`}>
              {n.why_mapped
                || "Why NivXRay mapped this technique: rationale not surfaced by the backend graph."}
            </div>
            <div style={{ marginTop: 10 }}>
              <Provenance chain={chain}
                          testid={`mitre-v2-prov-${n.id}`} />
            </div>
            <TacticLine tactic={n.tactic} method={n.mapping_method} />
          </div>
        );
      })}
    </div>
  );
}


function TacticLine({ tactic, method }) {
  if (!tactic && !method) return null;
  return (
    <div className="evops-mono" style={{ marginTop: 6 }}
         data-testid="mitre-v2-tactic">
      {tactic && <>Tactic <b>{tactic}</b></>}
      {tactic && method && " · "}
      {method && <>Mapping <b>{method}</b></>}
    </div>
  );
}


/* -----------------------------------------------------------------
 * Relationships section — sub-technique parenthood + backend-emitted
 * shared-entity / shared-evidence edges.  Every edge carries a
 * required <Relationship state="…"> per the primitive contract.
 * ----------------------------------------------------------------- */
function RelationshipsSection({ byId, parentEdges, witnessedEdges }) {
  const total = parentEdges.length + witnessedEdges.length;
  if (total === 0) return null;
  return (
    <div className="evops-section" data-testid="mitre-v2-relationships">
      <div className="evops-section__head">
        <span className="evops-section__eyebrow">
          Technique relationships
        </span>
        <span className="evops-section__count">{total}</span>
      </div>

      {parentEdges.map((e) => (
        <RelationshipRow
          key={e.id}
          edge={e}
          byId={byId}
          via="sub-technique of"
          testidPrefix="mitre-v2-rel-sub"
        />
      ))}

      {witnessedEdges.map((e) => (
        <RelationshipRow
          key={e.id}
          edge={e}
          byId={byId}
          via={e.proof?.reason === "shared_entity"
                ? "shared entity"
                : "shared evidence"}
          testidPrefix="mitre-v2-rel-edge"
        />
      ))}
    </div>
  );
}


function RelationshipRow({ edge, byId, via, testidPrefix }) {
  const s = byId[edge.source];
  const t = byId[edge.target];
  if (!s || !t) return null;
  const state = stateForConfidence(edge.confidence).state;
  return (
    <div style={{ padding: "10px 0",
                  borderBottom: "var(--evops-rule)" }}
         data-testid={`${testidPrefix}-${edge.id}`}>
      <Relationship
        from={<Entity kind="rule"
                      name={s.object_name || s.id}
                      id={s.id} />}
        via={via}
        to={<Entity kind="rule"
                    name={t.object_name || t.id}
                    id={t.id} />}
        state={state}
        testid={`${testidPrefix}-rel-${edge.id}`}
      />
    </div>
  );
}


function ContractNote({ note }) {
  return (
    <div className="evops-empty" data-testid="mitre-v2-contract"
         style={{ marginTop: 18 }}>
      <div className="evops-empty__title">Evidence-first contract</div>
      <div className="evops-empty__reason">
        {note
          || "This surface is a projection of the incident/evidence model. It renders only techniques substantiated by collected evidence — never hypothetical coverage."}
      </div>
    </div>
  );
}
