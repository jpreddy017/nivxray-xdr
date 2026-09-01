/**
 * MitreTabV2 · Round 29 · Tactic Coverage + Technique Cards.
 * ---------------------------------------------------------------
 * Two-layer visualisation, driven exclusively by the incident's
 * attack-chain graph:
 *
 *   1. Tactic Coverage strip — 14 ATT&CK tactic cells rendered as
 *      a compact scanning grid.  Each cell shows the count of
 *      evidence-backed techniques observed under that tactic in
 *      THIS incident.  Zero-count cells are honest coverage GAPS
 *      (muted `—`, not filled zeros).
 *
 *   2. Technique cards — one dense card per evidence-backed
 *      technique.  Left rail = confidence accent.  Body =
 *      technique id/name + rationale + evidence rollup (hosts /
 *      users / evidence refs) + Provenance chain + Action to open
 *      attack.mitre.org.  Related sub-technique or shared-entity
 *      edges are rendered inline via <Relationship>.
 *
 * Hard rules:
 *   · UNKNOWN / NOT_OBSERVED techniques are counted (as suppressed)
 *     but NEVER drawn.  We do not fabricate coverage from
 *     hypothesis.
 *   · Empty state is honest and compact — no giant decorative
 *     placeholders.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCcw, ExternalLink, User as UserIcon,
         Server as ServerIcon, FileDigit } from "lucide-react";

import api from "@/lib/api";
import Entity from "@/xdr/design/Entity";
import EvidenceState from "@/xdr/design/EvidenceState";
import Provenance from "@/xdr/design/Provenance";
import Relationship from "@/xdr/design/Relationship";
import Action, { ActionGroup } from "@/xdr/design/Action";
import { TechniqueGlyph, TacticGlyph } from "@/xdr/design/glyphs";
import "@/xdr/design/tokens.css";


/* ------------------------------------------------------------------
 * Static reference: canonical ATT&CK tactic order.  The list is not
 * telemetry — it is the schema of ATT&CK itself.  Counts against it
 * are strictly derived from the incident's graph.
 * ------------------------------------------------------------------ */
const TACTICS = [
  { id: "reconnaissance",         label: "Reconnaissance" },
  { id: "resource-development",   label: "Resource Dev" },
  { id: "initial-access",         label: "Initial Access" },
  { id: "execution",              label: "Execution" },
  { id: "persistence",            label: "Persistence" },
  { id: "privilege-escalation",   label: "Privilege Esc" },
  { id: "defense-evasion",        label: "Defense Evasion" },
  { id: "credential-access",      label: "Credential Access" },
  { id: "discovery",              label: "Discovery" },
  { id: "lateral-movement",       label: "Lateral Movement" },
  { id: "collection",             label: "Collection" },
  { id: "command-and-control",    label: "Command & Control" },
  { id: "exfiltration",           label: "Exfiltration" },
  { id: "impact",                 label: "Impact" },
];


function stateForConfidence(conf) {
  switch (conf) {
    case "CONFIRMED":              return { state: "observed",    reason: null };
    case "SUPPORTED":              return { state: "supported",   reason: null };
    case "INSUFFICIENT_EVIDENCE":  return { state: "missing",     reason: "INSUFFICIENT_EVIDENCE" };
    case "NOT_OBSERVED":           return { state: "unavailable", reason: "NOT_OBSERVED" };
    default:                        return { state: "missing",     reason: String(conf || "UNKNOWN") };
  }
}


function parentTechniqueId(id) {
  if (!id || typeof id !== "string") return null;
  const dot = id.indexOf(".");
  return dot > 0 ? id.slice(0, dot) : null;
}


function chainForNode(n) {
  const t = n?.traversal_chain || {};
  const telemetry = (n.telemetry_sources && n.telemetry_sources.length)
    ? n.telemetry_sources.join(", ") : null;
  const canonical = t.canonical_event_id
    || (Array.isArray(n.source_refs) && n.source_refs[0]) || null;
  const correlate = (Array.isArray(t.correlation_match_ids)
                        && t.correlation_match_ids.length)
    ? `${t.correlation_match_ids.length} match(es)` : null;
  return [
    { layer: "telemetry", value: telemetry,  present: !!telemetry },
    { layer: "canonical", value: canonical,  present: !!canonical },
    { layer: "correlate", value: correlate,  present: !!correlate },
    { layer: "mapping",   value: n.id || null, present: !!n.id },
  ];
}


/** Normalise the graph's raw tactic value against the static
 *  reference list — the graph may emit `Execution`, `execution`,
 *  or `TA0002`, so we match loosely. */
function normaliseTacticId(raw) {
  if (!raw) return null;
  const s = String(raw).trim().toLowerCase().replace(/\s+/g, "-");
  const hit = TACTICS.find((t) => t.id === s || t.label.toLowerCase() === s
                                    || t.label.toLowerCase().replace(/\s+/g,"-") === s);
  return hit ? hit.id : null;
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

  const nodes = Array.isArray(data?.nodes) ? data.nodes : [];
  const edges = Array.isArray(data?.edges) ? data.edges : [];

  const evidenceBacked = useMemo(() => nodes.filter(
    (n) => n.confidence === "CONFIRMED" || n.confidence === "SUPPORTED"
        || n.confidence === "INSUFFICIENT_EVIDENCE"), [nodes]);
  const suppressed = nodes.length - evidenceBacked.length;

  // Tactic coverage counts (evidence-backed only).
  const tacticCounts = useMemo(() => {
    const out = {};
    evidenceBacked.forEach((n) => {
      const t = normaliseTacticId(n.tactic);
      if (t) out[t] = (out[t] || 0) + 1;
    });
    return out;
  }, [evidenceBacked]);
  const observedTactics = Object.keys(tacticCounts).length;

  const byId = useMemo(() => {
    const m = {};
    nodes.forEach((n) => { m[n.id] = n; });
    return m;
  }, [nodes]);

  const parentEdges = useMemo(() => {
    const out = [];
    evidenceBacked.forEach((n) => {
      const pid = parentTechniqueId(n.id);
      if (pid && byId[pid]) {
        out.push({ id: `parent:${pid}->${n.id}`,
                   source: pid, target: n.id,
                   confidence: byId[pid].confidence,
                   kind: "sub_technique" });
      }
    });
    return out;
  }, [evidenceBacked, byId]);

  const evidenceIds  = new Set(evidenceBacked.map((n) => n.id));
  const relatedEdges = edges.filter((e) =>
    evidenceIds.has(e.source) && evidenceIds.has(e.target));

  const bandSource = incident?.id
    ? `GET /incidents/${incident.id}/attack-chain-graph`
    : `GET /incidents/…/attack-chain-graph`;

  return (
    <div className="evops evops-canvas" data-testid="mitre-tab-v2">
      <div className="evops-band">
        <div>
          <div className="evops-band__eyebrow">Incident › MITRE ATT&amp;CK</div>
          <div className="evops-band__title">Evidence-substantiated coverage</div>
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

      {!loading && !err && (
        <>
          {/* Tactic Coverage strip — always rendered so the analyst
              sees the honest coverage shape, not just the presence
              of hits. */}
          <div style={{ display: "flex", alignItems: "baseline",
                        gap: 10, padding: "4px 0 8px" }}>
            <span className="evops-section__eyebrow">
              Tactic Coverage
            </span>
            <span className="evops-section__count">
              {observedTactics}/{TACTICS.length} tactics observed ·
              {" "}{evidenceBacked.length} evidence-backed technique
              {evidenceBacked.length === 1 ? "" : "s"}
            </span>
            <span className="evops-section__spacer" />
            {suppressed > 0 && (
              <EvidenceState state="suppressed"
                              label={`${suppressed} suppressed`}
                              reason="NOT_OBSERVED · UNKNOWN"
                              testid="mitre-v2-suppressed-chip" />
            )}
          </div>

          <div className="evops-tactics"
               data-testid="mitre-v2-tactic-strip">
            {TACTICS.map((t) => {
              const c = tacticCounts[t.id] || 0;
              return (
                <div key={t.id}
                     className="evops-tactics__cell"
                     data-empty={c === 0 ? "true" : "false"}
                     data-testid={`mitre-v2-tactic-${t.id}`}>
                  <span className="evops-tactics__name"
                        style={{ display: "flex", alignItems: "center", gap: 5 }}>
                    <TacticGlyph size={10} />
                    <span>{t.label}</span>
                  </span>
                  <span className="evops-tactics__count">
                    {c === 0 ? "—" : c}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Empty state — appears BELOW the coverage strip so the
              analyst first understands "coverage everywhere is
              zero", then reads the honesty note. */}
          {evidenceBacked.length === 0 && (
            <div className="evops-empty"
                 data-testid="mitre-v2-empty">
              <div className="evops-empty__title">
                No evidence-backed ATT&amp;CK mapping
              </div>
              <div className="evops-empty__reason">
                The incident's collected evidence does not
                substantiate any ATT&amp;CK technique.  NivXRay XDR
                does not fabricate coverage from hypothesis — the
                analyst view for this incident remains empty until
                real evidence supports a mapping.
              </div>
              {suppressed > 0 && (
                <div className="evops-empty__hint"
                     data-testid="mitre-v2-suppressed-hint">
                  {suppressed} hypothetical technique
                  {suppressed === 1 ? "" : "s"} suppressed · not
                  observed in this incident's evidence.
                </div>
              )}
            </div>
          )}

          {/* Technique table — dense one-row-per-technique layout
              matching enterprise SOC "MITRE ATT&CK" module. */}
          {evidenceBacked.length > 0 && (
            <div data-testid="mitre-v2-cards">
              <div className="evops-section__head"
                   style={{ marginBottom: 8 }}>
                <span className="evops-section__eyebrow">
                  Evidence-backed techniques
                </span>
                <span className="evops-section__count">
                  {evidenceBacked.length}
                </span>
              </div>
              <div className="evops-tech-table">
                {evidenceBacked.map((n) => (
                  <TechniqueRow key={n.id} node={n} />
                ))}
              </div>
            </div>
          )}

          {(parentEdges.length + relatedEdges.length) > 0 && (
            <RelationshipsBlock
              byId={byId}
              parentEdges={parentEdges}
              relatedEdges={relatedEdges}
            />
          )}
        </>
      )}
    </div>
  );
}


/* ------------------------------------------------------------------
 * TechniqueRow — table-style, one row per evidence-backed technique.
 * Left  = technique id + name + rationale.
 * Right = tactic + evidence rollup + confidence pill + action.
 * Matches the enterprise SOC "MITRE ATT&CK" panel pattern.
 * ------------------------------------------------------------------ */
function TechniqueRow({ node }) {
  const conf = stateForConfidence(node.confidence);
  const attackHref =
    `https://attack.mitre.org/techniques/${node.id.replace(".", "/")}/`;

  const buckets = { hosts: [], users: [], files: [] };
  (node.entities || []).forEach((e) => {
    const k = String(e.kind || "").toLowerCase();
    if (k === "host" || k === "endpoint")   buckets.hosts.push(e.value);
    else if (k === "user" || k === "account") buckets.users.push(e.value);
    else if (k === "file" || k === "hash")    buckets.files.push(e.value);
  });
  const evCount = Array.isArray(node.evidence_ids) ? node.evidence_ids.length : 0;

  return (
    <div className="evops-tech-row"
         data-testid={`mitre-v2-row-${node.id}`}>
      <div className="evops-tech-row__id"
           style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <TechniqueGlyph size={13} />
        <span>{node.id}</span>
      </div>
      <div>
        <div className="evops-tech-row__name">
          {node.object_name || node.id}
        </div>
        {node.why_mapped && (
          <div className="evops-tech-row__why">{node.why_mapped}</div>
        )}
      </div>
      <div className="evops-tech-row__tactic"
           style={{ display: "flex", alignItems: "center", gap: 6 }}>
        {node.tactic
          ? <><TacticGlyph size={12} /> <span>{node.tactic}</span></>
          : <span>—</span>}
      </div>
      <div className="evops-tech-row__rollup">
        <span>{evCount} evidence · {buckets.hosts.length} host
              · {buckets.users.length} user</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <EvidenceState state={conf.state} reason={conf.reason}
                        testid={`mitre-v2-row-conf-${node.id}`} />
        <Action label="Open" icon={ExternalLink}
                 capability="cap-full"
                 onRun={() => window.open(attackHref, "_blank",
                                           "noopener,noreferrer")}
                 testid={`mitre-v2-row-ext-${node.id}`} />
      </div>
    </div>
  );
}


function TechniqueCard({ node, incidentId }) {
  const conf = stateForConfidence(node.confidence);
  const chain = chainForNode(node);
  const attackHref =
    `https://attack.mitre.org/techniques/${node.id.replace(".", "/")}/`;

  // Bucket entities so the analyst gets a per-technique rollup.
  const buckets = { hosts: [], users: [], files: [], other: [] };
  (node.entities || []).forEach((e) => {
    const k = String(e.kind || "").toLowerCase();
    if (k === "host" || k === "endpoint")  buckets.hosts.push(e.value);
    else if (k === "user" || k === "account") buckets.users.push(e.value);
    else if (k === "file" || k === "hash")    buckets.files.push(e.value);
    else buckets.other.push(`${k}:${e.value}`);
  });
  const evCount = Array.isArray(node.evidence_ids) ? node.evidence_ids.length : 0;

  return (
    <div className="evops-technique"
         data-conf={conf.state}
         data-testid={`mitre-v2-card-${node.id}`}>
      <div>
        <div className="evops-technique__id"
             data-testid={`mitre-v2-card-id-${node.id}`}>
          {node.id}
          {node.tactic && <> · {node.tactic}</>}
        </div>
        <div className="evops-technique__name">
          {node.object_name || node.id}
        </div>
        <div className="evops-technique__why"
             data-testid={`mitre-v2-card-why-${node.id}`}>
          {node.why_mapped
            || "Why NivXRay XDR mapped this technique: rationale not surfaced by the backend graph."}
        </div>
        <div style={{ marginTop: 8 }}>
          <Provenance chain={chain}
                      testid={`mitre-v2-card-prov-${node.id}`} />
        </div>
      </div>

      <div className="evops-technique__evidence">
        <span className="evops-technique__evidence-label">Evidence rollup</span>
        <EvRow icon={FileDigit} label={`${evCount} evidence ref${evCount === 1 ? "" : "s"}`}
               absent={evCount === 0} />
        <EvRow icon={ServerIcon}
               label={buckets.hosts.length
                        ? `${buckets.hosts.length} host${buckets.hosts.length === 1 ? "" : "s"} · ${buckets.hosts.slice(0,2).join(", ")}`
                        : "no host extracted"}
               absent={buckets.hosts.length === 0} />
        <EvRow icon={UserIcon}
               label={buckets.users.length
                        ? `${buckets.users.length} user${buckets.users.length === 1 ? "" : "s"} · ${buckets.users.slice(0,2).join(", ")}`
                        : "no user extracted"}
               absent={buckets.users.length === 0} />
      </div>

      <div className="evops-technique__actions">
        <EvidenceState state={conf.state} reason={conf.reason}
                        testid={`mitre-v2-card-conf-${node.id}`} />
        <ActionGroup>
          <Action label="View technique" icon={ExternalLink}
                   capability="cap-full"
                   onRun={() => window.open(attackHref, "_blank",
                                             "noopener,noreferrer")}
                   testid={`mitre-v2-card-ext-${node.id}`} />
        </ActionGroup>
      </div>
    </div>
  );
}


function EvRow({ icon: Icon, label, absent }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center",
                    gap: 6,
                    color: absent ? "var(--nx-faint)" : "var(--nx-text-dim)",
                    fontStyle: absent ? "italic" : "normal" }}>
      <Icon size={11} />
      <span>{label}</span>
    </span>
  );
}


function RelationshipsBlock({ byId, parentEdges, relatedEdges }) {
  const total = parentEdges.length + relatedEdges.length;
  return (
    <div className="evops-section"
         data-testid="mitre-v2-relationships">
      <div className="evops-section__head">
        <span className="evops-section__eyebrow">
          Technique relationships
        </span>
        <span className="evops-section__count">{total}</span>
      </div>
      {parentEdges.map((e) => (
        <Row key={e.id} edge={e} byId={byId}
              via="sub-technique of"
              testidPrefix="mitre-v2-rel-sub" />
      ))}
      {relatedEdges.map((e) => (
        <Row key={e.id} edge={e} byId={byId}
              via={e.proof?.reason === "shared_entity"
                    ? "shared entity"
                    : "shared evidence"}
              testidPrefix="mitre-v2-rel-edge" />
      ))}
    </div>
  );
}


function Row({ edge, byId, via, testidPrefix }) {
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
