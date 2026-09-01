/**
 * IncidentOverviewV2 · v1.1 Composition · Flagship surface.
 * ---------------------------------------------------------------
 * Composes the Round 24.9 primitives + the v1.0 glyph library into
 * the v1.1 flagship Incident Overview.
 *
 * Renders (top-to-bottom, VEEE §13.1 scan path):
 *
 *   [Attack Story band]      ─ Q5 How did it progress?
 *   [Investigation Graph]    ─ Q3 What is affected?
 *   [Evidence · Entities · MITRE · Recommendations cluster]
 *                            ─ Q4 · Q3 · Q6 · Q7
 *   [Provenance footer]      ─ compact contextual, never a section
 *
 * Empty-evidence rule (C2): the whole body collapses to ONE hint
 * strip instead of four "NOT PRESENT" cards.
 */
import React, { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import api from "@/lib/api";
import {
  EvidenceGlyph, HostGlyph, UserGlyph, ProcessGlyph, FileGlyph,
  NetworkGlyph, DomainGlyph, TechniqueGlyph, TacticGlyph,
  ResponseGlyph, ProvenanceGlyph, CorrelationGlyph,
} from "@/xdr/design/glyphs";
import "@/xdr/design/tokens.css";


/* ------------------------------------------------------------------
 * Provenance layers derived from the incident model.
 * ------------------------------------------------------------------ */
function provChain(incident) {
  const telemetry = incident?.source_integration_id
    || incident?.source
    || (Array.isArray(incident?.sources) && incident.sources[0])
    || null;
  const canonical = incident?.canonical_event_id
    || (Array.isArray(incident?.canonical_evidence_ids)
        && incident.canonical_evidence_ids.length
          ? `${incident.canonical_evidence_ids.length} event(s)`
          : null);
  const correlate = incident?.correlation_rule_id
    || (Array.isArray(incident?.correlation_match_ids)
        && incident.correlation_match_ids.length
          ? `${incident.correlation_match_ids.length} match(es)` : null);
  const upstreamPresent = !!(telemetry || canonical || correlate);
  // v1.0 rule: mapping cannot be present without upstream evidence.
  const mitre = upstreamPresent
                  && Array.isArray(incident?.mitre) && incident.mitre.length
    ? `${incident.mitre.length} technique(s)` : null;
  return { telemetry, canonical, correlate, mitre };
}


function countAssets(incident) {
  const a    = incident?.assets || {};
  const iocs = incident?.iocs   || {};
  const len  = (v) => Array.isArray(v) ? v.length : 0;
  return {
    hosts:     len(a.hosts)     || len(incident?.hosts),
    users:     len(a.users)     || len(incident?.users),
    processes: len(a.processes) || len(incident?.processes),
    files:     len(a.files)     || len(iocs.hashes) || len(iocs.files),
    ips:       len(iocs.ips),
    domains:   len(iocs.domains),
    urls:      len(iocs.urls),
  };
}


export default function IncidentOverviewV2({ incident }) {
  const [graph, setGraph] = useState(null);
  useEffect(() => {
    if (!incident?.id) return;
    api.get(`/admin/content-supply-chain/incidents/${incident.id}/attack-chain-graph`)
       .then((r) => setGraph(r.data)).catch(() => setGraph(null));
  }, [incident?.id]);

  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const evidenceBackedNodes = useMemo(() => nodes.filter(
    (n) => n.confidence === "CONFIRMED" || n.confidence === "SUPPORTED"
        || n.confidence === "INSUFFICIENT_EVIDENCE"), [nodes]);

  const evidenceCount = Number(incident?.evidence_count || 0);
  const chain         = provChain(incident);
  const assets        = countAssets(incident);
  const anyEvidence   = evidenceCount > 0
    || evidenceBackedNodes.length > 0
    || !!chain.telemetry || !!chain.canonical || !!chain.correlate;

  return (
    <div className="evops" data-testid="xdr-overview-v2">

      {!anyEvidence && (
        <div className="evops-empty-strip"
             data-testid="xdr-overview-v2-empty">
          <span className="evops-empty-strip__title">
            No telemetry-backed investigation available
          </span>
          <span className="evops-empty-strip__body">
            Attack Story, Investigation Graph, Evidence, Entities,
            MITRE and Recommendations will render as canonical
            evidence is ingested for this incident.
          </span>
        </div>
      )}

      {anyEvidence && (
        <>
          <AttackStoryBand evidenceBackedNodes={evidenceBackedNodes} />
          <InvestigationGraphMini assets={assets} />
          <BottomCluster
            incident={incident}
            evidenceBackedNodes={evidenceBackedNodes}
            evidenceCount={evidenceCount}
            assets={assets}
          />
        </>
      )}

      <ProvenanceFoot chain={chain} />
    </div>
  );
}


/* ---------- Attack Story band ---------- */
function AttackStoryBand({ evidenceBackedNodes }) {
  const sorted = [...(evidenceBackedNodes || [])]
    .sort((a, b) => String(a.first_seen_at || a.id)
      .localeCompare(String(b.first_seen_at || b.id)));

  return (
    <div className="evops-story" data-testid="xdr-overview-v2-story">
      <div className="evops-story__head">
        <span className="evops-story__title">Attack Story</span>
        <span className="evops-story__sub">
          {sorted.length
            ? "Evidence-derived progression · earliest → latest"
            : "No evidence-backed progression observed yet."}
        </span>
      </div>
      {sorted.length > 0 && (
        <div className="evops-story__chain">
          {sorted.slice(0, 8).map((n) => (
            <div key={n.id}
                 className="evops-story__node evops-story__node--observed"
                 data-testid={`xdr-overview-v2-story-node-${n.id}`}>
              <span className="evops-story__node-tactic">
                <TacticGlyph size={10} />{n.tactic || "TACTIC"}
              </span>
              <span className="evops-story__node-title">
                {n.object_name || n.id}
              </span>
              {n.first_seen_at && (
                <span className="evops-story__node-time">
                  {String(n.first_seen_at).slice(11, 16)}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


/* ---------- Investigation Graph mini ---------- */
function InvestigationGraphMini({ assets }) {
  const chain = [
    { glyph: <HostGlyph size={13} />,    label: "Host",    count: assets.hosts },
    { glyph: <UserGlyph size={13} />,    label: "User",    count: assets.users },
    { glyph: <ProcessGlyph size={13} />, label: "Process", count: assets.processes },
    { glyph: <FileGlyph size={13} />,    label: "File",    count: assets.files },
    { glyph: <NetworkGlyph size={13} />, label: "Network", count: assets.ips + assets.domains + assets.urls },
    { glyph: <DomainGlyph size={13} />,  label: "Domain",  count: assets.domains },
  ].filter((c) => c.count > 0);

  return (
    <div className="evops-graph" data-testid="xdr-overview-v2-graph">
      <div className="evops-story__head">
        <span className="evops-story__title">Investigation Graph</span>
        <span className="evops-story__sub">
          {chain.length
            ? `${chain.length} entity kind${chain.length === 1 ? "" : "s"} extracted from evidence`
            : "No investigative entities extracted from evidence yet."}
        </span>
      </div>
      {chain.length > 0 && (
        <div className="evops-graph__row">
          {chain.map((n, i) => (
            <React.Fragment key={n.label}>
              <span className="evops-graph__node"
                    data-testid={`xdr-overview-v2-graph-node-${n.label.toLowerCase()}`}>
                {n.glyph}
                <span>{n.label} · {n.count}</span>
              </span>
              {i < chain.length - 1 && (
                <span className="evops-graph__link">→</span>
              )}
            </React.Fragment>
          ))}
        </div>
      )}
    </div>
  );
}


/* ---------- Bottom 4-column cluster ---------- */
function BottomCluster({ incident, evidenceBackedNodes, evidenceCount, assets }) {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const gotoTab = (t) => {
    const p = new URLSearchParams(params);
    p.set("tab", t);
    navigate(`?${p.toString()}`);
  };

  const recCount = Number(incident?.recommendation_count
                            || incident?.recommendations?.length || 0);

  return (
    <div className="evops-cluster" data-testid="xdr-overview-v2-cluster">
      <ClusterCol
        glyph={<EvidenceGlyph size={12} />}
        title="Evidence"
        count={evidenceCount}
        rows={[
          { label: "Canonical events", count: evidenceCount },
          { label: "Correlation matches",
            count: Array.isArray(incident?.correlation_match_ids)
              ? incident.correlation_match_ids.length : 0 },
          { label: "IOC hashes", count: (incident?.iocs?.hashes || []).length },
        ]}
        onSeeAll={() => gotoTab("evidence")}
        testid="xdr-overview-v2-col-evidence"
      />
      <ClusterCol
        glyph={<HostGlyph size={12} />}
        title="Entities"
        count={assets.hosts + assets.users + assets.processes + assets.files}
        rows={[
          { label: "Hosts",     count: assets.hosts,     glyph: <HostGlyph size={11} /> },
          { label: "Users",     count: assets.users,     glyph: <UserGlyph size={11} /> },
          { label: "Processes", count: assets.processes, glyph: <ProcessGlyph size={11} /> },
          { label: "Files",     count: assets.files,     glyph: <FileGlyph size={11} /> },
        ]}
        onSeeAll={() => gotoTab("related")}
        testid="xdr-overview-v2-col-entities"
      />
      <ClusterCol
        glyph={<TechniqueGlyph size={12} />}
        title="MITRE ATT&CK"
        count={evidenceBackedNodes.length}
        rows={evidenceBackedNodes.slice(0, 4).map((n) => ({
          label: `${n.id} · ${n.object_name || n.tactic || ""}`.trim(),
          glyph: <TechniqueGlyph size={11} />,
        }))}
        emptyLabel="No evidence-backed technique yet."
        onSeeAll={() => gotoTab("mitre")}
        testid="xdr-overview-v2-col-mitre"
      />
      <ClusterCol
        glyph={<ResponseGlyph size={12} />}
        title="Recommendations"
        count={recCount}
        rows={(incident?.recommendations || []).slice(0, 4).map((r) => ({
          label: r?.title || r?.action_id || "recommendation",
          glyph: <ResponseGlyph size={11} />,
        }))}
        emptyLabel="No evidence-backed recommendation yet."
        onSeeAll={() => gotoTab("recommendations")}
        testid="xdr-overview-v2-col-recommendations"
      />
    </div>
  );
}


function ClusterCol({ glyph, title, count, rows, emptyLabel, onSeeAll, testid }) {
  const absent = !count;
  return (
    <div className="evops-cluster__col" data-testid={testid}>
      <div className="evops-cluster__head">
        <span className="evops-cluster__title">{glyph}{title}</span>
        <span className="evops-cluster__count"
              data-absent={absent ? "true" : "false"}>
          {absent ? "—" : count}
        </span>
      </div>
      {absent && (
        <div className="evops-cluster__empty">
          {emptyLabel || "No data yet."}
        </div>
      )}
      {!absent && (rows || []).length > 0 && (rows || []).map((r, i) => (
        <div key={i} className="evops-cluster__row">
          {r.glyph}
          <span style={{ overflow: "hidden", textOverflow: "ellipsis",
                          whiteSpace: "nowrap" }}>
            {r.label}
          </span>
          {r.count != null && (
            <span className="evops-cluster__row-count">{r.count}</span>
          )}
        </div>
      ))}
      {!absent && (
        <span className="evops-cluster__seeall"
              onClick={onSeeAll}
              data-testid={`${testid}-seeall`}>
          see all {count} →
        </span>
      )}
    </div>
  );
}


/* ---------- Compact Provenance footer (v1.1 C7) ---------- */
function ProvenanceFoot({ chain }) {
  const label = (val, missing) => val
    ? <b style={{ color: "var(--nx-text-dim)", fontWeight: 600 }}>{val}</b>
    : <span style={{ fontStyle: "italic", color: "var(--nx-faint)" }}>
        {missing}
      </span>;
  return (
    <div className="evops-prov-foot"
         data-testid="xdr-overview-v2-provenance">
      <span className="evops-prov-foot__label">
        <ProvenanceGlyph size={11} /> Provenance
      </span>
      <span>Telemetry {label(chain.telemetry, "not present")}</span>
      <span>·</span>
      <span>Canonical {label(chain.canonical, "not present")}</span>
      <span>·</span>
      <span>Correlation {label(chain.correlate, "not present")}</span>
      <span>·</span>
      <span>MITRE {label(chain.mitre, "not present")}</span>
    </div>
  );
}
