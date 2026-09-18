/**
 * XdrIncidentDetailPage · `/xdr/incidents/:id` · E2E-2
 *
 * The ONE authoritative investigation workspace. Rebuilt on `xdr/nx/`:
 * NxEntityHeader owns identity + verdict + actions + the single tab bar, and
 * the tab bodies are the EXISTING authoritative surfaces — nothing that
 * worked was reimplemented, and nothing was deleted.
 *
 * Information architecture (owner directive §5), left to right = the
 * investigation itself:
 *
 *   WHAT HAPPENED → HOW → WHAT WAS AFFECTED → WHAT PROVES IT
 *   → WHAT SHOULD WE DO → WHAT DID WE DO
 *
 * Deep links preserved: `?tab=` still selects a tab, and every previous tab
 * key is accepted via `LEGACY_TAB_ALIASES` so existing shared links resolve.
 */
import React, { lazy, useCallback, useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { ArrowUpRight } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { useAccess } from "@/xdr/access/AccessProvider";
import { getIncident, transitionIncidentState } from "@/lib/incidentsApi";
import {
  NxPageShell, NxEntityHeader, NxFact, NxTabs, NxChip, NxEmpty, NxSkeleton,
  NxVerdict, NxLifecycle, NxPriority, NxRisk, NxConfidence,
  NxProvenanceChip, NxAttackChain, NxMetric,
} from "@/xdr/nx";
import AnalystResponseDrawer from "@/xdr/respond/AnalystResponseDrawer";
import OpenInEdr from "@/xdr/components/OpenInEdr";
import IncidentIntelligenceContext from "@/xdr/intelligence/IncidentIntelligenceContext";

import ExecutiveTab         from "./incidents/record/tabs/ExecutiveTab";
import TechnicalTab         from "./incidents/record/tabs/TechnicalTab";
import EvidenceTab          from "./incidents/record/tabs/EvidenceTab";
import AutoInvestigationTab from "./incidents/record/tabs/AutoInvestigationTab";
import MitreTab             from "./incidents/record/tabs/MitreTab";
import AttackStoryTab       from "./incidents/record/tabs/AttackStoryTab";
import AttackGraphTab       from "./incidents/record/tabs/AttackGraphTab";
import RecommendationsTab   from "./incidents/record/tabs/RecommendationsTab";
import NotesTab             from "./incidents/record/tabs/NotesTab";
import TimelineTab          from "./incidents/record/tabs/TimelineTab";
import RelatedTab           from "./incidents/record/tabs/RelatedTab";
import ClosureTab           from "./incidents/record/tabs/ClosureTab";
import ReportTab            from "./incidents/record/tabs/ReportTab";

/**
 * B2-INV · the causal ENGINE panels are mounted UNDERNEATH the analyst
 * tabs that own the question they answer, never as primary navigation:
 *
 *   Device Trajectory        → Timeline
 *   Process Ancestry         → Attack Story
 *   Evidence Graph (IKG)     → Entities
 *   Extracted artifacts      → Evidence
 *   Deterministic Verdict    → Overview · why this verdict
 *   Security State / FSM     → Overview · technical reasoning
 *   Engine ATT&CK mapping    → MITRE
 *
 * Advanced underneath. Simple on top. Powerful when needed.
 */
const InvestigationEngine = lazy(
  () => import("./XdrInvestigationWorkspacePage"));

import "./incidents/queue-theme.css";
import "./incidents/record/record-theme.css";
import "@/xdr/nx/nx-entity.css";

const TABS = [
  { key: "overview",   label: "Overview" },
  { key: "story",      label: "Attack Story" },
  { key: "timeline",   label: "Timeline" },
  { key: "evidence",   label: "Evidence" },
  { key: "entities",   label: "Entities" },
  { key: "detections", label: "Detections" },
  { key: "mitre",      label: "MITRE" },
  { key: "response",   label: "Response" },
  { key: "activity",   label: "Activity" },
  { key: "report",     label: "Report" },
];

/** Every tab key the previous record used, so shared deep links still land. */
const LEGACY_TAB_ALIASES = {
  attack_story: "story", executive: "overview", summary: "overview",
  technical: "detections", attack_graph: "entities", graph: "entities",
  auto_investigation: "activity", notes: "activity", closure: "activity",
  recommendations: "response", related: "entities",
};

const LIFECYCLE_NEXT = {
  new:         ["in_progress"],
  in_progress: ["on_hold", "resolved"],
  on_hold:     ["in_progress"],
  resolved:    ["closed"],
  closed:      [],
};
const LC_LABEL = {
  in_progress: "Start work", on_hold: "Put on hold",
  resolved: "Mark resolved", closed: "Close",
};

/** Engine depth: present, never in the way. Collapsed by default so the
 *  analyst surface stays simple and the capability is one click away. */
function EngineDepth({ title, hint, caseId, capabilities }) {
  const [open, setOpen] = useState(false);
  const id = capabilities.join("-");
  return (
    <section className="nx-sec" data-testid={`engine-depth-${id}`}>
      <button className="nx-dt-btn" onClick={() => setOpen((v) => !v)}
              data-testid={`engine-depth-toggle-${id}`}
              data-open={open || undefined}>
        {open ? "▾" : "▸"} {title}
      </button>
      <p style={{ fontSize: 11.5, color: "var(--nx-text-dim)",
                  margin: "8px 0 0", lineHeight: 1.6 }}>
        {hint}
      </p>
      {open && (
        <div style={{ marginTop: 12 }}>
          <InvestigationEngine caseId={caseId} capabilities={capabilities}
                               embedded />
        </div>
      )}
    </section>
  );
}

function Absent({ children = "Not recorded", title }) {
  return <span className="nx-unavail" title={title}>{children}</span>;
}

export default function XdrIncidentDetailPage() {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const access = useAccess();

  const raw = params.get("tab") || "overview";
  const tab = TABS.some((t) => t.key === raw)
    ? raw : (LEGACY_TAB_ALIASES[raw] || "overview");

  const [incident, setIncident] = useState(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [busy, setBusy]         = useState(null);
  const [respondOpen, setRespondOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try { setIncident(await getIncident(id)); }
    catch (e) {
      setError(e?.response?.data?.detail || e?.message
        || "This incident could not be loaded.");
    } finally { setLoading(false); }
  }, [id]);
  useEffect(() => { load(); }, [load]);

  const setTab = useCallback((k) => {
    const next = new URLSearchParams(params);
    next.set("tab", k);
    setParams(next, { replace: true });
  }, [params, setParams]);

  const transition = async (target) => {
    setBusy(target);
    try { await transitionIncidentState(id, target, null); await load(); }
    catch (e) {
      setError(e?.response?.data?.detail || e?.message
        || "The state transition was refused.");
    } finally { setBusy(null); }
  };

  const canManage  = access.can("incidents.update");
  const canRespond = access.canAny(["response.recommend", "response.execute"]);

  const vc = incident?.verdict_card || {};
  const assets = incident?.assets || {};

  const actions = useMemo(() => {
    if (!incident) return null;
    const next = LIFECYCLE_NEXT[incident.state || "new"] || [];
    return (
      <>
        {next.map((s) => (
          <button key={s} className="nx-dt-btn"
                  data-testid={`incident-transition-${s}`}
                  disabled={busy === s || canManage === false}
                  title={canManage === false
                    ? "You are not authorized to change incident state"
                    : canManage === null
                      ? "Authorization contract unavailable — the server decides"
                      : undefined}
                  onClick={() => transition(s)}>
            {busy === s ? "…" : (LC_LABEL[s] || s)}
          </button>
        ))}
        <button className="nx-dt-btn" data-testid="incident-open-respond"
                disabled={canRespond === false}
                title={canRespond === false
                  ? "You are not authorized to request a response"
                  : undefined}
                onClick={() => setRespondOpen(true)}>
          Respond
        </button>
        <OpenInEdr
          device={incident.endpoint_campaign?.endpoint_id
                  || incident.endpoint_campaign?.device_ref
                  || incident.endpoint_campaign?.device_iid}
          incident={incident.id}
          disabledReason="This incident carries no endpoint identity, so no
                          trajectory can be opened for it."
        />
      </>
    );
  }, [incident, busy, canManage, canRespond]); // eslint-disable-line

  if (loading && !incident) {
    return (
      <XdrShell>
        <NxPageShell testid="incident-workspace-loading">
          <div className="nx-sec">
            <NxSkeleton width="40%" height={20} />
            <div style={{ marginTop: 12 }}><NxSkeleton width="70%" /></div>
            <div style={{ marginTop: 8 }}><NxSkeleton width="55%" /></div>
          </div>
        </NxPageShell>
      </XdrShell>
    );
  }

  if (!incident) {
    return (
      <XdrShell>
        <NxPageShell testid="incident-workspace-error">
          <NxEmpty
            title="This incident is not available to you"
            hint={String(error
              || "The incident does not exist, or it belongs to a tenant you "
               + "are not authorized for. NivXRay returns the same answer for "
               + "both, so existence is never disclosed.")}
            data-testid="incident-workspace-notfound"
          />
        </NxPageShell>
      </XdrShell>
    );
  }

  return (
    <XdrShell>
      <NxPageShell testid="incident-workspace">
        <NxEntityHeader
          testid="incident-header"
          eyebrow={`INCIDENT · ${incident.number || incident.id}`}
          title={incident.name}
          chips={
            <>
              <NxVerdict value={vc.verdict || incident.severity}
                         title={vc.reason} testid="incident-verdict" />
              <NxConfidence value={vc.confidence ?? incident.confidence}
                            testid="incident-confidence" />
              <NxRisk score={incident.verdict_stage2?.risk_score
                             ?? incident.verdict?.risk_score}
                      testid="incident-risk" />
              <NxPriority priority={incident.priority}
                          testid="incident-priority" />
              <NxLifecycle value={incident.state} testid="incident-state" />
            </>
          }
          actions={actions}
          facts={
            <>
              <NxFact label="Owner" testid="incident-fact-owner">
                {incident.assignee || <Absent>Unassigned</Absent>}
              </NxFact>
              <NxFact label="Tenant" testid="incident-fact-tenant">
                {incident.tenant || <Absent />}
              </NxFact>
              <NxFact label="Detection source" testid="incident-fact-source">
                {vc.engine || incident.source_integration_id || <Absent />}
              </NxFact>
              <NxFact label="Evidence" testid="incident-fact-evidence">
                {incident.evidence_count == null
                  ? <Absent /> : `${incident.evidence_count} canonical`}
              </NxFact>
              <NxFact label="Created" testid="incident-fact-created">
                {incident.created_at || <Absent />}
              </NxFact>
              <NxFact label="Updated" testid="incident-fact-updated">
                {incident.updated_at || <Absent />}
              </NxFact>
            </>
          }
          provenance={
            <>
              <NxProvenanceChip provenance={incident.provenance}
                                basis={incident.provenance_basis}
                                isReal={incident.provenance_is_real}
                                testid="incident-provenance" />
              <span style={{ marginLeft: 10 }}>
                {incident.provenance_basis
                  || "No provenance basis was recorded for this incident."}
              </span>
            </>
          }
          tabs={TABS}
          activeTab={tab}
          onTabChange={setTab}
        />

        {error && (
          <div className="nx-dt-error" role="alert"
               data-testid="incident-workspace-banner-error">
            <strong>The last action was refused.</strong>
            <span>{String(error)}</span>
          </div>
        )}

        <div data-testid={`incident-tab-${tab}`}>
          {tab === "overview" && (
            <>
              <IncidentIntelligenceContext incidentId={incident.id} />
              <section className="nx-sec">
                <h3 className="nx-sec-title">Verdict, cited</h3>
                <dl className="nx-kv">
                  <dt>Verdict</dt>
                  <dd><NxVerdict value={vc.verdict || incident.severity} /></dd>
                  <dt>Derivation</dt>
                  <dd>{vc.reason || <Absent>No derivation recorded</Absent>}</dd>
                  <dt>Engine</dt>
                  <dd>{vc.engine || <Absent />}</dd>
                  <dt>Provenance</dt>
                  <dd>{incident.provenance_basis || <Absent />}</dd>
                </dl>
              </section>
              <section className="nx-sec">
                <h3 className="nx-sec-title">What was affected</h3>
                <div className="nx-grid4">
                  {["hosts", "users", "processes", "files", "network"].map((k) => (
                    <NxMetric key={k} label={k} value={assets[k] ?? null}
                              reason="Not counted on this record"
                              testid={`incident-asset-${k}`} />
                  ))}
                </div>
              </section>
              <ExecutiveTab incident={incident} />
              <EngineDepth title="Why this verdict"
                           hint="Deterministic verdict derivation and the causal security-state machine, as the engine recorded them."
                           caseId={incident.id}
                           capabilities={["verdict", "security_state"]} />
            </>
          )}

          {tab === "story" && (
            <>
              <section className="nx-sec">
                <h3 className="nx-sec-title">Attack progression</h3>
                <NxAttackChain nodes={incident.attack_progression}
                               testid="incident-attack-chain" />
              </section>
              <AttackStoryTab incident={incident} />
              <EngineDepth title="How it unfolded"
                           hint="Reconstructed causal narrative and process ancestry for this incident."
                           caseId={incident.id}
                           capabilities={["story", "process"]} />
            </>
          )}

          {tab === "timeline"   && (
            <>
              <TimelineTab incident={incident} />
              <EngineDepth title="Device trajectory"
                           hint="Endpoint event stream across the process, network, file, registry and system lanes."
                           caseId={incident.id}
                           capabilities={["trajectory"]} />
            </>
          )}
          {tab === "evidence"   && (
            <>
              <EvidenceTab incident={incident} />
              <EngineDepth title="Extracted artifacts & hashes"
                           hint="Artifacts the pipeline extracted from this case, with their hash chain."
                           caseId={incident.id}
                           capabilities={["evidence"]} />
            </>
          )}
          {tab === "entities"   && (
            <>
              <AttackGraphTab incident={incident} onNavigateTab={setTab} />
              <RelatedTab incident={incident} />
              <EngineDepth title="Evidence graph (IKG)"
                           hint="Entity and relationship graph the investigation was derived from."
                           caseId={incident.id}
                           capabilities={["graph"]} />
            </>
          )}
          {tab === "detections" && <TechnicalTab  incident={incident} />}
          {tab === "mitre"      && (
            <>
              <MitreTab incident={incident} />
              <EngineDepth title="Engine technique mapping"
                           hint="ATT&CK techniques the causal engine attributed to this incident."
                           caseId={incident.id}
                           capabilities={["attack"]} />
            </>
          )}
          {tab === "response"   && (
            <>
              <section className="nx-sec">
                <h3 className="nx-sec-title">Response authority</h3>
                <p style={{ fontSize: 12, color: "var(--nx-text-dim)",
                            margin: "0 0 10px", lineHeight: 1.6 }}>
                  NivXRay keeps <strong>Requested → Approved → Dispatched →
                  Executed → Verified</strong> as five distinct facts. An
                  approved action is never rendered as a contained endpoint.
                </p>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {["Requested", "Approved", "Dispatched", "Executed",
                    "Verified"].map((s) => (
                    <NxChip key={s} tone="neutral" variant="dashed">{s}</NxChip>
                  ))}
                </div>
                <button className="nx-dt-btn" style={{ marginTop: 12 }}
                        data-testid="incident-response-open"
                        disabled={canRespond === false}
                        onClick={() => setRespondOpen(true)}>
                  Open response drawer <ArrowUpRight size={13} />
                </button>
              </section>
              <RecommendationsTab incident={incident} />
            </>
          )}
          {tab === "activity"   && (
            <>
              <AutoInvestigationTab incident={incident} />
              <NotesTab incident={incident} />
              <ClosureTab incident={incident} onUpdated={load} />
            </>
          )}
          {tab === "report"     && <ReportTab incident={incident} />}
        </div>
      </NxPageShell>

      {respondOpen && (
        <AnalystResponseDrawer
          incident={incident}
          analystEmail={access.principal}
          defaultHostId={incident.endpoint_campaign?.endpoint_id || null}
          open={respondOpen}
          onClose={() => setRespondOpen(false)}
        />
      )}
    </XdrShell>
  );
}
