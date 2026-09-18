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
  NxInvSection, NxInvMetrics, NxInvValue, NxInvTech, ABSENCE,
} from "@/xdr/nx";
import AnalystResponseDrawer from "@/xdr/respond/AnalystResponseDrawer";
import OpenInEdr from "@/xdr/components/OpenInEdr";
import IncidentIntelligenceContext from "@/xdr/intelligence/IncidentIntelligenceContext";

import ExecutiveTab         from "./incidents/record/tabs/ExecutiveTab";
import ActivityWorklogTab   from "./incidents/record/tabs/ActivityWorklogTab";
import TechnicalTab         from "./incidents/record/tabs/TechnicalTab";
import EvidenceTab          from "./incidents/record/tabs/EvidenceTab";
import AutoInvestigationTab from "./incidents/record/tabs/AutoInvestigationTab";
import MitreTab             from "./incidents/record/tabs/MitreTab";
import AttackStoryTab       from "./incidents/record/tabs/AttackStoryTab";
import EntitiesGraphTab     from "./incidents/record/tabs/EntitiesGraphTab";
import FindingsTab          from "./incidents/record/tabs/FindingsTab";
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
import "@/xdr/nx/nx-inv.css";
import { apiErrorText } from "@/xdr/nx/apiError";

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
      setError(apiErrorText(e, "This incident could not be loaded."));
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
      setError(apiErrorText(e, "The state transition was refused."));
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
              <NxChip tone="neutral" variant="dashed"
                      data-testid="incident-completeness"
                      title="Analysis completeness is NOT confidence. An incident can be high confidence and still evidence-incomplete.">
                {incident.analysis_completeness
                  || incident.completeness?.state
                  || ABSENCE.EVIDENCE_INCOMPLETE}
              </NxChip>
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

        {/* `record-theme.css` is scoped ENTIRELY under `.xdr-record-l3`, and
            no surface carried that class after the workspace rewrite — so
            every tab still using the legacy `rl-*` classes (Notes, Closure,
            Executive, Related, Threat Assessment) rendered as unstyled text
            with undefined colours. The scope is restored here until those
            components finish migrating to `xdr/nx`. */}
        <div className="xdr-record-l3" data-testid={`incident-tab-${tab}`}>
          {tab === "overview" && (
            <div className="inv">
              {/* Assessment · completeness · evidence — three DIFFERENT
                  questions, never collapsed into one another. An
                  investigation may be HIGH CONFIDENCE and still
                  EVIDENCE INCOMPLETE. */}
              <NxInvSection title="Assessment"
                            subtitle="what we believe, how sure we are, and how complete the analysis is"
                            testid="incident-overview-assessment">
                <NxInvMetrics testid="incident-overview-metrics" items={[
                  { key: "verdict", label: "Verdict",
                    value: vc.verdict || incident.severity || null,
                    absent: ABSENCE.NOT_EVALUATED },
                  { key: "confidence", label: "Confidence",
                    value: vc.confidence ?? incident.confidence ?? null,
                    absent: ABSENCE.NOT_EVALUATED },
                  { key: "completeness", label: "Analysis completeness",
                    value: incident.analysis_completeness
                      || incident.completeness?.state || null,
                    absent: ABSENCE.NOT_EVALUATED,
                    sub: "independent of confidence" },
                  { key: "risk", label: "Risk",
                    value: incident.verdict_stage2?.risk_score
                      ?? incident.verdict?.risk_score ?? null,
                    absent: ABSENCE.NOT_EVALUATED },
                  { key: "evidence", label: "Evidence",
                    value: incident.evidence_count ?? null,
                    absent: ABSENCE.EVIDENCE_INCOMPLETE },
                  { key: "priority", label: "Priority",
                    value: incident.priority?.label || incident.priority || null,
                    absent: ABSENCE.NOT_EVALUATED },
                ]} />
              </NxInvSection>

              <NxInvSection title="Why this verdict"
                            subtitle="derivation, engine and provenance — cited"
                            testid="incident-overview-verdict" pad>
                <dl className="inv-kv">
                  <dt>Verdict</dt>
                  <dd><NxVerdict value={vc.verdict || incident.severity} /></dd>
                  <dt>Derivation</dt>
                  <dd><NxInvValue value={vc.reason}
                        absent="NOT RECORDED — no derivation was stored" /></dd>
                  <dt>Engine</dt>
                  <dd className="mono"><NxInvValue value={vc.engine}
                        absent={ABSENCE.NOT_RECORDED} /></dd>
                  <dt>Provenance</dt>
                  <dd><NxInvValue value={incident.provenance_basis}
                        absent={ABSENCE.EVIDENCE_INCOMPLETE} /></dd>
                </dl>
              </NxInvSection>

              <NxInvSection title="What was affected"
                            subtitle="counts come from the incident record — an uncounted class is not zero"
                            testid="incident-overview-affected">
                <NxInvMetrics testid="incident-overview-assets" items={
                  ["hosts", "users", "processes", "files", "network"].map((k) => ({
                    key: k, label: k, value: assets[k] ?? null,
                    absent: ABSENCE.NOT_OBSERVED,
                  }))} />
              </NxInvSection>

              <NxInvSection title="Incident summary"
                            subtitle="evidence-backed narrative and recommended next inspection"
                            testid="incident-overview-summary">
                <div className="inv-sec__b--pad">
                  <ExecutiveTab incident={incident} />
                </div>
              </NxInvSection>

              <NxInvSection title="Intelligence context"
                            subtitle="effective intelligence applied to this incident"
                            testid="incident-overview-intel">
                <div className="inv-sec__b--pad">
                  <IncidentIntelligenceContext incidentId={incident.id} />
                </div>
              </NxInvSection>

              <EngineDepth title="Technical reasoning · verdict engine and causal state machine"
                           hint="The deterministic verdict derivation and the causal security-state machine, exactly as the engine recorded them."
                           caseId={incident.id}
                           capabilities={["verdict", "security_state"]} />
            </div>
          )}

          {tab === "story" && (
            <div className="inv">
              {(incident.attack_progression || []).length > 0 && (
                <NxInvSection title="Attack chain"
                              subtitle="the stages evidence places this incident in"
                              testid="incident-story-chain">
                  <div className="inv-sec__b--pad">
                    <NxAttackChain nodes={incident.attack_progression}
                                   testid="incident-attack-chain" />
                  </div>
                </NxInvSection>
              )}
              <AttackStoryTab incident={incident} />
              <EngineDepth title="How it unfolded"
                           hint="Reconstructed causal narrative and process ancestry for this incident."
                           caseId={incident.id}
                           capabilities={["story", "process"]} />
            </div>
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
            <div className="inv">
              <NxInvSection title="Entities"
                            subtitle="every entity class this incident touches — an uncounted class is not zero"
                            testid="incident-entities-inventory">
                <NxInvMetrics testid="incident-entities-metrics" items={[
                  { key: "devices", label: "Devices",
                    value: assets.hosts ?? null, absent: ABSENCE.NOT_OBSERVED },
                  { key: "users", label: "Users",
                    value: assets.users ?? null, absent: ABSENCE.NOT_OBSERVED },
                  { key: "processes", label: "Processes",
                    value: assets.processes ?? null, absent: ABSENCE.NOT_OBSERVED },
                  { key: "files", label: "Files / hashes",
                    value: assets.files ?? null, absent: ABSENCE.NOT_OBSERVED },
                  { key: "network", label: "IPs / domains / URLs",
                    value: assets.network ?? null, absent: ABSENCE.NOT_OBSERVED },
                ]} />
              </NxInvSection>

              <NxInvSection title="Related entities"
                            subtitle="pivot into any entity's own 360 view"
                            testid="incident-entities-related">
                <div className="inv-sec__b--pad">
                  <RelatedTab incident={incident} />
                </div>
              </NxInvSection>

              <NxInvSection title="Relationships"
                            subtitle="the causality graph for this incident — graph or table, with contextual entity details"
                            testid="incident-entities-relationships">
                <EntitiesGraphTab incident={incident}
                                  onNavigateTab={(t) =>
                                    setTab(t === "findings" ? "activity" : t)} />
              </NxInvSection>

              <EngineDepth title="Evidence graph (IKG)"
                           hint="The entity and relationship graph this investigation was derived from."
                           caseId={incident.id}
                           capabilities={["graph"]} />
            </div>
          )}
          {tab === "detections" && <TechnicalTab incident={incident} />}
          {tab === "mitre"      && (
            <div className="inv">
              <NxInvSection title="ATT&CK coverage"
                            subtitle="a technique appears only where evidence substantiates it"
                            testid="incident-mitre-sec">
                <div className="inv-sec__b--pad">
                  <MitreTab incident={incident} />
                </div>
              </NxInvSection>
              <EngineDepth title="Engine technique mapping"
                           hint="ATT&CK techniques the causal engine attributed to this incident."
                           caseId={incident.id}
                           capabilities={["attack"]} />
            </div>
          )}
          {tab === "response"   && (
            <>
              <section className="nx-sec" data-testid="incident-response-authority">
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
              <NxInvSection title="Response actions"
                            subtitle="recommended · requested · approved · dispatched · executed · verified"
                            testid="incident-response-actions">
                <div className="inv-sec__b--pad">
                  <RecommendationsTab incident={incident} />
                </div>
              </NxInvSection>
            </>
          )}
          {tab === "activity"   && (
            <div className="inv">
              <ActivityWorklogTab incident={incident}
                                  onNavigateTab={(t) =>
                                    setTab(t === "findings" ? "activity" : t)} />
              <FindingsTab incident={incident}
                           onNavigateTab={(t) =>
                             setTab(t === "findings" ? "activity" : t)} />
              <NxInvSection title="Analyst notes"
                            subtitle="attributed to the principal who wrote them"
                            testid="incident-activity-notes">
                <div className="inv-sec__b--pad">
                  <NotesTab incident={incident} />
                </div>
              </NxInvSection>
              <NxInvSection title="Closure"
                            subtitle="how this incident was concluded"
                            testid="incident-activity-closure">
                <div className="inv-sec__b--pad">
                  <ClosureTab incident={incident} onUpdated={load} />
                </div>
              </NxInvSection>
              {/* The previous prose feed is preserved as engine detail —
                  it is no longer a second, longer copy of the table above. */}
              <NxInvSection title="Engine detail"
                            subtitle="findings, overlays and the raw investigation feed"
                            testid="incident-activity-auto">
                <NxInvTech label="Autonomous investigation feed (engine view)"
                           testid="incident-activity-auto-tech">
                  <AutoInvestigationTab incident={incident} />
                </NxInvTech>
              </NxInvSection>
            </div>
          )}
          {tab === "report"     && (
            <div className="inv">
              <NxInvSection
                title="Investigation report"
                subtitle="evidence-derived sections are read-only; analyst sections are editable and attributed"
                testid="incident-report-sec">
                <div className="inv-sec__b--pad">
                  <ReportTab incident={incident} />
                </div>
              </NxInvSection>
            </div>
          )}
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
