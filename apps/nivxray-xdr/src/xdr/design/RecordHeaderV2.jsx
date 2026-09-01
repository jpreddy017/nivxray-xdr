/**
 * RecordHeaderV2 · Round 29 (Round 24.9 grammar).
 * ---------------------------------------------------------------
 * The migrated Incident Header — the identity band that anchors
 * every tab on the incident record page.
 *
 * The header is a PROJECTION of authoritative investigation state.
 * It does not read from a second source of truth and never invents
 * a severity, verdict, or provenance layer that the incident model
 * has not already produced.
 *
 * Composition contract:
 *   <Entity>        → the incident's identity
 *                     (name = incident.name, id = incident.number)
 *   <EvidenceState> → priority · state · verdict (closed enum only)
 *   <Provenance>    → Telemetry → Canonical → Correlation → Mapping
 *                     Missing layers render as "not present" — never
 *                     back-filled.
 *   <Relationship>  → owner · customer (when present)
 *   <Action>        → Respond (primary · capability-gated),
 *                     Generate Report (cap-standby · Phase 5),
 *                     More (cap-standby)
 */
import React from "react";
import { ChevronLeft, Zap, FileText, MoreHorizontal } from "lucide-react";
import { Link } from "react-router-dom";

import Entity from "@/xdr/design/Entity";
import EvidenceState from "@/xdr/design/EvidenceState";
import Provenance from "@/xdr/design/Provenance";
import Relationship from "@/xdr/design/Relationship";
import Action, { ActionGroup } from "@/xdr/design/Action";
import "@/xdr/design/tokens.css";


function fmtDate(iso) {
  if (!iso) return null;
  const s = String(iso);
  return s.length >= 16 ? s.slice(0, 16).replace("T", " ") : s;
}


/** Priority code (P1..P5) → closed EvidenceState value.  Never
 *  fabricates a level — an incident without a priority renders as
 *  `missing` with an explicit reason. */
function stateForPriority(code) {
  if (!code) return { state: "missing", reason: "PRIORITY_NOT_SET",
                       label: "Priority not set" };
  switch (String(code).toUpperCase()) {
    case "P1": return { state: "unavailable", reason: null, label: "Priority P1" };
    case "P2": return { state: "unavailable", reason: null, label: "Priority P2" };
    case "P3": return { state: "missing",     reason: null, label: "Priority P3" };
    case "P4": return { state: "suppressed",  reason: null, label: "Priority P4" };
    case "P5": return { state: "suppressed",  reason: null, label: "Priority P5" };
    default:   return { state: "missing",     reason: `PRIORITY_UNKNOWN · ${code}`,
                         label: `Priority ${code}` };
  }
}


/** Lifecycle state → closed EvidenceState value. */
function stateForLifecycle(state) {
  switch (String(state || "").toLowerCase()) {
    case "new":         return { state: "missing",     label: "New · triage pending" };
    case "in_progress": return { state: "supported",   label: "In progress" };
    case "on_hold":     return { state: "suppressed",  label: "On hold" };
    case "resolved":    return { state: "actioned",    label: "Resolved" };
    case "closed":      return { state: "suppressed",  label: "Closed" };
    default:            return { state: "missing",
                                  label: state ? `State ${state}` : "State unknown",
                                  reason: state ? null : "STATE_NOT_SET" };
  }
}


/** Stage-2 verdict → closed EvidenceState value.  If no verdict has
 *  been produced, we render `missing` — never a default of "unknown"
 *  disguised as green. */
function stateForVerdict(incident) {
  const raw = String(incident?.verdict_stage2?.label
                        || incident?.verdict || "").toLowerCase();
  if (!raw || raw === "unknown" || raw === "not_run") {
    return { state: "missing", label: "Verdict pending",
              reason: "NOT_RUN" };
  }
  if (raw === "malicious")  return { state: "observed",    label: "Verdict · MALICIOUS" };
  if (raw === "suspicious") return { state: "supported",   label: "Verdict · SUSPICIOUS" };
  if (raw === "benign")     return { state: "suppressed",  label: "Verdict · BENIGN" };
  return { state: "missing", label: `Verdict · ${raw.toUpperCase()}`,
            reason: "UNRECOGNISED" };
}


/** Build the header's Telemetry → Canonical → Correlation → Mapping
 *  chain from whatever the incident model has already produced.  A
 *  layer without a real value is `present: false` — the primitive
 *  will render "not present" in muted italic. */
function buildProvenance(incident) {
  const telemetry = incident?.source_integration_id
    || incident?.source
    || (Array.isArray(incident?.sources) && incident.sources[0])
    || null;
  const canonical =
       (Array.isArray(incident?.canonical_evidence_ids)
          && incident.canonical_evidence_ids.length
          ? `${incident.canonical_evidence_ids.length} event(s)`
          : null)
    || incident?.canonical_event_id
    || null;
  const correlate = incident?.correlation_rule_id
    || (Array.isArray(incident?.correlation_match_ids)
        && incident.correlation_match_ids.length
        ? `${incident.correlation_match_ids.length} match(es)` : null)
    || null;
  const techniques = Array.isArray(incident?.mitre) ? incident.mitre : [];
  const mapping = techniques.length
    ? `${techniques.length} technique${techniques.length === 1 ? "" : "s"}`
    : null;
  return [
    { layer: "telemetry", value: telemetry,  present: !!telemetry },
    { layer: "canonical", value: canonical,  present: !!canonical },
    { layer: "correlate", value: correlate,  present: !!correlate },
    { layer: "mapping",   value: mapping,    present: !!mapping },
  ];
}


export default function RecordHeaderV2({ incident, onOpenRespond }) {
  const priority  = stateForPriority(incident?.priority?.code);
  const lifecycle = stateForLifecycle(incident?.state);
  const verdict   = stateForVerdict(incident);
  const chain     = buildProvenance(incident);

  // The Respond action is bound to an operational capability, not a
  // decorative style.  A closed / resolved incident cannot accept a
  // new response — the Action renders the honest disabled reason
  // instead of a silently greyed button.
  const stateRaw = String(incident?.state || "").toLowerCase();
  const respondCap = (stateRaw === "closed" || stateRaw === "resolved")
    ? "cap-unavailable" : "cap-full";
  const respondReason = respondCap === "cap-unavailable"
    ? `INCIDENT_${stateRaw.toUpperCase()}` : null;

  const owner  = incident?.assignee || null;
  const tenant = incident?.tenant   || null;

  return (
    <div className="evops evops-canvas" data-testid="xdr-record-header-v2">
      <div className="rl-breadcrumb"
           data-testid="xdr-record-breadcrumb"
           style={{ paddingBottom: 6 }}>
        <Link to="/xdr/incidents" data-testid="xdr-record-back">
          <ChevronLeft size={12} style={{ display: "inline",
                                          verticalAlign: "-1px" }} />
          Incidents
        </Link>
        <span className="sep">/</span>
        <span className="rl-crumb-id">
          {incident?.number
            || (incident?.id || "").slice(0, 12) + "…"}
        </span>
      </div>

      <div className="evops-band" data-testid="xdr-record-header-v2-band">
        <div style={{ display: "flex", flexDirection: "column",
                      gap: 6, minWidth: 0 }}>
          <div className="evops-band__eyebrow">Incident</div>
          <Entity
            kind="rule"
            size="lg"
            name={incident?.name || "(unnamed incident)"}
            id={incident?.number || incident?.id || ""}
            testid="xdr-record-v2-entity"
          />
          <div className="evops-mono"
               data-testid="xdr-record-v2-timestamps">
            First seen {fmtDate(incident?.created_at) || "—"}
            {" · "}
            Last activity {fmtDate(incident?.updated_at) || "—"}
          </div>
        </div>

        <div className="evops-band__spacer" />

        <ActionGroup testid="xdr-record-v2-actions">
          <Action
            label="Respond"
            icon={Zap}
            tone="primary"
            capability={respondCap}
            onRun={onOpenRespond}
            reason={respondReason}
            testid="xdr-record-respond"
          />
          <Action
            label="Generate Report"
            icon={FileText}
            capability="cap-standby"
            reason="PHASE_5"
            testid="xdr-record-report"
          />
          <Action
            label="More"
            icon={MoreHorizontal}
            capability="cap-standby"
            reason="PHASE_3_PLUS"
            testid="xdr-record-more"
          />
        </ActionGroup>
      </div>

      <div className="evops-section"
           data-testid="xdr-record-v2-truthstate">
        <div className="evops-section__head">
          <span className="evops-section__eyebrow">Truth state</span>
          <span className="evops-section__spacer" />
        </div>
        <div style={{ display: "flex", flexWrap: "wrap",
                      gap: "10px 14px", padding: "10px 0",
                      alignItems: "center" }}>
          <EvidenceState
            state={priority.state}
            label={priority.label}
            reason={priority.reason}
            testid="xdr-record-v2-priority"
          />
          <EvidenceState
            state={lifecycle.state}
            label={lifecycle.label}
            reason={lifecycle.reason}
            testid="xdr-record-v2-state"
          />
          <EvidenceState
            state={verdict.state}
            label={verdict.label}
            reason={verdict.reason}
            testid="xdr-record-v2-verdict"
          />
        </div>
      </div>

      <div className="evops-section"
           data-testid="xdr-record-v2-provenance-section">
        <div className="evops-section__head">
          <span className="evops-section__eyebrow">Provenance</span>
          <span className="evops-section__spacer" />
        </div>
        <div style={{ padding: "10px 0" }}>
          <Provenance chain={chain}
                      testid="xdr-record-v2-provenance" />
        </div>
      </div>

      {(owner || tenant) && (
        <div className="evops-section"
             data-testid="xdr-record-v2-relationships">
          <div className="evops-section__head">
            <span className="evops-section__eyebrow">Relationships</span>
            <span className="evops-section__spacer" />
          </div>
          <div style={{ display: "flex", flexDirection: "column",
                        gap: 8, padding: "10px 0" }}>
            {owner && (
              <Relationship
                from={<Entity kind="user" name={owner} />}
                via="owns"
                to={<Entity kind="rule"
                            name={incident?.name || "incident"}
                            id={incident?.number || incident?.id} />}
                state="observed"
                testid="xdr-record-v2-rel-owner"
              />
            )}
            {tenant && (
              <Relationship
                from={<Entity kind="source" name={tenant}
                              id="customer" />}
                via="scoped to"
                to={<Entity kind="rule"
                            name={incident?.name || "incident"}
                            id={incident?.number || incident?.id} />}
                state="observed"
                testid="xdr-record-v2-rel-customer"
              />
            )}
          </div>
        </div>
      )}

      {!owner && (
        <div className="evops-empty"
             data-testid="xdr-record-v2-unassigned"
             style={{ marginTop: 12 }}>
          <div className="evops-empty__title">Unassigned</div>
          <div className="evops-empty__reason">
            No analyst has taken ownership of this incident yet — the
            queue view is authoritative for triage assignment.
          </div>
        </div>
      )}
    </div>
  );
}
