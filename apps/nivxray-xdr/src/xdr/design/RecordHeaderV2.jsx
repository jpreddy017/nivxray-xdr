/**
 * RecordHeaderV2 · Round 29 · Investigation Command Band.
 * ---------------------------------------------------------------
 * A single dense anchor at the top of every incident record.  The
 * information hierarchy the analyst reads in ≤10 seconds:
 *
 *   1. Priority accent (top rule)  — how urgent is this?
 *   2. Title + entity id           — what am I looking at?
 *   3. Inline state chips           — where in the pipeline is it?
 *   4. Meta line (first/last seen · owner · SLA)
 *   5. Vitals grid                  — the incident's evidence weight
 *      Evidence · Hosts · Users · Processes · Files · Network ·
 *      MITRE · Verdict
 *   6. Compact provenance line     — Telemetry → … → MITRE
 *
 * Rules:
 *   · No fabrication.  MITRE count is gated on evidence_count > 0
 *     because a mapping without upstream evidence cannot be
 *     evidence-backed.
 *   · No RBAC on the primary canvas.  Owner/tenant live in the
 *     command band's meta line — they are metadata, not
 *     investigation state.
 *   · Adaptive collapse: with no telemetry the vitals row still
 *     renders (so the analyst sees the honest zeros) but the
 *     provenance line falls to a single "no telemetry" hint.
 */
import React from "react";
import { ChevronLeft, Zap, FileText, MoreHorizontal, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";

import Entity from "@/xdr/design/Entity";
import EvidenceState from "@/xdr/design/EvidenceState";
import Provenance from "@/xdr/design/Provenance";
import Action, { ActionGroup } from "@/xdr/design/Action";
import "@/xdr/design/tokens.css";


function fmtDate(iso) {
  if (!iso) return null;
  const s = String(iso);
  return s.length >= 16 ? s.slice(0, 16).replace("T", " ") : s;
}


function stateForPriority(code) {
  if (!code) return { state: "missing", label: "Priority not set",
                       reason: "PRIORITY_NOT_SET" };
  const c = String(code).toUpperCase();
  switch (c) {
    case "P1": return { state: "unavailable", label: "P1 · Critical" };
    case "P2": return { state: "unavailable", label: "P2 · High" };
    case "P3": return { state: "missing",     label: "P3 · Medium" };
    case "P4": return { state: "suppressed",  label: "P4 · Low" };
    case "P5": return { state: "suppressed",  label: "P5 · Info" };
    default:   return { state: "missing",     label: c,
                         reason: "PRIORITY_UNKNOWN" };
  }
}


function stateForLifecycle(state) {
  switch (String(state || "").toLowerCase()) {
    case "new":         return { state: "missing",    label: "New" };
    case "in_progress": return { state: "supported",  label: "In progress" };
    case "on_hold":     return { state: "suppressed", label: "On hold" };
    case "resolved":    return { state: "actioned",   label: "Resolved" };
    case "closed":      return { state: "suppressed", label: "Closed" };
    default:            return { state: "missing",
                                  label: state ? String(state) : "State unknown",
                                  reason: state ? null : "STATE_NOT_SET" };
  }
}


function stateForVerdict(incident) {
  const raw = String(incident?.verdict_stage2?.label
                        || incident?.verdict || "").toLowerCase();
  if (!raw || raw === "unknown" || raw === "not_run") {
    return { state: "missing", label: "Verdict pending",
              reason: "NOT_RUN", short: "Pending" };
  }
  if (raw === "malicious")  return { state: "observed",   label: "Malicious",  short: "Malicious"  };
  if (raw === "suspicious") return { state: "supported",  label: "Suspicious", short: "Suspicious" };
  if (raw === "benign")     return { state: "suppressed", label: "Benign",     short: "Benign"     };
  return { state: "missing", label: raw.toUpperCase(),
            short: raw.toUpperCase(), reason: "UNRECOGNISED" };
}


function countEntities(incident) {
  const a    = incident?.assets || {};
  const iocs = incident?.iocs   || {};
  const len  = (v) => Array.isArray(v) ? v.length : 0;
  return {
    hosts:     len(a.hosts)     || len(incident?.hosts),
    users:     len(a.users)     || len(incident?.users),
    processes: len(a.processes) || len(incident?.processes),
    files:     len(a.files)     || len(iocs.hashes) || len(iocs.files),
    network:   len(a.network)   || len(iocs.ips) + len(iocs.domains)
                                    + len(iocs.urls),
  };
}


function buildProvenance(incident, evidenceCount) {
  const telemetryVal = incident?.source_integration_id
    || incident?.source
    || (Array.isArray(incident?.sources) && incident.sources[0])
    || null;
  const canonicalVal = (Array.isArray(incident?.canonical_evidence_ids)
        && incident.canonical_evidence_ids.length
          ? `${incident.canonical_evidence_ids.length} event(s)`
          : null)
    || incident?.canonical_event_id
    || (evidenceCount > 0
          ? `${evidenceCount} event${evidenceCount === 1 ? "" : "s"}`
          : null);
  const correlateVal = incident?.correlation_rule_id
    || (Array.isArray(incident?.correlation_match_ids)
        && incident.correlation_match_ids.length
        ? `${incident.correlation_match_ids.length} match(es)` : null)
    || null;
  const upstreamPresent = !!(telemetryVal || canonicalVal || correlateVal);
  const techniques = Array.isArray(incident?.mitre) ? incident.mitre : [];
  const mappingVal = upstreamPresent && techniques.length
    ? `${techniques.length} technique${techniques.length === 1 ? "" : "s"}`
    : null;
  return {
    chain: [
      { layer: "telemetry", value: telemetryVal, present: !!telemetryVal },
      { layer: "canonical", value: canonicalVal, present: !!canonicalVal },
      { layer: "correlate", value: correlateVal, present: !!correlateVal },
      { layer: "mapping",   value: mappingVal,   present: !!mappingVal },
    ],
    upstreamPresent,
  };
}


export default function RecordHeaderV2({ incident, onOpenRespond }) {
  const priorityCode = String(incident?.priority?.code || "").toUpperCase();
  const priority     = stateForPriority(priorityCode);
  const lifecycle    = stateForLifecycle(incident?.state);
  const verdict      = stateForVerdict(incident);

  const evidenceCount    = Number(incident?.evidence_count || 0);
  const correlationCount =
       Array.isArray(incident?.correlation_match_ids)
         ? incident.correlation_match_ids.length : 0;
  const rawMitreCount    = Array.isArray(incident?.mitre)
    ? incident.mitre.length : 0;
  // MITRE count is derived, not authoritative — gated on evidence.
  const mitreCount = evidenceCount > 0 ? rawMitreCount : 0;

  const { chain, upstreamPresent } = buildProvenance(incident, evidenceCount);
  const e = countEntities(incident);

  const stateRaw = String(incident?.state || "").toLowerCase();
  const respondCap = (stateRaw === "closed" || stateRaw === "resolved")
    ? "cap-unavailable" : "cap-full";
  const respondReason = respondCap === "cap-unavailable"
    ? `INCIDENT_${stateRaw.toUpperCase()}` : null;

  return (
    <div className="evops evops-canvas"
         data-testid="xdr-record-header-v2"
         style={{ paddingBottom: 4 }}>

      {/* Breadcrumb */}
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

      {/* Command Band — dark navy security-console strip */}
      <div className="evops-cmd"
           data-priority={priorityCode || ""}
           data-testid="xdr-record-v2-cmd-band">
        <div className="evops-cmd__row">
          <div style={{ minWidth: 0, flex: "0 1 auto" }}>
            <div className="evops-cmd__eyebrow">Incident</div>
            <div className="evops-cmd__title"
                 data-testid="xdr-record-v2-title">
              <span className="evops-entity" data-kind="rule">
                <span className="evops-entity__icon" aria-hidden>
                  <ShieldAlert size={16} />
                </span>
              </span>
              <span className="evops-cmd__title-text">
                {incident?.name || "(unnamed incident)"}
              </span>
            </div>
            <div className="evops-cmd__id"
                 data-testid="xdr-record-v2-id">
              {incident?.number || incident?.id}
            </div>
          </div>

          <div className="evops-cmd__spacer" />

          <div style={{ display: "flex", gap: 6, flexWrap: "wrap",
                        justifyContent: "flex-end",
                        alignSelf: "flex-start" }}
               data-testid="xdr-record-v2-chips">
            <EvidenceState state={priority.state}
                            label={priority.label}
                            reason={priority.reason}
                            testid="xdr-record-v2-priority" />
            <EvidenceState state={lifecycle.state}
                            label={lifecycle.label}
                            reason={lifecycle.reason}
                            testid="xdr-record-v2-state" />
            <EvidenceState state={verdict.state}
                            label={verdict.label}
                            reason={verdict.reason}
                            testid="xdr-record-v2-verdict" />
          </div>
        </div>

        <div className="evops-cmd__meta"
             data-testid="xdr-record-v2-meta">
          <span>First seen&nbsp;
            <b style={{ color: "rgba(230,235,243,0.82)" }}>
              {fmtDate(incident?.created_at) || "—"}
            </b>
          </span>
          <span>Last activity&nbsp;
            <b style={{ color: "rgba(230,235,243,0.82)" }}>
              {fmtDate(incident?.updated_at) || "—"}
            </b>
          </span>
          {incident?.assignee && (
            <span>Owner&nbsp;
              <b style={{ color: "rgba(230,235,243,0.82)" }}>
                {incident.assignee}
              </b>
            </span>
          )}
          {incident?.tenant && (
            <span>Tenant&nbsp;
              <b style={{ color: "rgba(230,235,243,0.82)" }}>
                {incident.tenant}
              </b>
            </span>
          )}
          {incident?.sla_due_at && (
            <span>SLA due&nbsp;
              <b style={{ color: "rgba(230,235,243,0.82)" }}>
                {fmtDate(incident.sla_due_at)}
              </b>
            </span>
          )}
          <span style={{ flex: 1 }} />
          <ActionGroup testid="xdr-record-v2-actions">
            <Action label="Respond" icon={Zap} tone="primary"
                     capability={respondCap} onRun={onOpenRespond}
                     reason={respondReason}
                     testid="xdr-record-respond" />
            <Action label="Generate Report" icon={FileText}
                     capability="cap-standby" reason="PHASE_5"
                     testid="xdr-record-report" />
            <Action label="More" icon={MoreHorizontal}
                     capability="cap-standby" reason="PHASE_3_PLUS"
                     testid="xdr-record-more" />
          </ActionGroup>
        </div>
      </div>

      {/* Vitals grid — data-driven investigation KPIs */}
      <div className="evops-vitals"
           data-testid="xdr-record-v2-vitals">
        <Vital label="Evidence"    value={evidenceCount}
                sub={evidenceCount === 1 ? "event" : "events"}
                testid="xdr-record-v2-vital-evidence" />
        <Vital label="Hosts"       value={e.hosts}
                testid="xdr-record-v2-vital-hosts" />
        <Vital label="Users"       value={e.users}
                testid="xdr-record-v2-vital-users" />
        <Vital label="Processes"   value={e.processes}
                testid="xdr-record-v2-vital-processes" />
        <Vital label="Files"       value={e.files}
                testid="xdr-record-v2-vital-files" />
        <Vital label="Network"     value={e.network}
                sub="ip · dns · url"
                testid="xdr-record-v2-vital-network" />
        <Vital label="MITRE"       value={mitreCount}
                sub={mitreCount === 1 ? "technique" : "techniques"}
                testid="xdr-record-v2-vital-mitre" />
        <Vital label="Verdict"     valueOverride={verdict.short}
                absent={verdict.state === "missing"}
                testid="xdr-record-v2-vital-verdict" />
      </div>

      {/* Compact provenance line */}
      <div className="evops-provline"
           data-testid="xdr-record-v2-provline">
        <span className="evops-provline__label">Provenance</span>
        <Provenance chain={chain}
                    testid="xdr-record-v2-provenance" />
        {correlationCount === 0 && evidenceCount === 0 && (
          <>
            <span className="evops-band__spacer" />
            <span className="evops-mono"
                  data-testid="xdr-record-v2-provline-hint">
              {upstreamPresent
                ? "No correlation has fired against this evidence yet."
                : "No telemetry linked · no evidence-backed investigation available."}
            </span>
          </>
        )}
      </div>
    </div>
  );
}


function Vital({ label, value, valueOverride, sub, absent, testid }) {
  const isAbsent = absent != null ? absent : !value;
  return (
    <div className="evops-vitals__cell" data-testid={testid}>
      <span className="evops-vitals__label">{label}</span>
      <span className="evops-vitals__value" data-absent={isAbsent ? "true" : "false"}>
        {valueOverride != null
          ? valueOverride
          : (isAbsent ? "—" : value)}
      </span>
      {sub && !isAbsent && (
        <span className="evops-vitals__sub">{sub}</span>
      )}
    </div>
  );
}
