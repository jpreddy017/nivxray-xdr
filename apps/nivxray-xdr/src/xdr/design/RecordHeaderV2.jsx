/**
 * RecordHeaderV2 · Round 29.5 · Investigation Command Header.
 * ---------------------------------------------------------------
 * First flagship implementation of the NivXRay XDR Visual
 * Language System v1.0 (see /app/memory/VISUAL_LANGUAGE.md).
 *
 * Composition (v1.0 rule §4.1 Incident record):
 *
 *   [ Command Band  ]  → identity + severity + verdict + response
 *
 * Visual hierarchy the analyst's eye lands in (v1.0 rule §7.2):
 *   1. Severity          → left rail + priority pill
 *   2. Incident title    → 24px 800 dominant
 *   3. Verdict + status  → soft dot-chips
 *   4. Evidence weight   → glyph-led KPI rail (28px numerals)
 *   5. Response          → Respond primary action
 *
 * Never expose primitives as analyst-facing headings (v1.0 §0.5).
 * Never fabricate metrics (v1.0 §0.2); absent values render as
 *   `—` italic-muted (v1.0 §5 NOT_PRESENT).
 */
import React from "react";
import { ChevronLeft, MoreHorizontal } from "lucide-react";
import { Link } from "react-router-dom";

import Action from "@/xdr/design/Action";
import {
  IncidentGlyph, EvidenceGlyph, HostGlyph, UserGlyph,
  TechniqueGlyph, CorrelationGlyph, ResponseGlyph, FileGlyph,
} from "@/xdr/design/glyphs";
import "@/xdr/design/tokens.css";


function fmtDate(iso) {
  if (!iso) return null;
  const s = String(iso);
  return s.length >= 16 ? s.slice(0, 16).replace("T", " ") : s;
}


function severityForPriority(code) {
  const c = String(code || "").toUpperCase();
  return c === "P1" ? "CRITICAL"
       : c === "P2" ? "HIGH"
       : c === "P3" ? "MEDIUM"
       : c === "P4" ? "LOW"
       : c === "P5" ? "INFO"
       : "UNSET";
}


function chipsForIncident(incident) {
  const priCode = String(incident?.priority?.code || "").toUpperCase();
  const stateRaw = String(incident?.state || "").toLowerCase();
  const verdictRaw = String(incident?.verdict_stage2?.label
                              || incident?.verdict || "").toLowerCase();

  const priTone = priCode === "P1" || priCode === "P2"
    ? "critical" : priCode === "P3" ? "high" : null;
  const priLabel = priCode ? `Priority ${priCode}` : "Priority not set";

  let stateTone = null;
  let stateLabel = stateRaw
    ? stateRaw.replace("_", " ").replace(/\b\w/g, (m) => m.toUpperCase())
    : "State unknown";
  if (stateRaw === "in_progress")             stateTone = "progress";
  else if (stateRaw === "on_hold")            stateTone = "pending";
  else if (stateRaw === "resolved"
           || stateRaw === "closed")          stateTone = "resolved";
  else if (stateRaw === "new")                stateTone = "pending";

  let verdictTone = "pending";
  let verdictLabel = "Verdict pending";
  if (verdictRaw === "malicious")       { verdictTone = "malicious";  verdictLabel = "Malicious"; }
  else if (verdictRaw === "suspicious") { verdictTone = "high";       verdictLabel = "Suspicious"; }
  else if (verdictRaw === "benign")     { verdictTone = "benign";     verdictLabel = "Benign"; }

  return [
    { key: "priority", tone: priTone,     label: priLabel },
    { key: "state",    tone: stateTone,   label: stateLabel },
    { key: "verdict",  tone: verdictTone, label: verdictLabel },
  ];
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
    network:   len(a.network)   || len(iocs.ips) + len(iocs.domains)
                                     + len(iocs.urls),
  };
}


export default function RecordHeaderV2({ incident, onOpenRespond }) {
  const priorityCode = String(incident?.priority?.code || "").toUpperCase();
  const severity     = severityForPriority(priorityCode);
  const chips        = chipsForIncident(incident);

  const evidenceCount    = Number(incident?.evidence_count || 0);
  const correlationCount =
       Array.isArray(incident?.correlation_match_ids)
         ? incident.correlation_match_ids.length : 0;
  const rawMitreCount    = Array.isArray(incident?.mitre)
    ? incident.mitre.length : 0;
  const mitreCount = evidenceCount > 0 ? rawMitreCount : 0;

  const assets = countAssets(incident);

  const stateRaw = String(incident?.state || "").toLowerCase();
  const respondCap = (stateRaw === "closed" || stateRaw === "resolved")
    ? "cap-unavailable" : "cap-full";
  const respondReason = respondCap === "cap-unavailable"
    ? `INCIDENT_${stateRaw.toUpperCase()}` : null;

  return (
    <div className="evops evops-canvas"
         data-testid="xdr-record-header-v2"
         style={{ paddingBottom: 2 }}>

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

      <div className="evops-cmd"
           data-priority={priorityCode || ""}
           data-testid="xdr-record-v2-cmd">
        {/* Identity — title dominant, severity supporting */}
        <div className="evops-cmd__ident">
          <div className="evops-cmd__title-row">
            <span className="evops-cmd__glyph"
                  data-testid="xdr-record-v2-glyph">
              <IncidentGlyph size={22} />
            </span>
            <span className="evops-cmd__title"
                  data-testid="xdr-record-v2-title">
              {incident?.name || "(unnamed incident)"}
            </span>
            {priorityCode && (
              <span className="evops-cmd__sev-pill"
                    data-testid="xdr-record-v2-sev-pill">
                {priorityCode}<span>·</span>{severity}
              </span>
            )}
          </div>
          <span className="evops-cmd__id"
                data-testid="xdr-record-v2-id">
            {incident?.number || incident?.id}
          </span>
          <div className="evops-cmd__chips"
               data-testid="xdr-record-v2-chips">
            {chips.map((c) => (
              <span key={c.key}
                    className="evops-cmd__chip"
                    data-tone={c.tone || ""}
                    data-testid={`xdr-record-v2-chip-${c.key}`}>
                <span className="evops-cmd__chip-dot" aria-hidden />
                <span>{c.label}</span>
              </span>
            ))}
          </div>
          <div className="evops-cmd__meta"
               data-testid="xdr-record-v2-meta">
            <span>First seen&nbsp;<b>{fmtDate(incident?.created_at) || "—"}</b></span>
            <span>Last activity&nbsp;<b>{fmtDate(incident?.updated_at) || "—"}</b></span>
            {incident?.assignee && (
              <span>Owner&nbsp;<b>{incident.assignee}</b></span>
            )}
            {incident?.tenant && (
              <span>Tenant&nbsp;<b>{incident.tenant}</b></span>
            )}
          </div>
        </div>

        {/* Glyph-led KPI rail */}
        <div className="evops-cmd__kpis"
             data-testid="xdr-record-v2-kpis">
          <Kpi glyph={<EvidenceGlyph size={12} />}    label="Evidence"
                value={evidenceCount}
                sub={evidenceCount === 1 ? "event" : "events"}
                testid="xdr-record-v2-kpi-evidence" />
          <Kpi glyph={<HostGlyph size={12} />}        label="Hosts"
                value={assets.hosts}
                testid="xdr-record-v2-kpi-hosts" />
          <Kpi glyph={<UserGlyph size={12} />}        label="Users"
                value={assets.users}
                testid="xdr-record-v2-kpi-users" />
          <Kpi glyph={<FileGlyph size={12} />}        label="Files"
                value={assets.files}
                testid="xdr-record-v2-kpi-files" />
          <Kpi glyph={<TechniqueGlyph size={12} />}   label="MITRE"
                value={mitreCount}
                sub={mitreCount === 1 ? "technique" : "techniques"}
                testid="xdr-record-v2-kpi-mitre" />
          <Kpi glyph={<CorrelationGlyph size={12} />} label="Correlation"
                value={correlationCount}
                sub={correlationCount === 1 ? "alert" : "alerts"}
                testid="xdr-record-v2-kpi-correlation" />
        </div>

        {/* Actions column */}
        <div className="evops-cmd__actions"
             data-testid="xdr-record-v2-actions">
          <Action label="Respond"          icon={ResponseGlyph} tone="primary"
                   capability={respondCap} onRun={onOpenRespond}
                   reason={respondReason}
                   testid="xdr-record-respond" />
          <Action label="Generate Report"  icon={EvidenceGlyph}
                   capability="cap-standby" reason="PHASE_5"
                   testid="xdr-record-report" />
          <Action label="More Actions"     icon={MoreHorizontal}
                   capability="cap-standby" reason="PHASE_3_PLUS"
                   testid="xdr-record-more" />
        </div>
      </div>
    </div>
  );
}


function Kpi({ glyph, label, value, sub, testid }) {
  const absent = !value;
  return (
    <div className="evops-cmd__kpi" data-testid={testid}>
      <span className="evops-cmd__kpi-label">
        <span className="evops-cmd__kpi-glyph" aria-hidden>{glyph}</span>
        {label}
      </span>
      <span className="evops-cmd__kpi-value" data-absent={absent ? "true" : "false"}>
        {absent ? "—" : value}
      </span>
      {sub && !absent && (
        <span className="evops-cmd__kpi-sub">{sub}</span>
      )}
    </div>
  );
}
