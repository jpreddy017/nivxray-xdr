/**
 * RecordHeaderV2 · v1.1 Composition · Investigation Command Band.
 * ---------------------------------------------------------------
 * One card, five rows.  KPI rail lives INSIDE the band (v1.1 C3).
 *
 *   Row 1 · Ⓘ Title …………………………………… P1 · CRITICAL
 *   Row 2 · INC-… ● IN PROGRESS   ● VERDICT PENDING
 *   Row 3 · First seen … Last activity … Owner … Tenant …
 *   ─── hairline ───
 *   Row 4 · Ⓔ Evidence …  Ⓐ Alerts …  Ⓗ Hosts …          [Respond] [⋯]
 *                Ⓤ Users …  Ⓕ Files …  Ⓣ MITRE …  Ⓒ Correlation …
 *
 * Analyst-facing headings only (v1.1 C8).  No "TRUTH STATE",
 * "PROVENANCE", "RELATIONSHIPS" on the primary canvas.
 */
import React from "react";
import { ChevronLeft, MoreHorizontal } from "lucide-react";
import { Link } from "react-router-dom";

import Action from "@/xdr/design/Action";
import {
  IncidentGlyph, EvidenceGlyph, HostGlyph, UserGlyph,
  TechniqueGlyph, CorrelationGlyph, ResponseGlyph, FileGlyph,
  AlertGlyph,
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
  const stateRaw   = String(incident?.state || "").toLowerCase();
  const verdictRaw = String(incident?.verdict_stage2?.label
                              || incident?.verdict || "").toLowerCase();

  let stateTone = "pending";
  let stateLabel = stateRaw
    ? stateRaw.replace("_", " ").replace(/\b\w/g, (m) => m.toUpperCase())
    : "State unknown";
  if (stateRaw === "in_progress")                  stateTone = "progress";
  else if (stateRaw === "on_hold")                 stateTone = "pending";
  else if (stateRaw === "resolved"
           || stateRaw === "closed")               stateTone = "resolved";
  else if (stateRaw === "new")                     stateTone = "pending";

  let verdictTone = "pending";
  let verdictLabel = "Verdict pending";
  if (verdictRaw === "malicious")       { verdictTone = "malicious";  verdictLabel = "Malicious"; }
  else if (verdictRaw === "suspicious") { verdictTone = "high";       verdictLabel = "Suspicious"; }
  else if (verdictRaw === "benign")     { verdictTone = "benign";     verdictLabel = "Benign"; }

  return [
    { key: "state",   tone: stateTone,   label: stateLabel },
    { key: "verdict", tone: verdictTone, label: verdictLabel },
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
  };
}


export default function RecordHeaderV2({ incident, onOpenRespond }) {
  const priorityCode = String(incident?.priority?.code || "").toUpperCase();
  const severity     = severityForPriority(priorityCode);
  const chips        = chipsForIncident(incident);

  const evidenceCount    = Number(incident?.evidence_count || 0);
  const alertCount       = Number(incident?.alert_count
                                  || incident?.alerts?.length || 0);
  const correlationCount =
       Array.isArray(incident?.correlation_match_ids)
         ? incident.correlation_match_ids.length : 0;
  const mitreCount = evidenceCount > 0
    ? (Array.isArray(incident?.mitre) ? incident.mitre.length : 0)
    : 0;

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
        {/* Row 1 · glyph · title · sev pill */}
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
              {priorityCode} · {severity}
            </span>
          )}
        </div>

        {/* Row 2 · id · state chips */}
        <div className="evops-cmd__id-row">
          <span className="evops-cmd__id"
                data-testid="xdr-record-v2-id">
            {incident?.number || incident?.id}
          </span>
          <span className="evops-cmd__chips"
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
          </span>
        </div>

        {/* Row 3 · meta */}
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

        <div className="evops-cmd__rule" aria-hidden />

        {/* Row 4 · vitals rail + actions (v1.1 C3) */}
        <div className="evops-cmd__foot">
          <div className="evops-cmd__kpis"
               data-testid="xdr-record-v2-kpis">
            <MiniKpi glyph={<EvidenceGlyph size={13} />}    label="Evidence"    value={evidenceCount}
                     testid="xdr-record-v2-kpi-evidence" />
            <MiniKpi glyph={<AlertGlyph size={13} />}       label="Alerts"      value={alertCount}
                     testid="xdr-record-v2-kpi-alerts" />
            <MiniKpi glyph={<HostGlyph size={13} />}        label="Hosts"       value={assets.hosts}
                     testid="xdr-record-v2-kpi-hosts" />
            <MiniKpi glyph={<UserGlyph size={13} />}        label="Users"       value={assets.users}
                     testid="xdr-record-v2-kpi-users" />
            <MiniKpi glyph={<FileGlyph size={13} />}        label="Files"       value={assets.files}
                     testid="xdr-record-v2-kpi-files" />
            <MiniKpi glyph={<TechniqueGlyph size={13} />}   label="MITRE"       value={mitreCount}
                     testid="xdr-record-v2-kpi-mitre" />
            <MiniKpi glyph={<CorrelationGlyph size={13} />} label="Correlation" value={correlationCount}
                     testid="xdr-record-v2-kpi-correlation" />
          </div>
          <div className="evops-cmd__actions"
               data-testid="xdr-record-v2-actions">
            <Action label="Respond" icon={ResponseGlyph} tone="primary"
                     capability={respondCap} onRun={onOpenRespond}
                     reason={respondReason}
                     testid="xdr-record-respond" />
            <Action label="" icon={MoreHorizontal}
                     capability="cap-standby" reason="PHASE_3_PLUS"
                     ariaLabel="More actions"
                     testid="xdr-record-more" />
          </div>
        </div>
      </div>
    </div>
  );
}


function MiniKpi({ glyph, label, value, testid }) {
  const absent = !value;
  return (
    <span className="evops-cmd__kpi" data-testid={testid}>
      <span className="evops-cmd__kpi-glyph" aria-hidden>{glyph}</span>
      <span className="evops-cmd__kpi-label">{label}</span>
      <span className="evops-cmd__kpi-value"
             data-absent={absent ? "true" : "false"}>
        {absent ? "—" : value}
      </span>
    </span>
  );
}
