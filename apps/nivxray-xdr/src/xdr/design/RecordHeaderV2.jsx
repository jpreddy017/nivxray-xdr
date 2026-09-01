/**
 * RecordHeaderV2 · Round 29 · Investigation Command Header (LIGHT).
 * ---------------------------------------------------------------
 * White/light enterprise SOC command header.  Corrected 2026-09-01
 * after the dark-navy iteration was rejected: NivXRay XDR is a
 * WHITE canvas — security state provides the ONLY colour, never
 * a decorative fill.
 *
 * Composition (single row on ≥1400px viewport):
 *
 *   [Severity]  [Title + ID + soft chips + meta]  [KPI band]  [Actions]
 *
 *   · Severity   → priority-coloured square score badge.
 *   · Title      → incident name + machine id.
 *   · Chips      → `● Priority Px · ● State · ● Verdict`, dot-chip
 *                  style (NOT the primitive's uppercase pill).
 *   · Meta       → First seen · Last activity · Created by.
 *   · KPI band   → Evidence · Assets · Users · MITRE · Correlation
 *                  Each cell has a big numeric value plus a small
 *                  sub-label.  Absent values render as `—` in
 *                  muted italic.  MITRE / Correlation are gated on
 *                  evidence being present.
 *   · Actions    → Respond (primary) · Generate Report · More.
 *
 * The header is a PROJECTION of authoritative investigation
 * state — it never introduces a second source of truth.  The
 * previous `TRUTH STATE / PROVENANCE / RELATIONSHIPS` sections
 * are DELETED from this surface; those concepts are internal
 * primitives, not primary page sections.
 */
import React from "react";
import { ChevronLeft, Zap, FileText, MoreHorizontal, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";

import Action from "@/xdr/design/Action";
import "@/xdr/design/tokens.css";


function fmtDate(iso) {
  if (!iso) return null;
  const s = String(iso);
  return s.length >= 16 ? s.slice(0, 16).replace("T", " ") : s;
}


/* ------------------------------------------------------------------
 * Priority code → score-badge composition.  Score value is the
 * priority label ("P1", "P2", …) — NEVER a fabricated numeric
 * risk-score.  A future risk engine can supply an authoritative
 * integer; until it does, the priority letter is the honest value.
 * ------------------------------------------------------------------ */
function scoreForPriority(code, riskScore) {
  const c = String(code || "").toUpperCase();
  const severityLabel = c === "P1" ? "CRITICAL"
                       : c === "P2" ? "HIGH"
                       : c === "P3" ? "MEDIUM"
                       : c === "P4" ? "LOW"
                       : c === "P5" ? "INFO"
                       : "UNSET";
  return {
    value: riskScore != null ? String(riskScore) : (c || "—"),
    label: severityLabel,
  };
}


function chipsForIncident(incident) {
  const priCode = String(incident?.priority?.code || "").toUpperCase();
  const stateRaw = String(incident?.state || "").toLowerCase();
  const verdictRaw = String(incident?.verdict_stage2?.label
                              || incident?.verdict || "").toLowerCase();

  const priTone = priCode === "P1" || priCode === "P2"
    ? "critical" : priCode === "P3" ? "high" : null;
  const priLabel = priCode
    ? `Priority ${priCode}`
    : "Priority not set";

  let stateTone = null;
  let stateLabel = stateRaw
    ? stateRaw.replace("_", " ").replace(/\b\w/g, (m) => m.toUpperCase())
    : "State unknown";
  if (stateRaw === "in_progress") stateTone = "progress";
  else if (stateRaw === "on_hold") stateTone = "pending";
  else if (stateRaw === "resolved" || stateRaw === "closed") stateTone = "resolved";
  else if (stateRaw === "new")     stateTone = "pending";

  let verdictTone = null;
  let verdictLabel = "Verdict pending";
  if (verdictRaw === "malicious")       { verdictTone = "malicious";  verdictLabel = "Malicious"; }
  else if (verdictRaw === "suspicious") { verdictTone = "high";       verdictLabel = "Suspicious"; }
  else if (verdictRaw === "benign")     { verdictTone = "benign";     verdictLabel = "Benign"; }
  else                                    { verdictTone = "pending"; }

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
  const riskScore    = incident?.risk_score
                        ?? incident?.verdict_stage2?.risk_score
                        ?? null;
  const score = scoreForPriority(priorityCode, riskScore);
  const chips = chipsForIncident(incident);

  const evidenceCount    = Number(incident?.evidence_count || 0);
  const correlationCount =
       Array.isArray(incident?.correlation_match_ids)
         ? incident.correlation_match_ids.length : 0;
  const rawMitreCount    = Array.isArray(incident?.mitre)
    ? incident.mitre.length : 0;
  // MITRE count is a DERIVED value: no upstream evidence → no
  // evidence-backed mapping.  The header must never contradict
  // its own provenance chain.
  const mitreCount = evidenceCount > 0 ? rawMitreCount : 0;

  const assets = countAssets(incident);
  const totalAssets = assets.hosts + assets.processes + assets.files
                        + assets.network;

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
        {/* Severity score badge */}
        <div className="evops-cmd__score"
             data-testid="xdr-record-v2-score">
          <ShieldAlert size={14}
                        style={{ color: priorityCode === "P1"
                                   ? "#DC2626"
                                   : priorityCode === "P2"
                                     ? "#EA580C" : "var(--nx-muted)" }} />
          <span className="evops-cmd__score-value">{score.value}</span>
          <span className="evops-cmd__score-label">{score.label}</span>
        </div>

        {/* Identity + chips + meta */}
        <div className="evops-cmd__ident">
          <div className="evops-cmd__title"
               data-testid="xdr-record-v2-title">
            {incident?.name || "(unnamed incident)"}
          </div>
          <div className="evops-cmd__id"
               data-testid="xdr-record-v2-id">
            {incident?.number || incident?.id}
          </div>
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

        {/* Inline KPI band */}
        <div className="evops-cmd__kpis"
             data-testid="xdr-record-v2-kpis">
          <Kpi label="Evidence"    value={evidenceCount}
                sub={evidenceCount === 1 ? "event" : "events"}
                testid="xdr-record-v2-kpi-evidence" />
          <Kpi label="Assets"      value={totalAssets}
                sub={totalAssets === 1 ? "asset" : "assets"}
                testid="xdr-record-v2-kpi-assets"
                count={`h ${assets.hosts} · p ${assets.processes} · f ${assets.files}`} />
          <Kpi label="Users"       value={assets.users}
                sub={assets.users === 1 ? "user" : "users"}
                testid="xdr-record-v2-kpi-users" />
          <Kpi label="MITRE"       value={mitreCount}
                sub={mitreCount === 1 ? "technique" : "techniques"}
                testid="xdr-record-v2-kpi-mitre" />
          <Kpi label="Correlation" value={correlationCount}
                sub={correlationCount === 1 ? "alert" : "alerts"}
                testid="xdr-record-v2-kpi-correlation" />
        </div>

        {/* Actions column */}
        <div className="evops-cmd__actions"
             data-testid="xdr-record-v2-actions">
          <Action label="Respond" icon={Zap} tone="primary"
                   capability={respondCap} onRun={onOpenRespond}
                   reason={respondReason}
                   testid="xdr-record-respond" />
          <Action label="Generate Report" icon={FileText}
                   capability="cap-standby" reason="PHASE_5"
                   testid="xdr-record-report" />
          <Action label="More Actions" icon={MoreHorizontal}
                   capability="cap-standby" reason="PHASE_3_PLUS"
                   testid="xdr-record-more" />
        </div>
      </div>
    </div>
  );
}


function Kpi({ label, value, sub, count, testid }) {
  const absent = !value;
  return (
    <div className="evops-cmd__kpi" data-testid={testid}>
      <span className="evops-cmd__kpi-label">
        {label}
        {count && !absent && (
          <span className="evops-cmd__kpi-count">{count}</span>
        )}
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
