/**
 * RecordHeader · Layer 3 · Defender-inspired incident header.
 *
 * Renders identity, chips (Priority · Severity · Verdict · State),
 * meta strip (Confidence · Owner · Customer · Detection · SLA · Aging
 * · First seen · Last activity), and analyst actions.  Every field
 * that has no backing data renders honestly (`—`, `NOT_RUN`, `UNKNOWN`,
 * `NOT AVAILABLE`, `UNASSIGNED`).
 */
import React from "react";
import { ChevronLeft, Zap, ExternalLink, FileText, MoreHorizontal } from "lucide-react";
import { Link } from "react-router-dom";

import {
  PriorityChip, SeverityChip, VerdictChip, StateChip,
} from "@/xdr/components/chips";

function fmtDate(iso) {
  if (!iso) return null;
  const s = String(iso);
  return s.length >= 16 ? s.slice(0, 16).replace("T", " ") : s;
}

function fmtAging(created) {
  if (!created) return null;
  const t = Date.parse(created);
  if (!Number.isFinite(t)) return null;
  const sec = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (sec < 60)    return `${sec}s`;
  if (sec < 3600)  return `${Math.floor(sec/60)}m`;
  if (sec < 86400) return `${Math.floor(sec/3600)}h`;
  return `${Math.floor(sec/86400)}d`;
}

const dash = <span className="v dash">—</span>;
const unassigned = <span className="v" style={{ color: "#D97706", fontWeight: 600 }}>UNASSIGNED</span>;
const notRun = <span className="v dash">NOT_RUN</span>;
const na = <span className="v dash">NOT AVAILABLE</span>;

export default function RecordHeader({ incident, onOpenRespond }) {
  const stage2   = incident.verdict_stage2 || {};
  const priority = incident.priority?.code || null;
  const verdict  = stage2.label || null;
  const conf     = stage2.confidence_bucket || null;
  const risk     = stage2.risk_score;
  const src      = stage2.engine || incident.engine || null;

  return (
    <>
      <div className="rl-breadcrumb" data-testid="xdr-record-breadcrumb">
        <Link to="/xdr/incidents" data-testid="xdr-record-back">
          <ChevronLeft size={12} style={{ display: "inline", verticalAlign: "-1px" }} />
          Incidents
        </Link>
        <span className="sep">/</span>
        <span style={{ fontFamily: "var(--rs-mono)", color: "var(--rl-text-dim)" }}>
          {incident.number || (incident.id || "").slice(0, 12) + "…"}
        </span>
      </div>

      <section className="rl-header" data-testid="xdr-record-header">
        <div className="rl-header-top">
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="rl-header-id" data-testid="xdr-record-id">
              {incident.number}
              <span className="sep">·</span>
              First seen {fmtDate(incident.created_at) || "—"}
              <span className="sep">·</span>
              Last activity {fmtDate(incident.updated_at) || "—"}
            </div>
            <h1 className="rl-header-title" data-testid="xdr-record-title">
              {incident.name || "(unnamed incident)"}
            </h1>
            <div className="rl-header-chips" data-testid="xdr-record-chips">
              {priority
                ? <PriorityChip code={priority} />
                : <span className="rl-state na">P?</span>}
              <SeverityChip value={incident.severity || "unknown"} />
              <VerdictChip value={verdict || "unknown"} />
              <StateChip value={incident.state || "new"} />
              {incident.high_fidelity && (
                <span className="rl-state err" data-testid="xdr-record-hifi">
                  HIGH FIDELITY
                </span>
              )}
              {incident.customer_engaged && (
                <span className="rl-state ok" data-testid="xdr-record-customer-engaged">
                  CUSTOMER ENGAGED
                </span>
              )}
            </div>
          </div>
          <div className="rl-header-actions">
            <button
              type="button"
              className="rl-btn primary"
              onClick={onOpenRespond}
              data-testid="xdr-record-respond"
            >
              <Zap size={13} /> Respond
            </button>
            <button
              type="button"
              className="rl-btn"
              disabled
              title="Report writer — Phase 5"
              data-testid="xdr-record-report"
            >
              <FileText size={13} /> Generate Report
            </button>
            <button
              type="button"
              className="rl-btn"
              disabled
              title="More actions — Phase 3+"
              data-testid="xdr-record-more"
            >
              <MoreHorizontal size={13} />
            </button>
          </div>
        </div>

        <div className="rl-meta" data-testid="xdr-record-meta">
          <MetaCell k="Confidence" testid="xdr-record-meta-confidence"
                     v={conf ? <span className="v mono">{String(conf).toUpperCase()}</span> : notRun} />
          <MetaCell k="Risk Score" testid="xdr-record-meta-risk"
                     v={risk != null
                        ? <span className="v mono">{risk}/100</span>
                        : na} />
          <MetaCell k="Owner"      testid="xdr-record-meta-owner"
                     v={incident.assignee
                        ? <span className="v mono">{incident.assignee}</span>
                        : unassigned} />
          <MetaCell k="Customer"   testid="xdr-record-meta-customer"
                     v={incident.tenant
                        ? <span className="v mono">{incident.tenant}</span>
                        : dash} />
          <MetaCell k="Detection"  testid="xdr-record-meta-detection"
                     v={src ? <span className="v mono">{src}</span> : notRun} />
          <MetaCell k="SLA Due"    testid="xdr-record-meta-sla"
                     v={incident.sla_due_at
                        ? <span className="v mono">{fmtDate(incident.sla_due_at)}</span>
                        : dash} />
          <MetaCell k="Aging"      testid="xdr-record-meta-aging"
                     v={<span className="v mono">{fmtAging(incident.created_at) || "—"}</span>} />
          <MetaCell k="Techniques" testid="xdr-record-meta-mitre"
                     v={(incident.mitre?.length ?? 0) > 0
                        ? <span className="v mono">{incident.mitre.length}</span>
                        : dash} />
        </div>
      </section>
    </>
  );
}

function MetaCell({ k, v, testid }) {
  return (
    <div className="m" data-testid={testid}>
      <div className="k">{k}</div>
      {v}
    </div>
  );
}
