/**
 * RecordHeader · Layer 3 · Phase A.2 · Visual Maturity composition.
 *
 * Sits on the workspace CANVAS.  Answers the §16.5 three questions
 * with a single operational attention statement — not a wall of
 * numeric metrics — followed by quiet supporting metadata.
 *
 *   1. What am I looking at?  → incident name + number
 *   2. What is important?     → priority chip + one-line
 *                              operational attention statement
 *                              (e.g. "Awaiting first analyst",
 *                               "Investigation in progress · verdict pending",
 *                               "MALICIOUS · 12 artifacts · 5 techniques")
 *   3. What can I do?         → Respond (primary) · Report · More
 *
 * Two typographic voices (§16.4).  Honest data states preserved.
 * Engineering vocabulary ("workspace_cases.live", "NOT_RUN")
 * intentionally kept out of the hero — those belong in the
 * technical tab, not on the identity band.
 */
import React from "react";
import { ChevronLeft, Zap, FileText, MoreHorizontal, Clock, FolderSearch } from "lucide-react";
import { Link } from "react-router-dom";

import { NxHeroHeader } from "@/xdr/nx";
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


/**
 * Compose the operational attention statement.
 *
 * Returns { headline, sub, tone } — a single dominant read that
 * summarises WHAT MATTERS about this incident right now.
 * Never fabricates: every branch is derived from real state.
 */
function attentionStatement(incident) {
  const stage2   = incident.verdict_stage2 || {};
  const verdict  = String(stage2.label || "").toLowerCase();
  const conf     = stage2.confidence_bucket || null;
  const evidence = incident.evidence_count || 0;
  const techs    = incident.mitre?.length || 0;
  const state    = incident.state || "new";
  const owner    = incident.assignee || null;
  const aging    = fmtAging(incident.created_at);

  // Resolved / closed → celebrate the completion, quietly.
  if (state === "closed") {
    return {
      headline: "Incident closed",
      sub: verdict && verdict !== "unknown"
        ? `Final verdict · ${verdict.toUpperCase()}`
        : "No outstanding actions",
      tone: "benign",
    };
  }
  if (state === "resolved") {
    return {
      headline: "Resolved · awaiting closure review",
      sub: verdict && verdict !== "unknown"
        ? `Verdict · ${verdict.toUpperCase()}`
        : "No outstanding actions",
      tone: "benign",
    };
  }

  // Known malicious or suspicious → attention is the verdict.
  if (verdict === "malicious" || verdict === "suspicious") {
    const parts = [];
    if (evidence > 0) parts.push(`${evidence} artifact${evidence > 1 ? "s" : ""}`);
    if (techs > 0)    parts.push(`${techs} technique${techs > 1 ? "s" : ""}`);
    if (conf)         parts.push(`${conf} confidence`);
    return {
      headline: verdict === "malicious" ? "Malicious activity confirmed"
                                        : "Suspicious activity — under review",
      sub: parts.length ? parts.join(" · ") : "Evidence still being collected",
      tone: verdict === "malicious" ? "critical" : "high",
    };
  }

  // Benign resolved verdict.
  if (verdict === "benign") {
    return {
      headline: "Verified benign",
      sub: "No malicious signal — retain for reference",
      tone: "benign",
    };
  }

  // In-progress but no verdict yet.
  if (state === "in_progress") {
    return {
      headline: owner ? "Investigation in progress" : "In progress — unassigned",
      sub: owner
        ? "Verdict pending · analyst actively working"
        : "Verdict pending · needs an owner",
      tone: owner ? "purple" : "medium",
    };
  }

  if (state === "on_hold") {
    return {
      headline: "On hold",
      sub: "Waiting on external input or customer response",
      tone: "medium",
    };
  }

  // Default: new / awaiting triage.
  if (!owner) {
    return {
      headline: "Awaiting first analyst",
      sub: aging ? `Unassigned for ${aging} since first seen` : "Unassigned",
      tone: "medium",
    };
  }
  return {
    headline: "New incident · triage pending",
    sub: "Owner assigned · investigation not started",
    tone: "low",
  };
}


export default function RecordHeader({ incident, onOpenRespond }) {
  const priority = incident.priority?.code || null;
  const state    = incident.state || "new";
  const attn     = attentionStatement(incident);

  return (
    <>
      <div className="rl-breadcrumb" data-testid="xdr-record-breadcrumb">
        <Link to="/xdr/incidents" data-testid="xdr-record-back">
          <ChevronLeft size={12} style={{ display: "inline", verticalAlign: "-1px" }} />
          Incidents
        </Link>
        <span className="sep">/</span>
        <span className="rl-crumb-id">
          {incident.number || (incident.id || "").slice(0, 12) + "…"}
        </span>
      </div>

      <div data-testid="xdr-record-header">
        <NxHeroHeader
          eyebrow="Incident"
          title={
            <span data-testid="xdr-record-title">
              {incident.name || "(unnamed incident)"}
            </span>
          }
          description={
            <span className="rl-hero-sub" data-testid="xdr-record-id">
              <span className="rl-hero-mono">{incident.number}</span>
              <span className="rl-hero-sep">·</span>
              <span>First seen&nbsp;
                <span className="rl-hero-mono">{fmtDate(incident.created_at) || "—"}</span>
              </span>
              <span className="rl-hero-sep">·</span>
              <span>Last activity&nbsp;
                <span className="rl-hero-mono">{fmtDate(incident.updated_at) || "—"}</span>
              </span>
            </span>
          }
          chips={
            <div className="rl-attn" data-testid="xdr-record-attention">
              {priority
                ? <PriorityChip code={priority} />
                : <span className="rl-state na">P?</span>}
              <StateChip value={state} />
              <span className={`rl-attn-headline rl-attn-tone-${attn.tone}`}
                       data-testid="xdr-record-attention-headline">
                {attn.headline}
              </span>
              <span className="rl-attn-sub"
                       data-testid="xdr-record-attention-sub">
                {attn.sub}
              </span>
            </div>
          }
          metrics={[]}
          action={
            <>
              <Link
                to={`/xdr/investigations/${encodeURIComponent(incident.id || incident.case_id || "")}`}
                className="rl-btn"
                title="Open full IKG Causal Investigation Workspace"
                data-testid="xdr-record-open-investigation"
                style={{ textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 5, color: "#5cc0a5", border: "1px solid rgba(92,192,165,0.35)", background: "rgba(92,192,165,0.08)" }}
              >
                <FolderSearch size={13} /> Full Investigation ↗
              </Link>
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
            </>
          }
          provenance={
            <div className="rl-hero-context" data-testid="xdr-record-context">
              <span className="rl-hero-owner-inline">
                <span className="rl-hero-context-label">Owner</span>
                {incident.assignee
                  ? <span className="rl-hero-mono">{incident.assignee}</span>
                  : <span className="rl-hero-unassigned">Unassigned</span>}
              </span>
              {incident.tenant && (
                <>
                  <span className="rl-hero-sep">·</span>
                  <span className="rl-hero-owner-inline">
                    <span className="rl-hero-context-label">Customer</span>
                    <span className="rl-hero-mono">{incident.tenant}</span>
                  </span>
                </>
              )}
              {incident.sla_due_at && (
                <>
                  <span className="rl-hero-sep">·</span>
                  <span className="rl-hero-owner-inline">
                    <Clock size={11} style={{ marginRight: 3, verticalAlign: "-1.5px" }} />
                    <span className="rl-hero-context-label">SLA due</span>
                    <span className="rl-hero-mono">{fmtDate(incident.sla_due_at)}</span>
                  </span>
                </>
              )}
            </div>
          }
        />
      </div>
    </>
  );
}
