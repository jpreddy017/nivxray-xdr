/**
 * MSS Dashboard · compact READ-ONLY intelligence status.
 *
 * Answers exactly one question: *what intelligence mode is currently
 * effective?* It exposes no configuration hierarchy, no policy enums and
 * no parent/child AI rows. The editable policy lives in
 * Administration › Intelligence Policy, one click away.
 */
import React from "react";
import { Link } from "react-router-dom";
import { ChevronRight, Cpu } from "lucide-react";
import useIntelligencePolicy from "./useIntelligencePolicy";
import { summarize } from "./intelligenceModel";
import "./intel.css";

export default function IntelligenceStatusChip() {
  const { values, health, loading, error } = useIntelligencePolicy({
    scope: "global",
  });

  if (loading) {
    return (
      <span className="nx-intel-strip" data-testid="xdr-intel-status-loading">
        <span className="nx-intel-strip__k">Intelligence</span>
        <span className="nx-intel-strip__v">Loading…</span>
      </span>
    );
  }

  if (error || !values) {
    // A0.5 · a cross-tenant principal that has named no customer cannot be
    // answered with one tenant's policy, and there is no default tenant.
    // The strip says so in one short line and carries the server's exact
    // reason in the tooltip — concise, never fabricated.
    const needsTenant = /tenant/i.test(String(error || ""));
    return (
      <Link
        to="/xdr/admin/intelligence-policy"
        className="nx-intel-strip"
        data-testid="xdr-intel-status-unavailable"
        data-state={needsTenant ? "TENANT_REQUIRED" : "NOT_AVAILABLE"}
        title={error || "no policy returned"}
      >
        <Cpu size={13} style={{ color: "var(--nx-purple)" }} />
        <span>
          <span className="nx-intel-strip__k">Intelligence&nbsp;</span>
          <span className="nx-intel-strip__v">
            <span className="nx-intel-dot nx-intel-dot--off" />
            {needsTenant ? "Select a customer" : "Not available"}
          </span>
        </span>
        <span className="nx-intel-strip__go"><ChevronRight size={14} /></span>
      </Link>
    );
  }

  const s = summarize({ values, health });

  return (
    <Link
      to="/xdr/admin/intelligence-policy"
      className="nx-intel-strip"
      data-testid="xdr-intel-status-chip"
      data-mode={s.mode?.id || "unresolved"}
      title="Open Intelligence Policy in Administration"
    >
      <Cpu size={13} style={{ color: "var(--nx-purple)" }} />
      <span>
        <span className="nx-intel-strip__k">Intelligence&nbsp;</span>
        <span className="nx-intel-strip__v" data-testid="xdr-intel-status-mode">
          <span className={"nx-intel-dot "
            + (s.mode?.id === "offline_only" ? "nx-intel-dot--off"
               : "nx-intel-dot--ok")} />
          {s.modeLabel}
        </span>
      </span>
      <span className="nx-intel-strip__sep" />
      <span>
        <span className="nx-intel-strip__k">Narration&nbsp;</span>
        <span className="nx-intel-strip__v"
              data-testid="xdr-intel-status-narration">{s.narration}</span>
      </span>
      <span className="nx-intel-strip__go"><ChevronRight size={14} /></span>
    </Link>
  );
}
