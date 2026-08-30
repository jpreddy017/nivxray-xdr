/**
 * XdrIncidentsPage · `/xdr/incidents`
 *
 * Full queue view.  URL params:
 *   ?mine=1        → My Queue (only rows assigned to me)
 *   ?q=…           → search prefill
 *   ?technique=T#  → filter to incidents whose Stage-2 evidence maps
 *                    to the given MITRE ATT&CK technique.  Powered by
 *                    the same rule→technique table the heatmap uses
 *                    (authoritative source: evidence[].rule_id +
 *                    evidence[].technique_id when present).  Never
 *                    fabricates a technique-to-incident relationship.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { X, Filter as FilterIcon } from "lucide-react";

import { useAuth } from "@/lib/auth";
import { listIncidents } from "@/lib/incidentsApi";
import XdrShell      from "@/xdr/XdrShell";
import IncidentQueue from "@/xdr/components/IncidentQueue";
import {
  RULE_TO_TECHNIQUE, TECHNIQUE_INDEX,
} from "@/xdr/mitre/mitreTactics";


// Test whether an incident's evidence maps to a given technique.
// The heatmap's authoritative source is:
//   1. evidence[].technique_id when the backend already tagged it;
//   2. otherwise RULE_TO_TECHNIQUE[evidence[].rule_id.upperCase()].
// No client-side fabrication.
function incidentMatchesTechnique(inc, techniqueId) {
  const ev = inc?.verdict_stage2?.evidence || inc?.evidence || [];
  for (const e of ev) {
    if (e.technique_id && String(e.technique_id).toUpperCase() === techniqueId) {
      return true;
    }
    const rid = String(e.rule_id || "").toUpperCase();
    if (RULE_TO_TECHNIQUE[rid] === techniqueId) return true;
  }
  return false;
}


export default function XdrIncidentsPage() {
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const mine       = params.get("mine") === "1";
  const initialQ   = params.get("q") || "";
  const techniqueParam = (params.get("technique") || "").toUpperCase();
  const technique  = techniqueParam && TECHNIQUE_INDEX[techniqueParam]
                       ? techniqueParam : null;

  const [rows, setRows]     = useState([]);
  const [loading, setL]     = useState(true);
  const [error, setError]   = useState(null);
  const [q, setQ]           = useState(initialQ);
  const [stateFilter, setS] = useState("all");

  const load = useCallback(async () => {
    setL(true); setError(null);
    try {
      const res = await listIncidents({ limit: 500 });
      setRows(res.incidents || []);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load incidents.");
    } finally { setL(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const visible = useMemo(() => {
    let list = rows;
    if (mine)      list = list.filter((r) => r.assignee && r.assignee === user?.email);
    if (technique) list = list.filter((r) => incidentMatchesTechnique(r, technique));
    return list;
  }, [rows, mine, user?.email, technique]);

  const clearTechnique = () => {
    const next = new URLSearchParams(params);
    next.delete("technique");
    setParams(next, { replace: true });
  };

  const title = mine
    ? "My Queue"
    : technique
      ? `Incidents · ${technique}`
      : "Incidents";

  return (
    <XdrShell activeTop="dashboards">
      <h1 className="page-h1" data-testid="xdr-incidents-heading">{title}</h1>
      <div className="page-sub">
        {mine
          ? "Incidents currently assigned to you."
          : technique
            ? "Incidents whose Stage-2 evidence maps to this ATT&CK technique."
            : "Every open incident across all tenants scoped to your account."}
      </div>

      {technique && (
        <div data-testid="xdr-incidents-technique-pill"
                style={{
                  display: "inline-flex", alignItems: "center", gap: 8,
                  padding: "5px 10px", marginTop: 8,
                  borderRadius: 4,
                  border: "1px solid var(--purple)",
                  background: "rgba(155, 123, 240, 0.12)",
                  color: "var(--text)", fontSize: 11.5, fontWeight: 700,
                }}>
          <FilterIcon size={11} style={{ color: "var(--purple)" }} />
          <span className="mono" style={{ color: "var(--text)" }}>
            {technique}
          </span>
          <span style={{ color: "var(--text-dim)" }}>
            {TECHNIQUE_INDEX[technique]?.name}
          </span>
          <button className="btn ghost"
                     onClick={clearTechnique}
                     data-testid="xdr-incidents-clear-technique"
                     style={{ padding: "1px 6px", fontSize: 10 }}>
            <X size={11} /> Clear
          </button>
        </div>
      )}

      {loading && <div className="x-empty">LOADING…</div>}
      {!loading && error && (
        <div className="x-empty" style={{ color: "#ff9494" }}>{String(error)}</div>
      )}
      {!loading && !error && technique && visible.length === 0 && (
        <div className="x-empty" data-testid="xdr-incidents-technique-empty"
                style={{ marginTop: 12 }}>
          <b>NO MATCHING EVIDENCE</b> — no incidents in the current scope
          carry Stage-2 evidence mapped to <span className="mono">{technique}</span>.
          This is <b>not</b> a "safe" result: it means either the technique
          is not exercised in your environment, or no detection rule is
          mapped to it yet. Clear the filter or open the heatmap's coverage-gap
          panel for details.
        </div>
      )}
      {!loading && !error && (visible.length > 0 || !technique) && (
        <IncidentQueue
          rows={visible}
          q={q} onQChange={setQ}
          stateFilter={stateFilter} onStateChange={setS}
          title={mine ? "My Assigned Incidents"
                     : technique ? `Filtered · ${technique}`
                     : "All Incidents"}
        />
      )}
    </XdrShell>
  );
}
