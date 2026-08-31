/**
 * XdrIncidentsPage · `/xdr/incidents`
 *
 * Full queue view.  URL params:
 *   ?lens=<id>      → Operations-Dashboard lens filter.  Backend
 *                     honours the same predicate as the tile the
 *                     analyst clicked, so tile count == queue count.
 *                     Supported ids: critical · high_priority ·
 *                     high_fidelity · unassigned · in_progress_mine ·
 *                     customer_response · on_hold · aging ·
 *                     recently_created · recently_updated.
 *   ?mine=1        → My Queue (only rows assigned to me).  Kept for
 *                     backwards compatibility with existing shortcuts;
 *                     `?lens=in_progress_mine` is the canonical form.
 *   ?q=…           → search prefill.
 *   ?technique=T#  → filter to incidents whose Stage-2 evidence maps
 *                     to the given MITRE ATT&CK technique.  Powered by
 *                     the same rule→technique table the heatmap uses.
 *                     Never fabricates a technique-to-incident link.
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


// ── Lens labels (mirrors backend/services/dashboard_lenses LENSES) ──
// Any string not in this table is treated as unknown and cleared from
// the URL.  Backend also rejects unknown lenses with 400.
const LENS_LABELS = {
  critical:          { label: "Critical",          desc: "Open P1 incidents." },
  high_priority:     { label: "High Priority",     desc: "Open P1 + P2 incidents." },
  high_fidelity:     { label: "High Fidelity",     desc: "Incidents flagged high-fidelity by the detection engine." },
  unassigned:        { label: "Unassigned",        desc: "Open incidents with no assignee." },
  in_progress_mine:  { label: "In Progress — Mine",desc: "Incidents in progress that are assigned to you." },
  customer_response: { label: "Customer Response", desc: "On-hold incidents awaiting a customer response." },
  on_hold:           { label: "On Hold",           desc: "Incidents currently on hold." },
  aging:             { label: "SLA / Aging Risk",  desc: "Open incidents with SLA due within 4 h or breached." },
  recently_created:  { label: "Recently Created",  desc: "Incidents created in the last 24 h." },
  recently_updated:  { label: "Recently Updated",  desc: "Incidents updated in the last 24 h." },
};


// Test whether an incident's evidence maps to a given technique.
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
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();

  const lensParam  = (params.get("lens") || "").toLowerCase();
  const lens       = LENS_LABELS[lensParam] ? lensParam : null;
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
      // When a lens is set, the backend performs the filter — we
      // pass ?lens=<id> straight through so tile-count == queue-count.
      const res = await listIncidents({ limit: 500, lens: lens || null });
      setRows(res.incidents || []);
    } catch (e) {
      setError(e?.response?.data?.detail?.error
                 || e?.response?.data?.detail
                 || e?.message
                 || "Failed to load incidents.");
    } finally { setL(false); }
  }, [lens]);
  useEffect(() => { load(); }, [load]);

  const visible = useMemo(() => {
    let list = rows;
    if (mine)      list = list.filter((r) => r.assignee && r.assignee === user?.email);
    if (technique) list = list.filter((r) => incidentMatchesTechnique(r, technique));
    return list;
  }, [rows, mine, user?.email, technique]);

  const clearLens = () => {
    const next = new URLSearchParams(params);
    next.delete("lens");
    setParams(next, { replace: true });
  };
  const clearTechnique = () => {
    const next = new URLSearchParams(params);
    next.delete("technique");
    setParams(next, { replace: true });
  };

  const title = lens
    ? `Incidents · ${LENS_LABELS[lens].label}`
    : mine
      ? "My Queue"
      : technique
        ? `Incidents · ${technique}`
        : "Incidents";

  const sub = lens
    ? LENS_LABELS[lens].desc
    : mine
      ? "Incidents currently assigned to you."
      : technique
        ? "Incidents whose Stage-2 evidence maps to this ATT&CK technique."
        : "Every open incident across all tenants scoped to your account.";

  return (
    <XdrShell activeTop="dashboards">
      <div style={headerRow}>
        <div>
          <h1 className="page-h1" data-testid="xdr-incidents-heading">{title}</h1>
          <div className="page-sub">{sub}</div>
        </div>
        <button className="btn ghost"
                   data-testid="xdr-incidents-back-to-dashboard"
                   onClick={() => navigate("/xdr/dashboard")}
                   style={backBtn}>
          ← Analyst Operations
        </button>
      </div>

      {lens && (
        <div data-testid="xdr-incidents-lens-pill"
                data-lens-id={lens}
                style={pillWrap}>
          <FilterIcon size={11} style={{ color: "var(--purple)" }} />
          <span className="mono" style={{ color: "var(--text)", fontWeight: 700 }}>
            LENS
          </span>
          <span style={{ color: "var(--text-dim)" }}>
            {LENS_LABELS[lens].label}
          </span>
          <button className="btn ghost"
                     onClick={clearLens}
                     data-testid="xdr-incidents-clear-lens"
                     style={pillClear}>
            <X size={11} /> Clear
          </button>
        </div>
      )}

      {technique && (
        <div data-testid="xdr-incidents-technique-pill" style={pillWrap}>
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
                     style={pillClear}>
            <X size={11} /> Clear
          </button>
        </div>
      )}

      {loading && <div className="x-empty">LOADING…</div>}

      {!loading && error && (
        <div className="x-empty"
              data-testid="xdr-incidents-error"
              style={{ color: "#ff9494" }}>
          {String(error)}
        </div>
      )}

      {!loading && !error && lens && visible.length === 0 && (
        <div className="x-empty"
              data-testid="xdr-incidents-lens-empty"
              style={{ marginTop: 12 }}>
          <b>NO MATCHES FOR LENS</b> — the {LENS_LABELS[lens].label} lens
          currently has zero incidents.  This is an <b>honest empty
          state</b>, not a fabricated zero.  Clear the lens to return to
          the full queue.
        </div>
      )}

      {!loading && !error && technique && visible.length === 0 && !lens && (
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

      {!loading && !error && (visible.length > 0
                                  || (!lens && !technique)) && (
        <IncidentQueue
          rows={visible}
          q={q} onQChange={setQ}
          stateFilter={stateFilter} onStateChange={setS}
          title={lens ? `Filtered · ${LENS_LABELS[lens].label}`
                       : mine ? "My Assigned Incidents"
                       : technique ? `Filtered · ${technique}`
                       : "All Incidents"}
        />
      )}
    </XdrShell>
  );
}


// ── Styles ─────────────────────────────────────────────────────────
const headerRow = {
  display: "flex", justifyContent: "space-between", alignItems: "flex-start",
  gap: 12, marginBottom: 4,
};
const backBtn = {
  padding: "6px 10px", fontSize: 11, fontFamily: "var(--mono)",
};
const pillWrap = {
  display: "inline-flex", alignItems: "center", gap: 8,
  padding: "5px 10px", marginTop: 8, marginRight: 8,
  borderRadius: 4,
  border: "1px solid var(--purple)",
  background: "rgba(155, 123, 240, 0.12)",
  color: "var(--text)", fontSize: 11.5, fontWeight: 700,
};
const pillClear = {
  padding: "1px 6px", fontSize: 10,
};
