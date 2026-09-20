/**
 * XdrInvestigationsListPage · `/xdr/investigations` — Investigate landing.
 *
 * B2-INV. The landing lists the investigations the principal may see and
 * opens each one in the SINGLE analyst workspace
 * (`/xdr/incidents/:id?tab=story`). There is no second investigation
 * experience: the causal engine's panels are mounted underneath the
 * analyst tabs that own their question.
 *
 * Data authority is unchanged — `/api/v2/cases` with the incident
 * registry as the fallback projection. A verdict the platform did not
 * issue stays NO EVIDENCE; nothing is coerced to "benign".
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { RefreshCw, ArrowRight, Search } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";
import "@/xdr/nx/nx-cc.css";
import { apiErrorText } from "@/xdr/nx/apiError";
import { NxChip, NxDataTable, NxButton } from "@/xdr/nx";

const BANDS = ["all", "critical", "malicious", "suspicious", "low",
               "informational", "benign", "unknown"];

const BAND_TONE = {
  critical: "critical", malicious: "critical", suspicious: "high",
  low: "high", informational: "", benign: "benign", unknown: "",
};

//: A verdict the platform did not issue reads "No evidence" — it is never
//: rounded to benign, and it is never shouted in raw machine casing.
function VerdictBadge({ band }) {
  const norm = typeof band === "string" && band ? band.toLowerCase() : "unknown";
  const label = norm === "unknown" ? "No evidence"
    : norm.charAt(0).toUpperCase() + norm.slice(1);
  const tone = BAND_TONE[norm] || "neutral";
  return (
    <NxChip tone={tone} variant={norm === "unknown" ? "dashed" : "tinted"}
            data-testid={`verdict-badge-${norm}`}>
      {label}
    </NxChip>
  );
}

export default function XdrInvestigationsListPage() {
  const navigate = useNavigate();
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filterQuery, setFilterQuery] = useState("");
  const [selectedBand, setSelectedBand] = useState("all");

  const loadCases = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      let casesList = [];
      try {
        const resV2 = await api.get("/v2/cases");
        const raw = resV2?.data?.cases || resV2?.data || [];
        if (Array.isArray(raw)) casesList = raw;
      } catch { /* fall through to the incident registry */ }

      if (casesList.length === 0) {
        try {
          const resInc = await api.get("/incidents?limit=500");
          const incs = resInc?.data?.incidents || resInc?.data || [];
          if (Array.isArray(incs)) {
            casesList = incs.map((inc) => {
              // Honest coercion: verdict may be a string, an object with
              // .label, or absent. Never "[object Object]", never invented.
              let bandRaw = inc.verdict_stage2?.label ?? inc.verdict;
              if (bandRaw && typeof bandRaw === "object") {
                bandRaw = bandRaw.label ?? bandRaw.verdict ?? null;
              }
              return {
                id: inc.id || inc.case_id,
                case_id: inc.id || inc.case_id,
                title: inc.name || inc.title || `Investigation ${inc.id}`,
                verdict_band: (typeof bandRaw === "string" && bandRaw)
                  ? bandRaw : null,
                device_score: inc.device_score ?? null,
                incident_score: inc.incident_score
                  ?? inc.verdict?.risk_score ?? null,
                event_count: inc.evidence_count ?? inc.event_count ?? null,
                process_count: inc.process_count ?? null,
                ikg_nodes: inc.ikg_nodes ?? null,
                ikg_edges: inc.ikg_edges ?? null,
                customer: inc.customer ?? null,
                updated_at: inc.updated_at || inc.created_at || null,
                source: "incidents",
              };
            });
          }
        } catch { /* both authorities silent — reported below */ }
      }
      setCases(casesList);
    } catch (err) {
      setError(apiErrorText(err, "Failed to load investigations."));
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { loadCases(); }, [loadCases]);

  const filtered = useMemo(() => cases.filter((c) => {
    const id = String(c.id || c.case_id || "").toLowerCase();
    const title = String(c.title || c.name || "").toLowerCase();
    const bandRaw = typeof c.verdict_band === "string" ? c.verdict_band : null;
    const band = bandRaw ? bandRaw.toLowerCase() : "unknown";
    const q = filterQuery.trim().toLowerCase();
    return (!q || id.includes(q) || title.includes(q))
      && (selectedBand === "all" || band === selectedBand);
  }), [cases, filterQuery, selectedBand]);

  //: 2026-06 · this sent the analyst to `/xdr/incidents/<caseId>`, but a
  //: case id is not an incident id: for a case with no incident of the same
  //: id the incident page correctly answers "not available to you" (it
  //: refuses to disclose existence), so "Investigate" dead-ended on a
  //: fail-closed page. It now opens the investigation workspace, which is
  //: the surface that can actually render a case.
  const open = (caseId) =>
    navigate(`/xdr/investigations/${encodeURIComponent(caseId)}/_engine?tab=story`);

  return (
    <XdrShell>
      <div className="cc" data-testid="xdr-investigations-list-page"
           style={{ padding: "12px 16px 24px" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12,
                      flexWrap: "wrap" }}>
          <h1 style={{ margin: 0, fontSize: 19, fontWeight: 700 }}
              data-testid="xdr-investigate-title">
            Investigate
          </h1>
          <span style={{ fontSize: 11, color: "var(--nx-muted, var(--muted))",
                         maxWidth: 760, lineHeight: 1.6 }}>
            Every investigation the platform holds, opened in one workspace:
            attack story, timeline, evidence, entities, detections, ATT&amp;CK,
            response and report. The causal engine sits underneath those
            surfaces, not beside them.
          </span>
          <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
            <NxButton onClick={loadCases} disabled={loading}
                      testid="refresh-investigations-btn">
              <RefreshCw size={11} /> Refresh
            </NxButton>
          </div>
        </div>

        <div className="cc-cond" data-testid="xdr-investigate-summary">
          <span className="cc-cond__i">
            <span className="cc-cond__k">Investigations</span>
            <span className="cc-cond__v">
              {loading ? "reading…" : cases.length}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Shown</span>
            <span className="cc-cond__v">{filtered.length}</span>
          </span>
          <span className="cc-cond__i" style={{ gap: 6 }}>
            <span className="cc-cond__k">Verdict</span>
            <select value={selectedBand}
                    onChange={(e) => setSelectedBand(e.target.value)}
                    data-testid="xdr-investigate-band-filter"
                    style={{ fontSize: 11, background: "transparent",
                             color: "var(--nx-text, var(--text))",
                             border: "1px solid var(--nx-bd-quiet, var(--border))",
                             borderRadius: 3, padding: "2px 5px" }}>
              {BANDS.map((b) => (
                <option key={b} value={b}>
                  {b === "all" ? "any" : b === "unknown" ? "no evidence" : b}
                </option>
              ))}
            </select>
          </span>
          <span className="cc-cond__i" style={{ marginLeft: "auto", gap: 6 }}>
            <Search size={11} style={{ opacity: .6 }} />
            <input value={filterQuery}
                   onChange={(e) => setFilterQuery(e.target.value)}
                   data-testid="xdr-investigate-filter"
                   placeholder="Filter case id or title…"
                   style={{ fontSize: 11, background: "transparent",
                            border: "none", outline: "none", width: 230,
                            color: "var(--nx-text, var(--text))" }} />
          </span>
        </div>

        <div className="cc-card" data-testid="xdr-investigate-list-card">
          <div className="cc-card__h">
            <span className="cc-card__t">Investigations</span>
            <span className="cc-card__s">
              opens the unified analyst workspace
            </span>
          </div>
          <div className="cc-card__b">
            {error && (
              <div className="cc-empty" data-testid="xdr-investigate-error">
                <b>Not available</b> — {String(
                  typeof error === "object" ? JSON.stringify(error) : error)}
              </div>
            )}
            {loading && !cases.length && (
              <div className="cc-empty">Reading the case authority…</div>
            )}
            {!loading && filtered.length === 0 && !error && (
              <div className="cc-empty" data-testid="xdr-investigate-empty">
                <b>No investigation in scope</b> — neither the case engine nor
                the incident registry returns a record your identity is
                authorized to open. This is an authorization and data
                statement, not a broken page.
              </div>
            )}
            {filtered.length > 0 && (
              <NxDataTable rows={filtered.slice(0, 200)} pageSize={25}
                           searchable={false}
                           rowKey={(c) => c.id || c.case_id}
                           onRowClick={(c) => open(c.id || c.case_id)}
                           testid="xdr-investigate-table"
                           emptyTitle="No investigation in scope"
                           columns={[
                { key: "case", header: "Case", width: "200px",
                  value: (c) => c.id || c.case_id,
                  render: (c) => (
                    <strong className="nx-mono"
                            data-testid={`investigation-row-${c.id || c.case_id}`}>
                      {c.id || c.case_id}
                    </strong>) },
                { key: "title", header: "Title",
                  value: (c) => c.title || c.name || "",
                  render: (c) => (c.title || c.name
                    || <span className="nx-absent">Unnamed</span>) },
                { key: "verdict", header: "Verdict", width: "140px",
                  value: (c) => c.verdict_band || "unknown",
                  render: (c) => <VerdictBadge band={c.verdict_band} /> },
                { key: "risk", header: "Risk", width: "80px", align: "right",
                  value: (c) => c.incident_score ?? c.device_score ?? -1,
                  render: (c) => (c.incident_score ?? c.device_score
                    ?? <span className="nx-absent">—</span>) },
                { key: "ikg", header: "Knowledge graph", width: "150px",
                  align: "right",
                  value: (c) => (c.ikg_nodes ?? -1),
                  render: (c) => (c.ikg_nodes == null && c.ikg_edges == null
                    ? <span className="nx-absent">Not built</span>
                    : `${c.ikg_nodes ?? 0}n / ${c.ikg_edges ?? 0}e`) },
                { key: "events", header: "Events", width: "90px",
                  align: "right",
                  value: (c) => c.event_count ?? -1,
                  render: (c) => (c.event_count
                    ?? <span className="nx-absent">—</span>) },
                { key: "customer", header: "Customer", width: "150px",
                  value: (c) => c.customer || "",
                  render: (c) => (c.customer
                    || <span className="nx-absent">Not attributed</span>) },
                { key: "open", header: "", width: "130px", sortable: false,
                  render: (c) => (
                    <button className="nx-btn"
                            data-testid={`open-case-${c.id || c.case_id}`}
                            onClick={(e) => { e.stopPropagation();
                                              open(c.id || c.case_id); }}>
                      Investigate <ArrowRight size={11} />
                    </button>) },
              ]} />
            )}
          </div>
        </div>
      </div>
    </XdrShell>
  );
}
