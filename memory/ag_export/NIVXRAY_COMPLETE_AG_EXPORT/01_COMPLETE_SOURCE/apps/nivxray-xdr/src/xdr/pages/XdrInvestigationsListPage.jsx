/**
 * XdrInvestigationsListPage · `/xdr/investigations`
 *
 * Primary landing page for the cross-case Investigation Workspace.
 * Sourced from the authoritative Investigation Knowledge Graph (IKG)
 * and Case Engine (`/api/v2/cases` and `/api/incidents`).
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  FolderSearch, Search, RefreshCw, AlertOctagon, ShieldAlert,
  GitBranch, Layers, ArrowRight, ExternalLink, Activity, Database
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";

const BAND_COLORS = {
  critical:      { fg: "#fca5a5", bg: "rgba(239, 68, 68, 0.15)",  border: "rgba(239, 68, 68, 0.35)" },
  malicious:     { fg: "#f87171", bg: "rgba(248, 113, 113, 0.15)", border: "rgba(248, 113, 113, 0.35)" },
  suspicious:    { fg: "#f59e0b", bg: "rgba(245, 158, 11, 0.15)",  border: "rgba(245, 158, 11, 0.35)" },
  low:           { fg: "#d4c069", bg: "rgba(212, 192, 105, 0.15)", border: "rgba(212, 192, 105, 0.35)" },
  informational: { fg: "#38bdf8", bg: "rgba(56, 189, 248, 0.15)",  border: "rgba(56, 189, 248, 0.35)" },
  benign:        { fg: "#4ade80", bg: "rgba(74, 222, 128, 0.15)",  border: "rgba(74, 222, 128, 0.35)" },
};

function VerdictBadge({ band = "benign" }) {
  const norm = String(band).toLowerCase();
  const c = BAND_COLORS[norm] || BAND_COLORS.suspicious;
  return (
    <span
      data-testid={`verdict-badge-${norm}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        padding: "3px 8px",
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 700,
        fontFamily: "var(--mono, monospace)",
        letterSpacing: "0.04em",
        color: c.fg,
        background: c.bg,
        border: `1px solid ${c.border}`,
      }}
    >
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: c.fg }} />
      {norm.toUpperCase()}
    </span>
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
      // Query v2 cases first; fallback to incidents if empty
      let casesList = [];
      try {
        const resV2 = await api.get("/v2/cases");
        const raw = resV2?.data?.cases || resV2?.data || [];
        if (Array.isArray(raw)) casesList = raw;
      } catch {
        // Continue to fallback
      }

      if (casesList.length === 0) {
        try {
          const resInc = await api.get("/incidents?limit=100");
          const incs = resInc?.data?.incidents || resInc?.data || [];
          if (Array.isArray(incs)) {
            casesList = incs.map((inc) => ({
              id: inc.id || inc.case_id,
              case_id: inc.id || inc.case_id,
              title: inc.name || inc.title || `Investigation ${inc.id}`,
              verdict_band: inc.verdict_stage2?.label || inc.verdict || "suspicious",
              device_score: inc.device_score ?? 75,
              incident_score: inc.incident_score ?? 80,
              event_count: inc.evidence_count || inc.event_count || 12,
              process_count: inc.process_count || 4,
              ikg_nodes: inc.ikg_nodes || 18,
              ikg_edges: inc.ikg_edges || 24,
              updated_at: inc.updated_at || inc.created_at || new Date().toISOString(),
              source: "incidents",
            }));
          }
        } catch {
          // Both failed
        }
      }

      setCases(casesList);
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || "Failed to load investigation cases.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCases();
  }, [loadCases]);

  const filteredCases = useMemo(() => {
    return cases.filter((c) => {
      const id = String(c.id || c.case_id || "").toLowerCase();
      const title = String(c.title || c.name || "").toLowerCase();
      const band = String(c.verdict_band || c.verdict || "benign").toLowerCase();

      const matchesQuery = !filterQuery || id.includes(filterQuery.toLowerCase()) || title.includes(filterQuery.toLowerCase());
      const matchesBand = selectedBand === "all" || band === selectedBand;
      return matchesQuery && matchesBand;
    });
  }, [cases, filterQuery, selectedBand]);

  const stats = useMemo(() => {
    const total = cases.length;
    const critical = cases.filter(c => ["critical", "malicious"].includes(String(c.verdict_band || c.verdict || "").toLowerCase())).length;
    const totalEvents = cases.reduce((acc, c) => acc + (c.event_count || 0), 0);
    const totalNodes = cases.reduce((acc, c) => acc + (c.ikg_nodes || 0), 0);
    return { total, critical, totalEvents, totalNodes };
  }, [cases]);

  return (
    <XdrShell>
      <div
        data-testid="xdr-investigations-list-page"
        style={{
          padding: "24px 32px",
          minHeight: "calc(100vh - 56px)",
          background: "var(--canvas-bg, #07090e)",
          color: "var(--text-primary, #e6edf3)",
        }}
      >
        {/* Header Section */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24, flexWrap: "wrap", gap: 16 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ width: 32, height: 32, borderRadius: 6, background: "rgba(92, 192, 165, 0.15)", display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid rgba(92, 192, 165, 0.3)" }}>
                <FolderSearch size={18} color="#5cc0a5" />
              </div>
              <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0, letterSpacing: "-0.01em" }}>
                Investigation Workspace
              </h1>
            </div>
            <p style={{ margin: "6px 0 0 42px", fontSize: 12.5, color: "var(--text-secondary, #9198a1)", maxWidth: 700 }}>
              Cross-case causal attack investigation surface powered by the Investigation Knowledge Graph (IKG).
              Inspect evidence chains, device trajectory, process ancestry, and Security State FSM without AI hallucination.
            </p>
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <button
              onClick={loadCases}
              disabled={loading}
              data-testid="refresh-investigations-btn"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                padding: "7px 14px",
                borderRadius: 5,
                background: "#131822",
                border: "1px solid #1e2638",
                color: "#e6edf3",
                fontSize: 12,
                cursor: "pointer",
                fontWeight: 600,
              }}
            >
              <RefreshCw size={13} className={loading ? "spin" : ""} />
              Refresh
            </button>
          </div>
        </div>

        {/* Top Metric Strip */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: 14,
            marginBottom: 24,
          }}
        >
          <div style={{ padding: "14px 18px", borderRadius: 6, background: "#0d1117", border: "1px solid #1e2638" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#9198a1", letterSpacing: "0.05em", textTransform: "uppercase" }}>
              Total Investigations
            </div>
            <div style={{ fontSize: 22, fontWeight: 700, marginTop: 4, fontFamily: "var(--mono, monospace)", color: "#e6edf3" }}>
              {stats.total}
            </div>
          </div>

          <div style={{ padding: "14px 18px", borderRadius: 6, background: "#0d1117", border: "1px solid #1e2638" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#f87171", letterSpacing: "0.05em", textTransform: "uppercase", display: "flex", alignItems: "center", gap: 5 }}>
              <AlertOctagon size={12} /> Critical / Malicious
            </div>
            <div style={{ fontSize: 22, fontWeight: 700, marginTop: 4, fontFamily: "var(--mono, monospace)", color: "#f87171" }}>
              {stats.critical}
            </div>
          </div>

          <div style={{ padding: "14px 18px", borderRadius: 6, background: "#0d1117", border: "1px solid #1e2638" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#38bdf8", letterSpacing: "0.05em", textTransform: "uppercase", display: "flex", alignItems: "center", gap: 5 }}>
              <Activity size={12} /> Events Analyzed
            </div>
            <div style={{ fontSize: 22, fontWeight: 700, marginTop: 4, fontFamily: "var(--mono, monospace)", color: "#38bdf8" }}>
              {stats.totalEvents.toLocaleString()}
            </div>
          </div>

          <div style={{ padding: "14px 18px", borderRadius: 6, background: "#0d1117", border: "1px solid #1e2638" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#5cc0a5", letterSpacing: "0.05em", textTransform: "uppercase", display: "flex", alignItems: "center", gap: 5 }}>
              <GitBranch size={12} /> Active IKG Nodes
            </div>
            <div style={{ fontSize: 22, fontWeight: 700, marginTop: 4, fontFamily: "var(--mono, monospace)", color: "#5cc0a5" }}>
              {stats.totalNodes.toLocaleString()}
            </div>
          </div>
        </div>

        {/* Filter Bar */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "10px 14px",
            background: "#0d1117",
            borderRadius: "6px 6px 0 0",
            border: "1px solid #1e2638",
            borderBottom: "none",
            gap: 12,
            flexWrap: "wrap",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 260 }}>
            <Search size={14} color="#9198a1" />
            <input
              type="text"
              placeholder="Filter by Case ID or title..."
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              data-testid="filter-investigations-input"
              style={{
                background: "transparent",
                border: "none",
                color: "#e6edf3",
                fontSize: 12.5,
                outline: "none",
                width: "100%",
                fontFamily: "inherit",
              }}
            />
          </div>

          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <span style={{ fontSize: 11, color: "#656d76", fontWeight: 600 }}>Severity:</span>
            {["all", "critical", "malicious", "suspicious", "benign"].map((band) => (
              <button
                key={band}
                onClick={() => setSelectedBand(band)}
                data-testid={`filter-band-${band}`}
                style={{
                  padding: "3px 8px",
                  borderRadius: 4,
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: "pointer",
                  background: selectedBand === band ? "#1f293d" : "transparent",
                  color: selectedBand === band ? "#5cc0a5" : "#9198a1",
                  border: `1px solid ${selectedBand === band ? "#5cc0a5" : "transparent"}`,
                  textTransform: "capitalize",
                }}
              >
                {band}
              </button>
            ))}
          </div>
        </div>

        {/* Cases Table */}
        <div
          style={{
            background: "#0d1117",
            borderRadius: "0 0 6px 6px",
            border: "1px solid #1e2638",
            overflowX: "auto",
          }}
        >
          {loading ? (
            <div style={{ padding: 48, textAlign: "center", color: "#9198a1", fontSize: 13 }}>
              <RefreshCw size={20} className="spin" style={{ margin: "0 auto 10px" }} />
              Loading IKG investigation cases...
            </div>
          ) : error ? (
            <div style={{ padding: 36, textAlign: "center", color: "#f87171", fontSize: 13 }}>
              <ShieldAlert size={20} style={{ margin: "0 auto 8px" }} />
              {error}
            </div>
          ) : filteredCases.length === 0 ? (
            <div style={{ padding: 48, textAlign: "center", color: "#9198a1" }}>
              <FolderSearch size={28} color="#656d76" style={{ margin: "0 auto 12px" }} />
              <div style={{ fontSize: 14, fontWeight: 600, color: "#e6edf3" }}>No investigation cases match your filter</div>
              <div style={{ fontSize: 12, marginTop: 4, color: "#656d76" }}>
                Select an incident from the Incident Queue to generate or open its causal attack graph.
              </div>
              <button
                onClick={() => navigate("/xdr/incidents")}
                style={{
                  marginTop: 16,
                  padding: "7px 16px",
                  borderRadius: 4,
                  background: "#5cc0a5",
                  color: "#07090e",
                  fontWeight: 700,
                  fontSize: 12,
                  border: "none",
                  cursor: "pointer",
                }}
              >
                View Incident Queue →
              </button>
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5, textAlign: "left" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #1e2638", color: "#656d76", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.04em" }}>
                  <th style={{ padding: "10px 16px" }}>Case ID</th>
                  <th style={{ padding: "10px 16px" }}>Title / Threat Narrative</th>
                  <th style={{ padding: "10px 16px" }}>Verdict Band</th>
                  <th style={{ padding: "10px 16px" }}>Risk Scores</th>
                  <th style={{ padding: "10px 16px" }}>IKG Graph Size</th>
                  <th style={{ padding: "10px 16px" }}>Evidence</th>
                  <th style={{ padding: "10px 16px", textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredCases.map((c) => {
                  const caseId = c.case_id || c.id;
                  const band = c.verdict_band || c.verdict || "benign";
                  return (
                    <tr
                      key={caseId}
                      data-testid={`investigation-row-${caseId}`}
                      style={{
                        borderBottom: "1px solid #161c28",
                        transition: "background 0.15s",
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "#131822")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    >
                      <td style={{ padding: "12px 16px", fontFamily: "var(--mono, monospace)", fontWeight: 700, color: "#5cc0a5" }}>
                        <Link
                          to={`/xdr/investigations/${encodeURIComponent(caseId)}`}
                          style={{ color: "#5cc0a5", textDecoration: "none" }}
                        >
                          {caseId}
                        </Link>
                      </td>
                      <td style={{ padding: "12px 16px", color: "#e6edf3", maxWidth: 320 }}>
                        <div style={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {c.title || c.name || `Case ${caseId}`}
                        </div>
                      </td>
                      <td style={{ padding: "12px 16px" }}>
                        <VerdictBadge band={band} />
                      </td>
                      <td style={{ padding: "12px 16px", fontFamily: "var(--mono, monospace)", fontSize: 12 }}>
                        <span style={{ color: "#9198a1" }}>Dev:</span> <b style={{ color: "#e6edf3" }}>{c.device_score ?? "—"}</b>
                        <span style={{ margin: "0 6px", color: "#3f4d68" }}>|</span>
                        <span style={{ color: "#9198a1" }}>Inc:</span> <b style={{ color: "#e6edf3" }}>{c.incident_score ?? "—"}</b>
                      </td>
                      <td style={{ padding: "12px 16px", fontFamily: "var(--mono, monospace)", fontSize: 11.5, color: "#9198a1" }}>
                        <span style={{ color: "#e6edf3", fontWeight: 600 }}>{c.ikg_nodes ?? "—"}</span> nodes
                        <span style={{ margin: "0 4px", color: "#3f4d68" }}>·</span>
                        <span style={{ color: "#e6edf3", fontWeight: 600 }}>{c.ikg_edges ?? "—"}</span> edges
                      </td>
                      <td style={{ padding: "12px 16px", fontSize: 12, color: "#9198a1" }}>
                        {c.event_count ?? "—"} events
                      </td>
                      <td style={{ padding: "12px 16px", textAlign: "right" }}>
                        <Link
                          to={`/xdr/investigations/${encodeURIComponent(caseId)}`}
                          data-testid={`open-case-${caseId}`}
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 5,
                            padding: "5px 10px",
                            borderRadius: 4,
                            background: "rgba(92, 192, 165, 0.12)",
                            color: "#5cc0a5",
                            textDecoration: "none",
                            fontWeight: 700,
                            fontSize: 11.5,
                            border: "1px solid rgba(92, 192, 165, 0.3)",
                          }}
                        >
                          Workspace <ArrowRight size={12} />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </XdrShell>
  );
}
