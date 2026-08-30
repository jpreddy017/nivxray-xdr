/**
 * XdrDetectionsPage · `/xdr/detections`
 *
 * Detection Engineering catalog.  Lists every authored rule with
 * lifecycle, severity, MITRE techniques, and validation status.
 * Runtime honesty banner surfaces the "AUTHORING AVAILABLE —
 * RUNTIME NOT WIRED" invariant.
 */
import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { PlusCircle, Filter as FilterIcon, AlertTriangle,
  Radar, GitBranch, FileText } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import {
  listRules, createRule, buildCoverage, LIFECYCLE, LIFECYCLE_LABELS,
  RUNTIME_STATUS,
} from "@/xdr/detect/detectionRuleStore";


export default function XdrDetectionsPage() {
  const [q, setQ]          = useState("");
  const [lc, setLc]        = useState("");
  const [refresh, setR]    = useState(0);
  const rules = useMemo(() => listRules({ q, lifecycle: lc || undefined }),
                                [q, lc, refresh]);
  const coverage = useMemo(() => buildCoverage(rules), [rules]);

  return (
    <XdrShell activeTop="detect">
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <h1 className="page-h1" data-testid="xdr-detections-heading">
          Detection Engineering
        </h1>
        <span style={{ flex: 1 }} />
        <button className="btn primary"
                  onClick={() => { createRule(); setR((n) => n + 1); }}
                  data-testid="xdr-detections-new"
                  style={{ padding: "4px 12px" }}>
          <PlusCircle size={11} /> New rule
        </button>
      </div>
      <div className="page-sub">
        Author Sigma-compatible detection rules with lifecycle,
        version history, MITRE mapping, and evidence-backed
        test/replay.  Runtime execution is NOT WIRED yet — this is
        the authoring &amp; testing workstation.
      </div>

      {/* Honest runtime banner */}
      <div data-testid="xdr-detections-runtime-banner"
              style={{ marginTop: 10, padding: 10,
                          border: "1px dashed var(--amber)", borderRadius: 4,
                          background: "rgba(245,166,35,.08)",
                          color: "var(--text-dim)", fontSize: 11.5 }}>
        <b style={{ color: "var(--amber)", fontFamily: "var(--mono)" }}>
          {RUNTIME_STATUS.status}
        </b> — {RUNTIME_STATUS.detail}
      </div>

      {/* Filter bar */}
      <div style={{ display: "flex", gap: 8, alignItems: "center",
                        margin: "12px 0" }}>
        <input className="x-input"
                  placeholder="Search title, tag, technique…"
                  value={q} onChange={(e) => setQ(e.target.value)}
                  data-testid="xdr-detections-search"
                  style={{ maxWidth: 320 }} />
        <select className="x-input"
                   value={lc} onChange={(e) => setLc(e.target.value)}
                   data-testid="xdr-detections-lifecycle"
                   style={{ maxWidth: 160 }}>
          <option value="">All lifecycles</option>
          {LIFECYCLE.map((l) => (
            <option key={l} value={l}>{LIFECYCLE_LABELS[l]}</option>
          ))}
        </select>
        <span className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>
          {rules.length} rules
        </span>
      </div>

      {rules.length === 0 && (
        <div className="x-empty" data-testid="xdr-detections-empty">
          No rules yet.  Click <b>New rule</b> to author your first
          Sigma detection.
        </div>
      )}

      {rules.map((r) => (
        <Link key={r.id} to={`/xdr/detections/${r.id}`}
                 data-testid={`xdr-detections-row-${r.id}`}
                 style={{ textDecoration: "none", color: "inherit" }}>
          <div className="panel" style={{ padding: 12, marginBottom: 8,
                                                          borderLeft: `3px solid ${_sevColor(r.severity)}` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10,
                              flexWrap: "wrap" }}>
              <b style={{ fontSize: 13, color: "var(--text)" }}>{r.title}</b>
              <span className="mono"
                       style={{ padding: "1px 6px", borderRadius: 3,
                                   border: "1px solid var(--faint)",
                                   color: "var(--faint)", fontSize: 9.5,
                                   letterSpacing: ".3px", textTransform: "uppercase" }}>
                {LIFECYCLE_LABELS[r.lifecycle]}
              </span>
              <span className="mono"
                       style={{ padding: "1px 6px", borderRadius: 3,
                                   color: _sevColor(r.severity),
                                   border: `1px solid ${_sevColor(r.severity)}`,
                                   fontSize: 9.5, letterSpacing: ".3px",
                                   textTransform: "uppercase" }}>
                {r.severity}
              </span>
              {r.validation && !r.validation.ok && (
                <span data-testid={`xdr-detections-invalid-${r.id}`}
                         style={{ color: "#ff9494", fontSize: 10.5 }}>
                  <AlertTriangle size={10} /> validation failed
                </span>
              )}
              {r.validation?.unsupported?.length > 0 && (
                <span style={{ color: "var(--amber)", fontSize: 10.5 }}>
                  <AlertTriangle size={10} /> unsupported: {r.validation.unsupported.join(", ")}
                </span>
              )}
              <span style={{ flex: 1 }} />
              <span className="mono" style={{ color: "var(--faint)", fontSize: 10 }}>
                v{r.version}
              </span>
            </div>
            <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
              {r.description || "(no description)"}
            </div>
            <div style={{ marginTop: 6, display: "flex", gap: 4,
                              flexWrap: "wrap" }}>
              {(r.techniques || []).map((t) => (
                <span key={t} className="mono"
                         style={{ padding: "1px 5px", borderRadius: 3,
                                     border: "1px solid #f472b6",
                                     background: "rgba(244,114,182,.08)",
                                     color: "#f472b6", fontSize: 9.5 }}>
                  {t}
                </span>
              ))}
            </div>
          </div>
        </Link>
      ))}

      {/* Coverage view */}
      {rules.length > 0 && (
        <div style={{ marginTop: 20 }}>
          <div className="section-title" style={{ marginBottom: 6 }}>
            Detection Coverage
          </div>
          <div style={{ fontSize: 10.5, color: "var(--faint)", marginBottom: 8 }}>
            Coverage is a projection of the rule catalog only — it exposes
            gaps rather than pretty percentages.  Zero means you have
            no detection for that lane; that IS the signal.
          </div>
          <div style={{ display: "grid",
                            gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div className="panel" style={{ padding: 10 }}>
              <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                            textTransform: "uppercase",
                                                            letterSpacing: ".3px",
                                                            marginBottom: 6 }}>
                By MITRE Technique
              </div>
              {Object.entries(coverage.byTechnique).length === 0 && (
                <div style={{ fontSize: 11, color: "var(--faint)" }}>
                  No MITRE mappings.
                </div>
              )}
              {Object.entries(coverage.byTechnique).map(([t, rs]) => (
                <div key={t}
                        style={{ display: "flex", justifyContent: "space-between",
                                    padding: "3px 0", fontSize: 11,
                                    borderBottom: "1px solid var(--border)" }}>
                  <span className="mono" style={{ color: "#f472b6" }}>{t}</span>
                  <span className="mono" style={{ color: "var(--text-dim)" }}>
                    {rs.length} rule{rs.length === 1 ? "" : "s"}
                  </span>
                </div>
              ))}
            </div>
            <div className="panel" style={{ padding: 10 }}>
              <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                            textTransform: "uppercase",
                                                            letterSpacing: ".3px",
                                                            marginBottom: 6 }}>
                By Data Source
              </div>
              {Object.entries(coverage.byLogsource).length === 0 && (
                <div style={{ fontSize: 11, color: "var(--faint)" }}>
                  No log sources yet.
                </div>
              )}
              {Object.entries(coverage.byLogsource).map(([ls, rs]) => (
                <div key={ls}
                        style={{ display: "flex", justifyContent: "space-between",
                                    padding: "3px 0", fontSize: 11,
                                    borderBottom: "1px solid var(--border)" }}>
                  <span className="mono" style={{ color: "var(--cyan)" }}>{ls}</span>
                  <span className="mono" style={{ color: "var(--text-dim)" }}>
                    {rs.length}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </XdrShell>
  );
}


function _sevColor(sev) {
  const s = String(sev || "").toLowerCase();
  if (s.startsWith("crit")) return "#f87171";
  if (s.startsWith("high")) return "#fb923c";
  if (s.startsWith("med"))  return "#facc15";
  if (s.startsWith("low"))  return "#38bdf8";
  return "#94a3b8";
}
