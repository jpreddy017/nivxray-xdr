/**
 * XdrDetectionsPage · `/xdr/detections`
 *
 * Detection Engineering catalog.  Lists every authored rule with
 * lifecycle, severity, MITRE techniques, and validation status.
 * Runtime honesty banner surfaces the "AUTHORING AVAILABLE —
 * RUNTIME NOT WIRED" invariant.
 */
import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { PlusCircle, Filter as FilterIcon, AlertTriangle,
  Radar, GitBranch, FileText } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { NxChip, NxDataTable, NxFilter, NxState,
         NxTokenList } from "@/xdr/nx";
import {
  listRules, createRule, buildCoverage, LIFECYCLE, LIFECYCLE_LABELS,
  RUNTIME_STATUS,
} from "@/xdr/detect/detectionRuleStore";


export default function XdrDetectionsPage() {
  const [q, setQ]          = useState("");
  const [lc, setLc]        = useState("");
  const [refresh, setR]    = useState(0);
  const navigate           = useNavigate();
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
        test/replay.  Rules authored here promote to the
        <b> Detection Registry</b>, which is the single source of
        truth for every rule NivXRay executes.
      </div>

      {/* Consolidation notice — one rule identity, one registry. */}
      <div data-testid="xdr-detections-consolidation-banner"
              style={{ marginTop: 10, padding: 10,
                          border: "1px solid var(--cyan)", borderRadius: 4,
                          background: "rgba(6,182,212,.06)",
                          color: "var(--text-dim)", fontSize: 11.5,
                          display: "flex", alignItems: "center", gap: 10 }}>
        <b style={{ color: "var(--cyan)", fontFamily: "var(--mono)",
                          letterSpacing: ".3px" }}>ONE AUTHORITATIVE REGISTRY</b>
        — the authoring workstation is a UI over the same
        <code style={{ margin: "0 4px" }}>/api/xdr/detection</code> registry
        surfaced under Admin › Detection Registry.  No parallel rule store.
        <span style={{ flex: 1 }} />
        <a href="/xdr/admin/detection-registry"
              style={{ color: "var(--cyan)",
                              fontFamily: "var(--mono)", fontSize: 11 }}>
          Open Detection Registry →
        </a>
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

      {/* One filter grammar, and the constraints are VISIBLE: an invisible
          filter is how an analyst concludes "there is no detection for
          this". */}
      <NxFilter testid="xdr-detections-filter"
                value={{ q, lifecycle: lc }}
                onChange={(v) => { setQ(v.q ?? ""); setLc(v.lifecycle ?? ""); }}
                onClear={() => { setQ(""); setLc(""); }}
                right={<span className="nx-absent nx-mono">
                  {rules.length} rules
                </span>}
                fields={[
        { key: "q", label: "Search",
          placeholder: "title, tag, technique…" },
        { key: "lifecycle", label: "Lifecycle", type: "select",
          options: [{ value: "", label: "All lifecycles" },
                    ...LIFECYCLE.map((l) => ({ value: l,
                                               label: LIFECYCLE_LABELS[l] }))] },
      ]} />

      <NxDataTable rows={rules} pageSize={25} searchable={false}
                   rowKey={(r) => r.id}
                   onRowClick={(r) => navigate(`/xdr/detections/${r.id}`)}
                   testid="xdr-detections-table"
                   emptyTitle="No detection rule matches this scope"
                   emptyHint='Use "New rule" to author a Sigma detection.
                              Nothing is pre-seeded, so an empty list means
                              nothing has been authored — not that coverage
                              is unknown.'
                   columns={[
        { key: "title", header: "Detection rule", width: "320px",
          value: (r) => r.title,
          render: (r) => (
            <span data-testid={`xdr-detections-row-${r.id}`}>
              <strong>{r.title}</strong>
              <div className="nx-absent">
                {r.description || "no description"}
              </div>
            </span>) },
        { key: "severity", header: "Severity", width: "110px",
          value: (r) => r.severity || "",
          render: (r) => <NxState value={r.severity} /> },
        { key: "lifecycle", header: "Lifecycle", width: "140px",
          value: (r) => r.lifecycle || "",
          render: (r) => (
            <NxChip tone={r.lifecycle === "active" ? "benign" : "neutral"}
                    variant={r.lifecycle === "active" ? "filled" : "dashed"}
                    data-testid={`xdr-detections-lc-${r.id}`}>
              {LIFECYCLE_LABELS[r.lifecycle] || r.lifecycle}
            </NxChip>) },
        { key: "techniques", header: "ATT&CK", width: "190px",
          value: (r) => (r.techniques || []).join(","),
          render: (r) => <NxTokenList values={r.techniques} limit={3} /> },
        { key: "validation", header: "Validation", width: "210px",
          value: (r) => (r.validation?.ok === false ? 0 : 1),
          render: (r) => {
            if (r.validation && !r.validation.ok) {
              return (
                <span data-testid={`xdr-detections-invalid-${r.id}`}>
                  <NxState value="FAIL" reason="rule validation failed" />
                </span>);
            }
            if (r.validation?.unsupported?.length) {
              return (
                <span title={r.validation.unsupported.join(", ")}>
                  <NxState value="PARTIAL"
                           reason={`unsupported: ${r.validation.unsupported.join(", ")}`} />
                </span>);
            }
            return <NxState value="PASS" />;
          } },
        { key: "version", header: "Version", width: "90px", align: "right",
          value: (r) => r.version,
          render: (r) => <span className="nx-mono">v{r.version}</span> },
      ]} />

      {/* Coverage view */}
      {rules.length > 0 && (
        <div style={{ marginTop: 20 }}>
          <div className="section-title" style={{ marginBottom: 6 }}>
            Detection Coverage
          </div>
          <div style={{ fontSize: 11.5, color: "var(--muted)", marginBottom: 10 }}>
            Where your detection catalog covers the MITRE matrix. Zero
            in a lane means no detection exists for it yet.
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
                  <span className="mono" style={{ color: "var(--nx-purple)" }}>{t}</span>
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
