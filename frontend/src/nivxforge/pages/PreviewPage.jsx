/**
 * NivXForge (Preview) — read-only surface.
 *
 * Consumes /api/nivxforge/preview/* endpoints. No writes, no
 * autonomous reasoning, no investigation workflow. Just exposes
 * governance status, ADRs, evidence inventory, and diagnostics so
 * analysts can see the platform state.
 *
 * This is the beginning of the independent NivXForge experience,
 * NOT a replacement for Workspace.
 */

import React, { useEffect, useMemo, useState } from "react";
import Header from "../../components/Header";
import NivxForgeSubNav from "../components/NivxForgeSubNav";
import api from "../../lib/api";

const S = {
  page: { padding: "24px 28px 72px", color: "var(--text)", minHeight: "100vh", background: "var(--bg)" },
  hero: { marginBottom: 28, paddingBottom: 20, borderBottom: "1px solid var(--border)" },
  eyebrow: { fontSize: 11, letterSpacing: "0.24em", color: "var(--accent, #7dd3fc)", textTransform: "uppercase", fontWeight: 600 },
  h1: { fontSize: 32, margin: "8px 0 6px", fontWeight: 700 },
  sub: { color: "var(--text-secondary, #94a3b8)", fontSize: 14, maxWidth: 720 },
  banner: { marginTop: 14, padding: "10px 14px", background: "rgba(125,211,252,0.08)", border: "1px solid rgba(125,211,252,0.25)", borderRadius: 8, fontSize: 13, color: "var(--text-secondary, #94a3b8)" },
  grid: { display: "grid", gap: 18, gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))" },
  card: { background: "var(--panel, #0f172a)", border: "1px solid var(--border, #1e293b)", borderRadius: 10, padding: 18 },
  cardH: { fontSize: 11, letterSpacing: "0.22em", color: "var(--text-secondary, #94a3b8)", marginBottom: 12, textTransform: "uppercase", fontWeight: 600 },
  row: { display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px dashed var(--border, #1e293b)", fontSize: 13 },
  chip: { display: "inline-block", padding: "2px 8px", borderRadius: 12, fontSize: 11, fontWeight: 600, letterSpacing: "0.05em" },
  chipAccepted: { background: "rgba(34,197,94,0.15)", color: "#4ade80", border: "1px solid rgba(34,197,94,0.35)" },
  chipProposed: { background: "rgba(250,204,21,0.15)", color: "#facc15", border: "1px solid rgba(250,204,21,0.35)" },
  chipOther: { background: "rgba(148,163,184,0.15)", color: "#cbd5e1", border: "1px solid rgba(148,163,184,0.35)" },
  pre: { fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 12, whiteSpace: "pre-wrap", background: "var(--bg, #020617)", border: "1px solid var(--border, #1e293b)", padding: 14, borderRadius: 8, maxHeight: 520, overflow: "auto", color: "var(--text, #e2e8f0)" },
  section: { marginTop: 22 },
  err: { color: "#f87171", fontSize: 13 },

  // Situational-awareness summary — monospaced status table, read-only.
  saWrap: { marginBottom: 26, background: "var(--panel, #0f172a)", border: "1px solid var(--border, #1e293b)", borderRadius: 10, padding: "18px 20px" },
  saHead: { display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 12 },
  saTitle: { fontSize: 12, letterSpacing: "0.22em", color: "var(--text-secondary, #94a3b8)", textTransform: "uppercase", fontWeight: 600 },
  saSub: { fontSize: 11, color: "var(--text-secondary, #94a3b8)", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" },
  saTable: { fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 13, display: "grid", gridTemplateColumns: "minmax(220px, max-content) 1fr", rowGap: 4, columnGap: 24 },
  saLabel: { color: "var(--text-secondary, #94a3b8)" },
  saValueActive: { color: "#4ade80", fontWeight: 600 },
  saValueHealthy: { color: "#4ade80", fontWeight: 600 },
  saValuePass: { color: "#4ade80", fontWeight: 600 },
  saValueUnverified: { color: "#facc15", fontWeight: 600 },
  saValueFail: { color: "#f87171", fontWeight: 600 },
  saValueNeutral: { color: "var(--text, #e2e8f0)" },
  saDetails: { marginTop: 14, borderTop: "1px dashed var(--border, #1e293b)", paddingTop: 12 },
  saDetailsToggle: { background: "transparent", border: "1px solid var(--border, #1e293b)", color: "var(--text-secondary, #94a3b8)", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 11, letterSpacing: "0.05em", padding: "5px 10px", borderRadius: 6, cursor: "pointer" },
  saDetailsGrid: { marginTop: 10, fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 12, display: "grid", gridTemplateColumns: "minmax(180px, max-content) 1fr", rowGap: 3, columnGap: 20, color: "var(--text-secondary, #94a3b8)" },
};

function statusChip(status) {
  const s = (status || "").toLowerCase();
  if (s === "accepted") return { ...S.chip, ...S.chipAccepted };
  if (s === "proposed") return { ...S.chip, ...S.chipProposed };
  return { ...S.chip, ...S.chipOther };
}

export default function PreviewPage() {
  const [gov, setGov] = useState(null);
  const [adrs, setAdrs] = useState(null);
  const [inv, setInv] = useState(null);
  const [diag, setDiag] = useState(null);
  const [fw, setFw] = useState(null);
  const [health, setHealth] = useState(null);
  const [err, setErr] = useState("");
  const [detailsOpen, setDetailsOpen] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const [g, a, i, d, f, h] = await Promise.all([
          api.get("/nivxforge/preview/governance"),
          api.get("/nivxforge/preview/adrs"),
          api.get("/nivxforge/preview/evidence-inventory"),
          api.get("/nivxforge/preview/diagnostics"),
          api.get("/nivxforge/preview/framework-status"),
          api.get("/nivxforge/preview/platform-health"),
        ]);
        setGov(g.data); setAdrs(a.data); setInv(i.data); setDiag(d.data); setFw(f.data); setHealth(h.data);
      } catch (e) {
        setErr(e?.message || "Failed to load Preview data");
      }
    })();
  }, []);

  const govRows = useMemo(() => {
    const docs = gov?.documents || {};
    return Object.entries(docs).map(([k, v]) => (
      <div key={k} style={S.row} data-testid={`gov-row-${k}`}>
        <span>{v.filename}</span>
        <span style={{ color: v.exists ? "#4ade80" : "#f87171", fontFamily: "ui-monospace" }}>
          {v.exists ? `${v.bytes} B` : "missing"}
        </span>
      </div>
    ));
  }, [gov]);

  return (
    <div>
      <Header />
      <NivxForgeSubNav active="governance" />
      <div style={S.page} data-testid="nivxforge-preview-page">
        <div style={S.hero}>
          <div style={S.eyebrow}>Evidence-Driven Preview</div>
          <h1 style={S.h1}>NivXForge <span style={{ opacity: 0.6, fontWeight: 400, fontSize: 18 }}>(Preview)</span></h1>
          <p style={S.sub}>
            This is the beginning of the independent NivXForge experience, not a replacement for Workspace.
            The Preview surface is <b>read-only</b> — it exposes governance state, evidence inventory,
            and accepted ADRs. No autonomous reasoning, no new investigative workflow.
          </p>
          <div style={S.banner} data-testid="preview-banner">
            All data below is served from <code>/api/nivxforge/preview/*</code> · GET-only endpoints ·
            Workspace behaviour unchanged.
          </div>
          {err ? <div style={{ ...S.banner, borderColor: "#f87171", color: "#f87171" }}>{err}</div> : null}
        </div>

        {health?.situational ? (
          <div style={S.saWrap} data-testid="situational-awareness">
            <div style={S.saHead}>
              <div style={S.saTitle}>Platform Status</div>
              <div style={S.saSub}>
                derived · read-only
              </div>
            </div>
            <div style={S.saTable}>
              <div style={S.saLabel}>Workspace Protection</div>
              <div style={S.saValueActive} data-testid="sa-workspace-protection">{health.situational.workspace_protection}</div>

              <div style={S.saLabel}>Preview Health</div>
              <div style={S.saValueHealthy} data-testid="sa-preview-health">{health.situational.preview_health}</div>

              <div style={S.saLabel}>Last Validation</div>
              <div style={S.saValueNeutral} data-testid="sa-last-validation">
                {health.situational.last_validation
                  ? (() => {
                      const d = new Date(health.situational.last_validation);
                      const pad = (n) => String(n).padStart(2, "0");
                      return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
                    })()
                  : "—"}
              </div>

              <div style={S.saLabel}>Validation Source</div>
              <div style={S.saValueNeutral} data-testid="sa-validation-source">
                {health.situational.validation_source || "—"}
              </div>

              <div style={S.saLabel}>Regression Suite</div>
              <div
                style={health.situational.regression_suite.includes("PASS") ? S.saValuePass
                     : health.situational.regression_suite === "unverified" ? S.saValueUnverified
                     : S.saValueFail}
                data-testid="sa-regression-suite"
              >
                {health.situational.regression_suite}
              </div>

              <div style={S.saLabel}>Accepted ADRs</div>
              <div style={S.saValueNeutral} data-testid="sa-accepted-adrs">{health.situational.accepted_adrs}</div>

              <div style={S.saLabel}>Registered Handlers</div>
              <div style={S.saValueNeutral} data-testid="sa-registered-handlers">{health.situational.registered_handlers}</div>

              <div style={S.saLabel}>Pending Handler ADRs</div>
              <div style={S.saValueNeutral} data-testid="sa-pending-handler-adrs">{health.situational.pending_handler_adrs}</div>

              <div style={S.saLabel}>SOC Cases Logged</div>
              <div style={S.saValueNeutral} data-testid="sa-soc-cases">{health.situational.soc_cases_logged}</div>
            </div>

            <div style={S.saDetails}>
              <button
                type="button"
                style={S.saDetailsToggle}
                onClick={() => setDetailsOpen((v) => !v)}
                data-testid="sa-details-toggle"
                aria-expanded={detailsOpen}
              >
                {detailsOpen ? "▾ Hide Validation Details" : "▸ View Validation Details"}
              </button>
              {detailsOpen && health.regression ? (
                <div style={S.saDetailsGrid} data-testid="sa-details-panel">
                  <div>Validation Timestamp</div>
                  <div style={{ color: "var(--text, #e2e8f0)" }}>{health.regression.verified_at || "—"}</div>
                  <div>Test Suite</div>
                  <div style={{ color: "var(--text, #e2e8f0)" }}>{health.regression.suite || "—"}</div>
                  <div>Duration</div>
                  <div style={{ color: "var(--text, #e2e8f0)" }}>
                    {health.regression.duration_seconds != null ? `${health.regression.duration_seconds}s` : "—"}
                  </div>
                  <div>Build Identifier</div>
                  <div style={{ color: "var(--text, #e2e8f0)" }}>{health.regression.build_id || "—"}</div>
                  <div>Verified By</div>
                  <div style={{ color: "var(--text, #e2e8f0)" }}>{health.regression.verified_by || "—"}</div>
                </div>
              ) : null}
            </div>
          </div>
        ) : null}

        <div style={S.grid}>
          <div style={S.card} data-testid="card-platform-health">
            <div style={S.cardH}>Platform Health</div>
            {health ? (
              <>
                <div style={S.row}><span>Framework version</span><span style={{ fontFamily: "ui-monospace", color: "#7dd3fc" }}>{health.framework.version}</span></div>
                <div style={S.row}><span>Accepted ADRs</span><span style={{ fontFamily: "ui-monospace" }}>{health.adrs.accepted} / {health.adrs.total}</span></div>
                <div style={S.row}><span>Registered handlers</span><span style={{ fontFamily: "ui-monospace" }}>{health.framework.registered_handlers}</span></div>
                <div style={S.row}><span>SOC cases logged</span><span style={{ fontFamily: "ui-monospace" }}>{health.evidence.soc_cases_logged}</span></div>
                <div style={S.row}><span>Diagnostic reports</span><span style={{ fontFamily: "ui-monospace" }}>{health.evidence.diagnostic_reports}</span></div>
                <div style={{ ...S.row, borderBottom: "none" }}><span>Mount mode</span><span style={{ ...S.chip, ...S.chipAccepted }}>{health.mount}</span></div>
              </>
            ) : <div style={S.err}>Loading…</div>}
          </div>

          <div style={S.card} data-testid="card-governance">
            <div style={S.cardH}>Governance Documents</div>
            {gov ? govRows : <div style={S.err}>Loading…</div>}
          </div>

          <div style={S.card} data-testid="card-adrs">
            <div style={S.cardH}>Architecture Decision Records</div>
            {adrs ? adrs.adrs.map((a) => (
              <div key={a.slug} style={S.row} data-testid={`adr-row-${a.id}`}>
                <span>
                  <code style={{ color: "#7dd3fc" }}>ADR-{a.id}</code> &nbsp; {a.title.replace(/^ADR\s*\d+\s*[—-]\s*/, "")}
                </span>
                <span style={statusChip(a.status)}>{a.status}</span>
              </div>
            )) : <div style={S.err}>Loading…</div>}
          </div>

          <div style={S.card} data-testid="card-framework">
            <div style={S.cardH}>Framework Status (ADR-0001)</div>
            {fw ? (
              <>
                <div style={S.row}><span>Registered detectors</span><span style={{ fontFamily: "ui-monospace" }}>{(fw.families_with_detectors || []).length}</span></div>
                <div style={S.row}><span>Registered handlers</span><span style={{ fontFamily: "ui-monospace" }}>{fw.total_handlers}</span></div>
                <div style={{ ...S.row, borderBottom: "none", color: "var(--text-secondary, #94a3b8)", fontSize: 12, paddingTop: 10 }}>
                  {fw.note}
                </div>
              </>
            ) : <div style={S.err}>Loading…</div>}
          </div>

          <div style={S.card} data-testid="card-diagnostics">
            <div style={S.cardH}>Recent Diagnostics</div>
            {diag ? (
              diag.diagnostics.length === 0
                ? <div style={{ color: "var(--text-secondary, #94a3b8)", fontSize: 13 }}>No diagnostics yet.</div>
                : diag.diagnostics.map((d) => (
                  <div key={d.filename} style={S.row}>
                    <span>{d.filename}</span>
                    <span style={{ fontFamily: "ui-monospace" }}>{d.bytes} B</span>
                  </div>
                ))
            ) : <div style={S.err}>Loading…</div>}
          </div>
        </div>

        <div style={S.section}>
          <div style={S.cardH}>Latest Evidence Inventory Report</div>
          {inv?.markdown ? (
            <pre style={S.pre} data-testid="evidence-inventory-body">{inv.markdown}</pre>
          ) : <div style={S.err}>Loading…</div>}
        </div>
      </div>
    </div>
  );
}
