/**
 * NivXForge · Investigate — Phase 1 (ADR-0006) analyst-parity surface.
 *
 * Presentation-layer only. Consumes the SAME backend endpoints
 * Workspace uses:
 *   • POST /api/decode/smart              — decode + verdict + IOCs + MITRE
 *   • POST /api/v2/auto-investigate       — auto-investigate (sync)
 *   • POST /api/upload                    — file upload
 *
 * Reuses existing result-rendering components from /components/*:
 *   VerdictCard · OutputView · TIShieldPanel · InvestigationBrainPanel
 *
 * NO reasoning engine, hypothesis engine, correlation engine, verdict
 * logic, or backend behaviour is introduced by this file. See
 * /app/memory/adr/0006-nivxforge-first-class-analyst-platform.md §2.1.
 */
import { useCallback, useRef, useState } from "react";
import NivxForgeLayout from "../components/NivxForgeLayout";
import InputToolbar from "../../components/InputToolbar";
import InvestigationPipeline from "../../components/InvestigationPipeline";
import { InvestigationReport } from "../../pages/AutoInvestigatePage";
import { isLab2Enabled } from "../lab2/FeatureFlagResolver";
import Lab2InvestigateRenderer from "../lab2/Lab2InvestigateRenderer";
import Lab2ToggleButton from "../lab2/Lab2ToggleButton";
import "../design/tokens.css";
import api from "../../lib/api";
const S = {
  page: { padding: "24px 28px 72px", color: "var(--text)", minHeight: "100vh", background: "var(--bg)" },
  hero: { marginBottom: 20 },
  eyebrow: { fontSize: 11, letterSpacing: "0.24em", color: "var(--accent, #7dd3fc)", textTransform: "uppercase", fontWeight: 600 },
  h1: { fontSize: 30, margin: "6px 0 4px", fontWeight: 700 },
  sub: { color: "var(--text-secondary, #94a3b8)", fontSize: 13, maxWidth: 780 },
  inputCard: {
    background: "var(--panel, #0f172a)", border: "1px solid var(--border, #1e293b)",
    borderRadius: 10, padding: 16, marginBottom: 18,
  },
  cardH: { fontSize: 11, letterSpacing: "0.22em", color: "var(--text-secondary, #94a3b8)", marginBottom: 10, textTransform: "uppercase", fontWeight: 600 },
  taWrap: { position: "relative" },
  textarea: {
    width: "100%", minHeight: 160, resize: "vertical",
    background: "var(--bg, #020617)", color: "var(--text, #e2e8f0)",
    border: "1px solid var(--border, #1e293b)", borderRadius: 6, padding: 12,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 13,
    boxSizing: "border-box",
  },
  controls: { display: "flex", flexWrap: "wrap", gap: 10, alignItems: "center", marginTop: 12 },
  btn: {
    padding: "8px 14px", background: "var(--accent, #7dd3fc)", color: "#020617",
    border: "1px solid var(--accent, #7dd3fc)", borderRadius: 5,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    fontSize: 12, letterSpacing: "0.08em", fontWeight: 700,
    textTransform: "uppercase", cursor: "pointer",
  },
  btnGhost: {
    padding: "8px 14px", background: "transparent", color: "var(--text, #e2e8f0)",
    border: "1px solid var(--border, #1e293b)", borderRadius: 5,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    fontSize: 12, letterSpacing: "0.08em", fontWeight: 600,
    textTransform: "uppercase", cursor: "pointer",
  },
  btnDisabled: { opacity: 0.4, cursor: "not-allowed" },
  focusInput: {
    background: "var(--bg, #020617)", color: "var(--text, #e2e8f0)",
    border: "1px solid var(--border, #1e293b)", borderRadius: 5, padding: "8px 10px",
    fontFamily: "ui-monospace", fontSize: 12, minWidth: 240,
  },
  parityBanner: {
    marginTop: 10, padding: "8px 12px", background: "rgba(125,211,252,0.06)",
    border: "1px solid rgba(125,211,252,0.25)", borderRadius: 6,
    fontSize: 11, color: "var(--text-secondary, #94a3b8)",
    fontFamily: "ui-monospace",
  },
  section: { marginTop: 22 },
  err: { color: "#f87171", fontSize: 13, marginTop: 8, fontFamily: "ui-monospace" },
  loading: { color: "var(--text-secondary, #94a3b8)", fontSize: 13, marginTop: 8, fontFamily: "ui-monospace" },
};

/**
 * ADR-0022 §4 · InvestigationLoader + FeatureFlagResolver.
 *
 * The route (/nivxforge/investigate) owns the experience. This
 * top-level component chooses the renderer:
 *
 *   ?lab2=1  →  Lab2InvestigateRenderer  (Lab2Shell workspace)
 *   default  →  LegacyInvestigateRenderer (unchanged production UI)
 *
 * Renderers do NOT coexist. The legacy renderer receives NO Lab 2.0
 * imports; the Lab 2.0 renderer never mounts the legacy pipeline UI.
 * At cutover (ADR-0022 §12) this file collapses to just the Lab2
 * renderer.
 */
export default function InvestigatePage() {
  if (isLab2Enabled()) {
    return <Lab2InvestigateRenderer />;
  }
  return <LegacyInvestigateRenderer />;
}

function LegacyInvestigateRenderer() {
  const [input, setInput] = useState("");
  const [locked, setLocked] = useState(false);
  const [focus, setFocus] = useState("");
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState(null);        // "decode" | "auto"
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");
  const [whyOpen, setWhyOpen] = useState(false);
  const fileInputRef = useRef(null);

  const canSubmit = input.trim().length > 0 && !loading;

  // ADR-0014 · Phase 1 · Content-based routing (replaces line-count heuristic).
  //
  // A single-line paste of a Cisco Secure Endpoint / QRadar / Defender /
  // CrowdStrike / Sysmon JSON is still an incident — routing must classify by
  // STRUCTURE not by line count. See operator directive 2026-02-28:
  //   "Routing should classify content, not line count."
  const detectPipeline = useCallback((text) => {
    const raw = (text || "").trim();
    if (!raw) return "decode";

    // Structured-alert / telemetry / incident detection (order matters:
    // structural markers > keyword markers > multi-line fallback).
    const looksLikeJson = /^[\[{]/.test(raw) && /[\]}]$/.test(raw);
    if (looksLikeJson) {
      // Vendor JSON schemas: Cisco Secure Endpoint / XDR, CrowdStrike Falcon,
      // Microsoft Defender, QRadar, Splunk, Sentinel, SentinelOne, Sysmon
      const vendorSignals = /"(connector_guid|computer|detection|falcon|CrowdStrike|Defender|SecurityAlert|QRadar|SentinelOne|threat_name|SHA256|sha256|ExecutedMalware|amp\.cisco\.com|xdr\.us\.security\.cisco\.com|Sysmon)"/i;
      if (vendorSignals.test(raw)) return "auto";
      // Generic JSON with incident-shape fields
      if (/"(incident|alert|host|user|process|command_line|src_ip|dst_ip|hash)"/i.test(raw)) return "auto";
    }

    // Multi-line + incident-shaped keywords (legacy path preserved)
    const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
    const incidentSignals = /\b(incident|alert|detection|malware|SIEM|SOC|IOC|SHA256|MD5|host\s*=|user\s*=|process\s*=|src_ip|dst_ip|ExecutedMalware|Quarantine|Cisco Secure|CrowdStrike|Falcon|Defender|QRadar|Splunk|SentinelOne|Sysmon)\b/i;
    if (incidentSignals.test(raw)) return "auto";
    if (lines.length >= 3) return "auto";

    // Single-artifact fallback: PowerShell -EncodedCommand, base64 blobs,
    // command lines, decoded strings — the decoder pipeline handles these.
    return "decode";
  }, []);

  const runInvestigate = useCallback(async () => {
    if (!canSubmit) return;
    const pipeline = detectPipeline(input);
    setLoading(true); setErr(""); setResult(null); setMode(pipeline);
    try {
      const r = pipeline === "auto"
        ? await api.post("/v2/auto-investigate", { incident_text: input, focus: focus || null })
        : await api.post("/decode/smart", { input });
      setResult(r.data);
    } catch (e) {
      setErr(e?.friendlyMessage || e?.response?.data?.detail || String(e?.message || e));
    } finally { setLoading(false); }
  }, [input, focus, canSubmit, detectPipeline]);

  const onFile = useCallback(async (ev) => {
    const f = ev.target.files?.[0]; if (!f) return;
    setErr("");
    try {
      const fd = new FormData(); fd.append("file", f);
      const r = await api.post("/upload", fd, { headers: { "Content-Type": "multipart/form-data" } });
      // The Workspace /upload endpoint returns { text, ... } or { content, ... }
      const text = r?.data?.text ?? r?.data?.content ?? r?.data?.extracted ?? "";
      if (text) setInput(text);
      else setErr("Uploaded file returned no extractable text (backend contract).");
    } catch (e) {
      setErr(e?.friendlyMessage || e?.response?.data?.detail || String(e?.message || e));
    } finally { if (fileInputRef.current) fileInputRef.current.value = ""; }
  }, []);

  // ─── Result renderers ──────────────────────────────────────────────
  // ADR-0013 §2.1 · One shared 10-section pipeline for both decode/smart
  // and auto-investigate responses.

  return (
    <NivxForgeLayout>
      <div style={S.page} data-testid="nivxforge-investigate-page">
        <div style={S.hero}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16 }}>
            <div>
              <div style={S.eyebrow}>Lab · Analyst Workspace</div>
              <h1 style={S.h1}>Investigate</h1>
              <p style={S.sub}>
                Paste a command line, script, incident excerpt, or upload a file. The same backend that powers
                the Workspace analyses your artifact — expect equivalent decoded output, verdict, IOCs, and MITRE mapping.
              </p>
            </div>
            <Lab2ToggleButton />
          </div>
        </div>

        <div style={S.inputCard} data-testid="investigate-input-card">
          <div style={S.cardH}>Input</div>
          <div style={S.taWrap}>
            <textarea
              style={S.textarea}
              placeholder={"powershell.exe -w hidden -enc SQBFAFgA..."}
              value={input}
              readOnly={locked}
              onChange={(e) => setInput(e.target.value)}
              data-testid="investigate-input"
            />
            <InputToolbar
              scope="investigate-input"
              value={input}
              onClear={() => setInput("")}
              onToggleEdit={() => setLocked((l) => !l)}
              locked={locked}
            />
          </div>

          <div style={S.controls}>
            <button
              type="button"
              style={{ ...S.btn, ...(canSubmit ? {} : S.btnDisabled) }}
              onClick={runInvestigate}
              disabled={!canSubmit}
              data-testid="investigate-run-btn"
              title="One adaptive investigation · engine picks the pipeline (ADR-0009 §2.4)"
            >🔍 Investigate</button>
            <button
              type="button"
              style={{ ...S.btnGhost, ...(input || result || err ? {} : S.btnDisabled) }}
              onClick={() => { setInput(""); setResult(null); setErr(""); setMode(null); setFocus(""); }}
              disabled={!(input || result || err)}
              data-testid="investigate-clear-btn"
              title="Clear input, focus, results, and errors"
            >Clear</button>
            <input
              type="text"
              value={focus}
              onChange={(e) => setFocus(e.target.value)}
              placeholder="focus (optional) — e.g. host name / MITRE technique"
              style={S.focusInput}
              data-testid="investigate-focus"
            />
            <label style={{ ...S.btnGhost, cursor: "pointer" }} data-testid="investigate-upload-label">
              Upload…
              <input ref={fileInputRef} type="file" onChange={onFile} style={{ display: "none" }} data-testid="investigate-upload-input" />
            </label>
          </div>

          <div style={S.parityBanner} data-testid="investigate-parity-banner">
            One adaptive action · engine classifies input structure (JSON telemetry / incident-shaped / single artifact) and routes to <code>/api/v2/auto-investigate</code> or <code>/api/decode/smart</code>. Analyst-grade narrative comes from the backend when available (ADR-0014 §1.1.9 · Investigation Summary never depends on UI).
          </div>

          {loading ? <div style={S.loading} data-testid="investigate-loading">Analyzing…</div> : null}
          {err ? <div style={S.err} data-testid="investigate-error">{err}</div> : null}
        </div>

        {/* ─── ADR-0014 · Phase 0 · Prefer backend InvestigationReport,
             fall back to InvestigationPipeline only if the backend did
             NOT produce an investigation_report block (single-artifact
             /decode/smart path). The frontend never composes prose. ─── */}
        {result ? (
          <div style={S.section} data-testid={`investigate-result-${mode}`}>
            {/* ADR-0022 §15.2 · The Lab2Shell renderer is NEVER embedded inside
                the legacy renderer. If lab2 flag is on, the route resolver
                mounts Lab2InvestigateRenderer instead of this component. */}
            {/* ADR-0014 §1.1.14 · Normalisation transparency banner.
                Analysts see what the engine understood BEFORE it started
                investigating. Only rendered when the ingress gate fired. */}
            {result?.cio?.metadata?.normalised_via ? (
              <div
                data-testid="investigate-normalized-badge"
                style={{
                  background: "rgba(16, 185, 129, 0.08)",
                  border: "1px solid rgba(16, 185, 129, 0.4)",
                  borderRadius: 6,
                  padding: "10px 14px",
                  marginBottom: 14,
                  fontSize: 12,
                  color: "#a7f3d0",
                  fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
                  lineHeight: 1.7,
                }}
              >
                <span style={{ color: "#34d399", fontWeight: 600 }}>▸ NORMALISED</span>
                {"  ·  "}
                <span style={{ color: "#e2e8f0" }}>
                  Input Type: {String(result.cio.metadata.normalised_via).replace("normalizers.py:", "")}
                </span>
                {"  ·  "}
                <span style={{ color: "#e2e8f0" }}>
                  Normalised By: {String(result.cio.metadata.normalised_via)}
                </span>
                {"  ·  "}
                <span style={{ color: "#e2e8f0" }}>
                  Canonical Event: ✓
                </span>
                {"  ·  "}
                <span style={{ color: "#e2e8f0" }}>
                  Graph Nodes: {result?.cio?.metadata?.node_count ?? 0}
                </span>
                {result?.cio?.verdict?.not_counted?.length ? (
                  <>
                    {"  ·  "}
                    <span style={{ color: "#e2e8f0" }}>
                      Vendor Metadata Stripped: {result.cio.verdict.not_counted.length}
                    </span>
                  </>
                ) : null}
              </div>
            ) : null}

            {/* ADR-0014 Slice-C · "Why this verdict?" explainability panel.
                Uses the verdict engine's `contributors` + `not_counted` — no
                frontend reasoning; pure presentation of backend evidence. */}
            {result?.cio?.verdict ? (
              <div
                data-testid="investigate-why-verdict-block"
                style={{
                  background: "rgba(15, 23, 42, 0.6)",
                  border: "1px solid var(--border, #1e293b)",
                  borderRadius: 6,
                  padding: "10px 14px",
                  marginBottom: 14,
                  fontSize: 13,
                  color: "#e2e8f0",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <span style={{ letterSpacing: "0.14em", fontSize: 11, color: "#94a3b8" }}>VERDICT</span>
                  <span style={{ fontWeight: 700, color: "#f8fafc" }}>{result.cio.verdict.label}</span>
                  <span style={{ color: "#94a3b8" }}>·</span>
                  <span style={{ color: "#e2e8f0" }}>confidence {result.cio.verdict.confidence_pct}%</span>
                  <button
                    data-testid="investigate-why-toggle"
                    onClick={() => setWhyOpen((v) => !v)}
                    style={{
                      marginLeft: "auto",
                      background: "transparent",
                      color: "#7dd3fc",
                      border: "1px solid rgba(125, 211, 252, 0.4)",
                      borderRadius: 4,
                      padding: "4px 10px",
                      cursor: "pointer",
                      fontSize: 12,
                    }}
                  >
                    {whyOpen ? "Hide reasoning" : "Why this verdict?"}
                  </button>
                </div>
                {whyOpen ? (
                  <div data-testid="investigate-why-panel" style={{ marginTop: 12, fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 12 }}>
                    <div style={{ color: "#94a3b8", marginBottom: 8 }}>{result.cio.verdict.reason}</div>
                    {result.cio.verdict.contributors?.length ? (
                      <div style={{ marginBottom: 8 }}>
                        <div style={{ color: "#a7f3d0", marginBottom: 4 }}>Contributing evidence</div>
                        {result.cio.verdict.contributors.slice(0, 10).map((c) => (
                          <div key={c.node_id} data-testid={`why-contributor-${c.node_id}`} style={{ color: "#e2e8f0" }}>
                            <span style={{ color: "#34d399", fontWeight: 600 }}>{" + "}</span>
                            {c.label} <span style={{ color: "#94a3b8" }}>(kind={c.kind}, weight={c.weight}, conf={Math.round((c.confidence || 0) * 100)}%)</span>
                          </div>
                        ))}
                      </div>
                    ) : null}
                    {result.cio.verdict.not_counted?.length ? (
                      <div>
                        <div style={{ color: "#fca5a5", marginBottom: 4 }}>Ignored (weight 0)</div>
                        {result.cio.verdict.not_counted.slice(0, 10).map((c) => (
                          <div key={c.node_id} data-testid={`why-not-counted-${c.node_id}`} style={{ color: "#e2e8f0" }}>
                            <span style={{ color: "#f87171", fontWeight: 600 }}>{" − "}</span>
                            {c.label} <span style={{ color: "#94a3b8" }}>({c.category || "unknown"})</span>
                          </div>
                        ))}
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </div>
            ) : null}
            {result.investigation_report && !result.investigation_report.empty ? (
              <InvestigationReport
                report={result.investigation_report}
                incident={input}
                pipeline={result}
              />
            ) : (
              <InvestigationPipeline result={result} />
            )}
          </div>
        ) : null}
      </div>
    </NivxForgeLayout>
  );
}
