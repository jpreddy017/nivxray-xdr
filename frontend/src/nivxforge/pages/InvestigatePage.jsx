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

export default function InvestigatePage() {
  const [input, setInput] = useState("");
  const [locked, setLocked] = useState(false);
  const [focus, setFocus] = useState("");
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState(null);        // "decode" | "auto"
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");
  const fileInputRef = useRef(null);

  const canSubmit = input.trim().length > 0 && !loading;

  // ADR-0009 §2.4 · One adaptive action.
  // The engine decides which pipeline to run. Light heuristic:
  //   multi-line + incident-shaped keywords → /api/v2/auto-investigate
  //   otherwise                              → /api/decode/smart
  // Both endpoints now return the additive `investigation` (CIM) field.
  const detectPipeline = useCallback((text) => {
    const raw = text || "";
    const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
    if (lines.length < 3) return "decode";
    const incidentSignals = /\b(incident|alert|detection|malware|SIEM|SOC|IOC|SHA256|MD5|host\s*=|user\s*=)\b/i;
    return incidentSignals.test(raw) ? "auto" : "decode";
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
          <div style={S.eyebrow}>Lab · Analyst Workspace</div>
          <h1 style={S.h1}>Investigate</h1>
          <p style={S.sub}>
            Paste a command line, script, incident excerpt, or upload a file. The same backend that powers
            the Workspace analyses your artifact — expect equivalent decoded output, verdict, IOCs, and MITRE mapping.
          </p>
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
            One adaptive action · engine chooses <code>/api/decode/smart</code> or <code>/api/v2/auto-investigate</code> based on input shape (ADR-0009 §2.4). Results render through the shared Investigation Pipeline (ADR-0013).
          </div>

          {loading ? <div style={S.loading} data-testid="investigate-loading">Analyzing…</div> : null}
          {err ? <div style={S.err} data-testid="investigate-error">{err}</div> : null}
        </div>

        {/* ─── ADR-0013 · Shared 10-section Investigation Pipeline ─── */}
        {result ? (
          <div style={S.section} data-testid={`investigate-result-${mode}`}>
            <InvestigationPipeline result={result} />
          </div>
        ) : null}
      </div>
    </NivxForgeLayout>
  );
}
