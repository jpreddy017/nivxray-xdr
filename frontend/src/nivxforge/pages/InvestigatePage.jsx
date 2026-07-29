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
import { useCallback, useMemo, useRef, useState } from "react";
import Header from "../../components/Header";
import NivxForgeSubNav from "../components/NivxForgeSubNav";
import VerdictCard from "../../components/VerdictCard";
import OutputView from "../../components/OutputView";
import TIShieldPanel from "../../components/TIShieldPanel";
import { InvestigationBrainPanel } from "../../components/investigation/InvestigationBrainPanel";
import InputToolbar from "../../components/InputToolbar";
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
  file: { fontSize: 12, color: "var(--text-secondary, #94a3b8)", fontFamily: "ui-monospace" },
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
  chipStrip: { display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 },
  chip: {
    display: "inline-block", padding: "3px 8px", borderRadius: 10, fontSize: 11,
    border: "1px solid var(--border, #1e293b)", color: "var(--text, #e2e8f0)",
    fontFamily: "ui-monospace",
  },
  listCard: {
    background: "var(--panel, #0f172a)", border: "1px solid var(--border, #1e293b)",
    borderRadius: 10, padding: 16,
  },
  kv: { display: "grid", gridTemplateColumns: "minmax(180px, max-content) 1fr", rowGap: 4, columnGap: 16, fontSize: 12, fontFamily: "ui-monospace" },
  kvLabel: { color: "var(--text-secondary, #94a3b8)" },
  kvVal: { color: "var(--text, #e2e8f0)" },
};

function extractIocList(iocs) {
  if (!iocs) return [];
  if (Array.isArray(iocs)) return iocs;
  const flat = [];
  for (const [kind, arr] of Object.entries(iocs)) {
    if (Array.isArray(arr)) arr.forEach((v) => flat.push({ kind, value: v }));
  }
  return flat;
}

function MitrePanel({ mitre, mitre_v2 }) {
  const source = mitre_v2 || mitre;
  if (!source) return null;
  const techniques = Array.isArray(source?.techniques) ? source.techniques
                   : Array.isArray(source) ? source
                   : [];
  if (techniques.length === 0) return null;
  return (
    <div style={S.listCard} data-testid="result-mitre">
      <div style={S.cardH}>MITRE ATT&CK</div>
      <div style={S.chipStrip}>
        {techniques.slice(0, 40).map((t, i) => {
          const id = t?.id || t?.technique_id || t?.tid || (typeof t === "string" ? t : "");
          const name = t?.name || t?.technique || "";
          if (!id && !name) return null;
          return (
            <span key={i} style={S.chip} data-testid={`mitre-chip-${id || i}`}>
              <span style={{ color: "#7dd3fc" }}>{id}</span>{name ? ` · ${name}` : ""}
            </span>
          );
        })}
      </div>
    </div>
  );
}

function IocsPanel({ iocs }) {
  const list = useMemo(() => extractIocList(iocs), [iocs]);
  if (list.length === 0) return null;
  const grouped = list.reduce((acc, it) => {
    (acc[it.kind] = acc[it.kind] || []).push(it.value); return acc;
  }, {});
  return (
    <div style={S.listCard} data-testid="result-iocs">
      <div style={S.cardH}>Extracted IOCs ({list.length})</div>
      <div style={S.kv}>
        {Object.entries(grouped).map(([kind, values]) => (
          <>
            <div key={`k-${kind}`} style={S.kvLabel}>{kind}</div>
            <div key={`v-${kind}`} style={S.kvVal} data-testid={`ioc-group-${kind}`}>
              {values.slice(0, 30).join("  ·  ")}
            </div>
          </>
        ))}
      </div>
    </div>
  );
}

function BehaviorsPanel({ behaviors }) {
  if (!Array.isArray(behaviors) || behaviors.length === 0) return null;
  return (
    <div style={S.listCard} data-testid="result-behaviors">
      <div style={S.cardH}>Behaviors</div>
      <div style={S.chipStrip}>
        {behaviors.slice(0, 30).map((b, i) => (
          <span key={i} style={S.chip}>
            {b?.name || b?.behavior || b?.id || (typeof b === "string" ? b : JSON.stringify(b).slice(0, 60))}
          </span>
        ))}
      </div>
    </div>
  );
}

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

  const runDecode = useCallback(async () => {
    if (!canSubmit) return;
    setLoading(true); setErr(""); setResult(null); setMode("decode");
    try {
      const r = await api.post("/decode/smart", { input });
      setResult(r.data);
    } catch (e) {
      setErr(e?.friendlyMessage || e?.response?.data?.detail || String(e?.message || e));
    } finally { setLoading(false); }
  }, [input, canSubmit]);

  const runAuto = useCallback(async () => {
    if (!canSubmit) return;
    setLoading(true); setErr(""); setResult(null); setMode("auto");
    try {
      const r = await api.post("/v2/auto-investigate", {
        incident_text: input, focus: focus || null,
      });
      setResult(r.data);
    } catch (e) {
      setErr(e?.friendlyMessage || e?.response?.data?.detail || String(e?.message || e));
    } finally { setLoading(false); }
  }, [input, focus, canSubmit]);

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
  const decodeResult = mode === "decode" && result ? result : null;
  const autoResult   = mode === "auto"   && result ? result : null;
  const brainInvestigation = decodeResult?.investigation || autoResult?.investigation || autoResult;

  return (
    <div>
      <Header />
      <NivxForgeSubNav active="investigate" />
      <div style={S.page} data-testid="nivxforge-investigate-page">
        <div style={S.hero}>
          <div style={S.eyebrow}>NivXForge · Analyst Workspace</div>
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
              onClick={runDecode}
              disabled={!canSubmit}
              data-testid="investigate-decode-btn"
              title="Recursive decode + verdict + IOCs + MITRE (same as Workspace)"
            >Decode</button>
            <button
              type="button"
              style={{ ...S.btnGhost, ...(canSubmit ? {} : S.btnDisabled) }}
              onClick={runAuto}
              disabled={!canSubmit}
              data-testid="investigate-auto-btn"
              title="Deterministic auto-investigate (same as Workspace)"
            >Auto Investigate</button>
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
            One backend, two surfaces · calls <code>/api/decode/smart</code> and <code>/api/v2/auto-investigate</code> — same endpoints Workspace uses (ADR-0006 §2.1).
          </div>

          {loading ? <div style={S.loading} data-testid="investigate-loading">Analyzing…</div> : null}
          {err ? <div style={S.err} data-testid="investigate-error">{err}</div> : null}
        </div>

        {/* ─── Result columns ─────────────────────────────────────────── */}
        {decodeResult ? (
          <div data-testid="investigate-result-decode">
            {decodeResult.verdict_card ? (
              <div style={S.section}><VerdictCard verdict={decodeResult.verdict_card} testidPrefix="verdict-decode" /></div>
            ) : null}

            {decodeResult.output != null ? (
              <div style={S.section}>
                <OutputView input={input} output={decodeResult.output} />
              </div>
            ) : null}

            {decodeResult.ti_shield ? (
              <div style={S.section}><TIShieldPanel layers={decodeResult.ti_shield} /></div>
            ) : null}

            <div style={S.section}><IocsPanel iocs={decodeResult.iocs} /></div>
            <div style={S.section}><MitrePanel mitre={decodeResult.mitre} mitre_v2={decodeResult.mitre_v2} /></div>
            <div style={S.section}><BehaviorsPanel behaviors={decodeResult.behaviors} /></div>

            {brainInvestigation ? (
              <div style={S.section}>
                <InvestigationBrainPanel investigation={brainInvestigation} />
              </div>
            ) : null}
          </div>
        ) : null}

        {autoResult ? (
          <div data-testid="investigate-result-auto">
            {brainInvestigation ? (
              <div style={S.section}>
                <InvestigationBrainPanel investigation={brainInvestigation} />
              </div>
            ) : null}
            {autoResult.verdict_card ? (
              <div style={S.section}><VerdictCard verdict={autoResult.verdict_card} testidPrefix="verdict-auto" /></div>
            ) : null}
            <div style={S.section}><IocsPanel iocs={autoResult.iocs || autoResult.final_incident_summary?.iocs} /></div>
            <div style={S.section}>
              <MitrePanel
                mitre={autoResult.mitre || autoResult.final_incident_summary?.mitre}
                mitre_v2={autoResult.mitre_v2}
              />
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
