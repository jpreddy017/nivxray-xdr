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
import NivxForgeLayout from "../components/NivxForgeLayout";
import VerdictCard from "../../components/VerdictCard";
import OutputView from "../../components/OutputView";
import TIShieldPanel from "../../components/TIShieldPanel";
import { InvestigationBrainPanel } from "../../components/investigation/InvestigationBrainPanel";
import InputToolbar from "../../components/InputToolbar";
import CIMInvestigation from "../cim/CIMInvestigation";
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
  const decodeResult = mode === "decode" && result ? result : null;
  const autoResult   = mode === "auto"   && result ? result : null;
  const brainInvestigation = decodeResult?.investigation;
  // ADR-0009 · Additive CIM (present on both endpoints).
  const cimInvestigation = (decodeResult || autoResult)?.investigation || null;

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
            One adaptive action · engine chooses <code>/api/decode/smart</code> or <code>/api/v2/auto-investigate</code> based on input shape (ADR-0009 §2.4). Every result is a Canonical Investigation Model (ADR-0009).
          </div>

          {loading ? <div style={S.loading} data-testid="investigate-loading">Analyzing…</div> : null}
          {err ? <div style={S.err} data-testid="investigate-error">{err}</div> : null}
        </div>

        {/* ─── ADR-0009 · Canonical Investigation Model · rendered first ─── */}
        {cimInvestigation ? (
          <CIMInvestigation investigation={cimInvestigation} />
        ) : null}

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
            {/* Executive Card — the canonical auto-investigate verdict surface */}
            {autoResult.executive_card ? (() => {
              const ec = autoResult.executive_card;
              return (
                <div style={{ ...S.listCard, marginTop: 22 }} data-testid="auto-executive-card">
                  <div style={S.cardH}>Executive Verdict</div>
                  <div style={{ fontSize: 20, fontWeight: 700, color: /malicious/i.test(ec.verdict_pretty || ec.verdict || "") ? "#f87171" : "#facc15" }}>
                    {ec.verdict_pretty || ec.verdict} · confidence {ec.confidence ?? "—"}%
                  </div>
                  {ec.what_happened?.primary_finding ? (
                    <div style={{ marginTop: 10, fontSize: 13, color: "var(--text, #e2e8f0)" }}>
                      <strong>Primary finding:</strong> {ec.what_happened.primary_finding}
                    </div>
                  ) : null}
                  {ec.what_happened?.recovered_behavior ? (
                    <div style={{ marginTop: 6, fontSize: 13, color: "var(--text, #e2e8f0)" }}>
                      <strong>Recovered behavior:</strong> {ec.what_happened.recovered_behavior}
                    </div>
                  ) : null}
                  {Array.isArray(ec.because) && ec.because.length ? (
                    <div style={{ marginTop: 10 }}>
                      <div style={S.cardH}>Because</div>
                      <ul style={{ paddingLeft: 20, fontSize: 13, color: "var(--text, #e2e8f0)", lineHeight: 1.7 }}>
                        {ec.because.map((b, i) => <li key={i}>{b}</li>)}
                      </ul>
                    </div>
                  ) : null}
                  {Array.isArray(ec.evidence?.positive) && ec.evidence.positive.length ? (
                    <div style={{ marginTop: 10 }}>
                      <div style={S.cardH}>Evidence</div>
                      <ul style={{ paddingLeft: 20, fontSize: 12, color: "var(--text-secondary, #94a3b8)", lineHeight: 1.7 }}>
                        {ec.evidence.positive.slice(0, 12).map((e, i) => <li key={i} style={{ color: "#4ade80" }}>{e}</li>)}
                      </ul>
                    </div>
                  ) : null}
                </div>
              );
            })() : null}

            {/* Final Incident Summary — MITRE + IOCs + classification */}
            {autoResult.final_incident_summary ? (() => {
              const fis = autoResult.final_incident_summary;
              return (
                <>
                  <div style={{ ...S.listCard, marginTop: 22 }} data-testid="auto-classification">
                    <div style={S.cardH}>Classification</div>
                    <div style={{ fontSize: 15, color: "var(--text, #e2e8f0)" }}>
                      {fis.classification || "—"} · severity <strong>{fis.severity || "—"}</strong> · verdict <strong>{fis.verdict || "—"}</strong>
                    </div>
                    {Array.isArray(fis.executive_summary) && fis.executive_summary.length ? (
                      <div style={{ marginTop: 10, fontSize: 13, color: "var(--text-secondary, #94a3b8)", lineHeight: 1.6 }}>
                        {fis.executive_summary.map((p, i) => <p key={i}>{p}</p>)}
                      </div>
                    ) : null}
                  </div>

                  {Array.isArray(fis.mitre_attack) && fis.mitre_attack.length ? (
                    <div style={{ ...S.listCard, marginTop: 18 }} data-testid="auto-mitre">
                      <div style={S.cardH}>MITRE ATT&CK ({fis.mitre_attack.length})</div>
                      <div style={S.chipStrip}>
                        {fis.mitre_attack.map((t, i) => (
                          <span key={i} style={S.chip}>
                            <span style={{ color: "#7dd3fc" }}>{t.id}</span> · {t.technique}
                            {t.tactic ? <span style={{ opacity: 0.7 }}> · {t.tactic}</span> : null}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  <div style={{ marginTop: 18 }}><IocsPanel iocs={fis.iocs} /></div>
                </>
              );
            })() : null}

            {/* Investigation Narrative */}
            {autoResult.investigation_narrative?.narrative ? (
              <div style={{ ...S.listCard, marginTop: 22 }} data-testid="auto-narrative">
                <div style={S.cardH}>Investigation Narrative</div>
                <div style={{ fontSize: 13, color: "var(--text, #e2e8f0)", lineHeight: 1.7, whiteSpace: "pre-wrap" }}>
                  {autoResult.investigation_narrative.narrative}
                </div>
              </div>
            ) : null}

            {/* Decode Pipeline chains — show recovered/decoded commands */}
            {Array.isArray(autoResult.decode_pipeline?.chains) && autoResult.decode_pipeline.chains.length ? (
              <div style={{ ...S.listCard, marginTop: 18 }} data-testid="auto-decode-chains">
                <div style={S.cardH}>Decode Chains ({autoResult.decode_pipeline.chains.length})</div>
                {autoResult.decode_pipeline.chains.map((ch, i) => (
                  <div key={i} style={{ marginTop: i ? 12 : 0, fontFamily: "ui-monospace", fontSize: 12 }}>
                    <div style={{ color: "var(--text-secondary, #94a3b8)" }}>#{ch.index} · {ch.binary} · {ch.layers?.length || 0} layers</div>
                    <div style={{ marginTop: 4, color: "var(--text, #e2e8f0)", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                      {(ch.command_line || "").slice(0, 220)}{(ch.command_line || "").length > 220 ? "…" : ""}
                    </div>
                  </div>
                ))}
              </div>
            ) : null}

            {/* MDR Investigation escalation & recommendations */}
            {autoResult.mdr_investigation ? (() => {
              const m = autoResult.mdr_investigation;
              return (
                <div style={{ ...S.listCard, marginTop: 18 }} data-testid="auto-mdr">
                  <div style={S.cardH}>MDR Escalation</div>
                  {m.escalation ? (
                    <div style={{ fontSize: 13, color: "var(--text, #e2e8f0)" }}>
                      Decision: <strong>{m.escalation.decision}</strong> · confidence {m.escalation.confidence}% — {m.escalation.reason}
                    </div>
                  ) : null}
                  {Array.isArray(m.recommendations) && m.recommendations.length ? (
                    <div style={{ marginTop: 10 }}>
                      <div style={S.cardH}>Recommendations</div>
                      <ul style={{ paddingLeft: 20, fontSize: 12, color: "var(--text-secondary, #94a3b8)", lineHeight: 1.7 }}>
                        {m.recommendations.slice(0, 8).map((r, i) => (
                          <li key={i}>[{r.severity}] <strong>{r.title}</strong> — {r.why}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>
              );
            })() : null}
          </div>
        ) : null}
      </div>
    </NivxForgeLayout>
  );
}
