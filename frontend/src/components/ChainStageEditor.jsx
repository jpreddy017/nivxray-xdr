/**
 * ChainStageEditor — Multi-stage payload chain UX.
 *
 * Design (matches user's Feb-2026 spec):
 *   - Primary UX: "+ ADD STAGE" button appends a new stage below
 *   - Power-user shortcut: paste text with blank-line separators → auto-splits
 *   - Auto-switch to "chain view" layout when stages > 3
 *   - Aggregate = unified SOC verdict (family, IOCs, MITRE, LOLBAS, YARA, kill-chain)
 *   - Deterministic per-stage (no LLM); AI runs ONCE on aggregate
 *   - Per-stage output preserved for drill-down
 *   - Export: Markdown, JSON (STIX 2.1 = P1)
 */
import { useState, useMemo } from "react";
import { Plus, X, Play, Sparkles, Download, FileText, ChevronDown, ChevronRight, AlertTriangle } from "lucide-react";
import api, { apiStream } from "../lib/api";

const uid = () => Math.random().toString(36).slice(2, 9);

export default function ChainStageEditor({ seedInput, onSeedConsumed, initialStages }) {
  const [stages, setStages] = useState(() => {
    if (Array.isArray(initialStages) && initialStages.length > 0) {
      return initialStages.map((s) => ({ id: uid(), input: s.input || s.input_preview || "" }));
    }
    return [{ id: uid(), input: seedInput || "" }];
  });
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);       // {stage_count, stages, aggregate}
  const [narrative, setNarrative] = useState(null); // {narrative, verdict, family, kill_chain}
  const [narrating, setNarrating] = useState(false);
  const [narrateProgress, setNarrateProgress] = useState(null);
  const [drillOpen, setDrillOpen] = useState({});   // stage_index -> bool

  const chainMode = stages.length > 3;   // auto-switch to compact list view

  const addStage = () => setStages((s) => [...s, { id: uid(), input: "" }]);
  const removeStage = (id) => setStages((s) => (s.length > 1 ? s.filter((x) => x.id !== id) : s));
  const setStageInput = (id, value) => setStages((s) => s.map((x) => (x.id === id ? { ...x, input: value } : x)));

  // Power-user auto-split: paste blank-line separated → append each as own stage
  const handlePasteSplit = (id, e) => {
    const text = e.clipboardData?.getData("text") || "";
    if (!text.includes("\n\n")) return;                  // no blank line → single-stage paste
    e.preventDefault();
    const parts = text.split(/\n\s*\n+/).map((p) => p.trim()).filter(Boolean);
    if (parts.length <= 1) return;
    setStages((s) => {
      const idx = s.findIndex((x) => x.id === id);
      // Fill current stage with first part, append the rest
      const next = [...s];
      next[idx] = { ...next[idx], input: parts[0] };
      parts.slice(1).forEach((p) => next.push({ id: uid(), input: p }));
      return next;
    });
  };

  const runChain = async () => {
    setRunning(true);
    setResult(null); setNarrative(null);
    try {
      const payload = { stages: stages.filter((s) => s.input.trim()).map((s) => ({ input: s.input })) };
      if (!payload.stages.length) { setRunning(false); return; }
      const r = await api.post("/decode/chain", payload);
      setResult(r.data);
      if (seedInput && onSeedConsumed) onSeedConsumed();
    } catch (e) {
      setResult({ error: e?.response?.data?.detail || e.message });
    } finally {
      setRunning(false);
    }
  };

  const runNarrative = async () => {
    if (!result) return;
    setNarrating(true); setNarrative(null); setNarrateProgress({ stage: "starting", elapsed_ms: 0 });
    const stages_body = stages.filter((s) => s.input.trim()).map((s) => ({ input: s.input }));
    try {
      // Prefer SSE (streamed) — heartbeats prevent Cloudflare 524 on long LLM calls.
      await apiStream("/decode/chain/narrative/stream",
        { stages: stages_body, aggregate: result.aggregate },
        {
          onProgress: (p) => setNarrateProgress(p),
          onDone: (data) => { setNarrative(data); setNarrateProgress(null); },
          onError: (msg) => { setNarrative({ error: msg }); setNarrateProgress(null); },
        }
      );
    } catch (e) {
      // Fallback: non-streamed endpoint (also protected by 85s server-side timeout)
      try {
        const r = await api.post("/decode/chain/narrative",
          { stages: stages_body, aggregate: result.aggregate });
        setNarrative(r.data);
      } catch (e2) {
        setNarrative({ error: e2?.friendlyMessage || e2?.response?.data?.detail || e2.message });
      }
      setNarrateProgress(null);
    } finally {
      setNarrating(false);
    }
  };

  const doExport = async (format) => {
    if (!result) return;
    try {
      const r = await api.post("/decode/chain/export", {
        stages: result.stages, aggregate: result.aggregate, format,
      });
      const content = r.data.content || JSON.stringify(r.data, null, 2);
      const blob = new Blob([content], { type: format === "markdown" ? "text/markdown" : "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `nivxray-chain-${Date.now()}.${format === "markdown" ? "md" : "json"}`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch (e) { /* silent */ }
  };

  const agg = result?.aggregate;
  const familyLabel = agg?.family?.family;
  const familyConf = agg?.family?.confidence;
  const verdict = agg?.risk?.verdict;
  const score = agg?.risk?.score;
  const level = agg?.risk?.level;

  return (
    <div data-testid="chain-editor" className="nvx-card" style={{ marginTop: 12 }}>
      <div className="nvx-card-head" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div className="mono" style={{ fontSize: 11, letterSpacing: "0.22em", color: "var(--accent)" }}>
          ▸ CHAIN ANALYSIS {chainMode && <span style={{ color: "var(--text-mute)", fontSize: 9 }}>· COMPACT VIEW ({stages.length} STAGES)</span>}
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <button className="nvx-btn sm ghost" onClick={addStage} data-testid="btn-chain-add-stage" title="Append another stage. Or paste text with blank-line separators to auto-split.">
            <Plus size={11} /> ADD STAGE
          </button>
          <button className="nvx-btn primary sm" onClick={runChain} disabled={running} data-testid="btn-chain-run"
                  title="Decode every stage deterministically, then aggregate into a unified SOC verdict.">
            <Play size={11} /> {running ? "RUNNING…" : "RUN CHAIN"}
          </button>
        </div>
      </div>

      <div className="nvx-card-body" style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {stages.map((s, idx) => (
          <div key={s.id} data-testid={`chain-stage-${idx}`} style={{
            border: "1px solid var(--border)", borderRadius: 4, padding: 8,
            background: "rgba(0,0,0,0.15)",
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <span className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.20em" }}>
                STAGE {idx}
              </span>
              {stages.length > 1 && (
                <button className="nvx-btn sm ghost" onClick={() => removeStage(s.id)}
                        data-testid={`btn-chain-remove-${idx}`} title="Remove this stage">
                  <X size={11} />
                </button>
              )}
            </div>
            <textarea
              className="nvx-textarea"
              rows={chainMode ? 2 : 3}
              data-testid={`chain-input-${idx}`}
              placeholder={idx === 0
                ? "Paste stage 0 — or paste multiple payloads separated by BLANK LINES to auto-split into stages."
                : `Stage ${idx} payload…`}
              value={s.input}
              onChange={(e) => setStageInput(s.id, e.target.value)}
              onPaste={(e) => handlePasteSplit(s.id, e)}
              style={{ fontSize: 11, minHeight: chainMode ? 40 : 60 }}
            />
            {result?.stages?.[idx] && (
              <div style={{ marginTop: 6, fontSize: 10.5 }}>
                <div className="mono" style={{ color: "var(--text-mute)" }}>
                  engine=<span style={{ color: "var(--accent)" }}>{result.stages[idx].engine || "n/a"}</span>
                  {" · "}conf=<span style={{ color: result.stages[idx].confidence >= 60 ? "var(--ok)" : "var(--warn)" }}>{result.stages[idx].confidence}/100</span>
                  {result.stages[idx].reached_shellcode && <span style={{ color: "var(--high)" }}> · SHELLCODE</span>}
                  {result.stages[idx].corrupt_payload && <span style={{ color: "var(--high)" }}> · <AlertTriangle size={9} /> CORRUPT</span>}
                  <button
                    className="nvx-btn sm ghost"
                    style={{ marginLeft: 8, padding: "2px 6px" }}
                    onClick={() => setDrillOpen((o) => ({ ...o, [idx]: !o[idx] }))}
                    data-testid={`btn-chain-drill-${idx}`}
                  >
                    {drillOpen[idx] ? <ChevronDown size={10} /> : <ChevronRight size={10} />} DRILL
                  </button>
                </div>
                {drillOpen[idx] && (
                  <pre style={{
                    background: "rgba(0,0,0,0.3)", padding: 6, marginTop: 4,
                    maxHeight: 200, overflow: "auto", fontSize: 10, borderRadius: 3,
                  }}>{(result.stages[idx].output || "").slice(0, 4000)}</pre>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {result?.error && (
        <div className="nvx-card-body" style={{ color: "var(--high)", fontSize: 12 }}>
          Chain run error: {result.error}
        </div>
      )}

      {agg && (
        <div className="nvx-card-body" style={{ borderTop: "1px solid var(--border)", background: "rgba(0,0,0,0.20)" }}>
          <div className="mono" style={{ fontSize: 11, letterSpacing: "0.22em", color: "var(--accent)", marginBottom: 8 }}>
            ▸ AGGREGATE — UNIFIED SOC VERDICT
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 8, marginBottom: 10 }}>
            {familyLabel && (
              <div data-testid="agg-family">
                <div className="mono" style={{ fontSize: 9, letterSpacing: "0.18em", color: "var(--text-mute)" }}>MALWARE FAMILY</div>
                <div style={{ fontSize: 13, color: "var(--high)", fontWeight: 700 }}>{familyLabel}</div>
                <div style={{ fontSize: 10, color: "var(--text-mute)" }}>confidence {familyConf}%</div>
              </div>
            )}
            <div data-testid="agg-verdict">
              <div className="mono" style={{ fontSize: 9, letterSpacing: "0.18em", color: "var(--text-mute)" }}>VERDICT</div>
              <div style={{ fontSize: 13, color: level === "high" ? "var(--high)" : level === "medium" ? "var(--warn)" : "var(--ok)", fontWeight: 700 }}>
                {verdict} · {score}/100
              </div>
              <div style={{ fontSize: 10, color: "var(--text-mute)" }}>{result.stage_count} stages · chain-amplified</div>
            </div>
            <div data-testid="agg-iocs">
              <div className="mono" style={{ fontSize: 9, letterSpacing: "0.18em", color: "var(--text-mute)" }}>MERGED IOCs</div>
              <div style={{ fontSize: 11, color: "var(--text)" }}>
                {Object.entries(agg.iocs || {}).filter(([, v]) => v?.length).map(([k, v]) => (
                  <span key={k} style={{ marginRight: 8 }}>{k}: <span style={{ color: "var(--accent)" }}>{v.length}</span></span>
                ))}
              </div>
            </div>
            <div>
              <div className="mono" style={{ fontSize: 9, letterSpacing: "0.18em", color: "var(--text-mute)" }}>MITRE / LOLBAS / YARA</div>
              <div style={{ fontSize: 11, color: "var(--text)" }}>
                {(agg.mitre || []).length}T · {(agg.lolbas || []).length}L · {(agg.yara || []).length}Y
              </div>
            </div>
          </div>

          {/* Kill chain */}
          {(agg.kill_chain || []).length > 0 && (
            <div style={{ marginBottom: 10 }}>
              <div className="mono" style={{ fontSize: 9, letterSpacing: "0.18em", color: "var(--text-mute)", marginBottom: 4 }}>KILL CHAIN (MITRE ATT&CK ORDERING)</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {agg.kill_chain.map((k, i) => (
                  <span key={i} data-testid={`agg-kc-${k.id}`} style={{
                    fontSize: 10, padding: "3px 7px", borderRadius: 3,
                    background: "rgba(226,126,93,0.10)", border: "1px solid var(--warn)",
                    color: "var(--warn)",
                  }} title={`${k.technique} · first seen: Stage ${k.stage}`}>
                    {k.id} <span style={{ color: "var(--text-mute)" }}>· S{k.stage}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Merged IOC drilldown */}
          {Object.entries(agg.iocs || {}).filter(([, v]) => v?.length).map(([k, v]) => (
            <div key={k} style={{ marginBottom: 6, fontSize: 10.5 }}>
              <span className="mono" style={{ color: "var(--text-mute)", letterSpacing: "0.14em" }}>{k.toUpperCase()} ▸ </span>
              {v.slice(0, 20).map((x, i) => (
                <span key={i} style={{ color: "var(--accent)", marginRight: 8, fontFamily: "JetBrains Mono, monospace" }}>{x}</span>
              ))}
            </div>
          ))}

          {/* Action row: AI narrative + export */}
          <div style={{ display: "flex", gap: 6, marginTop: 12, flexWrap: "wrap" }}>
            <button className="nvx-btn primary sm" onClick={runNarrative} disabled={narrating}
                    data-testid="btn-chain-narrative"
                    title="ONE LLM call across the full aggregated chain — writes a Sophos-style analyst narrative. Streamed via SSE so it never triggers Cloudflare 524s on long runs.">
              <Sparkles size={11} /> {narrating
                ? (narrateProgress
                    ? `${narrateProgress.stage.toUpperCase()} · ${Math.round((narrateProgress.elapsed_ms || 0) / 1000)}s`
                    : "GENERATING…")
                : "AI NARRATIVE (whole chain)"}
            </button>
            <button className="nvx-btn sm" onClick={() => doExport("markdown")} data-testid="btn-chain-export-md">
              <FileText size={11} /> EXPORT .MD
            </button>
            <button className="nvx-btn sm" onClick={() => doExport("json")} data-testid="btn-chain-export-json">
              <Download size={11} /> EXPORT .JSON
            </button>
          </div>

          {/* AI narrative panel */}
          {narrative && (
            <div style={{
              marginTop: 10, padding: 10, background: "rgba(93,163,226,0.08)",
              border: "1px solid rgba(93,163,226,0.3)", borderRadius: 4, fontSize: 11.5,
              lineHeight: 1.5, color: "var(--text)",
            }} data-testid="chain-narrative-panel">
              <div className="mono" style={{ fontSize: 9, letterSpacing: "0.20em", color: "var(--accent)", marginBottom: 6 }}>
                AI ANALYST NARRATIVE (LLM · ONE CALL · WHOLE CHAIN)
              </div>
              {narrative.error && <div style={{ color: "var(--high)" }}>Error: {narrative.error}</div>}
              {narrative.narrative?.summary && <div>{narrative.narrative.summary}</div>}
              {narrative.narrative?.tactical_intent && (
                <div style={{ marginTop: 6 }}>
                  <strong>Tactical intent:</strong> {narrative.narrative.tactical_intent}
                </div>
              )}
              {narrative.verdict?.verdict && (
                <div style={{ marginTop: 6 }}>
                  <strong>Verdict:</strong> {narrative.verdict.verdict} — {narrative.verdict.reasoning || ""}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
