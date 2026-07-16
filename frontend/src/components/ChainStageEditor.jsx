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
import { Plus, X, Play, Sparkles, Download, FileText, ChevronDown, ChevronRight, AlertTriangle, Scissors, RefreshCw, Circle } from "lucide-react";
import api, { apiStream } from "../lib/api";
import { splitCommandLines } from "../lib/commandSplitter";
import InputToolbar from "./InputToolbar";

const uid = () => Math.random().toString(36).slice(2, 9);

// ─── Chain-break classifier ─────────────────────────────────────────
// Given a per-stage result, decide whether the stage broke and how.
// Returns null (healthy) or { kind, severity, message }.
//
// Cases (Feb-2026 spec):
//   (a) DECODE_FAILED   — engine null OR output missing/empty AND no chain applied
//   (b) EMPTY_OUTPUT    — decoder ran but produced 0 bytes of output
//   (e) LOW_CONFIDENCE  — confidence < 40 (still ran, but noisy)
//   ERROR              — server-side exception on the stage
function classifyStageBreak(stageResult) {
  if (!stageResult) return null;
  if (stageResult.error) {
    return {
      kind: "ERROR",
      severity: "high",
      message: `Stage errored: ${stageResult.error}`.slice(0, 200),
    };
  }
  const conf = Number.isFinite(stageResult.confidence) ? stageResult.confidence : null;
  const outLen = stageResult.output_length ?? (stageResult.output || "").length;
  const engine = stageResult.engine;
  const chainOps = Array.isArray(stageResult.chain) ? stageResult.chain.length : 0;
  const inputLen = stageResult.input_length ?? (stageResult.input_preview || "").length;

  // (a) Decode failed — engine ran but no decoder matched, and no chain applied.
  if ((conf === 0 || conf === null) && chainOps === 0 && inputLen > 0) {
    return {
      kind: "DECODE_FAILED",
      severity: "high",
      message: "No known decoder matched · plain-text passthrough only",
    };
  }
  // (b) Empty output — decoder claims success but produced 0 bytes.
  if (outLen === 0 && inputLen > 0 && (conf ?? 0) > 0) {
    return {
      kind: "EMPTY_OUTPUT",
      severity: "med",
      message: "Decoder ran but yielded 0 bytes · input may be plaintext or malformed",
    };
  }
  // (e) Low confidence — below the 40 % floor. Includes stages where the
  // decoder chose a "passthrough" (no chain ops) but still assigned a
  // sub-40 confidence — analyst still needs a visible warning.
  if (conf !== null && conf < 40 && inputLen > 0) {
    return {
      kind: "LOW_CONFIDENCE",
      severity: "low",
      message: `Confidence ${conf}/100 · below 40 % floor · verify output manually`,
    };
  }
  return null;
}

export default function ChainStageEditor({ seedInput, onSeedConsumed, initialStages, initialResult, onChainComplete }) {
  const [stages, setStages] = useState(() => {
    if (Array.isArray(initialStages) && initialStages.length > 0) {
      return initialStages.map((s) => ({ id: uid(), input: s.input || s.input_preview || "" }));
    }
    return [{ id: uid(), input: seedInput || "" }];
  });
  const [running, setRunning] = useState(false);
  // Feb-2026 fix: seed with the parent-supplied chain result so RE-RUN
  // buttons and break-ribbons render immediately after auto-investigate,
  // without requiring the analyst to click RUN CHAIN a second time.
  const [result, setResult] = useState(initialResult || null);
  const [narrative, setNarrative] = useState(null); // {narrative, verdict, family, kill_chain}
  const [narrating, setNarrating] = useState(false);
  const [narrateProgress, setNarrateProgress] = useState(null);
  const [drillOpen, setDrillOpen] = useState({});   // stage_index -> bool
  // Feb-2026 enhancement: per-stage input lock (edit-toggle from InputToolbar).
  const [stageLocks, setStageLocks] = useState({});
  // Feb-2026 enhancement: which stage index is currently re-running (for spinner).
  const [rerunning, setRerunning] = useState(null);

  const chainMode = stages.length > 3;   // auto-switch to compact list view

  const addStage = () => setStages((s) => [...s, { id: uid(), input: "" }]);
  const removeStage = (id) => setStages((s) => (s.length > 1 ? s.filter((x) => x.id !== id) : s));
  const setStageInput = (id, value) => setStages((s) => s.map((x) => (x.id === id ? { ...x, input: value } : x)));

  // Power-user auto-split: paste blank-line separated OR multiple command-lookalike lines → append each as own stage
  const handlePasteSplit = (id, e) => {
    const text = e.clipboardData?.getData("text") || "";
    const parts = splitCommandLines(text);
    if (!parts || parts.length <= 1) return;             // no split → single-stage paste
    e.preventDefault();
    setStages((s) => {
      const idx = s.findIndex((x) => x.id === id);
      // Fill current stage with first part, append the rest
      const next = [...s];
      next[idx] = { ...next[idx], input: parts[0] };
      parts.slice(1).forEach((p) => next.push({ id: uid(), input: p }));
      return next;
    });
  };

  // Manual splitter — reads the current textarea content and splits it
  // in place. Analyst safety net when the paste-heuristic didn't fire.
  const splitStageInPlace = (id) => {
    setStages((s) => {
      const idx = s.findIndex((x) => x.id === id);
      const cur = s[idx];
      if (!cur) return s;
      const parts = splitCommandLines(cur.input);
      if (!parts || parts.length <= 1) return s;
      const next = [...s];
      next[idx] = { ...next[idx], input: parts[0] };
      const rest = parts.slice(1).map((p) => ({ id: uid(), input: p }));
      next.splice(idx + 1, 0, ...rest);
      return next;
    });
  };

  const canSplit = (input) => {
    const parts = splitCommandLines(input || "");
    return parts && parts.length > 1 ? parts.length : 0;
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
      // Feb-2026 UX fix — propagate the chain SOC report_text (or a
      // concatenated per-stage output fallback) up to the parent so the
      // top OUTPUT panel isn't left empty when the chain was driven
      // directly from the Chain Editor (no top-level INPUT paste).
      if (onChainComplete) {
        try {
          const data = r.data || {};
          const stagesArr = data.stages || [];
          const rpt = data.report_text
            || stagesArr
                 .map((s, i) => {
                   const head = `───── STAGE ${i} · engine=${s.engine || "?"} · conf=${s.confidence ?? 0}/100 ─────`;
                   return `${head}\n${s.output || "(no output)"}`;
                 })
                 .join("\n\n");
          onChainComplete(rpt, data);
        } catch { /* never block the run on a callback error */ }
      }
    } catch (e) {
      setResult({ error: e?.response?.data?.detail || e.message });
    } finally {
      setRunning(false);
    }
  };

  // Re-run the chain STARTING FROM a specific stage index. Prior stages'
  // decoded outputs are preserved from the last full-chain result; the
  // stage at `fromIdx` is fed its current textarea value; everything
  // after is re-decoded. This is the analyst's core loop when tweaking
  // one stage's parameters (e.g. adding an XOR key, editing a b64 blob)
  // without paying to re-decode the whole chain.
  const runFromStage = async (fromIdx) => {
    setRerunning(fromIdx);
    try {
      const trimmed = stages.filter((s) => s.input.trim());
      const tail = trimmed.slice(fromIdx).map((s) => ({ input: s.input }));
      if (!tail.length) return;
      const r = await api.post("/decode/chain", { stages: tail });
      const partial = r.data || {};
      // Splice new stage results back into the existing result state
      // (preserve stages 0..fromIdx-1 verbatim, then append re-computed
      // tail with stage_index re-based to the full chain index).
      setResult((prev) => {
        const prevStages = (prev?.stages || []).slice(0, fromIdx);
        const newTail = (partial.stages || []).map((st, i) => ({
          ...st, stage_index: fromIdx + i,
        }));
        return {
          ...(prev || {}),
          stage_count: prevStages.length + newTail.length,
          stages: [...prevStages, ...newTail],
          // Aggregate is re-emitted by the endpoint for the tail only,
          // so we merge conservatively — full-chain re-aggregation would
          // require a second server call. For most analyst workflows the
          // tail aggregate is what they need to inspect.
          aggregate: partial.aggregate || prev?.aggregate,
        };
      });
    } catch (e) {
      setResult((prev) => ({ ...(prev || {}), error: `Re-run from stage ${fromIdx} failed: ${e?.response?.data?.detail || e.message}` }));
    } finally {
      setRerunning(null);
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
        {stages.map((s, idx) => {
          const stageRes = result?.stages?.[idx];
          const breakInfo = classifyStageBreak(stageRes);
          const locked = !!stageLocks[s.id];
          return (
          <div key={s.id} data-testid={`chain-stage-${idx}`} style={{
            border: breakInfo
              ? `1px solid ${breakInfo.severity === "high" ? "var(--high)" : breakInfo.severity === "med" ? "var(--warn)" : "var(--text-mute)"}`
              : "1px solid var(--border)",
            borderRadius: 4, padding: 8,
            background: "rgba(0,0,0,0.15)",
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <span className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.20em" }}>
                STAGE {idx}
              </span>
              <div style={{ display: "flex", gap: 4 }}>
                {stageRes && idx < stages.length && (
                  <button
                    className="nvx-btn sm ghost"
                    onClick={() => runFromStage(idx)}
                    disabled={running || rerunning !== null}
                    data-testid={`btn-chain-rerun-from-${idx}`}
                    title={`Re-run decoding from stage ${idx} onwards using this stage's current textarea value. Previous stages are preserved.`}
                    style={{ padding: "2px 8px", fontSize: 10 }}
                  >
                    <RefreshCw size={10} className={rerunning === idx ? "spin" : ""} />
                    {" "}RE-RUN
                  </button>
                )}
                {canSplit(s.input) > 1 && (
                  <button
                    className="nvx-btn sm"
                    style={{ background: "rgba(126,227,201,0.10)",
                             border: "1px solid #7ee3c9", color: "#7ee3c9",
                             padding: "2px 8px", fontSize: 10 }}
                    onClick={() => splitStageInPlace(s.id)}
                    data-testid={`btn-chain-split-${idx}`}
                    title={`Split this stage into ${canSplit(s.input)} separate stages — one per command line.`}
                  >
                    <Scissors size={10} /> SPLIT ×{canSplit(s.input)}
                  </button>
                )}
                {stages.length > 1 && (
                  <button className="nvx-btn sm ghost" onClick={() => removeStage(s.id)}
                          data-testid={`btn-chain-remove-${idx}`} title="Remove this stage">
                    <X size={11} />
                  </button>
                )}
              </div>
            </div>
            <div style={{ position: "relative" }}>
              <textarea
                className="nvx-textarea"
                rows={chainMode ? 2 : 3}
                data-testid={`chain-input-${idx}`}
                placeholder={idx === 0
                  ? "Paste stage 0 — or paste multiple command lines (blank lines OR just one command per line) to auto-split into stages."
                  : `Stage ${idx} payload…`}
                value={s.input}
                readOnly={locked}
                onChange={(e) => setStageInput(s.id, e.target.value)}
                onPaste={(e) => handlePasteSplit(s.id, e)}
                style={{ fontSize: 11, minHeight: chainMode ? 40 : 60, paddingRight: 90 }}
              />
              <InputToolbar
                scope={`chain-input-${idx}`}
                value={s.input}
                locked={locked}
                onToggleEdit={() => setStageLocks((l) => ({ ...l, [s.id]: !l[s.id] }))}
                onClear={() => setStageInput(s.id, "")}
              />
            </div>
            {breakInfo && (
              <div
                data-testid={`chain-break-${idx}`}
                data-break-kind={breakInfo.kind}
                style={{
                  marginTop: 6,
                  padding: "5px 8px",
                  fontSize: 10.5,
                  fontFamily: "JetBrains Mono",
                  borderLeft: `3px solid ${breakInfo.severity === "high" ? "var(--high)" : breakInfo.severity === "med" ? "var(--warn)" : "var(--text-mute)"}`,
                  background: breakInfo.severity === "high"
                    ? "rgba(255,90,90,0.08)"
                    : breakInfo.severity === "med"
                    ? "rgba(255,180,60,0.08)"
                    : "rgba(200,200,200,0.05)",
                  color: breakInfo.severity === "high" ? "var(--high)" : "var(--warn)",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <AlertTriangle size={11} />
                <span style={{ letterSpacing: "0.14em", fontWeight: 700 }}>{breakInfo.kind.replace(/_/g, " ")}</span>
                <span style={{ color: "var(--text-dim)" }}>· {breakInfo.message}</span>
              </div>
            )}
            {stageRes && (
              <div style={{ marginTop: 6, fontSize: 10.5 }}>
                <div className="mono" style={{ color: "var(--text-mute)" }}>
                  engine=<span style={{ color: "var(--accent)" }}>{stageRes.engine || "n/a"}</span>
                  {" · "}conf=<span style={{ color: stageRes.confidence >= 60 ? "var(--ok)" : "var(--warn)" }}>{stageRes.confidence}/100</span>
                  {stageRes.reached_shellcode && <span style={{ color: "var(--high)" }}> · SHELLCODE</span>}
                  {stageRes.corrupt_payload && <span style={{ color: "var(--high)" }}> · <AlertTriangle size={9} /> CORRUPT</span>}
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
                  }}>{(stageRes.output || "").slice(0, 4000)}</pre>
                )}
              </div>
            )}
          </div>
        );})}
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
