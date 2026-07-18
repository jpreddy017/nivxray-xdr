import { useEffect, useState, useRef, useMemo } from "react";
import Header from "@/components/Header";
import OperationsPanel from "@/components/OperationsPanel";
import RecipePanel from "@/components/RecipePanel";
import ThreatAnalysis from "@/components/ThreatAnalysis";
import ReportMenu from "@/components/ReportMenu";
import AttackGraph from "@/components/AttackGraph";
import AttackPathClean from "@/components/AttackPathClean";
import FinalSummary from "@/components/FinalSummary";
import ShellcodeView from "@/components/ShellcodeView";
import OutputView from "@/components/OutputView";
import { runClientRecipe } from "@/lib/clientOps";
import { magicLite } from "@/lib/magicLite";
import { detectShellcode } from "@/lib/shellcodeDetect";
import { buildFallbackGraph } from "@/lib/fallbackGraph";
import GuidanceBanner, { getGuidanceGlowStyle } from "@/components/GuidanceBanner";
import SocVerdictPanel from "@/components/SocVerdictPanel";
import VerdictCard from "@/components/VerdictCard";
import DecodingTracePanel from "@/components/DecodingTracePanel";
import HistoryDrawer from "@/components/HistoryDrawer";
import ProcessTreeView from "@/components/ProcessTreeView";
import BoostBadge from "@/components/BoostBadge";
import ChainStageEditor from "@/components/ChainStageEditor";
import ChainReplayView from "@/components/ChainReplayView";
import CandidateExplorer from "@/components/CandidateExplorer";
import BadDecodeModal from "@/components/BadDecodeModal";
import EscalationLadder from "@/components/EscalationLadder";
import TIShieldPanel from "@/components/TIShieldPanel";
import MoEPanel from "@/components/MoEPanel";
import InvestigationTimeline from "@/components/InvestigationTimeline";
import api from "@/lib/api";
import { streamAnalyze } from "@/lib/sse";
import { splitCommandLines, isMultiCommandInput } from "@/lib/commandSplitter";
import InputToolbar from "@/components/InputToolbar";
import CorrectionRefineModal from "@/components/CorrectionRefineModal";
import {
  Play, Zap, Wand2, Wrench, Share2, Download, Upload, Trash2, Copy, Sparkles, X,
} from "lucide-react";

export default function WorkspacePage() {
  const [ops, setOps] = useState([]);
  const [examples, setExamples] = useState([]);
  const [input, setInput] = useState(() => {
    // Restore last input if a session expired mid-decode (see api.js 401 interceptor)
    try {
      const saved = localStorage.getItem("nvx_last_input");
      if (saved) {
        localStorage.removeItem("nvx_last_input");
        return saved;
      }
    } catch (_) {}
    return "";
  });
  const [output, setOutput] = useState("");
  const [steps, setSteps] = useState([]);
  const [detected, setDetected] = useState(null);
  const [chain, setChain] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [status, setStatus] = useState("READY");
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [shareUrl, setShareUrl] = useState("");
  const [tacticFilter, setTacticFilter] = useState(null); // P3: click-to-filter
  const [graphView, setGraphView] = useState("path"); // "tactical" | "path" — mode of the new card below
  const [personas, setPersonas] = useState([]);
  const [providers, setProviders] = useState([]);
  const [personaId, setPersonaId] = useState("");
  const [providerId, setProviderId] = useState("");
  const [magicResults, setMagicResults] = useState(null);
  const [showMagic, setShowMagic] = useState(false);
  const [shellcodeFlag, setShellcodeFlag] = useState(false);
  // Winner metadata from AI Decode / Auto Investigate — feeds the SOC Verdict panel
  const [decodeConfidence, setDecodeConfidence] = useState(null);
  const [decodeWinnerEngine, setDecodeWinnerEngine] = useState(null);
  // ▲ SOC Verdict Card — evidence-driven, backend-computed (Feb-2026)
  const [verdictCard, setVerdictCard] = useState(null);
  // Corrupted-container signal — big-red panel when the decoder refuses to
  // brute-force inside a corrupt GZIP / ZLIB / LZMA / BZIP2 archive.
  const [corruptedContainer, setCorruptedContainer] = useState(null);
  // Decoding Trace panel — per-layer intermediate outputs from the deterministic decoder
  const [decodeTrace, setDecodeTrace] = useState([]);
  const [reachedShellcode, setReachedShellcode] = useState(false);
  // Client-side auto-detect on paste — 14 decoders raced instantly to surface a suggestion
  const [pasteHint, setPasteHint] = useState(null);
  // Feb-2026: Server-side Smart Input Advisor (planner) hint — real-time layer detection
  const [plannerHint, setPlannerHint] = useState(null);
  // History drawer
  const [historyOpen, setHistoryOpen] = useState(false);
  // Feb-2026: Candidate Explorer toggle — shows the ranked encoding candidates
  // + structured why-not breakdown from /api/decode/candidates.
  const [showCandidateExplorer, setShowCandidateExplorer] = useState(false);
  // Feb-2026 P2: Mixture-of-Experts (MoE) Analyst Panel toggle
  const [showMoePanel, setShowMoePanel] = useState(false);
  // Predicted process tree (fed to both ProcessTreeView + SocVerdictPanel mini)
  const [predictedTree, setPredictedTree] = useState(null);
  // Learning Feedback Loop
  const [boost, setBoost] = useState(null);
  const [boostHit, setBoostHit] = useState(false);
  // ONE-BUTTON UX — collapse Smart/AI/Auto Investigate/Troubleshoot into ADVANCED
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [chainOpen, setChainOpen] = useState(false);
  // Chain replay — read-only viewer for a rehydrated multi-stage history record
  const [chainReplay, setChainReplay] = useState(null); // full history record with kind === "chain"
  // Pending stage seed for ChainStageEditor after user chooses to restore a saved chain
  const [pendingChainStages, setPendingChainStages] = useState(null);
  // Feb-2026 fix: parent-supplied chain result forwarded to ChainStageEditor
  // so RE-RUN buttons and break-ribbons render immediately after
  // auto-investigate (fixes iteration-11 gating issue).
  const [pendingChainResult, setPendingChainResult] = useState(null);
  const [chainEditorKey, setChainEditorKey] = useState(0); // force remount when initialStages change
  // Feb-2026 Enhancements: input lock (edit toggle) + multi-command auto-route toast
  const [inputLocked, setInputLocked] = useState(false);
  const [multiChainNotice, setMultiChainNotice] = useState(null);   // { stages, verdict, family }
  // Feb-2026 · once a case has been named+saved, subsequent SAVE clicks
  // silently upsert under the same name (no prompt). Reset when the input
  // is materially cleared (user starts a new investigation).
  const [savedCaseName, setSavedCaseName] = useState(null);
  // Feb-2026: analyst-corrections launcher state.
  const [refineOpen, setRefineOpen] = useState(false);
  const [refineCtx, setRefineCtx] = useState(null); // { surface, wrong_finding }
  const openRefine = (surface, wrongFinding) => {
    setRefineCtx({ surface, wrong_finding: wrongFinding });
    setRefineOpen(true);
  };
  const [nivxrayTrace, setNivxrayTrace] = useState([]);
  // v1.4.2 · Report Bad Decode + Enrich IOCs
  const [badDecodeOpen, setBadDecodeOpen] = useState(false);
  const [iocEnrichment, setIocEnrichment] = useState(null);
  const [enrichingIocs, setEnrichingIocs] = useState(false);
  const enrichIocs = async () => {
    if (!analysis?.iocs) return;
    const values = [];
    Object.values(analysis.iocs).forEach((v) => {
      if (Array.isArray(v)) v.forEach((x) => { if (typeof x === "string") values.push(x); });
    });
    if (values.length === 0) return;
    setEnrichingIocs(true);
    try {
      const axios = (await import("axios")).default;
      const API = process.env.REACT_APP_BACKEND_URL + "/api";
      const token = localStorage.getItem("nvx_token");
      const r = await axios.post(
        `${API}/threat-intel/enrich-batch`,
        { values: values.slice(0, 25) },
        { headers: token ? { Authorization: `Bearer ${token}` } : {} },
      );
      // Reshape to the pill format (v1.5.3 · full osint.enrich_iocs)
      const out = (r.data?.results || []).map((row) => ({
        value:            row.value || row.ioc || "",
        kind:             row.kind || "",
        malicious_score:  row.malicious_score || 0,
        abuse_confidence: row.abuse_confidence || 0,
        otx_pulses:       row.otx_pulses || 0,
        providers:        row.providers || {},
      }));
      setIocEnrichment(out);
    } catch (e) {
      setIocEnrichment([{ value: "enrichment failed: " + (e?.message || "unknown") }]);
    } finally {
      setEnrichingIocs(false);
    }
  };
  // Track whether the analyst has unsaved work in the current workspace so
  // rehydrating from history can prompt before overwriting.
  const hasUnsavedWork = () => !!(
    (input && input.trim()) ||
    (output && output.trim()) ||
    (steps && steps.length > 0)
  );
  const rehydrateFromHistory = async (rec) => {
    if (!rec) return;
    // Chain records — default UX is read-only viewer, RESTORE button transitions
    // into editing after unsaved-changes confirmation.
    if (rec.kind === "chain") {
      setChainReplay(rec);
      setHistoryOpen(false);
      setStatus(`▸ CHAIN REPLAY (${rec.stage_count || (rec.stages || []).length} stages · read-only)`);
      // Scroll the replay into view after render, offset for the sticky header
      setTimeout(() => {
        try {
          const el = document.querySelector('[data-testid="chain-replay-view"]');
          if (el) {
            const rect = el.getBoundingClientRect();
            const HEADER = 90; // brut-border top header + toolbar strip
            window.scrollTo({ top: rect.top + window.scrollY - HEADER, behavior: "smooth" });
          }
        } catch {}
      }, 60);
      return;
    }
    if (hasUnsavedWork() &&
        !window.confirm("You have unsaved work in the current workspace. Restore this investigation and overwrite it?")) {
      setHistoryOpen(false);
      return;
    }
    // ▲ SOC Verdict Card (Feb-2026) — fetch the full history doc so we get
    // the freshly-computed verdict_card + per-layer evidence on rehydrate.
    // The list endpoint only carries lightweight preview fields.
    let full = rec;
    if (rec.id && !rec.verdict_card) {
      try {
        const r = await api.get(`/history/${rec.id}`);
        full = { ...rec, ...r.data };
      } catch (_) {
        // fall back to the list record — restore still works, verdict just
        // won't render for this rehydrate.
      }
    }
    setInput(full.input_preview || full.input || "");
    setOutput(full.output_preview || full.output || "");
    setDecodeTrace(full.trace || []);
    setDecodeWinnerEngine(full.engine || null);
    setDecodeConfidence(full.confidence ?? null);
    setVerdictCard(full.verdict_card || null);
    setCorruptedContainer(full.corrupted_container || null);
    setReachedShellcode(!!full.reached_shellcode);
    setSteps((full.chain || []).map((op) => ({ op: (typeof op === "string" ? op : op.op), args: {} })));
    setChain((full.chain || []).map((op, i) => ({
      op: (typeof op === "string" ? op : op.op),
      reason: full.trace?.[i]?.reason || "",
      output_preview: full.trace?.[i]?.output_preview || "",
    })));
    setAnalysis({ iocs: rec.iocs || {}, mitre: rec.mitre || [], ai_verdict: rec.verdict });
    setStatus(`▸ RESTORED FROM HISTORY (${rec.engine} · ${rec.confidence}%)`);
    setHistoryOpen(false);
  };

  // Move a saved chain from the read-only replay viewer into the editable
  // ChainStageEditor. Prompts to confirm if there's unsaved single-stage work.
  const restoreChainToWorkspace = () => {
    if (!chainReplay) return;
    if (hasUnsavedWork() &&
        !window.confirm("You have unsaved work in the current workspace. Restore this chain and overwrite it?")) {
      return;
    }
    const stages = (chainReplay.stages || []).map((s) => ({
      input: s.input_preview || s.input || "",
    }));
    // Reset single-stage state (chain will own the workspace now)
    setInput("");
    setOutput("");
    setSteps([]);
    setChain([]);
    setAnalysis(null);
    setDecodeTrace([]);
    setDecodeWinnerEngine(null);
    setDecodeConfidence(null);
    setVerdictCard(null);
    setCorruptedContainer(null);
    setReachedShellcode(false);
    setPendingChainStages(stages);
    setChainEditorKey((k) => k + 1);
    setChainOpen(true);
    setChainReplay(null);
    setStatus(`▸ CHAIN RESTORED TO WORKSPACE · ${stages.length} stages ready to re-run`);
  };
  const isShellcodeClient = useMemo(() => !!detectShellcode(output || ""), [output]);
  const streamStopRef = useRef(null);
  const fileRef = useRef(null);

  useEffect(() => {
    api.get("/operations").then((r) => setOps(r.data)).catch(() => {});
    api.get("/examples").then((r) => setExamples(r.data)).catch(() => {});
    // Model Studio — load enabled personas + providers if the user is admin;
    // non-admin users get an empty list (the AI call falls back to defaults).
    api.get("/admin/models?kind=ai_persona")
      .then((r) => {
        const enabled = (r.data || []).filter((m) => m.enabled);
        setPersonas(enabled);
        // Auto-select the flagship "NivX Cognis" persona if present and no persona selected yet
        const cognis = enabled.find((m) => /nivx\s*cognis/i.test(m.name));
        if (cognis && !personaId) setPersonaId(cognis.id);
      })
      .catch(() => setPersonas([]));
    api.get("/admin/models?kind=ai_provider")
      .then((r) => setProviders((r.data || []).filter((m) => m.enabled)))
      .catch(() => setProviders([]));
    // Recipe URL sharing — if the page loads with #recipe=<base64>, restore input+steps
    if (window.location.hash.startsWith("#recipe=")) {
      try {
        const b64 = window.location.hash.slice("#recipe=".length);
        const decoded = JSON.parse(decodeURIComponent(escape(atob(b64))));
        if (decoded?.i) setInput(decoded.i);
        if (Array.isArray(decoded?.s)) {
          setSteps(decoded.s.map((s) => ({ op: s.op, args: s.a || {} })));
        }
        setStatus("RECIPE LOADED FROM URL");
      } catch (e) {
        setStatus("Invalid recipe URL");
      }
    }
  }, []);

  const addOp = (op) => {
    const args = {};
    (op.args || []).forEach((a) => { if (a.default !== undefined) args[a.name] = a.default; });
    setSteps([...steps, { op: op.id, args }]);
  };

  const runRecipe = async () => {
    setLoading(true);
    setStatus("RUNNING RECIPE...");
    try {
      const r = await api.post("/recipe/run", { input, steps });
      setOutput(r.data.output);
      setDetected(r.data.detected_type);
      setChain(r.data.steps_output || []);
      setStatus(r.data.errors?.length ? "COMPLETED WITH ERRORS" : "OK");
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setLoading(false);
    }
  };

  // ---------- P1.a — Real-time client-side recipe preview ----------
  // Runs the recipe in-browser as the analyst types / edits steps. Falls back
  // to the backend for ops not ported to JS (kept out of the debounce loop).
  // ~30ms debounce keeps the workspace fluid even on large paste.
  const [livePreview, setLivePreview] = useState(null);

  // Feb-2026: Debounced Smart Input Advisor — hits /api/planner/advise 400ms
  // after last keystroke. Zero cost when input < 20 chars.
  useEffect(() => {
    if (!input || input.length < 20) {
      setPlannerHint(null);
      return;
    }
    const t = setTimeout(async () => {
      try {
        const r = await api.post("/planner/advise", { input });
        const hints = r.data?.hints || [];
        setPlannerHint(hints[0] || null);
      } catch (_) {
        setPlannerHint(null);
      }
    }, 400);
    return () => clearTimeout(t);
  }, [input]);

  useEffect(() => {
    if (!input && !steps.length) {
      setLivePreview(null);
      return;
    }
    const t = setTimeout(() => {
      const t0 = performance.now();
      try {
        const r = runClientRecipe(input, steps);
        const latencyMs = Math.round(performance.now() - t0);
        setLivePreview({ ...r, latencyMs });
        // Preview only auto-populates Output if:
        //   1. All steps ran in JS (no backend fallback needed), AND
        //   2. The user hasn't manually triggered a run yet (output empty)
        //      OR the previously-set output came from an earlier client preview.
        if (!r.needsBackend && !r.error && r.output != null) {
          setOutput(r.output);
        }
      } catch (e) {
        setLivePreview({ output: "", ranSteps: [], unsupported: [], error: e.message, latencyMs: 0 });
      }
    }, 30);
    return () => clearTimeout(t);
  }, [input, steps]);

  // ─── Universal CLEAR — wipe input + output + recipe + all analysis state ──
  // (Previously "Clear" only touched input; now it resets every panel.)
  const clearAll = () => {
    setInput("");
    setOutput("");
    setSteps([]);
    setDetected(null);
    setChain([]);
    setAnalysis(null);
    setMagicResults(null);
    setShowMagic(false);
    setShellcodeFlag(false);
    setDecodeConfidence(null);
    setDecodeWinnerEngine(null);
    setDecodeTrace([]);
    setReachedShellcode(false);
    setPasteHint(null);
    setPredictedTree(null);
    setBoost(null);
    setBoostHit(false);
    setNivxrayTrace([]);
    setLivePreview(null);
    setShareUrl("");
    setTacticFilter(null);
    setStatus("READY");
    setChainOpen(false);
    setChainReplay(null);
    setPendingChainStages(null);
    setPendingChainResult(null);
    setMultiChainNotice(null);
    // Feb-2026 · reset saved-case tracker so next SAVE prompts for a new name
    setSavedCaseName(null);
    setInputLocked(false);
    try { localStorage.removeItem("nvx.pendingInput"); } catch {}
  };


  // ─── Multi-command chain routing ─────────────────────────────────────
  // When the analyst pastes multiple plain-text command lines (e.g. a Lumma
  // ClickFix sequence, an EDR-bypass chain, a Meterpreter runner), the
  // top-level AUTO INVESTIGATE / DECODE buttons must NOT flat-decode the
  // whole blob (that would only pick up line 1). Instead we split into
  // stages, run /api/decode/chain deterministically per stage, and expose
  // the AGGREGATE as the top-level Output / Recipe / Attack Graph / KILL
  // CHAIN so nothing is truncated. The full per-stage drill-down is
  // rendered by ChainStageEditor which we auto-open below.
  const runChainAnalysis = async (parts) => {
    setLoading(true);
    setStatus(`MULTI-COMMAND CHAIN DETECTED · analysing ${parts.length} stages…`);
    try {
      const r = await api.post("/decode/chain", {
        stages: parts.map((p) => ({ input: p })),
      });
      const d = r.data || {};
      const stages = d.stages || [];
      const agg = d.aggregate || {};

      // Aggregate confidence: floor of mean per-stage confidence, capped 0–100.
      const confs = stages.map((s) => s.confidence).filter((c) => Number.isFinite(c));
      const meanConf = confs.length
        ? Math.min(100, Math.max(0, Math.round(confs.reduce((a, b) => a + b, 0) / confs.length)))
        : null;
      const family = agg.family?.family;
      const verdict = agg.risk?.verdict;

      // Compose a unified OUTPUT preview — prefer the server-synthesized
      // SOC report when present (Feb-2026 UX fix so the OUTPUT panel does
      // NOT echo the analyst's raw multi-line paste), fall back to
      // per-stage headers + decoded blobs when the report is absent.
      const aggregatedOutput = (
        d.report_text
        || stages.map((s, i) => {
             const head = `─── STAGE ${i + 1} · engine=${s.engine || "?"} · conf=${s.confidence ?? "?"}/100 ───`;
             return `${head}\n${(s.output || "").trim() || "(no additional decode — plain-text command)"}`;
           }).join("\n\n")
      );

      // Sync top-level state so OUTPUT / RECIPE / MITRE / IOCs panels all
      // reflect the AGGREGATE and not just the first line.
      setOutput(aggregatedOutput);
      // Recipe: show a synthetic "chain" step-summary so the RECIPE panel
      // is not empty. Each stage becomes one recipe row.
      const recipeSteps = stages.map((s) => ({
        op: `stage-${s.stage_index + 1}`,
        args: {},
      }));
      setSteps(recipeSteps);
      setChain(stages.map((s) => ({
        op: `stage-${s.stage_index + 1}`,
        reason: `${s.engine || "?"} · conf=${s.confidence ?? "?"}/100 · ${(s.input_preview || "").slice(0, 80)}`,
        output_preview: (s.output || "").slice(0, 200),
      })));
      setDecodeTrace(stages.map((s) => ({
        op: `stage-${s.stage_index + 1}`,
        args: {},
        reason: `Stage ${s.stage_index + 1} · engine=${s.engine} · conf=${s.confidence}/100`,
        output_preview: (s.output || "").slice(0, 400),
        output_length: s.output_length,
      })));
      setDecodeWinnerEngine(`chain (${stages.length} stages)`);
      setDecodeConfidence(meanConf);
      setReachedShellcode(stages.some((s) => s.reached_shellcode));
      setVerdictCard(null);
      setCorruptedContainer(null);

      // Feed the ATTACK GRAPH / IOC / MITRE panels via the analysis object.
      setAnalysis({
        iocs: agg.iocs || {},
        mitre: agg.mitre || [],
        lolbins: agg.lolbas || [],   // fallbackGraph reads `lolbins`
        lolbas: agg.lolbas || [],
        yara: agg.yara || [],
        risk: agg.risk || {},
        family: agg.family || null,
        ai_verdict: verdict ? {
          verdict,
          confidence: agg.risk?.score,
          summary: `${family ? family + " · " : ""}${stages.length} stages · chain-amplified`,
        } : null,
        chain_result: d,    // preserve full response for downstream panels
        streaming: false,
      });

      // Auto-open Chain Mode so the per-stage drill-down UI is visible.
      const stageSeeds = stages.map((s) => ({
        input: s.input_preview && !s.input_preview.endsWith("…")
          ? s.input_preview : (parts[s.stage_index] || ""),
      }));
      setPendingChainStages(stageSeeds);
      setPendingChainResult(d);        // <-- forward full result to editor
      setChainEditorKey((k) => k + 1);
      setChainOpen(true);

      setStatus(
        `CHAIN COMPLETE · ${stages.length} stages · ${verdict || "unknown"}` +
        (family ? ` · ${family}` : "") +
        (meanConf != null ? ` · avg ${meanConf}%` : "")
      );
      setMultiChainNotice({
        stages: stages.length,
        verdict: verdict || "unknown",
        family: family || null,
      });
      setPasteHint(null);
      return d;
    } catch (e) {
      setStatus("CHAIN ERROR: " + (e?.response?.data?.detail || e.message));
      return null;
    } finally {
      setLoading(false);
    }
  };

  // Opt-out escape hatch — analyst wants the whole blob decoded flat
  // (e.g. for a payload that *looks* multi-command but is actually a
  // single obfuscation with newlines as delimiters). Bypasses the
  // splitter and runs /api/decode/smart on the raw text.
  const revertToFlatDecode = async () => {
    setMultiChainNotice(null);
    setChainOpen(false);
    setPendingChainResult(null);
    setPendingChainStages(null);
    setLoading(true);
    setStatus("REVERTED · analysing as flat blob…");
    try {
      const r = await api.post("/decode/smart", { input });
      const d = r.data || {};
      setOutput(d.output || "");
      setSteps((d.recipe || []).map((s) => ({ op: s.op, args: s.args || {} })));
      setChain(d.chain || []);
      setDecodeTrace(d.chain || []);
      setDecodeWinnerEngine(d.engine || null);
      setDecodeConfidence(d.confidence ?? null);
      setReachedShellcode(!!d.reached_shellcode);
      // Wipe stale chain-aggregated analysis so ATT&CK / IOC panels re-derive from single blob.
      setAnalysis({
        iocs: d.iocs || {},
        mitre: d.mitre || [],
        lolbins: d.lolbas || [],
        lolbas: d.lolbas || [],
        yara: d.yara || [],
        risk: d.risk || {},
        family: d.family || null,
        // v1.5.1 — Zero-Miss escalation trace
        layer_trace: d.layer_trace || [],
        engine: d.engine || null,
        confidence: (d.confidence ?? d.score ?? null),
        // v1.5.5 — TI Shield · 360° per-layer intelligence
        ti_shield: d.ti_shield || [],
      });
      setStatus(`FLAT DECODE · engine=${d.engine || "?"} · conf=${d.confidence ?? "?"}/100`);
    } catch (e) {
      setStatus("FLAT DECODE ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setLoading(false);
    }
  };


  // ─── ONE-BUTTON orchestrator ─────────────────────────────────────────
  // Auto-runs: (1) archetype/boost/deterministic via Smart Decode, then
  //           (2) AI fallback (Auto Investigate) if confidence < 40.
  // Fires a live trace so the analyst sees exactly what happened.
  const nivxrayDecode = async () => {
    if (!input.trim()) { setStatus("PROVIDE INPUT FIRST"); return; }
    // Multi-command chain? Route to /decode/chain so all stages are analysed.
    const parts = splitCommandLines(input);
    if (parts && parts.length > 1) {
      await runChainAnalysis(parts);
      return;
    }
    const trace = [];
    setNivxrayTrace(trace);
    setStatus("NIVXRAY DECODE — DETERMINISTIC + BOOST…");
    setLoading(true);
    try {
      // Step 1 · deterministic (archetype + smart/magic race + boost)
      const r = await api.post("/decode/smart", { input });
      const conf = r.data.confidence ?? 0;
      const eng = r.data.engine || "?";
      const outLen = (r.data.output || "").length;
      trace.push({
        step: "deterministic",
        engine: eng,
        confidence: conf,
        output_len: outLen,
        note: eng.startsWith("archetype:")
          ? `Matched wrapper archetype — ${eng.replace("archetype:", "")}`
          : `Smart/magic race — ${eng}`,
      });
      setSteps((r.data.recipe || []).map((s) => ({ op: s.op, args: s.args || {} })));
      setOutput(r.data.output || "");
      if (r.data.trace) setDecodeTrace(r.data.trace);
      setReachedShellcode(!!r.data.reached_shellcode);
      setDecodeConfidence(conf);
      setDecodeWinnerEngine(eng);
      setBoost(r.data.boost || null);
      setBoostHit(!!r.data.boost_hit);
      setNivxrayTrace([...trace]);
      // v1.5.1 — populate analysis with Zero-Miss escalation ladder so the
      // EscalationLadder component renders immediately on primary decode
      // (without waiting for the analyst to click ANALYZE + OSINT).
      setAnalysis((a) => ({
        ...(a || {}),
        iocs:        r.data.iocs || (a?.iocs) || {},
        mitre:       r.data.mitre || (a?.mitre) || [],
        lolbas:      r.data.lolbas || (a?.lolbas) || [],
        engine:      eng,
        confidence:  conf / 100,
        layer_trace: r.data.layer_trace || [],
        l3_metadata: r.data.l3_metadata || null,
        // v1.5.5 — TI Shield renders immediately on primary decode
        ti_shield:   r.data.ti_shield || (a?.ti_shield) || [],
      }));

      // Step 2 · AI fallback if confidence low OR archetype didn't match AND output is trivial
      const shouldFallback = conf < 40 && !eng.startsWith("archetype:");
      if (shouldFallback) {
        trace.push({
          step: "ai-fallback",
          note: `Confidence ${conf}% below threshold — escalating to Auto Investigate`,
        });
        setNivxrayTrace([...trace]);
        setStatus("NIVXRAY DECODE — AI FALLBACK…");
        await autoInvestigate();   // reuses existing SSE stream
        trace.push({ step: "ai-done", note: "AI investigation complete — see verdict panel" });
      } else {
        trace.push({
          step: "done",
          note: conf >= 40
            ? `Deterministic decode succeeded at ${conf}% — AI fallback not needed`
            : `Archetype match at 100% — AI fallback not needed`,
        });
      }
      setNivxrayTrace([...trace]);
      setStatus(`NIVXRAY DECODE COMPLETE · ${eng} · ${conf}%`);
    } catch (e) {
      trace.push({ step: "error", note: e?.response?.data?.detail || e.message });
      setNivxrayTrace([...trace]);
      setStatus("NIVXRAY DECODE FAILED — see trace");
    } finally {
      setLoading(false);
    }
  };

  // Feb-2026 · Strict vs Best-Effort container-recovery mode. Persisted per
  // user so the choice sticks across sessions.
  const [recoveryMode, setRecoveryMode] = useState(
    () => localStorage.getItem("nvx_recovery_mode") || "strict",
  );
  const setRecoveryModePersisted = (m) => {
    setRecoveryMode(m);
    try { localStorage.setItem("nvx_recovery_mode", m); } catch {}
  };

  const autoDecode = async ({ smart = false, disable_boost = false } = {}) => {
    if (!input.trim()) { setStatus("PROVIDE INPUT FIRST"); return; }
    // Multi-command chain? Route to /decode/chain (both smart and AI paths).
    const parts = splitCommandLines(input);
    if (parts && parts.length > 1) {
      await runChainAnalysis(parts);
      return;
    }
    setLoading(true);
    setStatus(smart ? "SMART-DECODING (DETERMINISTIC)..." : "AI AUTO-DECODING...");
    try {
      const url = smart ? "/decode/smart" : "/ai/auto-decode";
      const payload = smart ? { input, disable_boost, mode: recoveryMode } : { input };
      const r = await api.post(url, payload);
      setSteps((r.data.recipe || []).map((s) => ({ op: s.op, args: s.args || {} })));

      // Anti-hallucination guard — if backend refused to emit a decode (SOC-mode
      // graceful stop), keep the input unchanged and surface the explanation
      // instead of dumping garbage into the Output pane.
      if (r.data.stopped_gracefully) {
        setOutput("");
        setStatus(`⚠ ${r.data.graceful_message || "No further deterministic decoding possible"}`);
      } else {
        setOutput(r.data.output || "");
        const conf = r.data.confidence;
        const eng  = r.data.winner_engine;
        setDecodeConfidence(conf ?? null);
        setDecodeWinnerEngine(eng || null);
        const confPrefix = (conf != null && eng) ? `[${eng.toUpperCase()} · ${conf}%] ` : "";
        const detail = r.data.reasoning ? `AI: ${r.data.reasoning.slice(0, 120)}` : "SMART DECODE COMPLETE";
        setStatus(confPrefix + detail);
      }

      setDetected(r.data.detected_type || null);
      setChain((r.data.recipe || []).map((s, i) => ({
        op: s.op, reason: s.reason || "",
        output_preview: r.data.trace?.[i]?.output_preview || r.data.steps_output?.[i]?.output_preview || "",
        custom: !!s.custom, model_id: s.model_id, model_name: s.model_name,
      })));
      // Decoding Trace panel data (smart-decode returns full trace; ai-decode does not)
      if (smart && r.data.trace) {
        setDecodeTrace(r.data.trace);
        setReachedShellcode(!!r.data.reached_shellcode);
        setDecodeConfidence(r.data.confidence ?? null);
        setDecodeWinnerEngine(r.data.engine || null);
        // Learning Feedback Loop — boost metadata
        setBoost(r.data.boost || null);
        setBoostHit(!!r.data.boost_hit);
      }
      // ▲ SOC evidence-driven analyst brief (Feb-2026)
      setVerdictCard(r.data.verdict_card || null);
      setCorruptedContainer(r.data.corrupted_container || null);
      setPasteHint(null);
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setLoading(false);
    }
  };

  const magicDecode = async () => {
    if (!input.trim()) { setStatus("PROVIDE INPUT FIRST"); return; }
    setLoading(true);
    setStatus("MAGIC ▸ recursive multi-branch search…");
    try {
      const r = await api.post("/decode/magic", { input, max_depth: 4, max_branches: 4, top_n: 5 });
      setMagicResults(r.data);
      setShowMagic(true);
      setStatus(`MAGIC ▸ ${r.data.top_results?.length || 0} candidate chains · explored ${r.data.candidates_explored} paths`);
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setLoading(false);
    }
  };

  const applyMagicResult = (r) => {
    setSteps((r.chain || []).map((s) => ({ op: s.op, args: s.args || {} })));
    setOutput(r.output || "");
    setChain((r.chain || []).map((s, i) => ({
      op: s.op, reason: `magic auto-decoder (score ${r.score_breakdown?.score ?? "?"})`,
      output_preview: (r.output || "").slice(0, 400),
    })));
    // Propagate the shellcode stop-condition flag so the ShellcodeView can
    // auto-render when a magic chain terminates on binary output.
    setShellcodeFlag(!!r.is_shellcode);
    setShowMagic(false);
    setStatus(`APPLIED MAGIC CHAIN · score ${r.score_breakdown?.score}`);
  };

  const shareRecipe = () => {
    const payload = {
      i: input.slice(0, 40000),
      s: steps.map((s) => ({ op: s.op, a: s.args && Object.keys(s.args).length ? s.args : undefined })),
    };
    const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
    const url = `${window.location.origin}${window.location.pathname}#recipe=${encoded}`;
    setShareUrl(url);
    // Best-effort clipboard write; the toast shows the URL either way
    try {
      if (navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(url).then(
          () => setStatus("SHARE URL COPIED TO CLIPBOARD"),
          () => setStatus("SHARE URL READY — copy from the toast"),
        );
      } else {
        setStatus("SHARE URL READY — copy from the toast");
      }
    } catch {
      setStatus("SHARE URL READY — copy from the toast");
    }
  };

  const analyze = ({ describe = false, aiVerdict = false } = {}) => {
    if (!input.trim() && !output.trim()) { setStatus("PROVIDE INPUT OR OUTPUT FIRST"); return; }
    streamStopRef.current?.();
    setAnalyzing(true);
    if (describe || aiVerdict) {
      // AI-heavy path — use job polling to bypass reverse-proxy timeouts
      pollAnalyzeJob({ input, output, enrich_osint: true, describe, use_ai_verdict: aiVerdict,
                       persona_id: personaId || undefined, provider_id: providerId || undefined }, chain);
    } else {
      // Fast path — SSE streaming
      setStatus("ANALYZING…");
      setAnalysis((prev) => ({ ...(prev || {}), chain, streaming: true }));
      const stop = streamAnalyze(
        { input, output, enrich_osint: true, describe: false, use_ai_verdict: false },
        {
          onStatus:      (s) => setStatus(`▸ ${s.phase.toUpperCase()}: ${s.message}`),
          onPartial:     (p) => setAnalysis((a) => ({ ...(a || {}), ...p, chain, streaming: true })),
          onTiHits:      (h) => setAnalysis((a) => ({ ...(a || {}), ti_hits: h, streaming: true })),
          onOsint:       (o) => setAnalysis((a) => ({ ...(a || {}), osint: o, streaming: true })),
          onResult:      (r) => setAnalysis({ ...r, chain, streaming: false }),
          onError:       (e) => setStatus(`STREAM ERROR (${e.phase}): ${e.error}`),
          onDone:        ()  => { setAnalyzing(false); streamStopRef.current = null;
                                 setStatus((s) => s.startsWith("STREAM ERROR") ? s : "ANALYSIS COMPLETE"); },
        },
      );
      streamStopRef.current = stop;
    }
  };

  const pollAnalyzeJob = async (body, chainVal) => {
    // Poll-based analysis for AI-heavy runs (bypasses SSE / proxy timeouts).
    setStatus("ANALYZING ▸ enqueuing…");
    setAnalysis({ chain: chainVal, streaming: true, job_id: null });
    let jobId;
    try {
      const r = await api.post("/analyze/async", body);
      jobId = r.data.job_id;
      setAnalysis((a) => ({ ...(a || {}), job_id: jobId }));
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
      setAnalyzing(false);
      return;
    }
    let cancelled = false;
    streamStopRef.current = () => { cancelled = true; };
    const MAX_POLLS = 90;   // 90 × 3s = 270s
    for (let i = 0; i < MAX_POLLS; i++) {
      if (cancelled) return;
      try {
        const st = await api.get(`/analyze/status/${jobId}`);
        const d = st.data;
        setAnalysis((a) => ({
          ...(a || {}),
          job_id: jobId,
          iocs: d.iocs || a?.iocs,
          mitre: d.mitre || a?.mitre,
          yara: d.yara || a?.yara,
          lolbas: d.lolbas || a?.lolbas,
          risk: d.risk || a?.risk,
          ti_hits: d.ti_hits ?? a?.ti_hits,
          osint: d.osint ?? a?.osint,
          ai_verdict: d.ai_verdict ?? a?.ai_verdict,
          description: d.description ?? a?.description,
          playbooks_used: d.playbooks_used ?? a?.playbooks_used,
          chain: chainVal,
          streaming: d.status !== "done" && d.status !== "error",
        }));
        setStatus(`▸ ${(d.phase || "running").toUpperCase()} · ${d.progress || 0}%${d.elapsed_s ? " · " + d.elapsed_s + "s" : ""}`);
        if (d.status === "done") {
          setStatus(`ANALYSIS COMPLETE · ${d.risk?.verdict || ""}`);
          break;
        }
        if (d.status === "error") {
          setStatus(`ERROR: ${d.error}`);
          break;
        }
      } catch (e) {
        // Transient network hiccups — keep polling
        setStatus(`POLL WARN: ${e.message} — retrying…`);
      }
      await new Promise((r) => setTimeout(r, 3000));
    }
    setAnalyzing(false);
    streamStopRef.current = null;
  };

  const autoInvestigate = async () => {
    if (!input.trim()) { setStatus("PROVIDE INPUT FIRST"); return; }
    // Multi-command chain? Route to /decode/chain so every stage's IOCs /
    // MITRE / LOLBAS reach the top-level Attack Graph & Kill Chain.
    const parts = splitCommandLines(input);
    if (parts && parts.length > 1) {
      await runChainAnalysis(parts);
      return;
    }
    streamStopRef.current?.();
    setLoading(true); setAnalyzing(true);
    setTacticFilter(null);
    setStatus("AUTO-INVESTIGATE ▸ SMART DECODING…");
    try {
      // 1) Deterministic decode first (fast — now uses smart+magic race for deepest chain)
      const r = await api.post("/decode/smart", { input });
      const newSteps = (r.data.recipe || []).map((s) => ({ op: s.op, args: s.args || {} }));
      setSteps(newSteps);
      setOutput(r.data.output || "");
      setDetected(r.data.detected_type || null);
      const newChain = (r.data.recipe || []).map((s, i) => ({
        op: s.op, reason: s.reason || "",
        output_preview: r.data.trace?.[i]?.output_preview || "",
        custom: !!s.custom, model_id: s.model_id, model_name: s.model_name,
      }));
      setChain(newChain);
      // Decoding Trace panel data
      setDecodeTrace(r.data.trace || []);
      setDecodeWinnerEngine(r.data.engine || null);
      setDecodeConfidence(r.data.confidence ?? null);
      setReachedShellcode(!!r.data.reached_shellcode);
      setPasteHint(null); // dismiss the paste suggestion once we've decoded
      setLoading(false);

      // 2) Analysis via async job polling (bypasses 60s proxy timeout)
      pollAnalyzeJob(
        { input, output: r.data.output || "", enrich_osint: true, describe: true, use_ai_verdict: true,
          persona_id: personaId || undefined, provider_id: providerId || undefined },
        newChain,
      );
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
      setLoading(false); setAnalyzing(false);
    }
  };

  const cancelStream = () => {
    streamStopRef.current?.();
    streamStopRef.current = null;
    setAnalyzing(false); setLoading(false);
    setStatus("STREAM CANCELLED");
  };

  const troubleshoot = async (useAI = false) => {
    setLoading(true);
    setStatus(useAI ? "TROUBLESHOOT ▸ deterministic + AI escalation…"
                    : "TROUBLESHOOT ▸ deterministic rules…");
    try {
      const r = await api.post(`/troubleshoot/auto?use_ai=${useAI ? "true" : "false"}`,
                               { input, steps, error: null });
      const d = r.data;
      // Auto-apply the repaired state to the workspace
      if (d.final_steps?.length) {
        setSteps(d.final_steps.map((s) => ({ op: s.op, args: s.args || {} })));
      }
      if (d.final_output != null) {
        setOutput(d.final_output);
      }
      if (d.final_engine) setDecodeWinnerEngine(d.final_engine);
      if (d.final_confidence != null) setDecodeConfidence(d.final_confidence);
      setReachedShellcode(!!d.reached_shellcode);

      // Surface diagnostics as a compact toast + trace
      const trace = (d.diagnoses || []).map((diag) => ({
        step: "troubleshoot",
        engine: diag.severity.toUpperCase(),
        note: `[${diag.code}] ${diag.message}${diag.auto_fixed ? " ✓ AUTO-FIXED" : ""}`,
      }));
      if (d.fixes_applied?.length) {
        trace.push({
          step: "done",
          note: `${d.fixes_applied.length} auto-fix(es) applied: ${d.fixes_applied.join("; ")}`,
        });
      }
      setNivxrayTrace(trace);
      setStatus(d.human_summary || (d.success ? "TROUBLESHOOT OK" : "TROUBLESHOOT — NO FIXES POSSIBLE"));
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setLoading(false);
    }
  };

  const doShare = async () => {
    try {
      const r = await api.post("/share", { input, steps });
      const url = `${window.location.origin}/?share=${r.data.token}`;
      setShareUrl(url);
      navigator.clipboard.writeText(url);
      setStatus("SHARE LINK COPIED");
    } catch (e) {
      setStatus("SHARE FAILED: " + e.message);
    }
  };

  const downloadReport = async (fmt = "html") => {
    if (typeof fmt !== "string") fmt = "html";
    setStatus(`GENERATING ${fmt.toUpperCase()} REPORT...`);
    try {
      const r = await api.post(`/report/${fmt}`,
        { input, output, enrich_osint: true, describe: !!output, use_ai_verdict: !!output },
        { responseType: "blob" }
      );
      const disp = r.headers?.["x-filename"] || r.headers?.["content-disposition"] || "";
      let filename = `nivxray_report.${fmt}`;
      const m = /filename="?([^"]+)"?/.exec(disp);
      if (m) filename = m[1];
      const url = URL.createObjectURL(r.data);
      const a = document.createElement("a");
      a.href = url; a.download = filename; a.click();
      URL.revokeObjectURL(url);
      setStatus(`REPORT DOWNLOADED (${fmt.toUpperCase()})`);
    } catch (e) {
      setStatus("REPORT FAILED: " + (e?.response?.data?.detail || e.message));
    }
  };

  // Feb 2026 · Save the current workspace case (input+output+trace) with a
  // friendly name → recallable from Case Library page.
  const saveCase = async (opts = {}) => {
    if (!input || !output) {
      setStatus("SAVE CASE: run a decode first"); return;
    }
    // Feb-2026 UX · if the case already has a name from an earlier save,
    // reuse it silently (no prompt) so dynamic edits/re-decodes upsert
    // rather than force the analyst to re-type the name.  Only prompt on
    // the FIRST save, or when the user explicitly clicks SAVE AS (opts.forcePrompt).
    let name = savedCaseName;
    if (!name || opts.forcePrompt) {
      name = window.prompt(
        savedCaseName ? "Save this case AS a new name:" : "Name this case (for future reference):",
        savedCaseName || `Case · ${new Date().toLocaleString()}`,
      );
      if (!name) return;
    }
    setStatus(savedCaseName && !opts.forcePrompt ? `UPDATING CASE "${name}"...` : "SAVING CASE...");
    try {
      const r = await api.post("/cases/save", {
        name,
        input,
        output,
        engine: decodeWinnerEngine || "-",
        confidence: decodeConfidence ?? null,
        chain_ids: (chain || []).map((c) => c.op_id || c.id).filter(Boolean),
        verdict: verdictCard?.verdict || analysis?.ai_verdict || null,
        iocs: analysis?.iocs || {},
      });
      setSavedCaseName(name);
      const wasUpdate = !!r.data?.updated;
      setStatus(
        wasUpdate
          ? `CASE UPDATED: "${name}"`
          : `CASE SAVED: "${name}" (id=${(r.data?.id || "").slice(0, 8)})`
      );
    } catch (e) {
      const raw = e?.response?.data;
      let msg = raw?.detail || raw?.error || raw?.message || e?.message || String(e);
      if (Array.isArray(msg)) {
        msg = msg.map((v) => (v?.msg && v?.loc ? `${v.loc.join(".")}: ${v.msg}` : (v?.msg || JSON.stringify(v))))
                 .join(" · ");
      } else if (typeof msg === "object" && msg !== null) {
        msg = msg.msg || msg.error || JSON.stringify(msg);
      }
      setStatus("SAVE CASE FAILED: " + msg);
    }
  };

  const onUpload = async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const fd = new FormData();
    fd.append("file", f);
    setStatus(`UPLOADING ${f.name}...`);
    try {
      const r = await api.post("/upload", fd, { headers: { "Content-Type": "multipart/form-data" } });
      setInput(r.data.content);
      const type = r.data.file_type?.label || "?";
      const md5 = r.data.hashes?.md5 || "";
      setStatus(`LOADED: ${r.data.filename} · ${r.data.size} bytes · ${type} · MD5=${md5.slice(0, 12)}…`);
    } catch (e2) {
      setStatus("UPLOAD FAILED: " + (e2?.response?.data?.detail || e2.message));
    } finally {
      e.target.value = "";
    }
  };

  const loadExample = (ex) => {
    setInput(ex.input);
    setOutput("");
    setSteps([]);
    setChain([]);
    setAnalysis(null);
    setDetected(null);
    setStatus(`LOADED EXAMPLE: ${ex.label}`);
  };

  // support ?share=... on load
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    const share = p.get("share");
    if (share) {
      api.get(`/share/${share}`).then((r) => {
        setInput(r.data.input || "");
        setSteps(r.data.steps || []);
        setStatus("LOADED SHARED RECIPE");
      }).catch(() => setStatus("INVALID SHARE LINK"));
    }
  }, []);

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }} className="App">
      <Header />

      {/* Toolbar strip */}
      <div
        className="brut-border"
        style={{
          borderLeft: "none", borderRight: "none", borderTop: "none",
          padding: "10px 16px", display: "flex", gap: 8, alignItems: "center",
          flexWrap: "wrap", background: "var(--surface)",
        }}
      >
        <span className="badge">{ops.length || 87} OPS</span>
        <span className="badge warn">MITRE</span>
        <span className="badge warn">YARA</span>
        <span className="badge warn">LOLBAS</span>
        <span className="badge warn">IOC</span>
        <span className="badge warn">OSINT</span>
        <span className="badge warn">FLOW</span>
        <div style={{ flex: 1 }} />

        {(personas.length > 0 || providers.length > 0) && (
          <div style={{ display: "flex", gap: 6, alignItems: "center" }} data-testid="ai-model-picker">
            {personas.length > 0 && (
              <select
                className="brut-input"
                value={personaId}
                onChange={(e) => setPersonaId(e.target.value)}
                data-testid="ai-persona-select"
                title={
                  "AI PERSONA — the system prompt / analyst voice.\n\n" +
                  "★ NivX Cognis (recommended) — in-house flagship trained on Sophos layered-stager decoding + MITRE + LOLBAS.\n" +
                  "  Use for: malware triage, obfuscated PowerShell, LOLBin chains, shellcode reasoning.\n\n" +
                  "Default (JSON) — bare structured-output prompt.\n" +
                  "  Use for: quick sanity checks, when you want raw LLM reasoning without SOC-specific context.\n\n" +
                  "Custom personas — created in Model Studio → AI Personas."
                }
                style={{ padding: "4px 8px", fontSize: 11, height: 28, background: "var(--inset)" }}
              >
                <option value="">PERSONA · Default (JSON)</option>
                {personas.map((p) => (
                  <option key={p.id} value={p.id}>
                    {`${/nivx\s*cognis/i.test(p.name) ? "★ PERSONA · " : "PERSONA · "}${p.name}`}
                  </option>
                ))}
              </select>
            )}
            {providers.length > 0 && (
              <select
                className="brut-input"
                value={providerId}
                onChange={(e) => setProviderId(e.target.value)}
                data-testid="ai-provider-select"
                title={
                  "LLM PROVIDER — which model executes the AI steps.\n\n" +
                  "Default (Claude Sonnet 4.5) — best balance of accuracy + speed for malware triage.\n" +
                  "  Use for: everything, unless you have a specific reason to switch.\n\n" +
                  "GPT-5.2 — stronger on obscure JavaScript / eval-chain deobfuscation.\n" +
                  "Gemini 3 Pro — strongest for multi-modal (screenshots) and non-English lures.\n\n" +
                  "All providers use the Emergent Universal LLM Key. Switch in Model Studio → LLM Providers."
                }
                style={{ padding: "4px 8px", fontSize: 11, height: 28, background: "var(--inset)" }}
              >
                <option value="">LLM · Default</option>
                {providers.map((p) => <option key={p.id} value={p.id}>{`LLM · ${p.name}`}</option>)}
              </select>
            )}
          </div>
        )}

        {/* Real-time input classifier — glows the right buttons + shows a stepper */}
        <GuidanceBanner input={input} className="nvx-guidance-banner"
                         data-testid="input-guidance-banner-wrapper" />

        <button className="nvx-btn primary" onClick={nivxrayDecode} disabled={loading || analyzing}
                data-testid="btn-nivxray-decode"
                title={
                  "NIVXRAY DECODE — ONE BUTTON. Auto-runs:\n" +
                  "  1. Named wrapper archetype match (Empire/Cobalt/Bash/Node)\n" +
                  "  2. Learning-Feedback boost from your history + KB\n" +
                  "  3. Deterministic Smart Decode (magic ⊕ smart race)\n" +
                  "  4. AI fallback (Auto Investigate) if confidence < 40%\n\n" +
                  "▸ USE WHEN: literally always. Paste and click. NivXRay picks the sharpest path.\n" +
                  "▸ RETURNS: full pipeline trace showing what fired and why."
                }
                style={{
                  fontSize: 13, padding: "8px 18px",
                  ...(getGuidanceGlowStyle(input, "btn-auto-investigate") || {}),
                }}>
          <Sparkles size={14} /> NIVXRAY DECODE
        </button>
        <button className="nvx-btn ghost" onClick={() => setAdvancedOpen((v) => !v)}
                data-testid="btn-advanced-toggle"
                title="Show individual decode modes (Smart / AI / Auto Investigate / Magic / Troubleshoot)">
          {advancedOpen ? "▾ ADVANCED" : "▸ ADVANCED"}
        </button>
        {analyzing && (
          <button className="nvx-btn warn" onClick={cancelStream} data-testid="btn-cancel-stream">
            <X size={13} /> CANCEL
          </button>
        )}
        <button className="nvx-btn ghost" onClick={() => setHistoryOpen(true)} data-testid="btn-open-history"
                title="Investigation History — auto-saved for 30 days (starred entries kept forever).">
          📜 HISTORY
        </button>
        {advancedOpen && (
        <>
        <button className="nvx-btn" onClick={autoInvestigate} disabled={loading || analyzing} data-testid="btn-auto-investigate"
                title={
                  "AUTO INVESTIGATE — Full SOC pipeline (MAGIC decode → OSINT → threat-intel → MITRE → AI verdict)."
                }
                style={getGuidanceGlowStyle(input, "btn-auto-investigate") || undefined}>
          <Sparkles size={13} /> AUTO INVESTIGATE
        </button>
        <button className="nvx-btn" onClick={() => autoDecode({ smart: false })} disabled={loading} data-testid="btn-ai-decode"
                title={
                  "AI DECODE — LLM proposes a recipe (base64/gzip/XOR/etc.) with SOC anti-hallucination guard.\n" +
                  "Runs AI plan AND deterministic magic in parallel, picks the higher-confidence winner.\n\n" +
                  "▸ USE WHEN: the payload is unusual and you want the LLM to reason about the format.\n" +
                  "▸ SAFETY: if confidence < 35/100 it STOPS gracefully (no garbage output).\n" +
                  "▸ COST: 1 LLM call (~3–8s). Uses selected Persona + LLM (default NivX Cognis + Claude).\n" +
                  "▸ RETURNS: recipe + confidence % + winner engine + graceful-stop message if applicable."
                }
                style={getGuidanceGlowStyle(input, "btn-ai-decode") || undefined}>
          <Wand2 size={13} /> AI DECODE
        </button>
        <button className="nvx-btn" onClick={() => autoDecode({ smart: true })} disabled={loading} data-testid="btn-smart-decode"
                title={
                  "SMART DECODE — Fully deterministic. No AI. Fast.\n" +
                  "Rule-based recipe selection using signature prefixes (H4sI→gzip, JAB/SQBF→UTF-16LE, TVq→PE, XOR-loop sniffer, etc).\n\n" +
                  "▸ USE WHEN: you need repeatable results (regression tests, high-volume automation, air-gapped ops).\n" +
                  "▸ COST: <100ms, no LLM. Zero hallucination by design.\n" +
                  "▸ LIMITATION: only recognises known signatures. Falls back to no-op on unknown formats."
                }
                style={getGuidanceGlowStyle(input, "btn-smart-decode") || undefined}>
          <Zap size={13} /> SMART DECODE
        </button>
        {/* Feb-2026 · Corrupted-Container recovery mode toggle */}
        <div
          data-testid="recovery-mode-toggle"
          className="mono"
          style={{
            display: "inline-flex",
            alignItems: "stretch",
            border: "1px solid var(--border)",
            borderRadius: 2,
            marginLeft: 4,
            fontSize: 10,
            letterSpacing: "0.10em",
          }}
          title={
            "Corrupted-Container recovery mode.\n\n" +
            "STRICT (default) — Report CRC/trailer failures as Corrupted. Salvaged\n" +
            "  plaintext is available on `corrupted_container.salvaged` for reference.\n\n" +
            "BEST-EFFORT — Elevate salvaged plaintext to the primary output with a\n" +
            "  permanent ⚠ Integrity Warning. Verdict downgrades Corrupted → Suspicious\n" +
            "  so the payload can flow into Sample Library / TAXII / SIEM."
          }
        >
          <button
            onClick={() => setRecoveryModePersisted("strict")}
            data-testid="recovery-mode-strict"
            style={{
              padding: "4px 10px",
              background: recoveryMode === "strict" ? "var(--accent)" : "transparent",
              color: recoveryMode === "strict" ? "var(--bg)" : "var(--text-mute)",
              border: "none",
              cursor: "pointer",
            }}
          >
            STRICT
          </button>
          <button
            onClick={() => setRecoveryModePersisted("best_effort")}
            data-testid="recovery-mode-best-effort"
            style={{
              padding: "4px 10px",
              background: recoveryMode === "best_effort" ? "var(--warn)" : "transparent",
              color: recoveryMode === "best_effort" ? "var(--bg)" : "var(--text-mute)",
              border: "none",
              borderLeft: "1px solid var(--border)",
              cursor: "pointer",
            }}
          >
            BEST-EFFORT
          </button>
        </div>
        <button className="nvx-btn" onClick={magicDecode} disabled={loading} data-testid="btn-magic-decode"
                style={{ borderColor: "var(--warn)", color: "var(--warn)" }}
                title={
                  "MAGIC — Recursive multi-branch auto-decoder (CyberChef Magic parity).\n" +
                  "Tries every plausible op combination, scores each candidate (readability + shellcode prologue + IOC density), and returns the top-N chains for you to pick.\n\n" +
                  "▸ USE WHEN: input is heavily obfuscated (nested base64+gzip+XOR); you want to see multiple candidate chains ranked side-by-side.\n" +
                  "▸ COST: <500ms typically, no LLM.\n" +
                  "▸ RETURNS: top 5 chains with per-step ops + confidence score + shellcode flag."
                }>
          <Wand2 size={13} /> MAGIC
        </button>
        <button className="nvx-btn" onClick={runRecipe} disabled={loading || !steps.length} data-testid="btn-run-recipe"
                title={
                  "RUN RECIPE — Execute the current step list against the input.\n" +
                  "Use this when you've hand-built the recipe (via the Operations panel) or edited a Smart/Magic/AI Decode output.\n\n" +
                  "▸ COST: <100ms, no LLM.\n" +
                  "▸ Sends to backend. For a 0-latency preview of JS-supported ops, watch the OUTPUT card update as you edit the recipe."
                }>
          <Play size={13} /> RUN RECIPE
        </button>
        <button className="nvx-btn warn" onClick={() => troubleshoot(false)} disabled={loading} data-testid="btn-troubleshoot"
                title={
                  "TROUBLESHOOT — Universal one-click auto-fix.\n\n" +
                  "▸ WORKS OFFLINE (no LLM). Fixes at runtime:\n" +
                  "   • Base64 padding / alphabet corruption\n" +
                  "   • Truncated gzip / partial deflate\n" +
                  "   • Recipe stopped too early → applies deeper archetype\n" +
                  "   • Missing IOCs in shellcode → XOR-key sweep\n" +
                  "   • Over-decoded tail (rot13/reverse) → trimmed\n" +
                  "   • Low-confidence stall → escalates to magic-decoder\n" +
                  "   • Op crashes → rolls back to last good layer\n\n" +
                  "▸ AUTO-APPLIES the fix to the workspace (recipe + output).\n" +
                  "▸ Use `TROUBLESHOOT + AI` for LLM escalation if deterministic fails."
                }>
          <Wrench size={13} /> TROUBLESHOOT
        </button>
        <button className="nvx-btn warn" onClick={() => troubleshoot(true)} disabled={loading} data-testid="btn-troubleshoot-ai"
                title={
                  "TROUBLESHOOT + AI — Same deterministic pipeline as above, then\n" +
                  "escalates to the LLM (Claude Sonnet 4.5) ONLY if the offline rules\n" +
                  "leave the payload undecoded. LLM proposes a new recipe based on the\n" +
                  "collected diagnostics.\n\n" +
                  "Costs 1 LLM call (~3-6s) only when needed."
                }>
          <Sparkles size={13} /> TROUBLESHOOT + AI
        </button>
        </>
        )}
        <button className="nvx-btn" onClick={doShare} data-testid="btn-share"><Share2 size={13} /> SHARE</button>
        <button className="nvx-btn ghost" onClick={shareRecipe} data-testid="btn-share-url"
                title="Copy a URL that reproduces the current input + recipe (fully client-side)">
          <Share2 size={13} /> COPY LINK
        </button>
        <ReportMenu onDownload={downloadReport} />
        <button className="nvx-btn" onClick={saveCase} data-testid="btn-save-case"
                style={{borderColor:"#7ee3c9",color:"#7ee3c9"}}
                title="Save this decoded case to the Case Library with a friendly name">
          💾 SAVE CASE
        </button>
        <button className="nvx-btn" onClick={() => fileRef.current?.click()} data-testid="btn-upload">
          <Upload size={13} /> UPLOAD
        </button>
        <input type="file" ref={fileRef} onChange={onUpload} hidden data-testid="file-input" />
      </div>

      {/* Status bar */}
      <div
        style={{
          padding: "6px 16px", background: "var(--inset)",
          borderBottom: "1px solid var(--border)",
          display: "flex", alignItems: "center", gap: 14,
        }}
      >
        {(() => {
          // Feb-2026 v1.2.0 · Colour-coded STATUS bar so analysts can tell
          // ERROR / SUCCESS / IN-PROGRESS / INFO apart at a glance.
          const raw = String(status || "");
          const lower = raw.toLowerCase();
          let dot = "var(--accent)"; let text = "var(--text-dim)"; let label = "STATUS";
          if (/error|failed|stream error|chain error|flat decode error/i.test(raw)) {
            dot = "var(--high, #ef4444)"; text = "var(--high, #ef4444)"; label = "ERROR";
          } else if (/complete|ok\b|analysis complete|success|ready|✓/i.test(lower)) {
            dot = "#22c55e"; text = "#22c55e"; label = "OK";
          } else if (/running|decoding|analyz|streaming|loading|generating|working/i.test(lower)) {
            dot = "#f59e0b"; text = "#f59e0b"; label = "RUNNING";
          } else if (/warn|partial|no.*match|not\s+found/i.test(lower)) {
            dot = "#eab308"; text = "#eab308"; label = "WARN";
          }
          return (
            <>
              <span className="mono" data-testid="status-dot" style={{ fontSize: 10, color: dot, letterSpacing: "0.2em" }}>
                ● {label}
              </span>
              <span className="mono" data-testid="status-line" style={{ fontSize: 11, color: text }}>
                {status}
              </span>
            </>
          );
        })()}
        <div style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 10, color: "var(--text-mute)" }}>
          INPUT {input.length}c · OUTPUT {output.length}c
        </span>
      </div>

      {/* Examples strip */}
      <div
        style={{
          padding: "8px 16px", background: "var(--bg)",
          borderBottom: "1px solid var(--border)",
          display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap",
        }}
      >
        <span className="mono" style={{ fontSize: 10, letterSpacing: "0.2em", color: "var(--text-mute)" }}>
          LOAD EXAMPLE:
        </span>
        {examples.map((ex) => (
          <button
            key={ex.id}
            className="nvx-btn sm ghost"
            onClick={() => loadExample(ex)}
            data-testid={`example-${ex.id}`}
          >
            ◆ {ex.label}
          </button>
        ))}
      </div>

      {/* SOC VERDICT — appears above the workspace whenever a decode
          terminates on known shellcode / PE / ELF. Google-AI-style one-line
          verdict + copy-to-clipboard SOC ticket. */}
      <SocVerdictPanel
        output={output}
        confidence={decodeConfidence}
        winnerEngine={decodeWinnerEngine}
        predictedTree={predictedTree}
      />

      {/* ▲ CANDIDATE EXPLORER (Feb-2026) — ranked encoding candidates with
          structured "why-not" breakdowns, hex, IOCs, LOLBins, MITRE ATT&CK.
          Toggle button opens the panel; renders below when active and there
          is input to analyse. */}
      <div style={{ padding: "0 16px 8px", display: "flex", alignItems: "center", gap: 8 }}>
        <button
          className={`nvx-btn sm ${showCandidateExplorer ? "" : "ghost"}`}
          onClick={() => setShowCandidateExplorer((v) => !v)}
          data-testid="toggle-candidate-explorer"
        >
          {showCandidateExplorer ? "✕ Hide" : "◈ Show"} Candidate Explorer
        </button>
        <span style={{ fontSize: 11, color: "#94a3b8" }}>
          Ranked encoding candidates · evidence · why-not breakdown · IOCs / LOLBins / MITRE
        </span>
      </div>
      {showCandidateExplorer && input && input.trim().length > 0 && (
        <div style={{ padding: "0 16px 12px", display: "grid", gridTemplateColumns: "1fr 340px", gap: 12 }}>
          <CandidateExplorer
            input={input}
            testidPrefix="workspace-candidate-explorer"
          />
          <InvestigationTimeline
            input={input}
            testidPrefix="workspace-timeline"
          />
        </div>
      )}

      {/* MoE Analyst Panel toggle */}
      <div
        style={{
          padding: "8px 16px",
          display: "flex",
          alignItems: "center",
          gap: 10,
          borderTop: "1px solid #1e293b",
        }}
      >
        <button
          className={`nvx-btn sm ${showMoePanel ? "" : "ghost"}`}
          onClick={() => setShowMoePanel((v) => !v)}
          data-testid="toggle-moe-panel"
        >
          {showMoePanel ? "✕ Hide" : "▣ Show"} MoE Analyst Panel
        </button>
        <span style={{ fontSize: 11, color: "#94a3b8" }}>
          3-critic panel · Malware Analyst · Red Team · Defensive · Synthesiser (consensus + disagreements)
        </span>
      </div>
      {showMoePanel && input && input.trim().length > 0 && (
        <div style={{ padding: "0 16px 12px" }}>
          <MoEPanel input={input} testidPrefix="workspace-moe-panel" />
        </div>
      )}

      {/* ▲ SOC EVIDENCE-DRIVEN VERDICT CARD (Feb-2026) — always renders
          when the backend produces a verdict_card block. Consolidates
          Verdict · Confidence · Reason · Indicators · Recommended Action
          into a single analyst-facing panel so the SOC responder doesn't
          re-assemble the picture from 4 separate places. */}
      {verdictCard && (
        <div style={{ padding: "0 16px 12px" }}>
          <VerdictCard verdict={verdictCard} testidPrefix="workspace-verdict" />
        </div>
      )}

      {/* Feb-2026: ✎ Refine launcher — one button per surface. Analysts
          click the surface that has a wrong finding, pick which specific
          MITRE / IOC / LOLBIN / family / risk value is wrong inside the
          modal, then submit a correction with the 4-verdict picker. */}
      {(analysis || verdictCard) && (
        <div
          data-testid="refine-launcher-strip"
          style={{
            padding: "0 16px 10px", display: "flex", gap: 6, flexWrap: "wrap",
            fontFamily: "JetBrains Mono", fontSize: 10, alignItems: "center",
          }}
        >
          <span style={{ color: "var(--text-mute)", letterSpacing: "0.14em" }}>
            ✎ TEACH NIVXRAY —
          </span>
          {[
            ["mitre",  "MITRE"],
            ["ioc",    "IOC"],
            ["lolbas", "LOLBAS"],
            ["family", "FAMILY"],
            ["risk",   "RISK"],
          ].map(([surface, label]) => (
            <button
              key={surface}
              type="button"
              className="nvx-btn sm ghost"
              data-testid={`btn-refine-${surface}`}
              title={`Refine a wrong ${label} finding`}
              onClick={() => openRefine(surface,
                                        { kind: surface, value: "" })}
              style={{ padding: "2px 8px" }}
            >
              ✎ {label}
            </button>
          ))}
        </div>
      )}

      {/* 3-column layout */}
      <div className="nvx-workspace-grid">
        <OperationsPanel onAdd={addOp} />

        {/* Center column */}
        <section style={{ display: "flex", flexDirection: "column", minWidth: 0, overflow: "auto" }}>
          {/* Input Card */}
          <div className="nvx-card" data-testid="input-card">
            <div className="nvx-card-head">
              <div className="nvx-card-title">
                <span className="dot" />
                INPUT
                <span className="count">{input.length} chars</span>
                {plannerHint && (
                  <span className="mono" data-testid="planner-hint-chip"
                        style={{
                          fontSize: 10, padding: "2px 8px", marginLeft: 8,
                          background: "rgba(126,227,201,0.12)",
                          border: "1px solid #7ee3c9", color: "#7ee3c9",
                          letterSpacing: "0.08em", borderRadius: 3,
                        }}
                        title={plannerHint.reason}>
                    💡 {plannerHint.op} · {Math.round((plannerHint.confidence || 0) * 100)}% → try <b>{plannerHint.suggested_button}</b>
                  </span>
                )}
              </div>
              <div className="nvx-card-actions">
                <button className="nvx-btn primary sm" onClick={autoInvestigate} disabled={loading} data-testid="btn-auto-investigate-inline">
                  <Sparkles size={11} /> AUTO INVESTIGATE
                </button>
                <button className="nvx-btn sm" onClick={() => autoDecode({ smart: true })} disabled={loading} data-testid="btn-smart-decode-inline">
                  <Zap size={11} /> DECODE
                </button>
                <button className="nvx-btn sm ghost" onClick={clearAll} data-testid="btn-clear-input"
                        title="Clear everything: input, output, recipe, threat panels, trace, verdict, live preview.">
                  <Trash2 size={11} /> CLEAR
                </button>
              </div>
            </div>
            <div className="nvx-card-body">
              <div style={{ position: "relative" }}>
                <textarea
                  className="nvx-textarea"
                  data-testid="input-textarea"
                  placeholder="Paste anything — PowerShell, base64/hex, AES/RC4 ciphertext, JWT, PE/ELF headers, gzip/bzip2/LZMA, obfuscated JS, defanged IOCs…"
                  value={input}
                  readOnly={inputLocked}
                  onChange={(e) => setInput(e.target.value)}
                onPaste={(e) => {
                  // Client-side auto-detect: race 14 JS decoders against the pasted
                  // string INSIDE the browser (zero network). Surface the top
                  // candidate as an inline "USE THIS RECIPE" hint above the
                  // Recipe panel. If the analyst ignores it, no harm done.
                  const pasted = e.clipboardData?.getData("text") || "";
                  if (pasted.length < 12 || pasted.length > 100_000) return;
                  try {
                    const m = magicLite(pasted, { maxDepth: 3, topN: 3 });
                    if (m.best && m.best.score >= 0.35) {
                      setPasteHint({
                        chain: m.best.chain,
                        score: m.best.score,
                        preview: (m.best.output || "").slice(0, 200),
                        elapsedMs: m.elapsedMs,
                        alternates: m.candidates.slice(1, 3),
                      });
                    } else {
                      setPasteHint(null);
                    }
                  } catch { setPasteHint(null); }
                }}
                rows={6}
                spellCheck={false}
                style={{ height: 180, minHeight: 180, maxHeight: 180, resize: "none", overflowY: "auto" }}
              />
              <InputToolbar
                scope="input-textarea"
                value={input}
                locked={inputLocked}
                onToggleEdit={() => setInputLocked((v) => !v)}
                onClear={() => { setInput(""); setPasteHint(null); }}
              />
              </div>
              {multiChainNotice && (
                <div
                  data-testid="multi-chain-notice"
                  style={{
                    marginTop: 8, padding: "8px 12px",
                    border: "1px solid var(--accent)", borderRadius: 3,
                    background: "rgba(74,168,144,0.10)",
                    fontFamily: "JetBrains Mono", fontSize: 11,
                    display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
                  }}
                >
                  <span style={{ color: "var(--accent)", letterSpacing: "0.14em", fontWeight: 700 }}>
                    ⚡ MULTI-COMMAND CHAIN
                  </span>
                  <span style={{ color: "var(--text-dim)" }}>
                    detected · {multiChainNotice.stages} stages analysed
                    {multiChainNotice.family && ` · ${multiChainNotice.family}`}
                    {multiChainNotice.verdict && ` · ${multiChainNotice.verdict}`}
                  </span>
                  <span style={{ flex: 1 }} />
                  <button
                    className="nvx-btn sm ghost"
                    data-testid="btn-revert-flat-decode"
                    onClick={revertToFlatDecode}
                    disabled={loading}
                    title="Bypass chain routing and decode the whole input as a single blob (useful when newlines are part of the payload itself)."
                  >
                    ▸ ANALYSE AS FLAT BLOB
                  </button>
                  <button
                    className="nvx-btn sm ghost"
                    data-testid="btn-dismiss-multi-chain-notice"
                    onClick={() => setMultiChainNotice(null)}
                  >
                    <X size={11} />
                  </button>
                </div>
              )}
              {pasteHint && (
                <div
                  className="paste-hint"
                  data-testid="paste-hint"
                  style={{
                    marginTop: 8, padding: "10px 12px",
                    border: "1px solid var(--accent)", background: "rgba(74,168,144,0.08)",
                    fontFamily: "JetBrains Mono", fontSize: 11, display: "flex",
                    alignItems: "center", gap: 12, flexWrap: "wrap",
                  }}
                >
                  <span style={{ color: "var(--accent)", letterSpacing: "0.14em", fontWeight: 700 }}>
                    ⚡ AUTO-DETECT ({pasteHint.elapsedMs}ms)
                  </span>
                  <span style={{ color: "var(--text-dim)" }}>
                    likely {pasteHint.chain.map((c) => c.op).join(" → ")} · score {pasteHint.score.toFixed(2)}
                  </span>
                  <span style={{ flex: 1 }} />
                  <button
                    className="nvx-btn sm primary"
                    data-testid="btn-use-paste-recipe"
                    onClick={() => {
                      setSteps(pasteHint.chain.map((c) => ({ op: c.op, args: c.args || {} })));
                      setPasteHint(null);
                      setStatus(`✓ APPLIED CLIENT-SIDE RECIPE (${pasteHint.chain.length} ops)`);
                    }}
                  >
                    ▸ USE THIS RECIPE
                  </button>
                  <button
                    className="nvx-btn sm ghost"
                    data-testid="btn-dismiss-paste-hint"
                    onClick={() => setPasteHint(null)}
                  >
                    <X size={11} /> DISMISS
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Multi-Stage Chain Analysis (opt-in via ADD STAGE button) */}
          {chainReplay ? (
            <ChainReplayView
              record={chainReplay}
              onRestore={restoreChainToWorkspace}
              onClose={() => setChainReplay(null)}
            />
          ) : chainOpen ? (
            <ChainStageEditor
              key={chainEditorKey}
              seedInput={input}
              initialStages={pendingChainStages}
              initialResult={pendingChainResult}
              onSeedConsumed={() => { /* keep single-stage input intact */ }}
              onChainComplete={(reportText, chainData) => {
                // Feb-2026 UX fix — when the Chain Editor is driven
                // directly (no INPUT paste), populate the top OUTPUT
                // panel with the SOC report + light status update so
                // the analyst has a single glance-view.
                if (reportText) setOutput(reportText);
                const agg = chainData?.aggregate || {};
                const risk = agg?.risk || {};
                const fam  = agg?.family || {};
                const conf = Number.isFinite(risk?.score) ? risk.score : null;
                const stageCount = (chainData?.stages || []).length;
                const parts = [
                  `CHAIN COMPLETE · ${stageCount} stage${stageCount === 1 ? "" : "s"}`,
                  risk?.verdict || null,
                  fam?.family || null,
                  conf != null ? `${conf}/100` : null,
                ].filter(Boolean);
                setStatus(parts.join(" · "));
                if (conf != null) setDecodeConfidence(conf);
                setDecodeWinnerEngine("chain");
              }}
            />
          ) : (
            <div style={{ margin: "6px 12px 8px 12px", display: "flex", justifyContent: "flex-end" }}>
              <button
                className="nvx-btn sm ghost"
                data-testid="btn-open-chain-editor"
                onClick={() => setChainOpen(true)}
                title={
                  "Open Multi-Stage Chain Analysis. Decode a series of PowerShell/CMD commands (e.g. Lumma ClickFix)\n" +
                  "as one chain: per-stage deterministic decoding + unified SOC verdict + optional AI narrative for the WHOLE chain.\n\n" +
                  "▸ Paste text with BLANK LINES separating stages to auto-split.\n" +
                  "▸ Compact view auto-activates at 4+ stages."
                }
              >
                + CHAIN MODE (multi-stage)
              </button>
            </div>
          )}

          {/* Recipe */}
          <RecipePanel steps={steps} setSteps={setSteps} ops={ops} />

          {/* ONE-BUTTON pipeline trace */}
          {nivxrayTrace.length > 0 && (
            <div className="brut-border" style={{
              margin: "0 12px 10px 12px", background: "var(--surface)",
              padding: "8px 12px", fontFamily: "JetBrains Mono", fontSize: 11,
            }} data-testid="nivxray-decode-trace">
              <div style={{ color: "var(--accent)", letterSpacing: "0.16em",
                            fontSize: 10, fontWeight: 700, marginBottom: 6 }}>
                NIVXRAY DECODE · PIPELINE TRACE
              </div>
              {nivxrayTrace.map((t, i) => (
                <div key={i} style={{
                  display: "flex", gap: 8, alignItems: "center",
                  padding: "3px 0",
                  borderBottom: i < nivxrayTrace.length - 1 ? "1px dashed var(--border)" : "none",
                }} data-testid={`nvx-trace-step-${i}`}>
                  <span style={{ color: "var(--text-mute)", minWidth: 14 }}>#{i + 1}</span>
                  <span style={{ color: "var(--warn)", minWidth: 110,
                                 textTransform: "uppercase", letterSpacing: "0.1em" }}>
                    {t.step}
                  </span>
                  {t.engine && (
                    <span style={{ color: "var(--accent)" }}>{t.engine}</span>
                  )}
                  {t.confidence !== undefined && (
                    <span style={{ color: "var(--text-dim)" }}>· {t.confidence}%</span>
                  )}
                  <span style={{ color: "var(--text-dim)", flex: 1 }}>{t.note}</span>
                </div>
              ))}
            </div>
          )}

          {/* Learning Feedback Loop — BOOST badge with source + confidence + disable/re-run */}
          {boost && (
            <div style={{ margin: "0 12px" }}>
              <BoostBadge
                boost={boost}
                boostHit={boostHit}
                engine={decodeWinnerEngine}
                onRerun={(opts) => autoDecode({ smart: true, ...opts })}
              />
            </div>
          )}

          {/* Decoding Trace — expandable per-layer view for the deterministic decoder */}
          {decodeTrace.length > 0 && (
            <div style={{ margin: "0 12px" }}>
              <DecodingTracePanel
                trace={decodeTrace}
                engine={decodeWinnerEngine}
                confidence={decodeConfidence}
                reachedShellcode={reachedShellcode}
                onJumpToLayer={(i) => {
                  const layer = decodeTrace[i];
                  if (layer && !layer.error) {
                    setOutput(layer.output_preview || "");
                    setStatus(`▸ JUMPED TO LAYER ${i + 1} · ${layer.op}`);
                  }
                }}
              />
            </div>
          )}

          {/* Detected banner */}
          {detected && (
            <div className="detect-banner fade-in" data-testid="detected-banner"
              style={{
                margin: "0 12px", padding: "10px 12px", border: "1px solid var(--accent)",
                background: "rgba(74,168,144,0.08)", color: "var(--accent)",
                fontFamily: "JetBrains Mono", fontSize: 11, letterSpacing: "0.06em",
                display: "flex", alignItems: "center", gap: 8,
              }}
            >
              <span style={{ background: "var(--accent)", color: "#0a0a0c", padding: "2px 8px", fontWeight: 700, letterSpacing: "0.14em" }}>
                {'>_'}
              </span>
              <span style={{ fontWeight: 700 }}>{detected.label.toUpperCase()}</span>
              <span style={{ color: "var(--text-mute)", marginLeft: "auto" }}>{output.length} decoded chars</span>
            </div>
          )}

          {/* v1.5.1 — Zero-Miss Escalation Ladder */}
          {analysis?.layer_trace && Array.isArray(analysis.layer_trace) && analysis.layer_trace.length > 0 && (
            <EscalationLadder
              trace={analysis.layer_trace}
              winner={analysis.engine}
              confidence={analysis.confidence ?? analysis.score}
            />
          )}

          {/* v1.5.5 — TI Shield · 360° per-layer intelligence */}
          {Array.isArray(analysis?.ti_shield) && analysis.ti_shield.length > 0 && (
            <TIShieldPanel layers={analysis.ti_shield} />
          )}

          {/* Output Card — real-time preview + view toggles + byte diff */}
          <OutputView
            input={input}
            output={output}
            livePreview={livePreview}
            actions={<>
              <button className="nvx-btn sm" onClick={() => analyze({ describe: true, aiVerdict: true })} disabled={analyzing || !output} data-testid="btn-ai-describe">
                <Sparkles size={11} /> AI DESCRIBE
              </button>
              <button className="nvx-btn sm" onClick={() => analyze({})} disabled={analyzing || (!input && !output)} data-testid="btn-analyze">
                ANALYZE + OSINT
              </button>
              <button className="nvx-btn sm ghost" onClick={() => navigator.clipboard.writeText(output)} disabled={!output} data-testid="btn-copy-output">
                <Copy size={11} /> COPY
              </button>
              <button
                className="nvx-btn sm"
                style={{ background: "#dc2626", color: "#fff", borderColor: "#7f1d1d" }}
                onClick={() => setBadDecodeOpen(true)}
                disabled={!input}
                data-testid="btn-report-bad-decode"
                title="Report a bad / undecoded output — get AI-generated diagnosis"
              >
                REPORT BAD DECODE
              </button>
              <button
                className="nvx-btn sm"
                style={{ background: "#0f766e", color: "#fff", borderColor: "#134e4a" }}
                onClick={enrichIocs}
                disabled={
                  enrichingIocs ||
                  !(analysis?.iocs && Object.values(analysis.iocs).some((v) => Array.isArray(v) && v.length))
                }
                data-testid="btn-enrich-iocs"
                title="Push extracted IOCs to VirusTotal / OTX / AbuseIPDB for reputation lookup"
              >
                {enrichingIocs ? "ENRICHING…" : "ENRICH IOCs"}
              </button>
            </>}
          />

          {/* IOC enrichment pills — populated after ENRICH IOCs is clicked */}
          {iocEnrichment && iocEnrichment.length > 0 && (
            <div className="nvx-card" data-testid="ioc-enrichment-card">
              <div className="nvx-card-head">
                <div className="nvx-card-title">
                  <span className="dot" style={{ background: "#0f766e" }} />
                  IOC ENRICHMENT
                  <span className="count">{iocEnrichment.length} IOCs enriched</span>
                </div>
              </div>
              <div className="nvx-card-body" style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {iocEnrichment.map((e, i) => {
                  const isError = typeof e.value === "string" &&
                                  (e.value.startsWith("enrichment failed") ||
                                   e.value.startsWith("provider unavailable") ||
                                   e.error);
                  const bad = isError ||
                              (e.malicious_score || 0) > 0 ||
                              (e.abuse_confidence || 0) > 25 ||
                              (e.otx_pulses || 0) > 0;
                  const bg = isError ? "#991b1b" : (bad ? "#7f1d1d" : "#134e4a");
                  // v1.5.3 · richer pill label — surface OTX pulses + AbuseIPDB confidence
                  const badges = [];
                  if (!isError && e.malicious_score) badges.push(`VT:${e.malicious_score}`);
                  if (!isError && e.abuse_confidence) badges.push(`AB:${e.abuse_confidence}%`);
                  if (!isError && e.otx_pulses) badges.push(`OTX:${e.otx_pulses}`);
                  const label = isError
                    ? e.value
                    : e.value + (badges.length ? ` · ${badges.join(" · ")}` : "");
                  const icon = isError ? "⚠️ " : (bad ? "🔴 " : "🟢 ");
                  return (
                    <span
                      key={i}
                      data-testid={`ioc-pill-${i}${isError ? "-error" : ""}`}
                      style={{
                        background: bg, color: "#fff", padding: "6px 12px",
                        borderRadius: 999, fontSize: 11, letterSpacing: 0.6,
                        border: `1px solid ${isError ? "#dc2626" : "rgba(255,255,255,0.15)"}`,
                      }}
                      title={JSON.stringify(e.providers || {}, null, 2)}
                    >
                      {icon}
                      {label}
                    </span>
                  );
                })}
              </div>
            </div>
          )}

          {/* Bad-decode feedback modal */}
          <BadDecodeModal
            open={badDecodeOpen}
            onClose={() => setBadDecodeOpen(false)}
            rawInput={input}
            observedOutput={output}
            observedChain={(analysis?.chain?.steps || analysis?.chain || []).map?.((s) => s?.op || s) || []}
          />

          {/* Attack Graph Card — Tactical MITRE ATT&CK swim-lane */}
          {analysis?.description?.entity_graph?.nodes?.length > 0 && (
            <div className="nvx-card" data-testid="attack-graph-card">
              <div className="nvx-card-head">
                <div className="nvx-card-title">
                  <span className="dot" style={{ background: "var(--warn)" }} />
                  ATTACK GRAPH
                  <span className="count">
                    {analysis.description.entity_graph.nodes.length} entities · {(analysis.description.entity_graph.edges || []).length} relations
                  </span>
                </div>
                {tacticFilter && (
                  <div className="nvx-card-actions">
                    <span className="badge warn" data-testid="tactic-filter-badge">
                      FILTER · {tacticFilter}
                    </span>
                    <button className="nvx-btn sm ghost" onClick={() => setTacticFilter(null)} data-testid="btn-clear-tactic-filter">
                      <X size={11} /> CLEAR
                    </button>
                  </div>
                )}
              </div>
              <div className="nvx-card-body">
                <AttackGraph
                  nodes={analysis.description.entity_graph.nodes}
                  edges={analysis.description.entity_graph.edges || []}
                  selectedTactic={tacticFilter}
                  onTacticClick={(t) => setTacticFilter((cur) => cur === t ? null : t)}
                />
              </div>
            </div>
          )}

          {/* Kill-Chain Path Card — G1/G2 toggle. Renders as soon as we have
              ANY decode signal (chain / output / IOCs / lolbins), synthesising
              a graph on the fly if the AI describe hasn't run yet.

              Feb 2026 · Stability Fix: the Kill-Chain Path card now ALWAYS
              uses the deterministic synth graph. The LLM narrative graph is
              async and used to overwrite this card ~10-30 s after page load,
              which analysts perceived as "the graph keeps changing". The
              AI narrative graph now stays exclusively in the TACTICAL
              SWIM-LANE card above, so each card has one stable source. */}
          {(() => {
            const hasDecodeSignal = !!(
              output || input ||
              (analysis?.chain && (Array.isArray(analysis.chain) ? analysis.chain.length : (analysis.chain.steps || []).length)) ||
              (analysis?.iocs && Object.values(analysis.iocs).some((v) => Array.isArray(v) && v.length)) ||
              (analysis?.lolbins && analysis.lolbins.length) ||
              (analysis?.mitre && analysis.mitre.length)
            );
            if (!hasDecodeSignal) return null;

            const graph = buildFallbackGraph({ input, output, analysis, verdict: verdictCard });
            const source = "synth";

            return (
              <div className="nvx-card" data-testid="attack-path-card">
                <div className="nvx-card-head">
                  <div className="nvx-card-title">
                    <span className="dot" style={{ background: "#38bdf8" }} />
                    {graphView === "path" ? "G1 · KILL-CHAIN PATH" : "G2 · TACTICAL (ALT)"}
                    <span className="count">
                      {graphView === "path"
                        ? `${graph.nodes.length} nodes · ${graph.edges.length} edges · deterministic`
                        : "MITRE swim-lane (mirrors top card)"}
                    </span>
                  </div>
                  <div className="nvx-card-actions">
                    <div style={{ display: "inline-flex", border: "1px solid var(--border)",
                                  borderRadius: 4, overflow: "hidden" }}
                         data-testid="attack-path-view-toggle">
                      <button
                        className={`nvx-btn sm ${graphView === "path" ? "" : "ghost"}`}
                        onClick={() => setGraphView("path")}
                        data-testid="btn-graph-view-path"
                        title="G1 — Clean kill-chain path (entry → choke → crown jewel)"
                        style={{ borderRadius: 0, borderRight: "1px solid var(--border)" }}
                      >
                        G1
                      </button>
                      <button
                        className={`nvx-btn sm ${graphView === "tactical" ? "" : "ghost"}`}
                        onClick={() => setGraphView("tactical")}
                        data-testid="btn-graph-view-tactical"
                        title="G2 — MITRE tactical swim-lane"
                        style={{ borderRadius: 0 }}
                      >
                        G2
                      </button>
                    </div>
                  </div>
                </div>
                <div className="nvx-card-body">
                  {graphView === "path" ? (
                    <AttackPathClean nodes={graph.nodes} edges={graph.edges} />
                  ) : (
                    <AttackGraph
                      nodes={graph.nodes}
                      edges={graph.edges}
                      selectedTactic={tacticFilter}
                      onTacticClick={(t) => setTacticFilter((cur) => cur === t ? null : t)}
                    />
                  )}
                </div>
              </div>
            );
          })()}

          {/* Predicted Process Tree — appears once we have decoded output */}
          {(output || input) && (
            <ProcessTreeView
              raw={input}
              decoded={output || input}
              autoFetch={false}
              onTreeReady={setPredictedTree}
            />
          )}

          {/* Final Summary — executive briefing derived from AI describe */}
          {analysis?.description && (
            <FinalSummary
              description={analysis.description}
              verdict={analysis.ai_verdict}
              risk={analysis.risk}
              jobId={analysis.job_id}
              playbooksUsed={analysis.playbooks_used || []}
            />
          )}

          {/* Shellcode view — auto-renders when the magic decoder flags binary output */}
          {(shellcodeFlag || isShellcodeClient) && output && (
            <div data-testid="shellcode-view">
              <ShellcodeView output={output} />
            </div>
          )}
        </section>

        <ThreatAnalysis
          analysis={analysis}
          loading={analyzing}
          selectedTactic={tacticFilter}
          onClearTactic={() => setTacticFilter(null)}
          rawInput={input}
          decodedOutput={output}
          decodeTrace={decodeTrace}
          decodeEngine={decodeWinnerEngine}
          decodeConfidence={decodeConfidence}
          reachedShellcode={reachedShellcode}
          onRerunFromNode={(layerIdx) => {
            const layer = decodeTrace[layerIdx];
            if (layer && !layer.error) {
              setOutput(layer.output_preview || "");
              setSteps(decodeTrace.slice(0, layerIdx + 1).map((t) => ({ op: t.op, args: t.args || {} })));
              setStatus(`▸ RE-RUNNING FROM LAYER ${layerIdx + 1} (${layer.op})`);
            }
          }}
        />
      </div>

      {showMagic && magicResults && (
        <div
          data-testid="magic-modal"
          style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 50, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}
          onClick={(e) => { if (e.target === e.currentTarget) setShowMagic(false); }}
        >
          <div className="brut-border" style={{ background: "var(--surface)", maxWidth: 1000, width: "100%", maxHeight: "85vh", display: "flex", flexDirection: "column" }}>
            <div style={{ padding: "14px 18px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div className="mono" style={{ fontSize: 12, color: "var(--warn)", letterSpacing: "0.22em" }}>
                ▸ MAGIC — {magicResults.top_results?.length || 0} CANDIDATE CHAINS · explored {magicResults.candidates_explored} paths
              </div>
              <button className="nvx-btn sm ghost" onClick={() => setShowMagic(false)} data-testid="btn-magic-close">
                <X size={11} /> CLOSE
              </button>
            </div>
            <div style={{ overflow: "auto", padding: 16, display: "grid", gap: 12 }}>
              {(magicResults.top_results || []).map((r, i) => (
                <MagicResultCard key={i} r={r} idx={i} onApply={() => applyMagicResult(r)} />
              ))}
            </div>
          </div>
        </div>
      )}

      {shareUrl && (
        <div
          className="brut-border"
          style={{
            position: "fixed", right: 20, bottom: 20, background: "var(--surface)",
            padding: 12, maxWidth: 420,
          }}
          data-testid="share-toast"
        >
          <div className="mono" style={{ fontSize: 10, color: "var(--accent)", letterSpacing: "0.2em", marginBottom: 4 }}>
            SHARE URL COPIED TO CLIPBOARD
          </div>
          <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", wordBreak: "break-all" }}>{shareUrl}</div>
          <button className="nvx-btn sm ghost" style={{ marginTop: 6 }} onClick={() => setShareUrl("")}>DISMISS</button>
        </div>
      )}

      <HistoryDrawer
        open={historyOpen}
        onClose={() => setHistoryOpen(false)}
        onRehydrate={rehydrateFromHistory}
      />

      {/* Feb-2026 · Analyst-corrections modal — opened by ✎ launcher strip */}
      <CorrectionRefineModal
        open={refineOpen}
        onClose={() => setRefineOpen(false)}
        surface={refineCtx?.surface}
        wrongFinding={refineCtx?.wrong_finding || {}}
        inputText={input}
        defaultTags={[]}
        onRerun={autoInvestigate}
      />
    </div>
  );
}


/**
 * MagicResultCard — one candidate row inside the /decode/magic modal.
 *
 * When the candidate is flagged as shellcode by the backend
 * (`is_shellcode:true`), an inline `🔬 ANALYZE BINARY` toggle appears that
 * expands a full `ShellcodeView` (Capstone disassembly + IOC panel) directly
 * inside the modal — no need to Apply Chain first.
 */
function MagicResultCard({ r, idx, onApply }) {
  const [expanded, setExpanded] = useState(false);
  const sb = r.score_breakdown || {};
  return (
    <div className="brut-border" style={{ padding: 12, background: "var(--inset)" }}
         data-testid={`magic-result-${idx}`}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
        <div className="mono" style={{ fontSize: 12, color: "var(--accent)" }}>
          #{idx + 1} · SCORE <b style={{ color: "var(--warn)" }}>{sb.score}</b>
          {sb.printable !== undefined && ` · printable=${sb.printable}`}
          {sb.english !== undefined && ` · english=${sb.english}`}
          {r.is_shellcode && (
            <span className="badge" data-testid={`magic-result-${idx}-shellcode-badge`}
                  style={{ marginLeft: 8, background: "var(--high)22", color: "var(--high)", border: "1px solid var(--high)" }}>
              ⚠ SHELLCODE · {r.stop_condition?.reason?.replace(/_/g, " ")}
            </span>
          )}
        </div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {r.is_shellcode && (
            <button
              className="nvx-btn sm ghost"
              onClick={() => setExpanded((v) => !v)}
              data-testid={`btn-magic-analyze-binary-${idx}`}
              style={{ borderColor: "var(--high)", color: "var(--high)" }}
            >
              <Sparkles size={11} /> {expanded ? "HIDE BINARY" : "🔬 ANALYZE BINARY"}
            </button>
          )}
          <button className="nvx-btn sm primary" onClick={onApply} data-testid={`btn-magic-apply-${idx}`}>
            <Play size={11} /> APPLY CHAIN
          </button>
        </div>
      </div>
      <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 8 }}>
        chain: {r.chain?.length ? r.chain.map((c) => c.op).join(" → ") : "(no ops — input already clean)"}
      </div>
      {sb.reasons?.length > 0 && (
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 8 }}>
          {sb.reasons.map((rr, ri) => <span key={ri} className="badge">{rr}</span>)}
        </div>
      )}
      <pre className="mono" style={{
        margin: 0, padding: 8, background: "var(--bg)", border: "1px solid var(--border)",
        fontSize: 11, color: "var(--text)", maxHeight: 160, overflow: "auto",
        whiteSpace: "pre-wrap", wordBreak: "break-all",
      }}>{(r.output || "").slice(0, 1200)}{(r.output || "").length > 1200 ? "…" : ""}</pre>

      {r.is_shellcode && expanded && (
        <div style={{ marginTop: 10 }} data-testid={`magic-shellcode-view-${idx}`}>
          <ShellcodeView output={r.output || ""} />
        </div>
      )}
    </div>
  );
}
