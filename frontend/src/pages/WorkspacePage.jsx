import { useEffect, useState, useRef, useMemo } from "react";
import Header from "@/components/Header";
import OperationsPanel from "@/components/OperationsPanel";
import RecipePanel from "@/components/RecipePanel";
import ThreatAnalysis from "@/components/ThreatAnalysis";
import ReportMenu from "@/components/ReportMenu";
import AttackGraph from "@/components/AttackGraph";
import FinalSummary from "@/components/FinalSummary";
import ShellcodeView from "@/components/ShellcodeView";
import OutputView from "@/components/OutputView";
import { runClientRecipe } from "@/lib/clientOps";
import { magicLite } from "@/lib/magicLite";
import { detectShellcode } from "@/lib/shellcodeDetect";
import SocVerdictPanel from "@/components/SocVerdictPanel";
import DecodingTracePanel from "@/components/DecodingTracePanel";
import HistoryDrawer from "@/components/HistoryDrawer";
import ProcessTreeView from "@/components/ProcessTreeView";
import BoostBadge from "@/components/BoostBadge";
import ChainStageEditor from "@/components/ChainStageEditor";
import api from "@/lib/api";
import { streamAnalyze } from "@/lib/sse";
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
  // Decoding Trace panel — per-layer intermediate outputs from the deterministic decoder
  const [decodeTrace, setDecodeTrace] = useState([]);
  const [reachedShellcode, setReachedShellcode] = useState(false);
  // Client-side auto-detect on paste — 14 decoders raced instantly to surface a suggestion
  const [pasteHint, setPasteHint] = useState(null);
  // History drawer
  const [historyOpen, setHistoryOpen] = useState(false);
  // Predicted process tree (fed to both ProcessTreeView + SocVerdictPanel mini)
  const [predictedTree, setPredictedTree] = useState(null);
  // Learning Feedback Loop
  const [boost, setBoost] = useState(null);
  const [boostHit, setBoostHit] = useState(false);
  // ONE-BUTTON UX — collapse Smart/AI/Auto Investigate/Troubleshoot into ADVANCED
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [chainOpen, setChainOpen] = useState(false);
  const [nivxrayTrace, setNivxrayTrace] = useState([]);
  const rehydrateFromHistory = (rec) => {
    if (!rec) return;
    setInput(rec.input_preview || "");
    setOutput(rec.output_preview || "");
    setDecodeTrace(rec.trace || []);
    setDecodeWinnerEngine(rec.engine || null);
    setDecodeConfidence(rec.confidence ?? null);
    setReachedShellcode(!!rec.reached_shellcode);
    setSteps((rec.chain || []).map((op) => ({ op, args: {} })));
    setChain((rec.chain || []).map((op, i) => ({
      op, reason: rec.trace?.[i]?.reason || "",
      output_preview: rec.trace?.[i]?.output_preview || "",
    })));
    setAnalysis({ iocs: rec.iocs || {}, mitre: rec.mitre || [], ai_verdict: rec.verdict });
    setStatus(`▸ RESTORED FROM HISTORY (${rec.engine} · ${rec.confidence}%)`);
    setHistoryOpen(false);
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
    try { localStorage.removeItem("nvx.pendingInput"); } catch {}
  };


  // ─── ONE-BUTTON orchestrator ─────────────────────────────────────────
  // Auto-runs: (1) archetype/boost/deterministic via Smart Decode, then
  //           (2) AI fallback (Auto Investigate) if confidence < 40.
  // Fires a live trace so the analyst sees exactly what happened.
  const nivxrayDecode = async () => {
    if (!input.trim()) { setStatus("PROVIDE INPUT FIRST"); return; }
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

  const autoDecode = async ({ smart = false, disable_boost = false } = {}) => {
    if (!input.trim()) { setStatus("PROVIDE INPUT FIRST"); return; }
    setLoading(true);
    setStatus(smart ? "SMART-DECODING (DETERMINISTIC)..." : "AI AUTO-DECODING...");
    try {
      const url = smart ? "/decode/smart" : "/ai/auto-decode";
      const payload = smart ? { input, disable_boost } : { input };
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
                    {/nivx\s*cognis/i.test(p.name) ? "★ PERSONA · " : "PERSONA · "}{p.name}
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
                {providers.map((p) => <option key={p.id} value={p.id}>LLM · {p.name}</option>)}
              </select>
            )}
          </div>
        )}

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
                style={{ fontSize: 13, padding: "8px 18px" }}>
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
                }>
          <Sparkles size={13} /> AUTO INVESTIGATE
        </button>
        <button className="nvx-btn" onClick={() => autoDecode({ smart: false })} disabled={loading} data-testid="btn-auto-decode"
                title={
                  "AI DECODE — LLM proposes a recipe (base64/gzip/XOR/etc.) with SOC anti-hallucination guard.\n" +
                  "Runs AI plan AND deterministic magic in parallel, picks the higher-confidence winner.\n\n" +
                  "▸ USE WHEN: the payload is unusual and you want the LLM to reason about the format.\n" +
                  "▸ SAFETY: if confidence < 35/100 it STOPS gracefully (no garbage output).\n" +
                  "▸ COST: 1 LLM call (~3–8s). Uses selected Persona + LLM (default NivX Cognis + Claude).\n" +
                  "▸ RETURNS: recipe + confidence % + winner engine + graceful-stop message if applicable."
                }>
          <Wand2 size={13} /> AI DECODE
        </button>
        <button className="nvx-btn" onClick={() => autoDecode({ smart: true })} disabled={loading} data-testid="btn-smart-decode"
                title={
                  "SMART DECODE — Fully deterministic. No AI. Fast.\n" +
                  "Rule-based recipe selection using signature prefixes (H4sI→gzip, JAB/SQBF→UTF-16LE, TVq→PE, XOR-loop sniffer, etc).\n\n" +
                  "▸ USE WHEN: you need repeatable results (regression tests, high-volume automation, air-gapped ops).\n" +
                  "▸ COST: <100ms, no LLM. Zero hallucination by design.\n" +
                  "▸ LIMITATION: only recognises known signatures. Falls back to no-op on unknown formats."
                }>
          <Zap size={13} /> SMART DECODE
        </button>
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
        <span className="mono" style={{ fontSize: 10, color: "var(--accent)", letterSpacing: "0.2em" }}>
          ● STATUS
        </span>
        <span className="mono" data-testid="status-line" style={{ fontSize: 11, color: "var(--text-dim)" }}>
          {status}
        </span>
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
              <textarea
                className="nvx-textarea"
                data-testid="input-textarea"
                placeholder="Paste anything — PowerShell, base64/hex, AES/RC4 ciphertext, JWT, PE/ELF headers, gzip/bzip2/LZMA, obfuscated JS, defanged IOCs…"
                value={input}
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
          {chainOpen ? (
            <ChainStageEditor
              seedInput={input}
              onSeedConsumed={() => { /* keep single-stage input intact */ }}
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
            </>}
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
