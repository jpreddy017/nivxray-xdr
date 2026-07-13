import { useEffect, useState, useRef } from "react";
import Header from "@/components/Header";
import OperationsPanel from "@/components/OperationsPanel";
import RecipePanel from "@/components/RecipePanel";
import ThreatAnalysis from "@/components/ThreatAnalysis";
import api from "@/lib/api";
import {
  Play, Zap, Wand2, Wrench, Share2, Download, Upload, Trash2, Copy, Sparkles,
} from "lucide-react";

export default function WorkspacePage() {
  const [ops, setOps] = useState([]);
  const [examples, setExamples] = useState([]);
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [steps, setSteps] = useState([]);
  const [detected, setDetected] = useState(null);
  const [chain, setChain] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [status, setStatus] = useState("READY");
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [shareUrl, setShareUrl] = useState("");
  const fileRef = useRef(null);

  useEffect(() => {
    api.get("/operations").then((r) => setOps(r.data)).catch(() => {});
    api.get("/examples").then((r) => setExamples(r.data)).catch(() => {});
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

  const autoDecode = async ({ smart = false } = {}) => {
    if (!input.trim()) { setStatus("PROVIDE INPUT FIRST"); return; }
    setLoading(true);
    setStatus(smart ? "SMART-DECODING (DETERMINISTIC)..." : "AI AUTO-DECODING...");
    try {
      const url = smart ? "/decode/smart" : "/ai/auto-decode";
      const r = await api.post(url, { input });
      setSteps((r.data.recipe || []).map((s) => ({ op: s.op, args: s.args || {} })));
      setOutput(r.data.output || "");
      setDetected(r.data.detected_type || null);
      setChain((r.data.recipe || []).map((s, i) => ({
        op: s.op, reason: s.reason || "",
        output_preview: r.data.steps_output?.[i]?.output_preview || "",
      })));
      setStatus(r.data.reasoning ? `AI: ${r.data.reasoning.slice(0, 120)}` : "SMART DECODE COMPLETE");
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setLoading(false);
    }
  };

  const analyze = async ({ describe = false, aiVerdict = false } = {}) => {
    if (!input.trim() && !output.trim()) { setStatus("PROVIDE INPUT OR OUTPUT FIRST"); return; }
    setAnalyzing(true);
    setStatus(describe ? "ANALYZING + AI DESCRIBE..." : "ANALYZING...");
    try {
      const r = await api.post("/analyze", {
        input, output, enrich_osint: true, describe, use_ai_verdict: aiVerdict,
      });
      setAnalysis({ ...r.data, chain });
      setStatus("ANALYSIS COMPLETE");
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setAnalyzing(false);
    }
  };

  const autoInvestigate = async () => {
    if (!input.trim()) { setStatus("PROVIDE INPUT FIRST"); return; }
    setLoading(true); setAnalyzing(true);
    setStatus("AUTO-INVESTIGATE: DECODING + OSINT + AI...");
    try {
      const r = await api.post("/ai/auto-investigate", { input });
      setSteps((r.data.recipe || []).map((s) => ({ op: s.op, args: s.args || {} })));
      setOutput(r.data.output || "");
      setDetected(r.data.detected_type || null);
      const newChain = (r.data.recipe || []).map((s, i) => ({
        op: s.op, reason: s.reason || "",
        output_preview: r.data.steps_output?.[i]?.output_preview || "",
      }));
      setChain(newChain);
      setAnalysis({ ...r.data.analysis, chain: newChain });
      setStatus(`INVESTIGATION COMPLETE · ${r.data.analysis?.risk?.verdict || ""}`);
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setLoading(false); setAnalyzing(false);
    }
  };

  const troubleshoot = async () => {
    setLoading(true);
    setStatus("TROUBLESHOOTING WITH AI...");
    try {
      const r = await api.post("/ai/troubleshoot", { input, steps, error: null });
      if (r.data.suggested_steps?.length) {
        setSteps(r.data.suggested_steps.map((s) => ({ op: s.op, args: s.args || {} })));
        setStatus(`DIAGNOSIS: ${r.data.diagnosis?.slice(0, 140)}`);
      } else {
        setStatus("NO SUGGESTIONS RETURNED");
      }
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

  const downloadReport = async () => {
    try {
      const r = await api.post("/report", { input, output });
      const blob = new Blob([r.data.report], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = r.data.filename; a.click();
      URL.revokeObjectURL(url);
      setStatus("REPORT DOWNLOADED");
    } catch (e) {
      setStatus("REPORT FAILED: " + e.message);
    }
  };

  const onUpload = async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const fd = new FormData();
    fd.append("file", f);
    try {
      const r = await api.post("/upload", fd, { headers: { "Content-Type": "multipart/form-data" } });
      setInput(r.data.content);
      setStatus(`FILE LOADED: ${r.data.filename} (${r.data.size} bytes)`);
    } catch (e2) {
      setStatus("UPLOAD FAILED: " + e2.message);
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
        <span className="badge">42 OPS</span>
        <span className="badge warn">MITRE</span>
        <span className="badge warn">YARA</span>
        <span className="badge warn">IOC</span>
        <span className="badge warn">OSINT</span>
        <div style={{ flex: 1 }} />

        <button className="nvx-btn primary" onClick={autoInvestigate} disabled={loading} data-testid="btn-auto-investigate">
          <Sparkles size={13} /> AUTO INVESTIGATE
        </button>
        <button className="nvx-btn" onClick={() => autoDecode({ smart: false })} disabled={loading} data-testid="btn-auto-decode">
          <Wand2 size={13} /> AI DECODE
        </button>
        <button className="nvx-btn" onClick={() => autoDecode({ smart: true })} disabled={loading} data-testid="btn-smart-decode">
          <Zap size={13} /> SMART DECODE
        </button>
        <button className="nvx-btn" onClick={runRecipe} disabled={loading || !steps.length} data-testid="btn-run-recipe">
          <Play size={13} /> RUN RECIPE
        </button>
        <button className="nvx-btn warn" onClick={troubleshoot} disabled={loading} data-testid="btn-troubleshoot">
          <Wrench size={13} /> TROUBLESHOOT
        </button>
        <button className="nvx-btn" onClick={doShare} data-testid="btn-share"><Share2 size={13} /> SHARE</button>
        <button className="nvx-btn" onClick={downloadReport} data-testid="btn-download-report"><Download size={13} /> REPORT</button>
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

      {/* 3-column layout */}
      <div
        style={{
          flex: 1,
          display: "grid",
          gridTemplateColumns: "300px 1fr 380px",
          minHeight: 0,
        }}
      >
        <OperationsPanel onAdd={addOp} />

        {/* Center column */}
        <section style={{ display: "flex", flexDirection: "column", minWidth: 0, overflow: "hidden" }}>
          {/* Input */}
          <div style={{ padding: 14, borderBottom: "1px solid var(--border)" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
              <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>
                ▸ INPUT
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                <button className="nvx-btn sm ghost" onClick={() => setInput("")} data-testid="btn-clear-input">
                  <Trash2 size={11} /> CLEAR
                </button>
              </div>
            </div>
            <textarea
              className="nvx-textarea"
              data-testid="input-textarea"
              placeholder="Paste payload — PowerShell, base64, hex, gzip, defanged IOCs, XSS, JS charcode…"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              rows={7}
              spellCheck={false}
            />
          </div>

          {/* Recipe */}
          <RecipePanel steps={steps} setSteps={setSteps} ops={ops} />

          {/* Output */}
          <div style={{ padding: 14, flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
              <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>
                ▸ OUTPUT
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                <button className="nvx-btn sm" onClick={() => analyze({ describe: true, aiVerdict: true })} disabled={analyzing || !output} data-testid="btn-ai-describe">
                  <Sparkles size={11} /> AI DESCRIBE
                </button>
                <button className="nvx-btn sm" onClick={() => analyze({})} disabled={analyzing || (!input && !output)} data-testid="btn-analyze">
                  ANALYZE + OSINT
                </button>
                <button className="nvx-btn sm ghost" onClick={() => navigator.clipboard.writeText(output)} disabled={!output} data-testid="btn-copy-output">
                  <Copy size={11} /> COPY
                </button>
              </div>
            </div>

            {detected && (
              <div className="detect-banner fade-in" data-testid="detected-banner"
                style={{
                  padding: "8px 12px", border: "1px solid var(--accent)",
                  background: "rgba(74,168,144,0.08)", color: "var(--accent)",
                  marginBottom: 8, fontFamily: "JetBrains Mono", fontSize: 11,
                  letterSpacing: "0.06em",
                }}
              >
                ◉ {detected.label.toUpperCase()}
              </div>
            )}

            <textarea
              className="nvx-textarea"
              data-testid="output-textarea"
              value={output}
              readOnly
              rows={9}
              placeholder="Run a recipe, press SMART DECODE, or hit AUTO INVESTIGATE…"
              style={{ flex: 1, minHeight: 160 }}
            />
          </div>
        </section>

        <ThreatAnalysis analysis={analysis} loading={analyzing} />
      </div>

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
    </div>
  );
}
