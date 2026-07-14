import { useEffect, useState, useRef } from "react";
import Header from "@/components/Header";
import OperationsPanel from "@/components/OperationsPanel";
import RecipePanel from "@/components/RecipePanel";
import ThreatAnalysis from "@/components/ThreatAnalysis";
import ReportMenu from "@/components/ReportMenu";
import AttackGraph from "@/components/AttackGraph";
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
        <span className="badge">45 OPS</span>
        <span className="badge warn">MITRE</span>
        <span className="badge warn">YARA</span>
        <span className="badge warn">LOLBAS</span>
        <span className="badge warn">IOC</span>
        <span className="badge warn">OSINT</span>
        <span className="badge warn">FLOW</span>
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
                <button className="nvx-btn sm ghost" onClick={() => setInput("")} data-testid="btn-clear-input">
                  <Trash2 size={11} /> CLEAR
                </button>
              </div>
            </div>
            <div className="nvx-card-body">
              <textarea
                className="nvx-textarea"
                data-testid="input-textarea"
                placeholder="Paste payload — PowerShell, base64, hex, gzip, defanged IOCs, XSS, JS charcode…"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                rows={6}
                spellCheck={false}
                style={{ height: 180, minHeight: 180, maxHeight: 180, resize: "none", overflowY: "auto" }}
              />
            </div>
          </div>

          {/* Recipe */}
          <RecipePanel steps={steps} setSteps={setSteps} ops={ops} />

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

          {/* Output Card */}
          <div className="nvx-card" data-testid="output-card">
            <div className="nvx-card-head">
              <div className="nvx-card-title">
                <span className="dot" />
                OUTPUT
              </div>
              <div className="nvx-card-actions">
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
            <div className="nvx-card-body">
              <textarea
                className="nvx-textarea nvx-output-textarea"
                data-testid="output-textarea"
                value={output}
                readOnly
                placeholder="Run a recipe or click AUTO INVESTIGATE to see decoded output here…"
              />
            </div>
          </div>

          {/* Attack Graph Card — Cortex XDR-style entity graph */}
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
              </div>
              <div className="nvx-card-body">
                <AttackGraph
                  nodes={analysis.description.entity_graph.nodes}
                  edges={analysis.description.entity_graph.edges || []}
                />
              </div>
            </div>
          )}
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
