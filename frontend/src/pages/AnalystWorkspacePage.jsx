/*
 * Analyst Workspace (v2) — customer-facing MCIP surface.
 *
 * Pastes an encoded/obfuscated command → deterministic report:
 *   • Executive Summary
 *   • Verdict + Explainable Confidence Breakdown
 *   • Malware Family
 *   • Decode Timeline
 *   • IOC Cards
 *   • MITRE ATT&CK Mapping
 *   • LOLBAS Detection
 *   • Investigation Recommendations
 *   • Plugin Execution Report
 *   • One-click download (Markdown / JSON / plain text)
 *
 * UI principle: page stays responsive during analysis (button locked +
 * skeleton state; no blocking modal).
 */
import React, { useState, useMemo, useCallback } from "react";
import api, { API_BASE } from "@/lib/api";

const verdictBadge = {
  malicious:    "bg-red-600/20 text-red-300 border-red-500/40",
  suspicious:   "bg-amber-500/20 text-amber-200 border-amber-500/40",
  needs_review: "bg-sky-500/20 text-sky-200 border-sky-500/40",
  benign:       "bg-emerald-500/20 text-emerald-200 border-emerald-500/40",
  unknown:      "bg-slate-500/20 text-slate-200 border-slate-500/40",
};

function Card({ title, children, right }) {
  return (
    <section
      className="border border-slate-700/60 bg-slate-900/40 rounded-xl p-5 shadow-sm"
      data-testid={`analyst-card-${title.toLowerCase().replace(/\s+/g, "-")}`}
    >
      <header className="flex items-center justify-between mb-4">
        <h2 className="text-base font-semibold text-slate-100">{title}</h2>
        {right}
      </header>
      {children}
    </section>
  );
}

function KV({ k, v }) {
  return (
    <div className="flex justify-between border-b border-slate-800/60 py-2 text-sm">
      <span className="text-slate-400">{k}</span>
      <span className="text-slate-100 font-mono text-right max-w-[70%] break-all">{v}</span>
    </div>
  );
}

function DownloadBtn({ label, onClick, testid }) {
  return (
    <button
      onClick={onClick}
      className="px-3 py-1.5 text-sm border border-slate-700 rounded-lg hover:bg-slate-800/60 text-slate-200"
      data-testid={testid}
    >
      {label}
    </button>
  );
}

export default function AnalystWorkspacePage() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState(null);

  const verdictClass = useMemo(
    () => verdictBadge[report?.findings?.verdict] || verdictBadge.unknown,
    [report]
  );

  const runAnalyze = useCallback(async () => {
    if (!input.trim()) return;
    setLoading(true);
    setError("");
    setReport(null);
    try {
      const r = await api.post("/v2/analyze", { input });
      setReport(r.data.report);
    } catch (e) {
      setError(e.friendlyMessage || e.response?.data?.detail || String(e.message || e));
    } finally {
      setLoading(false);
    }
  }, [input]);

  const downloadReport = useCallback(async (fmt) => {
    try {
      const token = localStorage.getItem("nvx_token");
      const r = await fetch(`${API_BASE}/v2/analyze/report?fmt=${fmt}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ input }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const ext = fmt === "md" ? "md" : fmt === "json" ? "json" : fmt === "pdf" ? "pdf" : "txt";
      a.download = `nivxray-analyst-report.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(String(e.message || e));
    }
  }, [input]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 px-6 py-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <header className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">NivXRay · Analyst Workspace</h1>
            <p className="text-sm text-slate-400 mt-1">
              Deterministic Malware Command Intelligence — offline, explainable, plugin-driven.
            </p>
          </div>
          <div className="flex gap-2">
            <a href="/battery" className="text-sm text-slate-400 hover:text-slate-200">Battery</a>
            <a href="/" className="text-sm text-slate-400 hover:text-slate-200">Legacy Workspace</a>
          </div>
        </header>

        {/* Input area */}
        <Card
          title="Command / Payload Input"
          right={
            <button
              onClick={runAnalyze}
              disabled={loading || !input.trim()}
              className="px-4 py-2 text-sm rounded-lg bg-cyan-500/80 hover:bg-cyan-500 disabled:bg-slate-700 disabled:text-slate-500 text-slate-950 font-medium"
              data-testid="analyst-run-btn"
            >
              {loading ? "Analyzing…" : "Run Deterministic Analysis"}
            </button>
          }
        >
          <textarea
            className="w-full min-h-[130px] bg-slate-950/60 border border-slate-800 rounded-lg p-3 font-mono text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            placeholder="Paste an encoded PowerShell / cmd / macro / shellcode-runner payload…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={loading}
            data-testid="analyst-input"
          />
          {error && (
            <div className="mt-3 text-sm text-red-400" data-testid="analyst-error">
              {error}
            </div>
          )}
        </Card>

        {/* Skeleton while loading */}
        {loading && (
          <div className="animate-pulse space-y-4">
            <div className="h-40 bg-slate-800/40 rounded-xl" />
            <div className="h-40 bg-slate-800/40 rounded-xl" />
          </div>
        )}

        {report && (
          <>
            {/* Executive summary + verdict */}
            <Card
              title="Executive Summary"
              right={
                <div className="flex items-center gap-2">
                  <span
                    className={`px-3 py-1 text-xs uppercase tracking-wide rounded-full border ${verdictClass}`}
                    data-testid="analyst-verdict"
                  >
                    {report.findings.verdict}
                  </span>
                  <span
                    className="text-xs text-slate-300 border border-slate-700 rounded-full px-3 py-1"
                    data-testid="analyst-risk"
                  >
                    Risk {report.findings.risk_score}/100
                  </span>
                </div>
              }
            >
              <p className="text-sm leading-relaxed text-slate-200">
                {report.executive_summary}
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                <DownloadBtn testid="dl-pdf"  label="Download PDF"      onClick={() => downloadReport("pdf")} />
                <DownloadBtn testid="dl-md"   label="Download Markdown" onClick={() => downloadReport("md")} />
                <DownloadBtn testid="dl-json" label="Download JSON"     onClick={() => downloadReport("json")} />
                <DownloadBtn testid="dl-txt"  label="Download Text"     onClick={() => downloadReport("txt")} />
              </div>
            </Card>

            {/* Confidence breakdown */}
            {report.confidence_breakdown?.contributions?.length > 0 && (
              <Card title="Why This Score">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-slate-400 text-left border-b border-slate-800">
                      <th className="py-2">Source</th>
                      <th className="py-2 text-right">Points</th>
                      <th className="py-2">Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.confidence_breakdown.contributions.map((c, i) => (
                      <tr key={i} className="border-b border-slate-900">
                        <td className="py-2 text-slate-300 font-mono">{c.source}</td>
                        <td className="py-2 text-right text-cyan-300 font-mono">+{c.points}</td>
                        <td className="py-2 text-slate-400">{c.detail}</td>
                      </tr>
                    ))}
                    <tr>
                      <td className="py-2 font-semibold text-slate-100">Total (capped at 100)</td>
                      <td className="py-2 text-right font-bold text-cyan-300 font-mono">
                        {report.confidence_breakdown.total}
                      </td>
                      <td />
                    </tr>
                  </tbody>
                </table>
              </Card>
            )}

            {/* Malware family */}
            {report.findings.family?.family && report.findings.family.family !== "unknown" && (
              <Card title="Malware Family">
                <KV k="Family"     v={report.findings.family.family} />
                <KV k="Confidence" v={`${(report.findings.family.confidence * 100).toFixed(0)}%`} />
                {report.findings.family.evidence?.length > 0 && (
                  <div className="mt-3 text-sm text-slate-300">
                    <div className="text-slate-400 mb-1">Evidence</div>
                    <ul className="list-disc pl-5 space-y-1">
                      {report.findings.family.evidence.map((e, i) => (
                        <li key={i}>{e}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </Card>
            )}

            {/* Decode timeline */}
            <Card
              title="Decode Timeline"
              right={<span className="text-xs text-slate-500">terminal: <span className="font-mono">{report.terminal}</span></span>}
            >
              {report.trace?.length > 0 ? (
                <div className="space-y-3" data-testid="analyst-timeline">
                  {report.trace.map((s, i) => (
                    <div
                      key={i}
                      className="border border-slate-800 rounded-lg p-3 bg-slate-950/40"
                      data-testid={`timeline-step-${i}`}
                    >
                      <div className="flex justify-between items-start gap-3">
                        <div className="text-slate-100 font-mono text-sm">
                          <span className="text-cyan-400">L{s.layer}</span> · {s.decoder}
                          <span className="text-slate-500 ml-2">({(s.confidence * 100).toFixed(0)}%)</span>
                        </div>
                        <div className="text-xs text-slate-500 font-mono whitespace-nowrap">
                          {s.in_len} → {s.out_len} · {s.exec_ms} ms
                        </div>
                      </div>
                      <div className="text-xs text-slate-400 mt-1">{s.why}</div>
                      {s.preview && (
                        <pre className="mt-2 text-xs bg-slate-950/60 p-2 rounded overflow-x-auto text-slate-300 font-mono max-h-32">
                          {s.preview}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-400">No transforms applied — input appears to be plaintext.</p>
              )}
              <p className="mt-3 text-xs text-slate-500">
                <span className="text-slate-400">Stopped:</span> {report.stopped_reason}
              </p>
            </Card>

            {/* IOC Cards */}
            {(() => {
              const iocs = report.findings.iocs || {};
              const buckets = [
                ["IPs", iocs.ips],
                ["URLs", iocs.urls],
                ["Domains", iocs.domains],
                ["Emails", iocs.emails],
                ["SHA-256", iocs.sha256],
                ["SHA-1", iocs.sha1],
                ["MD5", iocs.md5],
              ].filter(([, v]) => Array.isArray(v) && v.length > 0);
              if (buckets.length === 0) return null;
              return (
                <Card title="Indicators of Compromise">
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3" data-testid="analyst-iocs">
                    {buckets.map(([label, values]) => (
                      <div key={label} className="border border-slate-800 rounded-lg p-3 bg-slate-950/40">
                        <div className="text-xs text-slate-400 uppercase tracking-wide mb-2">{label} ({values.length})</div>
                        <ul className="text-sm font-mono text-slate-200 space-y-1 break-all">
                          {values.slice(0, 8).map((v, i) => (<li key={i}>{v}</li>))}
                          {values.length > 8 && <li className="text-slate-500">…{values.length - 8} more</li>}
                        </ul>
                      </div>
                    ))}
                  </div>
                </Card>
              );
            })()}

            {/* MITRE ATT&CK */}
            {report.findings.mitre_techniques?.length > 0 && (
              <Card title="MITRE ATT&CK Mapping">
                <table className="w-full text-sm" data-testid="analyst-mitre">
                  <thead>
                    <tr className="text-slate-400 text-left border-b border-slate-800">
                      <th className="py-2">Technique</th>
                      <th className="py-2">Name</th>
                      <th className="py-2">Tactic</th>
                      <th className="py-2">Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.findings.mitre_techniques.map((h, i) => (
                      <tr key={i} className="border-b border-slate-900">
                        <td className="py-2 font-mono text-cyan-300">{h.id}</td>
                        <td className="py-2 text-slate-200">{h.technique}</td>
                        <td className="py-2 text-slate-400">{h.tactic}</td>
                        <td className="py-2 text-slate-500 text-xs">{h.evidence}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Card>
            )}

            {/* LOLBAS */}
            {report.findings.lolbas?.length > 0 && (
              <Card title="LOLBAS Detection">
                <ul className="text-sm space-y-2" data-testid="analyst-lolbas">
                  {report.findings.lolbas.map((h, i) => (
                    <li key={i} className="flex justify-between border-b border-slate-800 py-2">
                      <span className="font-mono text-slate-100">{h.binary}</span>
                      <span className="text-xs text-slate-400">{h.technique_id} · {h.evidence}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            )}

            {/* Investigation recommendations */}
            {report.investigation_steps?.length > 0 && (
              <Card title="Recommended Investigation Steps">
                <ol className="space-y-3 text-sm" data-testid="analyst-recommendations">
                  {report.investigation_steps.map((rec, i) => (
                    <li key={i} className="border-l-2 border-cyan-500/40 pl-3">
                      <div className="flex items-baseline gap-2">
                        <span className={`text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full border ${
                          rec.priority === "critical" ? "border-red-500/60 text-red-300" :
                          rec.priority === "high" ? "border-amber-500/60 text-amber-300" :
                          "border-sky-500/60 text-sky-300"
                        }`}>{rec.priority}</span>
                        <span className="text-slate-100 font-medium">{rec.action}</span>
                      </div>
                      {rec.rationale && (
                        <div className="text-xs text-slate-400 mt-1">{rec.rationale}</div>
                      )}
                    </li>
                  ))}
                </ol>
              </Card>
            )}

            {/* Plugin execution report */}
            {report.plugin_report?.entries?.length > 0 && (
              <Card
                title="Plugin Execution Report"
                right={<span className="text-xs text-slate-500 font-mono">{report.plugin_report.layers_run} layers · {report.plugin_report.total_time_ms} ms</span>}
              >
                <table className="w-full text-xs font-mono" data-testid="analyst-plugin-report">
                  <thead>
                    <tr className="text-slate-500 text-left border-b border-slate-800">
                      <th className="py-1">L</th>
                      <th className="py-1">Plugin</th>
                      <th className="py-1">Outcome</th>
                      <th className="py-1 text-right">Conf</th>
                      <th className="py-1">Reason</th>
                      <th className="py-1 text-right">ms</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.plugin_report.entries.map((e, i) => (
                      <tr key={i} className="border-b border-slate-900">
                        <td className="py-1 text-slate-500">{e.layer}</td>
                        <td className="py-1 text-slate-200">{e.plugin}</td>
                        <td className={`py-1 ${
                          e.outcome === "accepted" ? "text-emerald-400" :
                          e.outcome === "decode_error" ? "text-red-400" :
                          "text-slate-500"
                        }`}>{e.outcome}</td>
                        <td className="py-1 text-right text-slate-400">{(e.detect_confidence * 100).toFixed(0)}%</td>
                        <td className="py-1 text-slate-500 max-w-md truncate">{e.reason || e.detect_reason}</td>
                        <td className="py-1 text-right text-slate-400">{e.exec_ms}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Card>
            )}

            {/* Final decoded output */}
            <Card title="Final Decoded Output">
              <pre className="text-xs bg-slate-950/60 p-3 rounded overflow-x-auto max-h-72 text-slate-200 whitespace-pre-wrap font-mono" data-testid="analyst-final-output">
                {report.output?.slice(0, 4000) || "(empty)"}
                {report.output?.length > 4000 && `\n\n… ${report.output.length - 4000} more chars truncated`}
              </pre>
            </Card>
          </>
        )}
      </div>
    </div>
  );
}
