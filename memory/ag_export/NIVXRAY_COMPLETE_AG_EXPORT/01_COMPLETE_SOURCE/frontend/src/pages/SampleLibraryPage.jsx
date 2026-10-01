import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/lib/auth";
import Header from "@/components/Header";
import PageHeader from "@/components/PageHeader";
import api from "@/lib/api";
import {
  Plus, Trash2, Save, Play, ChevronRight, ChevronDown,
  Upload, Check, X, AlertTriangle, BarChart3, Beaker,
} from "lucide-react";

const CATEGORY_COLORS = {
  PowerShell: "#4aa890", CMD: "#c58af9", Bash: "#f7c17b", Python: "#4aa890",
  JavaScript: "#e2b93b", ".NET": "#c58af9", LOLBAS: "#e27e5d", "Malware Family": "#d96c6c",
  Compression: "#4aa890", Crypto: "#e2b93b", "Multi-stage": "#e27e5d", "Living-off-the-Land": "#d96c6c",
};

export default function SampleLibraryPage() {
  const { user } = useAuth();
  const [samples, setSamples] = useState([]);
  const [dashboard, setDashboard] = useState(null);
  const [filter, setFilter] = useState("");
  const [editing, setEditing] = useState(null);
  const [bulkJson, setBulkJson] = useState("");
  const [showBulk, setShowBulk] = useState(false);
  const [bench, setBench] = useState(null);
  const [benching, setBenching] = useState(false);
  const [error, setError] = useState("");

  const load = async () => {
    try {
      const [s, d] = await Promise.all([
        api.get(filter ? `/admin/samples?category=${encodeURIComponent(filter)}` : "/admin/samples"),
        api.get("/admin/samples/dashboard"),
      ]);
      setSamples(s.data); setDashboard(d.data);
    } catch (e) { setError(e?.response?.data?.detail || e.message); }
  };
  // `load` is stable within the component; only `user` / `filter` should re-trigger.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { if (user?.role === "admin") load(); }, [user, filter]);

  if (user?.role !== "admin") {
    return (<div style={{ minHeight: "100vh", background: "var(--bg)" }}><Header /><div style={{ padding: 40 }}>Admin only.</div></div>);
  }

  const cats = dashboard?.categories_available || [];
  const catCounts = dashboard?.by_category || {};

  const startNew = () => setEditing({ id: null, name: "", raw_input: "", expected_output: "",
    categories: [], tags: [], expected_mitre: [], expected_iocs: [],
    difficulty: "medium", source_url: "", notes: "" });

  const save = async () => {
    if (!editing) return;
    try {
      if (editing.id) {
        await api.put(`/admin/samples/${editing.id}`, editing);
      } else {
        await api.post("/admin/samples", editing);
      }
      setEditing(null); await load();
    } catch (e) { setError(e?.response?.data?.detail || e.message); }
  };

  const remove = async (id) => {
    if (!window.confirm("Delete sample?")) return;
    try { await api.delete(`/admin/samples/${id}`); await load(); }
    catch (e) { alert(e?.response?.data?.detail || e.message); }
  };

  const importJson = async () => {
    try {
      const parsed = JSON.parse(bulkJson);
      const arr = Array.isArray(parsed) ? parsed : [parsed];
      const r = await api.post("/admin/samples/bulk", { samples: arr });
      alert(`Imported ${r.data.created}, failed ${r.data.failed}`);
      setBulkJson(""); setShowBulk(false); await load();
    } catch (e) { alert(e?.response?.data?.detail || e.message); }
  };

  const runBenchmarkAll = async () => {
    setBenching(true); setBench(null);
    try {
      const r = await api.post("/admin/samples/benchmark/all", {}, { timeout: 180000 });
      setBench(r.data); await load();
    } catch (e) { setError(e?.response?.data?.detail || e.message); }
    finally { setBenching(false); }
  };

  const benchOne = async (id) => {
    try {
      const r = await api.post(`/admin/samples/${id}/benchmark`, {}, { timeout: 60000 });
      // Merge result into current sample
      setSamples((prev) => prev.map((s) => s.id === id ? { ...s, last_bench_result: r.data } : s));
    } catch (e) { alert(e?.response?.data?.detail || e.message); }
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg)" }} data-testid="sample-library-page">
      <Header />
      <div style={{ padding: 24, maxWidth: 1500, margin: "0 auto" }}>
        <PageHeader
          testId="samples-hero"
          eyebrow="Regression Corpus · Feb 2026"
          title="Sample Library"
          subtitle="Real-world encoded / obfuscated payloads paired with their expected decoded output. Continuous regression testing keeps NivXRay's decoder coverage growing without breaking existing samples. Nightly benchmark runs automatically."
          icon={Beaker}
          tone="accent"
        />

        {/* Coverage dashboard */}
        {dashboard && (
          <div className="brut-border" style={{ background: "var(--surface)", padding: 16, marginBottom: 20 }} data-testid="sl-dashboard">
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
              <div className="mono" style={{ fontSize: 12, color: "var(--accent)", letterSpacing: "0.22em" }}>
                <BarChart3 size={12} style={{ display: "inline", marginRight: 6 }} /> COVERAGE · {dashboard.total_samples} SAMPLES
              </div>
              {dashboard.latest_run && (
                <span className="badge">
                  LAST RUN {new Date(dashboard.latest_run.at).toLocaleString()} ·
                  {" "}{dashboard.latest_run.passed}/{dashboard.latest_run.total} passed
                </span>
              )}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: 10 }}>
              {Object.entries(dashboard.by_category).map(([cat, count]) => {
                const passStats = dashboard.latest_run?.coverage?.[cat];
                const pct = passStats?.pass_pct;
                const color = pct === undefined ? "var(--text-mute)"
                            : pct >= 95 ? "var(--accent)"
                            : pct >= 70 ? "var(--warn)" : "var(--high)";
                return (
                  <div key={cat} className="brut-border" style={{ padding: 10, background: "var(--inset)" }} data-testid={`sl-cov-${cat}`}>
                    <div className="mono" style={{ fontSize: 11, color: color, fontWeight: 700 }}>{cat}</div>
                    <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 3 }}>
                      {count} sample{count !== 1 ? "s" : ""}
                      {passStats && ` · ${passStats.passed}/${passStats.total} pass · ${passStats.pass_pct}%`}
                    </div>
                    {passStats && (
                      <div style={{ marginTop: 6, height: 4, background: "var(--bg)", borderRadius: 0 }}>
                        <div style={{ width: `${passStats.pass_pct}%`, height: "100%", background: color }} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Toolbar */}
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <button className="nvx-btn primary" onClick={startNew} data-testid="sl-btn-new"><Plus size={12} /> NEW SAMPLE</button>
          <button className="nvx-btn" onClick={() => setShowBulk(!showBulk)} data-testid="sl-btn-import"><Upload size={12} /> IMPORT JSON</button>
          <button className="nvx-btn" onClick={runBenchmarkAll} disabled={benching} data-testid="sl-btn-bench-all"
                  style={{ borderColor: "var(--warn)", color: "var(--warn)" }}>
            <Play size={12} /> {benching ? "BENCHMARKING..." : "RUN BENCHMARK"}
          </button>
          <div style={{ flex: 1 }} />
          <select className="brut-input" value={filter} onChange={(e) => setFilter(e.target.value)}
                  style={{ padding: "4px 8px", fontSize: 11, height: 30, background: "var(--inset)" }} data-testid="sl-filter">
            <option value="">{`ALL CATEGORIES (${dashboard?.total_samples || 0})`}</option>
            {cats.map((c) => <option key={c} value={c}>{`${c} (${catCounts[c] || 0})`}</option>)}
          </select>
        </div>

        {error && (
          <div className="brut-border" style={{ padding: 10, background: "rgba(217,108,108,0.1)", borderColor: "var(--high)", marginBottom: 12, color: "var(--high)", fontSize: 12 }}>
            <AlertTriangle size={12} style={{ marginRight: 6 }} /> {error}
            <button className="nvx-btn sm ghost" style={{ float: "right" }} onClick={() => setError("")}><X size={11} /></button>
          </div>
        )}

        {/* Bulk import */}
        {showBulk && (
          <div className="brut-border" style={{ padding: 14, marginBottom: 12, background: "var(--inset)" }}>
            <div className="mono" style={{ fontSize: 11, color: "var(--accent)", letterSpacing: "0.2em", marginBottom: 8 }}>▸ BULK IMPORT · JSON ARRAY</div>
            <textarea className="brut-input" style={{ minHeight: 160, fontFamily: "JetBrains Mono, monospace", fontSize: 11 }}
              placeholder='[{"name":"…","raw_input":"…","expected_output":"…","categories":["PowerShell"],"expected_mitre":["T1059.001"]}]'
              value={bulkJson} onChange={(e) => setBulkJson(e.target.value)} data-testid="sl-bulk-json" />
            <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
              <button className="nvx-btn primary" onClick={importJson} data-testid="sl-btn-bulk-save"><Save size={12} /> IMPORT</button>
              <button className="nvx-btn ghost" onClick={() => { setBulkJson(""); setShowBulk(false); }}>CANCEL</button>
            </div>
          </div>
        )}

        {/* Sample list */}
        <div style={{ display: "grid", gap: 8 }} data-testid="sl-list">
          {samples.map((s) => (
            <SampleRow key={s.id} sample={s}
                       onEdit={() => setEditing(s)}
                       onDelete={() => remove(s.id)}
                       onBench={() => benchOne(s.id)} />
          ))}
          {samples.length === 0 && (
            <div className="mono" style={{ color: "var(--text-mute)", fontSize: 12, padding: 20, textAlign: "center", border: "1px dashed var(--border)" }}>
              No samples in this category yet.
            </div>
          )}
        </div>

        {/* Editor */}
        {editing && (
          <div className="brut-border" style={{ background: "var(--inset)", padding: 20, marginTop: 20 }} data-testid="sl-editor">
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
              <div className="mono" style={{ fontSize: 12, color: "var(--accent)", letterSpacing: "0.2em" }}>
                ▸ {editing.id ? "EDIT" : "NEW"} SAMPLE
              </div>
              <button className="nvx-btn sm ghost" onClick={() => setEditing(null)}><X size={11} /> CLOSE</button>
            </div>
            <div style={{ display: "grid", gap: 10 }}>
              <TextField label="Name" value={editing.name} onChange={(v) => setEditing({ ...editing, name: v })} testid="sl-input-name" />
              <TextArea label="Raw input (encoded)" value={editing.raw_input} onChange={(v) => setEditing({ ...editing, raw_input: v })} rows={5} testid="sl-input-raw" />
              <TextArea label="Expected output (substring match)" value={editing.expected_output} onChange={(v) => setEditing({ ...editing, expected_output: v })} rows={3} testid="sl-input-expected" />
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <div>
                  <Label>Categories (comma-separated)</Label>
                  <input className="brut-input" value={(editing.categories || []).join(", ")}
                         onChange={(e) => setEditing({ ...editing, categories: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })}
                         placeholder="PowerShell, LOLBAS" data-testid="sl-input-categories" />
                </div>
                <div>
                  <Label>Difficulty</Label>
                  <select className="brut-input" value={editing.difficulty || "medium"} onChange={(e) => setEditing({ ...editing, difficulty: e.target.value })}>
                    <option value="easy">EASY</option>
                    <option value="medium">MEDIUM</option>
                    <option value="hard">HARD</option>
                  </select>
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <div>
                  <Label>Expected MITRE IDs</Label>
                  <input className="brut-input" value={(editing.expected_mitre || []).join(", ")}
                         onChange={(e) => setEditing({ ...editing, expected_mitre: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })}
                         placeholder="T1059.001, T1105" />
                </div>
                <div>
                  <Label>Expected IOCs</Label>
                  <input className="brut-input" value={(editing.expected_iocs || []).join(", ")}
                         onChange={(e) => setEditing({ ...editing, expected_iocs: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })}
                         placeholder="http://evil.com/x" />
                </div>
              </div>
              <TextField label="Source URL" value={editing.source_url || ""} onChange={(v) => setEditing({ ...editing, source_url: v })} />
              <TextArea label="Notes" value={editing.notes || ""} onChange={(v) => setEditing({ ...editing, notes: v })} rows={3} />
              <div style={{ display: "flex", gap: 8 }}>
                <button className="nvx-btn primary" onClick={save} data-testid="sl-btn-save"><Save size={12} /> SAVE</button>
                <button className="nvx-btn ghost" onClick={() => setEditing(null)}>CANCEL</button>
              </div>
            </div>
          </div>
        )}

        {/* Benchmark result */}
        {bench && (
          <div className="brut-border" style={{ background: "var(--surface)", padding: 16, marginTop: 20 }} data-testid="sl-bench-result">
            <div className="mono" style={{ fontSize: 12, color: "var(--warn)", letterSpacing: "0.2em", marginBottom: 8 }}>
              ▸ LATEST BENCHMARK · {bench.passed}/{bench.total} passed ({bench.pass_pct}%)
            </div>
            {bench.results.filter((r) => !r.overall_pass).map((r, i) => (
              <div key={i} className="brut-border" style={{ padding: 10, marginTop: 8, background: "var(--inset)", borderColor: "var(--high)" }}>
                <div className="mono" style={{ fontSize: 11, color: "var(--high)" }}>✗ {r.name}</div>
                <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 4 }}>
                  smart chain: {r.engines?.smart?.chain?.join(" → ") || r.engines?.smart?.error || "n/a"}
                </div>
                <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)" }}>
                  magic chains: {(r.engines?.magic?.top_result_chains || []).map((c) => c.join("→")).join("  |  ") || r.engines?.magic?.error || "n/a"}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SampleRow({ sample, onEdit, onDelete, onBench }) {
  const [expand, setExpand] = useState(false);
  const bench = sample.last_bench_result;
  const pass = bench?.overall_pass;
  return (
    <div className="brut-border" style={{ background: "var(--surface)" }} data-testid={`sl-row-${sample.id}`}>
      <div style={{ padding: 12, display: "grid", gridTemplateColumns: "22px 1fr auto", gap: 10, alignItems: "center", cursor: "pointer" }}
           onClick={() => setExpand(!expand)}>
        {expand ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        <div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            {bench && (pass
              ? <span className="badge safe" data-testid={`sl-row-badge-${sample.id}`}><Check size={10} /> PASS</span>
              : <span className="badge high" data-testid={`sl-row-badge-${sample.id}`}><X size={10} /> FAIL</span>
            )}
            <span className="mono" style={{ fontSize: 12, color: "var(--text)", fontWeight: 700 }}>{sample.name}</span>
            {sample.protected && <span className="badge">BUILT-IN</span>}
            <span className="badge">{sample.difficulty}</span>
          </div>
          <div style={{ display: "flex", gap: 4, marginTop: 4, flexWrap: "wrap" }}>
            {(sample.categories || []).map((c) => (
              <span key={c} className="badge" style={{ borderColor: CATEGORY_COLORS[c] || "var(--border)", color: CATEGORY_COLORS[c] || "var(--text-mute)" }}>{c}</span>
            ))}
          </div>
        </div>
        <div style={{ display: "flex", gap: 6 }} onClick={(e) => e.stopPropagation()}>
          <button className="nvx-btn sm" onClick={onBench} data-testid={`sl-bench-${sample.id}`}><Play size={10} /> BENCH</button>
          <button className="nvx-btn sm ghost" onClick={onEdit}>EDIT</button>
          {!sample.protected && (
            <button className="nvx-btn sm ghost" onClick={onDelete}
                    style={{ borderColor: "var(--high)", color: "var(--high)" }}><Trash2 size={11} /></button>
          )}
        </div>
      </div>
      {expand && (
        <div style={{ padding: "0 16px 14px", borderTop: "1px solid var(--border)", background: "var(--inset)" }}>
          <Label>RAW INPUT</Label>
          <pre className="mono" style={{ fontSize: 10, color: "var(--text-mute)", background: "var(--bg)", padding: 8, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 120, overflow: "auto" }}>
            {sample.raw_input}
          </pre>
          <Label>EXPECTED OUTPUT (substring)</Label>
          <pre className="mono" style={{ fontSize: 10, color: "var(--accent)", background: "var(--bg)", padding: 8, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 100, overflow: "auto" }}>
            {sample.expected_output}
          </pre>
          {sample.notes && (
            <>
              <Label>NOTES</Label>
              <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", lineHeight: 1.5 }}>{sample.notes}</div>
            </>
          )}
          {bench && (
            <>
              <Label>LATEST BENCHMARK</Label>
              <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)" }}>
                smart: {bench.engines?.smart?.passed ? "✓" : "✗"} · chain: {bench.engines?.smart?.chain?.join(" → ") || bench.engines?.smart?.error}
              </div>
              <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 3 }}>
                magic: {bench.engines?.magic?.passed ? "✓" : "✗"} · best hit: {bench.engines?.magic?.best_hit_chain?.join(" → ") || "none"}
              </div>
              {bench.engines?.smart?.output_preview && (
                <details style={{ marginTop: 6 }}>
                  <summary className="mono" style={{ fontSize: 10, color: "var(--text-mute)", cursor: "pointer" }}>Show smart-decoder output preview</summary>
                  <pre className="mono" style={{ fontSize: 10, color: "var(--text-dim)", background: "var(--bg)", padding: 8, marginTop: 4, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 100, overflow: "auto" }}>{bench.engines.smart.output_preview}</pre>
                </details>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function Label({ children }) {
  return <div className="mono" style={{ fontSize: 10, letterSpacing: "0.16em", color: "var(--text-mute)", marginTop: 8, marginBottom: 4, textTransform: "uppercase" }}>{children}</div>;
}
function TextField({ label, value, onChange, testid }) {
  return (
    <div>
      <Label>{label}</Label>
      <input className="brut-input" value={value} onChange={(e) => onChange(e.target.value)} data-testid={testid} />
    </div>
  );
}
function TextArea({ label, value, onChange, rows = 4, testid }) {
  return (
    <div>
      <Label>{label}</Label>
      <textarea className="brut-input" value={value} onChange={(e) => onChange(e.target.value)}
                style={{ minHeight: rows * 20, fontFamily: "JetBrains Mono, monospace", fontSize: 11 }} data-testid={testid} />
    </div>
  );
}
