import { useEffect, useState, useCallback, useRef } from "react";
import api from "@/lib/api";
import Header from "@/components/Header";
import { Upload, Trash2, RefreshCw, FileText, Download, Zap } from "lucide-react";

const ACCEPT = ".pdf,.doc,.docx,.csv,.xls,.xlsx,.json,.jsonl,.txt,.log,.eml,.msg,.html,.htm,.xml,.md,.yml,.yaml,.ps1,.bat,.sh,.py,.js,.vbs";
const PREVIEWABLE = /\.(json|jsonl|txt|log|eml|html|htm|xml|md|yml|yaml|csv|ps1|bat|sh|py|js|vbs|pdf|docx|xlsx)$/i;

export default function DocumentsPage() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [busy, setBusy] = useState(null);
  const [preview, setPreview] = useState(null);
  const inputRef = useRef(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get("/documents", { params: { limit: 200 } });
      setItems(r.data.items || []);
      setTotal(r.data.total || 0);
    } catch (e) {
      console.warn("documents load failed:", e);
    }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const upload = async (files) => {
    if (!files || !files.length) return;
    setUploading(true);
    for (const f of files) {
      const fd = new FormData();
      fd.append("file", f);
      try {
        await api.post("/documents/upload", fd, {
          headers: { "Content-Type": "multipart/form-data" },
        });
      } catch (e) {
        alert(`Upload of "${f.name}" failed: ${e?.response?.data?.detail || e.message}`);
      }
    }
    setUploading(false);
    load();
  };

  const remove = async (item) => {
    if (!window.confirm(`Delete "${item.filename}"?`)) return;
    try {
      await api.delete(`/documents/${item.id}`);
      setItems((prev) => prev.filter((d) => d.id !== item.id));
    } catch (e) {
      alert("Delete failed: " + (e?.response?.data?.detail || e.message));
    }
  };

  const download = (item) => {
    const url = `${api.defaults.baseURL}/documents/${item.id}/download`;
    // Include auth via a temporary blob fetch
    api.get(`/documents/${item.id}/download`, { responseType: "blob" }).then((r) => {
      const blob = new Blob([r.data]);
      const u = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = u; a.download = item.filename; document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(u);
    });
  };

  const doPreview = async (item) => {
    setBusy(item.id);
    try {
      const r = await api.get(`/documents/${item.id}/preview`);
      setPreview({ item, data: r.data });
    } catch (e) {
      alert("Preview failed: " + (e?.response?.data?.detail || e.message));
    }
    setBusy(null);
  };

  const reinvestigate = async (item) => {
    setBusy(item.id);
    try {
      const r = await api.post(`/documents/${item.id}/re-investigate`, {});
      const cn = r.data;
      alert(
        `Re-investigated "${item.filename}"\n\n` +
        `Verdict: ${cn.verdict_card?.verdict || "?"} · ${cn.verdict_card?.risk_score || 0}/100\n` +
        `Engine:  ${cn.engine}\n` +
        `Chain:   ${(cn.chain || []).join(" → ")}\n` +
        `IOCs:    urls=${(cn.iocs?.urls || []).length} ips=${(cn.iocs?.ips || []).length}\n` +
        `MITRE:   ${(cn.mitre || []).length} techniques\n` +
        `History id: ${cn.history_id || "n/a"}`
      );
      load();
    } catch (e) {
      alert("Re-investigate failed: " + (e?.response?.data?.detail || e.message));
    }
    setBusy(null);
  };

  const batchDecode = async (item) => {
    if (!window.confirm(
      `BATCH DECODE will extract EVERY command-line from "${item.filename}" and run each ` +
      `through the deterministic pipeline. Each result is auto-saved as a Case (browsable ` +
      `in the CASES drawer with SIGMA export). This may take 1-5 minutes for large files. Continue?`
    )) return;
    setBusy(item.id);
    try {
      const r = await api.post(`/documents/${item.id}/batch-decode`, { max_lines: 500 }, { timeout: 600000 });
      const d = r.data;
      const c = d.counts || {};
      const total = d.extracted_lines || 0;
      const verified = (d.results || []).filter(x => x.verified).length;
      alert(
        `═══ BATCH DECODE COMPLETE ═══\n\n` +
        `File: ${d.filename}\n` +
        `Extracted lines: ${total}\n\n` +
        `VERDICT BREAKDOWN:\n` +
        `  Malicious:      ${c.malicious || 0}\n` +
        `  Partial:        ${c.partial || 0}\n` +
        `  Suspicious:     ${c.suspicious || 0}\n` +
        `  Undecoded:      ${c.undecoded || 0}\n` +
        `  Benign:         ${c.benign || 0}\n` +
        `  Error:          ${c.error || 0}\n\n` +
        `HONEST COVERAGE:\n` +
        `  Verified (real evidence): ${verified} (${((verified/total)*100).toFixed(1)}%)\n` +
        `  Unverified (wrapper only): ${total - verified} (${(((total-verified)/total)*100).toFixed(1)}%)\n\n` +
        `Cases saved to Case Library — open CASES drawer to browse.`
      );
      load();
    } catch (e) {
      alert("Batch decode failed: " + (e?.response?.data?.detail || e.message));
    }
    setBusy(null);
  };

  const ingest = async (item) => {
    setBusy(item.id);
    try {
      const r = await api.post(`/documents/${item.id}/ingest-fixture`);
      alert(`Ingest ${r.data.ok ? "OK" : "FAILED"}\n\nSTDOUT:\n${r.data.stdout || "(empty)"}\n\nSTDERR:\n${r.data.stderr || "(empty)"}`);
      load();
    } catch (e) {
      alert("Ingest failed: " + (e?.response?.data?.detail || e.message));
    }
    setBusy(null);
  };

  const fmtBytes = (n) => {
    if (n == null) return "?";
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <>
      <Header />
      <div style={{ padding: "20px 24px", maxWidth: 1300, margin: "0 auto" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 18 }}>
        <span className="mono" style={{ fontSize: 22, letterSpacing: "0.24em", color: "var(--accent)", fontWeight: 700 }}>
          📂 DOCUMENTS
        </span>
        <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }} data-testid="docs-total">
          {items.length} / {total} · {fmtBytes(items.reduce((s, i) => s + (i.length || 0), 0))} total
        </span>
        <div style={{ flex: 1 }} />
        <button className="nvx-btn" onClick={() => inputRef.current?.click()}
                disabled={uploading} data-testid="btn-docs-upload"
                style={{ borderColor: "var(--accent)", color: "var(--accent)" }}>
          <Upload size={12} /> {uploading ? "UPLOADING…" : "UPLOAD FILES"}
        </button>
        <button className="nvx-btn ghost" onClick={load} data-testid="btn-docs-refresh">
          <RefreshCw size={11} /> REFRESH
        </button>
        <input ref={inputRef} type="file" multiple hidden accept={ACCEPT}
               onChange={(e) => upload(Array.from(e.target.files || []))}
               data-testid="input-docs-file" />
      </div>

      <div className="mono" style={{ fontSize: 10, color: "var(--text-dim)", marginBottom: 14, letterSpacing: "0.06em" }}>
        Supported: PDF · DOC · DOCX · CSV · XLS · XLSX · JSON · TXT · EML · HTML · MD · YAML · PS1 · BAT · SH · PY · JS · VBS · LOG (max 25 MB per file)
      </div>

      <div style={{ border: "1px solid var(--border)" }}>
        <div className="mono" style={{
          display: "grid", gridTemplateColumns: "1fr 90px 120px 160px 380px",
          padding: "8px 12px", background: "var(--inset)",
          fontSize: 10, letterSpacing: "0.14em", color: "var(--text-dim)",
          borderBottom: "1px solid var(--border)",
        }}>
          <div>FILENAME</div>
          <div>SIZE</div>
          <div>TYPE</div>
          <div>UPLOADED</div>
          <div style={{ textAlign: "right" }}>ACTIONS</div>
        </div>
        {loading && <div className="mono" style={{ padding: 20, fontSize: 11, color: "var(--text-dim)" }}>loading…</div>}
        {!loading && items.length === 0 && (
          <div className="mono" style={{ padding: 24, textAlign: "center", fontSize: 11, color: "var(--text-dim)" }}>
            No documents. Click UPLOAD FILES to add your first case export or artefact.
          </div>
        )}
        {items.map((d) => {
          const isJson = /\.(json|jsonl)$/i.test(d.filename);
          const canPreview = PREVIEWABLE.test(d.filename);
          return (
            <div key={d.id} data-testid={`doc-row-${d.id}`}
                 className="mono" style={{
                   display: "grid", gridTemplateColumns: "1fr 90px 120px 160px 380px",
                   padding: "10px 12px", borderBottom: "1px solid var(--border)",
                   alignItems: "center", fontSize: 11,
                 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <FileText size={12} style={{ color: "var(--accent)" }} />
                <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={d.filename}>
                  {d.filename}
                </span>
                {d.ingested && (
                  <span style={{ fontSize: 9, color: "#22c55e", border: "1px solid #22c55e", padding: "1px 4px" }}>FIXTURE</span>
                )}
                {d.reinvestigated && (
                  <span style={{ fontSize: 9, color: "#7ee3c9", border: "1px solid #7ee3c9", padding: "1px 4px" }}>RE-INVESTIGATED</span>
                )}
              </div>
              <div style={{ color: "var(--text-dim)" }}>{fmtBytes(d.length)}</div>
              <div style={{ color: "var(--text-dim)" }}>.{d.ext || "?"}</div>
              <div style={{ color: "var(--text-dim)", fontSize: 10 }}>
                {(d.upload_date || "").slice(0, 19).replace("T", " ")}
              </div>
              <div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                {canPreview && (
                  <button className="nvx-btn sm ghost" onClick={() => doPreview(d)}
                          disabled={busy === d.id} data-testid={`btn-doc-preview-${d.id}`}>
                    PREVIEW
                  </button>
                )}
                <button className="nvx-btn sm ghost" onClick={() => reinvestigate(d)}
                        disabled={busy === d.id} data-testid={`btn-doc-reinvestigate-${d.id}`}
                        title="Extract text payload and run through /decode/smart"
                        style={{ borderColor: "#7ee3c9", color: "#7ee3c9" }}>
                  <Zap size={10} /> {busy === d.id ? "…" : "DECODE"}
                </button>
                <button className="nvx-btn sm ghost" onClick={() => batchDecode(d)}
                        disabled={busy === d.id} data-testid={`btn-doc-batch-decode-${d.id}`}
                        title="BATCH DECODE — split into command-lines, decode EACH, auto-save as Cases (~1-5 min)"
                        style={{ borderColor: "#f59e0b", color: "#f59e0b" }}>
                  <Zap size={10} /> BATCH
                </button>
                {isJson && (
                  <button className="nvx-btn sm ghost" onClick={() => ingest(d)}
                          disabled={busy === d.id} data-testid={`btn-doc-ingest-${d.id}`}
                          title="Ingest this IR-export JSON as a CI regression fixture"
                          style={{ borderColor: "#22c55e", color: "#22c55e" }}>
                    INGEST
                  </button>
                )}
                <button className="nvx-btn sm ghost" onClick={() => download(d)}
                        data-testid={`btn-doc-download-${d.id}`}>
                  <Download size={10} />
                </button>
                <button className="nvx-btn sm ghost" onClick={() => remove(d)}
                        data-testid={`btn-doc-delete-${d.id}`}>
                  <Trash2 size={10} />
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {preview && (
        <div data-testid="doc-preview-modal"
             style={{
               position: "fixed", inset: 0, zIndex: 60,
               background: "rgba(0,0,0,0.6)",
               display: "flex", alignItems: "center", justifyContent: "center",
             }}
             onClick={(e) => { if (e.target === e.currentTarget) setPreview(null); }}>
          <div className="brut-border" style={{
            width: "min(1000px, 92vw)", height: "min(720px, 90vh)",
            background: "var(--surface)", display: "flex", flexDirection: "column",
          }}>
            <div style={{
              padding: "10px 14px", borderBottom: "1px solid var(--border)",
              display: "flex", alignItems: "center", gap: 10,
            }}>
              <span className="mono" style={{ fontSize: 11, color: "var(--accent)", letterSpacing: "0.16em" }}>
                📄 PREVIEW · {preview.item.filename}
              </span>
              <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>
                {preview.data.kind} · {fmtBytes(preview.data.length)}
              </span>
              <div style={{ flex: 1 }} />
              <button className="nvx-btn sm ghost" onClick={() => setPreview(null)} data-testid="btn-doc-preview-close">CLOSE</button>
            </div>
            <pre className="mono" style={{
              flex: 1, margin: 0, padding: 14, overflow: "auto",
              fontSize: 12, lineHeight: 1.5, whiteSpace: "pre-wrap",
              background: "var(--inset)", color: "var(--text)",
            }}>{preview.data.content}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
