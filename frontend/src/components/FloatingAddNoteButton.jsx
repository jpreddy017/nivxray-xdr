import { useState } from "react";
import { useAuth } from "@/lib/auth";
import { useLocation } from "react-router-dom";
import api from "@/lib/api";
import {
  GraduationCap, X, Save, Link as LinkIcon, Sparkles, RefreshCw,
} from "lucide-react";

/**
 * FloatingAddNoteButton
 * ---------------------
 * Global floating button (bottom-right) visible on every authenticated page.
 * Opens a lightweight modal that creates a new global training note via
 * `POST /admin/models` with `kind=training_note`. Admin-only.
 *
 * URL feature: paste a reference URL (article / CTI report / blog) + click
 * SYNC — backend fetches the page, condenses via Claude Sonnet 4.5 into a
 * directive, and prefills the title + body. The URL is pinned as `ref_url`
 * on the saved note so analysts can jump back to the source.
 */

// High-contrast input styles so the modal is readable on the dark surface.
const INPUT_STYLE = {
  width: "100%",
  fontFamily: "JetBrains Mono, monospace",
  fontSize: 13,
  fontWeight: 600,
  color: "#f8fafc",              // near-white typed text
  background: "#0b1220",         // extra-dark input backdrop
  border: "1px solid #334155",
  padding: "10px 12px",
  outline: "none",
  caretColor: "#7ee3c9",
};
const LABEL_STYLE = {
  fontSize: 10, letterSpacing: "0.16em",
  color: "#94a3b8", marginBottom: 4, textTransform: "uppercase",
  fontWeight: 700,
};

export default function FloatingAddNoteButton() {
  const { user } = useAuth();
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [body, setBody] = useState("");
  const [refUrl, setRefUrl] = useState("");
  const [saving, setSaving] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState("");
  const [syncMeta, setSyncMeta] = useState(null); // {source, fetched, summary}

  if (!user || user.role !== "admin") return null;
  // 2026-02 · Owner nav-consolidation directive — TRAINING NOTE is a
  // documentation authoring tool. It should only appear inside the
  // knowledge / documentation surfaces (Docs · Knowledge Base) so it
  // never clutters the investigation flow. Analysts should not see this
  // floating button on the Workspace, History, Trajectory, Batch,
  // Heatmap, X-Lab, or any other analytical surface.
  const ALLOWED_PATHS = ["/docs", "/kb"];
  const isAllowed = ALLOWED_PATHS.some(
    (p) => pathname === p || pathname.startsWith(p + "/"),
  );
  if (!isAllowed) return null;

  const validUrl = /^https?:\/\/[^\s]+$/i.test(refUrl.trim());

  const syncFromUrl = async () => {
    setError("");
    setSyncMeta(null);
    if (!validUrl) {
      setError("Enter an http(s) URL to sync from.");
      return;
    }
    setSyncing(true);
    try {
      const r = await api.post("/admin/training-notes/sync-url",
                                { url: refUrl.trim() });
      // New envelope (Feb 2026): 200 always; check `ok` flag.
      if (r.data && r.data.ok === false) {
        const msg = r.data.error || "SYNC failed";
        const hint = r.data.hint ? `  ${r.data.hint}` : "";
        setError(`SYNC failed: ${msg}${hint}`);
        return;
      }
      setName(r.data.title || "");
      setBody(r.data.body || "");
      setSyncMeta({
        source: r.data.ref_source,
        fetched: r.data.fetched_chars,
        summary: r.data.summary_chars,
        tags: r.data.tags || [],
      });
    } catch (e) {
      // Fallback for legacy 4xx/5xx paths — parse whatever we can.
      const raw = e?.response?.data;
      const msg = raw?.error || raw?.detail || e?.message || String(e);
      const hint = raw?.hint ? `  ${raw.hint}` : "";
      setError(`SYNC failed: ${msg}${hint}`);
    } finally {
      setSyncing(false);
    }
  };

  const save = async () => {
    if (!name.trim() || !body.trim()) {
      setError("Both title and body are required");
      return;
    }
    const cleanUrl = refUrl.trim();
    if (cleanUrl && !validUrl) {
      setError("Reference URL must start with http:// or https://");
      return;
    }
    setSaving(true);
    setError("");
    try {
      const cfg = { body: body.trim() };
      if (cleanUrl) {
        cfg.ref_url = cleanUrl;
        try { cfg.ref_source = new URL(cleanUrl).hostname; } catch { /* ignore */ }
      }
      if (syncMeta?.tags?.length) cfg.tags = syncMeta.tags;
      await api.post("/admin/models", {
        kind: "training_note",
        name: name.trim(),
        enabled: true,
        config: cfg,
      });
      setName("");
      setBody("");
      setRefUrl("");
      setSyncMeta(null);
      setOpen(false);
    } catch (e) {
      setError(e?.response?.data?.detail || e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      {/* Floating trigger */}
      <button
        onClick={() => setOpen(true)}
        className="nvx-btn primary"
        style={{
          position: "fixed",
          right: 24,
          bottom: 24,
          zIndex: 60,
          padding: "12px 18px",
          borderRadius: 0,
          boxShadow: "0 6px 20px rgba(0,0,0,0.35)",
          fontSize: 12,
          letterSpacing: "0.14em",
        }}
        title="Add global AI training note (always-on directive)"
        data-testid="floating-add-training-note-btn"
      >
        <GraduationCap size={13} /> + TRAINING NOTE
      </button>

      {/* Modal */}
      {open && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 100,
            background: "rgba(0,0,0,0.7)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 20,
          }}
          onClick={(e) => { if (e.target === e.currentTarget) setOpen(false); }}
          data-testid="training-note-modal-backdrop"
        >
          <div
            className="brut-border"
            style={{ width: "100%", maxWidth: 720, background: "var(--surface)", padding: 20 }}
            data-testid="training-note-modal"
          >
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <GraduationCap size={16} style={{ color: "#7ee3c9" }} />
                <div>
                  <div className="mono" style={{ fontSize: 12, letterSpacing: "0.2em", color: "#7ee3c9", fontWeight: 700 }}>
                    NEW TRAINING NOTE
                  </div>
                  <div className="mono" style={{ fontSize: 10, color: "#94a3b8", marginTop: 2 }}>
                    Prepended to every AI investigation · feedback-weighted
                  </div>
                </div>
              </div>
              <button className="nvx-btn ghost" onClick={() => setOpen(false)} data-testid="training-note-modal-close">
                <X size={12} />
              </button>
            </div>

            {/* ── Reference URL + LLM SYNC ─────────────────────────────── */}
            <div className="mono" style={{ ...LABEL_STYLE, display: "flex", alignItems: "center", gap: 6 }}>
              <LinkIcon size={11} /> Reference URL <span style={{ opacity: 0.55, fontWeight: 500 }}>· optional — LLM will condense the page into a directive</span>
            </div>
            <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
              <input
                className="brut-input"
                style={{ ...INPUT_STYLE, flex: 1 }}
                placeholder="https://readsecurity.medium.com/... (article, CTI report, MITRE page, blog)"
                value={refUrl}
                onChange={(e) => setRefUrl(e.target.value)}
                data-testid="floating-training-note-refurl"
              />
              <button
                className={`nvx-btn ${validUrl ? "primary" : "ghost"}`}
                onClick={syncFromUrl}
                disabled={syncing || !validUrl}
                title="Fetch the URL, extract article text, and condense it into a training-note directive"
                data-testid="floating-training-note-sync"
                style={{ whiteSpace: "nowrap" }}
              >
                {syncing
                  ? <><RefreshCw size={12} className="spin" /> SYNCING…</>
                  : <><Sparkles size={12} /> SYNC</>}
              </button>
            </div>
            {syncMeta && (
              <div className="mono" data-testid="floating-training-note-sync-meta"
                   style={{ fontSize: 10, color: "#38bdf8",
                            padding: "6px 8px", marginBottom: 12,
                            background: "rgba(14,165,233,0.08)",
                            border: "1px solid #0ea5e9",
                            letterSpacing: "0.06em" }}>
                ✓ Synced from <b>{syncMeta.source}</b> · {syncMeta.fetched.toLocaleString()} chars → {syncMeta.summary.toLocaleString()} char directive
                {syncMeta.tags?.length ? <> · tags: {syncMeta.tags.join(", ")}</> : null}
              </div>
            )}

            {/* Title */}
            <div className="mono" style={LABEL_STYLE}>Title</div>
            <input
              className="brut-input"
              style={{ ...INPUT_STYLE, marginBottom: 12 }}
              placeholder="e.g. Defang all URLs · Cite decoded evidence"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
              data-testid="floating-training-note-title"
            />

            {/* Directive */}
            <div className="mono" style={{ ...LABEL_STYLE, display: "flex", alignItems: "center", gap: 6 }}>
              Directive
              <span style={{ opacity: 0.55, fontWeight: 500 }}>· or upload a payload sample file (ANY format)</span>
              <label
                htmlFor="floating-tn-file-upload"
                className="mono"
                data-testid="floating-training-note-upload-label"
                style={{
                  cursor: "pointer", padding: "3px 8px",
                  background: "rgba(126,227,201,0.12)",
                  border: "1px solid #7ee3c9", color: "#7ee3c9",
                  fontSize: 9, letterSpacing: "0.14em", textTransform: "uppercase",
                  marginLeft: "auto",
                }}
              >
                📄 Upload File
              </label>
              <input
                id="floating-tn-file-upload"
                type="file"
                accept="*/*"
                onChange={(e) => {
                  setError("");
                  const f = e.target.files?.[0];
                  if (!f) return;
                  if (f.size > 16 * 1024 * 1024) {
                    setError(`File too large: ${(f.size / 1024 / 1024).toFixed(1)} MB (max 16 MB)`);
                    e.target.value = "";
                    return;
                  }
                  // Detect binary vs text: read first 4 KB, count non-printable bytes.
                  // If >5% non-printable → treat as binary (store as base64).
                  const probe = new FileReader();
                  probe.onload = () => {
                    const buf = new Uint8Array(probe.result);
                    const sampleLen = Math.min(buf.length, 4096);
                    let nonPrint = 0;
                    for (let i = 0; i < sampleLen; i++) {
                      const b = buf[i];
                      const printable = (b >= 32 && b < 127) || b === 9 || b === 10 || b === 13;
                      if (!printable) nonPrint++;
                    }
                    const isBinary = sampleLen > 0 && (nonPrint / sampleLen) > 0.05;
                    if (isBinary) {
                      // Read full file as base64 data URL, strip the prefix
                      const b64Reader = new FileReader();
                      b64Reader.onload = () => {
                        const dataUrl = String(b64Reader.result || "");
                        const b64 = dataUrl.split(",")[1] || "";
                        // Compute sha256 client-side for provenance
                        crypto.subtle.digest("SHA-256", buf).then((hashBuf) => {
                          const hex = Array.from(new Uint8Array(hashBuf))
                            .map(b => b.toString(16).padStart(2,"0")).join("");
                          const meta = [
                            "[NIVX_BINARY_SAMPLE]",
                            `filename=${f.name}`,
                            `size=${f.size}`,
                            `mime=${f.type || "application/octet-stream"}`,
                            `sha256=${hex}`,
                            "encoding=base64",
                            "---",
                            b64,
                          ].join("\n");
                          setBody(meta);
                          if (!name.trim()) setName(f.name.replace(/\.[^.]+$/, ""));
                        });
                      };
                      b64Reader.onerror = () => setError("Failed to read binary file");
                      b64Reader.readAsDataURL(f);
                    } else {
                      // Text file — decode directly for readability
                      const txt = new TextDecoder("utf-8", { fatal: false }).decode(buf.slice(0, sampleLen));
                      // For full text content, re-read as text (in case file > 4KB)
                      if (f.size <= sampleLen) {
                        setBody(txt);
                        if (!name.trim()) setName(f.name.replace(/\.[^.]+$/, ""));
                      } else {
                        const txtReader = new FileReader();
                        txtReader.onload = () => {
                          setBody(String(txtReader.result || ""));
                          if (!name.trim()) setName(f.name.replace(/\.[^.]+$/, ""));
                        };
                        txtReader.onerror = () => setError("Failed to read text file");
                        txtReader.readAsText(f);
                      }
                    }
                  };
                  probe.onerror = () => setError("Failed to read file");
                  probe.readAsArrayBuffer(f);
                  e.target.value = "";
                }}
                style={{ display: "none" }}
                data-testid="floating-training-note-upload-input"
              />
            </div>
            <textarea
              className="brut-input"
              style={{ ...INPUT_STYLE, minHeight: 200, resize: "vertical", lineHeight: 1.55 }}
              placeholder={"E.g.:\n- ALWAYS defang URLs (hxxp://) in the final report\n- Never claim a payload is benign without decoded evidence\n- Treat T1218.011 rundll32 as CRITICAL even without a network IOC\n\n— OR click 📄 UPLOAD FILE above to load a payload/sample file.\n   ▸ Text files → pasted as-is into the directive\n   ▸ Binary files (any format: .exe, .zip, .pdf, .doc, .bin, etc.) → auto-encoded as base64 with metadata header (filename, size, mime, sha256) so downstream engines can decode/scan safely (max 16 MB)."}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              data-testid="floating-training-note-body"
            />

            {/* Footer */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 14, gap: 8 }}>
              <div className="mono" style={{ fontSize: 10, color: "#f87171", fontWeight: 600 }} data-testid="floating-training-note-error">
                {error}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="nvx-btn ghost" onClick={() => setOpen(false)}>
                  CANCEL
                </button>
                <button
                  className="nvx-btn primary"
                  onClick={save}
                  disabled={saving || !name.trim() || !body.trim()}
                  data-testid="floating-training-note-save"
                >
                  <Save size={12} /> {saving ? "SAVING…" : "SAVE & ACTIVATE"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Local keyframes for the SYNC spinner */}
      <style>{`
        .spin { animation: nivxray-spin 1s linear infinite; }
        @keyframes nivxray-spin { to { transform: rotate(360deg); } }
      `}</style>
    </>
  );
}
