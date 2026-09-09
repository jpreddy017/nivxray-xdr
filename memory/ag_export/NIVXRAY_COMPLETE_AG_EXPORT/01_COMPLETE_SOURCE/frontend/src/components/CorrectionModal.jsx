import { useState } from "react";
import { X, Send, Trash2 } from "lucide-react";
import api from "@/lib/api";

/**
 * CorrectionModal — Feb-2026 #3 UI for analyst correction submission.
 *
 * Opens from CandidateExplorer / VerdictCard "Correct this decode" button.
 * Submits to POST /api/learning/correction with optional promote_to_corpus
 * + trigger_benchmark flags.
 *
 * Props:
 *   open, onClose
 *   input:            string   the original obfuscated input
 *   engineOutput:     string   what NivXRay decoded to
 *   engineChain:      array    [{op, args}] the chain the engine used
 *   engineConfidence: number|null
 *   onSubmitted:      function(response) — called on success
 */
export default function CorrectionModal({
  open, onClose,
  input, engineOutput, engineChain, engineConfidence,
  onSubmitted,
}) {
  const [correctedOutput, setCorrectedOutput] = useState("");
  const [correctedChainText, setCorrectedChainText] = useState(
    (engineChain || []).map((s) => s.op).join(" → "),
  );
  const [notes, setNotes] = useState("");
  const [promote, setPromote] = useState(true);
  const [sampleName, setSampleName] = useState("");
  const [triggerBench, setTriggerBench] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  if (!open) return null;

  const parseChain = (text) => {
    return (text || "")
      .split(/[→>,]/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((op) => ({ op }));
  };

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    setResult(null);
    try {
      const body = {
        input,
        engine_output: engineOutput || "",
        engine_chain: engineChain || [],
        engine_confidence: engineConfidence ?? null,
        corrected_output: correctedOutput,
        corrected_chain: parseChain(correctedChainText),
        notes: notes || null,
        promote_to_corpus: promote,
        sample_name: promote ? (sampleName || null) : null,
        trigger_benchmark: promote && triggerBench,
      };
      const r = await api.post("/learning/correction", body);
      setResult(r.data);
      if (onSubmitted) onSubmitted(r.data);
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      role="dialog"
      onClick={(e) => e.target === e.currentTarget && onClose && onClose()}
      style={{
        position: "fixed", inset: 0, background: "rgba(2,6,23,0.75)",
        display: "flex", alignItems: "center", justifyContent: "center",
        zIndex: 500,
      }}
      data-testid="correction-modal"
    >
      <div
        style={{
          width: 640, maxHeight: "90vh", overflow: "auto",
          background: "#0f172a", border: "1px solid rgba(148,163,184,0.2)",
          borderRadius: 6,
        }}
      >
        <div
          style={{
            display: "flex", alignItems: "center", padding: "12px 16px",
            borderBottom: "1px solid rgba(148,163,184,0.15)",
          }}
        >
          <div style={{ flex: 1, color: "#7ee3c9", fontWeight: 600, letterSpacing: 1 }}>
            ▸ CORRECT THIS DECODE
          </div>
          <button
            onClick={onClose}
            className="nvx-btn sm ghost"
            data-testid="correction-modal-close"
          >
            <X size={12} />
          </button>
        </div>
        <div style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 4 }}>INPUT</div>
          <div
            style={{
              padding: "6px 10px", fontFamily: "monospace", fontSize: 11,
              background: "rgba(15,23,42,0.5)", borderRadius: 3, color: "#c9d1d9",
              marginBottom: 12, wordBreak: "break-all", maxHeight: 60, overflow: "auto",
            }}
          >
            {input}
          </div>

          <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 4 }}>
            ENGINE OUTPUT{engineConfidence != null && ` (confidence ${(engineConfidence * 100).toFixed(0)}%)`}
          </div>
          <div
            style={{
              padding: "6px 10px", fontFamily: "monospace", fontSize: 11,
              background: "rgba(248,113,113,0.05)", border: "1px solid rgba(248,113,113,0.15)",
              borderRadius: 3, color: "#c9d1d9", marginBottom: 12,
            }}
          >
            {engineOutput || "(empty)"}
          </div>

          <label style={{ fontSize: 11, color: "#7ee3c9", fontWeight: 600 }}>
            CORRECTED OUTPUT *
            <textarea
              className="nvx-input"
              value={correctedOutput}
              onChange={(e) => setCorrectedOutput(e.target.value)}
              placeholder="The correct decoded value…"
              rows={3}
              style={{ marginTop: 4, width: "100%", fontFamily: "monospace" }}
              data-testid="correction-corrected-output"
            />
          </label>

          <label style={{ fontSize: 11, color: "#94a3b8", marginTop: 10, display: "block" }}>
            CORRECTED CHAIN (op1 → op2 → op3)
            <input
              className="nvx-input"
              value={correctedChainText}
              onChange={(e) => setCorrectedChainText(e.target.value)}
              placeholder="e.g. base64-decode → gzip-decompress"
              style={{ marginTop: 4, width: "100%" }}
              data-testid="correction-corrected-chain"
            />
          </label>

          <label style={{ fontSize: 11, color: "#94a3b8", marginTop: 10, display: "block" }}>
            NOTES (optional)
            <textarea
              className="nvx-input"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Why the engine was wrong / context"
              rows={2}
              style={{ marginTop: 4, width: "100%" }}
              data-testid="correction-notes"
            />
          </label>

          <div
            style={{
              marginTop: 14, padding: 10,
              background: "rgba(126,227,201,0.06)", borderRadius: 4,
              border: "1px solid rgba(126,227,201,0.15)",
            }}
          >
            <label
              style={{
                display: "flex", alignItems: "center", gap: 8,
                fontSize: 12, color: "#7ee3c9",
              }}
            >
              <input
                type="checkbox"
                checked={promote}
                onChange={(e) => setPromote(e.target.checked)}
                data-testid="correction-promote"
              />
              Promote to regression corpus (versioned sample library)
            </label>
            {promote && (
              <div style={{ marginTop: 8, paddingLeft: 22 }}>
                <input
                  className="nvx-input"
                  value={sampleName}
                  onChange={(e) => setSampleName(e.target.value)}
                  placeholder="Sample name (optional — auto-generated if empty)"
                  style={{ width: "100%", fontSize: 11 }}
                  data-testid="correction-sample-name"
                />
                <label
                  style={{
                    display: "flex", alignItems: "center", gap: 6,
                    fontSize: 11, color: "#94a3b8", marginTop: 6,
                  }}
                >
                  <input
                    type="checkbox"
                    checked={triggerBench}
                    onChange={(e) => setTriggerBench(e.target.checked)}
                    data-testid="correction-trigger-bench"
                  />
                  Trigger regression benchmark immediately after promote
                </label>
              </div>
            )}
          </div>

          {error && (
            <div
              style={{
                marginTop: 12, padding: 10, background: "rgba(248,113,113,0.08)",
                border: "1px solid rgba(248,113,113,0.3)", borderRadius: 4,
                color: "#f87171", fontSize: 11,
              }}
              data-testid="correction-error"
            >
              {typeof error === "string" ? error : JSON.stringify(error)}
            </div>
          )}

          {result && (
            <div
              style={{
                marginTop: 12, padding: 10, background: "rgba(126,227,201,0.08)",
                border: "1px solid rgba(126,227,201,0.3)", borderRadius: 4,
                color: "#c9d1d9", fontSize: 11, fontFamily: "monospace",
              }}
              data-testid="correction-result"
            >
              <div style={{ color: "#7ee3c9", fontWeight: 600 }}>✓ Correction recorded</div>
              {result.corpus_entry && (
                <div>→ Added to regression corpus (id {result.corpus_entry._id?.slice(-8)})</div>
              )}
              {result.benchmark_run && (
                <div>
                  → Benchmark: {result.benchmark_run.passed}/{result.benchmark_run.total} passed
                  {" · "}
                  {result.benchmark_run.flips?.length > 0 && (
                    <span style={{ color: "#f59e0b" }}>
                      {result.benchmark_run.flips.length} flip
                      {result.benchmark_run.flips.length > 1 ? "s" : ""} vs previous
                    </span>
                  )}
                </div>
              )}
            </div>
          )}

          <div style={{ marginTop: 16, display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <button
              className="nvx-btn sm ghost"
              onClick={onClose}
              disabled={submitting}
              data-testid="correction-cancel"
            >
              Cancel
            </button>
            <button
              className="nvx-btn sm"
              onClick={submit}
              disabled={submitting || !correctedOutput.trim()}
              data-testid="correction-submit"
            >
              <Send size={12} /> {submitting ? "SUBMITTING…" : "SUBMIT CORRECTION"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
