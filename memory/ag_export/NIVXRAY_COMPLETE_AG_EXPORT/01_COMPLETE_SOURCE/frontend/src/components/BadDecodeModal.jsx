import { useState } from "react";
import axios from "axios";

const API = process.env.REACT_APP_BACKEND_URL + "/api";

export default function BadDecodeModal({ open, onClose, rawInput, observedOutput, observedChain }) {
  const [expected, setExpected] = useState("");
  const [reason, setReason] = useState("");
  const [kind, setKind] = useState("wrong_output");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState(null);

  if (!open) return null;

  const submit = async () => {
    setSubmitting(true); setErr(null);
    try {
      const token = localStorage.getItem("nvx_token");
      const r = await axios.post(
        `${API}/decode/feedback`,
        {
          raw_input: rawInput || "",
          observed_output: observedOutput || "",
          observed_chain: observedChain || [],
          expected_output: expected || "",
          reason: reason || "",
          kind,
        },
        { headers: token ? { Authorization: `Bearer ${token}` } : {} },
      );
      setResult(r.data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "submit failed");
    } finally {
      setSubmitting(false);
    }
  };

  const close = () => {
    setResult(null); setErr(null); setExpected(""); setReason(""); setKind("wrong_output");
    onClose?.();
  };

  return (
    <div
      data-testid="bad-decode-modal"
      onClick={close}
      style={{
        position: "fixed", inset: 0, background: "rgba(0,0,0,0.65)",
        display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "#0f172a", color: "#e5e7eb", padding: 24, borderRadius: 10,
          width: "min(920px, 92vw)", maxHeight: "88vh", overflow: "auto",
          border: "1px solid #334155", fontFamily: "ui-monospace, Menlo, monospace",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
          <h2 style={{ margin: 0, color: "#f87171", fontSize: 18 }}>
            REPORT BAD DECODE — AI DIAGNOSIS
          </h2>
          <button
            onClick={close}
            data-testid="bad-decode-close"
            style={{ background: "transparent", color: "#94a3b8", border: "1px solid #334155", padding: "4px 10px", borderRadius: 6, cursor: "pointer" }}
          >
            ✕
          </button>
        </div>

        {!result && (
          <>
            <div style={{ marginBottom: 12 }}>
              <label style={label}>What went wrong?</label>
              <select
                value={kind} onChange={(e) => setKind(e.target.value)}
                data-testid="bad-decode-kind"
                style={{ ...inputStyle, marginBottom: 8 }}
              >
                <option value="wrong_output">Wrong output (decoded to gibberish)</option>
                <option value="undecoded">Undecoded (decoder produced nothing / passthrough)</option>
                <option value="partial">Partial (some layers peeled, stopped early)</option>
              </select>
            </div>

            <div style={{ marginBottom: 12 }}>
              <label style={label}>Reason / What you expected (optional but recommended)</label>
              <textarea
                value={reason} onChange={(e) => setReason(e.target.value)}
                data-testid="bad-decode-reason"
                rows={2}
                placeholder="e.g. Should have peeled the GZIP layer, but stopped at base64. Or: URL was in cleartext but not extracted."
                style={{ ...inputStyle, resize: "vertical" }}
              />
            </div>

            <div style={{ marginBottom: 12 }}>
              <label style={label}>Ground truth / expected plaintext (optional)</label>
              <textarea
                value={expected} onChange={(e) => setExpected(e.target.value)}
                data-testid="bad-decode-expected"
                rows={4}
                placeholder="Paste what the decoded output should have been (if you know)."
                style={{ ...inputStyle, resize: "vertical" }}
              />
            </div>

            <div style={{ background: "#1e293b", padding: 12, borderRadius: 6, marginBottom: 12, fontSize: 11 }}>
              <div style={{ color: "#94a3b8", marginBottom: 4 }}>OBSERVED CHAIN ({(observedChain || []).length} ops)</div>
              <div style={{ color: "#a7f3d0" }}>{(observedChain || []).join(" → ") || "(empty — decoder found no ops)"}</div>
            </div>

            {err && <div style={{ color: "#f87171", marginBottom: 8 }}>Error: {err}</div>}

            <button
              onClick={submit} disabled={submitting}
              data-testid="bad-decode-submit"
              style={{
                background: "#dc2626", color: "#fff", border: "none", padding: "10px 18px",
                borderRadius: 6, fontWeight: 600, cursor: submitting ? "wait" : "pointer",
                letterSpacing: 0.8,
              }}
            >
              {submitting ? "DIAGNOSING WITH CLAUDE…" : "SUBMIT + GET AI DIAGNOSIS"}
            </button>
          </>
        )}

        {result && (
          <div data-testid="bad-decode-result">
            <div style={{ background: "#065f46", padding: 12, borderRadius: 6, marginBottom: 14, color: "#a7f3d0" }}>
              ✓ Submitted · id={result.id} · diagnosed in {result.record?.diagnosis_ms || "?"} ms
            </div>

            <Section title="ROOT CAUSE">
              <div style={{ color: "#fbbf24" }}>
                {result.diagnosis?.root_cause || "—"}
              </div>
            </Section>

            <Section title="WHY IT FAILED">
              <div>{result.diagnosis?.ai_explanation || "(no AI explanation)"}</div>
            </Section>

            {(result.diagnosis?.heuristic_hints || []).length > 0 && (
              <Section title="DETERMINISTIC HINTS">
                <ul style={{ paddingLeft: 18, margin: 0 }}>
                  {result.diagnosis.heuristic_hints.map((h, i) => (
                    <li key={i} style={{ marginBottom: 4 }}>{h}</li>
                  ))}
                </ul>
              </Section>
            )}

            {(result.diagnosis?.fix_steps || []).length > 0 && (
              <Section title="HOW TO FIX">
                <ol style={{ paddingLeft: 18, margin: 0 }}>
                  {result.diagnosis.fix_steps.map((s, i) => (
                    <li key={i} style={{ marginBottom: 6 }}>
                      <b style={{ color: "#a7f3d0" }}>{s.op}</b>
                      {s.args_hint && <span style={{ color: "#94a3b8" }}> · args: {s.args_hint}</span>}
                      {s.note && <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 2 }}>{s.note}</div>}
                    </li>
                  ))}
                </ol>
              </Section>
            )}

            {(result.diagnosis?.suggested_recipe || []).length > 0 && (
              <Section title="SUGGESTED RECIPE (paste into custom recipe builder)">
                <code style={{ display: "block", background: "#020617", padding: 10, borderRadius: 6, color: "#a7f3d0", fontSize: 12 }}>
                  {result.diagnosis.suggested_recipe.join(" → ")}
                </code>
              </Section>
            )}

            {result.diagnosis?.missing_heuristic && (
              <Section title="MISSING HEURISTIC (engineering ticket)">
                <div style={{ color: "#fbbf24", fontSize: 12 }}>{result.diagnosis.missing_heuristic}</div>
              </Section>
            )}

            <button
              onClick={close}
              data-testid="bad-decode-done"
              style={{ marginTop: 12, background: "#334155", color: "#fff", border: "none", padding: "8px 16px", borderRadius: 6, cursor: "pointer" }}
            >
              DONE
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

const label = { display: "block", fontSize: 11, letterSpacing: 1.4, color: "#94a3b8", marginBottom: 4, textTransform: "uppercase" };
const inputStyle = {
  width: "100%", background: "#020617", color: "#e5e7eb", border: "1px solid #334155",
  padding: "8px 10px", borderRadius: 6, fontFamily: "inherit", fontSize: 13, boxSizing: "border-box",
};

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ fontSize: 10, color: "#a7f3d0", letterSpacing: 1.6, marginBottom: 6 }}>{title}</div>
      <div style={{ fontSize: 13, lineHeight: 1.5 }}>{children}</div>
    </div>
  );
}
