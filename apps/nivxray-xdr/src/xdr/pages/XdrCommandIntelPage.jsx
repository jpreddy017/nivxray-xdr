/**
 * XdrCommandIntelPage · `/xdr/intelligence/command`
 *
 * Wires the EXISTING NivXRay semantic command analyser into NivXRay XDR:
 *   POST /api/analyze/command  {input, force_decode_span?}
 *
 * Reuses the analyser as-is — no second decode fabric, no heuristics added
 * here. The response is rendered as returned, including the `needs_choice`
 * disambiguation path, which is resubmitted with `force_decode_span` exactly
 * as the service asks.
 */
import React, { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Terminal, Zap } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";

export default function XdrCommandIntelPage() {
  const [params] = useSearchParams();
  const [input, setInput]   = useState(params.get("q") || "");
  const [res, setRes]       = useState(null);
  const [busy, setBusy]     = useState(false);
  const [err, setErr]       = useState(null);

  const run = async (span) => {
    if (!input.trim()) return;
    setBusy(true); setErr(null); setRes(null);
    try {
      const r = await api.post("/analyze/command", {
        input: input.trim(),
        ...(span ? { force_decode_span: span } : {}),
      });
      setRes(r?.data || null);
    } catch (x) {
      setErr(x?.response?.data?.detail || x?.message || "analysis failed");
    } finally { setBusy(false); }
  };

  const choices = res?.needs_choice ? (res.candidate_spans || res.choices || []) : [];

  return (
    <XdrShell>
      <div data-testid="xdr-command-intel-page">
        <div style={head}>
          <Terminal size={16} />
          <h1 className="page-h1" style={{ margin: 0 }}>Command Intelligence</h1>
        </div>
        <div style={sub}>
          Semantic analysis of a command line through the NivXRay decode
          fabric. Output is the service response, rendered as returned.
        </div>

        <form style={panel} onSubmit={(e) => { e.preventDefault(); run(null); }}>
          <div style={panelH}>Command</div>
          <div style={{ padding: "8px 10px" }}>
            <textarea value={input} onChange={(e) => setInput(e.target.value)}
                      rows={4} data-testid="xdr-cmd-input"
                      placeholder="powershell -enc SQBFAFgA…"
                      style={{ width: "100%", padding: "6px 8px",
                                fontSize: 12, fontFamily: "var(--mono)" }} />
            <button type="submit" className="btn primary" disabled={busy}
                    data-testid="xdr-cmd-analyze"
                    style={{ marginTop: 8, fontSize: 11,
                              opacity: busy ? 0.5 : 1 }}>
              <Zap size={12} /> {busy ? "Analysing…" : "Analyse"}
            </button>
          </div>
        </form>

        {err && <div style={errBox} data-testid="xdr-cmd-error">{err}</div>}

        {choices.length > 0 && (
          <div style={{ ...panel, marginTop: 10 }} data-testid="xdr-cmd-choices">
            <div style={panelH}>Decode span disambiguation required</div>
            <div style={{ padding: "8px 10px", display: "flex",
                           flexWrap: "wrap", gap: 6 }}>
              {choices.map((c, i) => {
                const span = typeof c === "string" ? c : (c.span || c.value || "");
                return (
                  <button key={i} type="button" className="btn"
                          data-testid={`xdr-cmd-choice-${i}`}
                          onClick={() => run(span)}
                          style={{ fontSize: 10.5, fontFamily: "var(--mono)" }}>
                    {String(span).slice(0, 60)}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {res && (
          <div style={{ ...panel, marginTop: 10 }} data-testid="xdr-cmd-result">
            <div style={panelH}>Analyser response</div>
            <pre style={pre}>{JSON.stringify(res, null, 2)}</pre>
          </div>
        )}
      </div>
    </XdrShell>
  );
}

const head = { display: "flex", alignItems: "center", gap: 10, marginBottom: 6 };
const sub = { color: "var(--text-dim)", fontSize: 12, marginBottom: 12,
              maxWidth: 760, lineHeight: 1.6 };
const panel = { border: "1px solid var(--border)", borderRadius: 3,
                overflow: "hidden" };
const panelH = { padding: "7px 10px", fontSize: 10, fontWeight: 800,
                 letterSpacing: ".4px", textTransform: "uppercase",
                 color: "var(--faint)", borderBottom: "1px solid var(--border)" };
const pre = { background: "var(--panel2, rgba(0,0,0,.04))", padding: 10,
              margin: 0, overflow: "auto", fontSize: 11,
              whiteSpace: "pre-wrap", maxHeight: "56vh" };
const errBox = { border: "1px solid var(--nx-danger, #d64545)", borderRadius: 3,
                 padding: "8px 10px", fontSize: 11, marginTop: 10,
                 fontFamily: "var(--mono)" };
