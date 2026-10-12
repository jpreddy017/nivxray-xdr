/** Command Intelligence uses the existing authenticated API and Universal Decoder. */
import React, { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Terminal, Zap } from "lucide-react";
import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";
import { apiErrorText } from "@/xdr/nx/apiError";
import { activeTenant, TENANT_BOUND_EVENT } from "@/lib/tenant";
import { commandRequest, validateCommandResult } from "./commandIntelligenceContract";

function Payload({ value, format = "text" }) {
  return <><div style={muted}>{format === "base64" ? "Binary evidence (Base64 representation, not a decoded script)" : "Text evidence"}</div><pre style={pre}>{value}</pre></>;
}

export function CommandResult({ result }) {
  const canonical = result.canonical_decoded_artifact;
  return <div data-testid="xdr-cmd-result" aria-live="polite">
    <section style={panel}>
      <h2 style={panelH}>{result.decode_status.replaceAll("_", " ")}</h2>
      <div style={body}><p>{result.decode_status_reason}</p>
        <p style={muted}>Static reconstruction only. Decoded does not mean executed. Confidence describes recovery, not whether the command is malicious.</p>
        <p><strong>Detected methods: </strong>{result.detected_methods.join(" → ") || "None identified"}</p>
        {result.warnings.map((w, i) => <p key={i} role="note" style={warning}>{w}</p>)}
      </div>
    </section>
    <section style={panel}><h2 style={panelH}>Original command · preserved exactly</h2><Payload value={result.original_command}/></section>
    <section style={panel}><h2 style={panelH}>{canonical.promoted ? "Canonical decoded evidence" : "Best recoverable candidate · not canonical"}</h2>
      <Payload {...result.final_recoverable}/><p style={{ ...muted, padding: 10 }}>{canonical.reason}</p>
    </section>
    {result.candidates.map((c, ci) => <section style={panel} key={`${c.id}-${ci}`}>
      <h2 style={panelH}>Candidate {ci + 1} · {c.embedded ? "embedded payload" : "whole input"} · {c.confidence.toLowerCase()} recovery confidence</h2>
      <div style={body}>
        <div style={muted}>Ranking score {c.score} (heuristic, not a probability) · {c.id}</div>
        {c.unresolved.map((w, i) => <p style={warning} key={i}>{w}</p>)}
        <ol style={{ paddingLeft: 24 }}>
          {c.layers.map((l, i) => <li key={i} style={{ margin: "12px 0" }}>
            <details><summary style={{ cursor: "pointer" }}>{i + 1}. {l.stage} · {l.bytes_in} → {l.bytes_out} bytes</summary>
              <p style={muted}>{l.notes}</p><div style={muted}>Arguments: {JSON.stringify(l.args)}</div>
              <details><summary>Intermediate input</summary><Payload {...l.input}/></details>
              <Payload value={l.output} format={l.output_format}/>
              <div style={muted}>Input SHA-256: {l.input_sha256}<br/>Output SHA-256: {l.output_sha256}</div>
            </details>
          </li>)}
        </ol>
        <details><summary>Reproducible recipe (version {result.engine_version})</summary><pre style={pre}>{JSON.stringify(c.recipe, null, 2)}</pre></details>
        <details><summary>Candidate output</summary><Payload {...c.payload}/></details>
      </div>
    </section>)}
    <section style={panel}><h2 style={panelH}>Behavioral evidence</h2><div style={body}>
      {result.behaviors.length ? result.behaviors.map((b, i) => <p key={i}>{b.kind && <strong>{b.kind.replaceAll("_", " ")} · </strong>}{b.explanation} <code>{b.match}</code><br/><small style={muted}>{b.evidence_id}{b.basis && ` · ${b.basis.replaceAll("_", " ")} · characters ${b.start}–${b.end}`}</small></p>) : <p>No supported behavioral pattern identified. This is not a benign verdict.</p>}
      <p style={muted}>{result.mitre_status}</p>
    </div></section>
    <section style={panel}><h2 style={panelH}>Extracted indicators · observed strings, not reputation verdicts</h2><div style={{ overflowX: "auto" }}>
      {result.iocs.length ? <table style={{ width: "100%", fontSize: 12 }}><thead><tr><th>Type</th><th>Value</th><th>Evidence</th></tr></thead><tbody>{result.iocs.map((ioc, i) => <tr key={i}><td>{ioc.type}</td><td><code>{ioc.value}</code></td><td style={muted}>{ioc.evidence_id}</td></tr>)}</tbody></table> : <p style={body}>No supported indicators extracted.</p>}
    </div></section>
    {result.unresolved_portions.length > 0 && <section style={panel}><h2 style={panelH}>Unresolved limitations</h2><div style={body}>
      {result.unresolved_portions.map((w, i) => <p key={i} style={warning}>{w}</p>)}
    </div></section>}
    <details style={panel}><summary style={panelH}>Full evidence report and resource limits</summary><pre style={pre}>{JSON.stringify(result, null, 2)}</pre></details>
  </div>;
}

export default function XdrCommandIntelPage() {
  const [params] = useSearchParams();
  const [input, setInput] = useState(params.get("q") || "");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const pending = useRef(null);
  const generation = useRef(0);
  useEffect(() => {
    const clear = () => {
      generation.current += 1;
      pending.current?.abort();
      setResult(null); setError(null); setBusy(false); setInput("");
    };
    window.addEventListener(TENANT_BOUND_EVENT, clear);
    window.addEventListener("storage", clear);
    return () => { generation.current += 1; pending.current?.abort(); window.removeEventListener(TENANT_BOUND_EVENT, clear); window.removeEventListener("storage", clear); };
  }, []);
  const run = async () => {
    pending.current?.abort();
    const id = ++generation.current;
    const tenant = activeTenant();
    const controller = new AbortController();
    pending.current = controller;
    setResult(null); setError(null); setBusy(true);
    try {
      const request = commandRequest(input);
      const response = await api.post("/analyze/command", request, { signal: controller.signal });
      if (generation.current === id && tenant === activeTenant()) setResult(validateCommandResult(response.data, request.input));
    } catch (e) {
      if (!controller.signal.aborted && generation.current === id && tenant === activeTenant()) setError(apiErrorText(e, e.message || "Command analysis failed. Try again with a smaller payload."));
    } finally { if (generation.current === id) setBusy(false); }
  };
  return <XdrShell><div data-testid="xdr-command-intel-page" style={{ maxWidth: 1200 }}>
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}><Terminal size={18}/><h1 className="page-h1">Command Intelligence</h1></div>
    <p style={muted}>Paste a command to automatically recover supported encoding, compression and obfuscation layers. Submitted commands are never executed.</p>
    <form style={panel} onSubmit={e => { e.preventDefault(); run(); }}><label htmlFor="command-input" style={panelH}>Command line · up to 16 KiB</label><div style={body}>
      <textarea id="command-input" value={input} disabled={busy} onChange={e => { setInput(e.target.value); setResult(null); setError(null); }} rows={6} data-testid="xdr-cmd-input" spellCheck={false} placeholder="powershell -EncodedCommand …" style={{ width: "100%", boxSizing: "border-box", padding: 10, fontFamily: "var(--mono)", fontSize: 12 }}/>
      <button type="submit" className="btn primary" disabled={busy || !input.trim()} data-testid="xdr-cmd-analyze" style={{ marginTop: 10 }}><Zap size={12}/> {busy ? "Analysing…" : "Analyse"}</button>
    </div></form>
    {error && <p role="alert" data-testid="xdr-cmd-error" style={warning}>{error}</p>}
    {result && <CommandResult result={result}/>}
  </div></XdrShell>;
}
const panel = { border: "1px solid var(--border)", borderRadius: 4, marginTop: 14, overflow: "hidden" };
const panelH = { display: "block", margin: 0, padding: "10px 12px", fontSize: 12, fontWeight: 700, borderBottom: "1px solid var(--border)" };
const body = { padding: "10px 12px", fontSize: 12 };
const muted = { color: "var(--text-dim)", fontSize: 11, overflowWrap: "anywhere" };
const pre = { background: "var(--panel2, rgba(0,0,0,.04))", padding: 12, margin: 0, overflow: "auto", fontSize: 12, whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 360 };
const warning = { padding: 10, borderLeft: "3px solid var(--nx-warning, #b7791f)", background: "var(--panel2)", overflowWrap: "anywhere" };
