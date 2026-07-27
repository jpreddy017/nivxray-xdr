/**
 * InvestigationBrainPanel — unified visualisation of the
 * Input Understanding → Command Reconstruction → Recursive
 * Transformation → Semantic Intent pipeline.
 *
 * Analysts see one investigation flow instead of four separate
 * engines. Consumes the `investigation` payload delivered by
 * `/api/decode/smart` (`v2/investigation/pipeline.py::investigate`).
 *
 * Deterministic — the rendered output is a pure function of the
 * investigation payload; no derived heuristics on the frontend.
 */
import React, { useMemo } from "react";

const CATEGORY_COLORS = {
  staging:            { bg: "#3a1f00", fg: "#ffb347", label: "STAGING" },
  remote_execution:   { bg: "#3a0000", fg: "#ff6b6b", label: "REMOTE EXEC" },
  defense_evasion:    { bg: "#3a2400", fg: "#ffb347", label: "DEFENSE EVASION" },
  discovery:          { bg: "#002a3a", fg: "#5ec8ff", label: "DISCOVERY" },
  persistence:        { bg: "#3a002a", fg: "#ff6bd4", label: "PERSISTENCE" },
  credential_access:  { bg: "#3a0000", fg: "#ff5252", label: "CRED ACCESS" },
  lateral_movement:   { bg: "#2a003a", fg: "#c084fc", label: "LATERAL MOVE" },
  collection:         { bg: "#00303a", fg: "#5ee3c4", label: "COLLECTION" },
  exfiltration:       { bg: "#3a0028", fg: "#ff8ec7", label: "EXFIL" },
  impact:             { bg: "#3a0000", fg: "#ff3838", label: "IMPACT" },
  runtime_dependent:  { bg: "#1c2938", fg: "#8fa5c2", label: "RUNTIME DEPENDENT" },
};

const RISK_COLORS = {
  high:    "#ff5252",
  medium:  "#ffb347",
  low:     "#5ec8ff",
  unknown: "#8fa5c2",
};

function Section({ title, subtitle, testid, children }) {
  return (
    <div
      data-testid={testid}
      style={{
        marginBottom: 14,
        padding: 12,
        border: "1px solid #22344b",
        borderRadius: 8,
        background: "#0b1522",
      }}
    >
      <div
        style={{
          fontSize: 12,
          fontWeight: 700,
          color: "#5ec8ff",
          letterSpacing: 0.7,
          textTransform: "uppercase",
          marginBottom: subtitle ? 2 : 8,
        }}
      >
        {title}
      </div>
      {subtitle && (
        <div style={{ fontSize: 11, color: "#8fa5c2", marginBottom: 8 }}>
          {subtitle}
        </div>
      )}
      {children}
    </div>
  );
}

function Pill({ text, fg = "#e5edf7", bg = "#152234", testid }) {
  return (
    <span
      data-testid={testid}
      style={{
        padding: "2px 8px",
        borderRadius: 4,
        fontSize: 11,
        fontFamily: "ui-monospace, monospace",
        color: fg,
        background: bg,
        border: `1px solid ${fg}33`,
        marginRight: 6,
        marginBottom: 6,
        display: "inline-block",
      }}
    >
      {text}
    </span>
  );
}

function StageArrow() {
  return (
    <div style={{ textAlign: "center", color: "#3a4d6b", fontSize: 16, margin: "4px 0" }}>
      ↓
    </div>
  );
}

export function InvestigationBrainPanel({ investigation }) {
  const iu = investigation?.iu;
  const cre = investigation?.cre;
  const rte = investigation?.rte;
  const intent = investigation?.intent;
  const verdict = investigation?.verdict;
  const graph = investigation?.graph;
  const report = investigation?.report;
  const signals = report?.confidence_signals || {};

  const intentsSorted = useMemo(() => {
    if (!intent?.intents) return [];
    return [...intent.intents];   // backend already ordered by conf DESC
  }, [intent]);

  const verdictColors = {
    malicious:         { bg: "#3a0000", fg: "#ff5252", border: "#ff5252" },
    suspicious:        { bg: "#3a2400", fg: "#ffb347", border: "#ffb347" },
    runtime_dependent: { bg: "#1c2938", fg: "#8fa5c2", border: "#5ec8ff" },
    benign:            { bg: "#062b18", fg: "#5ee3c4", border: "#5ee3c4" },
  };

  if (!investigation) return null;

  return (
    <div
      data-testid="investigation-brain-panel"
      style={{
        margin: "16px",
        padding: 14,
        border: "1px solid #22344b",
        borderRadius: 10,
        background: "#050e18",
        color: "#e5edf7",
        fontSize: 13,
        fontFamily: "ui-sans-serif, system-ui, sans-serif",
      }}
    >
      <div
        style={{
          fontSize: 14,
          fontWeight: 700,
          color: "#ffd166",
          letterSpacing: 1.2,
          textTransform: "uppercase",
          marginBottom: 4,
        }}
      >
        Investigation Summary
      </div>
      <div style={{ fontSize: 11, color: "#8fa5c2", marginBottom: 12 }}>
        Deterministic pipeline · coverage: {(investigation.coverage || []).join(" → ")}
        {" · "}determinism hash{" "}
        <code style={{ color: "#5ec8ff" }}>
          {(investigation.determinism_hash || "").slice(0, 16)}
        </code>
      </div>

      {/* ── 0. VERDICT UPLIFT — the 5-second answer ────────── */}
      {verdict && (
        <div
          data-testid="brain-verdict"
          style={{
            marginBottom: 14,
            padding: 14,
            borderRadius: 8,
            background: (verdictColors[verdict.band] || verdictColors.benign).bg,
            border: `2px solid ${(verdictColors[verdict.band] || verdictColors.benign).border}`,
          }}
        >
          <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
            <div
              data-testid="brain-verdict-band"
              style={{
                fontSize: 18,
                fontWeight: 700,
                letterSpacing: 1.4,
                textTransform: "uppercase",
                color: (verdictColors[verdict.band] || verdictColors.benign).fg,
              }}
            >
              {verdict.band.replace("_", " ")}
            </div>
            <div
              data-testid="brain-verdict-confidence"
              style={{ fontSize: 12, color: "#a4c4e6" }}
            >
              confidence {verdict.confidence}
            </div>
          </div>
          <div
            data-testid="brain-verdict-reason"
            style={{ marginTop: 6, color: "#e5edf7" }}
          >
            {verdict.reason}
          </div>
          {(verdict.evidence || []).length > 0 && (
            <details style={{ marginTop: 8 }} data-testid="brain-verdict-evidence">
              <summary style={{ cursor: "pointer", fontSize: 11, color: "#5ec8ff" }}>
                Supporting evidence ({verdict.evidence.length})
              </summary>
              <div style={{ marginTop: 6 }}>
                {verdict.evidence.map((ev, i) => (
                  <div
                    key={i}
                    style={{
                      padding: 6,
                      marginBottom: 4,
                      background: "#00000055",
                      borderRadius: 4,
                      fontSize: 11,
                      fontFamily: "ui-monospace, monospace",
                      color: "#a4c4e6",
                    }}
                  >
                    <div style={{ color: "#5ec8ff", marginBottom: 2 }}>
                      [{ev.source}] · conf {ev.confidence}
                    </div>
                    <div style={{ wordBreak: "break-all" }}>{ev.observation}</div>
                    <div style={{ marginTop: 2, color: "#8fa5c2" }}>{ev.rationale}</div>
                  </div>
                ))}
              </div>
            </details>
          )}
        </div>
      )}

      {/* ── Investigation Signals — per-investigation cues, NOT
          engineering QA metrics. Locked with user directive. */}
      {report && (
        <div
          data-testid="brain-signals"
          style={{
            marginBottom: 14,
            padding: 10,
            borderRadius: 8,
            background: "#0b1522",
            border: "1px solid #22344b",
            display: "flex",
            flexWrap: "wrap",
            gap: 20,
          }}
        >
          <div>
            <div style={{ fontSize: 10, color: "#5ec8ff", letterSpacing: 0.6 }}>
              CONFIDENCE
            </div>
            <div data-testid="brain-signal-confidence"
                 style={{ color: "#e5edf7", fontSize: 13, textTransform: "capitalize" }}>
              {signals.confidence || "—"}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 10, color: "#5ec8ff", letterSpacing: 0.6 }}>
              EVIDENCE
            </div>
            <div data-testid="brain-signal-evidence"
                 style={{ color: "#e5edf7", fontSize: 13, textTransform: "capitalize" }}>
              {signals.evidence_strength || "—"}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 10, color: "#5ec8ff", letterSpacing: 0.6 }}>
              UNKNOWNS
            </div>
            <div data-testid="brain-signal-unknowns"
                 style={{ color: "#e5edf7", fontSize: 13 }}>
              {signals.unknowns_present === "yes" ? "present" : "none"}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 10, color: "#5ec8ff", letterSpacing: 0.6 }}>
              REASONING
            </div>
            <div data-testid="brain-signal-reasoning"
                 style={{ color: "#e5edf7", fontSize: 13 }}>
              {(signals.reasoning || "—").replace(/_/g, " ")}
            </div>
          </div>
        </div>
      )}

      {/* ── Analyst Report (deterministic, evidence-anchored) ─── */}
      {report && (
        <div
          data-testid="brain-report"
          style={{
            marginBottom: 14,
            padding: 12,
            borderRadius: 8,
            background: "#0b1522",
            border: "1px solid #22344b",
          }}
        >
          <div style={{ fontSize: 12, fontWeight: 700, color: "#ffd166",
                        letterSpacing: 0.7, textTransform: "uppercase", marginBottom: 6 }}>
            Analyst Report
          </div>
          <div data-testid="brain-report-summary" style={{ marginBottom: 10, color: "#e5edf7" }}>
            {report.executive_summary}
          </div>
          {(report.unknowns || []).length > 0 && (
            <div data-testid="brain-report-unknowns" style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 11, color: "#5ec8ff", marginBottom: 4 }}>
                UNKNOWNS ({report.unknowns.length})
              </div>
              {report.unknowns.map((u, i) => (
                <div key={i} style={{ fontSize: 12, color: "#a4c4e6", marginBottom: 4 }}>
                  · {u}
                </div>
              ))}
            </div>
          )}
          {(report.recommendations || []).length > 0 && (
            <div data-testid="brain-report-recommendations">
              <div style={{ fontSize: 11, color: "#5ec8ff", marginBottom: 4 }}>
                RECOMMENDED NEXT STEPS ({report.recommendations.length})
              </div>
              {report.recommendations.map((r, i) => (
                <div key={i}
                     data-testid={`brain-report-rec-${i}`}
                     style={{ padding: 6, marginBottom: 4, background: "#02080f",
                              border: "1px solid #143047", borderRadius: 4, fontSize: 12 }}>
                  <span style={{ color: "#ffb347", textTransform: "uppercase",
                                 fontSize: 10, marginRight: 6 }}>
                    {r.priority.replace("_", " ")}
                  </span>
                  <span style={{ color: "#e5edf7" }}>{r.action}</span>
                  <div style={{ marginTop: 2, color: "#8fa5c2", fontSize: 11 }}>
                    {r.rationale}
                  </div>
                </div>
              ))}
            </div>
          )}
          {(report.iocs || []).length > 0 && (
            <div data-testid="brain-report-iocs" style={{ marginTop: 8 }}>
              <div style={{ fontSize: 11, color: "#5ec8ff", marginBottom: 4 }}>
                IOCS ({report.iocs.length})
              </div>
              {report.iocs.map((ioc, i) => (
                <div key={i} style={{ fontFamily: "ui-monospace, monospace",
                                        fontSize: 11, color: "#a4c4e6", marginBottom: 2 }}>
                  <span style={{ color: "#c084fc" }}>[{ioc.kind}]</span>{" "}
                  {ioc.value}
                </div>
              ))}
            </div>
          )}
          {(report.mitre || []).length > 0 && (
            <div data-testid="brain-report-mitre" style={{ marginTop: 8 }}>
              <div style={{ fontSize: 11, color: "#5ec8ff", marginBottom: 4 }}>
                MITRE ATT&amp;CK ({report.mitre.length})
              </div>
              {report.mitre.map((m, i) => (
                <span key={i} style={{ display: "inline-block",
                                        padding: "2px 8px", marginRight: 4, marginBottom: 4,
                                        background: "#1b0033", color: "#c084fc",
                                        border: "1px solid #c084fc55", borderRadius: 4,
                                        fontSize: 11, fontFamily: "ui-monospace, monospace" }}>
                  {m.id} · {m.name}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── 1. INPUT UNDERSTANDING ───────────────────────────── */}
      {iu && (
        <Section
          title="1 · Input Understanding"
          subtitle={`What is this artefact? (confidence ${iu.confidence})`}
          testid="brain-iu"
        >
          <div style={{ marginBottom: 6 }}>
            <Pill
              text={iu.primary_type}
              fg="#ffd166"
              bg="#2a1f00"
              testid="brain-iu-primary"
            />
            {(iu.embedded || []).map((e) => (
              <Pill key={e} text={`embedded: ${e}`} testid={`brain-iu-embedded-${e}`} />
            ))}
          </div>
          <div>
            {(iu.dispatch || []).map((c) => (
              <Pill
                key={c}
                text={c}
                fg="#5ec8ff"
                bg="#001d2a"
                testid={`brain-iu-cap-${c}`}
              />
            ))}
          </div>
        </Section>
      )}

      {(iu && cre) && <StageArrow />}

      {/* ── 2. COMMAND RECONSTRUCTION ────────────────────────── */}
      {cre && cre.chain && cre.chain.length > 0 && (
        <Section
          title="2 · Command Reconstruction"
          subtitle={`What will actually execute? (${cre.chain.length} wrapper step${cre.chain.length === 1 ? "" : "s"} · dispatch: ${cre.dispatch_hint})`}
          testid="brain-cre"
        >
          {cre.chain.map((step, i) => (
            <div key={i} data-testid={`brain-cre-step-${i}`} style={{ marginBottom: 6 }}>
              <Pill text={`L${i}: ${step.wrapper}`} fg="#ff9d5c" bg="#2a1500" />
              {step.mode && <Pill text={step.mode} />}
            </div>
          ))}
          <div
            data-testid="brain-cre-effective-payload"
            style={{
              marginTop: 8,
              padding: 8,
              background: "#02080f",
              border: "1px solid #143047",
              borderRadius: 5,
              fontFamily: "ui-monospace, monospace",
              fontSize: 12,
              color: "#a4c4e6",
              wordBreak: "break-all",
            }}
          >
            <div style={{ color: "#5ec8ff", fontSize: 10, marginBottom: 4 }}>
              EFFECTIVE PAYLOAD
            </div>
            {cre.effective_payload || "(empty)"}
          </div>
        </Section>
      )}

      {cre && rte && <StageArrow />}

      {/* ── 3. RECURSIVE TRANSFORMATION ─────────────────────── */}
      {rte && (
        <Section
          title="3 · Recursive Transformation"
          subtitle={`Reveal the hidden payload — ${rte.depth} transformation layer${rte.depth === 1 ? "" : "s"} · stopped: ${rte.stop_reason}`}
          testid="brain-rte"
        >
          {(rte.artifacts || []).map((a, i) => (
            <div
              key={i}
              data-testid={`brain-rte-layer-${i}`}
              style={{
                padding: 8,
                marginBottom: 6,
                background: "#02080f",
                border: "1px solid #143047",
                borderRadius: 5,
              }}
            >
              <div style={{ marginBottom: 4 }}>
                <Pill text={`L${a.layer}`} fg="#ffd166" bg="#2a1f00" />
                <Pill text={a.classification?.primary_type} fg="#5ec8ff" bg="#001d2a" />
              </div>
              <div
                style={{
                  fontFamily: "ui-monospace, monospace",
                  fontSize: 12,
                  color: "#a4c4e6",
                  wordBreak: "break-all",
                  maxHeight: 120,
                  overflowY: "auto",
                }}
              >
                {(a.content || "").slice(0, 400)}
                {(a.content || "").length > 400 && (
                  <span style={{ color: "#5ec8ff" }}>
                    { " …[" }{a.content.length - 400}{ " more chars]"}
                  </span>
                )}
              </div>
            </div>
          ))}
          {(rte.steps || []).length > 0 && (
            <div style={{ marginTop: 8, fontSize: 11, color: "#8fa5c2" }}>
              Transformations applied:{" "}
              {rte.steps.map((s, i) => (
                <Pill
                  key={i}
                  text={`${s.transformation} (${s.confidence})`}
                  fg="#c084fc"
                  bg="#1b0033"
                  testid={`brain-rte-step-${i}`}
                />
              ))}
            </div>
          )}
        </Section>
      )}

      {rte && intent && <StageArrow />}

      {/* ── 4. SEMANTIC INTENT ──────────────────────────────── */}
      {intent && (
        <Section
          title="4 · Semantic Intent"
          subtitle="Why does it matter? Analyst-facing intent inferred from the effective payload"
          testid="brain-intent"
        >
          <div
            data-testid="brain-intent-summary"
            style={{ marginBottom: 10, fontStyle: "italic", color: "#a4c4e6" }}
          >
            {intent.summary}
          </div>
          {intentsSorted.length === 0 ? (
            <div data-testid="brain-intent-none" style={{ color: "#8fa5c2" }}>
              No high-signal analyst intent inferred.
            </div>
          ) : (
            intentsSorted.map((i, idx) => {
              const cat = CATEGORY_COLORS[i.category] || {
                bg: "#152234",
                fg: "#e5edf7",
                label: i.category,
              };
              return (
                <div
                  key={idx}
                  data-testid={`brain-intent-${i.category}`}
                  style={{
                    padding: 10,
                    marginBottom: 8,
                    borderRadius: 6,
                    background: cat.bg,
                    border: `1px solid ${cat.fg}55`,
                  }}
                >
                  <div style={{ marginBottom: 6 }}>
                    <Pill
                      text={cat.label}
                      fg={cat.fg}
                      bg="#00000055"
                      testid={`brain-intent-cat-${i.category}`}
                    />
                    <Pill
                      text={`risk: ${i.risk}`}
                      fg={RISK_COLORS[i.risk] || "#e5edf7"}
                      bg="#00000055"
                      testid={`brain-intent-risk-${i.category}`}
                    />
                    <Pill text={`conf ${i.confidence}`} testid={`brain-intent-conf-${i.category}`} />
                    {(i.mitre_ids || []).map((m) => (
                      <Pill
                        key={m}
                        text={m}
                        fg="#c084fc"
                        bg="#1b0033"
                        testid={`brain-intent-mitre-${m}`}
                      />
                    ))}
                  </div>
                  <div style={{ marginBottom: 4, color: "#e5edf7" }}>
                    <strong>Purpose:</strong> {i.purpose}
                  </div>
                  <div style={{ marginBottom: 4, fontSize: 12, color: "#a4c4e6" }}>
                    <strong>Why it matters:</strong> {i.rationale}
                  </div>
                  {(i.evidence || []).length > 0 && (
                    <details style={{ marginTop: 4 }}>
                      <summary style={{ cursor: "pointer", fontSize: 11, color: "#5ec8ff" }}>
                        Evidence ({i.evidence.length})
                      </summary>
                      <div style={{ marginTop: 6 }}>
                        {i.evidence.map((ev, ei) => (
                          <div
                            key={ei}
                            style={{
                              padding: 6,
                              marginBottom: 4,
                              background: "#00000055",
                              borderRadius: 4,
                              fontFamily: "ui-monospace, monospace",
                              fontSize: 11,
                              color: "#a4c4e6",
                            }}
                          >
                            <div style={{ color: "#5ec8ff", marginBottom: 2 }}>
                              [{ev.source}] · conf {ev.confidence}
                            </div>
                            <div style={{ wordBreak: "break-all" }}>
                              {ev.observation}
                            </div>
                            <div style={{ marginTop: 2, color: "#8fa5c2" }}>
                              {ev.rationale}
                            </div>
                          </div>
                        ))}
                      </div>
                    </details>
                  )}
                </div>
              );
            })
          )}
        </Section>
      )}

      {/* ── 5. EVIDENCE GRAPH — DAG summary for explainability ─── */}
      {graph && (graph.nodes?.length || 0) > 0 && (
        <Section
          title="5 · Evidence Graph"
          subtitle={`Homogeneous DAG · ${graph.nodes.length} node${graph.nodes.length === 1 ? "" : "s"}, ${graph.edges.length} edge${graph.edges.length === 1 ? "" : "s"} · every conclusion cites evidence`}
          testid="brain-graph"
        >
          <details>
            <summary
              data-testid="brain-graph-toggle"
              style={{ cursor: "pointer", fontSize: 11, color: "#5ec8ff" }}
            >
              Show graph nodes & edges
            </summary>
            <div style={{ marginTop: 8 }}>
              <div style={{ fontSize: 11, color: "#8fa5c2", marginBottom: 4 }}>
                NODES
              </div>
              <div style={{ maxHeight: 220, overflowY: "auto", paddingRight: 4 }}>
                {graph.nodes.map((n) => (
                  <div
                    key={n.id}
                    data-testid={`brain-graph-node-${n.id}`}
                    style={{
                      padding: 6,
                      marginBottom: 4,
                      background: "#02080f",
                      border: "1px solid #143047",
                      borderRadius: 4,
                      fontSize: 11,
                      fontFamily: "ui-monospace, monospace",
                    }}
                  >
                    <span style={{ color: "#ffd166" }}>[{n.kind}]</span>{" "}
                    <span style={{ color: "#5ec8ff" }}>{n.id}</span>{" "}
                    <span style={{ color: "#e5edf7" }}>{n.label}</span>
                    {typeof n.confidence === "number" && (
                      <span style={{ color: "#8fa5c2" }}> · conf {n.confidence}</span>
                    )}
                  </div>
                ))}
              </div>
              <div style={{ fontSize: 11, color: "#8fa5c2", margin: "8px 0 4px" }}>
                EDGES
              </div>
              <div style={{ maxHeight: 180, overflowY: "auto", paddingRight: 4 }}>
                {graph.edges.map((e, i) => (
                  <div
                    key={i}
                    data-testid={`brain-graph-edge-${i}`}
                    style={{
                      padding: 4,
                      marginBottom: 2,
                      fontSize: 11,
                      fontFamily: "ui-monospace, monospace",
                      color: "#a4c4e6",
                    }}
                  >
                    <span style={{ color: "#5ec8ff" }}>{e.src}</span>{" "}
                    <span style={{ color: "#c084fc" }}>--{e.kind}--&gt;</span>{" "}
                    <span style={{ color: "#5ec8ff" }}>{e.dst}</span>
                  </div>
                ))}
              </div>
            </div>
          </details>
        </Section>
      )}
    </div>
  );
}

export default InvestigationBrainPanel;
