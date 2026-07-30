/**
 * InvestigationPipeline — ADR-0013 §2.1 shared 10-section renderer.
 *
 * Consumes an unmodified /api/decode/smart OR /api/v2/auto-investigate
 * response, runs it through investigationSynthesizer, and renders the
 * canonical 10 sections in the frozen order as collapsible cards.
 *
 * Determinism: every value shown is READ from the backend response
 * (via the synthesiser). This component never mutates verdict /
 * severity / confidence / ATT&CK / IOCs.
 */
import { Fragment, useMemo, useState } from "react";
import synthesize from "../lib/investigationSynthesizer";

const S = {
  wrap: { display: "flex", flexDirection: "column", gap: 14 },
  card: {
    background: "var(--panel, #0f172a)",
    border: "1px solid var(--border, #1e293b)",
    borderRadius: 10,
    overflow: "hidden",
  },
  head: {
    display: "flex", alignItems: "center", gap: 12,
    padding: "14px 18px",
    cursor: "pointer",
    userSelect: "none",
    background: "linear-gradient(180deg, rgba(125,211,252,0.04) 0%, rgba(125,211,252,0.00) 100%)",
    borderBottom: "1px solid transparent",
    transition: "border-color 0.15s ease",
  },
  headOpen: { borderBottom: "1px solid var(--border, #1e293b)" },
  index: {
    width: 26, height: 26, minWidth: 26,
    borderRadius: 6,
    display: "grid", placeItems: "center",
    fontSize: 11, fontWeight: 700,
    background: "rgba(125,211,252,0.10)",
    border: "1px solid rgba(125,211,252,0.28)",
    color: "#7dd3fc",
    fontFamily: "ui-monospace",
  },
  title: {
    fontSize: 13,
    letterSpacing: "0.14em",
    textTransform: "uppercase",
    fontWeight: 700,
    color: "var(--text, #e2e8f0)",
  },
  spacer: { flex: 1 },
  badge: {
    fontSize: 10, letterSpacing: "0.08em",
    padding: "3px 8px", borderRadius: 999,
    background: "rgba(148,163,184,0.10)",
    border: "1px solid rgba(148,163,184,0.30)",
    color: "var(--text-secondary, #94a3b8)",
    fontFamily: "ui-monospace",
  },
  chev: {
    fontSize: 12, color: "var(--text-secondary, #94a3b8)",
    transition: "transform 0.18s ease", transformOrigin: "center",
  },
  chevOpen: { transform: "rotate(90deg)" },
  body: { padding: "18px 20px 20px", fontSize: 13, color: "var(--text, #e2e8f0)", lineHeight: 1.65 },
  bodyMono: { fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 12 },
  kv: { display: "grid", gridTemplateColumns: "minmax(140px, max-content) 1fr", rowGap: 6, columnGap: 16, fontSize: 12, fontFamily: "ui-monospace" },
  kLabel: { color: "var(--text-secondary, #94a3b8)", letterSpacing: "0.06em", textTransform: "uppercase", fontSize: 10 },
  kVal: { color: "var(--text, #e2e8f0)", wordBreak: "break-word" },
  chipStrip: { display: "flex", flexWrap: "wrap", gap: 6 },
  chip: {
    fontSize: 11, padding: "3px 9px", borderRadius: 999,
    background: "rgba(125,211,252,0.06)",
    border: "1px solid rgba(125,211,252,0.30)",
    color: "var(--text, #e2e8f0)",
    fontFamily: "ui-monospace",
  },
  chipMuted: {
    background: "rgba(148,163,184,0.08)", border: "1px solid rgba(148,163,184,0.25)",
    color: "var(--text-secondary, #94a3b8)",
  },
  chipMal: {
    background: "rgba(248,113,113,0.10)", border: "1px solid rgba(248,113,113,0.35)",
    color: "#fecaca",
  },
  chipWarn: {
    background: "rgba(250,204,21,0.08)", border: "1px solid rgba(250,204,21,0.35)",
    color: "#fde68a",
  },
  narrativeGrid: { display: "grid", gap: 12 },
  narrativeRow: {
    display: "grid",
    gridTemplateColumns: "88px 1fr",
    gap: 14,
    alignItems: "start",
    padding: "10px 12px",
    background: "rgba(2,6,23,0.4)",
    borderRadius: 6,
    border: "1px solid var(--border, #1e293b)",
  },
  nLabel: { fontSize: 10, letterSpacing: "0.22em", textTransform: "uppercase", color: "#7dd3fc", fontWeight: 700, paddingTop: 2 },
  nText: { color: "var(--text, #e2e8f0)", fontSize: 13, lineHeight: 1.6 },
  narrativeProse: {
    display: "flex", flexDirection: "column", gap: 12,
    padding: "14px 16px",
    background: "rgba(2,6,23,0.4)",
    borderRadius: 8,
    border: "1px solid var(--border, #1e293b)",
    fontSize: 13, lineHeight: 1.7, color: "var(--text, #e2e8f0)",
  },
  narrativeP: { margin: 0 },
  narrativePFirst: { margin: 0, fontWeight: 600 },
  execProse: {
    fontSize: 13, lineHeight: 1.75, color: "var(--text, #e2e8f0)",
    display: "flex", flexDirection: "column", gap: 10,
  },
  execFacts: {
    display: "flex", flexWrap: "wrap", gap: 8,
    padding: "10px 12px",
    borderRadius: 6,
    background: "rgba(125,211,252,0.05)",
    border: "1px solid rgba(125,211,252,0.20)",
    marginBottom: 4,
  },
  execFact: {
    fontSize: 11, fontFamily: "ui-monospace",
    color: "var(--text-secondary, #94a3b8)",
    letterSpacing: "0.04em",
  },
  execFactValue: { color: "var(--text, #e2e8f0)", fontWeight: 600, marginLeft: 4 },
  timelineWrap: { display: "grid", gap: 10 },
  timelineRow: { display: "grid", gridTemplateColumns: "28px 1fr auto", alignItems: "center", gap: 10 },
  timelineDot: {
    width: 8, height: 8, borderRadius: "50%",
    background: "#7dd3fc",
    boxShadow: "0 0 0 3px rgba(125,211,252,0.15)",
    justifySelf: "center",
  },
  timelineLabel: { fontSize: 13, color: "var(--text, #e2e8f0)" },
  timelineDetail: { fontSize: 11, color: "var(--text-secondary, #94a3b8)", fontFamily: "ui-monospace" },
  pre: {
    padding: 12, background: "var(--bg, #020617)", border: "1px solid var(--border, #1e293b)",
    borderRadius: 6, overflow: "auto", maxHeight: 320,
    color: "var(--text, #e2e8f0)", fontSize: 12,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    whiteSpace: "pre-wrap", wordBreak: "break-word", margin: 0,
  },
  emptyNote: {
    fontSize: 12, color: "var(--text-secondary, #94a3b8)", fontStyle: "italic",
    padding: 12, border: "1px dashed var(--border, #1e293b)", borderRadius: 6,
  },
  mitList: { display: "grid", gap: 12 },
  mitCard: {
    padding: 12, borderRadius: 6,
    background: "rgba(2,6,23,0.4)",
    border: "1px solid var(--border, #1e293b)",
  },
  mitHead: { display: "flex", alignItems: "center", gap: 8, marginBottom: 6 },
  mitTitle: { fontSize: 13, fontWeight: 700, color: "var(--text, #e2e8f0)" },
  mitWhy: { fontSize: 12, color: "var(--text-secondary, #94a3b8)", marginBottom: 8, lineHeight: 1.55 },
  mitActions: { paddingLeft: 20, margin: 0, fontSize: 12, color: "var(--text, #e2e8f0)", lineHeight: 1.7 },
  provenance: {
    marginTop: 8,
    padding: "6px 10px",
    borderRadius: 6,
    background: "rgba(250,204,21,0.06)",
    border: "1px solid rgba(250,204,21,0.30)",
    color: "#fde68a",
    fontSize: 11,
    fontFamily: "ui-monospace",
  },
};

function Section({ index, id, title, badge, defaultOpen, children }) {
  const [open, setOpen] = useState(!!defaultOpen);
  return (
    <div style={S.card} data-testid={`pipeline-section-${id}`}>
      <div
        style={{ ...S.head, ...(open ? S.headOpen : {}) }}
        onClick={() => setOpen((o) => !o)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setOpen((o) => !o); } }}
        data-testid={`pipeline-toggle-${id}`}
        aria-expanded={open}
      >
        <div style={S.index}>{index}</div>
        <div style={S.title}>{title}</div>
        <div style={S.spacer} />
        {badge ? <div style={S.badge}>{badge}</div> : null}
        <div style={{ ...S.chev, ...(open ? S.chevOpen : {}) }}>▶</div>
      </div>
      {open ? <div style={S.body} data-testid={`pipeline-body-${id}`}>{children}</div> : null}
    </div>
  );
}

function Empty({ text }) {
  return <div style={S.emptyNote} data-testid="pipeline-empty">{text}</div>;
}

function verdictChipStyle(v) {
  const s = String(v || "").toLowerCase();
  if (/malicious/.test(s)) return { ...S.chip, ...S.chipMal };
  if (/suspicious|partial|runtime/.test(s)) return { ...S.chip, ...S.chipWarn };
  return { ...S.chip, ...S.chipMuted };
}

export default function InvestigationPipeline({ result }) {
  const model = useMemo(() => synthesize(result), [result]);
  if (!model) return null;

  const { executive, technical, threatIntel, osint, iocs, mitre, timeline, narrative, mitigation, evidence, meta } = model;

  return (
    <div style={S.wrap} data-testid="investigation-pipeline">
      {/* 1 · Executive Summary — SOC-ticket-style prose */}
      <Section index="1" id="executive" title="Executive Summary" defaultOpen badge={meta.mode === "auto" ? "auto-investigate" : "decode/smart"}>
        {/* Compact facts strip — the analyst's at-a-glance line */}
        <div style={S.execFacts} data-testid="pipeline-exec-facts">
          <span style={S.execFact}>Verdict:<span style={{ ...S.execFactValue, marginLeft: 6 }}><span style={verdictChipStyle(executive.verdict)}>{executive.verdict}</span></span></span>
          {executive.severity ? <span style={S.execFact}>Severity:<span style={S.execFactValue}>{executive.severity}</span></span> : null}
          {executive.confidence !== null && executive.confidence !== undefined ? <span style={S.execFact}>Confidence:<span style={S.execFactValue}>{executive.confidence}</span></span> : null}
        </div>

        {/* Prose narrative */}
        <div style={S.execProse} data-testid="pipeline-executive-prose">
          {narrative.executive_paragraphs.length ? (
            narrative.executive_paragraphs.map((p, i) => (
              <p key={i} style={i === 0 ? S.narrativePFirst : S.narrativeP}>{p}</p>
            ))
          ) : (
            <p style={S.narrativeP}>{executive.headline}</p>
          )}
        </div>

        {executive.partial ? (
          <div style={{ ...S.provenance, marginTop: 12 }} data-testid="pipeline-partial-badge">
            ADR-0012 · Partial Decode · cause={meta.cause || "truncated"} · evidence provenance = partial_recovery. Severity capped; do not treat as complete.
          </div>
        ) : null}

        {executive.because.length ? (
          <div style={{ marginTop: 14 }}>
            <div style={S.kLabel}>Because</div>
            <ul style={{ paddingLeft: 20, marginTop: 4, lineHeight: 1.7 }}>
              {executive.because.map((b, i) => (
                <li key={i}>{typeof b === "string" ? b : (b?.reason || b?.text || JSON.stringify(b))}</li>
              ))}
            </ul>
          </div>
        ) : null}
      </Section>

      {/* 2 · Technical Analysis */}
      <Section index="2" id="technical" title="Technical Analysis" badge={technical.engine}>
        <div style={S.kv}>
          <div style={S.kLabel}>Engine</div>
          <div style={S.kVal}>{technical.engine}</div>
          {technical.detectedType ? (<>
            <div style={S.kLabel}>Detected type</div>
            <div style={S.kVal}>{technical.detectedType}</div>
          </>) : null}
          {technical.recoveredLayers ? (<>
            <div style={S.kLabel}>Recovered layers</div>
            <div style={S.kVal}>{technical.recoveredLayers}</div>
          </>) : null}
          {technical.chain_ids.length ? (<>
            <div style={S.kLabel}>Chain</div>
            <div style={S.kVal}>
              <div style={S.chipStrip}>
                {technical.chain_ids.map((c, i) => <span key={i} style={S.chip}>{c}</span>)}
              </div>
            </div>
          </>) : null}
        </div>
        {technical.output ? (
          <div style={{ marginTop: 12 }}>
            <div style={S.kLabel}>Decoded output</div>
            <pre style={{ ...S.pre, marginTop: 6 }} data-testid="pipeline-output">{technical.output}</pre>
          </div>
        ) : null}
        {technical.notes.length ? (
          <div style={{ marginTop: 12 }}>
            <div style={S.kLabel}>Notes</div>
            <ul style={{ paddingLeft: 20, marginTop: 4, fontSize: 12, color: "var(--text-secondary, #94a3b8)", lineHeight: 1.65 }}>
              {technical.notes.map((n, i) => (
                <li key={i}>{typeof n === "string" ? n : (n?.message || n?.text || JSON.stringify(n))}</li>
              ))}
            </ul>
          </div>
        ) : null}
      </Section>

      {/* 3 · Threat Intelligence */}
      <Section index="3" id="threat-intel" title="Threat Intelligence" badge={threatIntel.hasData ? `${threatIntel.hits.length} hit${threatIntel.hits.length === 1 ? "" : "s"}` : "no hits"}>
        {threatIntel.hasData ? (
          <div style={S.chipStrip}>
            {threatIntel.hits.map((h, i) => (
              <span key={i} style={S.chip} data-testid={`ti-hit-${i}`}>
                <strong style={{ color: "#7dd3fc" }}>{h.provider}</strong>
                {h.family ? ` · ${h.family}` : ""}
                {h.subject ? ` · ${h.subject}` : ""}
              </span>
            ))}
          </div>
        ) : (
          <Empty text="No deterministic threat-intel hits for this artifact." />
        )}
      </Section>

      {/* 4 · OSINT Enrichment */}
      <Section index="4" id="osint" title="OSINT Enrichment" badge="7 providers">
        <div style={S.chipStrip}>
          {osint.providers.map((p, i) => (
            <span
              key={i}
              style={{ ...S.chip, ...S.chipMuted }}
              data-testid={`osint-${p.name.replace(/\s+/g, "-").toLowerCase()}`}
              title="No API key configured — enable in Admin → Integrations (slice-2)"
            >
              {p.name} · not configured
            </span>
          ))}
        </div>
        <div style={{ ...S.emptyNote, marginTop: 12 }}>
          ADR-0013 §2.3 · Live OSINT lookups (VirusTotal / AbuseIPDB / URLScan / OTX / MalwareBazaar / ThreatFox / Shodan) will be wired in slice-2. This section always renders "not configured" instead of erroring.
        </div>
      </Section>

      {/* 5 · Indicators of Compromise */}
      <Section index="5" id="iocs" title="Indicators of Compromise" badge={iocs.total ? `${iocs.total}` : "0"}>
        {iocs.total ? (
          <div style={S.kv}>
            {Object.entries(iocs.grouped).map(([kind, values]) => (
              <Fragment key={kind}>
                <div style={S.kLabel}>{kind}</div>
                <div style={S.kVal} data-testid={`ioc-group-${kind}`}>
                  <div style={S.chipStrip}>
                    {values.map((v, i) => <span key={i} style={{ ...S.chip, ...S.chipMuted }}>{String(v)}</span>)}
                  </div>
                </div>
              </Fragment>
            ))}
            {meta.provenance ? (
              <Fragment key="provenance">
                <div style={S.kLabel}>Provenance</div>
                <div style={S.kVal}>{meta.provenance}{meta.truncationNote ? ` · ${meta.truncationNote}` : ""}</div>
              </Fragment>
            ) : null}
          </div>
        ) : (
          <Empty text="No IOCs recovered from this artifact." />
        )}
      </Section>

      {/* 6 · MITRE ATT&CK */}
      <Section index="6" id="mitre" title="MITRE ATT&CK" badge={mitre.techniques.length ? `${mitre.techniques.length} techniques` : "0"}>
        {mitre.techniques.length ? (
          <div style={S.chipStrip}>
            {mitre.techniques.map((t, i) => (
              <span key={i} style={S.chip} data-testid={`pipeline-mitre-${t.id || i}`}>
                <span style={{ color: "#7dd3fc", fontWeight: 700 }}>{t.id}</span>
                {t.name ? ` · ${t.name}` : ""}
                {t.tactic ? <span style={{ opacity: 0.7 }}> · {t.tactic}</span> : null}
              </span>
            ))}
          </div>
        ) : (
          <Empty text="No ATT&CK techniques mapped to this artifact." />
        )}
      </Section>

      {/* 7 · Investigation Timeline */}
      <Section index="7" id="timeline" title="Investigation Timeline" badge={`${timeline.length} step${timeline.length === 1 ? "" : "s"}`}>
        {timeline.length ? (
          <div style={S.timelineWrap}>
            {timeline.map((t, i) => (
              <div key={i} style={S.timelineRow} data-testid={`pipeline-timeline-${i}`}>
                <div style={S.timelineDot} />
                <div>
                  <div style={S.timelineLabel}><strong>{t.step}.</strong> {t.label}</div>
                  {t.detail ? <div style={S.timelineDetail}>{t.detail}</div> : null}
                </div>
                {t.badge ? <span style={{ ...S.chip, ...S.chipMuted }}>{t.badge}</span> : null}
              </div>
            ))}
          </div>
        ) : (
          <Empty text="No timeline steps to show." />
        )}
      </Section>

      {/* 8 · Investigation Summary — SOC-ticket-style prose (When · Who · What · Why · Where · How) */}
      <Section index="8" id="narrative" title="Investigation Summary" badge="Prose · deterministic" defaultOpen>
        <div style={S.narrativeProse} data-testid="pipeline-narrative-prose">
          {narrative.investigation_paragraphs.length ? (
            narrative.investigation_paragraphs.map((p, i) => (
              <p key={i} style={i === 0 ? S.narrativePFirst : S.narrativeP}>{p}</p>
            ))
          ) : (
            <p style={S.narrativeP}>Investigation processed. See Technical Analysis and Raw Evidence for details.</p>
          )}
        </div>
      </Section>

      {/* 9 · Mitigation */}
      <Section index="9" id="mitigation" title="Mitigation" badge={mitigation.length ? `${mitigation.length}` : "0"}>
        {mitigation.length ? (
          <div style={S.mitList}>
            {mitigation.map((m, i) => (
              <div key={i} style={S.mitCard} data-testid={`pipeline-mit-${i}`}>
                <div style={S.mitHead}>
                  <span style={{ ...S.chip, ...S.chipMuted }}>{m.severity}</span>
                  <div style={S.mitTitle}>{m.title}</div>
                </div>
                {m.why ? <div style={S.mitWhy}>{m.why}</div> : null}
                {m.actions?.length ? (
                  <ul style={S.mitActions}>
                    {m.actions.map((a, j) => (
                      <li key={j}>{typeof a === "string" ? a : (a?.text || a?.title || JSON.stringify(a))}</li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ))}
          </div>
        ) : (
          <Empty text="No mitigation recommendations produced for this artifact." />
        )}
      </Section>

      {/* 10 · Raw Evidence */}
      <Section index="10" id="evidence" title="Raw Evidence" badge="explainability · chains · unknowns">
        {evidence.explainability && Object.keys(evidence.explainability).length ? (
          <div style={{ marginBottom: 12 }}>
            <div style={S.kLabel}>Explainability</div>
            <pre style={{ ...S.pre, marginTop: 6 }} data-testid="pipeline-explainability">{JSON.stringify(evidence.explainability, null, 2)}</pre>
          </div>
        ) : null}
        {evidence.decodeChains.length ? (
          <div style={{ marginBottom: 12 }}>
            <div style={S.kLabel}>Decode chains</div>
            {evidence.decodeChains.map((ch, i) => (
              <div key={i} style={{ marginTop: 8, fontFamily: "ui-monospace", fontSize: 12 }}>
                <div style={{ color: "var(--text-secondary, #94a3b8)" }}>#{ch.index} · {ch.binary} · {ch.layers?.length || 0} layers</div>
                <div style={{ marginTop: 4, color: "var(--text, #e2e8f0)", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                  {(ch.command_line || "").slice(0, 400)}{(ch.command_line || "").length > 400 ? "…" : ""}
                </div>
              </div>
            ))}
          </div>
        ) : null}
        {evidence.rawOutput ? (
          <div style={{ marginBottom: 12 }}>
            <div style={S.kLabel}>Raw output</div>
            <pre style={{ ...S.pre, marginTop: 6 }} data-testid="pipeline-raw-output">{evidence.rawOutput}</pre>
          </div>
        ) : null}
        {evidence.unknowns.length ? (
          <div>
            <div style={S.kLabel}>Unknowns</div>
            <ul style={{ paddingLeft: 20, marginTop: 4, fontSize: 12, color: "var(--text-secondary, #94a3b8)", lineHeight: 1.65 }}>
              {evidence.unknowns.slice(0, 20).map((u, i) => (
                <li key={i}>{typeof u === "string" ? u : (u.description || u.reason || JSON.stringify(u))}</li>
              ))}
            </ul>
          </div>
        ) : null}
        {!evidence.rawOutput && !evidence.decodeChains.length && !evidence.unknowns.length && !(evidence.explainability && Object.keys(evidence.explainability).length) ? (
          <Empty text="No additional raw evidence." />
        ) : null}
      </Section>
    </div>
  );
}
