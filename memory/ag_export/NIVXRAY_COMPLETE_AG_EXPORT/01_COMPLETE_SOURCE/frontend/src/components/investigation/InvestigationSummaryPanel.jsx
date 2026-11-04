/**
 * InvestigationSummaryPanel · Rule R22 (2026-03-02)
 * ─────────────────────────────────────────────────
 * The FIRST thing an analyst reads after AUTO INVESTIGATE.
 * Nine deterministic sections rendered from session.summary_narrative
 * (backend, zero LLM) — modelled on Cisco XDR / ThreatGrid case-file
 * layouts.
 *
 *   1  Executive Investigation Summary  (risk chip · confidence)
 *   2  Analyst Summary                  (copyable ticket block)
 *   3  Observed Behaviour               (✓ bullets)
 *   4  Attack Intent
 *   5  Potential Impact                 (bullets + likelihood)
 *   6  MITRE ATT&CK Summary             (grouped by tactic)
 *   7  IOC Intelligence                 (per-IOC card, pending badges
 *                                        on external OSINT fields)
 *   8  Recommendations                  (Immediate · Hunting · Contain)
 *   9  Evidence Confidence              (roll-up)
 *
 * The panel does NOT render extracted artefact tables — those live
 * on the dedicated Investigation Session page.  The gateway button
 * at the bottom is the analyst's transition to the deep-dive.
 */
import React, { useEffect, useState } from "react";
import api from "@/lib/api";

export default function InvestigationSummaryPanel({ narrative, onOpenSession }) {
  const [enriched, setEnriched] = useState(null);
  const [enriching, setEnriching] = useState(false);
  // R28.15 · Drill-down expand/collapse for the whole brief.  The
  // choice is persisted so analysts don't have to re-open the panel
  // on every workspace mount.  Defaults to OPEN so first-time
  // analysts see the full picture.
  const [briefOpen, setBriefOpen] = useState(() => {
    try {
      const v = localStorage.getItem("nvx.brief.open");
      return v == null ? true : v === "1";
    } catch { return true; }
  });
  useEffect(() => {
    try { localStorage.setItem("nvx.brief.open", briefOpen ? "1" : "0"); }
    catch { /* noop */ }
  }, [briefOpen]);
  const iocs = narrative?.ioc_intelligence   || [];

  // Kick off IOC intelligence enrichment as soon as the panel mounts
  // with IOCs present.  Fan-out happens server-side; we only wait for
  // the batch response (cache-first, so repeats are instant).
  useEffect(() => {
    if (!iocs.length) return;
    let alive = true;
    setEnriching(true);
    (async () => {
      try {
        const payload = iocs
          .filter(i => i.value && ["hash", "url", "domain", "ip"].includes(i.kind))
          .map(i => ({ kind: i.kind, value: i.value }));
        if (!payload.length) { if (alive) setEnriching(false); return; }
        const { data } = await api.post("/ioc/enrich", { iocs: payload });
        if (alive) setEnriched(data?.results || []);
      } catch { /* leave stub cards in place on failure */ }
      finally { if (alive) setEnriching(false); }
    })();
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [narrative]);

  if (!narrative) return null;

  const ex   = narrative.executive_summary || {};
  const bs   = narrative.behavior_summary   || [];
  const mit  = narrative.mitre_summary      || [];
  const rec  = narrative.recommendations    || {};
  const ec   = narrative.evidence_confidence || {};
  const imp  = narrative.impact_assessment  || {};

  const iocCards = enriched && enriched.length ? enriched : iocs;

  return (
    <section style={sx.wrap} data-testid="investigation-summary-panel">
      <Head risk={ex.risk} confidence={ex.confidence}
             onOpen={onOpenSession}
             open={briefOpen}
             onToggle={() => setBriefOpen(o => !o)} />

      {briefOpen && (<>
      <Card title="1 · Executive Investigation Summary"
             testid="summary-executive"
             copyable={ex.paragraph}>
        <p style={sx.body}>{ex.paragraph || "—"}</p>
        <div style={sx.metaRow}>
          <span>Overall Risk</span><RiskChip risk={ex.risk} />
          <span>Confidence</span><strong>{ex.confidence ?? 0}%</strong>
        </div>
      </Card>

      <Card title="2 · Analyst Summary (ticket-ready)"
             testid="summary-analyst"
             copyable={narrative.analyst_summary}>
        <p style={sx.body}>{narrative.analyst_summary || "—"}</p>
      </Card>

      <Card title={`3 · Observed Behaviour (${bs.length})`} testid="summary-behaviours">
        {bs.length ? (
          <ul style={sx.checkList}>
            {bs.map((b, i) => (
              <li key={i} style={sx.check}
                  data-testid={`behaviour-${i}`}>
                <span style={sx.ok}>✓</span>
                <span>{b.label}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p style={sx.dim}>No behaviours observed.</p>
        )}
      </Card>

      <Card title="4 · Attack Intent" testid="summary-intent">
        <p style={sx.body}>{narrative.attack_intent || "—"}</p>
      </Card>

      <Card title="5 · Potential Impact" testid="summary-impact">
        <ul style={sx.bulletList}>
          {(imp.bullets || []).map((b, i) => (
            <li key={i} style={sx.bullet}>• {b}</li>
          ))}
        </ul>
        <div style={sx.metaRow}>
          <span>Likelihood</span>
          <strong style={_likelihoodColor(imp.likelihood)}>
            {imp.likelihood || "Unknown"}
          </strong>
        </div>
      </Card>

      <Card title={`6 · MITRE ATT&CK Summary (${_flatMitreCount(mit)})`}
             testid="summary-mitre">
        {mit.length ? (
          <div style={sx.mitreGrid}>
            {mit.map((g, i) => (
              <div key={i} style={sx.mitreGroup}
                   data-testid={`mitre-group-${i}`}>
                <div style={sx.mitreTactic}>{g.tactic}</div>
                <ul style={sx.mitreList}>
                  {(g.techniques || []).map((t, j) => (
                    <li key={j} style={sx.mitreItem}>
                      <span style={sx.tid}>{t.id}</span>
                      <span>{t.name}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        ) : (
          <p style={sx.dim}>No MITRE mapping.</p>
        )}
      </Card>

      <Card title={`7 · IOC Intelligence (${iocCards.length}${enriching ? " · enriching…" : ""})`}
             testid="summary-iocs">
        {iocCards.length ? (
          <ul style={sx.iocList}>
            {iocCards.map((c, k) => <IocIntelCard key={k} card={c} idx={k} />)}
          </ul>
        ) : (
          <p style={sx.dim}>No IOCs correlated.</p>
        )}
        <p style={sx.footnote} data-testid="ioc-pending-note">
          Providers marked <em>pending</em> require credentials
          (VirusTotal · AbuseIPDB · abuse.ch Auth-Key).  Add them to
          <code> backend/.env </code> to activate live enrichment.
        </p>
      </Card>

      <Card title="8 · Recommendations" testid="summary-recs">
        <RecBucket label="Immediate"      items={rec.immediate}   accent="#ff9a9a" />
        <RecBucket label="Threat Hunting" items={rec.hunting}     accent="#ffd66b" mono />
        <RecBucket label="Containment"    items={rec.containment} accent="#7ee6a8" />
      </Card>

      <Card title="9 · Evidence Confidence" testid="summary-evidence">
        <ConfidenceGrid ec={ec} />
      </Card>

      <div style={sx.gatewayRow}>
        <button
          type="button"
          onClick={onOpenSession}
          data-testid="btn-open-session-from-summary"
          style={sx.primary}>
          Open Investigation Session →
        </button>
      </div>
      </>)}
    </section>
  );
}


// ══════════════════════════════════════════════════════════════════
// Sub-components
// ══════════════════════════════════════════════════════════════════
function Head({ risk, confidence, onOpen, open, onToggle }) {
  // R28.15 · Clickable drill-down header — the entire eyebrow + title
  // block toggles the brief.  Chevron rotates 0°/90° for open/closed.
  return (
    <div style={sx.head}>
      <button type="button"
              onClick={onToggle}
              aria-expanded={!!open}
              data-testid="brief-toggle"
              style={sx.headToggle}>
        <span style={{
          ...sx.headChev,
          transform: open ? "rotate(90deg)" : "rotate(0deg)",
        }} aria-hidden>▸</span>
        <div>
          <div style={sx.eyebrow}>DETERMINISTIC ANALYST BRIEF</div>
          <div style={sx.title}>
            {open
              ? "Every card below is derived from the SSOT · ready to ship"
              : "Brief collapsed · click to expand"}
          </div>
        </div>
      </button>
      <div style={sx.headRight}>
        <div style={sx.headStat}>
          <div style={sx.headStatLabel}>Risk</div>
          <RiskChip risk={risk} />
        </div>
        <div style={sx.headStat}>
          <div style={sx.headStatLabel}>Confidence</div>
          <div style={sx.headStatValue}>{confidence ?? 0}%</div>
        </div>
      </div>
    </div>
  );
}

function Card({ title, testid, copyable, children }) {
  const [open, setOpen] = useState(true);
  const [copied, setCopied] = useState(false);
  function copy() {
    try {
      navigator.clipboard.writeText(copyable || "");
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch { /* noop */ }
  }
  return (
    <div style={sx.card} data-testid={testid}>
      <div style={sx.cardHead}>
        <button type="button" onClick={() => setOpen(o => !o)}
                style={sx.cardTitle}
                data-testid={`${testid}-toggle`}>
          <span style={sx.chev}>{open ? "▾" : "▸"}</span>
          {title}
        </button>
        {copyable && (
          <button type="button" onClick={copy}
                  style={sx.copyBtn}
                  data-testid={`${testid}-copy`}>
            {copied ? "COPIED" : "COPY"}
          </button>
        )}
      </div>
      {open && <div style={sx.cardBody}>{children}</div>}
    </div>
  );
}

function RiskChip({ risk }) {
  const r = (risk || "Unknown").toString();
  const color = r === "Critical" ? "#ff9a9a"
              : r === "High"     ? "#ffb26b"
              : r === "Medium"   ? "#ffd66b"
              : r === "Low"      ? "#96c9aa"
              :                    "#96c9aa";
  return (
    <span style={{ ...sx.riskChip, color, borderColor: color }}
           data-testid="risk-chip">
      {r.toUpperCase()}
    </span>
  );
}

function IocIntelCard({ card, idx }) {
  // Handles BOTH shapes:
  //   1) rich card returned by /api/ioc/enrich  (with .consensus)
  //   2) stub card synthesised by summary_narrative (no .consensus)
  const rich = !!card?.consensus;
  if (!rich) return <IocStubCard ioc={card} idx={idx} />;
  const c   = card.consensus || {};
  const tl  = card.timeline  || {};
  const rel = card.related   || {};
  const verdictColor = c.verdict === "malicious" ? "#ff9a9a"
                     : c.verdict === "suspicious" ? "#ffb26b"
                     : c.verdict === "clean"      ? "#96c9aa"
                     :                              "#96c9aa";
  return (
    <li style={sx.iocItem} data-testid={`ioc-card-${idx}`}>
      <div style={sx.iocHead}>
        <span style={sx.iocKind}>{card.kind.toUpperCase()}</span>
        <span style={sx.iocValue}>{card.value}</span>
        <span style={{ ...sx.verdictChip, color: verdictColor,
                        borderColor: verdictColor }}
               data-testid={`ioc-verdict-${idx}`}>
          {(c.verdict || "unknown").toUpperCase()}
        </span>
      </div>

      <div style={sx.iocConfLine} data-testid={`ioc-confidence-${idx}`}>
        <span style={sx.iocConfLabel}>Confidence</span>
        <strong>{c.confidence_percent ?? 0}%</strong>
        <span style={{ ...sx.iocConfLabel, marginLeft: 8 }}>
          {(c.confidence_label || "low").toUpperCase()}
        </span>
        {card.from_cache && <span style={sx.cachedTag}>CACHED</span>}
      </div>

      {c.evidence?.length > 0 && (
        <div style={sx.iocEvidenceBlock}>
          <div style={sx.eyebrow}>▸ EVIDENCE</div>
          <ul style={sx.evidenceList}>
            {c.evidence.map((e, i) => (
              <li key={i} style={sx.evidenceItem}
                  data-testid={`ioc-evidence-${idx}-${i}`}>
                <span style={_evidenceGlyph(e)}>{_evidenceSymbol(e)}</span>
                <strong style={sx.evidenceProvider}>{e.provider}</strong>
                <span style={sx.evidenceDetail}>
                  {e.state === "pending" ? "pending — " + (e.detail || "credentials required")
                    : e.state === "error" ? "error — " + (e.detail || "unavailable")
                    : `${(e.verdict || "").toLowerCase()} · ${e.detail || ""}`}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {(tl.first_seen || tl.last_seen || tl.still_active) && (
        <div style={sx.iocMetaGrid} data-testid={`ioc-timeline-${idx}`}>
          <KV k="First Seen"   v={tl.first_seen  || "—"} />
          <KV k="Last Seen"    v={tl.last_seen   || "—"} />
          <KV k="Still Active" v={tl.still_active ? "YES" : "no"} />
          <KV k="Sources"      v={`${c.source_count ?? 0} live · ${c.pending_count ?? 0} pending`} />
        </div>
      )}

      {(rel.families?.length || rel.campaigns?.length || rel.threat_types?.length) && (
        <div style={sx.iocRelated} data-testid={`ioc-related-${idx}`}>
          {rel.families?.length > 0 && (
            <ChipRow label="Families"   items={rel.families} />)}
          {rel.campaigns?.length > 0 && (
            <ChipRow label="Campaigns"  items={rel.campaigns} />)}
          {rel.threat_types?.length > 0 && (
            <ChipRow label="Threat Types" items={rel.threat_types} />)}
        </div>
      )}
    </li>
  );
}

function ChipRow({ label, items }) {
  return (
    <div style={sx.chipRow}>
      <span style={sx.chipLabel}>{label}</span>
      {items.map((it, i) => (
        <span key={i} style={sx.chip}>{it}</span>
      ))}
    </div>
  );
}

function _evidenceSymbol(e) {
  if (e.state === "pending") return "○";
  if (e.state === "error")   return "✗";
  if (e.verdict === "malicious")  return "✓";
  if (e.verdict === "suspicious") return "▲";
  if (e.verdict === "clean")      return "·";
  return "·";
}

function _evidenceGlyph(e) {
  const color = e.state === "pending" ? "#8ba598"
              : e.state === "error"   ? "#ff9a9a"
              : e.verdict === "malicious"  ? "#ff9a9a"
              : e.verdict === "suspicious" ? "#ffb26b"
              : e.verdict === "clean"      ? "#96c9aa"
              :                              "#96c9aa";
  return { ...sx.ok, color };
}


function IocStubCard({ ioc, idx }) {
  return (
    <li style={sx.iocItem} data-testid={`ioc-card-${idx}`}>
      <div style={sx.iocHead}>
        <span style={sx.iocKind}>{ioc.kind?.toUpperCase() || "IOC"}</span>
        <span style={sx.iocValue}>{ioc.value || ""}</span>
        <span style={{ ...sx.verdictChip, color: "#8ba598",
                        borderColor: "#8ba598" }}>UNKNOWN</span>
      </div>
      <div style={sx.iocConfLine}>
        <span style={sx.iocConfLabel}>Enrichment</span>
        <em style={{ color: "#8ba598" }}>pending — awaiting engine response</em>
      </div>
    </li>
  );
}

function KV({ k, v, pending }) {
  return (
    <div style={sx.iocKv}>
      <span style={sx.iocKvKey}>{k}</span>
      <span style={{ ...sx.iocKvVal,
                       color: pending ? "#6a8f74" : "#e6ffe9",
                       fontStyle: pending ? "italic" : "normal" }}>
        {pending ? "pending" : v}
      </span>
    </div>
  );
}

function _fmt(field, key) {
  if (!field) return "—";
  if (field.source === "pending") return "pending";
  return field[key] ?? "—";
}

function RecBucket({ label, items, accent, mono }) {
  if (!items?.length) return null;
  return (
    <div style={{ marginBottom: 10 }} data-testid={`rec-${label.toLowerCase().split(" ")[0]}`}>
      <div style={{ ...sx.eyebrow, color: accent }}>▸ {label.toUpperCase()}</div>
      <ul style={sx.bulletList}>
        {items.map((r, i) => (
          <li key={i} style={{ ...sx.bullet, fontFamily: mono ? "ui-monospace, Menlo, monospace" : "inherit" }}>
            • {r}
          </li>
        ))}
      </ul>
    </div>
  );
}

function ConfidenceGrid({ ec }) {
  const rows = [
    ["Commands",   `${(ec.commands || {}).investigated || 0}/${(ec.commands || {}).total || 0}`, "investigated"],
    ["MITRE",      `${(ec.mitre || {}).count || 0}`, (ec.mitre || {}).state || "none"],
    ["IOCs",       `${(ec.iocs || {}).count || 0}`,  (ec.iocs || {}).state || "none"],
    ["Threat Intel", (ec.threat_intel || {}).state || "pending",
                     (ec.threat_intel || {}).detail || ""],
    ["Completeness", `${ec.completeness_percent || 0}%`, ec.confidence_label || ""],
  ];
  return (
    <div style={sx.confGrid}>
      {rows.map(([k, v, meta]) => (
        <div key={k} style={sx.confItem} data-testid={`conf-${k.toLowerCase().replace(/ /g, "-")}`}>
          <div style={sx.confKey}>{k}</div>
          <div style={sx.confVal}>{v}</div>
          <div style={sx.confMeta}>{meta}</div>
        </div>
      ))}
    </div>
  );
}

function _likelihoodColor(l) {
  return {
    color: l === "High" ? "#ffb26b" : l === "Medium" ? "#ffd66b" : "#96c9aa",
  };
}

function _flatMitreCount(mit) {
  return (mit || []).reduce((n, g) => n + (g.techniques || []).length, 0);
}


// ══════════════════════════════════════════════════════════════════
// Styles
// ══════════════════════════════════════════════════════════════════
const sx = {
  wrap: {
    margin: "12px",
    padding: "16px 18px",
    border: "1px solid rgba(126, 230, 168, 0.28)",
    borderRadius: 4,
    background: "linear-gradient(180deg, rgba(0, 40, 22, 0.55), rgba(0, 30, 15, 0.35))",
    color: "#c5f5d6",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
  },
  head: {
    display: "flex", justifyContent: "space-between", alignItems: "flex-end",
    paddingBottom: 14,
    borderBottom: "1px solid rgba(126, 230, 168, 0.2)",
    marginBottom: 14,
    gap: 12,
  },
  headToggle: {
    display: "flex", alignItems: "center", gap: 12,
    background: "transparent", border: 0, padding: 0,
    color: "inherit", cursor: "pointer", textAlign: "left",
    font: "inherit",
  },
  headChev: {
    display: "inline-block", fontSize: 16, lineHeight: 1,
    color: "#7ee6a8",
    transition: "transform 180ms ease",
  },
  eyebrow: { fontSize: 10, letterSpacing: 2, color: "#7ee6a8" },
  title:   { fontSize: 16, color: "#e6ffe9", marginTop: 4 },
  headRight: { display: "flex", gap: 18, alignItems: "flex-end" },
  headStat:  { textAlign: "right" },
  headStatLabel: { fontSize: 9, color: "#4a8b63", letterSpacing: 1.6 },
  headStatValue: { fontSize: 20, color: "#e6ffe9" },
  card: {
    marginBottom: 10, padding: "10px 12px",
    border: "1px solid rgba(126, 230, 168, 0.16)",
    background: "rgba(0, 30, 15, 0.35)",
    borderRadius: 3,
  },
  cardHead: { display: "flex", justifyContent: "space-between", alignItems: "center" },
  cardTitle: {
    background: "none", border: "none", color: "#e6ffe9",
    fontFamily: "inherit", fontSize: 11, letterSpacing: 1.4,
    cursor: "pointer", textTransform: "uppercase",
    padding: 0, textAlign: "left",
    display: "flex", alignItems: "center", gap: 8,
  },
  chev: { color: "#7ee6a8", width: 12, display: "inline-block" },
  copyBtn: {
    background: "transparent", color: "#7ee6a8",
    border: "1px solid rgba(126, 230, 168, 0.35)",
    padding: "3px 8px", borderRadius: 3,
    fontFamily: "inherit", fontSize: 9, letterSpacing: 1.4,
    cursor: "pointer",
  },
  cardBody: { paddingTop: 10 },
  body: { fontSize: 12, color: "#e6ffe9", lineHeight: 1.6, margin: 0 },
  metaRow: {
    marginTop: 10, display: "flex", gap: 10, alignItems: "center",
    fontSize: 11, color: "#96c9aa",
  },
  riskChip: {
    fontSize: 10, letterSpacing: 1.4, border: "1px solid",
    padding: "2px 8px", borderRadius: 3,
  },
  checkList: { listStyle: "none", padding: 0, margin: 0,
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                gap: 4, fontSize: 12 },
  check: { display: "flex", gap: 6, alignItems: "baseline", color: "#e6ffe9" },
  ok: { color: "#3ddc84" },
  bulletList: { listStyle: "none", padding: 0, margin: 0,
                 display: "flex", flexDirection: "column", gap: 4 },
  bullet: { color: "#e6ffe9", fontSize: 12, lineHeight: 1.6 },
  mitreGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
    gap: 10,
  },
  mitreGroup: {
    padding: "8px 10px",
    border: "1px solid rgba(126, 230, 168, 0.14)",
    background: "rgba(0, 40, 22, 0.28)", borderRadius: 3,
  },
  mitreTactic: { fontSize: 10, letterSpacing: 1.4, color: "#ffe0b3",
                  marginBottom: 6 },
  mitreList:   { listStyle: "none", padding: 0, margin: 0,
                  display: "flex", flexDirection: "column", gap: 3 },
  mitreItem:   { display: "flex", gap: 6, fontSize: 11, color: "#e6ffe9" },
  tid: { color: "#7ee6a8", letterSpacing: 1 },
  iocList: { listStyle: "none", padding: 0, margin: 0,
              display: "flex", flexDirection: "column", gap: 10 },
  iocItem: {
    padding: "10px 12px",
    border: "1px solid rgba(126, 230, 168, 0.18)",
    background: "rgba(0, 40, 22, 0.32)", borderRadius: 3,
  },
  iocHead: { display: "flex", gap: 10, alignItems: "baseline",
              marginBottom: 6, flexWrap: "wrap" },
  iocKind: { color: "#7ee6a8", fontSize: 10, letterSpacing: 1.4 },
  iocValue: { color: "#e6ffe9", fontSize: 12, wordBreak: "break-all", flex: 1 },
  verdictChip: {
    fontSize: 10, letterSpacing: 1.4, border: "1px solid",
    padding: "2px 8px", borderRadius: 3, marginLeft: "auto",
  },
  iocConfLine: {
    display: "flex", alignItems: "center", gap: 8,
    marginTop: 4, marginBottom: 8, fontSize: 12,
    color: "#e6ffe9",
  },
  iocConfLabel: { fontSize: 10, letterSpacing: 1.2, color: "#7ee6a8" },
  cachedTag: {
    fontSize: 9, letterSpacing: 1.2, padding: "1px 6px",
    border: "1px solid #4a8b63", color: "#96c9aa",
    borderRadius: 2, marginLeft: 6,
  },
  iocEvidenceBlock: { marginTop: 6, marginBottom: 8 },
  evidenceList: { listStyle: "none", padding: 0, margin: "4px 0 0",
                    display: "flex", flexDirection: "column", gap: 2 },
  evidenceItem: {
    display: "flex", gap: 8, alignItems: "baseline", fontSize: 11,
    color: "#e6ffe9",
  },
  evidenceProvider: { color: "#c5f5d6", minWidth: 110, textTransform: "capitalize" },
  evidenceDetail:   { color: "#96c9aa", flex: 1 },
  iocMetaGrid: { display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
                  gap: "3px 12px", fontSize: 11, marginTop: 6 },
  iocKv: { display: "flex", justifyContent: "space-between" },
  iocKvKey: { color: "#7ee6a8", letterSpacing: 1 },
  iocKvVal: { color: "#e6ffe9" },
  iocRelated: { marginTop: 8, display: "flex",
                 flexDirection: "column", gap: 4 },
  chipRow: { display: "flex", flexWrap: "wrap", gap: 4, alignItems: "center" },
  chipLabel: { fontSize: 10, letterSpacing: 1.2, color: "#7ee6a8",
                marginRight: 4 },
  chip: {
    fontSize: 10, padding: "1px 6px",
    border: "1px solid rgba(126, 230, 168, 0.3)",
    borderRadius: 2, color: "#c5f5d6",
  },
  footnote: { fontSize: 10, color: "#96c9aa", marginTop: 10, fontStyle: "italic" },
  confGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
    gap: 8,
  },
  confItem: {
    padding: "8px 10px",
    border: "1px solid rgba(126, 230, 168, 0.16)",
    background: "rgba(0, 40, 22, 0.28)", borderRadius: 3,
  },
  confKey: { fontSize: 10, letterSpacing: 1.4, color: "#7ee6a8" },
  confVal: { fontSize: 18, color: "#e6ffe9", marginTop: 4 },
  confMeta: { fontSize: 10, color: "#96c9aa", marginTop: 4 },
  gatewayRow: {
    marginTop: 14, paddingTop: 12,
    borderTop: "1px solid rgba(126, 230, 168, 0.18)",
    display: "flex", justifyContent: "flex-end",
  },
  primary: {
    background: "#0d3d24", color: "#7ee6a8",
    border: "1px solid #7ee6a8",
    padding: "8px 18px", borderRadius: 3,
    fontFamily: "inherit", fontSize: 12, letterSpacing: 1.2,
    cursor: "pointer", textTransform: "uppercase",
  },
  dim: { color: "#96c9aa", fontSize: 11 },
};
