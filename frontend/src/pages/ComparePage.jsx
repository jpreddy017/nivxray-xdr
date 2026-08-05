/**
 * ComparePage — Phase A.5 · items 1 + 2 (fingerprint-powered
 * Compare Cases UI + Confidence Provenance Visualization).
 *
 * Owner-locked design (2026-02-16):
 *   - Split-pane analyst workspace: Case A ↔ Case B
 *   - Overall similarity gauge + per-dimension Jaccard bars
 *   - "Similarity Explanation" (the Why-are-they-similar chain)
 *   - "Confidence Provenance" panel per side (the Why-did-each-
 *     case-score-what-it-scored chain, sums visibly to derived score)
 *   - Zero AI, zero mocked data — every field is a deterministic
 *     read from POST /api/correlations/compare which auto-attaches
 *     Confidence Provenance to both cases.
 */
import { useEffect, useMemo, useState } from "react";
import { useParams, useNavigate, useSearchParams } from "react-router-dom";
import Header from "@/components/Header";
import api from "@/lib/api";
import { useEvidenceModal } from "@/components/EvidenceModal";
import { fromProvenanceRuleFire } from "@/components/evidenceDescriptors";
import {
  Radar,
  ShieldAlert,
  Layers,
  GitCompareArrows,
  Info,
  Cpu,
  FileText,
} from "lucide-react";

const COL = {
  bg:      "var(--bg,#0b1220)",
  panel:   "#0f1a2c",
  border:  "#1f2b3f",
  muted:   "#94a3b8",
  accent:  "#38bdf8",
  good:    "#86efac",
  bad:     "#f87171",
  warn:    "#fbbf24",
  text:    "#e5e7eb",
};

// ═══════════════════════════════════════════════════════════════════
// Root page
// ═══════════════════════════════════════════════════════════════════
export default function ComparePage() {
  const { caseA: paramA, caseB: paramB } = useParams();
  const [search] = useSearchParams();
  const nav = useNavigate();

  const initialA = paramA || search.get("a") || "";
  const initialB = paramB || search.get("b") || "";

  const [caseA, setCaseA]   = useState(initialA);
  const [caseB, setCaseB]   = useState(initialB);
  const [running, setRun]   = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError]   = useState("");

  const [history, setHistory] = useState([]);
  useEffect(() => {
    (async () => {
      try {
        const r = await api.get("/history", { params: { limit: 100 } });
        setHistory(r.data?.items || []);
      } catch {
        /* silently ignored — the picker still works with pasted IDs */
      }
    })();
  }, []);

  const run = async (a, b) => {
    if (!a || !b) { setError("Both case IDs are required."); return; }
    setRun(true); setError(""); setResult(null);
    try {
      const r = await api.post("/correlations/compare",
        { case_a_id: a, case_b_id: b });
      setResult(r.data);
      nav(`/compare/${a}/${b}`, { replace: true });
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || String(e));
    } finally { setRun(false); }
  };

  useEffect(() => {
    if (initialA && initialB) run(initialA, initialB);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div style={{ minHeight: "100vh", background: COL.bg, color: COL.text }}
         data-testid="compare-page">
      <Header />
      <div style={{ maxWidth: 1400, margin: "0 auto", padding: "28px 24px" }}>
        <PageTitle />
        <CasePicker
          history={history}
          caseA={caseA} setCaseA={setCaseA}
          caseB={caseB} setCaseB={setCaseB}
          onRun={() => run(caseA, caseB)}
          running={running}
        />
        {error && (
          <div data-testid="compare-error"
               style={{ marginTop: 16, padding: 12, borderRadius: 8,
                        background: "#3a1d1d", color: COL.bad }}>
            {error}
          </div>
        )}
        {running && (
          <div data-testid="compare-running"
               style={{ marginTop: 24, textAlign: "center", color: COL.muted }}>
            Running deterministic comparison…
          </div>
        )}
        {result && <CompareResult result={result} caseA={caseA} caseB={caseB}
                                   onOpenEvidence={evi.open} />}
      </div>
      {evi.modal}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// Header
// ═══════════════════════════════════════════════════════════════════
function PageTitle() {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 14,
                  marginBottom: 20 }}>
      <div style={{ background: "#0e223b", padding: 10, borderRadius: 10 }}>
        <GitCompareArrows size={24} color={COL.accent} />
      </div>
      <div>
        <h1 data-testid="compare-page-title"
            style={{ fontSize: 26, margin: 0, letterSpacing: -0.3 }}>
          Compare Cases
        </h1>
        <div style={{ color: COL.muted, fontSize: 13, marginTop: 2 }}>
          Deterministic side-by-side · Similarity Explanation ·
          Confidence Provenance
        </div>
      </div>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// Case picker
// ═══════════════════════════════════════════════════════════════════
function CasePicker({ history, caseA, setCaseA, caseB, setCaseB,
                      onRun, running }) {
  const opts = history.slice(0, 60);
  return (
    <div style={{ background: COL.panel, border: `1px solid ${COL.border}`,
                  borderRadius: 12, padding: 16 }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto",
                    gap: 12, alignItems: "end" }}>
        <SideSelect label="Case A" value={caseA} setValue={setCaseA}
                    opts={opts} testid="compare-case-a-input" />
        <SideSelect label="Case B" value={caseB} setValue={setCaseB}
                    opts={opts} testid="compare-case-b-input" />
        <button data-testid="compare-run-button"
                onClick={onRun} disabled={running || !caseA || !caseB}
                style={{
                  background: COL.accent, color: "#052437",
                  border: "none", borderRadius: 10, padding: "10px 20px",
                  fontWeight: 600, cursor: running ? "wait" : "pointer",
                  opacity: (!caseA || !caseB) ? 0.5 : 1
                }}>
          {running ? "Comparing…" : "Compare"}
        </button>
      </div>
    </div>
  );
}

function SideSelect({ label, value, setValue, opts, testid }) {
  return (
    <div>
      <div style={{ fontSize: 12, color: COL.muted, marginBottom: 6 }}>
        {label}
      </div>
      <input
        data-testid={testid}
        list={`${testid}-list`}
        value={value}
        onChange={(e) => setValue(e.target.value.trim())}
        placeholder="paste case id or pick from history"
        style={{
          width: "100%", padding: "10px 12px", borderRadius: 8,
          border: `1px solid ${COL.border}`, background: "#0a1526",
          color: COL.text, fontFamily: "ui-monospace, monospace",
          fontSize: 13
        }} />
      <datalist id={`${testid}-list`}>
        {opts.map(o => (
          <option key={o.id} value={o.id}>
            {String(o.name || o.verdict || "case").slice(0, 60)}
          </option>
        ))}
      </datalist>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// Result body
// ═══════════════════════════════════════════════════════════════════
function CompareResult({ result, caseA, caseB, onOpenEvidence }) {
  const overall = result.similarity_score?.overall ?? 0;
  const fpMatch = !!result.fingerprint_match;

  return (
    <div data-testid="compare-result" style={{ marginTop: 22 }}>
      <SimilarityGauge overall={overall} fpMatch={fpMatch} result={result} />
      <SimilarityExplanation
        explanation={result.similarity_score?.explanation} />
      <DimensionMatrix dims={result.dimensions}
                       perDim={result.similarity_score?.per_dimension} />
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr",
                    gap: 16, marginTop: 22 }}>
        <CaseColumn side="A" caseId={caseA} verdict={result.verdicts?.a}
                    provenance={result.dimensions?.confidence_provenance?.a}
                    onOpenEvidence={onOpenEvidence} />
        <CaseColumn side="B" caseId={caseB} verdict={result.verdicts?.b}
                    provenance={result.dimensions?.confidence_provenance?.b}
                    onOpenEvidence={onOpenEvidence} />
      </div>
      <FingerprintDetail dim={result.dimensions?.attack_fingerprint} />
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// Overall similarity gauge
// ═══════════════════════════════════════════════════════════════════
function SimilarityGauge({ overall, fpMatch, result }) {
  const pct = Math.round(overall * 100);
  const ring = pct >= 80 ? COL.good : pct >= 40 ? COL.warn : COL.bad;
  return (
    <div data-testid="similarity-gauge"
         style={{ background: COL.panel, border: `1px solid ${COL.border}`,
                  borderRadius: 12, padding: 20,
                  display: "flex", gap: 24, alignItems: "center" }}>
      <div style={{ position: "relative", width: 130, height: 130 }}>
        <svg viewBox="0 0 100 100" width="100%" height="100%">
          <circle cx="50" cy="50" r="42" fill="none"
                  stroke={COL.border} strokeWidth="8" />
          <circle cx="50" cy="50" r="42" fill="none"
                  stroke={ring} strokeWidth="8"
                  strokeDasharray={`${(pct/100) * 263.9} 263.9`}
                  strokeLinecap="round"
                  transform="rotate(-90 50 50)"
                  data-testid="similarity-gauge-arc" />
        </svg>
        <div style={{
          position: "absolute", inset: 0, display: "flex",
          alignItems: "center", justifyContent: "center",
          fontSize: 28, fontWeight: 700, color: ring,
        }} data-testid="similarity-gauge-value">
          {pct}%
        </div>
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 13, color: COL.muted }}>
          Overall Similarity
        </div>
        <div style={{ fontSize: 22, fontWeight: 600, marginTop: 4 }}>
          {pct >= 80 ? "Highly similar campaigns" :
           pct >= 40 ? "Partial overlap" :
                       "Distinct investigations"}
        </div>
        <div style={{ marginTop: 10, display: "flex", gap: 20,
                      flexWrap: "wrap", fontSize: 13 }}>
          <Chip label="Fingerprint" value={fpMatch ? "Match" : "Different"}
                testid="fp-match-chip"
                color={fpMatch ? COL.good : COL.warn} />
          <Chip label="Compare v" value={result.compare_version}
                testid="compare-version-chip" />
          <Chip label="Case A" value={result.case_a_id?.slice(0, 12) + "…"}
                testid="case-a-id-chip" />
          <Chip label="Case B" value={result.case_b_id?.slice(0, 12) + "…"}
                testid="case-b-id-chip" />
        </div>
      </div>
    </div>
  );
}

function Chip({ label, value, color, testid }) {
  return (
    <div data-testid={testid} style={{ display: "flex", alignItems: "center",
                  gap: 6, color: COL.muted, fontFamily: "ui-monospace, monospace" }}>
      <span>{label}:</span>
      <span style={{ color: color || COL.text, fontWeight: 500 }}>{value}</span>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// Similarity Explanation — "Why is this X%?"
// ═══════════════════════════════════════════════════════════════════
function SimilarityExplanation({ explanation }) {
  if (!explanation) return null;
  const nonzero = explanation.contributors.filter(c => c.contribution > 0);
  return (
    <div data-testid="similarity-explanation"
         style={{ marginTop: 16, background: COL.panel,
                  border: `1px solid ${COL.border}`,
                  borderRadius: 12, padding: 20 }}>
      <SectionHeader icon={<Info size={16} />}
                     title="Similarity Explanation"
                     hint="Every contributor sums to the overall score" />
      <div style={{ display: "flex", flexDirection: "column", gap: 8,
                    marginTop: 12 }}>
        {nonzero.length === 0 && (
          <div style={{ color: COL.muted, fontSize: 13 }}>
            No shared signals between these two cases.
          </div>
        )}
        {nonzero.map(c => (
          <ContribRow key={c.dimension} contrib={c} />
        ))}
      </div>
    </div>
  );
}

function ContribRow({ contrib }) {
  const pct = Math.round(contrib.contribution);
  const filled = Math.min(100, pct);
  return (
    <div data-testid={`similarity-contrib-${contrib.dimension}`}
         style={{ display: "grid",
                  gridTemplateColumns: "220px 1fr 90px 120px",
                  gap: 12, alignItems: "center" }}>
      <div style={{ fontFamily: "ui-monospace, monospace", fontSize: 13 }}>
        {contrib.dimension}
      </div>
      <div style={{ height: 8, background: COL.border, borderRadius: 4,
                    overflow: "hidden" }}>
        <div style={{ width: `${filled}%`, height: "100%",
                      background: COL.accent }} />
      </div>
      <div style={{ fontSize: 13, color: COL.muted, textAlign: "right" }}>
        +{contrib.contribution}%
      </div>
      <div style={{ fontSize: 12, color: COL.muted, textAlign: "right",
                    fontFamily: "ui-monospace, monospace" }}>
        j={contrib.jaccard} · w={contrib.weight}
      </div>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// Per-dimension matrix (all 14 dimensions with shared/unique counts)
// ═══════════════════════════════════════════════════════════════════
const DIM_LABELS = {
  threat_summary:       "Threat Summary",
  attack_chain:         "Attack Chain",
  timeline:             "Timeline",
  mitre:                "MITRE",
  iocs:                 "IOCs",
  recipe:               "Recipe",
  transformation_trace: "Transformation Trace",
  decision_trace:       "Decision Trace",
  interpreter_chain:    "Interpreter Chain",
  artifact_graph:       "Artifact Graph",
  canonical_hashes:     "Canonical Hashes",
  behavior_codes:       "Behavior Codes",
  attack_fingerprint:   "Attack Fingerprint",
  confidence_provenance: "Confidence Provenance",
};

function DimensionMatrix({ dims, perDim }) {
  if (!dims) return null;
  const order = Object.keys(DIM_LABELS);
  return (
    <div data-testid="dimension-matrix"
         style={{ marginTop: 16, background: COL.panel,
                  border: `1px solid ${COL.border}`, borderRadius: 12,
                  padding: 20 }}>
      <SectionHeader icon={<Layers size={16} />}
                     title="Per-Dimension Diff"
                     hint="Shared / unique to A / unique to B" />
      <div style={{ display: "flex", flexDirection: "column",
                    gap: 8, marginTop: 12 }}>
        {order.map(k => {
          const d = dims[k];
          if (!d) return null;
          return <DimensionRow key={k} name={DIM_LABELS[k]} dim={d}
                               perDim={perDim?.[k]} testid={`dim-${k}`} />;
        })}
      </div>
    </div>
  );
}

function DimensionRow({ name, dim, perDim, testid }) {
  const shared = dim.shared?.length ?? dim.shared_count ?? 0;
  const aOnly = dim.a_only?.length ?? dim.a_only_count ?? 0;
  const bOnly = dim.b_only?.length ?? dim.b_only_count ?? 0;
  const j = perDim?.jaccard ?? dim.jaccard;
  const filled = Math.round((j ?? 0) * 100);
  const isEqual = dim.equal || dim.match || (shared > 0 && !aOnly && !bOnly);
  return (
    <div data-testid={testid}
         style={{ display: "grid",
                  gridTemplateColumns: "220px 1fr 60px 220px",
                  gap: 12, alignItems: "center" }}>
      <div style={{ fontSize: 13 }}>{name}</div>
      <div style={{ height: 8, background: COL.border, borderRadius: 4,
                    overflow: "hidden" }}>
        <div style={{ width: `${filled}%`, height: "100%",
                      background: isEqual ? COL.good : COL.accent }} />
      </div>
      <div style={{ fontSize: 12, color: COL.muted, textAlign: "right" }}>
        {j != null ? `${filled}%` : "—"}
      </div>
      <div style={{ fontSize: 12, color: COL.muted, textAlign: "right",
                    fontFamily: "ui-monospace, monospace" }}>
        <span style={{ color: COL.good }}>shared:{shared}</span>{"  "}
        <span style={{ color: COL.accent }}>A:{aOnly}</span>{"  "}
        <span style={{ color: COL.warn }}>B:{bOnly}</span>
      </div>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// Per-case column with Confidence Provenance
// ═══════════════════════════════════════════════════════════════════
function CaseColumn({ side, caseId, verdict, provenance, onOpenEvidence }) {
  const vLabel = verdict?.verdict || provenance?.derived?.verdict || "—";
  const vScore = verdict?.risk_score ?? provenance?.derived?.risk_score ?? "—";
  const bgVerdict = /malicious/i.test(vLabel) ? COL.bad :
                    /suspicious/i.test(vLabel) ? COL.warn :
                    /benign|low/i.test(vLabel) ? COL.good : COL.muted;
  return (
    <div data-testid={`case-column-${side.toLowerCase()}`}
         style={{ background: COL.panel, border: `1px solid ${COL.border}`,
                  borderRadius: 12, padding: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between",
                    alignItems: "center", marginBottom: 12 }}>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <div style={{ background: "#0e223b", padding: 6,
                        borderRadius: 6 }}>
            <ShieldAlert size={14} color={COL.accent} />
          </div>
          <div style={{ fontSize: 14 }}>Case {side}</div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center",
                      fontSize: 12, fontFamily: "ui-monospace, monospace" }}>
          <span style={{ color: COL.muted }}>{(caseId || "").slice(0, 14)}…</span>
        </div>
      </div>
      <div style={{ display: "flex", gap: 10, alignItems: "center",
                    marginBottom: 14 }}>
        <div style={{ background: "#0a1526", padding: "8px 12px",
                      borderRadius: 8, border: `1px solid ${COL.border}` }}>
          <div style={{ fontSize: 11, color: COL.muted }}>Verdict</div>
          <div style={{ color: bgVerdict, fontWeight: 600 }}>{vLabel}</div>
        </div>
        <div style={{ background: "#0a1526", padding: "8px 12px",
                      borderRadius: 8, border: `1px solid ${COL.border}` }}>
          <div style={{ fontSize: 11, color: COL.muted }}>Risk score</div>
          <div style={{ fontWeight: 600 }}>{vScore}</div>
        </div>
      </div>
      <ProvenancePanel provenance={provenance} side={side}
                       onOpenEvidence={onOpenEvidence} />
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// Confidence Provenance — the "Why?" chain
// ═══════════════════════════════════════════════════════════════════
function ProvenancePanel({ provenance, side, onOpenEvidence }) {
  if (!provenance || (!provenance.provenance_hash && !provenance.rules?.length)) {
    return (
      <div style={{ color: COL.muted, fontSize: 13 }}>
        No Confidence Provenance available for this case.
      </div>
    );
  }
  const p = provenance;
  const total = p.derived?.risk_score ?? 0;
  return (
    <div data-testid={`provenance-panel-${side.toLowerCase()}`}>
      <SectionHeader icon={<Cpu size={16} />}
                     title="Confidence Provenance"
                     hint={`v${p.provenance_version || "1.0"}`} />
      <div style={{ marginTop: 10, marginBottom: 12, fontSize: 12,
                    color: COL.muted }}>
        {p.rules?.length || 0} rule(s) fired ·{" "}
        {p.rules_skipped?.length || 0} skipped ·{" "}
        <span style={{ color: COL.text }}>derived score {total}</span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {(p.rules || []).map((r, i) => (
          <RuleFireRow key={r.id} rule={r} score={total}
                       testid={`${side.toLowerCase()}-rule-${r.id}`}
                       onOpenEvidence={onOpenEvidence
                         ? () => onOpenEvidence(fromProvenanceRuleFire(r, side))
                         : null} />
        ))}
      </div>
      {p.rules?.length > 0 && (
        <div data-testid={`${side.toLowerCase()}-provenance-total`}
             style={{ marginTop: 10, paddingTop: 10,
                      borderTop: `1px dashed ${COL.border}`,
                      display: "flex", justifyContent: "space-between",
                      fontFamily: "ui-monospace, monospace" }}>
          <span style={{ color: COL.muted }}>Total</span>
          <span style={{ color: COL.text, fontWeight: 700 }}>
            {(p.rules || []).reduce((s, r) => s + (r.contribution || 0), 0)}
          </span>
        </div>
      )}
    </div>
  );
}

function RuleFireRow({ rule, score, testid, onOpenEvidence }) {
  const clickable = !!onOpenEvidence;
  return (
    <div data-testid={testid}
         onClick={clickable ? onOpenEvidence : undefined}
         role={clickable ? "button" : undefined}
         tabIndex={clickable ? 0 : undefined}
         onKeyDown={clickable
           ? (e) => { if (e.key === "Enter" || e.key === " ") onOpenEvidence(); }
           : undefined}
         style={{ display: "grid",
                  gridTemplateColumns: "1fr 60px 220px",
                  gap: 10, alignItems: "center",
                  padding: "6px 10px", background: "#0a1526",
                  borderRadius: 6,
                  cursor: clickable ? "pointer" : "default",
                  transition: "background 0.15s ease" }}
         onMouseEnter={clickable
           ? (e) => e.currentTarget.style.background = "#13233d"
           : undefined}
         onMouseLeave={clickable
           ? (e) => e.currentTarget.style.background = "#0a1526"
           : undefined}>
      <div>
        <div style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>
          + {rule.contribution} · {rule.id}
        </div>
        <div style={{ fontSize: 11, color: COL.muted, marginTop: 2 }}>
          {rule.description}
        </div>
      </div>
      <div style={{ fontSize: 11, color: COL.muted, textAlign: "right",
                    fontFamily: "ui-monospace, monospace" }}>
        w={rule.weight}
      </div>
      <div style={{ fontSize: 11, color: COL.muted,
                    fontFamily: "ui-monospace, monospace",
                    textAlign: "right",
                    whiteSpace: "nowrap", overflow: "hidden",
                    textOverflow: "ellipsis" }}
           title={JSON.stringify(rule.evidence_refs)}>
        {rule.hit_count} evidence hit(s)
      </div>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// Fingerprint detail
// ═══════════════════════════════════════════════════════════════════
function FingerprintDetail({ dim }) {
  if (!dim) return null;
  return (
    <div data-testid="fingerprint-detail"
         style={{ marginTop: 16, background: COL.panel,
                  border: `1px solid ${COL.border}`, borderRadius: 12,
                  padding: 20 }}>
      <SectionHeader icon={<Radar size={16} />}
                     title="Attack Fingerprint"
                     hint={dim.match ? "Fingerprints match" :
                                       "Fingerprints differ"} />
      <div style={{ marginTop: 10, display: "grid",
                    gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <HashCell label="A" hash={dim.a_hash} />
        <HashCell label="B" hash={dim.b_hash} />
      </div>
      <div style={{ marginTop: 14 }}>
        <div style={{ fontSize: 12, color: COL.muted, marginBottom: 6 }}>
          Component digests match:
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {Object.entries(dim.component_matches || {}).map(([k, v]) => (
            <span key={k}
                  data-testid={`component-match-${k}`}
                  style={{ padding: "3px 8px", borderRadius: 6,
                           fontSize: 11,
                           fontFamily: "ui-monospace, monospace",
                           background: v ? "#0f2b1a" : "#2b0f0f",
                           color: v ? COL.good : COL.bad }}>
              {k.replace("_digest", "")}: {v ? "✓" : "✗"}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function HashCell({ label, hash }) {
  return (
    <div style={{ background: "#0a1526", border: `1px solid ${COL.border}`,
                  borderRadius: 8, padding: 10 }}>
      <div style={{ fontSize: 11, color: COL.muted }}>{label}</div>
      <div style={{ marginTop: 3, fontFamily: "ui-monospace, monospace",
                    fontSize: 12, wordBreak: "break-all" }}>
        {hash || <span style={{ color: COL.muted }}>—</span>}
      </div>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
// Shared helper
// ═══════════════════════════════════════════════════════════════════
function SectionHeader({ icon, title, hint }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between",
                  alignItems: "center" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center",
                    fontSize: 14, fontWeight: 600 }}>
        <span style={{ color: COL.accent }}>{icon}</span>{title}
      </div>
      {hint && (
        <div style={{ fontSize: 12, color: COL.muted }}>{hint}</div>
      )}
    </div>
  );
}
