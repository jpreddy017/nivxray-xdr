/**
 * v2/pages/ValidationPage.jsx · Validation Pack matrix (Phase 4.2).
 *
 * Runs the full Golden Investigation Corpus through the correlation
 * + IKG + verdict pipeline and shows a green/red per-dimension matrix.
 * Every dataset declares an ExpectedInvestigation contract; the runner
 * checks 11 dimensions and marks the row PASS only when all pass.
 */
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import api from "@/lib/api";
import { T } from "@/v2/theme";

const DIM_ORDER = [
  "Verdict", "Score", "FP-Guard", "MITRE",
  "Story", "StoryText", "Processes", "Parent-Child",
  "IOCs", "Workspace", "Report",
];

const CAT_TONE = {
  benign:      { fg: T.green, bg: T.amberBg, label: "BENIGN" },
  ambiguous:   { fg: T.blue,  bg: T.blueT,   label: "AMBIGUOUS" },
  suspicious:  { fg: "#F5B942", bg: "rgba(245,185,66,0.10)", label: "SUSPICIOUS" },
  malicious:   { fg: T.red,   bg: "rgba(248,113,113,0.10)", label: "MALICIOUS" },
};

function Cell({ ok, detail }) {
  return (
    <div
      title={detail || ""}
      style={{
        width: 22, height: 22, borderRadius: 4,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: ok ? "rgba(52,211,153,0.18)" : "rgba(248,113,113,0.18)",
        color: ok ? T.green : T.red,
        fontFamily: "JetBrains Mono, monospace", fontSize: 11, fontWeight: 700,
      }}
    >{ok ? "✓" : "✗"}</div>
  );
}

function MetricPill({ label, value, tone = "neutral" }) {
  const tones = {
    neutral: { fg: T.inkDim, bg: T.paper2, br: T.line },
    good:    { fg: T.green,  bg: T.amberBg, br: T.amber },
    bad:     { fg: T.red,    bg: "rgba(248,113,113,0.10)", br: T.red },
  };
  const s = tones[tone] || tones.neutral;
  return (
    <div style={{
      background: s.bg, border: `1px solid ${s.br}`, borderRadius: 8,
      padding: "10px 14px", minWidth: 140,
    }}>
      <div style={{ color: T.inkMute, fontSize: 10, letterSpacing: "0.14em",
                    fontFamily: "JetBrains Mono, monospace" }}>{label}</div>
      <div style={{ color: s.fg, fontSize: 22, fontWeight: 700, marginTop: 2,
                    fontFamily: "JetBrains Mono, monospace" }}>{value}</div>
    </div>
  );
}

export default function ValidationPage() {
  const [datasets, setDatasets] = useState([]);
  const [summary, setSummary] = useState(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    api.get("/v2/validation/datasets")
       .then(r => setDatasets(r.data?.datasets || []))
       .catch(() => setDatasets([]));
  }, []);

  const runAll = useCallback(async () => {
    setRunning(true);
    try {
      const { data } = await api.get("/v2/validation/run", { timeout: 60000 });
      setSummary(data);
      toast.success(`Validation complete · ${data.overall_accuracy}% accuracy`);
    } catch (ex) {
      toast.error("Run failed", { description: ex?.response?.data?.detail || String(ex) });
    } finally {
      setRunning(false);
    }
  }, []);

  const resultById = new Map((summary?.results || []).map(r => [r.id, r]));

  const acc = summary?.dimension_accuracy || {};
  const overall = summary?.overall_accuracy ?? null;

  return (
    <div
      data-testid="validation-page"
      style={{
        minHeight: "100vh", background: T.bg, color: T.ink,
        padding: "40px 32px",
        fontFamily: "Inter, -apple-system, BlinkMacSystemFont, sans-serif",
      }}
    >
      <div style={{ maxWidth: 1360, margin: "0 auto" }}>
        {/* Header */}
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 20 }}>
          <div>
            <div style={{ fontSize: 11, color: T.inkMute, letterSpacing: "0.14em",
                          fontFamily: "JetBrains Mono, monospace" }}>
              NIVXRAY · v2 · PHASE 4.2
            </div>
            <div style={{ fontSize: 28, fontWeight: 700, marginTop: 4 }}>
              Validation Pack
            </div>
            <div style={{ marginTop: 6, color: T.inkDim, fontSize: 14, maxWidth: 900 }}>
              Runs the Golden Investigation Corpus through the full ingestion →
              correlation → IKG → story → verdict pipeline. Every dataset ships
              with an ExpectedInvestigation contract; the runner checks 11
              dimensions independently and marks the row PASS only when every
              assertion holds. This is the release gate.
            </div>
          </div>
          <button
            data-testid="validation-run-all"
            disabled={running}
            onClick={runAll}
            style={{
              background: running ? T.paper2 : T.amber,
              color: running ? T.inkDim : T.paper,
              border: "none", padding: "12px 22px", borderRadius: 8,
              fontWeight: 700, cursor: running ? "wait" : "pointer",
              fontFamily: "JetBrains Mono, monospace",
              letterSpacing: "0.06em", fontSize: 12,
            }}
          >{running ? "RUNNING…" : "RUN VALIDATION →"}</button>
        </div>

        {/* Summary metrics */}
        {summary && (
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 20 }}
               data-testid="validation-summary">
            <MetricPill label="Overall Accuracy"
                        value={`${overall ?? 0}%`}
                        tone={overall >= 90 ? "good" : overall >= 70 ? "neutral" : "bad"} />
            <MetricPill label="Datasets" value={summary.datasets_total} />
            <MetricPill label="Passed"  value={summary.datasets_passed} tone="good" />
            <MetricPill label="Failed"  value={summary.datasets_failed}
                        tone={summary.datasets_failed > 0 ? "bad" : "good"} />
            <MetricPill label="Avg Investigation"
                        value={`${summary.average_investigation_ms} ms`} />
            <MetricPill label="Total Duration"
                        value={`${summary.duration_ms} ms`} />
          </div>
        )}

        {/* Per-dimension accuracy */}
        {summary && (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 24 }}>
            {DIM_ORDER.filter(k => k in acc).map(k => (
              <div key={k} style={{
                background: T.paper2, border: `1px solid ${T.line}`,
                borderRadius: 6, padding: "6px 10px", fontFamily: "JetBrains Mono, monospace",
              }}>
                <span style={{ color: T.inkMute, fontSize: 10 }}>{k}</span>
                <span style={{ marginLeft: 8, color: acc[k] === 100 ? T.green : T.red,
                               fontWeight: 700, fontSize: 12 }}>
                  {acc[k]}%
                </span>
              </div>
            ))}
          </div>
        )}

        {/* Matrix */}
        <div style={{
          background: T.cardGradient,
          border: `1px solid ${T.line}`,
          borderRadius: 12,
          overflow: "hidden",
        }}>
          <div style={{
            display: "grid",
            gridTemplateColumns: `260px 140px 100px 90px 90px repeat(${DIM_ORDER.length}, 30px) 90px`,
            padding: "12px 16px",
            borderBottom: `1px solid ${T.line}`,
            background: T.paper,
            fontSize: 10, color: T.inkMute,
            fontFamily: "JetBrains Mono, monospace",
            letterSpacing: "0.10em",
            gap: 8, alignItems: "center",
          }}>
            <div>DATASET</div>
            <div>CATEGORY</div>
            <div>BAND</div>
            <div>SCORE</div>
            <div>CONF</div>
            {DIM_ORDER.map(d => (
              <div key={d} style={{
                writingMode: "vertical-rl", transform: "rotate(180deg)",
                textAlign: "left", height: 60,
              }}>{d}</div>
            ))}
            <div style={{ textAlign: "right" }}>OVERALL</div>
          </div>
          {datasets.map(d => {
            const r = resultById.get(d.id);
            const tone = CAT_TONE[d.category] || CAT_TONE.malicious;
            const dimMap = new Map((r?.dimensions || []).map(x => [x.name, x]));
            return (
              <div key={d.id}
                   data-testid={`validation-row-${d.id}`}
                   style={{
                     display: "grid",
                     gridTemplateColumns: `260px 140px 100px 90px 90px repeat(${DIM_ORDER.length}, 30px) 90px`,
                     padding: "10px 16px",
                     borderBottom: `1px solid ${T.line}`,
                     gap: 8, alignItems: "center", fontSize: 12,
                   }}>
                <div>
                  <div style={{ color: T.ink, fontWeight: 600, fontSize: 12 }}>{d.label}</div>
                  <div style={{ color: T.inkFaint, fontSize: 10,
                                fontFamily: "JetBrains Mono, monospace", marginTop: 2 }}>
                    {d.id}
                  </div>
                </div>
                <div>
                  <span style={{
                    padding: "2px 8px", borderRadius: 999,
                    color: tone.fg, background: tone.bg,
                    border: `1px solid ${tone.fg}`,
                    fontSize: 9, letterSpacing: "0.08em",
                    fontFamily: "JetBrains Mono, monospace",
                  }}>{tone.label}</span>
                </div>
                <div style={{ color: T.inkDim, fontFamily: "JetBrains Mono, monospace", fontSize: 11 }}>
                  {r ? r.verdict_band : "—"}
                </div>
                <div style={{ color: T.ink, fontFamily: "JetBrains Mono, monospace",
                              fontWeight: 700, fontSize: 12 }}>
                  {r ? r.device_score : "—"}
                </div>
                <div style={{ color: T.inkDim, fontFamily: "JetBrains Mono, monospace", fontSize: 11 }}>
                  {r ? `${r.confidence}%` : "—"}
                </div>
                {DIM_ORDER.map(dim => {
                  const x = dimMap.get(dim);
                  if (!x) return <div key={dim} style={{ color: T.inkFaint, textAlign: "center" }}>—</div>;
                  return <Cell key={dim} ok={x.ok} detail={x.detail} />;
                })}
                <div style={{ textAlign: "right" }}>
                  {r ? (
                    <span style={{
                      padding: "3px 10px", borderRadius: 999,
                      color: r.overall ? T.green : T.red,
                      background: r.overall ? "rgba(52,211,153,0.14)" : "rgba(248,113,113,0.14)",
                      border: `1px solid ${r.overall ? T.green : T.red}`,
                      fontSize: 10, letterSpacing: "0.08em", fontWeight: 700,
                      fontFamily: "JetBrains Mono, monospace",
                    }}>{r.overall ? "PASS" : "FAIL"}</span>
                  ) : <span style={{ color: T.inkFaint, fontSize: 10 }}>—</span>}
                </div>
              </div>
            );
          })}
        </div>

        <div style={{ marginTop: 20, color: T.inkMute, fontSize: 11,
                      fontFamily: "JetBrains Mono, monospace" }}>
          The Validation Pack is a hard release gate — any regression fails the CI
          `pytest tests/test_validation_pack.py` run. Extend the corpus by adding
          new datasets to `v2/ingestion/golden_corpus.py` with their
          ExpectedInvestigation contract.
        </div>
      </div>
    </div>
  );
}
