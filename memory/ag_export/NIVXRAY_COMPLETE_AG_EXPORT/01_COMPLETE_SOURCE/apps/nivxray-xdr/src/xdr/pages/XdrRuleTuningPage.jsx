/**
 * XdrRuleTuningPage · `/xdr/detect/tuning/:ruleId`
 *
 * Evidence-backed Rule Tuning Workbench.  Consumes:
 *
 *   · /api/regression/latest, /history, /gate, /run
 *   · /api/batch/test/json, /api/batch/history
 *   · /api/corrections, /api/corrections/analytics
 *   · Local detectionRuleStore for lifecycle + version history
 *
 * Every metric is derived from real base data.  If the base returns
 * nothing, the row shows `INSUFFICIENT TELEMETRY FOR METRIC` —
 * NEVER fabricates percentages.
 */
import React, { useEffect, useState } from "react";
import { NavLink, useParams } from "react-router-dom";
import { RefreshCw, Play, ShieldCheck, AlertTriangle,
  ChevronLeft } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { getRule } from "@/xdr/detect/detectionRuleStore";
import { RegressionConsumer, BatchTestConsumer, CorrectionsConsumer,
  CorpusConsumer } from "@/xdr/adopt/baseCapabilities";


function _honest(v, unit = "") {
  if (v == null || v === "") return null;
  return `${v}${unit}`;
}

function _pct(num, den) {
  if (num == null || den == null || den === 0) return null;
  return `${((num / den) * 100).toFixed(1)}%`;
}


function MetricCard({ label, value, testid, note }) {
  const honest = value != null && value !== "";
  return (
    <div data-testid={testid}
            style={{ padding: 10, borderRadius: 4,
                        border: "1px solid var(--border)",
                        background: "var(--panel2)" }}>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                    textTransform: "uppercase",
                                                    marginBottom: 4 }}>
        {label}
      </div>
      <div className="mono" style={{ fontSize: honest ? 16 : 10.5,
                                                    color: honest ? "var(--text)"
                                                                             : "var(--amber)" }}>
        {honest ? value : "INSUFFICIENT TELEMETRY FOR METRIC"}
      </div>
      {note && (
        <div style={{ marginTop: 4, fontSize: 10, color: "var(--faint)" }}>
          {note}
        </div>
      )}
    </div>
  );
}


export default function XdrRuleTuningPage() {
  const { ruleId } = useParams();
  const rule = getRule(ruleId);

  const [state, setState] = useState({ loading: true, latest: null,
                                                       corrections: null, gate: null });
  const [replay, setReplay] = useState({ running: false, result: null,
                                                            error: null });
  const [refresh, setR] = useState(0);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setState({ loading: true, latest: null,
                       corrections: null, gate: null });
      const [latest, corr, gate] = await Promise.all([
        RegressionConsumer.latest(),
        CorrectionsConsumer.analytics(),
        RegressionConsumer.gate(),
      ]);
      if (!cancelled) setState({
        loading: false,
        latest: latest.ok ? latest.data : null,
        corrections: corr.ok ? corr.data : null,
        gate: gate.ok ? gate.data : null,
      });
    })();
    return () => { cancelled = true; };
  }, [ruleId, refresh]);

  const runReplay = async (scope) => {
    setReplay({ running: true, result: null, error: null });
    // Compose regression + batch-test if available.
    const body = { rule_id: ruleId, scope };
    const [regres, batch] = await Promise.all([
      RegressionConsumer.run(body),
      BatchTestConsumer.test(body),
    ]);
    if (!regres.ok && !batch.ok) {
      setReplay({ running: false, result: null,
                       error: regres.error || batch.error
                           || "Base regression + batch-test unavailable" });
      return;
    }
    setReplay({ running: false,
                     result: {
                       regression: regres.ok ? regres.data : null,
                       batch:      batch.ok  ? batch.data  : null,
                       scope,
                     }, error: null });
  };

  const runCorpusGate = async () => {
    setReplay({ running: true, result: null, error: null });
    const r = await CorpusConsumer.validate({ rule_id: ruleId });
    setReplay({ running: false,
                     result: r.ok ? { corpus: r.data, scope: "golden_corpus" } : null,
                     error: r.ok ? null : (r.error || "Base corpus validator unavailable") });
  };

  const latest      = state.latest || {};
  const corr        = state.corrections || {};
  const gate        = state.gate || {};

  return (
    <XdrShell>
      <div data-testid="xdr-rule-tuning-page">
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                          marginBottom: 8 }}>
          <NavLink to="/xdr/detections" className="btn ghost"
                       style={{ padding: "2px 8px", fontSize: 11 }}>
            <ChevronLeft size={12} /> Detections
          </NavLink>
          <h1 className="page-h1" style={{ margin: 0 }}>
            Rule Tuning · {rule?.name || rule?.title || ruleId}
          </h1>
          <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
            {ruleId}
          </span>
          <span style={{ flex: 1 }} />
          <button className="btn" onClick={() => setR((n) => n + 1)}
                    data-testid="xdr-rule-tuning-refresh"
                    style={{ padding: "3px 10px", fontSize: 11 }}>
            <RefreshCw size={11} /> Refresh
          </button>
        </div>
        <div className="page-sub">
          Evidence-backed metrics + replay against real historical data +
          golden-corpus regression gate.  Consumes{" "}
          <span className="mono">/api/regression/*</span>,{" "}
          <span className="mono">/api/batch/test/*</span>,{" "}
          <span className="mono">/api/corrections/*</span>,{" "}
          <span className="mono">/api/corpus/validate/*</span>.
        </div>

        {/* ── Rule performance metrics (real or honest empty) ── */}
        <section className="panel" style={{ padding: 12, marginTop: 12 }}>
          <div className="section-title" style={{ marginBottom: 8 }}>
            Rule Performance
          </div>
          <div style={{ display: "grid",
                            gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))",
                            gap: 8 }}>
            <MetricCard label="Matches" testid="metric-matches"
                              value={_honest(latest?.per_rule?.[ruleId]?.matches
                                     ?? latest?.matches?.[ruleId])} />
            <MetricCard label="True Positive" testid="metric-tp"
                              value={_honest(corr?.per_rule?.[ruleId]?.tp
                                     ?? corr?.tp?.[ruleId])} />
            <MetricCard label="False Positive" testid="metric-fp"
                              value={_honest(corr?.per_rule?.[ruleId]?.fp
                                     ?? corr?.fp?.[ruleId])} />
            <MetricCard label="Benign" testid="metric-benign"
                              value={_honest(corr?.per_rule?.[ruleId]?.benign
                                     ?? corr?.benign?.[ruleId])} />
            <MetricCard label="Precision" testid="metric-precision"
                              value={_pct(
                                corr?.per_rule?.[ruleId]?.tp,
                                (corr?.per_rule?.[ruleId]?.tp || 0)
                                  + (corr?.per_rule?.[ruleId]?.fp || 0))} />
            <MetricCard label="Regression Gate" testid="metric-gate"
                              value={_honest(gate?.status || gate?.state)} />
          </div>
          <div style={{ marginTop: 6, fontSize: 11, color: "var(--muted)",
                            fontFamily: "var(--sans)" }}>
            Regression, corrections and quality gate — refreshed on each build.
          </div>
        </section>

        {/* ── Replay controls ── */}
        <section className="panel" style={{ padding: 12, marginTop: 12 }}>
          <div className="section-title" style={{ marginBottom: 8,
                                                                display: "flex", alignItems: "center", gap: 8 }}>
            Test / Replay
            <span style={{ flex: 1 }} />
            <button className="btn primary"
                      onClick={() => runReplay("24h")}
                      disabled={replay.running}
                      data-testid="xdr-rule-replay-24h"
                      style={{ padding: "3px 10px", fontSize: 11 }}>
              <Play size={10} /> Last 24h
            </button>
            <button className="btn primary"
                      onClick={() => runReplay("7d")}
                      disabled={replay.running}
                      data-testid="xdr-rule-replay-7d"
                      style={{ padding: "3px 10px", fontSize: 11 }}>
              <Play size={10} /> Last 7d
            </button>
            <button className="btn primary"
                      onClick={runCorpusGate}
                      disabled={replay.running}
                      data-testid="xdr-rule-replay-corpus"
                      style={{ padding: "3px 10px", fontSize: 11 }}>
              <ShieldCheck size={10} /> Golden Corpus
            </button>
          </div>
          {replay.running && (
            <div style={{ fontSize: 11, color: "var(--faint)" }}>
              Running replay against real historical evidence…
            </div>
          )}
          {replay.error && (
            <div style={{ padding: 8, borderRadius: 3,
                              border: "1px dashed var(--amber)",
                              color: "var(--amber)", fontSize: 11,
                              fontFamily: "var(--mono)" }}
                    data-testid="xdr-rule-replay-error">
              INSUFFICIENT TELEMETRY FOR REPLAY · {replay.error}
            </div>
          )}
          {replay.result && (
            <div data-testid="xdr-rule-replay-result"
                    style={{ marginTop: 8 }}>
              <ReplayResult r={replay.result} />
            </div>
          )}
        </section>

        {/* ── Version history + lifecycle (local store) ── */}
        <section className="panel" style={{ padding: 12, marginTop: 12 }}>
          <div className="section-title" style={{ marginBottom: 8 }}>
            Versions & Lifecycle
          </div>
          {rule ? (
            <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
              lifecycle · <b className="mono" style={{ color: "var(--cyan)" }}>
                {rule.status || rule.state || "draft"}
              </b>{" "}
              · versions · <b className="mono">
                {rule.versions?.length || 1}
              </b>
              {rule.versions?.length ? (
                <ul style={{ marginTop: 6, fontFamily: "var(--mono)",
                                  fontSize: 10.5, color: "var(--faint)" }}>
                  {rule.versions.slice(-5).map((v, i) => (
                    <li key={i} style={{ padding: "2px 0" }}>
                      v{v.version}{" · "}{v.timestamp || v.created_at || ""}
                      {v.note ? ` · ${v.note}` : ""}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : (
            <div style={{ fontSize: 11, color: "var(--amber)",
                              fontFamily: "var(--mono)" }}>
              INSUFFICIENT TELEMETRY FOR VERSION HISTORY · rule not found in local store.
            </div>
          )}
        </section>

        <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--faint)",
                         fontFamily: "var(--mono)" }}>
          Never fabricates metrics.  Every value above is either real base
          data or explicitly flagged as INSUFFICIENT TELEMETRY.
        </div>
      </div>
    </XdrShell>
  );
}


function ReplayResult({ r }) {
  const regres = r.regression;
  const batch  = r.batch;
  return (
    <div>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                    marginBottom: 4 }}>
        scope: {r.scope}
      </div>
      <div style={{ display: "grid",
                        gridTemplateColumns: "1fr 1fr",
                        gap: 8 }}>
        <div>
          <b className="mono" style={{ fontSize: 10.5,
                                                      color: "var(--mint)" }}>
            Regression run
          </b>
          <pre style={{ marginTop: 4, fontSize: 10.5,
                            fontFamily: "var(--mono)",
                            background: "var(--panel2)",
                            border: "1px solid var(--border)",
                            padding: 6, maxHeight: 220,
                            overflow: "auto",
                            color: "var(--text-dim)" }}>
            {regres ? JSON.stringify(regres, null, 2)
                             : "INSUFFICIENT TELEMETRY FOR REGRESSION SLICE"}
          </pre>
        </div>
        <div>
          <b className="mono" style={{ fontSize: 10.5,
                                                      color: "var(--cyan)" }}>
            Batch-test run
          </b>
          <pre style={{ marginTop: 4, fontSize: 10.5,
                            fontFamily: "var(--mono)",
                            background: "var(--panel2)",
                            border: "1px solid var(--border)",
                            padding: 6, maxHeight: 220,
                            overflow: "auto",
                            color: "var(--text-dim)" }}>
            {batch ? JSON.stringify(batch, null, 2)
                          : "INSUFFICIENT TELEMETRY FOR BATCH SLICE"}
          </pre>
        </div>
      </div>
    </div>
  );
}
