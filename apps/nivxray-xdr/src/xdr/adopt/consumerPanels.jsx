/**
 * XDR consumer panels that adopt existing NivXRay engines.
 *
 * Each panel is a THIN consumer:
 *   fetch → render authoritative fields → cross-link back to base
 *
 * If the base call fails we surface the honest capability-registry
 * banner (``AVAILABLE IN NIVXRAY — XDR ADAPTER NOT YET CONNECTED``)
 * — never fabricate the missing data.
 */
import React, { useEffect, useState } from "react";
import { ShieldCheck, AlertTriangle, ExternalLink, RefreshCw,
  FileCheck2, Bug } from "lucide-react";

import { honestyBanner } from "@/xdr/capabilityRegistry";
import { VerdictConsumer, IocConsumer, ReportConsumer,
  AnalyzeConsumer } from "@/xdr/adopt/baseCapabilities";


function _HonestyBox({ capId, extra }) {
  const b = honestyBanner(capId);
  if (!b) return null;
  const color = b.kind === "external" ? "var(--cyan)" : "var(--amber)";
  return (
    <div data-testid={`xdr-honesty-${capId}`}
            style={{ padding: 8, marginBottom: 8, borderRadius: 4,
                        border: `1px dashed ${color}`,
                        background: `${color === "var(--cyan)"
                                          ? "rgba(34,211,238,.08)"
                                          : "rgba(245,166,35,.08)"}`,
                        color: "var(--text-dim)", fontSize: 11 }}>
      <b style={{ color, fontFamily: "var(--mono)" }}>
        {b.kind.toUpperCase().replace("_", " ")}
      </b> — {b.text}
      {extra && <div style={{ marginTop: 4, fontSize: 10.5 }}>{extra}</div>}
    </div>
  );
}


// ── Verdict Stage-2 consumer panel ────────────────────────────────
export function XdrVerdictPanel({ incident }) {
  const [state, setState] = useState({ loading: true, data: null, err: null });
  const [refresh, setR]   = useState(0);
  useEffect(() => {
    if (!incident?.id) return;
    let cancelled = false;
    (async () => {
      setState((s) => ({ ...s, loading: true }));
      const r = await VerdictConsumer.fetch({ incident_id: incident.id });
      if (!cancelled) setState({ loading: false,
                                       data: r.ok ? r.data : null,
                                       err: r.ok ? null : r });
    })();
    return () => { cancelled = true; };
  }, [incident?.id, refresh]);
  const d = state.data;
  return (
    <div className="panel" data-testid="xdr-verdict-panel"
            style={{ padding: 12, marginTop: 12 }}>
      <div className="section-title" style={{ marginBottom: 6,
                                                            display: "flex", alignItems: "center", gap: 6 }}>
        <ShieldCheck size={12} /> Verdict · Stage-2 (authoritative)
        <span style={{ flex: 1 }} />
        <button className="btn ghost" onClick={() => setR((n) => n + 1)}
                  data-testid="xdr-verdict-refresh"
                  style={{ padding: "2px 8px", fontSize: 10 }}>
          <RefreshCw size={10} /> Refresh
        </button>
      </div>
      {state.err && (
        <_HonestyBox capId="verdict.stage2"
                          extra={`Base call failed · ${state.err.error || state.err.status}`} />
      )}
      {state.loading && <div style={{ fontSize: 11, color: "var(--faint)" }}>Loading…</div>}
      {d && (
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <b className="mono" style={{ fontSize: 11,
                                                        color: _sev(d.severity || d.verdict) }}>
              {(d.verdict || d.severity || "unknown").toString().toUpperCase()}
            </b>
            <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
              confidence {d.confidence ?? "—"}
            </span>
            <span style={{ flex: 1 }} />
            <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
              provenance: {d.provenance?.source || d.source || "verdict/stage2"}
            </span>
          </div>
          {d.summary && (
            <div style={{ fontSize: 12, color: "var(--text-dim)",
                              marginBottom: 8 }}>{d.summary}</div>
          )}
          {(d.techniques || []).length > 0 && (
            <div style={{ marginBottom: 8, display: "flex",
                              flexWrap: "wrap", gap: 4 }}>
              {(d.techniques || []).map((t) => (
                <a key={t} className="mono"
                     href={`/xdr/intelligence/mitre?technique=${encodeURIComponent(t)}`}
                     style={{ padding: "1px 5px", borderRadius: 3,
                                 border: "1px solid #f472b6",
                                 background: "rgba(244,114,182,.08)",
                                 color: "#f472b6", fontSize: 9.5,
                                 textDecoration: "none" }}>
                  {t}
                </a>
              ))}
            </div>
          )}
          {(d.evidence || d.contributing_factors || []).length > 0 && (
            <div>
              <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                            textTransform: "uppercase",
                                                            marginBottom: 4 }}>
                Contributing evidence
              </div>
              {(d.evidence || d.contributing_factors).slice(0, 8).map((e, i) => (
                <div key={i} style={{ fontSize: 11, color: "var(--text-dim)",
                                            padding: "2px 0",
                                            borderBottom: "1px solid var(--border)" }}>
                  <span className="mono" style={{ color: "var(--cyan)" }}>
                    {e.rule_id || e.factor || e.name || `evidence #${i + 1}`}
                  </span>
                  {e.weight != null && (
                    <span className="mono" style={{ color: "var(--mint)",
                                                                  marginLeft: 6, fontSize: 10 }}>
                      +{e.weight}
                    </span>
                  )}
                  {e.reason && (
                    <span style={{ marginLeft: 6, color: "var(--faint)" }}>
                      · {e.reason}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
          {(d.negative_explanations || d.negative || []).length > 0 && (
            <div style={{ marginTop: 8 }}>
              <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                            textTransform: "uppercase",
                                                            marginBottom: 4 }}>
                Why NOT worse (negative explainability)
              </div>
              {(d.negative_explanations || d.negative).slice(0, 6).map((n, i) => (
                <div key={i} style={{ fontSize: 11, color: "var(--text-dim)",
                                            padding: "2px 0" }}>
                  · {typeof n === "string" ? n : n.reason || JSON.stringify(n)}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      {!state.loading && !d && !state.err && (
        <div style={{ fontSize: 11, color: "var(--faint)" }}>No verdict available.</div>
      )}
    </div>
  );
}


// ── IOC Intelligence consumer panel ──────────────────────────────
export function XdrIocEnrichmentPanel({ value, kind }) {
  const [state, setState] = useState({ loading: true, data: null, err: null });
  useEffect(() => {
    if (!value) return;
    let cancelled = false;
    (async () => {
      setState({ loading: true, data: null, err: null });
      const r = await IocConsumer.lookup({ value, kind });
      if (!cancelled) setState({ loading: false,
                                       data: r.ok ? r.data : null,
                                       err: r.ok ? null : r });
    })();
    return () => { cancelled = true; };
  }, [value, kind]);
  const d = state.data;
  return (
    <div data-testid="xdr-ioc-enrichment"
            style={{ padding: 10, marginTop: 8, borderRadius: 4,
                        border: "1px solid var(--border)",
                        background: "var(--panel2)", fontSize: 11 }}>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                    textTransform: "uppercase",
                                                    marginBottom: 4 }}>
        NivXRay IOC Intelligence · {kind}
      </div>
      {state.err && (
        <_HonestyBox capId="ioc.intel"
                          extra={`Base /api/ioc/lookup unavailable · ${state.err.error || state.err.status || "no route"}`} />
      )}
      {state.loading && <div style={{ color: "var(--faint)" }}>Looking up…</div>}
      {d && (
        <div>
          <div style={{ marginBottom: 4 }}>
            <b className="mono" style={{ color: _sev(d.reputation || d.verdict) }}>
              {(d.reputation || d.verdict || "unknown").toString().toUpperCase()}
            </b>
            {d.malware_family && (
              <span className="mono" style={{ marginLeft: 6,
                                                            color: "var(--amber)" }}>
                family: {d.malware_family}
              </span>
            )}
          </div>
          {(d.sources || d.providers || []).length > 0 && (
            <div style={{ fontSize: 10.5, color: "var(--faint)" }}>
              sources: {(d.sources || d.providers).join(", ")}
            </div>
          )}
          {d.first_seen && (
            <div className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
              first seen · {d.first_seen}
            </div>
          )}
          {(d.related_incidents || []).length > 0 && (
            <div style={{ marginTop: 4 }}>
              {(d.related_incidents || []).slice(0, 5).map((r) => (
                <a key={r.id} href={`/xdr/incidents/${encodeURIComponent(r.id)}`}
                     className="mono"
                     style={{ display: "block", color: "var(--cyan)",
                                 fontSize: 10.5, textDecoration: "none" }}>
                  → {r.id} · {r.title || ""}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}


// ── Decode chain consumer (used from Sigma test/replay) ──────────
export async function decodeCommandLineViaBase(command_line) {
  const r = await AnalyzeConsumer.analyzeCommand(command_line);
  if (!r.ok) return r;
  return { ok: true, data: r.data };
}


// ── Investigation report consumer ─────────────────────────────────
export function XdrInvestigationReportPanel({ incident }) {
  const [state, setState] = useState({ loading: true, data: null, err: null });
  useEffect(() => {
    if (!incident?.id) return;
    let cancelled = false;
    (async () => {
      setState({ loading: true, data: null, err: null });
      const r = await ReportConsumer.summary(incident.id);
      if (!cancelled) setState({ loading: false,
                                       data: r.ok ? r.data : null,
                                       err: r.ok ? null : r });
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);
  const d = state.data;
  return (
    <div className="panel" data-testid="xdr-investigation-report"
            style={{ padding: 12, marginTop: 12 }}>
      <div className="section-title" style={{ marginBottom: 6 }}>
        <FileCheck2 size={12} style={{ verticalAlign: "middle" }} />{" "}
        Investigation Report (authoritative)
      </div>
      {state.err && (
        <_HonestyBox capId="report.investigation"
                          extra={`Base /api/incidents/:id/summary unavailable · ${state.err.error || state.err.status || "no route"}`} />
      )}
      {state.loading && <div style={{ fontSize: 11, color: "var(--faint)" }}>Loading…</div>}
      {d && (
        <div style={{ fontSize: 12, color: "var(--text-dim)",
                          whiteSpace: "pre-wrap" }}>
          {typeof d === "string" ? d
             : d.summary || d.narrative || d.report || d.text
                 || JSON.stringify(d, null, 2)}
        </div>
      )}
    </div>
  );
}


// ── helpers ──────────────────────────────────────────────────────
function _sev(v) {
  const s = String(v || "").toLowerCase();
  if (s.startsWith("mal") || s.startsWith("crit")) return "#f87171";
  if (s.startsWith("high") || s.startsWith("susp")) return "#fb923c";
  if (s.startsWith("med"))   return "#facc15";
  if (s.startsWith("clean") || s.startsWith("bng")) return "var(--mint)";
  return "var(--faint)";
}
