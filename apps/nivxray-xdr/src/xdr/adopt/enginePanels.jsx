/**
 * XDR consumer panels for the P1 engine adoption wave.
 *
 * Each panel is a THIN consumer of an authoritative NivXRay engine:
 *
 *   · DIE   — /api/die/ *          Deterministic Investigation Engine
 *   · IEDDE — /api/iedde/analyze  Iterative Evidence-Driven Decoding Engine
 *   · IUE   — /api/iue/lane-{a,b,c}/analyze + /api/iue/timeline/fuse
 *   · UAIE  — /api/uaie/catalog
 *
 * These panels NEVER re-implement engine logic and NEVER fabricate a
 * result when the base call fails.  On failure they surface the honest
 * capability-registry banner
 *
 *     AVAILABLE IN NIVXRAY — XDR ADAPTER NOT YET CONNECTED
 *
 * so analysts can trust the surface.
 *
 * The panels are intentionally analyst-triggered (button-driven) — they
 * do not fire on mount because DIE / IEDDE / IUE analysis takes a real
 * input payload (a command line, a script, a base64 blob).  The analyst
 * chooses what to analyse.
 */
import React, { useEffect, useState } from "react";
import { Cpu, ScanLine, GitBranch, Layers, RefreshCw, Play,
  BookOpen } from "lucide-react";

import { honestyBanner } from "@/xdr/capabilityRegistry";
import { DieConsumer, IeddeConsumer, IueConsumer,
  UaieConsumer } from "@/xdr/adopt/baseCapabilities";


/* ══════════════════════════════════════════════════════════════
   Shared honesty box (mirrors ../consumerPanels.jsx style)
   ══════════════════════════════════════════════════════════════ */
function _Honesty({ capId, extra }) {
  const b = honestyBanner(capId);
  if (!b) return null;
  const color =
    b.kind === "external"   ? "var(--cyan)"
  : b.kind === "not_present" ? "#f87171"
  : b.kind === "base_only"   ? "var(--faint)"
                             : "var(--amber)";
  return (
    <div data-testid={`xdr-honesty-${capId}`}
            style={{ padding: 8, marginBottom: 8, borderRadius: 4,
                        border: `1px dashed ${color}`,
                        background: "rgba(245,166,35,.06)",
                        color: "var(--text-dim)", fontSize: 11 }}>
      <b style={{ color, fontFamily: "var(--mono)" }}>
        {b.kind.toUpperCase().replace("_", " ")}
      </b> — {b.text}
      {extra && <div style={{ marginTop: 4, fontSize: 10.5 }}>{extra}</div>}
    </div>
  );
}


function _AnalystInputBox({ value, onChange, placeholder, "data-testid": tid }) {
  return (
    <textarea
      data-testid={tid}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      spellCheck={false}
      style={{ width: "100%", minHeight: 60, padding: 8,
                  borderRadius: 4, border: "1px solid var(--border)",
                  background: "var(--panel2)", color: "var(--text)",
                  fontFamily: "var(--mono)", fontSize: 11,
                  resize: "vertical" }} />
  );
}


function _RunButton({ onClick, disabled, label, testid }) {
  return (
    <button className="btn primary" onClick={onClick} disabled={disabled}
              data-testid={testid}
              style={{ padding: "4px 10px", fontSize: 11,
                          display: "inline-flex", alignItems: "center", gap: 6 }}>
      <Play size={11} /> {label || "Run"}
    </button>
  );
}


function _Provenance({ children }) {
  return (
    <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                  marginTop: 4 }}>
      {children}
    </div>
  );
}


/* ══════════════════════════════════════════════════════════════
   §1 · DIE Decoder Chain Panel
   ══════════════════════════════════════════════════════════════ */
export function XdrDieChainPanel({ incident, defaultInput }) {
  const [input, setInput] = useState(defaultInput
    || _pickCommandFromIncident(incident)
    || "");
  const [state, setState] = useState({ loading: false, data: null, err: null });

  const run = async () => {
    if (!input.trim()) return;
    setState({ loading: true, data: null, err: null });
    const r = await DieConsumer.analyze({ input });
    setState({ loading: false, data: r.ok ? r.data : null,
                    err: r.ok ? null : r });
  };

  const d = state.data;
  return (
    <div className="panel" data-testid="xdr-die-chain-panel"
            style={{ padding: 12, marginTop: 12 }}>
      <div className="section-title" style={{ marginBottom: 6,
                                                            display: "flex", alignItems: "center", gap: 6 }}>
        <ScanLine size={12} /> DIE · Deterministic Investigation Engine
        <span className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                        marginLeft: 4 }}>
          /api/die/analyze
        </span>
        <span style={{ flex: 1 }} />
        <_RunButton onClick={run} disabled={state.loading}
                          testid="xdr-die-run" label="Analyze" />
      </div>
      <_Honesty capId="engine.die"
                    extra="Enter a command line / script / payload; DIE returns the deterministic decode chain." />
      {state.err && (
        <_Honesty capId="engine.die.analyze"
                        extra={`Base call failed · ${state.err.error || state.err.status}`} />
      )}
      <_AnalystInputBox value={input} onChange={setInput}
                                  placeholder='e.g.  powershell -enc <base64>'
                                  data-testid="xdr-die-input" />
      {state.loading && (
        <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 6 }}>
          Analyzing via DIE…
        </div>
      )}
      {d && (
        <div style={{ marginTop: 8 }}
                data-testid="xdr-die-result">
          <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                        textTransform: "uppercase",
                                                        marginBottom: 4 }}>
            Decode chain · {(d.stages || d.chain || []).length} stage(s)
          </div>
          {(d.stages || d.chain || []).slice(0, 12).map((s, i) => (
            <div key={i} style={{ padding: "2px 0", fontSize: 11,
                                        color: "var(--text-dim)",
                                        borderBottom: "1px solid var(--border)" }}>
              <span className="mono" style={{ color: "var(--cyan)" }}>
                step {i + 1}
              </span>
              {s.interpreter && (
                <span className="mono" style={{ marginLeft: 6,
                                                              color: "#c084fc", fontSize: 10 }}>
                  · {s.interpreter}
                </span>
              )}
              {s.transformation && (
                <span className="mono" style={{ marginLeft: 6,
                                                              color: "var(--amber)", fontSize: 10 }}>
                  · {s.transformation}
                </span>
              )}
              {s.output && (
                <div style={{ marginLeft: 12, fontFamily: "var(--mono)",
                                  fontSize: 10.5, whiteSpace: "pre-wrap",
                                  color: "var(--text)" }}>
                  {String(s.output).slice(0, 240)}
                  {String(s.output).length > 240 ? "…" : ""}
                </div>
              )}
            </div>
          ))}
          {(d.canonical_output || d.result) && (
            <div style={{ marginTop: 6, padding: 6, borderRadius: 3,
                              background: "var(--panel2)",
                              border: "1px solid var(--border)" }}>
              <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                            textTransform: "uppercase",
                                                            marginBottom: 2 }}>
                Canonical output
              </div>
              <div style={{ fontFamily: "var(--mono)", fontSize: 11,
                                whiteSpace: "pre-wrap", color: "var(--text)" }}>
                {String(d.canonical_output || d.result).slice(0, 600)}
              </div>
            </div>
          )}
          {(d.iocs || []).length > 0 && (
            <div style={{ marginTop: 6 }}>
              <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                            textTransform: "uppercase",
                                                            marginBottom: 2 }}>
                Extracted IOCs
              </div>
              {(d.iocs || []).slice(0, 10).map((ioc, i) => (
                <div key={i} className="mono" style={{ fontSize: 10.5,
                                                                              color: "var(--cyan)" }}>
                  · {ioc.value || ioc.indicator || JSON.stringify(ioc)}
                  {ioc.kind && (
                    <span style={{ color: "var(--faint)", marginLeft: 4 }}>
                      ({ioc.kind})
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
          <_Provenance>
            provenance: {d.provenance?.source || "die/analyze"}
            {d.iterations_executed != null && (
              <> · iterations: {d.iterations_executed}</>
            )}
          </_Provenance>
        </div>
      )}
    </div>
  );
}


/* ══════════════════════════════════════════════════════════════
   §2 · IEDDE Stage Inspector
   ══════════════════════════════════════════════════════════════ */
export function XdrIeddeStagePanel({ incident, defaultInput }) {
  const [input, setInput] = useState(defaultInput
    || _pickCommandFromIncident(incident)
    || "");
  const [state, setState] = useState({ loading: false, data: null, err: null });

  const run = async () => {
    if (!input.trim()) return;
    setState({ loading: true, data: null, err: null });
    const r = await IeddeConsumer.analyze(input);
    setState({ loading: false, data: r.ok ? r.data : null,
                    err: r.ok ? null : r });
  };

  const d = state.data;
  return (
    <div className="panel" data-testid="xdr-iedde-stage-panel"
            style={{ padding: 12, marginTop: 12 }}>
      <div className="section-title" style={{ marginBottom: 6,
                                                            display: "flex", alignItems: "center", gap: 6 }}>
        <GitBranch size={12} /> IEDDE · Iterative Evidence-Driven Decoding
        <span className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                        marginLeft: 4 }}>
          /api/iedde/analyze
        </span>
        <span style={{ flex: 1 }} />
        <_RunButton onClick={run} disabled={state.loading}
                          testid="xdr-iedde-run" label="Analyze" />
      </div>
      <_Honesty capId="engine.iedde"
                    extra="Stage 1 → 2 → 3 deterministic decoding.  Byte-identical output for identical input." />
      {state.err && (
        <_Honesty capId="engine.iedde"
                        extra={`Base call failed · ${state.err.error || state.err.status}`} />
      )}
      <_AnalystInputBox value={input} onChange={setInput}
                                  placeholder="Paste the payload IEDDE should decode…"
                                  data-testid="xdr-iedde-input" />
      {state.loading && (
        <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 6 }}>
          Running IEDDE loop…
        </div>
      )}
      {d && (
        <div style={{ marginTop: 8 }}
                data-testid="xdr-iedde-result">
          <div style={{ display: "flex", gap: 8, marginBottom: 6 }}>
            <span className="mono" style={{ fontSize: 10.5,
                                                            color: "var(--cyan)" }}>
              interpreter: {d.interpreter_identification?.primary_interpreter || "?"}
            </span>
            <span className="mono" style={{ fontSize: 10.5,
                                                            color: "var(--mint)" }}>
              iterations: {d.iterations_executed ?? "—"}
            </span>
            <span className="mono" style={{ fontSize: 10.5,
                                                            color: "var(--amber)" }}>
              terminal: {d.terminal_state || "—"}
            </span>
          </div>
          {d.stop_reason && (
            <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                          marginBottom: 6 }}>
              stop reason · {d.stop_reason}
            </div>
          )}
          <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                        textTransform: "uppercase",
                                                        marginBottom: 4 }}>
            Stage trace
          </div>
          {(d.stages || []).map((s, i) => (
            <div key={i} style={{ padding: "3px 0", fontSize: 11,
                                        color: "var(--text-dim)",
                                        borderBottom: "1px solid var(--border)" }}>
              <span className="mono" style={{ color: "var(--cyan)" }}>
                iter {s.iteration ?? i + 1}
              </span>
              <span className="mono" style={{ marginLeft: 6,
                                                            color: "#c084fc", fontSize: 10 }}>
                · {s.interpreter || "?"} (c{s.interpreter_confidence ?? "—"})
              </span>
              {s.decision && (
                <span className="mono" style={{ marginLeft: 6,
                                                              color: "var(--amber)", fontSize: 10 }}>
                  · {s.decision.selected || "no-op"}
                </span>
              )}
              {(s.fired_transformations || []).length > 0 && (
                <div style={{ marginLeft: 12, fontSize: 10.5,
                                  color: "var(--text)" }}>
                  fired: {(s.fired_transformations || []).join(", ")}
                </div>
              )}
              {s.canonicality_delta != null && (
                <div style={{ marginLeft: 12, fontSize: 10,
                                  color: "var(--faint)" }}>
                  Δcanonicality: {s.canonicality_delta}
                </div>
              )}
            </div>
          ))}
          {d.canonical_output && (
            <div style={{ marginTop: 6, padding: 6, borderRadius: 3,
                              background: "var(--panel2)",
                              border: "1px solid var(--border)" }}>
              <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                            textTransform: "uppercase",
                                                            marginBottom: 2 }}>
                Canonical output
              </div>
              <div style={{ fontFamily: "var(--mono)", fontSize: 11,
                                whiteSpace: "pre-wrap", color: "var(--text)" }}>
                {String(d.canonical_output).slice(0, 600)}
              </div>
            </div>
          )}
          {(d.final_technique_inventory?.techniques || []).length > 0 && (
            <div style={{ marginTop: 6, display: "flex",
                              flexWrap: "wrap", gap: 4 }}>
              {d.final_technique_inventory.techniques.slice(0, 12)
                .map((t, i) => (
                <span key={i} className="mono"
                          style={{ padding: "1px 5px", borderRadius: 3,
                                      border: "1px solid #f472b6",
                                      background: "rgba(244,114,182,.08)",
                                      color: "#f472b6", fontSize: 9.5 }}>
                  {t.technique_id || t.id || t}
                </span>
              ))}
            </div>
          )}
          <_Provenance>provenance: iedde/analyze · deterministic</_Provenance>
        </div>
      )}
    </div>
  );
}


/* ══════════════════════════════════════════════════════════════
   §3 · IUE Timeline / Lane overlay
   ══════════════════════════════════════════════════════════════ */
export function XdrIueTimelinePanel({ incident }) {
  const [state, setState] = useState({ loading: false, data: null,
                                                    err: null, laneStatus: {} });

  useEffect(() => {
    if (!incident?.id) return;
    (async () => {
      const [a, c] = await Promise.all([
        IueConsumer.laneAStatus(), IueConsumer.laneCStatus(),
      ]);
      setState((s) => ({ ...s, laneStatus: { a: a.ok ? a.data : null,
                                                             c: c.ok ? c.data : null } }));
    })();
  }, [incident?.id]);

  const run = async () => {
    setState({ loading: true, data: null, err: null,
                    laneStatus: state.laneStatus });
    // Fuse the timeline from the incident scope.  The base fuse
    // endpoint accepts either an incident_id or an evidence bundle;
    // we pass the incident id and let the base decide what to fuse.
    const r = await IueConsumer.timelineFuse({ incident_id: incident?.id });
    setState({ loading: false, data: r.ok ? r.data : null,
                    err: r.ok ? null : r, laneStatus: state.laneStatus });
  };

  const d = state.data;
  return (
    <div className="panel" data-testid="xdr-iue-timeline-panel"
            style={{ padding: 12, marginTop: 12 }}>
      <div className="section-title" style={{ marginBottom: 6,
                                                            display: "flex", alignItems: "center", gap: 6 }}>
        <Layers size={12} /> IUE · Investigation Understanding
        <span className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                        marginLeft: 4 }}>
          /api/iue/timeline/fuse
        </span>
        <span style={{ flex: 1 }} />
        <_RunButton onClick={run} disabled={state.loading}
                          testid="xdr-iue-run" label="Fuse Timeline" />
      </div>
      <_Honesty capId="engine.iue.timeline_fuse"
                    extra="Fuses evidence + understanding from Lane A / B / C into a unified authoritative timeline." />
      <div style={{ display: "flex", gap: 12, marginBottom: 8, fontSize: 10.5 }}>
        <span data-testid="xdr-iue-lane-a-status">
          <b className="mono" style={{ color: "var(--cyan)" }}>Lane A</b>
          <span style={{ marginLeft: 4, color: "var(--faint)" }}>
            {state.laneStatus.a?.status || state.laneStatus.a?.ok || "unknown"}
          </span>
        </span>
        <span data-testid="xdr-iue-lane-b-status">
          <b className="mono" style={{ color: "var(--cyan)" }}>Lane B</b>
          <span style={{ marginLeft: 4, color: "var(--faint)" }}>
            (POST-only — analyze on demand)
          </span>
        </span>
        <span data-testid="xdr-iue-lane-c-status">
          <b className="mono" style={{ color: "var(--cyan)" }}>Lane C</b>
          <span style={{ marginLeft: 4, color: "var(--faint)" }}>
            {state.laneStatus.c?.status || state.laneStatus.c?.ok || "unknown"}
          </span>
        </span>
      </div>
      {state.err && (
        <_Honesty capId="engine.iue.timeline_fuse"
                        extra={`Base fuse call failed · ${state.err.error || state.err.status}`} />
      )}
      {state.loading && (
        <div style={{ fontSize: 11, color: "var(--faint)" }}>
          Fusing timeline via IUE…
        </div>
      )}
      {d && (
        <div data-testid="xdr-iue-result">
          <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                        textTransform: "uppercase",
                                                        marginBottom: 4 }}>
            Unified timeline · {(d.events || d.timeline || []).length} event(s)
          </div>
          {(d.events || d.timeline || []).slice(0, 12).map((ev, i) => (
            <div key={i} style={{ padding: "2px 0", fontSize: 11,
                                        color: "var(--text-dim)",
                                        borderBottom: "1px solid var(--border)" }}>
              <span className="mono" style={{ color: "var(--cyan)" }}>
                {ev.timestamp || ev.ts || `#${i + 1}`}
              </span>
              <span style={{ marginLeft: 6 }}>
                {ev.summary || ev.description || ev.kind || "event"}
              </span>
              {ev.lane && (
                <span className="mono" style={{ marginLeft: 4,
                                                              color: "#c084fc", fontSize: 10 }}>
                  · lane {ev.lane}
                </span>
              )}
              {ev.technique_id && (
                <span className="mono" style={{ marginLeft: 4,
                                                              color: "#f472b6", fontSize: 10 }}>
                  · {ev.technique_id}
                </span>
              )}
            </div>
          ))}
          <_Provenance>
            provenance: iue/timeline/fuse ·
            fused {(d.events || d.timeline || []).length} events
          </_Provenance>
        </div>
      )}
    </div>
  );
}


/* ══════════════════════════════════════════════════════════════
   §4 · UAIE Catalog Pivot
   ══════════════════════════════════════════════════════════════ */
export function XdrUaieCatalogPanel() {
  const [state, setState] = useState({ loading: true, data: null, err: null });
  const [refresh, setR] = useState(0);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setState({ loading: true, data: null, err: null });
      const r = await UaieConsumer.catalog();
      if (!cancelled) setState({ loading: false,
                                       data: r.ok ? r.data : null,
                                       err: r.ok ? null : r });
    })();
    return () => { cancelled = true; };
  }, [refresh]);

  const d = state.data;
  const catalog = d?.catalog || d?.capabilities || {};
  const capabilityEntries = Array.isArray(catalog)
    ? catalog
    : Object.entries(catalog).map(([id, v]) => ({ id, ...v }));
  const edges = d?.dependency_graph?.edges || d?.edges || [];

  return (
    <div className="panel" data-testid="xdr-uaie-catalog-panel"
            style={{ padding: 12, marginTop: 12 }}>
      <div className="section-title" style={{ marginBottom: 6,
                                                            display: "flex", alignItems: "center", gap: 6 }}>
        <BookOpen size={12} /> UAIE · Capability Catalog
        <span className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                        marginLeft: 4 }}>
          /api/uaie/catalog
        </span>
        <span style={{ flex: 1 }} />
        <button className="btn ghost" onClick={() => setR((n) => n + 1)}
                  data-testid="xdr-uaie-refresh"
                  style={{ padding: "2px 8px", fontSize: 10 }}>
          <RefreshCw size={10} /> Refresh
        </button>
      </div>
      <_Honesty capId="engine.uaie.catalog"
                    extra="Relationship-rich UAIE capability catalog with produces→requires graph." />
      {state.err && (
        <_Honesty capId="engine.uaie.catalog"
                        extra={`Base call failed · ${state.err.error || state.err.status}`} />
      )}
      {state.loading && (
        <div style={{ fontSize: 11, color: "var(--faint)" }}>
          Loading UAIE catalog…
        </div>
      )}
      {d && (
        <div data-testid="xdr-uaie-result">
          <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                        marginBottom: 4 }}>
            {capabilityEntries.length} capabilit{capabilityEntries.length === 1 ? "y" : "ies"}
            {" · "}{edges.length} dependency edge(s)
            {d?.schema_version != null && (
              <> · schema v{d.schema_version}</>
            )}
          </div>
          <div style={{ maxHeight: 260, overflowY: "auto",
                            border: "1px solid var(--border)",
                            borderRadius: 3, padding: 6,
                            background: "var(--panel2)" }}>
            {capabilityEntries.slice(0, 40).map((c, i) => (
              <div key={c.id || i} style={{ padding: "3px 0",
                                                              fontSize: 11,
                                                              color: "var(--text-dim)",
                                                              borderBottom: "1px solid var(--border)" }}>
                <span className="mono" style={{ color: "var(--cyan)" }}>
                  {c.id || c.capability_id || `cap_${i}`}
                </span>
                {c.name && (
                  <span style={{ marginLeft: 6 }}>{c.name}</span>
                )}
                {(c.produces || []).length > 0 && (
                  <span className="mono" style={{ marginLeft: 6,
                                                                color: "var(--mint)", fontSize: 10 }}>
                    produces: {(c.produces || []).slice(0, 3).join(", ")}
                  </span>
                )}
                {(c.requires || []).length > 0 && (
                  <span className="mono" style={{ marginLeft: 6,
                                                                color: "var(--amber)", fontSize: 10 }}>
                    requires: {(c.requires || []).slice(0, 3).join(", ")}
                  </span>
                )}
              </div>
            ))}
            {capabilityEntries.length > 40 && (
              <div style={{ fontSize: 10, color: "var(--faint)",
                                paddingTop: 4 }}>
                … showing 40 of {capabilityEntries.length}
              </div>
            )}
          </div>
          <_Provenance>
            provenance: uaie/catalog (schema-versioned)
          </_Provenance>
        </div>
      )}
    </div>
  );
}


/* ══════════════════════════════════════════════════════════════
   Helpers
   ══════════════════════════════════════════════════════════════ */

// Pick a candidate command line from an incident payload so the
// analyst has something to run without pasting.  Never fabricates —
// if the incident has no command, the input stays empty and the
// analyst must paste one.
function _pickCommandFromIncident(incident) {
  if (!incident) return "";
  const candidates = [
    incident.command_line,
    incident.commandline,
    incident.command,
    incident.evidence?.[0]?.command_line,
    incident.evidence?.[0]?.commandline,
    incident.evidence?.[0]?.command,
    incident.processes?.[0]?.command,
    incident.processes?.[0]?.command_line,
  ];
  const found = candidates.find((c) => typeof c === "string" && c.trim().length);
  return found || "";
}
