/**
 * XdrDetectionRuleEditorPage · `/xdr/detections/:id`
 *
 * Detection Engineering workstation.  Three-pane layout:
 *
 *   [ Rule editor · YAML ]  [ MITRE / metadata · Version history ]
 *   [ Test / replay input                                        ]
 *   [ Evaluation trace — evidence-backed                         ]
 *
 * Every "MATCH" is accompanied by the concrete field values that
 * fired.  A rule with unsupported Sigma modifiers is honestly
 * marked instead of silently pretending to match.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ChevronLeft, Play, Save, GitBranch, History,
  ShieldCheck, AlertTriangle, Layers, PenTool, Undo2 } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { useAuth } from "@/lib/auth";
import {
  getRule, saveRule, transitionLifecycle, rollbackRule,
  LIFECYCLE, LIFECYCLE_LABELS, LIFECYCLE_TRANSITIONS, RUNTIME_STATUS,
} from "@/xdr/detect/detectionRuleStore";
import { parseSigma, evaluateSigma } from "@/xdr/detect/sigmaEngine";

const SAMPLE_EVENT = `{
  "EventID": 1,
  "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
  "CommandLine": "powershell.exe -nop -w hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA==",
  "User": "alice@acme.com",
  "ParentImage": "C:\\\\Program Files\\\\Microsoft Office\\\\Root\\\\Office16\\\\WINWORD.EXE",
  "ProcessId": 4216
}`;


export default function XdrDetectionRuleEditorPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const [rule, setRule]     = useState(() => getRule(id));
  const [yaml, setYaml]     = useState(rule?.sigma_yaml || "");
  const [event, setEvent]   = useState(SAMPLE_EVENT);
  const [dirty, setDirty]   = useState(false);
  const [trace, setTrace]   = useState(null);
  const [error, setError]   = useState(null);

  // Live parse — surfaces schema errors + unsupported modifiers as
  // the analyst types.  Never silently drops issues.
  const parsed = useMemo(() => parseSigma(yaml), [yaml]);

  useEffect(() => {
    if (!rule && id) setRule(getRule(id));
  }, [id, rule]);

  if (!rule) {
    return (
      <XdrShell activeTop="detect">
        <div className="x-empty">Rule not found.  <Link to="/xdr/detections">Back to catalog</Link>.</div>
      </XdrShell>
    );
  }

  function doSave() {
    try {
      const next = saveRule({ ...rule, sigma_yaml: yaml },
                                    { by: user?.email || "NivXRay",
                                      note: "Manual save from editor." });
      setRule(next); setDirty(false); setError(null);
    } catch (e) { setError(e.message); }
  }
  function doLifecycle(target) {
    try {
      const next = transitionLifecycle(rule.id, target,
                                                   { by: user?.email || "NivXRay" });
      setRule(next);
    } catch (e) { setError(e.message); }
  }
  function doTest() {
    setError(null); setTrace(null);
    let parsedEvent;
    try { parsedEvent = JSON.parse(event); }
    catch (e) { setError("Invalid event JSON: " + e.message); return; }
    const t = evaluateSigma(parsed, parsedEvent);
    setTrace(t);
  }

  const allowedTransitions = LIFECYCLE_TRANSITIONS[rule.lifecycle] || [];
  return (
    <XdrShell activeTop="detect">
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <Link to="/xdr/detections" style={{
          display: "inline-flex", alignItems: "center", gap: 6,
          color: "var(--muted)", textDecoration: "none",
          fontSize: 10.5, letterSpacing: ".4px",
          textTransform: "uppercase", fontWeight: 700,
        }}>
          <ChevronLeft size={12} /> Back to catalog
        </Link>
        <span style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
          v{rule.version}
        </span>
        <button className="btn" onClick={doSave} disabled={!dirty}
                  data-testid="xdr-rule-save"
                  style={{ padding: "4px 12px" }}>
          <Save size={11} /> Save
        </button>
      </div>
      <h1 className="page-h1" data-testid="xdr-rule-heading">
        {rule.title}
      </h1>
      <div className="page-sub">
        {rule.description || "(no description)"}
      </div>

      {/* Runtime honesty */}
      <div data-testid="xdr-rule-runtime-banner"
              style={{ marginTop: 10, padding: 8,
                          border: "1px dashed var(--amber)", borderRadius: 4,
                          background: "rgba(245,166,35,.08)",
                          color: "var(--text-dim)", fontSize: 11 }}>
        <b style={{ color: "var(--amber)", fontFamily: "var(--mono)" }}>
          {RUNTIME_STATUS.status}
        </b> — test evaluations here run in-browser against the
        sample event.  Live-telemetry execution is not wired.
      </div>

      {/* Two-column: editor + sidebar */}
      <div style={{ display: "grid",
                        gridTemplateColumns: "minmax(320px, 1.4fr) 320px",
                        gap: 12, marginTop: 12 }}>
        <section className="panel" style={{ padding: 10 }}
                    data-testid="xdr-rule-editor-yaml">
          <div className="section-title" style={{ marginBottom: 6,
                                                                display: "flex", alignItems: "center", gap: 6 }}>
            <PenTool size={11} /> Sigma YAML
            {parsed.ok
              ? <span style={{ color: "var(--mint)", fontSize: 10 }}>· valid</span>
              : <span style={{ color: "#ff9494", fontSize: 10 }}>· invalid</span>}
            {parsed.unsupported?.length > 0 && (
              <span style={{ color: "var(--amber)", fontSize: 10 }}>
                · {parsed.unsupported.length} unsupported modifier(s)
              </span>
            )}
          </div>
          <textarea rows={18} value={yaml}
                       onChange={(e) => { setYaml(e.target.value); setDirty(true); }}
                       className="x-input"
                       style={{ fontFamily: "var(--mono)", fontSize: 11.5,
                                   width: "100%", resize: "vertical" }}
                       data-testid="xdr-rule-yaml" />
          {!parsed.ok && (
            <div style={{ marginTop: 6, color: "#ff9494", fontSize: 11 }}>
              <AlertTriangle size={11} /> {parsed.errors.join(" · ")}
            </div>
          )}
          {parsed.unsupported?.length > 0 && (
            <div style={{ marginTop: 6, color: "var(--amber)", fontSize: 11 }}>
              <AlertTriangle size={11} /> Unsupported Sigma modifiers:{" "}
              <span className="mono">{parsed.unsupported.join(", ")}</span>.
              The engine will refuse to fake a match on this rule.
            </div>
          )}
        </section>

        <aside style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div className="panel" style={{ padding: 10 }}
                  data-testid="xdr-rule-meta">
            <div className="section-title" style={{ marginBottom: 6 }}>
              Metadata
            </div>
            <Meta k="Rule ID"      v={rule.id} mono />
            <Meta k="Lifecycle"    v={LIFECYCLE_LABELS[rule.lifecycle]} />
            <Meta k="Severity"     v={rule.severity} />
            <Meta k="Techniques"   v={(rule.techniques || []).join(", ") || "—"} />
            <Meta k="Data source"  v={_dataSource(rule)} />
            <Meta k="Tags"         v={(rule.tags || []).join(", ") || "—"} />
            <Meta k="Author"       v={rule.author} />
            <Meta k="Updated"      v={rule.updated_at} />
          </div>

          <div className="panel" style={{ padding: 10 }}
                  data-testid="xdr-rule-lifecycle">
            <div className="section-title" style={{ marginBottom: 6 }}>
              Lifecycle
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {LIFECYCLE.map((l) => (
                <span key={l}
                         style={{ padding: "2px 6px", borderRadius: 3,
                                     fontSize: 10, fontFamily: "var(--mono)",
                                     border: `1px solid ${rule.lifecycle === l
                                                                   ? "var(--purple)"
                                                                   : "var(--border)"}`,
                                     background: rule.lifecycle === l
                                                       ? "rgba(155,123,240,.12)" : "transparent",
                                     color: rule.lifecycle === l
                                               ? "var(--text)" : "var(--faint)" }}>
                  {LIFECYCLE_LABELS[l]}
                </span>
              ))}
            </div>
            <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 4 }}>
              {allowedTransitions.map((t) => (
                <button key={t} className="btn"
                          onClick={() => doLifecycle(t)}
                          data-testid={`xdr-rule-transition-${t}`}
                          style={{ padding: "3px 10px", fontSize: 10.5 }}>
                  → {LIFECYCLE_LABELS[t]}
                </button>
              ))}
            </div>
          </div>

          <div className="panel" style={{ padding: 10 }}
                  data-testid="xdr-rule-versions">
            <div className="section-title" style={{ marginBottom: 6 }}>
              <History size={11} style={{ verticalAlign: "middle" }} /> Version history
            </div>
            {(rule.versions || []).slice().reverse().map((v) => (
              <div key={`${v.version}-${v.at}`}
                      style={{ fontSize: 11, color: "var(--text-dim)",
                                  padding: "4px 0",
                                  borderBottom: "1px solid var(--border)" }}>
                <div>
                  <span className="mono" style={{ color: "var(--cyan)" }}>v{v.version}</span>{" "}
                  <span style={{ color: "var(--faint)" }}>· {v.at}</span>
                </div>
                <div style={{ color: "var(--text-dim)" }}>{v.note}</div>
              </div>
            ))}
          </div>
        </aside>
      </div>

      {/* Test / replay */}
      <div style={{ marginTop: 14, display: "grid",
                        gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <section className="panel" style={{ padding: 10 }}
                    data-testid="xdr-rule-test-input">
          <div className="section-title" style={{ marginBottom: 6 }}>
            Test event (JSON)
          </div>
          <textarea rows={9} value={event}
                       onChange={(e) => setEvent(e.target.value)}
                       className="x-input"
                       style={{ fontFamily: "var(--mono)", fontSize: 11.5,
                                   width: "100%", resize: "vertical" }}
                       data-testid="xdr-rule-test-event" />
          <button className="btn primary" onClick={doTest}
                    data-testid="xdr-rule-test-run"
                    style={{ padding: "4px 12px", marginTop: 6 }}>
            <Play size={11} /> Evaluate
          </button>
          {error && (
            <div style={{ marginTop: 6, color: "#ff9494", fontSize: 11 }}>
              <AlertTriangle size={11} /> {error}
            </div>
          )}
        </section>

        <section className="panel" style={{ padding: 10 }}
                    data-testid="xdr-rule-test-trace">
          <div className="section-title" style={{ marginBottom: 6 }}>
            Evaluation trace
          </div>
          {!trace && (
            <div style={{ fontSize: 11, color: "var(--faint)" }}>
              Press <b>Evaluate</b> to run the parsed rule against the
              test event.  Every match is accompanied by the concrete
              fields and values that fired.
            </div>
          )}
          {trace && <EvalTrace trace={trace} />}
        </section>
      </div>
    </XdrShell>
  );
}


function EvalTrace({ trace }) {
  if (trace.errors) {
    return (
      <div style={{ color: "#ff9494", fontSize: 11.5 }}>
        <AlertTriangle size={11} /> Rule cannot be evaluated: {trace.errors.join(" · ")}.
      </div>
    );
  }
  if (trace.unsupported) {
    return (
      <div style={{ color: "var(--amber)", fontSize: 11.5 }}>
        <AlertTriangle size={11} /> {trace.note} · {trace.unsupported.join(", ")}
      </div>
    );
  }
  return (
    <div>
      <div style={{ fontSize: 12, marginBottom: 6 }}
              data-testid="xdr-rule-test-result">
        <b style={{ color: trace.matched ? "var(--mint)" : "var(--faint)",
                       fontFamily: "var(--mono)", letterSpacing: ".3px" }}>
          {trace.matched ? "MATCH" : "NO MATCH"}
        </b>
        <span className="mono" style={{ marginLeft: 6, color: "var(--faint)",
                                                    fontSize: 10.5 }}>
          {trace.condition_evaluation}
        </span>
      </div>
      {trace.matched_conditions.length > 0 && (
        <div>
          <div className="mono" style={{ fontSize: 10, color: "var(--mint)",
                                                    textTransform: "uppercase",
                                                    letterSpacing: ".3px",
                                                    marginBottom: 4 }}>
            Matched conditions
          </div>
          {trace.matched_conditions.map((c, i) => (
            <ConditionBlock key={i} c={c} color="var(--mint)" />
          ))}
        </div>
      )}
      {trace.failed_conditions.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                    textTransform: "uppercase",
                                                    letterSpacing: ".3px",
                                                    marginBottom: 4 }}>
            Not matched
          </div>
          {trace.failed_conditions.map((c, i) => (
            <ConditionBlock key={i} c={c} color="var(--faint)" />
          ))}
        </div>
      )}
    </div>
  );
}
function ConditionBlock({ c, color }) {
  return (
    <div style={{ marginBottom: 6, padding: 6, borderRadius: 3,
                    border: `1px solid ${color}`,
                    background: "var(--panel2)", fontSize: 11 }}>
      <div className="mono" style={{ color, fontSize: 10.5 }}>
        {c.selection}
      </div>
      {(c.fields || []).map((f, i) => (
        <div key={i} style={{ fontSize: 10.5, marginTop: 2,
                                    color: f.matched ? "var(--text)" : "var(--faint)" }}>
          <span className="mono">{f.field}</span>
          {f.mods?.length ? <span className="mono" style={{ color: "var(--cyan)" }}>|{f.mods.join("|")}</span> : ""}
          {" "}
          <span style={{ color: f.matched ? "var(--mint)" : "#ff9494" }}>
            {f.matched ? "✓" : "✗"}
          </span>
          <span className="mono" style={{ marginLeft: 6, color: "var(--faint)" }}>
            expected {JSON.stringify(f.expected)} · actual {JSON.stringify(f.actual)}
          </span>
        </div>
      ))}
    </div>
  );
}


function Meta({ k, v, mono, color }) {
  if (v == null || v === "") return null;
  return (
    <div style={{ display: "flex", justifyContent: "space-between",
                    gap: 6, padding: "3px 0",
                    borderBottom: "1px solid var(--border)", fontSize: 11 }}>
      <span style={{ color: "var(--faint)", fontSize: 10.5,
                        textTransform: "uppercase", letterSpacing: ".3px" }}>{k}</span>
      <span style={{ color: color || "var(--text-dim)",
                        fontFamily: mono ? "var(--mono)" : "inherit",
                        wordBreak: "break-all", maxWidth: "70%" }}>{v}</span>
    </div>
  );
}
function _dataSource(rule) {
  const ls = rule.logsource || {};
  return [ls.product, ls.category, ls.service].filter(Boolean).join(" · ") || "—";
}
