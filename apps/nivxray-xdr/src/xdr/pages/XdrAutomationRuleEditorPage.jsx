/**
 * XdrAutomationRuleEditorPage · `/xdr/respond/automation-rules/:id`
 *
 * WHEN / IF / THEN editor.  Simulation runs client-side only; nothing
 * is executed until the Response Engine is wired.
 */
import React, { useEffect, useMemo, useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import {
  Save, Plus, Trash2, Play, Pause, FlaskConical, Archive, X,
  ShieldAlert, ArrowRight,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import {
  getRule, saveRule, transitionLifecycle, simulate,
  TRIGGERS, getTrigger, OPS, ACTION_KINDS, getActionKind,
  LIFECYCLE, canTransition,
} from "@/xdr/respond/automationRuleStore";
import { listPlaybooks } from "@/xdr/respond/playbookStore";
import { RESPONSE_ENGINE_WIRED } from "@/xdr/respond/actionRegistry";


const LC_BUTTONS = [
  { to: LIFECYCLE.TESTING,    label: "Move to Testing",    Icon: FlaskConical },
  { to: LIFECYCLE.ENABLED,    label: "Enable",             Icon: Play },
  { to: LIFECYCLE.DISABLED,   label: "Disable",            Icon: Pause },
  { to: LIFECYCLE.DRAFT,      label: "Back to Draft",      Icon: X },
  { to: LIFECYCLE.DEPRECATED, label: "Deprecate",          Icon: Archive },
];


export default function XdrAutomationRuleEditorPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [rule, setRule]  = useState(null);
  const [dirty, setDirty] = useState(false);
  const [saveState, setSs] = useState("clean");
  const [sim, setSim] = useState(null);
  const [simEvent, setSimEvent] = useState('{"severity":"critical","verdict":"malicious"}');

  useEffect(() => {
    const r = getRule(id);
    if (!r) { navigate("/xdr/respond/automation-rules"); return; }
    setRule(r);
  }, [id, navigate]);

  const playbooks = useMemo(() => listPlaybooks(), [rule?.updated_at]);
  const trigger = useMemo(() => getTrigger(rule?.trigger?.type), [rule?.trigger?.type]);

  if (!rule) return null;

  const mutate = (patch) => { setRule({ ...rule, ...patch }); setDirty(true); };
  const doSave = () => {
    setSs("saving");
    try {
      const saved = saveRule(rule, { note: "editor save" });
      setRule(saved); setDirty(false); setSs("saved");
      setTimeout(() => setSs("clean"), 1200);
    } catch (e) { setSs("error"); window.alert(String(e)); }
  };
  const doLc = (to) => {
    try { setRule(transitionLifecycle(rule.id, to)); }
    catch (e) { window.alert(String(e)); }
  };
  const doSim = () => {
    try {
      const evt = JSON.parse(simEvent);
      setSim(simulate(rule, evt));
    } catch (e) { setSim({ error: "Invalid JSON: " + e.message }); }
  };

  // ── Condition helpers ─────────────────────────────────────
  const addCondition = () => mutate({
    conditions: [ ...(rule.conditions || []),
                    { field: trigger?.fields?.[0] || "severity", op: "eq", value: "critical" } ],
  });
  const setCondition = (i, patch) => {
    const cs = [...(rule.conditions || [])];
    cs[i] = { ...cs[i], ...patch };
    mutate({ conditions: cs });
  };
  const rmCondition = (i) => {
    const cs = [...(rule.conditions || [])]; cs.splice(i, 1);
    mutate({ conditions: cs });
  };

  // ── Action helpers ────────────────────────────────────────
  const addAction = () => mutate({
    actions: [ ...(rule.actions || []),
                  { kind: "invoke_playbook",
                     params: { playbook_id: playbooks[0]?.id || "" } } ],
  });
  const setAction = (i, patch) => {
    const as = [...(rule.actions || [])];
    as[i] = { ...as[i], ...patch };
    mutate({ actions: as });
  };
  const rmAction = (i) => {
    const as = [...(rule.actions || [])]; as.splice(i, 1);
    mutate({ actions: as });
  };

  return (
    <XdrShell>
      {!RESPONSE_ENGINE_WIRED && (
        <div data-testid="xdr-rule-editor-not-wired"
                style={{
                  padding: "8px 12px", marginBottom: 12,
                  borderRadius: 4, border: "1px dashed var(--amber)",
                  background: "rgba(245, 166, 35, .08)",
                  color: "var(--text-dim)", fontSize: 11.5,
                }}>
          <b style={{ color: "var(--amber)", fontFamily: "var(--mono)" }}>NOT WIRED</b>
          {" "}— Save / Version / Simulate work; the rule will not fire real
          executions until the Response Engine is deployed.
        </div>
      )}

      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <input value={rule.name}
                  onChange={(e) => mutate({ name: e.target.value })}
                  className="x-input"
                  style={{ maxWidth: 380, fontWeight: 700, fontSize: 15 }}
                  data-testid="xdr-rule-name" />
        <span className="mono" style={{ color: "var(--faint)", fontSize: 11 }}>
          v{rule.version} · {rule.lifecycle.toUpperCase()}
        </span>
        <div style={{ flex: 1 }} />
        <button className="btn primary" onClick={doSave} disabled={!dirty || saveState === "saving"}
                  style={{ padding: "4px 10px" }}
                  data-testid="xdr-rule-save">
          <Save size={11} /> {saveState === "saving" ? "Saving…"
                                : saveState === "saved" ? "Saved" : "Save"}
        </button>
      </div>
      <div className="page-sub" style={{ marginBottom: 12 }}>
        Trigger · <span className="mono">{rule.trigger?.type}</span> ·
        Conditions · <b>{(rule.conditions || []).length}</b> ·
        Actions · <b>{(rule.actions || []).length}</b> ·
        Versions · <b>{rule.versions?.length ?? 0}</b>
      </div>

      {/* Lifecycle bar */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 12 }}
             data-testid="xdr-rule-lifecycle">
        {LC_BUTTONS.map(({ to, label, Icon }) => {
          const ok = canTransition(rule.lifecycle, to);
          return (
            <button key={to} className="btn" disabled={!ok}
                       onClick={() => doLc(to)}
                       style={{ padding: "3px 10px", opacity: ok ? 1 : 0.35 }}
                       data-testid={`xdr-rule-lc-${to}`}>
              <Icon size={11} /> {label}
            </button>
          );
        })}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 340px",
                       gap: 14, alignItems: "start" }}>
        {/* Rule body */}
        <section className="panel" style={{ padding: 16 }}
                    data-testid="xdr-rule-body">
          {/* WHEN */}
          <SectionHead>WHEN</SectionHead>
          <select className="x-input" value={rule.trigger?.type}
                     onChange={(e) => mutate({ trigger: { type: e.target.value } })}
                     data-testid="xdr-rule-trigger">
            {TRIGGERS.map((t) => (
              <option key={t.type} value={t.type}>{t.label}</option>
            ))}
          </select>

          {/* IF (conditions) */}
          <SectionHead>IF (all match)</SectionHead>
          {(rule.conditions || []).map((c, i) => (
            <div key={i} style={{
              display: "grid",
              gridTemplateColumns: "1fr 160px 1fr auto",
              gap: 6, marginBottom: 6,
            }} data-testid={`xdr-rule-cond-${i}`}>
              <select className="x-input" value={c.field}
                         onChange={(e) => setCondition(i, { field: e.target.value })}>
                {(trigger?.fields || [c.field]).map((f) => (
                  <option key={f} value={f}>{f}</option>
                ))}
              </select>
              <select className="x-input" value={c.op}
                         onChange={(e) => setCondition(i, { op: e.target.value })}>
                {OPS.map((o) => <option key={o.op} value={o.op}>{o.label}</option>)}
              </select>
              <input className="x-input" value={c.value ?? ""}
                        onChange={(e) => setCondition(i, { value: e.target.value })}
                        placeholder="value" />
              <button className="btn ghost" style={{ padding: 3 }}
                        onClick={() => rmCondition(i)}
                        data-testid={`xdr-rule-cond-del-${i}`}>
                <Trash2 size={11} />
              </button>
            </div>
          ))}
          <button className="btn ghost" onClick={addCondition}
                     style={{ padding: "3px 10px" }}
                     data-testid="xdr-rule-add-condition">
            <Plus size={11} /> Add condition
          </button>

          {/* THEN (actions) */}
          <SectionHead>THEN</SectionHead>
          <div style={{ fontSize: 10.5, color: "var(--faint)",
                           marginBottom: 8, fontFamily: "var(--mono)" }}>
            Run order:&nbsp;
            <select value={rule.run_order || "sequential"}
                       onChange={(e) => mutate({ run_order: e.target.value })}
                       style={{
                         background: "var(--panel2)",
                         border: "1px solid var(--border)",
                         color: "var(--text)", padding: "1px 4px",
                       }}>
              <option value="sequential">sequential</option>
              <option value="parallel">parallel</option>
            </select>
          </div>
          {(rule.actions || []).map((a, i) => {
            const meta = getActionKind(a.kind);
            return (
              <div key={i} style={{
                padding: 10, marginBottom: 8, borderRadius: 4,
                border: "1px solid var(--border)",
                background: "var(--panel2)",
              }} data-testid={`xdr-rule-act-${i}`}>
                <div style={{ display: "flex", gap: 6, alignItems: "center",
                                 marginBottom: 8 }}>
                  <select className="x-input" style={{ maxWidth: 220 }}
                             value={a.kind}
                             onChange={(e) => setAction(i, { kind: e.target.value, params: {} })}>
                    {ACTION_KINDS.map((x) => <option key={x.kind} value={x.kind}>{x.label}</option>)}
                  </select>
                  <span style={{ flex: 1 }} />
                  <button className="btn ghost" style={{ padding: 3 }}
                            onClick={() => rmAction(i)}
                            data-testid={`xdr-rule-act-del-${i}`}>
                    <Trash2 size={11} />
                  </button>
                </div>
                {(meta?.params || []).map((p) => {
                  // Special-case invoke_playbook → select from persisted playbooks
                  if (a.kind === "invoke_playbook" && p.key === "playbook_id") {
                    return (
                      <div key={p.key} style={{ marginBottom: 4 }}>
                        <FieldLabel>{p.label}</FieldLabel>
                        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                          <select className="x-input"
                                     value={(a.params || {})[p.key] || ""}
                                     onChange={(e) => setAction(i, {
                                       params: { ...(a.params || {}), [p.key]: e.target.value },
                                     })}
                                     data-testid={`xdr-rule-act-playbook-${i}`}>
                            <option value="">— pick a playbook —</option>
                            {playbooks.map((pb) => (
                              <option key={pb.id} value={pb.id}>
                                {pb.name} — v{pb.version} ({pb.lifecycle})
                              </option>
                            ))}
                          </select>
                          {(a.params || {})[p.key] && (
                            <Link to={`/xdr/respond/playbooks/${a.params[p.key]}`}
                                     className="btn ghost"
                                     style={{ padding: "3px 8px", fontSize: 10 }}
                                     data-testid={`xdr-rule-open-playbook-${i}`}>
                              Open <ArrowRight size={11} />
                            </Link>
                          )}
                        </div>
                        {playbooks.length === 0 && (
                          <div style={{ marginTop: 4, fontSize: 10.5,
                                             color: "var(--amber)" }}>
                            No playbooks yet.&nbsp;
                            <Link to="/xdr/respond/playbooks"
                                     style={{ color: "var(--cyan)" }}>
                              Create one first
                            </Link>.
                          </div>
                        )}
                      </div>
                    );
                  }
                  return (
                    <div key={p.key} style={{ marginBottom: 4 }}>
                      <FieldLabel>{p.label}</FieldLabel>
                      <input className="x-input"
                                value={(a.params || {})[p.key] || ""}
                                onChange={(e) => setAction(i, {
                                  params: { ...(a.params || {}), [p.key]: e.target.value },
                                })} />
                    </div>
                  );
                })}
              </div>
            );
          })}
          <button className="btn ghost" onClick={addAction}
                     style={{ padding: "3px 10px" }}
                     data-testid="xdr-rule-add-action">
            <Plus size={11} /> Add action
          </button>
        </section>

        {/* Simulator */}
        <aside className="panel" style={{ padding: 14 }}
                  data-testid="xdr-rule-simulator">
          <div style={{ fontFamily: "var(--mono)", fontSize: 10, fontWeight: 800,
                           color: "var(--muted)", textTransform: "uppercase",
                           letterSpacing: ".3px", marginBottom: 10 }}>
            Simulate (design-time only)
          </div>
          <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 6 }}>
            Paste a hypothetical event JSON and click Simulate. Runs
            client-side; no executions.
          </div>
          <textarea rows={6}
                       value={simEvent}
                       onChange={(e) => setSimEvent(e.target.value)}
                       className="x-input"
                       style={{ fontFamily: "var(--mono)", fontSize: 11 }}
                       data-testid="xdr-rule-sim-input" />
          <button className="btn" onClick={doSim}
                    style={{ padding: "4px 10px", marginTop: 8 }}
                    data-testid="xdr-rule-sim-run">
            <FlaskConical size={11} /> Simulate
          </button>
          {sim && (
            <div style={{ marginTop: 10, padding: 8, borderRadius: 4,
                             background: "var(--panel2)",
                             border: `1px solid ${sim.matched ? "var(--mint)" : "var(--amber)"}`,
                             fontSize: 11, color: "var(--text-dim)" }}
                    data-testid="xdr-rule-sim-result">
              {sim.error
                ? <span style={{ color: "#ff9494" }}>{sim.error}</span>
                : <>
                    <div><b style={{ color: sim.matched ? "var(--mint)" : "var(--amber)" }}>
                      {sim.matched ? "MATCH" : "NO MATCH"}
                    </b></div>
                    {sim.matched && (
                      <div style={{ marginTop: 4 }}>
                        Would run: <span className="mono">{sim.would_execute.join(", ") || "(nothing)"}</span>
                      </div>
                    )}
                    <div style={{ marginTop: 6, color: "var(--faint)", fontSize: 10 }}>
                      {sim.note}
                    </div>
                  </>}
            </div>
          )}
          <div style={{ marginTop: 18, paddingTop: 10, borderTop: "1px solid var(--border)",
                           fontSize: 10.5, color: "var(--faint)",
                           fontFamily: "var(--mono)" }}>
            <ShieldAlert size={10} style={{ verticalAlign: "middle", marginRight: 4 }} />
            Response Engine: <b style={{ color: "var(--amber)" }}>NOT WIRED</b>
            <br />See <span style={{ color: "var(--cyan)" }}>docs/RESPONSE_CONTRACT.md</span>.
          </div>
        </aside>
      </div>
    </XdrShell>
  );
}


function SectionHead({ children }) {
  return (
    <div style={{ marginTop: 14, marginBottom: 6,
                    fontFamily: "var(--mono)", fontSize: 10, fontWeight: 800,
                    letterSpacing: ".3px", color: "var(--muted)",
                    textTransform: "uppercase" }}>{children}</div>
  );
}
function FieldLabel({ children }) {
  return (
    <div style={{ fontSize: 9.5, color: "var(--faint)",
                    textTransform: "uppercase", letterSpacing: ".3px",
                    fontFamily: "var(--mono)", marginBottom: 3 }}>
      {children}
    </div>
  );
}
