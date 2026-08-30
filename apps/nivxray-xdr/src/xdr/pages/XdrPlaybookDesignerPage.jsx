/**
 * XdrPlaybookDesignerPage · `/xdr/respond/playbooks/:id`
 *
 * Design-only canvas.  Linear vertical flow with insert-action and
 * insert-condition affordances.  Right-side inspector edits the
 * selected node.  Never executes; execution surface says NOT WIRED.
 */
import React, { useEffect, useMemo, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Plus, Save, Trash2, GitBranch, ArrowRight, X,
  Play, Pause, Archive, FlaskConical, ArrowDown, ShieldAlert,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import {
  getPlaybook, savePlaybook, transitionLifecycle,
  insertAfter, insertCondition, removeNode,
  LIFECYCLE, canTransition,
} from "@/xdr/respond/playbookStore";
import {
  RESPONSE_ACTIONS, ACTIONS_BY_PROVIDER, getAction, RESPONSE_ENGINE_WIRED,
} from "@/xdr/respond/actionRegistry";
import * as Engine from "@/xdr/respond/responseEngineApi";


const LIFECYCLE_BUTTONS = [
  { to: LIFECYCLE.TESTING,    label: "Move to Testing",    Icon: FlaskConical },
  { to: LIFECYCLE.ENABLED,    label: "Enable",             Icon: Play },
  { to: LIFECYCLE.DISABLED,   label: "Disable",            Icon: Pause },
  { to: LIFECYCLE.DRAFT,      label: "Back to Draft",      Icon: X },
  { to: LIFECYCLE.DEPRECATED, label: "Deprecate",          Icon: Archive },
];


export default function XdrPlaybookDesignerPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [pb, setPb]         = useState(null);
  const [selected, setSel]  = useState(null);
  const [dirty, setDirty]   = useState(false);
  const [saveState, setSs]  = useState("clean");

  const [sim, setSim] = useState(null);
  const [simEvent, setSimEvent] = useState('{"verdict":"malicious","severity":"critical"}');
  const [simBusy, setSimBusy] = useState(false);

  useEffect(() => {
    const p = getPlaybook(id);
    if (!p) { navigate("/xdr/respond/playbooks"); return; }
    setPb(p);
  }, [id, navigate]);

  const chain = useMemo(() => flatten(pb), [pb]);

  if (!pb) return null;

  const mutate = (fn) => {
    const next = fn({ ...pb, nodes: pb.nodes.map((n) => ({ ...n })) });
    setPb(next); setDirty(true);
  };
  const doSave = () => {
    setSs("saving");
    try {
      const saved = savePlaybook(pb, { by: "operator", note: "designer save" });
      setPb(saved); setDirty(false); setSs("saved");
      setTimeout(() => setSs("clean"), 1200);
    } catch (e) { setSs("error"); window.alert(String(e)); }
  };
  const doLifecycle = (to) => {
    try { setPb(transitionLifecycle(pb.id, to, { by: "operator" })); }
    catch (e) { window.alert(String(e)); }
  };
  const doSimulate = async () => {
    setSimBusy(true); setSim(null);
    try {
      let evt = {};
      try { evt = JSON.parse(simEvent); }
      catch { setSim({ error: "Invalid event JSON" }); setSimBusy(false); return; }
      const result = await Engine.simulatePlaybook({
        playbook_id: pb.id,
        tenant_id:   pb.tenant_id || "simulate",
        entry:       pb.entry,
        nodes:       pb.nodes,
        event:       evt,
      });
      setSim(result);
    } catch (e) {
      setSim({ error: e?.code === "RESPONSE_ENGINE_NOT_DEPLOYED"
        ? "Response Engine URL not set (VITE_XDR_RESPONSE_URL). Simulation requires the standalone engine."
        : (e?.response?.data?.detail?.error || e?.message || String(e)) });
    } finally { setSimBusy(false); }
  };

  const selNode = pb.nodes.find((n) => n.id === selected) || null;

  return (
    <XdrShell>
      {!RESPONSE_ENGINE_WIRED && (
        <div data-testid="xdr-designer-not-wired"
                style={{
                  padding: "8px 12px", marginBottom: 12,
                  borderRadius: 4, border: "1px dashed var(--amber)",
                  background: "rgba(245, 166, 35, .08)",
                  color: "var(--text-dim)", fontSize: 11.5,
                }}>
          <b style={{ color: "var(--amber)", fontFamily: "var(--mono)" }}>NOT WIRED</b>
          {" "}— Response Engine not connected. Save / Version / Lifecycle work; Run / Test are disabled.
        </div>
      )}

      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <input value={pb.name}
                  onChange={(e) => mutate((p) => ({ ...p, name: e.target.value }))}
                  className="x-input"
                  style={{ maxWidth: 360, fontWeight: 700, fontSize: 15 }}
                  data-testid="xdr-designer-name" />
        <span className="mono" style={{ color: "var(--faint)", fontSize: 11 }}>
          v{pb.version} · {pb.lifecycle.toUpperCase()}
        </span>
        <div style={{ flex: 1 }} />
        <button className="btn" style={{ padding: "4px 10px" }}
                  onClick={doSimulate} disabled={simBusy}
                  data-testid="xdr-designer-simulate">
          <FlaskConical size={11} /> {simBusy ? "Simulating…" : "Simulate"}
        </button>
        <button className="btn" style={{ padding: "4px 10px",
                                                 opacity: RESPONSE_ENGINE_WIRED ? 1 : 0.5,
                                                 cursor: RESPONSE_ENGINE_WIRED ? "pointer" : "not-allowed" }}
                  disabled={!RESPONSE_ENGINE_WIRED}
                  title={RESPONSE_ENGINE_WIRED
                            ? "Run against real Response Engine — real adapters, but stubs in Phase 1"
                            : "Response Engine not wired · set VITE_XDR_RESPONSE_URL"}
                  data-testid="xdr-designer-run-disabled">
          <Play size={11} /> Run {RESPONSE_ENGINE_WIRED ? "" : "(disabled)"}
        </button>
        <button className="btn primary" onClick={doSave} disabled={!dirty || saveState === "saving"}
                  style={{ padding: "4px 10px" }}
                  data-testid="xdr-designer-save">
          <Save size={11} /> {saveState === "saving" ? "Saving…"
                                : saveState === "saved" ? "Saved" : "Save"}
        </button>
      </div>

      <div className="page-sub" style={{ marginBottom: 12 }}>
        Trigger · <span className="mono">{pb.trigger?.type}</span> ·
        Nodes · <b>{pb.nodes.length}</b> · Versions · <b>{pb.versions?.length ?? 0}</b>
      </div>

      {/* Lifecycle bar */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 12 }}
             data-testid="xdr-designer-lifecycle">
        {LIFECYCLE_BUTTONS.map(({ to, label, Icon }) => {
          const ok = canTransition(pb.lifecycle, to);
          return (
            <button key={to} className="btn" disabled={!ok}
                       onClick={() => doLifecycle(to)}
                       style={{ padding: "3px 10px", opacity: ok ? 1 : 0.35 }}
                       data-testid={`xdr-designer-lc-${to}`}>
              <Icon size={11} /> {label}
            </button>
          );
        })}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 340px",
                       gap: 14, alignItems: "start" }}>
        {/* Canvas — linear chain */}
        <section className="panel" style={{ padding: 20 }}
                    data-testid="xdr-designer-canvas">
          {chain.map((entry, i) => (
            <NodeCard key={entry.id}
                          entry={entry}
                          selected={selected === entry.id}
                          onSelect={() => setSel(entry.id)}
                          onDelete={() => { mutate((p) => removeNode(p, entry.id)); setSel(null); }}
                          onInsertAction={() => {
                            const act = RESPONSE_ACTIONS[0];
                            mutate((p) => insertAfter(p, entry.id, {
                              kind: "action", action_id: act.action_id, config: {} }));
                          }}
                          onInsertCondition={() => mutate((p) => insertCondition(p, entry.id))}
                          isLast={i === chain.length - 1} />
          ))}
        </section>

        {/* Inspector */}
        <aside className="panel" style={{ padding: 14 }}
                  data-testid="xdr-designer-inspector">
          <div style={{ fontFamily: "var(--mono)", fontSize: 10, fontWeight: 800,
                           color: "var(--muted)", textTransform: "uppercase",
                           letterSpacing: ".3px", marginBottom: 10 }}>Inspector</div>
          {!selNode && (
            <div style={{ color: "var(--text-dim)", fontSize: 11.5 }}>
              Click a node to edit.
            </div>
          )}
          {selNode && (
            <Inspector node={selNode}
                          onChange={(patch) => mutate((p) => {
                            p.nodes = p.nodes.map((n) =>
                              n.id === selNode.id ? { ...n, ...patch } : n);
                            return p;
                          })} />
          )}
          <div style={{ marginTop: 18, paddingTop: 10, borderTop: "1px solid var(--border)",
                           fontSize: 10.5, color: "var(--faint)",
                           fontFamily: "var(--mono)" }}>
            <ShieldAlert size={10} style={{ verticalAlign: "middle", marginRight: 4 }} />
            Response Engine:{" "}
            <b style={{ color: RESPONSE_ENGINE_WIRED ? "var(--mint)" : "var(--amber)" }}>
              {RESPONSE_ENGINE_WIRED ? "WIRED" : "NOT WIRED"}
            </b>
            <br />See <span style={{ color: "var(--cyan)" }}>RESPONSE_CONTRACT.md</span>.
          </div>

          {/* Simulate input + trace */}
          <div style={{ marginTop: 14, paddingTop: 12, borderTop: "1px solid var(--border)" }}
                  data-testid="xdr-designer-sim-panel">
            <div style={{ fontFamily: "var(--mono)", fontSize: 10, fontWeight: 800,
                             color: "var(--muted)", textTransform: "uppercase",
                             letterSpacing: ".3px", marginBottom: 8 }}>
              Simulation input
            </div>
            <textarea rows={4} value={simEvent}
                         onChange={(e) => setSimEvent(e.target.value)}
                         className="x-input"
                         style={{ fontFamily: "var(--mono)", fontSize: 11 }}
                         data-testid="xdr-designer-sim-event" />
            {sim && (
              <div style={{ marginTop: 10, padding: 8, borderRadius: 4,
                               background: "var(--panel2)",
                               border: `1px solid ${sim.error ? "#ff5b5b" : "var(--mint)"}`,
                               fontSize: 11, color: "var(--text-dim)" }}
                      data-testid="xdr-designer-sim-trace">
                {sim.error
                  ? <span style={{ color: "#ff9494" }}>{sim.error}</span>
                  : <>
                      <div style={{ color: "var(--mint)", fontWeight: 700 }}>
                        MODE: {sim.mode?.toUpperCase()} · {sim.steps} steps
                      </div>
                      <div style={{ marginTop: 6 }}>
                        {(sim.trace || []).map((t, i) => (
                          <div key={i} className="mono"
                                  style={{ fontSize: 10.5, color: t.status === "rejected"
                                              ? "#ff9494" : t.branch === "yes"
                                              ? "var(--mint)" : t.branch === "no"
                                              ? "var(--faint)" : "var(--text-dim)" }}>
                            {i + 1}. {t.kind?.toUpperCase()}
                            {t.action_id ? " · " + t.action_id : ""}
                            {t.branch ? " → " + t.branch : ""}
                            {t.status ? " [" + t.status + "]" : ""}
                          </div>
                        ))}
                      </div>
                      <div style={{ marginTop: 6, color: "var(--faint)", fontSize: 10 }}>
                        {sim.note}
                      </div>
                    </>}
              </div>
            )}
          </div>
        </aside>
      </div>
    </XdrShell>
  );
}


function flatten(pb) {
  if (!pb) return [];
  const out = [];
  const byId = Object.fromEntries(pb.nodes.map((n) => [n.id, n]));
  const seen = new Set();
  let cur = byId[pb.entry];
  while (cur && !seen.has(cur.id)) {
    seen.add(cur.id);
    out.push({ ...cur });
    if (cur.kind === "condition") break;              // condition splits — inspector handles branches
    cur = byId[cur.next];
  }
  return out;
}


function NodeCard({ entry, selected, onSelect, onDelete, onInsertAction, onInsertCondition, isLast }) {
  const info = describeNode(entry);
  return (
    <div style={{ display: "flex", flexDirection: "column",
                    alignItems: "center", gap: 4 }}
            data-testid={`xdr-node-${entry.id}`}>
      <div
        onClick={onSelect}
        style={{
          cursor: "pointer", minWidth: 320, maxWidth: 520,
          padding: "10px 14px", borderRadius: 6,
          border: `1px solid ${selected ? "var(--mint)" : info.border}`,
          background: info.bg,
          color: "var(--text)", fontSize: 12,
        }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontFamily: "var(--mono)", fontSize: 10, fontWeight: 800,
                            letterSpacing: ".3px", textTransform: "uppercase",
                            color: info.accent }}>{info.kindLabel}</span>
          <span style={{ flex: 1 }} />
          {entry.kind !== "start" && entry.kind !== "end" && (
            <button className="btn ghost" style={{ padding: 2 }}
                       onClick={(e) => { e.stopPropagation(); onDelete(); }}
                       data-testid={`xdr-node-del-${entry.id}`}
                       title="Remove node">
              <Trash2 size={10} />
            </button>
          )}
        </div>
        <div style={{ marginTop: 4, fontWeight: 600 }}>{info.title}</div>
        {info.subtitle && (
          <div style={{ marginTop: 2, color: "var(--text-dim)", fontSize: 11 }}>
            {info.subtitle}
          </div>
        )}
        {entry.kind === "condition" && (
          <div style={{ marginTop: 8, display: "flex", gap: 6, fontSize: 10.5,
                          fontFamily: "var(--mono)" }}>
            <span style={{ color: "var(--mint)" }}>yes → {entry.yes_next?.slice(-5)}</span>
            <span style={{ color: "var(--faint)" }}>·</span>
            <span style={{ color: "#ff9494" }}>no → {entry.no_next?.slice(-5)}</span>
          </div>
        )}
      </div>
      {!isLast && (
        <>
          <ArrowDown size={12} style={{ color: "var(--faint)" }} />
          {entry.kind !== "end" && (
            <div style={{ display: "flex", gap: 6, marginBottom: 4 }}>
              <button className="btn ghost" style={{ padding: "2px 8px", fontSize: 10 }}
                        onClick={onInsertAction}
                        data-testid={`xdr-node-add-action-${entry.id}`}>
                <Plus size={9} /> Action
              </button>
              <button className="btn ghost" style={{ padding: "2px 8px", fontSize: 10 }}
                        onClick={onInsertCondition}
                        data-testid={`xdr-node-add-condition-${entry.id}`}>
                <GitBranch size={9} /> Condition
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}


function describeNode(n) {
  if (n.kind === "start") return {
    kindLabel: "START",      accent: "var(--mint)",
    border: "var(--mint)",    bg: "rgba(60,232,184,.08)",
    title: "Trigger fired",   subtitle: "Playbook entry point",
  };
  if (n.kind === "end") return {
    kindLabel: "END",         accent: "var(--faint)",
    border: "var(--border)",  bg: "var(--panel2)",
    title: "End",             subtitle: "Terminal step",
  };
  if (n.kind === "condition") return {
    kindLabel: "CONDITION",   accent: "var(--amber)",
    border: "var(--amber)",   bg: "rgba(245,166,35,.06)",
    title: n.config?.field
      ? `${n.config.field} ${n.config.op || "=="} ${JSON.stringify(n.config.value)}`
      : "Configure condition",
    subtitle: "Splits into yes / no branches",
  };
  if (n.kind === "action") {
    const a = getAction(n.action_id);
    return {
      kindLabel: "ACTION",      accent: "var(--purple)",
      border: "var(--purple)",  bg: "rgba(155,123,240,.08)",
      title: a?.label || n.action_id || "Unconfigured",
      subtitle: a
        ? `${a.provider} · ${a.destructive ? "destructive · " : ""}${a.approval_required ? "approval required" : "auto-approved"}`
        : "Pick a response action in the inspector",
    };
  }
  return { kindLabel: n.kind.toUpperCase(), accent: "var(--faint)",
             border: "var(--border)", bg: "var(--panel2)",
             title: n.id, subtitle: "" };
}


function Inspector({ node, onChange }) {
  if (node.kind === "action") {
    const a = getAction(node.action_id);
    return (
      <div>
        <FieldLabel>Response Action</FieldLabel>
        <select className="x-input" value={node.action_id || ""}
                   onChange={(e) => onChange({ action_id: e.target.value, config: {} })}>
          <option value="">— pick an action —</option>
          {Object.entries(ACTIONS_BY_PROVIDER).map(([prov, acts]) => (
            <optgroup key={prov} label={prov.toUpperCase()}>
              {acts.map((x) => (
                <option key={x.action_id} value={x.action_id}>{x.label}</option>
              ))}
            </optgroup>
          ))}
        </select>
        {a && (
          <>
            <MetaRow k="Provider"          v={a.provider} />
            <MetaRow k="Capability"        v={a.capability} />
            <MetaRow k="Destructive"       v={a.destructive ? "yes" : "no"}
                        color={a.destructive ? "#ff9494" : "var(--mint)"} />
            <MetaRow k="Reversible"        v={a.reversible ? "yes" : "no"} />
            <MetaRow k="Approval required" v={a.approval_required ? "yes" : "no"}
                        color={a.approval_required ? "var(--amber)" : "var(--mint)"} />
            <MetaRow k="Permissions" v={
              (a.required_permissions || []).map((p) => `${p.role}:${p.scope}`).join(", ") || "—"
            } />
            <MetaRow k="Execution" v={
              <span style={{ color: "var(--amber)" }}>NOT WIRED · Response Engine pending</span>
            } />
            {(a.parameters || []).length > 0 && (
              <>
                <FieldLabel>Parameters</FieldLabel>
                {a.parameters.map((p) => (
                  <div key={p.key} style={{ marginBottom: 8 }}>
                    <div style={{ fontSize: 10, color: "var(--faint)",
                                     textTransform: "uppercase" }}>{p.label}</div>
                    <input className="x-input"
                              value={node.config?.[p.key] || ""}
                              onChange={(e) => onChange({
                                config: { ...(node.config || {}), [p.key]: e.target.value },
                              })} />
                  </div>
                ))}
              </>
            )}
          </>
        )}
      </div>
    );
  }
  if (node.kind === "condition") {
    return (
      <div>
        <FieldLabel>Condition</FieldLabel>
        <input className="x-input" placeholder="field"
                  value={node.config?.field || ""}
                  onChange={(e) => onChange({ config: { ...(node.config || {}), field: e.target.value } })} />
        <div style={{ height: 6 }} />
        <select className="x-input" value={node.config?.op || "eq"}
                   onChange={(e) => onChange({ config: { ...(node.config || {}), op: e.target.value } })}>
          <option value="eq">equals</option>
          <option value="neq">not equals</option>
          <option value="gt">greater than</option>
          <option value="lt">less than</option>
          <option value="contains">contains</option>
        </select>
        <div style={{ height: 6 }} />
        <input className="x-input" placeholder="value"
                  value={node.config?.value ?? ""}
                  onChange={(e) => onChange({ config: { ...(node.config || {}), value: e.target.value } })} />
      </div>
    );
  }
  return (
    <div style={{ color: "var(--text-dim)", fontSize: 11.5 }}>
      Node id: <span className="mono">{node.id}</span><br />
      Kind: <b>{node.kind}</b>
    </div>
  );
}


function FieldLabel({ children }) {
  return (
    <div style={{ fontSize: 10, color: "var(--faint)",
                    textTransform: "uppercase", letterSpacing: ".3px",
                    fontFamily: "var(--mono)", marginBottom: 4, marginTop: 6 }}>
      {children}
    </div>
  );
}
function MetaRow({ k, v, color }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between",
                    padding: "4px 0", borderBottom: "1px solid var(--border)",
                    fontSize: 11 }}>
      <span style={{ color: "var(--faint)" }}>{k}</span>
      <span style={{ color: color || "var(--text-dim)", fontFamily: "var(--mono)" }}>{v}</span>
    </div>
  );
}
