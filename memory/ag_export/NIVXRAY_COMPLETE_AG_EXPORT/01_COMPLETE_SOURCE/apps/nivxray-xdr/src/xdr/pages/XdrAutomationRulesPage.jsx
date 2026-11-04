/**
 * XdrAutomationRulesPage · `/xdr/respond/automation-rules`
 *
 * List + create.  Design-only until Response Engine is wired.
 */
import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Plus, Copy, Trash2, ShieldAlert } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import {
  listRules, createRule, duplicateRule, deleteRule,
} from "@/xdr/respond/automationRuleStore";
import { RESPONSE_ENGINE_WIRED } from "@/xdr/respond/actionRegistry";


function LifecyclePill({ state }) {
  const map = {
    draft:      { glyph: "◌", color: "var(--faint)",   label: "Draft" },
    testing:    { glyph: "◌", color: "var(--cyan)",    label: "Testing" },
    enabled:    { glyph: "●", color: "var(--mint)",    label: "Enabled" },
    disabled:   { glyph: "○", color: "var(--muted)",   label: "Disabled" },
    deprecated: { glyph: "⊘", color: "#ff5b5b",         label: "Deprecated" },
  }[state] || { glyph: "?", color: "var(--faint)", label: state };
  return (
    <span data-testid={`xdr-rule-lc-${state}`}
             style={{ color: map.color, fontWeight: 700, fontSize: 11 }}>
      {map.glyph} {map.label}
    </span>
  );
}


export default function XdrAutomationRulesPage() {
  const navigate = useNavigate();
  const [rows, setRows] = useState([]);

  const refresh = () => setRows(listRules());
  useEffect(() => { refresh(); }, []);

  const create = () => {
    const r = createRule({ name: "New automation rule" });
    navigate(`/xdr/respond/automation-rules/${r.id}`);
  };

  return (
    <XdrShell>
      {!RESPONSE_ENGINE_WIRED && (
        <div data-testid="xdr-rules-not-wired"
                style={{
                  padding: "8px 12px", marginBottom: 12,
                  borderRadius: 4, border: "1px dashed var(--amber)",
                  background: "rgba(245, 166, 35, .08)",
                  color: "var(--text-dim)", fontSize: 11.5, lineHeight: 1.6,
                }}>
          <b style={{ color: "var(--amber)", fontFamily: "var(--mono)",
                          letterSpacing: ".3px" }}>NOT WIRED</b>{" "}
          — Response Engine is not connected yet.  Automation rules in
          this milestone are <b>design-only</b>: they define WHEN a
          playbook would fire, persist, version, and simulate — but
          they will not trigger executions until{" "}
          <span className="mono">POST /api/respond/execute</span> lands.
          See <span className="mono">docs/RESPONSE_CONTRACT.md</span>.
        </div>
      )}

      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <h1 className="page-h1" style={{ margin: 0 }}
             data-testid="xdr-rules-heading">Automation Rules</h1>
        <div style={{ flex: 1 }} />
        <button className="btn primary" onClick={create}
                  data-testid="xdr-rules-create"
                  style={{ padding: "5px 12px" }}>
          <Plus size={11} /> Create Rule
        </button>
      </div>
      <div className="page-sub">
        WHEN conditions match, THEN invoke a playbook or side action.
        Rules own the decision; playbooks own the execution.
      </div>

      <section className="panel" style={{ padding: 0, marginTop: 12,
                                                overflow: "hidden" }}>
        {rows.length === 0 ? (
          <div className="x-empty" style={{ padding: 20 }}
                 data-testid="xdr-rules-empty">
            <b>NO AUTOMATION RULES</b> — Design-only store is empty.
          </div>
        ) : (
          <table className="x-table" style={{ width: "100%" }}
                    data-testid="xdr-rules-table">
            <thead>
              <tr>
                <th>Name</th><th>Trigger</th><th>Conditions</th>
                <th>Actions</th><th>Version</th><th>Lifecycle</th>
                <th>Last modified</th><th style={{ width: 150 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} data-testid={`xdr-rule-row-${r.id}`}>
                  <td>
                    <Link to={`/xdr/respond/automation-rules/${r.id}`}
                             style={{ color: "var(--text)", fontWeight: 700,
                                          textDecoration: "none" }}>
                      {r.name}
                    </Link>
                    <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                          marginTop: 2 }}>{r.id}</div>
                  </td>
                  <td className="mono" style={{ color: "var(--text-dim)" }}>
                    {r.trigger?.type || "—"}
                  </td>
                  <td className="mono" style={{ color: "var(--text-dim)" }}>
                    {(r.conditions || []).length}
                  </td>
                  <td className="mono" style={{ color: "var(--text-dim)" }}>
                    {(r.actions || []).length}
                  </td>
                  <td className="mono" style={{ color: "var(--text-dim)" }}>
                    v{r.version}
                  </td>
                  <td><LifecyclePill state={r.lifecycle} /></td>
                  <td className="mono" style={{ color: "var(--muted)" }}>
                    {(r.updated_at || "").slice(0, 19).replace("T", " ")}
                  </td>
                  <td>
                    <div style={{ display: "flex", gap: 4 }}>
                      <button className="btn ghost" style={{ padding: "3px 8px" }}
                                onClick={() => { duplicateRule(r.id); refresh(); }}
                                data-testid={`xdr-rule-dup-${r.id}`}>
                        <Copy size={11} /> Duplicate
                      </button>
                      <button className="btn ghost" style={{ padding: "3px 8px", color: "#ff9494" }}
                                onClick={() => {
                                  if (!window.confirm(`Delete "${r.name}"?`)) return;
                                  deleteRule(r.id); refresh();
                                }}
                                data-testid={`xdr-rule-del-${r.id}`}>
                        <Trash2 size={11} /> Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div style={{ padding: "8px 14px", borderTop: "1px solid var(--border)",
                         background: "var(--panel2)",
                         color: "var(--faint)", fontSize: 10.5,
                         fontFamily: "var(--mono)" }}>
          <ShieldAlert size={10} style={{ verticalAlign: "middle", marginRight: 4 }} />
          STORAGE: LOCAL BROWSER · versioned, not yet backed by NivXRay
        </div>
      </section>
    </XdrShell>
  );
}
