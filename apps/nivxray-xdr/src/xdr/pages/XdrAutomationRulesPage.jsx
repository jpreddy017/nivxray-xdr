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
import { NxChip, NxDataTable, NxSection, NxState } from "@/xdr/nx";


//: Lifecycle is a state, so it wears the platform's state grammar rather
//: than a page-local glyph palette.
const LC_TONE = {
  draft: "not_run", testing: "medium", enabled: "benign",
  disabled: "neutral", deprecated: "high",
};

function LifecyclePill({ state }) {
  const key = String(state || "").toLowerCase();
  const label = key ? key.charAt(0).toUpperCase() + key.slice(1) : "Unknown";
  return (
    <NxChip tone={LC_TONE[key] || "neutral"}
            variant={key === "enabled" ? "filled" : "tinted"}
            data-testid={`xdr-rule-lc-${state}`}>
      {label}
    </NxChip>
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
        <NxSection variant="inset" testid="xdr-rules-not-wired"
                   title="Response engine is not connected"
                   note={"Automation rules in this milestone are design-only: they define WHEN a playbook would fire, and they persist, version and simulate — but they trigger no execution. Rules own the decision; playbooks own the execution."}>
          <NxState value="NOT_CONFIGURED"
                   reason="POST /api/respond/execute is not wired in this build" />
        </NxSection>
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
        {/* The table renders whether or not there are rows: its headers are
            the contract, and its own empty state says what is missing. A
            bespoke empty block here hid both. */}
          <NxDataTable rows={rows} rowKey={(r) => r.id} pageSize={25}
                       searchPlaceholder="Search rule, trigger, id"
                       onRowClick={(r) => navigate(
                         `/xdr/respond/automation-rules/${r.id}`)}
                       testid="xdr-rules-table"
                       emptyTitle="No automation rule exists yet"
                       columns={[
            { key: "name", header: "Name", width: "280px",
              value: (r) => r.name,
              render: (r) => (
                <span data-testid={`xdr-rule-row-${r.id}`}>
                  <strong>{r.name}</strong>
                  <div className="nx-absent nx-mono">{r.id}</div>
                </span>) },
            { key: "trigger", header: "Trigger", width: "170px",
              value: (r) => r.trigger?.type || "",
              render: (r) => (r.trigger?.type
                ? <span className="nx-mono">{r.trigger.type}</span>
                : <span className="nx-absent">—</span>) },
            { key: "conditions", header: "Conditions", width: "110px",
              align: "right", value: (r) => (r.conditions || []).length },
            { key: "actions", header: "Actions", width: "100px",
              align: "right", value: (r) => (r.actions || []).length },
            { key: "version", header: "Version", width: "90px",
              align: "right", value: (r) => r.version,
              render: (r) => <span className="nx-mono">v{r.version}</span> },
            { key: "lifecycle", header: "Lifecycle", width: "130px",
              value: (r) => r.lifecycle,
              render: (r) => <LifecyclePill state={r.lifecycle} /> },
            { key: "updated", header: "Last modified", width: "170px",
              value: (r) => r.updated_at || "",
              render: (r) => (
                <span className="nx-mono">
                  {(r.updated_at || "").slice(0, 19).replace("T", " ")}
                </span>) },
            { key: "row_actions", header: "", width: "200px",
              sortable: false,
              render: (r) => (
                <span style={{ display: "flex", gap: 4 }}>
                  <button className="nx-btn"
                          onClick={(e) => { e.stopPropagation();
                                            duplicateRule(r.id); refresh(); }}
                          data-testid={`xdr-rule-dup-${r.id}`}>
                    <Copy size={11} /> Duplicate
                  </button>
                  <button className="nx-btn"
                          style={{ color: "var(--nx-critical)" }}
                          onClick={(e) => {
                            e.stopPropagation();
                            if (!window.confirm(`Delete "${r.name}"?`)) return;
                            deleteRule(r.id); refresh();
                          }}
                          data-testid={`xdr-rule-del-${r.id}`}>
                    <Trash2 size={11} /> Delete
                  </button>
                </span>) },
          ]} />
        <div style={{ padding: "8px 14px", borderTop: "1px solid var(--border)",
                         background: "var(--panel2)",
                         color: "var(--faint)", fontSize: 10.5,
                         fontFamily: "var(--mono)" }}>
          <ShieldAlert size={10} style={{ verticalAlign: "middle", marginRight: 4 }} />
          Storage: local browser · versioned, not yet backed by NivXRay
        </div>
      </section>
    </XdrShell>
  );
}
