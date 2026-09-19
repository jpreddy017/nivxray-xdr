/**
 * XdrPlaybooksPage · `/xdr/respond/playbooks`
 *
 * Playbook list + create.  Design-only; execution shows an honest
 * "NOT WIRED — Response Engine not yet connected" state everywhere.
 */
import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Plus, Copy, Trash2, ShieldAlert } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import {
  listPlaybooks, createPlaybook, duplicatePlaybook, deletePlaybook,
  LIFECYCLE,
} from "@/xdr/respond/playbookStore";
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
            data-testid={`xdr-playbook-lc-${state}`}>
      {label}
    </NxChip>
  );
}


export default function XdrPlaybooksPage() {
  const navigate = useNavigate();
  const [rows, setRows] = useState([]);

  const refresh = () => setRows(listPlaybooks());
  useEffect(() => { refresh(); }, []);

  const create = () => {
    const pb = createPlaybook({ name: "New playbook", created_by: "operator" });
    navigate(`/xdr/respond/playbooks/${pb.id}`);
  };

  return (
    <XdrShell>
      {!RESPONSE_ENGINE_WIRED && (
        <NxSection variant="inset" testid="xdr-playbooks-not-wired"
                   title="Response engine is not connected"
                   note={"Playbooks in this milestone are design-only: they persist, version and validate, but they execute against no endpoint, identity, network or mailbox until the response plane lands."}>
          <NxState value="NOT_CONFIGURED"
                   reason="POST /api/respond/execute is not wired in this build" />
        </NxSection>
      )}

      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <h1 className="page-h1" style={{ margin: 0 }}
             data-testid="xdr-playbooks-heading">Playbooks</h1>
        <div style={{ flex: 1 }} />
        <button className="btn primary" onClick={create}
                  data-testid="xdr-playbooks-create"
                  style={{ padding: "5px 12px" }}>
          <Plus size={11} /> Create Playbook
        </button>
      </div>
      <div className="page-sub">
        Reusable response workflows. Create, version, and manage here;
        analysts execute them from Incidents once the Response Engine
        is wired.
      </div>

      <section className="panel" style={{ padding: 0, marginTop: 12,
                                                overflow: "hidden" }}>
        {rows.length === 0 ? (
          <div className="x-empty" style={{ padding: 20 }}
                 data-testid="xdr-playbooks-empty">
            <b>No playbook exists yet</b> — the design-only store is
            empty. Use "Create Playbook" to draft one.
          </div>
        ) : (
          <NxDataTable rows={rows} rowKey={(pb) => pb.id} pageSize={25}
                       searchPlaceholder="Search playbook, trigger, id"
                       onRowClick={(pb) => navigate(
                         `/xdr/respond/playbooks/${pb.id}`)}
                       testid="xdr-playbooks-table"
                       emptyTitle="No playbook exists yet"
                       columns={[
            { key: "name", header: "Name", width: "300px",
              value: (pb) => pb.name,
              render: (pb) => (
                <span data-testid={`xdr-playbook-row-${pb.id}`}>
                  <strong>{pb.name}</strong>
                  <div className="nx-absent nx-mono">{pb.id}</div>
                </span>) },
            { key: "trigger", header: "Trigger", width: "170px",
              value: (pb) => pb.trigger?.type || "",
              render: (pb) => (pb.trigger?.type
                ? <span className="nx-mono">{pb.trigger.type}</span>
                : <span className="nx-absent">—</span>) },
            { key: "nodes", header: "Nodes", width: "90px", align: "right",
              value: (pb) => pb.nodes.length },
            { key: "version", header: "Version", width: "90px",
              align: "right", value: (pb) => pb.version,
              render: (pb) => <span className="nx-mono">v{pb.version}</span> },
            { key: "lifecycle", header: "Lifecycle", width: "130px",
              value: (pb) => pb.lifecycle,
              render: (pb) => <LifecyclePill state={pb.lifecycle} /> },
            { key: "updated", header: "Last modified", width: "170px",
              value: (pb) => pb.updated_at || "",
              render: (pb) => (
                <span className="nx-mono">
                  {(pb.updated_at || "").slice(0, 19).replace("T", " ")}
                </span>) },
            { key: "row_actions", header: "", width: "200px",
              sortable: false,
              render: (pb) => (
                <span style={{ display: "flex", gap: 4 }}>
                  <button className="nx-btn"
                          onClick={(e) => { e.stopPropagation();
                            duplicatePlaybook(pb.id, { by: "operator" });
                            refresh(); }}
                          data-testid={`xdr-playbook-dup-${pb.id}`}>
                    <Copy size={11} /> Duplicate
                  </button>
                  <button className="nx-btn"
                          style={{ color: "var(--nx-critical)" }}
                          onClick={(e) => {
                            e.stopPropagation();
                            if (!window.confirm(`Delete "${pb.name}"?`)) return;
                            deletePlaybook(pb.id); refresh();
                          }}
                          data-testid={`xdr-playbook-del-${pb.id}`}>
                    <Trash2 size={11} /> Delete
                  </button>
                </span>) },
          ]} />
        )}
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
