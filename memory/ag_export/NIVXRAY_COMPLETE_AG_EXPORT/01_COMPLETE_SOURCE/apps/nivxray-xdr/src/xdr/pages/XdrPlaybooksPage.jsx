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


function LifecyclePill({ state }) {
  const map = {
    draft:      { glyph: "◌", color: "var(--faint)",   label: "Draft" },
    testing:    { glyph: "◌", color: "var(--cyan)",    label: "Testing" },
    enabled:    { glyph: "●", color: "var(--mint)",    label: "Enabled" },
    disabled:   { glyph: "○", color: "var(--muted)",   label: "Disabled" },
    deprecated: { glyph: "⊘", color: "#ff5b5b",         label: "Deprecated" },
  }[state] || { glyph: "?", color: "var(--faint)", label: state };
  return (
    <span data-testid={`xdr-playbook-lc-${state}`}
             style={{ color: map.color, fontWeight: 700, fontSize: 11 }}>
      {map.glyph} {map.label}
    </span>
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
        <div data-testid="xdr-playbooks-not-wired"
                style={{
                  padding: "8px 12px", marginBottom: 12,
                  borderRadius: 4, border: "1px dashed var(--amber)",
                  background: "rgba(245, 166, 35, .08)",
                  color: "var(--text-dim)", fontSize: 11.5, lineHeight: 1.6,
                }}>
          <b style={{ color: "var(--amber)", fontFamily: "var(--mono)",
                          letterSpacing: ".3px" }}>NOT WIRED</b>{" "}
          — Response Engine is not connected yet.  Playbooks in this
          milestone are <b>design-only</b>: they persist, version, and
          validate, but they will not execute against endpoints, identity,
          network, or email.  The eventual{" "}
          <span className="mono">/api/respond/execute</span> plane will
          light this up.
        </div>
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
            <b>NO PLAYBOOKS</b> — Design-only store is empty.  Click
            "Create Playbook" to draft one.
          </div>
        ) : (
          <table className="x-table" style={{ width: "100%" }}
                    data-testid="xdr-playbooks-table">
            <thead>
              <tr>
                <th>Name</th><th>Trigger</th><th>Nodes</th>
                <th>Version</th><th>Lifecycle</th>
                <th>Last modified</th><th style={{ width: 150 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((pb) => (
                <tr key={pb.id} data-testid={`xdr-playbook-row-${pb.id}`}>
                  <td>
                    <Link to={`/xdr/respond/playbooks/${pb.id}`}
                             style={{ color: "var(--text)", fontWeight: 700,
                                          textDecoration: "none" }}>
                      {pb.name}
                    </Link>
                    <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                          marginTop: 2 }}>{pb.id}</div>
                  </td>
                  <td className="mono" style={{ color: "var(--text-dim)" }}>
                    {pb.trigger?.type || "—"}
                  </td>
                  <td className="mono" style={{ color: "var(--text-dim)" }}>
                    {pb.nodes.length}
                  </td>
                  <td className="mono" style={{ color: "var(--text-dim)" }}>
                    v{pb.version}
                  </td>
                  <td><LifecyclePill state={pb.lifecycle} /></td>
                  <td className="mono" style={{ color: "var(--muted)" }}>
                    {(pb.updated_at || "").slice(0, 19).replace("T", " ")}
                  </td>
                  <td>
                    <div style={{ display: "flex", gap: 4 }}>
                      <button className="btn ghost" style={{ padding: "3px 8px" }}
                                onClick={() => { duplicatePlaybook(pb.id, { by: "operator" }); refresh(); }}
                                data-testid={`xdr-playbook-dup-${pb.id}`}>
                        <Copy size={11} /> Duplicate
                      </button>
                      <button className="btn ghost" style={{ padding: "3px 8px", color: "#ff9494" }}
                                onClick={() => {
                                  if (!window.confirm(`Delete "${pb.name}"?`)) return;
                                  deletePlaybook(pb.id); refresh();
                                }}
                                data-testid={`xdr-playbook-del-${pb.id}`}>
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
