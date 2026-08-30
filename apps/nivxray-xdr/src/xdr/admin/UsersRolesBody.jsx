/**
 * Admin › Users & Roles — P0-3 live control-plane surface.
 *
 * Consumes:
 *   GET  /api/xdr/rbac/permissions
 *   GET  /api/xdr/rbac/roles     · POST · PUT/{id} · POST /{id}/clone
 *   GET  /api/xdr/rbac/users     · POST · PUT/{id} · DELETE
 *      POST /users/{id}/roles · DELETE /users/{id}/roles/{aid}
 *      GET  /users/{id}/effective
 *   POST /api/xdr/rbac/simulate
 *
 * Contract:
 *   • Every mutation surfaces the returned `audit_ref`.
 *   • RBAC is enforced server-side — the UI reflects backend outcomes,
 *     it does not decide access itself.
 *   • Empty state renders honestly.  No fabricated users/roles.
 */
import React, { useEffect, useMemo, useState } from "react";
import {
  Users, Shield, KeyRound, Search, Plus, RefreshCcw, Trash2,
  Power, PowerOff, X, PlayCircle, Copy, ChevronRight, CheckCircle2,
  XCircle,
} from "lucide-react";

import api from "@/lib/api";


// ── Small helpers ─────────────────────────────────────────────────
function Badge({ label, color = "var(--faint)", testid }) {
  return (
    <span data-testid={testid} style={{
      display: "inline-block", padding: "1px 6px", borderRadius: 3,
      border: `1px solid ${color}`, color, fontSize: 9.5,
      letterSpacing: ".3px", fontWeight: 700, textTransform: "uppercase",
      fontFamily: "var(--mono)",
    }}>{label}</span>
  );
}


// ── Users tab ────────────────────────────────────────────────────
function UsersTab({ rolesById, refresh, onRefresh }) {
  const [users, setUsers] = useState([]);
  const [err, setErr]     = useState(null);
  const [addOpen, setAddOpen] = useState(false);
  const [lastAudit, setLastAudit] = useState(null);
  const [assignFor, setAssignFor] = useState(null);
  const [effectiveFor, setEffectiveFor] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const r = await api.get("/api/xdr/rbac/users");
        setUsers(r?.data?.data?.users || []); setErr(null);
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.message || "list failed");
        setUsers([]);
      }
    })();
  }, [refresh]);

  const toggleEnabled = async (u) => {
    try {
      const r = await api.put(`/api/xdr/rbac/users/${u.id}`,
                                          { enabled: !u.enabled });
      setLastAudit(r?.data?.audit_ref); onRefresh();
    } catch (e) { setErr(e?.response?.data?.detail || e?.message); }
  };
  const removeUser = async (u) => {
    if (!window.confirm(`Remove user ${u.email}?`)) return;
    try {
      const r = await api.delete(`/api/xdr/rbac/users/${u.id}`);
      setLastAudit(r?.data?.audit_ref); onRefresh();
    } catch (e) { setErr(e?.response?.data?.detail || e?.message); }
  };

  return (
    <div data-testid="rbac-tab-users">
      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
        <button className="btn" data-testid="rbac-user-add-btn"
                     onClick={() => setAddOpen(true)}
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <Plus size={11} /> Invite user
        </button>
        <button className="btn ghost" onClick={onRefresh}
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <RefreshCcw size={11} /> Refresh
        </button>
        <span style={{ flex: 1 }} />
        {lastAudit && (
          <span data-testid="rbac-user-last-audit"
                    style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--faint)" }}>
            last audit: {lastAudit}
          </span>
        )}
      </div>
      {err && <div style={{ color: "#f87171", fontSize: 11 }}>{err}</div>}
      <div data-testid="rbac-user-rows"
                style={{ border: "1px solid var(--border)", borderRadius: 3,
                                overflow: "hidden" }}>
        <div className="mono" style={rowHeadUsers}>
          <div>Email</div><div>Display</div><div>Roles</div>
          <div>Status</div><div>Last login</div><div>Actions</div>
        </div>
        {users.length === 0 && (
          <div data-testid="rbac-users-empty"
                   style={{ padding: 10, fontSize: 11, color: "var(--faint)",
                                   fontFamily: "var(--mono)" }}>
            NO USERS PROVISIONED FOR THIS TENANT YET
          </div>
        )}
        {users.map((u) => (
          <div key={u.id} className="mono" style={rowBodyUsers}
                   data-testid={`rbac-user-row-${u.id}`}>
            <div style={{ color: "var(--cyan)" }}>{u.email}</div>
            <div>{u.display_name}</div>
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {(u.role_names || []).map((n) => (
                <Badge key={n} label={n} color="var(--cyan)" />
              ))}
              {(u.role_names || []).length === 0 && (
                <span style={{ color: "var(--faint)" }}>—</span>
              )}
            </div>
            <div>{u.enabled
              ? <Badge label="ENABLED" color="var(--mint)" />
              : <Badge label="DISABLED" color="#f87171" />}</div>
            <div style={{ color: "var(--faint)", fontSize: 10 }}>
              {(u.last_login || "").slice(0, 19) || "never"}
            </div>
            <div style={{ display: "flex", gap: 4 }}>
              <button className="btn ghost" title="Effective permissions"
                           data-testid={`rbac-user-effective-${u.id}`}
                           onClick={() => setEffectiveFor(u)}
                           style={iconBtn}><ChevronRight size={11} /></button>
              <button className="btn ghost" title="Assign role"
                           data-testid={`rbac-user-assign-${u.id}`}
                           onClick={() => setAssignFor(u)}
                           style={iconBtn}><Shield size={11} /></button>
              <button className="btn ghost"
                           title={u.enabled ? "Disable" : "Enable"}
                           data-testid={`rbac-user-toggle-${u.id}`}
                           onClick={() => toggleEnabled(u)}
                           style={iconBtn}>
                {u.enabled ? <PowerOff size={11} /> : <Power size={11} />}
              </button>
              <button className="btn ghost" title="Delete"
                           data-testid={`rbac-user-delete-${u.id}`}
                           onClick={() => removeUser(u)}
                           style={{ ...iconBtn, color: "#f87171" }}>
                <Trash2 size={11} />
              </button>
            </div>
          </div>
        ))}
      </div>

      {addOpen && (
        <AddUserModal roles={Object.values(rolesById)}
                                onClose={() => setAddOpen(false)}
                                onCreated={(res) => {
                                  setLastAudit(res?.audit_ref); onRefresh();
                                }} />
      )}
      {assignFor && (
        <AssignRoleModal user={assignFor}
                                       roles={Object.values(rolesById)}
                                       onClose={() => setAssignFor(null)}
                                       onAssigned={(res) => {
                                         setLastAudit(res?.audit_ref); onRefresh();
                                       }} />
      )}
      {effectiveFor && (
        <EffectiveModal user={effectiveFor}
                                    onClose={() => setEffectiveFor(null)} />
      )}
    </div>
  );
}


function AddUserModal({ roles, onClose, onCreated }) {
  const [f, setF] = useState({ email: "", display_name: "", initial_roles: [] });
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState(null);
  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await api.post("/api/xdr/rbac/users", f);
      onCreated?.(r?.data); onClose();
    } catch (e) {
      setErr(e?.response?.data?.detail?.reason
                 || e?.response?.data?.detail || e?.message || "create failed");
    } finally { setBusy(false); }
  };
  const toggleRole = (name) => setF((s) => ({
    ...s, initial_roles: s.initial_roles.includes(name)
      ? s.initial_roles.filter((x) => x !== name)
      : [...s.initial_roles, name],
  }));
  return (
    <ModalShell title="INVITE USER" onClose={onClose}>
      <label style={lbl}>Email
        <input value={f.email} data-testid="rbac-user-add-email"
                   onChange={(e) => setF({ ...f, email: e.target.value })}
                   style={inp} />
      </label>
      <label style={lbl}>Display name
        <input value={f.display_name} data-testid="rbac-user-add-display"
                   onChange={(e) => setF({ ...f, display_name: e.target.value })}
                   style={inp} />
      </label>
      <div style={lbl}>Initial roles
        <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 4 }}>
          {roles.map((r) => (
            <button key={r.name} type="button"
                         data-testid={`rbac-user-add-role-${r.name}`}
                         onClick={() => toggleRole(r.name)}
                         className={f.initial_roles.includes(r.name) ? "btn" : "btn ghost"}
                         style={{ padding: "2px 6px", fontSize: 10 }}>
              {r.display_name}
            </button>
          ))}
        </div>
      </div>
      {err && <div style={{ color: "#f87171", fontSize: 11 }}
                              data-testid="rbac-user-add-error">{err}</div>}
      <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
        <span style={{ flex: 1 }} />
        <button className="btn ghost" onClick={onClose}
                     style={{ padding: "3px 10px", fontSize: 11 }}>Cancel</button>
        <button className="btn" disabled={busy || !f.email}
                     data-testid="rbac-user-add-submit"
                     onClick={submit}
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <Plus size={11} /> {busy ? "Inviting…" : "Invite"}
        </button>
      </div>
    </ModalShell>
  );
}


function AssignRoleModal({ user, roles, onClose, onAssigned }) {
  const [selected, setSelected] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState(null);
  const submit = async () => {
    if (!selected) return;
    setBusy(true); setErr(null);
    try {
      const r = await api.post(`/api/xdr/rbac/users/${user.id}/roles`,
                                          { role_id: selected, scope: {} });
      onAssigned?.(r?.data); onClose();
    } catch (e) {
      setErr(e?.response?.data?.detail?.reason
                 || e?.response?.data?.detail || e?.message || "assign failed");
    } finally { setBusy(false); }
  };
  return (
    <ModalShell title={`ASSIGN ROLE · ${user.email}`} onClose={onClose}>
      <label style={lbl}>Role
        <select value={selected}
                    data-testid="rbac-assign-role-select"
                    onChange={(e) => setSelected(e.target.value)}
                    style={inp}>
          <option value="">— select role —</option>
          {roles.map((r) => (
            <option key={r.id} value={r.id}>
              {r.display_name} ({r.name})
            </option>
          ))}
        </select>
      </label>
      {err && <div style={{ color: "#f87171", fontSize: 11 }}>{err}</div>}
      <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
        <span style={{ flex: 1 }} />
        <button className="btn ghost" onClick={onClose}
                     style={{ padding: "3px 10px", fontSize: 11 }}>Cancel</button>
        <button className="btn" disabled={busy || !selected}
                     data-testid="rbac-assign-submit"
                     onClick={submit}
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <Shield size={11} /> {busy ? "Assigning…" : "Assign"}
        </button>
      </div>
    </ModalShell>
  );
}


function EffectiveModal({ user, onClose }) {
  const [eff, setEff] = useState(null);
  useEffect(() => {
    (async () => {
      try {
        const r = await api.get(`/api/xdr/rbac/users/${user.id}/effective`);
        setEff(r?.data?.data);
      } catch { setEff({ error: true }); }
    })();
  }, [user]);
  return (
    <ModalShell title={`EFFECTIVE ACCESS · ${user.email}`} onClose={onClose} wide>
      {!eff && <div style={{ fontSize: 11, color: "var(--faint)" }}>Loading…</div>}
      {eff?.error && <div style={{ color: "#f87171", fontSize: 11 }}>load failed</div>}
      {eff && !eff.error && (
        <>
          <div style={{ fontSize: 11, marginBottom: 8, color: "var(--text-dim)" }}>
            <b>{eff.count}</b> permission(s) via <b>{(eff.roles || []).length}</b> role(s):
            {" "}
            {(eff.roles || []).map((r) => (
              <Badge key={r.id} label={r.name} color="var(--cyan)" />
            ))}
          </div>
          <div className="mono"
                    data-testid="rbac-effective-perms"
                    style={{ maxHeight: 320, overflow: "auto",
                                    background: "var(--panel2)",
                                    border: "1px solid var(--border)",
                                    borderRadius: 3, padding: 8,
                                    fontSize: 10.5, color: "var(--text-dim)" }}>
            {(eff.permissions || []).map((p) => (
              <div key={p}>{p}</div>
            ))}
          </div>
        </>
      )}
    </ModalShell>
  );
}


// ── Roles tab ────────────────────────────────────────────────────
function RolesTab({ roles, refresh, onRefresh }) {
  const [addOpen, setAddOpen] = useState(false);
  const [lastAudit, setLastAudit] = useState(null);
  const [err, setErr] = useState(null);

  const clone = async (r) => {
    try {
      const res = await api.post(`/api/xdr/rbac/roles/${r.id}/clone`);
      setLastAudit(res?.data?.audit_ref); onRefresh();
    } catch (e) { setErr(e?.response?.data?.detail || e?.message); }
  };
  const remove = async (r) => {
    if (r.type === "SYSTEM") return;
    if (!window.confirm(`Delete role ${r.name}?`)) return;
    try {
      const res = await api.delete(`/api/xdr/rbac/roles/${r.id}`);
      setLastAudit(res?.data?.audit_ref); onRefresh();
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message);
    }
  };

  return (
    <div data-testid="rbac-tab-roles">
      <div style={{ display: "flex", gap: 8, alignItems: "center",
                       marginBottom: 8 }}>
        <button className="btn" onClick={() => setAddOpen(true)}
                     data-testid="rbac-role-add-btn"
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <Plus size={11} /> Create custom role
        </button>
        <button className="btn ghost" onClick={onRefresh}
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <RefreshCcw size={11} /> Refresh
        </button>
        <span style={{ flex: 1 }} />
        {lastAudit && (
          <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                                color: "var(--faint)" }}
                    data-testid="rbac-role-last-audit">
            last audit: {lastAudit}
          </span>
        )}
      </div>
      {err && <div style={{ color: "#f87171", fontSize: 11 }}
                              data-testid="rbac-role-error">{err}</div>}
      <div data-testid="rbac-role-rows"
                style={{ border: "1px solid var(--border)", borderRadius: 3,
                                overflow: "hidden" }}>
        <div className="mono" style={rowHeadRoles}>
          <div>Name</div><div>Display</div><div>Tier</div>
          <div>Type</div><div>Perms</div><div>Actions</div>
        </div>
        {roles.map((r) => (
          <div key={r.id} className="mono" style={rowBodyRoles}
                   data-testid={`rbac-role-row-${r.name}`}>
            <div style={{ color: "var(--cyan)" }}>{r.name}</div>
            <div>{r.display_name}
              {r.description && <div style={{ fontSize: 10,
                                                                    color: "var(--faint)" }}>
                {r.description}
              </div>}
            </div>
            <div>{r.tier || "—"}</div>
            <div><Badge label={r.type}
                                    color={r.type === "SYSTEM" ? "var(--faint)" : "var(--mint)"} /></div>
            <div>{(r.permissions || []).length}</div>
            <div style={{ display: "flex", gap: 4 }}>
              <button className="btn ghost" title="Clone"
                           data-testid={`rbac-role-clone-${r.name}`}
                           onClick={() => clone(r)}
                           style={iconBtn}><Copy size={11} /></button>
              {r.type !== "SYSTEM" && (
                <button className="btn ghost" title="Delete"
                             data-testid={`rbac-role-delete-${r.name}`}
                             onClick={() => remove(r)}
                             style={{ ...iconBtn, color: "#f87171" }}>
                  <Trash2 size={11} />
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      {addOpen && (
        <AddRoleModal onClose={() => setAddOpen(false)}
                                onCreated={(res) => {
                                  setLastAudit(res?.audit_ref); onRefresh();
                                }} />
      )}
    </div>
  );
}


function AddRoleModal({ onClose, onCreated }) {
  const [perms, setPerms] = useState(null);
  const [f, setF] = useState({ name: "", display_name: "",
                                                     description: "", tier: "L2",
                                                     permissions: [] });
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState(null);
  useEffect(() => {
    (async () => {
      try {
        const r = await api.get("/api/xdr/rbac/permissions");
        setPerms(r?.data?.data);
      } catch { setPerms({ error: true }); }
    })();
  }, []);
  const togglePerm = (p) => setF((s) => ({
    ...s, permissions: s.permissions.includes(p)
      ? s.permissions.filter((x) => x !== p)
      : [...s.permissions, p],
  }));
  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await api.post("/api/xdr/rbac/roles", f);
      onCreated?.(r?.data); onClose();
    } catch (e) {
      setErr(e?.response?.data?.detail?.reason
                 || e?.response?.data?.detail || e?.message || "create failed");
    } finally { setBusy(false); }
  };
  return (
    <ModalShell title="CREATE CUSTOM ROLE" onClose={onClose} wide>
      <label style={lbl}>Name (lowercase · unique)
        <input value={f.name} data-testid="rbac-role-add-name"
                   onChange={(e) => setF({ ...f, name: e.target.value })}
                   style={inp} placeholder="detection_engineer" />
      </label>
      <label style={lbl}>Display name
        <input value={f.display_name} data-testid="rbac-role-add-display"
                   onChange={(e) => setF({ ...f, display_name: e.target.value })}
                   style={inp} placeholder="Detection Engineer" />
      </label>
      <label style={lbl}>Description
        <input value={f.description}
                   onChange={(e) => setF({ ...f, description: e.target.value })}
                   style={inp} />
      </label>
      <label style={lbl}>SOC tier
        <select value={f.tier}
                    onChange={(e) => setF({ ...f, tier: e.target.value })}
                    style={inp}>
          {["L1", "L2", "L3", "SPECIALIST", "MANAGEMENT",
              "PLATFORM", "AUDIT"].map((t) => <option key={t}>{t}</option>)}
        </select>
      </label>
      <div style={lbl}>Permissions ({f.permissions.length} selected)</div>
      <div data-testid="rbac-role-add-perms"
                style={{ maxHeight: 260, overflow: "auto",
                                border: "1px solid var(--border)", borderRadius: 3,
                                background: "var(--panel2)", padding: 6 }}>
        {perms && !perms.error && Object.entries(perms.groups).map(([g, res]) => (
          <div key={g} style={{ marginBottom: 8 }}>
            <div className="mono" style={{ fontSize: 10,
                                                          color: "var(--faint)",
                                                          textTransform: "uppercase",
                                                          marginBottom: 3 }}>
              {g}
            </div>
            {res.map((r) => (
              <div key={r.resource} style={{ marginBottom: 3 }}>
                <span className="mono" style={{ color: "var(--cyan)",
                                                                      fontSize: 10.5 }}>
                  {r.resource}
                </span>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 3,
                                    marginTop: 2 }}>
                  {r.permissions.map((p) => (
                    <button key={p.key} type="button"
                                 data-testid={`rbac-role-add-perm-${p.key}`}
                                 onClick={() => togglePerm(p.key)}
                                 className={f.permissions.includes(p.key) ? "btn" : "btn ghost"}
                                 style={{ padding: "1px 5px", fontSize: 9.5 }}>
                      {p.action}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>
      {err && <div style={{ marginTop: 6, color: "#f87171", fontSize: 11 }}
                              data-testid="rbac-role-add-error">{err}</div>}
      <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
        <span style={{ flex: 1 }} />
        <button className="btn ghost" onClick={onClose}
                     style={{ padding: "3px 10px", fontSize: 11 }}>Cancel</button>
        <button className="btn" disabled={busy || !f.name || !f.display_name}
                     data-testid="rbac-role-add-submit"
                     onClick={submit}
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <Plus size={11} /> {busy ? "Creating…" : "Create role"}
        </button>
      </div>
    </ModalShell>
  );
}


// ── Permissions catalog tab ──────────────────────────────────────
function PermissionsTab() {
  const [d, setD] = useState(null);
  useEffect(() => {
    (async () => {
      try {
        const r = await api.get("/api/xdr/rbac/permissions");
        setD(r?.data?.data);
      } catch { setD({ error: true }); }
    })();
  }, []);
  if (!d) return <div style={{ fontSize: 11, color: "var(--faint)" }}>Loading…</div>;
  if (d.error) return <div style={{ color: "#f87171", fontSize: 11 }}>load failed</div>;
  return (
    <div data-testid="rbac-tab-permissions">
      <div style={{ fontSize: 11, color: "var(--faint)", marginBottom: 6 }}>
        {d.all.length} canonical permissions · {Object.keys(d.resources).length} resources
      </div>
      {Object.entries(d.groups).map(([g, res]) => (
        <div key={g} style={{ marginBottom: 12 }}
                  data-testid={`rbac-perm-group-${g}`}>
          <div className="mono" style={{ fontSize: 10, color: "var(--cyan)",
                                                        textTransform: "uppercase",
                                                        marginBottom: 4 }}>
            {g}
          </div>
          {res.map((r) => (
            <div key={r.resource} style={{ display: "flex", gap: 6,
                                                            padding: "3px 0",
                                                            borderTop: "1px solid var(--border)",
                                                            alignItems: "center" }}>
              <span className="mono" style={{ width: 180,
                                                                    color: "var(--text)",
                                                                    fontSize: 11 }}>
                {r.resource}
              </span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                {r.permissions.map((p) => (
                  <Badge key={p.key} label={p.action} color="var(--faint)" />
                ))}
              </div>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}


// ── Simulator tab ─────────────────────────────────────────────────
function SimulatorTab({ users, permissionsCatalog }) {
  const [form, setForm] = useState({ user: "", permission: "" });
  const [res, setRes]   = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState(null);
  const submit = async () => {
    setBusy(true); setErr(null); setRes(null);
    try {
      const r = await api.post("/api/xdr/rbac/simulate", {
        user_id_or_email: form.user, permission: form.permission,
      });
      setRes(r?.data?.data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "simulate failed");
    } finally { setBusy(false); }
  };
  return (
    <div data-testid="rbac-tab-simulator">
      <div style={{ fontSize: 10.5, color: "var(--faint)", marginBottom: 8,
                       fontFamily: "var(--mono)" }}>
        Simulate whether a user WOULD be allowed a specific permission.
        Backend never mutates state; every simulation is audit-logged.
      </div>
      <div style={{ display: "grid", gap: 6, maxWidth: 480 }}>
        <label style={lbl}>User
          <select value={form.user} data-testid="rbac-sim-user"
                      onChange={(e) => setForm({ ...form, user: e.target.value })}
                      style={inp}>
            <option value="">— select —</option>
            {users.map((u) => (
              <option key={u.id} value={u.email}>{u.email}</option>
            ))}
          </select>
        </label>
        <label style={lbl}>Permission
          <select value={form.permission} data-testid="rbac-sim-permission"
                      onChange={(e) => setForm({ ...form, permission: e.target.value })}
                      style={inp}>
            <option value="">— select —</option>
            {(permissionsCatalog?.all || []).map((p) => (
              <option key={p}>{p}</option>
            ))}
          </select>
        </label>
        <div>
          <button className="btn" onClick={submit}
                       disabled={busy || !form.user || !form.permission}
                       data-testid="rbac-sim-run"
                       style={{ padding: "3px 10px", fontSize: 11 }}>
            <PlayCircle size={11} /> {busy ? "Simulating…" : "Test access"}
          </button>
        </div>
      </div>
      {err && <div style={{ color: "#f87171", fontSize: 11, marginTop: 8 }}>{err}</div>}
      {res && (
        <div data-testid="rbac-sim-result" style={{ marginTop: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8,
                            padding: 10, borderRadius: 3,
                            border: `1px solid ${res.decision === "ALLOW"
                              ? "var(--mint)" : "#f87171"}`,
                            background: "var(--panel2)" }}>
            {res.decision === "ALLOW"
              ? <CheckCircle2 size={14} style={{ color: "var(--mint)" }} />
              : <XCircle       size={14} style={{ color: "#f87171" }} />}
            <b style={{ color: res.decision === "ALLOW"
                                ? "var(--mint)" : "#f87171",
                              fontFamily: "var(--mono)" }}>
              {res.decision}
            </b>
            <span style={{ color: "var(--faint)", fontSize: 11,
                              fontFamily: "var(--mono)" }}>
              · {res.reason}
            </span>
          </div>
          <div className="mono" style={{ marginTop: 8, fontSize: 10.5,
                                                            color: "var(--text-dim)" }}>
            <div>target user: <b>{res.target?.email}</b></div>
            <div>permission: <b>{res.permission}</b></div>
            {res.matched_role &&
              <div>matched role: <b>{res.matched_role}</b></div>}
            <div>effective perms count: {res.effective_permissions_count}</div>
          </div>
        </div>
      )}
    </div>
  );
}


// ── Modal shell ──────────────────────────────────────────────────
function ModalShell({ title, onClose, wide, children }) {
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.55)",
                     display: "flex", alignItems: "center",
                     justifyContent: "center", zIndex: 60 }}>
      <div className="panel" style={{ padding: 18,
                                                          width: wide ? 640 : 460,
                                                          maxHeight: "82vh", overflow: "auto" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                          marginBottom: 10 }}>
          <Shield size={14} style={{ color: "var(--mint)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{title}</b>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose}
                       style={{ padding: "2px 6px", fontSize: 11 }}>
            <X size={11} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}


// ── Main body ────────────────────────────────────────────────────
export default function UsersRolesBody() {
  const [tab, setTab] = useState("users");
  const [tick, setTick] = useState(0);
  const [roles, setRoles] = useState([]);
  const [users, setUsers] = useState([]);
  const [perms, setPerms] = useState(null);
  const rolesById = useMemo(
    () => Object.fromEntries(roles.map((r) => [r.id, r])), [roles]);

  useEffect(() => {
    (async () => {
      try {
        const [rr, ru, rp] = await Promise.all([
          api.get("/api/xdr/rbac/roles"),
          api.get("/api/xdr/rbac/users"),
          api.get("/api/xdr/rbac/permissions"),
        ]);
        setRoles(rr?.data?.data?.roles || []);
        setUsers(ru?.data?.data?.users || []);
        setPerms(rp?.data?.data);
      } catch { /* honest empty state */ }
    })();
  }, [tick]);

  const TABS = [
    { key: "users",       label: "Users",       icon: Users },
    { key: "roles",       label: "Roles",       icon: Shield },
    { key: "permissions", label: "Permissions", icon: KeyRound },
    { key: "simulator",   label: "Simulator",   icon: PlayCircle },
  ];

  return (
    <div data-testid="xdr-users-roles-body">
      <div style={{ display: "flex", gap: 4, marginBottom: 10,
                       borderBottom: "1px solid var(--border)" }}>
        {TABS.map((t) => (
          <button key={t.key} onClick={() => setTab(t.key)}
                        data-testid={`rbac-tab-${t.key}`}
                        style={{ padding: "6px 12px",
                                        background: "transparent",
                                        border: "none",
                                        borderBottom: tab === t.key
                                          ? "2px solid var(--mint)" : "2px solid transparent",
                                        color: tab === t.key ? "var(--text)" : "var(--faint)",
                                        cursor: "pointer",
                                        fontFamily: "var(--mono)", fontSize: 11,
                                        textTransform: "uppercase",
                                        letterSpacing: ".4px" }}>
            <t.icon size={11} style={{ verticalAlign: "middle",
                                                        marginRight: 4 }} />
            {t.label}
          </button>
        ))}
      </div>

      {tab === "users" && <UsersTab rolesById={rolesById}
                                                              refresh={tick}
                                                              onRefresh={() => setTick((n) => n + 1)} />}
      {tab === "roles" && <RolesTab roles={roles}
                                                              refresh={tick}
                                                              onRefresh={() => setTick((n) => n + 1)} />}
      {tab === "permissions" && <PermissionsTab />}
      {tab === "simulator"   && <SimulatorTab users={users}
                                                                        permissionsCatalog={perms} />}
    </div>
  );
}


// ── Styles ────────────────────────────────────────────────────────
const inp = {
  display: "block", width: "100%", marginTop: 3, padding: "4px 8px",
  fontSize: 11, border: "1px solid var(--border)", borderRadius: 3,
  background: "var(--panel2)", color: "var(--text)",
  fontFamily: "var(--mono)",
};
const lbl = { color: "var(--faint)", fontSize: 11, marginBottom: 4 };
const iconBtn = { padding: "2px 6px", fontSize: 10 };
const rowHeadUsers = {
  display: "grid",
  gridTemplateColumns: "1.4fr 1fr 1.4fr 0.7fr 0.8fr 0.9fr",
  gap: 6, padding: "4px 8px", background: "var(--panel2)",
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
};
const rowBodyUsers = {
  display: "grid",
  gridTemplateColumns: "1.4fr 1fr 1.4fr 0.7fr 0.8fr 0.9fr",
  gap: 6, padding: "4px 8px", fontSize: 11,
  color: "var(--text-dim)", borderTop: "1px solid var(--border)",
  alignItems: "center",
};
const rowHeadRoles = {
  display: "grid",
  gridTemplateColumns: "1.4fr 1.8fr 0.8fr 0.7fr 0.5fr 0.7fr",
  gap: 6, padding: "4px 8px", background: "var(--panel2)",
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
};
const rowBodyRoles = {
  display: "grid",
  gridTemplateColumns: "1.4fr 1.8fr 0.8fr 0.7fr 0.5fr 0.7fr",
  gap: 6, padding: "6px 8px", fontSize: 11,
  color: "var(--text-dim)", borderTop: "1px solid var(--border)",
  alignItems: "center",
};
