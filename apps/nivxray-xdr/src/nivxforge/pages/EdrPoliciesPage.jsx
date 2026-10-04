/**
 * GATE 5 · Policies — the policy authority console.
 *
 * The five facts are never collapsed here. A policy that the platform
 * handed to a computer is rendered DELIVERED, not protected; only an
 * authenticated connector acknowledgement of the exact version and
 * config digest renders APPLIED, and a second independent check-in
 * renders VERIFIED. Every state token and basis sentence is the
 * server's.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { CheckCircle2, Layers, Plus, RefreshCw, Users } from "lucide-react";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { assignPolicy, createGroup, createPolicy, createPolicyVersion,
         getPolicy, getPolicyDeployment, listGroups, listPolicies }
  from "@/nivxforge/managementApi";
import { Ago, Kpi, NA, OpsTable, Refusal, Skeleton, StateChip }
  from "@/nivxforge/components/OpsPrimitives";
import { apiErrorText } from "@/xdr/nx/apiError";
import "@/nivxforge/nvf-ops.css";

const CONFIRMED = ["APPLIED", "VERIFIED"];

function NewPolicyForm({ onDone, onCancel }) {
  const [name, setName] = useState("");
  const [os, setOs] = useState("WINDOWS");
  const [interval, setInterval] = useState(60);
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const out = await createPolicy({
        name, os, description: description || null,
        config: { mode: "DETECT_ONLY", prevention_enabled: false,
                  report_interval_seconds: Number(interval),
                  heartbeat_interval_seconds: Number(interval),
                  collect_process_events: true },
      });
      onDone(out);
    } catch (e) {
      setErr(apiErrorText(e, "policy refused"));
    } finally { setBusy(false); }
  };

  return (
    <div className="panel" style={{ padding: "11px 13px", marginBottom: 14 }}
         data-testid="edr-policy-form">
      <div className="section-title" style={{ marginBottom: 8 }}>
        New policy · version 1
      </div>
      <div className="kv">
        <span className="k">Name</span>
        <span className="v">
          <input value={name} onChange={(e) => setName(e.target.value)}
                 placeholder="Windows Servers · Detect Only"
                 data-testid="edr-policy-name" />
        </span>
        <span className="k">Operating system</span>
        <span className="v">
          <select value={os} onChange={(e) => setOs(e.target.value)}
                  data-testid="edr-policy-os">
            <option value="WINDOWS">WINDOWS</option>
            <option value="LINUX">LINUX</option>
            <option value="MACOS">MACOS</option>
          </select>
        </span>
        <span className="k">Report cadence (s)</span>
        <span className="v">
          <input type="number" min={10} max={3600} value={interval}
                 onChange={(e) => setInterval(e.target.value)}
                 data-testid="edr-policy-interval" />
        </span>
        <span className="k">Description</span>
        <span className="v">
          <input value={description}
                 onChange={(e) => setDescription(e.target.value)}
                 data-testid="edr-policy-description" />
        </span>
      </div>
      <div className="basis" style={{ marginTop: 8 }}>
        Mode is DETECT_ONLY: the released connector collects and reports and
        enforces nothing, so a PREVENT policy would be recorded as requested
        and reported as NOT ENFORCED. Prevention is not offered here while
        that remains true.
      </div>
      {err ? <Refusal title="Policy refused" body={err}
                      testid="edr-policy-form-error" /> : null}
      <div className="ops-actions" style={{ marginTop: 10 }}>
        <button className="btn mint" disabled={busy || name.trim().length < 2}
                onClick={submit} data-testid="edr-policy-create">
          {busy ? "Creating…" : "Create policy"}
        </button>
        <button className="btn" onClick={onCancel}
                data-testid="edr-policy-cancel">Cancel</button>
      </div>
    </div>
  );
}

function NewGroupForm({ policies, onDone, onCancel }) {
  const [name, setName] = useState("");
  const [policyId, setPolicyId] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      onDone(await createGroup({ name, description: null,
                                 policy_id: policyId || null }));
    } catch (e) { setErr(apiErrorText(e, "group refused")); }
    finally { setBusy(false); }
  };

  return (
    <div className="panel" style={{ padding: "11px 13px", marginBottom: 14 }}
         data-testid="edr-group-form">
      <div className="section-title" style={{ marginBottom: 8 }}>New group</div>
      <div className="kv">
        <span className="k">Name</span>
        <span className="v">
          <input value={name} onChange={(e) => setName(e.target.value)}
                 placeholder="Windows Servers"
                 data-testid="edr-group-name" />
        </span>
        <span className="k">Policy</span>
        <span className="v">
          <select value={policyId} onChange={(e) => setPolicyId(e.target.value)}
                  data-testid="edr-group-policy">
            <option value="">None — computers read POLICY UNASSIGNED</option>
            {policies.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>))}
          </select>
        </span>
      </div>
      {err ? <Refusal title="Group refused" body={err}
                      testid="edr-group-form-error" /> : null}
      <div className="ops-actions" style={{ marginTop: 10 }}>
        <button className="btn mint" disabled={busy || name.trim().length < 2}
                onClick={submit} data-testid="edr-group-create">
          {busy ? "Creating…" : "Create group"}
        </button>
        <button className="btn" onClick={onCancel}
                data-testid="edr-group-cancel">Cancel</button>
      </div>
    </div>
  );
}

function PolicyDetail({ policyId, groups, onChanged }) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [groupId, setGroupId] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    setData(null); setErr(null);
    getPolicy(policyId).then(setData)
      .catch((e) => setErr(apiErrorText(e, "policy unavailable")));
  }, [policyId]);

  useEffect(load, [load]);

  const assign = async () => {
    setBusy(true);
    try {
      await assignPolicy(policyId, { scope_type: "GROUP", scope_id: groupId });
      load(); onChanged();
    } catch (e) { setErr(apiErrorText(e, "assignment refused")); }
    finally { setBusy(false); }
  };

  const newVersion = async () => {
    const current = data?.versions?.[0]?.config;
    if (!current) return;
    setBusy(true);
    try {
      await createPolicyVersion(policyId, {
        config: { ...current,
                  report_interval_seconds:
                    Math.min(3600, (current.report_interval_seconds || 60) + 30) },
        notes: "cadence increased from the console",
      });
      load(); onChanged();
    } catch (e) { setErr(apiErrorText(e, "version refused")); }
    finally { setBusy(false); }
  };

  if (err) {
    return <Refusal title="Policy unavailable" body={err}
                    testid="edr-policy-detail-error" />;
  }
  if (!data) return <Skeleton rows={6} testid="edr-policy-detail-loading" />;

  const current = data.versions.find(
    (v) => v.version === data.policy.current_version);
  const rows = data.endpoints || [];
  const confirmed = rows.filter((r) => CONFIRMED.includes(r.state)).length;

  return (
    <div data-testid="edr-policy-detail">
      <div className="ops-head" style={{ marginBottom: 10 }}>
        <div>
          <span className="eyebrow">Policy</span>
          <h1 className="ttl" style={{ fontSize: 20 }}
              data-testid="edr-policy-detail-name">{data.policy.name}</h1>
          <div className="sub mono">
            {data.policy.id} · version {data.policy.current_version}
            {data.policy.is_default ? " · platform default" : ""}
          </div>
        </div>
        <div className="spacer" />
        <div className="ops-actions">
          <select value={groupId} onChange={(e) => setGroupId(e.target.value)}
                  data-testid="edr-policy-assign-group">
            <option value="">Assign to group…</option>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name} ({g.endpoint_count})
              </option>))}
          </select>
          <button className="btn mint" disabled={!groupId || busy}
                  onClick={assign} data-testid="edr-policy-assign">
            Assign
          </button>
          <button className="btn" disabled={busy} onClick={newVersion}
                  data-testid="edr-policy-new-version">
            <Plus size={11} /> New version
          </button>
        </div>
      </div>

      <div className="kpi-rail" data-testid="edr-policy-kpis">
        <Kpi label="Endpoints assigned" value={rows.length}
             testid="edr-policy-kpi-assigned" />
        <Kpi label="Confirmed by endpoint" value={confirmed}
             tone={confirmed ? "mint" : undefined}
             title="APPLIED or VERIFIED — the endpoint acknowledged the exact
                    config digest"
             testid="edr-policy-kpi-confirmed" />
        <Kpi label="Not confirmed" value={rows.length - confirmed}
             tone={rows.length - confirmed ? "amber" : undefined}
             testid="edr-policy-kpi-unconfirmed" />
        <Kpi label="Versions" value={data.versions.length}
             testid="edr-policy-kpi-versions" />
      </div>

      <div className="panel" style={{ padding: "11px 13px", marginBottom: 14 }}
           data-testid="edr-policy-config">
        <div className="section-title" style={{ marginBottom: 7 }}>
          Version {current?.version} configuration
          <span className="chip mono" style={{ marginLeft: 8 }}>
            {current?.config_digest}
          </span>
        </div>
        <div className="kv">
          {Object.entries(current?.config || {}).map(([k, v]) => (
            <React.Fragment key={k}>
              <span className="k">{k.replace(/_/g, " ")}</span>
              <span className="v mono">
                {Array.isArray(v)
                  ? (v.length ? v.join(", ") : <NA label="NONE" />)
                  : (v === null ? <NA /> : String(v))}
              </span>
            </React.Fragment>))}
        </div>
        {(data.not_enforced || []).length ? (
          <div style={{ marginTop: 9 }} data-testid="edr-policy-not-enforced">
            <div className="section-title" style={{ marginBottom: 5 }}>
              Requested but NOT ENFORCED by the released connector
            </div>
            {data.not_enforced.map((n) => (
              <div className="ci-row" key={n.setting}>
                <StateChip token={n.state} tone="warn" />
                <span className="basis">{n.setting} — {n.reason}</span>
              </div>))}
          </div>
        ) : null}
      </div>

      <div className="section-title" style={{ marginBottom: 6 }}>
        Delivery truth per computer
      </div>
      <OpsTable
        testid="edr-policy-deployment-table"
        rows={rows}
        rowKey={(r) => r.endpoint_id}
        columns={[
          { key: "hostname", label: "Computer", width: 190,
            render: (r) => r.hostname
              || <span className="mono">{r.endpoint_id}</span> },
          { key: "group", label: "Group", width: 150,
            render: (r) => r.group || <NA label="UNASSIGNED" /> },
          { key: "state", label: "Lifecycle state", width: 160,
            render: (r) => (
              <StateChip token={r.state} title={r.basis}
                         tone={CONFIRMED.includes(r.state) ? "ok"
                           : r.state === "FAILED" ? "bad"
                           : r.state === "OUT_OF_SYNC" ? "warn" : undefined}
                         testid={`edr-policy-state-${r.endpoint_id}`} />) },
          { key: "assigned_version", label: "Assigned", width: 78,
            render: (r) => <span className="mono">
              {r.assigned_version ?? <NA />}</span> },
          { key: "applied_version", label: "Applied", width: 78,
            render: (r) => (r.applied_version != null
              ? <span className="mono">{r.applied_version}</span>
              : <NA label="NOT CONFIRMED" />) },
          { key: "delivered_at", label: "Delivered", width: 96,
            render: (r) => (r.delivered_at ? <Ago iso={r.delivered_at} />
              : <NA label="NOT DELIVERED" />) },
          { key: "verified_at", label: "Verified", width: 96,
            render: (r) => (r.verified_at ? <Ago iso={r.verified_at} />
              : <NA label="NOT VERIFIED" />) },
          { key: "basis", label: "Basis", cls: "basis",
            render: (r) => <span title={r.basis}>{r.basis}</span> },
        ]} />
      {!rows.length ? (
        <div className="basis" data-testid="edr-policy-no-endpoints">
          No computer resolves to this policy yet. Assign it to a group, or
          deploy a connector into a group that carries it.
        </div>
      ) : null}
    </div>
  );
}

export default function EdrPoliciesPage() {
  const [policies, setPolicies] = useState(null);
  const [groups, setGroups] = useState([]);
  const [deployment, setDeployment] = useState(null);
  const [selected, setSelected] = useState(null);
  const [form, setForm] = useState(null);
  const [err, setErr] = useState(null);

  const load = useCallback(() => {
    setErr(null);
    Promise.all([listPolicies(), listGroups(), getPolicyDeployment()])
      .then(([p, g, d]) => {
        setPolicies(p);
        setGroups(g.groups || []);
        setDeployment(d);
        setSelected((cur) => cur || (p.policies || [])[0]?.id || null);
      })
      .catch((e) => setErr(apiErrorText(e, "policy authority unavailable")));
  }, []);

  useEffect(load, [load]);

  const dist = deployment?.state_distribution || {};
  const rows = policies?.policies || [];

  const columns = useMemo(() => [
    { key: "name", label: "Policy",
      render: (r) => (
        <span>
          {r.name}
          {r.is_default
            ? <span className="chip" style={{ marginLeft: 6 }}>DEFAULT</span>
            : null}
        </span>) },
    { key: "os", label: "OS", width: 80 },
    { key: "current_version", label: "Version", width: 70, cls: "mono" },
    { key: "endpoints_assigned", label: "Endpoints", width: 82, cls: "mono" },
    { key: "bound_groups", label: "Groups",
      render: (r) => (r.bound_groups?.length
        ? <span className="chipline">
            {r.bound_groups.map((g) => (
              <span className="chip" key={g}>{g}</span>))}
          </span>
        : <NA label="NOT BOUND" />) },
  ], []);

  return (
    <NivXForgeConsole activeTab="policies">
      <div className="ops-head">
        <div>
          <span className="eyebrow">Respond</span>
          <h1 className="ttl">Policies</h1>
          <div className="sub">
            Tenant → Group → Policy → Version → Assignment → Delivery →
            Acknowledgement → Applied → Verified.
            <strong> Delivery is never application</strong>: only an
            authenticated connector acknowledgement of the exact version and
            config digest can move a computer to APPLIED.
          </div>
        </div>
        <div className="spacer" />
        <div className="ops-actions">
          <button className="btn" onClick={load}
                  data-testid="edr-policies-refresh">
            <RefreshCw size={11} /> Refresh
          </button>
          <button className="btn"
                  onClick={() => setForm(form === "group" ? null : "group")}
                  data-testid="edr-policies-new-group">
            <Users size={11} /> New group
          </button>
          <button className="btn mint"
                  onClick={() => setForm(form === "policy" ? null : "policy")}
                  data-testid="edr-policies-new-policy">
            <Plus size={11} /> New policy
          </button>
        </div>
      </div>

      {err ? <Refusal title="Policy authority unavailable" body={err}
                      testid="edr-policies-refusal" /> : null}
      {!policies && !err ? <Skeleton rows={7} testid="edr-policies-loading" />
        : null}

      {form === "policy" ? (
        <NewPolicyForm onCancel={() => setForm(null)}
                       onDone={(out) => { setForm(null); setSelected(
                         out.policy.id); load(); }} />
      ) : null}
      {form === "group" ? (
        <NewGroupForm policies={rows} onCancel={() => setForm(null)}
                      onDone={() => { setForm(null); load(); }} />
      ) : null}

      {policies ? (
        <>
          <div className="kpi-rail" data-testid="edr-policies-kpis">
            <Kpi label="Policies" value={policies.count}
                 testid="edr-kpi-policies" />
            <Kpi label="Groups" value={groups.length}
                 testid="edr-kpi-groups" />
            <Kpi label="Applied + Verified"
                 value={(dist.APPLIED || 0) + (dist.VERIFIED || 0)}
                 tone={(dist.APPLIED || dist.VERIFIED) ? "mint" : undefined}
                 testid="edr-kpi-applied" />
            <Kpi label="Awaiting confirmation"
                 value={(dist.ASSIGNED || 0) + (dist.PENDING_DELIVERY || 0)
                        + (dist.DELIVERED || 0) + (dist.ACKNOWLEDGED || 0)}
                 tone="amber" testid="edr-kpi-awaiting" />
            <Kpi label="Out of sync / failed"
                 value={(dist.OUT_OF_SYNC || 0) + (dist.FAILED || 0)
                        + (dist.STALE || 0)}
                 tone={(dist.OUT_OF_SYNC || dist.FAILED || dist.STALE)
                   ? "red" : undefined}
                 testid="edr-kpi-drift" />
            <Kpi label="Policy unassigned" value={dist.POLICY_UNASSIGNED || 0}
                 testid="edr-kpi-unassigned" />
          </div>

          <div className="panel" style={{ padding: "9px 13px",
                                          marginBottom: 14 }}
               data-testid="edr-policies-lifecycle">
            <div className="section-title" style={{ marginBottom: 6 }}>
              <Layers size={10} style={{ verticalAlign: -1, marginRight: 5 }} />
              Lifecycle
            </div>
            <div className="chipline">
              {(policies.lifecycle || []).map((s) => (
                <span className="chip" key={s}
                      data-testid={`edr-lifecycle-${s}`}>
                  {s}{dist[s] ? ` · ${dist[s]}` : ""}
                </span>))}
            </div>
            <div className="basis" style={{ marginTop: 6 }}>
              {policies.lifecycle_contract}
            </div>
          </div>

          <div className="section-title" style={{ marginBottom: 6 }}>
            <CheckCircle2 size={10}
                          style={{ verticalAlign: -1, marginRight: 5 }} />
            Policies
          </div>
          <OpsTable columns={columns} rows={rows} rowKey={(r) => r.id}
                    selectedKey={selected}
                    onSelect={(r) => setSelected(r.id)}
                    testid="edr-policies-table" />

          {!rows.length ? (
            <div className="basis" data-testid="edr-policies-empty">
              NO POLICY EXISTS FOR THIS CUSTOMER.
              {" "}{deployment?.count === 0
                ? "No computer is enrolled in this customer either, and the "
                  + "platform default policy is written at the FIRST "
                  + "connector enrolment — so an empty customer honestly has "
                  + "no policy rather than an invented one. "
                : `${deployment?.count} computer(s) are enrolled and every `
                  + "one of them reads POLICY UNASSIGNED. "}
              Check the CUSTOMER selector in the header if you expected to see
              an existing estate here: a policy authored in one customer is
              never visible in another.
            </div>
          ) : null}

          {selected ? (
            <div style={{ marginTop: 18 }}>
              <PolicyDetail policyId={selected} groups={groups}
                            onChanged={load} />
            </div>
          ) : null}
        </>
      ) : null}
    </NivXForgeConsole>
  );
}
