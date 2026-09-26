/**
 * GATE 7 · Exclusions — declared protection blind spots.
 *
 * Nothing here implies that a record is an exclusion. An exclusion is
 * inert until a SECOND operator approves it, and the console shows the
 * per-engine truth state that the server derived: server-side
 * enforcement is proven by running the real fabric with and without the
 * gate, and endpoint-side enforcement honestly reads
 * EXCLUSION_NOT_SUPPORTED_BY_ENGINE or EXCLUSION_PENDING_POLICY until
 * the endpoint proves otherwise.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { FlaskConical, Plus, RefreshCw, ShieldOff } from "lucide-react";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { createExclusion, createExclusionSet, decideExclusion,
         getEnforcementProof, getExclusionTaxonomy, listExclusionSets,
         listExclusions, revokeExclusion } from "@/nivxforge/managementApi";
import { Ago, Kpi, NA, OpsTable, Refusal, Skeleton, StateChip }
  from "@/nivxforge/components/OpsPrimitives";
import { apiErrorText } from "@/xdr/nx/apiError";
import "@/nivxforge/nvf-ops.css";

const TONE = {
  ACTIVE: "ok",
  INACTIVE_PENDING_APPROVAL: "warn",
  NOT_YET_EFFECTIVE: "info",
  EXPIRED: "void",
  REVOKED: "void",
  REVIEW_OVERDUE: "bad",
  SERVER_EXCLUSION_APPLIED: "ok",
  ENDPOINT_EXCLUSION_APPLIED: "ok",
  EXCLUSION_PENDING_POLICY: "warn",
  EXCLUSION_NOT_SUPPORTED_BY_ENGINE: "void",
};

function NewSetForm({ onDone, onCancel }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  return (
    <div className="panel" style={{ padding: "11px 13px", marginBottom: 14 }}
         data-testid="edr-exclusion-set-form">
      <div className="section-title" style={{ marginBottom: 8 }}>
        New exclusion set
      </div>
      <div className="kv">
        <span className="k">Name</span>
        <span className="v">
          <input value={name} onChange={(e) => setName(e.target.value)}
                 placeholder="Backup agent exclusions"
                 data-testid="edr-exclusion-set-name" />
        </span>
      </div>
      {err ? <Refusal title="Set refused" body={err}
                      testid="edr-exclusion-set-error" /> : null}
      <div className="ops-actions" style={{ marginTop: 10 }}>
        <button className="btn mint" disabled={busy || name.trim().length < 2}
                onClick={async () => {
                  setBusy(true); setErr(null);
                  try { onDone(await createExclusionSet({ name, os: "WINDOWS" })); }
                  catch (e) { setErr(apiErrorText(e, "set refused")); }
                  finally { setBusy(false); }
                }}
                data-testid="edr-exclusion-set-create">
          {busy ? "Creating…" : "Create set"}
        </button>
        <button className="btn" onClick={onCancel}
                data-testid="edr-exclusion-set-cancel">Cancel</button>
      </div>
    </div>
  );
}

function NewExclusionForm({ sets, taxonomy, onDone, onCancel }) {
  const [setId, setSetId] = useState(sets[0]?.set_id || "");
  const [type, setType] = useState("PATH");
  const [match, setMatch] = useState("EXACT");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [engines, setEngines] = useState(["server.deterministic.rule"]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const toggle = (e) => setEngines((cur) => (cur.includes(e)
    ? cur.filter((x) => x !== e) : [...cur, e]));

  return (
    <div className="panel" style={{ padding: "11px 13px", marginBottom: 14 }}
         data-testid="edr-exclusion-form">
      <div className="section-title" style={{ marginBottom: 8 }}>
        New exclusion · submitted for approval
      </div>
      <div className="kv">
        <span className="k">Set</span>
        <span className="v">
          <select value={setId} onChange={(e) => setSetId(e.target.value)}
                  data-testid="edr-exclusion-set-select">
            {sets.map((s) => (
              <option key={s.set_id} value={s.set_id}>{s.name}</option>))}
          </select>
        </span>
        <span className="k">Type</span>
        <span className="v">
          <select value={type} onChange={(e) => setType(e.target.value)}
                  data-testid="edr-exclusion-type">
            {(taxonomy?.types || []).map((t) => (
              <option key={t} value={t}>{t}</option>))}
          </select>
        </span>
        <span className="k">Match</span>
        <span className="v">
          <select value={match} onChange={(e) => setMatch(e.target.value)}
                  data-testid="edr-exclusion-match">
            {(taxonomy?.match_kinds || []).map((m) => (
              <option key={m} value={m}>{m}</option>))}
          </select>
        </span>
        <span className="k">Value</span>
        <span className="v">
          <input value={value} onChange={(e) => setValue(e.target.value)}
                 placeholder={type === "FILE_HASH" ? "sha-256 hex digest"
                   : "C:\\Program Files\\Vendor\\agent.exe"}
                 data-testid="edr-exclusion-value" />
        </span>
        <span className="k">Reason</span>
        <span className="v">
          <input value={reason} onChange={(e) => setReason(e.target.value)}
                 placeholder="Why this protection blind spot is accepted (min 10 chars)"
                 data-testid="edr-exclusion-reason" />
        </span>
        <span className="k">Affected engines</span>
        <span className="v">
          <span className="chipline">
            {(taxonomy?.engines || []).map((e) => (
              <button key={e.engine}
                      className={`chip ${engines.includes(e.engine) ? "mint" : ""}`}
                      onClick={() => toggle(e.engine)}
                      title={e.implemented
                        ? `${e.enforcement_point} · implemented`
                        : `${e.enforcement_point} · NOT IMPLEMENTED — this `
                          + `exclusion will report its real state instead of `
                          + `claiming enforcement`}
                      data-testid={`edr-exclusion-engine-${e.engine}`}>
                {e.engine}{e.implemented ? "" : " ◇"}
              </button>))}
          </span>
        </span>
      </div>
      <div className="basis" style={{ marginTop: 8 }}>
        {taxonomy?.authority_contract}
      </div>
      {err ? <Refusal title="Exclusion refused" body={err}
                      testid="edr-exclusion-form-error" /> : null}
      <div className="ops-actions" style={{ marginTop: 10 }}>
        <button className="btn mint"
                disabled={busy || !setId || value.trim().length < 1
                          || reason.trim().length < 10 || !engines.length}
                onClick={async () => {
                  setBusy(true); setErr(null);
                  try {
                    onDone(await createExclusion({
                      set_id: setId, type, match, value: value.trim(),
                      reason: reason.trim(), affected_engines: engines,
                      scope: { type: "TENANT", ids: [] } }));
                  } catch (e) {
                    setErr(apiErrorText(e, "exclusion refused"));
                  } finally { setBusy(false); }
                }}
                data-testid="edr-exclusion-create">
          {busy ? "Submitting…" : "Submit for approval"}
        </button>
        <button className="btn" onClick={onCancel}
                data-testid="edr-exclusion-cancel">Cancel</button>
      </div>
    </div>
  );
}

function ProofPanel() {
  const [proof, setProof] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const run = async () => {
    setBusy(true); setErr(null);
    try { setProof(await getEnforcementProof(400)); }
    catch (e) { setErr(apiErrorText(e, "proof unavailable")); }
    finally { setBusy(false); }
  };

  return (
    <div className="panel" style={{ padding: "11px 13px", marginBottom: 14 }}
         data-testid="edr-exclusion-proof">
      <div className="ops-head" style={{ marginBottom: 6 }}>
        <div className="section-title">
          <FlaskConical size={10} style={{ verticalAlign: -1, marginRight: 5 }} />
          Enforcement proof
        </div>
        <div className="spacer" />
        <button className="btn mint" disabled={busy} onClick={run}
                data-testid="edr-exclusion-proof-run">
          {busy ? "Running…" : "Run against real evidence"}
        </button>
      </div>
      <div className="basis">
        Executes the registered detection fabric over this tenant's real
        persisted evidence twice — with and without the exclusion gate — and
        reports the delta. Read-only. A record that changes nothing cannot
        pass it.
      </div>
      {err ? <Refusal title="Proof unavailable" body={err}
                      testid="edr-exclusion-proof-error" /> : null}
      {proof ? (
        <>
          <div className="kpi-rail" style={{ marginTop: 10 }}>
            <Kpi label="Evidence sampled" value={proof.evidence_sampled}
                 testid="edr-proof-sampled" />
            <Kpi label="Approved exclusions consulted"
                 value={proof.approved_exclusions_consulted}
                 testid="edr-proof-consulted" />
            <Kpi label="Evidence bypassed" value={proof.evidence_bypassed}
                 tone={proof.evidence_bypassed ? "amber" : undefined}
                 testid="edr-proof-bypassed" />
            <Kpi label="Findings suppressed" value={proof.findings_suppressed}
                 tone={proof.findings_suppressed ? "red" : undefined}
                 testid="edr-proof-suppressed" />
          </div>
          <div className="ci-row" style={{ marginTop: 8 }}>
            <StateChip token={proof.changed_engine_behaviour
              ? "ENGINE_BEHAVIOUR_CHANGED" : "NO_MATCH_IN_SAMPLE"}
                       tone={proof.changed_engine_behaviour ? "ok" : "void"}
                       testid="edr-proof-verdict" />
            <span className="basis">{proof.verdict}</span>
          </div>
          {(proof.examples || []).length ? (
            <div style={{ marginTop: 8 }}>
              <div className="section-title" style={{ marginBottom: 5 }}>
                What actually happened to the evidence
              </div>
              {proof.examples.slice(0, 8).map((e) => (
                <div className="ci-row" key={e.evidence_ref}
                     data-testid={`edr-proof-example-${e.evidence_ref}`}>
                  <StateChip token={e.evidence_truth_state} tone="warn" />
                  <StateChip token={e.enforcement_truth_state} tone="info" />
                  <span className="basis mono">{e.matched_attribute}=
                    {e.observed_value} → {e.baseline_outcome} became
                    {" "}{e.gated_outcome}</span>
                </div>))}
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

export default function EdrExclusionsPage() {
  const [taxonomy, setTaxonomy] = useState(null);
  const [sets, setSets] = useState([]);
  const [rows, setRows] = useState(null);
  const [form, setForm] = useState(null);
  const [err, setErr] = useState(null);
  const [busyId, setBusyId] = useState(null);

  const load = useCallback(() => {
    setErr(null);
    Promise.all([getExclusionTaxonomy(), listExclusionSets(), listExclusions()])
      .then(([t, s, e]) => {
        setTaxonomy(t); setSets(s.sets || []); setRows(e);
      })
      .catch((e) => setErr(apiErrorText(e, "exclusions unavailable")));
  }, []);

  useEffect(load, [load]);

  const act = async (fn) => {
    try { await fn(); load(); }
    catch (e) { setErr(apiErrorText(e, "action refused")); }
    finally { setBusyId(null); }
  };

  const exclusions = rows?.exclusions || [];
  const active = exclusions.filter((e) => e.enforceable).length;
  const pending = exclusions.filter(
    (e) => e.approval_state === "PENDING_APPROVAL").length;

  const columns = useMemo(() => [
    { key: "type", label: "Type", width: 150,
      render: (r) => <StateChip token={r.type} tone="info" /> },
    { key: "value", label: "Value", cls: "mono",
      render: (r) => (
        <span title={`${r.match} match`}>{r.value}</span>) },
    { key: "lifecycle", label: "Lifecycle", width: 165,
      sortValue: (r) => r.lifecycle?.state,
      render: (r) => (
        <StateChip token={r.lifecycle?.state} title={r.lifecycle?.basis}
                   tone={TONE[r.lifecycle?.state]}
                   testid={`edr-exclusion-lifecycle-${r.exclusion_id}`} />) },
    { key: "enforcement", label: "Enforcement truth", width: 300,
      render: (r) => (
        <span className="chipline">
          {(r.enforcement || []).map((p) => (
            <StateChip key={p.engine} token={p.truth_state}
                       tone={TONE[p.truth_state]}
                       title={`${p.engine} · ${p.enforcement_point} — ${p.basis}`}
                       testid={`edr-exclusion-point-${r.exclusion_id}-${p.engine}`} />))}
        </span>) },
    { key: "reason", label: "Accepted because", cls: "basis",
      render: (r) => <span title={r.reason}>{r.reason}</span> },
    { key: "created_at", label: "Created", width: 92,
      render: (r) => <Ago iso={r.created_at} /> },
    { key: "actions", label: "", width: 160,
      render: (r) => (
        <span className="ops-actions">
          {r.approval_state === "PENDING_APPROVAL" ? (
            <button className="btn mint" disabled={busyId === r.exclusion_id}
                    onClick={(e) => { e.stopPropagation();
                      setBusyId(r.exclusion_id);
                      act(() => decideExclusion(r.exclusion_id,
                                                { decision: "APPROVED" })); }}
                    data-testid={`edr-exclusion-approve-${r.exclusion_id}`}>
              Approve
            </button>
          ) : null}
          {!r.revoked_at ? (
            <button className="btn" disabled={busyId === r.exclusion_id}
                    onClick={(e) => { e.stopPropagation();
                      setBusyId(r.exclusion_id);
                      act(() => revokeExclusion(r.exclusion_id,
                                                "revoked from the console")); }}
                    data-testid={`edr-exclusion-revoke-${r.exclusion_id}`}>
              Revoke
            </button>
          ) : null}
        </span>) },
  ], [busyId]);

  return (
    <NivXForgeConsole activeTab="exclusions">
      <div className="ops-head">
        <div>
          <span className="eyebrow">Respond</span>
          <h1 className="ttl">Exclusions</h1>
          <div className="sub">
            Declared protection blind spots. An exclusion is
            <strong> inert until a second operator approves it</strong>, and
            what actually happened is preserved: EXCLUDED when a finding was
            suppressed, NOT_EVALUATED_DUE_TO_EXCLUSION when the engine was
            bypassed before it ran.
          </div>
        </div>
        <div className="spacer" />
        <div className="ops-actions">
          <button className="btn" onClick={load}
                  data-testid="edr-exclusions-refresh">
            <RefreshCw size={11} /> Refresh
          </button>
          <button className="btn"
                  onClick={() => setForm(form === "set" ? null : "set")}
                  data-testid="edr-exclusions-new-set">
            <Plus size={11} /> New set
          </button>
          <button className="btn mint" disabled={!sets.length}
                  onClick={() => setForm(form === "excl" ? null : "excl")}
                  data-testid="edr-exclusions-new">
            <ShieldOff size={11} /> New exclusion
          </button>
        </div>
      </div>

      {err ? <Refusal title="Exclusions unavailable" body={err}
                      testid="edr-exclusions-refusal" /> : null}
      {!rows && !err ? <Skeleton rows={7} testid="edr-exclusions-loading" />
        : null}

      {form === "set" ? (
        <NewSetForm onCancel={() => setForm(null)}
                    onDone={() => { setForm(null); load(); }} />
      ) : null}
      {form === "excl" && sets.length ? (
        <NewExclusionForm sets={sets} taxonomy={taxonomy}
                          onCancel={() => setForm(null)}
                          onDone={() => { setForm(null); load(); }} />
      ) : null}

      {rows ? (
        <>
          <div className="kpi-rail" data-testid="edr-exclusions-kpis">
            <Kpi label="Exclusion sets" value={sets.length}
                 testid="edr-kpi-sets" />
            <Kpi label="Exclusions" value={rows.count}
                 testid="edr-kpi-exclusions" />
            <Kpi label="Enforceable now" value={active}
                 tone={active ? "amber" : undefined}
                 title="approved, effective, in scope — these change what an
                        engine does"
                 testid="edr-kpi-enforceable" />
            <Kpi label="Awaiting approval" value={pending}
                 tone={pending ? "amber" : undefined}
                 testid="edr-kpi-pending-approval" />
          </div>

          <ProofPanel />

          {sets.length ? (
            <>
              <div className="section-title" style={{ marginBottom: 6 }}>
                Exclusion sets
              </div>
              <div className="chipline" style={{ marginBottom: 12 }}>
                {sets.map((s) => (
                  <span className="chip" key={s.set_id}
                        title={s.description || ""}
                        data-testid={`edr-exclusion-set-${s.set_id}`}>
                    {s.name} · {s.exclusion_count} ({s.enforceable_count}
                    {" "}enforceable)
                  </span>))}
              </div>
            </>
          ) : (
            <div className="basis" data-testid="edr-exclusions-no-sets">
              NO EXCLUSION SET EXISTS. Nothing is excluded, so no engine is
              being bypassed in this tenant.
            </div>
          )}

          <OpsTable columns={columns} rows={exclusions}
                    rowKey={(r) => r.exclusion_id}
                    testid="edr-exclusions-table" />
          {!exclusions.length ? (
            <div className="basis" data-testid="edr-exclusions-empty">
              NO EXCLUSION RECORDED. The detection fabric evaluates every
              piece of evidence it receives.
            </div>
          ) : null}
          <div className="basis" style={{ marginTop: 10 }}
               data-testid="edr-exclusions-contract">
            {rows.authority_contract}
          </div>
        </>
      ) : null}
    </NivXForgeConsole>
  );
}
