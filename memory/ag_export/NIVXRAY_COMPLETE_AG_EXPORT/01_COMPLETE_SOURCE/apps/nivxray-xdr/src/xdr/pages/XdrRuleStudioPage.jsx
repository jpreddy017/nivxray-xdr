/**
 * XdrRuleStudioPage — Authoritative Rule Studio shell (Step 1).
 *
 * ONE surface, nine lanes:
 *   event · endpoint · ioc · network · dns_proxy · cve_exposure
 *   · correlation · behavior · content
 *
 * The New Rule wizard is type-aware and creates rules in DRAFT.
 * ACTIVE promotion runs the 11-check gate (Step 2).  No lane
 * implementations here — this is the shell + lifecycle + gate UI.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Layers, Search, RefreshCcw, Plus, Play, Ban, CheckCircle2,
                XCircle, HelpCircle, ArrowRight } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";


const STATE_COLOR = {
  DRAFT:      "var(--faint)",
  TESTING:    "#38bdf8",
  VALIDATED:  "var(--mint)",
  ENABLED:    "var(--cyan)",
  ACTIVE:     "#22c55e",
  TUNING:     "var(--amber)",
  DISABLED:   "#94a3b8",
  DEPRECATED: "#f87171",
};

const GATE_STATUS_COLOR = {
  PASS: "var(--mint)", FAIL: "#f87171",
  SKIP: "var(--amber)", UNKNOWN: "var(--faint)",
};


export default function XdrRuleStudioPage() {
  const [status,  setStatus]  = useState(null);
  const [lanes,   setLanes]   = useState([]);
  const [rules,   setRules]   = useState([]);
  const [busy,    setBusy]    = useState(false);
  const [err,     setErr]     = useState(null);
  const [q,       setQ]       = useState("");
  const [lane,    setLane]    = useState("");
  const [state,   setState]   = useState("");
  const [refresh, setRefresh] = useState(0);
  const [openRule, setOpenRule] = useState(null);
  const [wizard,  setWizard]  = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setBusy(true); setErr(null);
      try {
        const [s, l, r] = await Promise.all([
          api.get("/xdr/rule-studio/status"),
          api.get("/xdr/rule-studio/lanes"),
          api.get("/xdr/rule-studio/rules", { params: { limit: 1000,
              q: q || undefined,
              lane: lane || undefined,
              lifecycle_state: state || undefined }}),
        ]);
        if (cancelled) return;
        setStatus(s?.data?.data || null);
        setLanes(l?.data?.data?.lanes || []);
        setRules(r?.data?.data?.rules || []);
      } catch (x) {
        setErr(x?.response?.data?.detail || x?.message || "load failed");
      } finally { if (!cancelled) setBusy(false); }
    })();
    return () => { cancelled = true; };
  }, [refresh, q, lane, state]);

  const s = status || {};
  const byLane = s.by_lane || {};
  const byLifecycle = s.by_lifecycle || {};

  const transition = async (ruleId, to) => {
    try {
      await api.post(`/xdr/rule-studio/rules/${ruleId}/transition`,
                                    { to, reason: `analyst → ${to}` });
      setRefresh((n) => n + 1);
      if (openRule?.id === ruleId) {
        const g = await api.post(`/xdr/rule-studio/rules/${ruleId}/gate`);
        setOpenRule({ ...openRule, gate_state: g.data.data.gate,
                                lifecycle_state: to });
      }
    } catch (x) {
      const d = x?.response?.data?.detail;
      if (d?.code === "REGRESSION_GATE_FAILED" && openRule) {
        setOpenRule({ ...openRule, gate_state: d.gate });
      }
      setErr(d?.reason || d?.code || x?.message);
    }
  };
  const promote = async (ruleId) => {
    try {
      await api.post(`/xdr/rule-studio/rules/${ruleId}/promote`);
      setRefresh((n) => n + 1);
    } catch (x) {
      const d = x?.response?.data?.detail;
      if (d?.code === "REGRESSION_GATE_FAILED" && openRule?.id === ruleId) {
        setOpenRule({ ...openRule, gate_state: d.gate });
      }
      setErr(d?.reason || d?.code || x?.message);
    }
  };
  const dryRunGate = async (ruleId) => {
    try {
      const g = await api.post(`/xdr/rule-studio/rules/${ruleId}/gate`);
      if (openRule?.id === ruleId) {
        setOpenRule({ ...openRule, gate_state: g.data.data.gate });
      }
    } catch (x) { setErr(x?.response?.data?.detail || x?.message); }
  };

  return (
    <XdrShell>
      <div data-testid="xdr-rule-studio-page">
        <div style={{ display: "flex", alignItems: "center", gap: 10,
                                marginBottom: 6 }}>
          <Layers size={16} style={{ color: "var(--cyan)" }} />
          <h1 className="page-h1" style={{ margin: 0 }}>Rule Studio</h1>
          <span style={{ padding: "1px 6px", border: "1px solid var(--cyan)",
                                  color: "var(--cyan)", borderRadius: 2, fontSize: 9.5,
                                  fontFamily: "var(--mono)", fontWeight: 700 }}>
            9 LANES · 11-CHECK REGRESSION GATE
          </span>
          <span style={{ flex: 1 }} />
          <button className="btn" onClick={() => setWizard(true)}
                        data-testid="rs-new-rule-btn"
                        style={{ padding: "3px 10px", fontSize: 11 }}>
            <Plus size={11} /> New rule
          </button>
          <button className="btn ghost" onClick={() => setRefresh((n) => n + 1)}
                        disabled={busy} data-testid="rs-refresh"
                        style={{ padding: "3px 10px", fontSize: 11,
                                        opacity: busy ? 0.5 : 1 }}>
            <RefreshCcw size={11}
                                    style={{ animation: busy ? "spin 0.8s linear infinite"
                                                                            : "none" }} /> {busy ? "Loading…" : "Refresh"}
          </button>
        </div>
        <div className="page-sub" style={{ marginBottom: 12,
                                                                fontFamily: "var(--mono)",
                                                                fontSize: 11 }}>
          {s.semantic_contract ||
              "RULE → OBSERVATION → CORRELATION → EVIDENCE → IKG → ICE → VERDICT → INCIDENT → PLAYBOOK"}
          <span style={{ color: "var(--faint)", marginLeft: 8 }}>
            · Verdicts owned by {s.verdict_owned_by || "Verdict Engine"} · rules NEVER emit verdicts
          </span>
        </div>

        {/* Lane strip */}
        <div style={{ display: "grid",
                                gridTemplateColumns: "repeat(9, 1fr)",
                                gap: 4, marginBottom: 10 }}>
          <button data-testid="rs-lane-all"
                        onClick={() => setLane("")}
                        style={{ ...laneBtn,
                                        border: `1px solid ${lane === "" ? "var(--cyan)"
                                                                                                : "var(--border)"}`,
                                        color: lane === "" ? "var(--cyan)"
                                                                              : "var(--text-dim)" }}>
            <div style={laneCount}>{s.total ?? 0}</div>
            <div style={laneLabel}>All lanes</div>
          </button>
          {lanes.slice(0, 8).map((l) => (
            <button key={l.key}
                          data-testid={`rs-lane-${l.key}`}
                          onClick={() => setLane(l.key === lane ? "" : l.key)}
                          title={l.description}
                          style={{ ...laneBtn,
                                          border: `1px solid ${lane === l.key ? "var(--cyan)"
                                                                                                  : "var(--border)"}`,
                                          color: lane === l.key ? "var(--cyan)"
                                                                                : "var(--text-dim)" }}>
              <div style={laneCount}>{byLane[l.key] ?? 0}</div>
              <div style={laneLabel}>{l.label}</div>
            </button>
          ))}
        </div>
        {/* 9th lane wraps below the 8-wide grid to avoid clipping */}
        {lanes[8] && (
          <div style={{ marginBottom: 12 }}>
            <button data-testid={`rs-lane-${lanes[8].key}`}
                          onClick={() => setLane(lanes[8].key === lane ? "" : lanes[8].key)}
                          title={lanes[8].description}
                          style={{ ...laneBtn, width: "100%",
                                          border: `1px solid ${lane === lanes[8].key ? "var(--cyan)"
                                                                                                              : "var(--border)"}`,
                                          color: lane === lanes[8].key ? "var(--cyan)"
                                                                                            : "var(--text-dim)" }}>
              <div style={laneCount}>{byLane[lanes[8].key] ?? 0}</div>
              <div style={laneLabel}>{lanes[8].label}</div>
            </button>
          </div>
        )}

        {/* Lifecycle strip */}
        <div style={{ display: "flex", gap: 4, marginBottom: 10,
                                flexWrap: "wrap" }}>
          {(s.lifecycle_states || []).map((st) => (
            <button key={st}
                          data-testid={`rs-lifecycle-${st}`}
                          onClick={() => setState(state === st ? "" : st)}
                          style={{ padding: "3px 8px", fontSize: 10,
                                          fontFamily: "var(--mono)", fontWeight: 700,
                                          border: `1px solid ${state === st
                                                                                ? STATE_COLOR[st]
                                                                                : "var(--border)"}`,
                                          borderRadius: 2, background: "var(--panel2)",
                                          color: STATE_COLOR[st], cursor: "pointer" }}>
              {st} · {byLifecycle[st] ?? 0}
            </button>
          ))}
        </div>

        {/* Search */}
        <div style={{ display: "flex", gap: 6, marginBottom: 8,
                                alignItems: "center" }}>
          <Search size={12} style={{ color: "var(--faint)" }} />
          <input value={q} onChange={(e) => setQ(e.target.value)}
                       placeholder="Search rules by title or description…"
                       data-testid="rs-search"
                       style={inputStyle} />
        </div>

        {err && <div style={errBox} data-testid="rs-error">{err}</div>}

        <div style={{ color: "var(--faint)", fontSize: 10.5,
                                fontFamily: "var(--mono)", marginBottom: 6 }}>
          {busy ? "Loading…" : `${rules.length} rules`}
          {lane && ` · lane=${lane}`}
          {state && ` · lifecycle=${state}`}
        </div>

        {/* Rule table */}
        <div style={{ border: "1px solid var(--border)", borderRadius: 3,
                                overflow: "hidden" }}>
          <div style={rowHead}>
            <div>Title</div><div>Lane</div><div>Lifecycle</div>
            <div>Gate</div><div>License</div><div>Source</div>
          </div>
          {rules.map((r) => (
            <div key={r.id} style={rowBody}
                       data-testid={`rs-row-${r.id}`}
                       onClick={() => setOpenRule(r)}>
              <div style={{ color: "var(--cyan)" }}>
                {(r.title || "").slice(0, 60) || r.id}
              </div>
              <div>{r.lane || "content"}</div>
              <div>
                <span style={{ color: STATE_COLOR[r.lifecycle_state] ||
                                                      "var(--faint)",
                                        fontWeight: 700 }}>
                  {r.lifecycle_state}
                </span>
              </div>
              <div style={{ color: r.gate_state?.pass ? "var(--mint)"
                                                              : "var(--faint)" }}>
                {r.gate_state?.pass ? "PASS" : r.gate_state?.summary
                    ? `${r.gate_state.summary.pass}/${r.gate_state.summary.pass +
                            r.gate_state.summary.fail + r.gate_state.summary.skip}`
                    : "—"}
              </div>
              <div style={{ fontSize: 10 }}>{r.license_policy_state}</div>
              <div style={{ color: "var(--faint)", fontSize: 10 }}>
                {r.source}
              </div>
            </div>
          ))}
          {rules.length === 0 && !busy && (
            <div style={emptyRow}>NO RULES MATCH — adjust filters</div>
          )}
        </div>

        {openRule && (
          <RuleDetail rule={openRule}
                                  onClose={() => setOpenRule(null)}
                                  onTransition={(to) => transition(openRule.id, to)}
                                  onPromote={() => promote(openRule.id)}
                                  onDryRun={() => dryRunGate(openRule.id)}
                                  transitions={s.transitions || {}} />
        )}

        {wizard && (
          <NewRuleWizard lanes={lanes}
                                          onClose={() => setWizard(false)}
                                          onCreated={() => { setWizard(false); setRefresh((n) => n + 1); }} />
        )}
      </div>
    </XdrShell>
  );
}


function RuleDetail({ rule, onClose, onTransition, onPromote, onDryRun,
                                          transitions }) {
  const allowed = transitions[rule.lifecycle_state] || [];
  const gate = rule.gate_state || {};
  return (
    <div style={drawerBackdrop} onClick={onClose}>
      <div style={drawerPanel} onClick={(e) => e.stopPropagation()}
                data-testid={`rs-detail-${rule.id}`}>
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                                marginBottom: 8 }}>
          <Layers size={12} style={{ color: "var(--cyan)" }} />
          <b>{rule.title}</b>
          <span style={{ padding: "1px 6px",
                                  border: `1px solid ${STATE_COLOR[rule.lifecycle_state]}`,
                                  color: STATE_COLOR[rule.lifecycle_state],
                                  borderRadius: 2, fontSize: 10,
                                  fontFamily: "var(--mono)", fontWeight: 700 }}>
            {rule.lifecycle_state}
          </span>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose}
                        style={{ padding: "3px 8px", fontSize: 11 }}>Close</button>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr",
                                gap: 12 }}>
          <div>
            <MetaRow label="Lane"           value={rule.lane} />
            <MetaRow label="Rule type"      value={rule.rule_type} />
            <MetaRow label="Source"         value={rule.source} />
            <MetaRow label="License"        value={`${rule.license} · ${rule.license_policy_state}`} />
            <MetaRow label="ATT&CK"         value={(rule.attack_techniques || []).join(", ") || "—"} />
            <MetaRow label="Emits"          value={rule.emits || "OBSERVATION"} />
            <MetaRow label="Verdict-capable"
                              value={rule.verdict_capable ? "YES ⚠" : "NO (capability_not_verdict)"} />
          </div>
          <div>
            <div style={{ ...metaLabel, marginBottom: 6 }}>
              11-check Regression Gate ·{" "}
              <span style={{ color: gate.pass ? "var(--mint)" : "#f87171" }}>
                {gate.pass ? "PASSED" : "NOT PASSED"}
              </span>
              {gate.last_run_at && (
                <span style={{ color: "var(--faint)", marginLeft: 6 }}>
                  · last run {gate.last_run_at.slice(11, 19)}Z
                </span>
              )}
            </div>
            <div style={{ maxHeight: 260, overflow: "auto",
                                    border: "1px solid var(--border)",
                                    borderRadius: 2 }}>
              {Object.entries(gate.checks || {}).map(([name, c]) => (
                <div key={name}
                            data-testid={`rs-gate-${name}`}
                            style={{ display: "flex", gap: 6, padding: "4px 8px",
                                            borderBottom: "1px solid var(--border)",
                                            fontSize: 10.5, fontFamily: "var(--mono)" }}>
                  {c.status === "PASS" && <CheckCircle2 size={11}
                                                          style={{ color: GATE_STATUS_COLOR.PASS }} />}
                  {c.status === "FAIL" && <XCircle size={11}
                                                          style={{ color: GATE_STATUS_COLOR.FAIL }} />}
                  {c.status === "SKIP" && <HelpCircle size={11}
                                                          style={{ color: GATE_STATUS_COLOR.SKIP }} />}
                  {c.status === "UNKNOWN" && <HelpCircle size={11}
                                                          style={{ color: GATE_STATUS_COLOR.UNKNOWN }} />}
                  <span style={{ color: GATE_STATUS_COLOR[c.status] || "var(--faint)",
                                          minWidth: 40, fontWeight: 700 }}>
                    {c.status}
                  </span>
                  <span style={{ minWidth: 120 }}>{name}</span>
                  <span style={{ color: "var(--faint)" }}>{c.reason}</span>
                </div>
              ))}
              {Object.keys(gate.checks || {}).length === 0 && (
                <div style={{ padding: 8, color: "var(--faint)",
                                        fontSize: 10.5, fontFamily: "var(--mono)" }}>
                  Gate has never run — click "Run gate (dry-run)".
                </div>
              )}
            </div>
            <div style={{ display: "flex", gap: 4, marginTop: 8,
                                    flexWrap: "wrap" }}>
              <button className="btn ghost" onClick={onDryRun}
                            data-testid="rs-gate-dry-run"
                            style={{ padding: "3px 8px", fontSize: 10.5 }}>
                <Play size={10} /> Run gate (dry-run)
              </button>
              {allowed.filter((t) => t !== "ACTIVE").map((t) => (
                <button key={t} className="btn ghost" onClick={() => onTransition(t)}
                              data-testid={`rs-transition-${t}`}
                              style={{ padding: "3px 8px", fontSize: 10.5,
                                              color: STATE_COLOR[t] }}>
                  <ArrowRight size={10} /> {t}
                </button>
              ))}
              {allowed.includes("ACTIVE") && (
                <button className="btn" onClick={onPromote}
                              data-testid="rs-promote-active"
                              style={{ padding: "3px 8px", fontSize: 10.5,
                                              background: "var(--mint)", color: "#000" }}>
                  <CheckCircle2 size={10} /> Promote → ACTIVE
                </button>
              )}
              {rule.lifecycle_state === "ACTIVE" && (
                <button className="btn ghost" onClick={() => onTransition("DISABLED")}
                              data-testid="rs-disable"
                              style={{ padding: "3px 8px", fontSize: 10.5,
                                              color: STATE_COLOR.DISABLED }}>
                  <Ban size={10} /> Disable
                </button>
              )}
            </div>
          </div>
        </div>

        {rule.description && (
          <div style={{ marginTop: 10, padding: 8, background: "var(--panel2)",
                                  borderRadius: 2, fontSize: 11,
                                  color: "var(--text-dim)" }}>
            {rule.description}
          </div>
        )}
      </div>
    </div>
  );
}


function NewRuleWizard({ lanes, onClose, onCreated }) {
  const [form, setForm] = useState({
    lane: "endpoint", title: "", description: "",
    rule_type: "sigma", attack_techniques: "", level: "medium",
    detection: "{\n  \"selection\": {},\n  \"condition\": \"selection\"\n}",
  });
  const [busy, setBusy] = useState(false);
  const [err,  setErr]  = useState(null);
  const [schema, setSchema] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await api.get(`/xdr/rule-studio/lanes/${form.lane}/schema`);
        if (!cancelled) setSchema(r?.data?.data || null);
      } catch { if (!cancelled) setSchema(null); }
    })();
    return () => { cancelled = true; };
  }, [form.lane]);

  const insertField = (fieldKey) => {
    try {
      const obj = JSON.parse(form.detection);
      const sel = obj.selection || (obj.selection = {});
      if (!(fieldKey in sel)) sel[fieldKey] = "";
      setForm({ ...form,
                        detection: JSON.stringify(obj, null, 2) });
    } catch {
      setErr("Detection body must be valid JSON before inserting a field");
    }
  };
  const applyTemplate = (tpl) => {
    setForm({ ...form,
                      title: form.title || tpl.title,
                      detection: JSON.stringify(tpl.detection, null, 2) });
  };

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      let detection = {};
      try { detection = JSON.parse(form.detection); }
      catch { throw new Error("detection body must be valid JSON"); }
      await api.post("/xdr/rule-studio/rules", {
        lane: form.lane, title: form.title, description: form.description,
        rule_type: form.rule_type, level: form.level,
        detection,
        attack_techniques: form.attack_techniques.split(",")
                                                                            .map((x) => x.trim())
                                                                            .filter(Boolean),
      });
      onCreated();
    } catch (x) {
      setErr(x?.response?.data?.detail?.code
                  || x?.response?.data?.detail
                  || x?.message);
    } finally { setBusy(false); }
  };

  const laneSchema = schema?.schema;
  return (
    <div style={drawerBackdrop} onClick={onClose}>
      <div style={drawerPanel} onClick={(e) => e.stopPropagation()}
                data-testid="rs-new-rule-wizard">
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                                marginBottom: 10 }}>
          <Plus size={14} style={{ color: "var(--cyan)" }} />
          <b>New rule (starts in DRAFT)</b>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose}
                        style={{ padding: "3px 8px", fontSize: 11 }}>Close</button>
        </div>

        <Field label="Lane">
          <select value={form.lane}
                       onChange={(e) => setForm({ ...form, lane: e.target.value })}
                       data-testid="rs-wizard-lane" style={selectStyle}>
            {lanes.map((l) => <option key={l.key} value={l.key}>{l.label}</option>)}
          </select>
        </Field>
        <Field label="Title">
          <input value={form.title}
                       onChange={(e) => setForm({ ...form, title: e.target.value })}
                       placeholder="e.g. LOLBIN rundll32 with remote payload"
                       data-testid="rs-wizard-title" style={inputStyle} />
        </Field>
        <Field label="Description">
          <input value={form.description}
                       onChange={(e) => setForm({ ...form, description: e.target.value })}
                       placeholder="What observation does this rule emit?"
                       data-testid="rs-wizard-description" style={inputStyle} />
        </Field>

        {laneSchema && (
          <>
            <Field label={`${laneSchema.display_name} · fields (click to insert)`}>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}
                        data-testid="rs-wizard-field-chips">
                {laneSchema.fields.map((f) => (
                  <button key={f.key} type="button"
                                data-testid={`rs-wizard-field-${f.key}`}
                                onClick={() => insertField(f.key)}
                                title={`${f.type}${f.example
                                                            ? ` · e.g. ${f.example}`
                                                            : ""}${f.description
                                                                                ? ` — ${f.description}`
                                                                                : ""}`}
                                style={{ padding: "2px 6px", fontSize: 10,
                                                fontFamily: "var(--mono)", cursor: "pointer",
                                                background: "var(--panel2)",
                                                border: "1px solid var(--border)",
                                                borderRadius: 2, color: "var(--cyan)" }}>
                    {f.key}
                  </button>
                ))}
              </div>
            </Field>
            {(laneSchema.templates || []).length > 0 && (
              <Field label="Templates (click to load)">
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}
                          data-testid="rs-wizard-templates">
                  {laneSchema.templates.map((t) => (
                    <button key={t.title} type="button"
                                  data-testid={`rs-wizard-template-${t.title.replace(/[^a-z0-9]/gi, "-").toLowerCase()}`}
                                  onClick={() => applyTemplate(t)}
                                  style={{ padding: "2px 6px", fontSize: 10,
                                                  fontFamily: "var(--mono)", cursor: "pointer",
                                                  background: "var(--panel2)",
                                                  border: "1px dashed var(--cyan)",
                                                  borderRadius: 2, color: "var(--text)" }}>
                    {t.title}
                    </button>
                  ))}
                </div>
              </Field>
            )}
          </>
        )}
        {schema && !schema.available && (
          <div style={{ padding: "4px 8px", fontSize: 10.5,
                                  fontFamily: "var(--mono)",
                                  color: "var(--faint)", marginBottom: 6 }}>
            Lane body not yet shipped — advanced-mode JSON detection accepted.
          </div>
        )}

        <Field label="Rule type">
          <input value={form.rule_type}
                       onChange={(e) => setForm({ ...form, rule_type: e.target.value })}
                       data-testid="rs-wizard-type" style={inputStyle} />
        </Field>
        <Field label="ATT&CK techniques (comma-separated)">
          <input value={form.attack_techniques}
                       onChange={(e) => setForm({ ...form, attack_techniques: e.target.value })}
                       placeholder="T1218.011, T1059.001"
                       data-testid="rs-wizard-attack" style={inputStyle} />
        </Field>
        <Field label="Severity">
          <select value={form.level}
                       onChange={(e) => setForm({ ...form, level: e.target.value })}
                       data-testid="rs-wizard-level" style={selectStyle}>
            <option>low</option><option>medium</option>
            <option>high</option><option>critical</option>
          </select>
        </Field>
        <Field label="Detection body (JSON)">
          <textarea rows={7} value={form.detection}
                             onChange={(e) => setForm({ ...form, detection: e.target.value })}
                             data-testid="rs-wizard-detection"
                             style={{ ...inputStyle, resize: "vertical",
                                              fontFamily: "var(--mono)" }} />
        </Field>

        <div style={{ marginTop: 8, color: "var(--faint)", fontSize: 10.5,
                                fontFamily: "var(--mono)" }}>
          This rule will be stamped emits=OBSERVATION · emits_verdict=false ·
          capability_not_verdict=true. ACTIVE promotion is blocked until the
          11-check gate passes.
        </div>

        {err && <div style={{ ...errBox, marginTop: 8 }}
                                  data-testid="rs-wizard-error">{String(err)}</div>}

        <div style={{ display: "flex", gap: 6, justifyContent: "flex-end",
                                marginTop: 12 }}>
          <button className="btn" onClick={submit} disabled={busy || !form.title}
                        data-testid="rs-wizard-create"
                        style={{ padding: "4px 12px", fontSize: 11,
                                        opacity: (busy || !form.title) ? 0.5 : 1 }}>
            {busy ? "Creating…" : "Create rule (DRAFT)"}
          </button>
        </div>
      </div>
    </div>
  );
}


function Field({ label, children }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ ...metaLabel, marginBottom: 3 }}>{label}</div>
      {children}
    </div>
  );
}

function MetaRow({ label, value }) {
  return (
    <div style={{ display: "flex", gap: 8, padding: "3px 0",
                            fontSize: 11, fontFamily: "var(--mono)" }}>
      <div style={{ ...metaLabel, minWidth: 130 }}>{label}</div>
      <div style={{ color: "var(--text-dim)" }}>{value || "—"}</div>
    </div>
  );
}

const inputStyle = { flex: 1, padding: "4px 8px", background: "var(--panel2)",
                                     border: "1px solid var(--border)",
                                     color: "var(--text)", fontSize: 11,
                                     borderRadius: 3, fontFamily: "var(--mono)",
                                     width: "100%", boxSizing: "border-box" };
const selectStyle = { padding: "4px 6px", background: "var(--panel2)",
                                     border: "1px solid var(--border)",
                                     color: "var(--text)", fontSize: 11,
                                     borderRadius: 3, fontFamily: "var(--mono)",
                                     width: "100%", boxSizing: "border-box" };
const laneBtn = { padding: 8, borderRadius: 3, background: "var(--panel2)",
                              cursor: "pointer", textAlign: "left", minWidth: 0 };
const laneCount = { fontSize: 18, fontWeight: 700, fontFamily: "var(--mono)" };
const laneLabel = { fontSize: 9.5, fontFamily: "var(--mono)",
                                     color: "var(--faint)",
                                     textTransform: "uppercase", letterSpacing: ".3px",
                                     overflow: "hidden", textOverflow: "ellipsis",
                                     whiteSpace: "nowrap" };
const rowHead = { display: "grid",
                                gridTemplateColumns: "3fr 1fr 1fr 0.8fr 1fr 1.5fr",
                                gap: 6, padding: "5px 10px",
                                background: "var(--panel2)", fontSize: 10,
                                color: "var(--faint)", textTransform: "uppercase",
                                fontFamily: "var(--mono)", fontWeight: 700 };
const rowBody = { display: "grid",
                                gridTemplateColumns: "3fr 1fr 1fr 0.8fr 1fr 1.5fr",
                                gap: 6, padding: "6px 10px", fontSize: 11,
                                color: "var(--text-dim)",
                                borderTop: "1px solid var(--border)",
                                fontFamily: "var(--mono)", cursor: "pointer" };
const emptyRow = { padding: 12, fontSize: 11, color: "var(--faint)",
                                  fontFamily: "var(--mono)" };
const errBox = { padding: "6px 10px", border: "1px solid var(--amber)",
                             color: "var(--amber)", fontSize: 11,
                             fontFamily: "var(--mono)", borderRadius: 3,
                             marginBottom: 8 };
const drawerBackdrop = {
  position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
  background: "rgba(0,0,0,.6)", display: "flex", alignItems: "center",
  justifyContent: "center", zIndex: 1000,
};
const drawerPanel = {
  width: "min(900px, 92vw)", padding: 16, borderRadius: 3,
  background: "var(--panel)", border: "1px solid var(--border)",
  fontFamily: "var(--mono)", maxHeight: "88vh", overflow: "auto",
};
const metaLabel = {
  fontSize: 9.5, color: "var(--faint)", textTransform: "uppercase",
  letterSpacing: ".3px", fontFamily: "var(--mono)", fontWeight: 700,
};
