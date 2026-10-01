/**
 * Admin › Capability Hub — plug-and-play extension surface.
 *
 * Reads exclusively from src/xdr/extensions/extensionRegistry.js
 * (docs/extensions/**\/*.json).  Every manifest is validated against
 * the extension contract; invalid manifests are rendered honestly with
 * their missing fields.
 *
 * The `+ ADD CAPABILITY` wizard is a client-side scaffold that walks
 * the user through Install → Configure → Test → Enable.  Actual
 * mutation belongs to a future control-plane API — today the wizard
 * documents what fields the operator MUST supply so the extension can
 * eventually be persisted server-side.  It NEVER pretends an
 * extension is installed when it isn't.
 */
import React, { useMemo, useState } from "react";
import { Plug, Search, PlusCircle, X, CheckCircle2,
  AlertTriangle } from "lucide-react";

import { EXTENSION_TYPES } from "@/xdr/extensions/extensionContract";
import { listAll, coverage, validateAll }
  from "@/xdr/extensions/extensionRegistry";


function lifecycleColor(ls) {
  const s = String(ls || "").toUpperCase();
  if (s === "ENABLED")     return "var(--mint)";
  if (s === "TESTED")      return "var(--cyan)";
  if (s === "CONFIGURED")  return "var(--cyan)";
  if (s === "INSTALLED")   return "var(--amber)";
  if (s === "AVAILABLE")   return "var(--faint)";
  if (s === "DISABLED")    return "var(--faint)";
  if (s === "DEPRECATED")  return "#c084fc";
  if (s === "FAILED")      return "#f87171";
  return "var(--faint)";
}


function CapabilityCard({ m, validation, onClick }) {
  return (
    <div className="panel"
            data-testid={`xdr-capability-${m.capability_id}`}
            onClick={onClick}
            style={{ padding: 10, display: "flex",
                        flexDirection: "column", gap: 4, cursor: "pointer" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <b className="mono" style={{ fontSize: 11, color: "var(--text)" }}>
          {m.name}
        </b>
        <span style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 9.5,
                                                        color: lifecycleColor(m.lifecycle),
                                                        padding: "1px 6px", borderRadius: 3,
                                                        border: `1px solid ${lifecycleColor(m.lifecycle)}` }}>
          {m.lifecycle}
        </span>
      </div>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
        {m.capability_id}
      </div>
      <div className="mono" style={{ fontSize: 10, color: "var(--cyan)" }}>
        {m.type} · v{m.version} · {m.vendor}
      </div>
      {m.description && (
        <div style={{ fontSize: 10.5, color: "var(--text-dim)" }}>
          {m.description}
        </div>
      )}
      {!validation.ok && (
        <div style={{ fontSize: 10, color: "var(--amber)" }}>
          MANIFEST INVALID · missing: {validation.missing.join(", ")}
          {validation.invalid.length > 0
            ? ` · invalid: ${validation.invalid.join(", ")}`
            : ""}
        </div>
      )}
      {m.adapter_status && m.adapter_status !== "AVAILABLE" && (
        <div style={{ fontSize: 10, color: "var(--faint)",
                          fontFamily: "var(--mono)" }}>
          adapter: {m.adapter_status}
        </div>
      )}
    </div>
  );
}


function AddCapabilityWizard({ onClose }) {
  const [step, setStep] = useState(1);
  const [type, setType] = useState(null);
  const [form, setForm] = useState({ capability_id: "", name: "",
                                                       provider: "", version: "0.1.0",
                                                       vendor: "" });
  return (
    <div data-testid="xdr-add-capability-wizard"
            style={{ position: "fixed", inset: 0,
                        background: "rgba(0,0,0,.5)",
                        display: "flex", alignItems: "center",
                        justifyContent: "center", zIndex: 1000 }}
            onClick={onClose}>
      <div onClick={(e) => e.stopPropagation()}
              style={{ width: 560, maxWidth: "92vw", background: "var(--panel)",
                          border: "1px solid var(--border)", borderRadius: 6,
                          padding: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6,
                          marginBottom: 8 }}>
          <PlusCircle size={14} />
          <b>Add Capability</b>
          <span className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                          marginLeft: 4 }}>
            step {step} / 4
          </span>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose}
                    data-testid="xdr-add-capability-close"
                    style={{ padding: "2px 6px", fontSize: 11 }}>
            <X size={12} />
          </button>
        </div>

        {step === 1 && (
          <div>
            <div style={{ fontSize: 11, color: "var(--faint)",
                              marginBottom: 8 }}>
              What are you adding?
            </div>
            <div style={{ display: "grid",
                              gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))",
                              gap: 6 }}>
              {EXTENSION_TYPES.map((t) => (
                <button key={t} className="btn ghost"
                            data-testid={`xdr-add-type-${t}`}
                            onClick={() => { setType(t); setStep(2); }}
                            style={{ padding: "6px 8px", fontSize: 11,
                                        borderColor: type === t ? "var(--cyan)" : "var(--border)" }}>
                  {t}
                </button>
              ))}
            </div>
          </div>
        )}

        {step === 2 && (
          <div data-testid="xdr-add-configure">
            <div style={{ fontSize: 11, color: "var(--faint)",
                              marginBottom: 8 }}>
              Configure the manifest for <b>{type}</b>.
            </div>
            {["capability_id", "name", "provider", "version", "vendor"].map((k) => (
              <div key={k} style={{ marginBottom: 6 }}>
                <label className="mono" style={{ fontSize: 10,
                                                                color: "var(--faint)", display: "block" }}>
                  {k}
                </label>
                <input
                  data-testid={`xdr-add-field-${k}`}
                  value={form[k]}
                  onChange={(e) => setForm((f) => ({ ...f, [k]: e.target.value }))}
                  style={{ width: "100%", padding: 4, fontSize: 11,
                              border: "1px solid var(--border)", borderRadius: 3,
                              background: "var(--panel2)", color: "var(--text)",
                              fontFamily: "var(--mono)" }} />
              </div>
            ))}
            <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
              <button className="btn" onClick={() => setStep(1)}
                        style={{ padding: "3px 10px", fontSize: 11 }}>
                Back
              </button>
              <button className="btn primary"
                        onClick={() => setStep(3)}
                        disabled={!form.capability_id || !form.name || !form.provider}
                        data-testid="xdr-add-next-test"
                        style={{ padding: "3px 10px", fontSize: 11 }}>
                Next · Test connection
              </button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div data-testid="xdr-add-test">
            <div style={{ fontSize: 11, color: "var(--faint)",
                              marginBottom: 8 }}>
              Test connection
            </div>
            <div style={{ padding: 8, borderRadius: 3,
                              border: "1px dashed var(--amber)",
                              color: "var(--amber)", fontSize: 11,
                              fontFamily: "var(--mono)" }}>
              TEST CONNECTION UNAVAILABLE · this is a client-side wizard.
              Persist + run test through the future control-plane API
              (POST /api/xdr/extensions/{"{"}id{"}"}/test).
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
              <button className="btn" onClick={() => setStep(2)}
                        style={{ padding: "3px 10px", fontSize: 11 }}>
                Back
              </button>
              <button className="btn primary" onClick={() => setStep(4)}
                        data-testid="xdr-add-next-enable"
                        style={{ padding: "3px 10px", fontSize: 11 }}>
                Next · Review
              </button>
            </div>
          </div>
        )}

        {step === 4 && (
          <div data-testid="xdr-add-review">
            <div style={{ fontSize: 11, color: "var(--faint)",
                              marginBottom: 8 }}>
              Review the manifest that would be persisted
            </div>
            <pre style={{ fontSize: 10, background: "var(--panel2)",
                              border: "1px solid var(--border)",
                              padding: 8, borderRadius: 3, maxHeight: 260,
                              overflow: "auto", color: "var(--text-dim)" }}>
{JSON.stringify({ ...form, type,
                            authentication: [], permissions: [],
                            supported_operations: [],
                            input_schema: {}, output_schema: {},
                            health_check: { kind: "manual", interval_seconds: 3600 },
                            lifecycle: "INSTALLED",
                            adapter_status: "STUB" }, null, 2)}
            </pre>
            <div style={{ marginTop: 8, fontSize: 10.5, color: "var(--faint)" }}>
              Register with{" "}
              <span className="mono" style={{ color: "var(--cyan)" }}>
                POST /api/xdr/extensions
              </span>{" "}(pending control-plane API).
              Until then, add this JSON to{" "}
              <span className="mono">docs/extensions/{type.toLowerCase()}/</span>
              {" "}and commit.
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
              <button className="btn" onClick={() => setStep(3)}
                        style={{ padding: "3px 10px", fontSize: 11 }}>
                Back
              </button>
              <button className="btn primary" onClick={onClose}
                        data-testid="xdr-add-finish"
                        style={{ padding: "3px 10px", fontSize: 11 }}>
                Close
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}


export default function CapabilityHubBody() {
  const [q, setQ]         = useState("");
  const [type, setType]   = useState("all");
  const [wizardOpen, setW] = useState(false);

  const all           = useMemo(() => listAll(), []);
  const validations   = useMemo(() => {
    const map = {};
    for (const v of validateAll()) map[v.id] = v;
    return map;
  }, []);
  const cov           = useMemo(() => coverage(), []);
  const filtered      = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return all.filter((m) => {
      if (type !== "all" && m.type !== type) return false;
      if (!needle) return true;
      return `${m.capability_id} ${m.name} ${m.vendor}
                     ${m.description || ""}`.toLowerCase().includes(needle);
    });
  }, [all, q, type]);

  return (
    <div data-testid="xdr-capability-hub-body">
      <div style={{ display: "flex", alignItems: "center", gap: 12,
                       marginBottom: 10, flexWrap: "wrap" }}>
        <div className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>
          {all.length} extension manifest{all.length === 1 ? "" : "s"} ·{" "}
          {EXTENSION_TYPES.filter((t) => (cov[t]?.total || 0) > 0).length}
          {" "}extension type{EXTENSION_TYPES.length === 1 ? "" : "s"}
        </div>
        <span style={{ flex: 1 }} />
        <div style={{ position: "relative" }}>
          <Search size={11} style={{ position: "absolute", left: 6,
                                                        top: 6, color: "var(--faint)" }} />
          <input
            data-testid="xdr-capability-search"
            placeholder="Search capabilities…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            style={{ padding: "4px 8px 4px 22px", fontSize: 11,
                        width: 240, border: "1px solid var(--border)",
                        borderRadius: 4, background: "var(--panel2)",
                        color: "var(--text)", fontFamily: "var(--mono)" }} />
        </div>
        <select value={type} onChange={(e) => setType(e.target.value)}
                  data-testid="xdr-capability-type-filter"
                  style={{ padding: "4px 6px", fontSize: 11,
                              border: "1px solid var(--border)", borderRadius: 4,
                              background: "var(--panel2)", color: "var(--text)" }}>
          <option value="all">All types</option>
          {EXTENSION_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <button className="btn primary"
                  onClick={() => setW(true)}
                  data-testid="xdr-add-capability-btn"
                  style={{ padding: "3px 10px", fontSize: 11 }}>
          <PlusCircle size={11} /> Add Capability
        </button>
      </div>

      <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))",
                        gap: 8 }}>
        {filtered.map((m) => (
          <CapabilityCard key={m.capability_id} m={m}
                                    validation={validations[m.capability_id]
                                      || { ok: true, missing: [], invalid: [] }} />
        ))}
      </div>

      {filtered.length === 0 && (
        <div style={{ padding: 10, fontSize: 11, color: "var(--faint)",
                          fontFamily: "var(--mono)" }}>
          NO MATCHING CAPABILITIES
        </div>
      )}

      <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--faint)",
                       fontFamily: "var(--mono)" }}>
        source: <span style={{ color: "var(--cyan)" }}>
          docs/extensions/**/*.json
        </span>{" "}· validated against{" "}
        <span style={{ color: "var(--cyan)" }}>extensionContract.js</span>.
        Never fabricates state — every card reflects the manifest's real
        lifecycle field.
      </div>

      {wizardOpen && <AddCapabilityWizard onClose={() => setW(false)} />}
    </div>
  );
}
