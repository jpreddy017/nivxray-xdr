/**
 * Round 25a · CortexOnboardingWizard.
 *
 * Typed onboarding for Palo Alto Cortex XDR — never a generic REST
 * connector.  Progressive-disclosure stages, each rendered as an
 * `<EvidenceState>` with a `<Provenance>` derivation chain.
 *
 * Locked stage grammar (owner · Round 25a):
 *
 *   Identity        → the vendor is chosen           (observed)
 *   Authentication  → operator supplies credentials  (observed | missing)
 *   Connectivity    → real /healthcheck against vendor
 *     · pre-submit                       → NOT_OBSERVED · NO_LIVE_TENANT
 *     · vendor 401/403                   → UNAVAILABLE · AUTHENTICATION_FAILED
 *     · DNS/timeout/transport            → UNAVAILABLE · CONNECTION_FAILED
 *     · 2xx                              → OBSERVED   · VENDOR_REACHED
 *   Capability      → adapter probe of every canonical action
 *     · connect failed                   → NOT RUN
 *     · connect ok                       → per-action AVAILABLE/UNAVAILABLE/FAILED/NOT_SUPPORTED
 *   Binding         → persist into xdr_integrations
 *     · connect not ok                   → LOCKED
 *     · connect ok, unsaved              → PENDING
 *     · saved                            → ACTIONED
 *
 * Credential handling:
 *   • API key is held in a React ref, cleared on submit.
 *   • Never rendered back in the DOM after submit (input is
 *     `type="password"` and value is only shown while the operator
 *     is typing).
 *   • Backend response is redacted to `***`.
 */
import React, { useMemo, useRef, useState } from "react";
import axios from "axios";
import { Plug, X, ShieldCheck, Server, Radar, Lock, CheckCircle2 } from "lucide-react";

import Entity from "./Entity";
import EvidenceState from "./EvidenceState";
import Provenance from "./Provenance";
import Action, { ActionGroup } from "./Action";

const BACKEND =
  (typeof process !== "undefined" && process.env && process.env.REACT_APP_BACKEND_URL) || "";
const API = BACKEND ? `${BACKEND.replace(/\/+$/, "")}/api/xdr/vendor/cortex` : "";

const STAGE_LABELS = [
  { key: "identity",       label: "Identity" },
  { key: "authentication", label: "Authentication" },
  { key: "connectivity",   label: "Connectivity" },
  { key: "capability",     label: "Capability" },
  { key: "binding",        label: "Binding" },
];

const REASON_LABEL = {
  NO_LIVE_TENANT:         "no credentials submitted yet",
  AUTHENTICATION_FAILED:  "vendor rejected credentials",
  CONNECTION_FAILED:      "vendor unreachable",
  VENDOR_ERROR:           "vendor returned an error",
  VENDOR_REACHED:         "healthcheck ok",
  UNEXPECTED_STATUS:      "vendor returned an unexpected status",
};

export default function CortexOnboardingWizard({ onClose, onBound }) {
  // Form state — API key held in a ref, never in setState, so React
  // devtools / DOM inspection never expose it after submit.
  const [label,      setLabel]      = useState("Cortex XDR");
  const [baseUrl,    setBaseUrl]    = useState("");
  const [apiKeyId,   setApiKeyId]   = useState("");
  const [tenant,     setTenant]     = useState("");
  const [advApi,     setAdvApi]     = useState(true);
  const apiKeyRef = useRef("");

  // Probe/persist state
  const [busy,        setBusy]        = useState(false);
  const [probe,       setProbe]       = useState(null);   // last probe payload
  const [saveError,   setSaveError]   = useState(null);
  const [savedId,     setSavedId]     = useState(null);

  const credsSupplied = !!(baseUrl && apiKeyId && apiKeyRef.current);

  const runProbe = async () => {
    if (!API) { setSaveError("REACT_APP_BACKEND_URL not set"); return; }
    setBusy(true); setSaveError(null);
    try {
      const { data } = await axios.post(`${API}/probe`, {
        base_url:    baseUrl,
        api_key_id:  apiKeyId,
        api_key:     apiKeyRef.current,
        tenant:      tenant || null,
        advanced_api: advApi,
      }, { timeout: 15000 });
      setProbe(data);
    } catch (e) {
      setProbe(null);
      setSaveError(e?.response?.data?.detail || e?.message || "probe failed");
    } finally { setBusy(false); }
  };

  const runBind = async () => {
    setBusy(true); setSaveError(null);
    try {
      const { data } = await axios.post(`${API}/connections`, {
        label,
        base_url:    baseUrl,
        api_key_id:  apiKeyId,
        api_key:     apiKeyRef.current,
        tenant:      tenant || null,
        advanced_api: advApi,
      }, { timeout: 15000 });
      // Scrub the key from every runtime holder we control.
      apiKeyRef.current = "";
      setSavedId(data?.integration_id || null);
      onBound && onBound(data);
    } catch (e) {
      const d = e?.response?.data?.detail;
      setSaveError(
        typeof d === "object"
          ? `${d.reason || "bind_failed"} · ${d.vendor_detail || ""}`
          : (d || e?.message || "bind failed"),
      );
    } finally { setBusy(false); }
  };

  const stages = deriveStages({ credsSupplied, probe, savedId });

  return (
    <div
      role="dialog"
      aria-label="Cortex XDR onboarding"
      data-testid="cortex-wizard"
      style={{
        position: "fixed", inset: 0,
        background: "rgba(17, 24, 39, 0.35)",
        display: "flex", justifyContent: "flex-end", zIndex: 70,
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 640, maxWidth: "100%", height: "100%",
          background: "var(--nx-surf-primary)",
          borderLeft: "1px solid var(--nx-bd-strong)",
          padding: "22px 26px 32px",
          overflow: "auto",
          fontFamily: "var(--sans)",
        }}
        className="evops"
      >
        <Header onClose={onClose} bound={!!savedId} />

        <StageTrack stages={stages} />

        {savedId ? (
          <BoundReceipt savedId={savedId} onClose={onClose} />
        ) : (
          <>
            <AuthenticationSection
              label={label} setLabel={setLabel}
              baseUrl={baseUrl} setBaseUrl={setBaseUrl}
              apiKeyId={apiKeyId} setApiKeyId={setApiKeyId}
              tenant={tenant} setTenant={setTenant}
              advApi={advApi} setAdvApi={setAdvApi}
              apiKeyRef={apiKeyRef}
              disabled={busy}
            />
            <ConnectivitySection
              probe={probe} credsSupplied={credsSupplied}
              busy={busy} runProbe={runProbe}
            />
            <CapabilitySection probe={probe} />
            <BindingSection
              probe={probe} busy={busy} saveError={saveError}
              runBind={runBind}
            />
          </>
        )}
      </div>
    </div>
  );
}

// ── Header ─────────────────────────────────────────────────────
function Header({ onClose, bound }) {
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: 12,
                     marginBottom: 20 }}>
      <div>
        <div className="evops-band__eyebrow">Admin › Integrations › Add source</div>
        <div className="evops-band__title" style={{ fontSize: 16 }}>
          {bound ? "Cortex XDR · bound" : "Onboard Palo Alto Cortex XDR"}
        </div>
      </div>
      <div style={{ flex: 1 }} />
      <button type="button" className="evops-action" onClick={onClose}
              data-testid="cortex-wizard-close">
        <X size={12} /> Close
      </button>
    </div>
  );
}

// ── Stage track (the "evidence establishment" pill row) ────────
function StageTrack({ stages }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)",
                     gap: 8, marginBottom: 26 }}
            data-testid="cortex-stage-track">
      {STAGE_LABELS.map((s, i) => {
        const st = stages[s.key] || { state: "cap-standby", reason: "PENDING" };
        return (
          <div key={s.key} style={{ display: "flex", flexDirection: "column", gap: 4 }}
                data-testid={`cortex-stage-${s.key}`}>
            <div className="evops-band__eyebrow">{`0${i + 1} · ${s.label}`}</div>
            <EvidenceState state={st.state} reason={st.reason} />
          </div>
        );
      })}
    </div>
  );
}

// ── Authentication section ─────────────────────────────────────
function AuthenticationSection({
  label, setLabel, baseUrl, setBaseUrl, apiKeyId, setApiKeyId,
  tenant, setTenant, advApi, setAdvApi, apiKeyRef, disabled,
}) {
  return (
    <section style={{ marginBottom: 22 }}>
      <div className="evops-section__head">
        <div className="evops-section__eyebrow">02 · Authentication</div>
        <div className="evops-section__spacer" />
        <div className="evops-band__source">POST /api/xdr/vendor/cortex/probe</div>
      </div>
      <Provenance chain={[
        { layer: "telemetry", value: "Cortex XDR REST API", present: true },
        { layer: "canonical", value: "xdr_integrations.credentials", present: true },
        { layer: "correlate", value: null, present: false },
        { layer: "mapping",   value: null, present: false },
      ]} />
      <div style={{ display: "grid", gap: 12, marginTop: 12 }}>
        <Field label="Label">
          <input value={label} onChange={(e) => setLabel(e.target.value)}
                    disabled={disabled}
                    data-testid="cortex-field-label"
                    placeholder="e.g. Cortex XDR · Corp US" />
        </Field>
        <Field label="Cortex FQDN"
                 hint="Advanced-API base URL from your Cortex tenant · Settings > Configurations > API Keys.">
          <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
                    disabled={disabled}
                    data-testid="cortex-field-base-url"
                    placeholder="https://api-yourorg.xdr.us.paloaltonetworks.com" />
        </Field>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <Field label="API Key ID"
                   hint="Numeric identifier shown next to the key in Cortex.">
            <input value={apiKeyId} onChange={(e) => setApiKeyId(e.target.value)}
                      disabled={disabled}
                      data-testid="cortex-field-api-key-id"
                      placeholder="42" />
          </Field>
          <Field label="Tenant (optional)"
                   hint="Only if your Cortex FQDN is multi-tenant.">
            <input value={tenant} onChange={(e) => setTenant(e.target.value)}
                      disabled={disabled}
                      data-testid="cortex-field-tenant" />
          </Field>
        </div>
        <Field label="API Key" hint="Advanced-API secret · write-only · never rendered back.">
          <input type="password"
                    autoComplete="new-password"
                    disabled={disabled}
                    data-testid="cortex-field-api-key"
                    placeholder="write-only · sent once, redacted on read"
                    onChange={(e) => { apiKeyRef.current = e.target.value; }} />
        </Field>
        <label style={{ display: "flex", alignItems: "center", gap: 8,
                            fontSize: 12, color: "var(--nx-muted)" }}>
          <input type="checkbox" checked={advApi}
                    onChange={(e) => setAdvApi(e.target.checked)}
                    disabled={disabled}
                    data-testid="cortex-field-advanced-api" />
          Advanced API (required for response actions · isolate host,
          terminate process, block hash)
        </label>
      </div>
    </section>
  );
}

function Field({ label, hint, children }) {
  return (
    <div>
      <div className="evops-band__eyebrow" style={{ marginBottom: 4 }}>{label}</div>
      {React.cloneElement(children, {
        className: "x-input",
        style: {
          width: "100%", padding: "6px 10px", borderRadius: 4,
          border: "1px solid var(--nx-bd-strong)",
          background: "var(--nx-surf-inset)",
          fontFamily: label.toLowerCase().includes("key")
                          ? "var(--mono)" : "var(--sans)",
          fontSize: 13,
        },
      })}
      {hint && <div className="evops-hint" style={{ marginTop: 3 }}>{hint}</div>}
    </div>
  );
}

// ── Connectivity section (real probe) ──────────────────────────
function ConnectivitySection({ probe, credsSupplied, busy, runProbe }) {
  const state = deriveConnectivityState(probe, credsSupplied);
  return (
    <section style={{ marginBottom: 22 }}>
      <div className="evops-section__head">
        <div className="evops-section__eyebrow">03 · Connectivity</div>
        <div className="evops-section__spacer" />
        <EvidenceState state={state.state} reason={state.reason} testid="cortex-connectivity-state" />
        <Action
          label={probe ? "Re-probe" : "Test connection"}
          icon={Radar}
          tone="primary"
          forceDisabled={busy || !credsSupplied}
          reason={credsSupplied ? null : "NO_CREDENTIALS"}
          onRun={runProbe}
          testid="cortex-connectivity-run"
        />
      </div>
      <div className="evops-hint" style={{ marginTop: 6 }}>
        Runs <code>connect()</code> against the Cortex Advanced-API
        healthcheck.  NivXRay renders the vendor's actual response —
        never a synthetic success.
      </div>
      {probe && (
        <div className="evops-mono" style={{ marginTop: 8 }}
               data-testid="cortex-connectivity-detail">
          {probe.connect.detail}
          {probe.connect.vendor_reference
            ? <span style={{ marginLeft: 8, color: "var(--nx-muted)" }}>
                · vendor_ref {probe.connect.vendor_reference}
              </span>
            : null}
        </div>
      )}
    </section>
  );
}

// ── Capability section (real per-action probe) ─────────────────
function CapabilitySection({ probe }) {
  const connectOk = probe?.connect?.ok;
  const rows = probe?.capabilities || [];
  return (
    <section style={{ marginBottom: 22 }}>
      <div className="evops-section__head">
        <div className="evops-section__eyebrow">04 · Capability</div>
        <div className="evops-section__spacer" />
        <EvidenceState
          state={connectOk ? "observed" : "suppressed"}
          reason={connectOk ? null : "NOT_RUN · awaiting connectivity"}
          testid="cortex-capability-state"
        />
      </div>
      {!connectOk && (
        <div className="evops-hint" style={{ marginTop: 6 }}>
          Capability probe is deferred until connectivity is established.
          Each canonical action will render its authoritative state —
          AVAILABLE, UNAVAILABLE, FAILED or NOT_SUPPORTED — never inferred
          from credential presence.
        </div>
      )}
      {connectOk && rows.length > 0 && (
        <div className="evops-roster" data-testid="cortex-capability-list"
                style={{ marginTop: 6 }}>
          {rows.map((r) => (
            <div key={r.action_id} className="evops-roster__row"
                    style={{ gridTemplateColumns: "1.4fr 1fr 2fr" }}
                    data-testid={`cortex-cap-${r.action_id}`}>
              <Entity kind="rule" name={humanizeAction(r.action_id)}
                          id={r.action_id} />
              <EvidenceState
                state={mapCapabilityState(r.state)}
                reason={r.state}
              />
              <div className="evops-hint" style={{ whiteSpace: "normal" }}>
                {r.detail || "no vendor detail returned"}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

// ── Binding section ────────────────────────────────────────────
function BindingSection({ probe, busy, saveError, runBind }) {
  const canBind = probe?.connect?.ok;
  const state = canBind ? "cap-ingest" : "cap-standby";
  const reason = canBind ? "READY_TO_BIND" : "LOCKED · awaiting successful probe";
  return (
    <section>
      <div className="evops-section__head">
        <div className="evops-section__eyebrow">05 · Binding</div>
        <div className="evops-section__spacer" />
        <EvidenceState state={state} reason={reason} testid="cortex-binding-state" />
        <Action
          label="Bind & Activate"
          icon={CheckCircle2}
          tone="primary"
          forceDisabled={busy || !canBind}
          reason={canBind ? null : "AWAITING_PROBE"}
          onRun={runBind}
          testid="cortex-binding-run"
        />
      </div>
      <div className="evops-hint" style={{ marginTop: 6 }}>
        On bind, NivXRay writes the integration record into
        <span className="evops-mono"> xdr_integrations</span> (Round 24
        contract).  The API key is encrypted at rest and never returned
        by any subsequent read.
      </div>
      {saveError && (
        <div className="evops-mono" style={{
          marginTop: 8, padding: 8,
          border: "1px solid var(--evops-ev-unavail-fg)",
          color: "var(--evops-ev-unavail-fg)", borderRadius: 3,
        }} data-testid="cortex-binding-error">
          {saveError}
        </div>
      )}
    </section>
  );
}

function BoundReceipt({ savedId, onClose }) {
  return (
    <section data-testid="cortex-wizard-bound">
      <div className="evops-section__head">
        <div className="evops-section__eyebrow">Integration bound</div>
        <div className="evops-section__spacer" />
        <EvidenceState state="actioned" label="Active" />
      </div>
      <div style={{ marginTop: 10 }}>
        <Entity kind="adapter" name="Palo Alto Cortex XDR" id={savedId}
                    size="lg" />
      </div>
      <Provenance chain={[
        { layer: "telemetry", value: "Cortex Advanced API", present: true },
        { layer: "canonical", value: "xdr_integrations", present: true },
        { layer: "correlate", value: "capability_matrix", present: true },
        { layer: "mapping",   value: "edr.* → action_id", present: true },
      ]} />
      <div style={{ marginTop: 18 }}>
        <ActionGroup>
          <Action label="Close" onRun={onClose} tone="primary" />
        </ActionGroup>
      </div>
      <div className="evops-hint" style={{ marginTop: 10 }}>
        Round 25b (envelope-encrypted vault) will replace the interim
        Fernet envelope currently protecting this key at rest.
      </div>
    </section>
  );
}

// ── Pure derivation helpers ────────────────────────────────────
function deriveStages({ credsSupplied, probe, savedId }) {
  const identity = { state: "observed", reason: "PALO_ALTO_CORTEX_XDR" };
  const auth = credsSupplied
    ? { state: "observed", reason: "CREDENTIALS_SUBMITTED" }
    : { state: "missing",  reason: "AWAITING_CREDENTIALS" };
  const conn = deriveConnectivityState(probe, credsSupplied);
  const cap = !probe?.connect?.ok
    ? { state: "suppressed", reason: "NOT_RUN" }
    : (probe.capabilities?.length
        ? { state: "observed", reason: "PROBED" }
        : { state: "missing",  reason: "NO_ACTIONS_PROBED" });
  const bind = savedId
    ? { state: "actioned", reason: "ACTIVE" }
    : (probe?.connect?.ok
        ? { state: "cap-ingest", reason: "READY_TO_BIND" }
        : { state: "cap-standby", reason: "LOCKED" });
  return { identity, authentication: auth, connectivity: conn,
             capability: cap, binding: bind };
}

function deriveConnectivityState(probe, credsSupplied) {
  if (!credsSupplied && !probe) {
    return { state: "missing",     reason: "NO_LIVE_TENANT" };
  }
  if (!probe) {
    return { state: "missing",     reason: "AWAITING_PROBE" };
  }
  if (probe.connect.ok) {
    return { state: "observed",    reason: "VENDOR_REACHED" };
  }
  const r = probe.connect.reason;
  const label = REASON_LABEL[r] || r || "unknown";
  return { state: "unavailable", reason: `${r || "UNKNOWN"} · ${label}` };
}

function mapCapabilityState(state) {
  if (state === "AVAILABLE")     return "observed";
  if (state === "NOT_SUPPORTED") return "suppressed";
  if (state === "FAILED")        return "unavailable";
  return "missing"; // UNAVAILABLE
}

function humanizeAction(id) {
  return id.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
