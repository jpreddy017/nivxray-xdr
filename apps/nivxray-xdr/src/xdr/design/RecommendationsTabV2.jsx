/**
 * RecommendationsTabV2 · Round 27 (Round 24.9 grammar).
 *
 * This is the migrated Recommendations surface — the ONLY grammar
 * where the flagship Execute experience is allowed to ship, per
 * owner-lock.  Behind the ``?design=v2`` feature flag.  Legacy
 * `RecommendationsTab.jsx` stays untouched.
 *
 * Every recommendation renders as a composition of the five
 * Round 24.9 primitives:
 *
 *   <Entity>         → the observed target of the recommendation
 *   <EvidenceState>  → applicability truth-state (APPLICABLE /
 *                       CAPABILITY_UNAVAILABLE / …)
 *   <Provenance>     → derivation chain
 *                       (Telemetry → Canonical → Correlation → Mapping)
 *   <Action>         → Execute · capability-gated by the ACTUAL
 *                       adapter capability_matrix; the UI is NEVER
 *                       the security boundary — the backend
 *                       independently rejects a NOT_SUPPORTED /
 *                       UNAVAILABLE action with 409.
 *
 * The UI reads the same synthesizer endpoint as the legacy tab so
 * there is no data-shape divergence:
 *
 *   POST /admin/content-supply-chain/response/{incident_id}/recompute
 *
 * Execute calls the Round 27 endpoint:
 *
 *   POST /api/xdr/vendor/cortex/actions
 */
import React, { useCallback, useEffect, useState } from "react";
import { Play, RefreshCcw, ShieldAlert } from "lucide-react";

import api from "@/lib/api";
import Entity from "@/xdr/design/Entity";
import EvidenceState from "@/xdr/design/EvidenceState";
import Provenance from "@/xdr/design/Provenance";
import Action, { ActionGroup } from "@/xdr/design/Action";
import "@/xdr/design/tokens.css";

const BACKEND =
  (typeof process !== "undefined" && process.env
    && process.env.REACT_APP_BACKEND_URL) || "";

// Map the synthesizer's applicability enum to closed EvidenceState values.
function stateForApplicability(app) {
  switch (app) {
    case "APPLICABLE":             return { state: "observed",    reason: null };
    case "ALREADY_EXECUTED":       return { state: "actioned",    reason: "ALREADY_EXECUTED" };
    case "CAPABILITY_UNAVAILABLE": return { state: "unavailable", reason: "CAPABILITY_UNAVAILABLE" };
    case "INSUFFICIENT_EVIDENCE":  return { state: "missing",     reason: "INSUFFICIENT_EVIDENCE" };
    case "NOT_APPLICABLE":         return { state: "suppressed",  reason: "NOT_APPLICABLE" };
    case "SUPERSEDED":             return { state: "suppressed",  reason: "SUPERSEDED" };
    default:                        return { state: "missing",     reason: String(app || "UNKNOWN") };
  }
}

// Cortex-adapter capability id → canonical action id.  Only the
// adapter (backend) is authoritative; this mapping exists ONLY to
// pre-render the Execute button state so the analyst does not click
// something the backend will just reject.
const ACTION_FOR_SUGGESTION = {
  "isolate_endpoint":  "ENDPOINT_ISOLATE",
  "contain_process":   "PROCESS_KILL",
  "block_hash":        "BLOCK_HASH",
  "disable_user":      "DISABLE_USER",
  "revoke_token":      "REVOKE_TOKEN",
};

function capabilityStateFor(reco) {
  // Prefer the synthesizer's explicit `capability` block; fall back to
  // `applicability` if the synthesizer already resolved capability
  // internally.
  const s = reco?.capability?.state || reco?.capability_state;
  if (s === "AVAILABLE")     return "cap-full";
  if (s === "UNAVAILABLE")   return "cap-unavailable";
  if (s === "FAILED")        return "cap-degraded";
  if (s === "NOT_SUPPORTED") return "cap-unavailable";
  if (reco?.applicability === "APPLICABLE") return "cap-full";
  return "cap-standby";
}

export default function RecommendationsTabV2({ incident }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr]         = useState(null);
  const [busyId, setBusyId]   = useState(null);
  const [flash, setFlash]     = useState(null);

  const load = useCallback(async () => {
    if (!incident?.id) return;
    setLoading(true); setErr(null);
    try {
      const r = await api.post(
        `/admin/content-supply-chain/response/${incident.id}/recompute`);
      setData(r.data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "unavailable");
    } finally { setLoading(false); }
  }, [incident?.id]);

  useEffect(() => { load(); }, [load]);

  const onExecute = async (reco) => {
    setBusyId(reco.recommendation_id); setFlash(null);
    try {
      const target = reco.entity || reco.observed_entity || {};
      const suggestion = reco.suggested_action || reco.action;
      const canonical  = ACTION_FOR_SUGGESTION[suggestion] || suggestion;
      const { data: r } = await api.post(
        `${BACKEND.replace(/\/+$/, "")}/api/xdr/vendor/cortex/actions`,
        {
          integration_id:    reco.integration_id
                                  || incident?.source_integration_id,
          xdr_incident_id:   incident?.xdr_incident_id || incident?.id,
          recommendation_id: reco.recommendation_id,
          action_id:         canonical,
          entity: {
            kind:   target.kind  || target.type || "host",
            value:  target.value || target.name || target.host || "",
            source_event_id: target.source_event_id,
          },
        },
        { timeout: 20000 });
      setFlash({
        recommendation_id: reco.recommendation_id,
        ok:               r.ok,
        result_state:     r.result_state,
        vendor_action_id: r.vendor_action_id,
        evidence_event_id: r.evidence_event_id,
        detail:           r.detail,
      });
      await load();
    } catch (e) {
      const d = e?.response?.data?.detail;
      setFlash({
        recommendation_id: reco.recommendation_id,
        ok: false,
        result_state: (typeof d === "object" && d?.error)
                            ? d.error.toUpperCase()
                            : "EXECUTION_FAILED",
        detail: typeof d === "object" ? JSON.stringify(d) : (d || e?.message),
      });
    } finally { setBusyId(null); }
  };

  // The synthesizer envelope has evolved over the rounds; accept the
  // three shapes it currently emits without breaking on any of them.
  const recos = Array.isArray(data?.recommendations) ? data.recommendations
                    : Array.isArray(data?.recommendations?.entries) ? data.recommendations.entries
                    : Array.isArray(data?.result?.recommendations) ? data.result.recommendations
                    : Array.isArray(data?.entries) ? data.entries
                    : [];

  return (
    <div className="evops evops-canvas" data-testid="recommendations-tab-v2">
      <div className="evops-band">
        <div>
          <div className="evops-band__eyebrow">Incident › Recommendations</div>
          <div className="evops-band__title">Evidence-derived response</div>
        </div>
        <div className="evops-band__spacer" />
        <div className="evops-band__source">
          POST /response/{incident?.id}/recompute
        </div>
        <Action label="Refresh" icon={RefreshCcw} onRun={load}
                   testid="reco-refresh" />
      </div>

      {loading && <div className="evops-hint">Loading real recommendations …</div>}
      {err && (
        <div className="evops-empty" data-testid="reco-error">
          <div className="evops-empty__title">Recommendations unavailable</div>
          <div className="evops-empty__reason">{err}</div>
        </div>
      )}
      {!loading && !err && recos.length === 0 && (
        <div className="evops-empty" data-testid="reco-empty">
          <div className="evops-empty__title">No recommendations synthesised</div>
          <div className="evops-empty__reason">
            The synthesizer found no evidence-derived response candidates for
            this incident.  NivXRay XDR never renders a generic "verb → static
            recommendation" fallback here.
          </div>
        </div>
      )}

      {recos.map((reco) => {
        const applic = stateForApplicability(reco.applicability);
        const cap    = capabilityStateFor(reco);
        const canExec = applic.state === "observed" &&
                            (cap === "cap-full" || cap === "cap-degraded");
        const target = reco.entity || reco.observed_entity || {};
        const chain = [
          { layer: "telemetry", value: reco.provenance?.telemetry,
            present: !!reco.provenance?.telemetry },
          { layer: "canonical", value: reco.provenance?.canonical_event_id
                                            || target.source_event_id,
            present: !!(reco.provenance?.canonical_event_id
                            || target.source_event_id) },
          { layer: "correlate", value: reco.provenance?.correlation_rule_id,
            present: !!reco.provenance?.correlation_rule_id },
          { layer: "mapping",   value: reco.framework_rationale
                                            || reco.mitre_technique,
            present: !!(reco.framework_rationale || reco.mitre_technique) },
        ];
        const fired = flash && flash.recommendation_id === reco.recommendation_id;
        return (
          <div
            className="evops-section"
            key={reco.recommendation_id}
            data-testid={`reco-${reco.recommendation_id}`}
          >
            <div className="evops-section__head">
              <Entity
                kind={target.kind === "user" ? "user"
                        : target.kind === "process" ? "rule"
                        : target.kind === "file"    ? "source"
                        : "host"}
                name={target.value || target.name || reco.title
                          || reco.suggested_action || "unnamed target"}
                id={target.source_event_id || target.id}
              />
              <div className="evops-section__spacer" />
              <EvidenceState state={applic.state} reason={applic.reason}
                                 testid={`reco-applic-${reco.recommendation_id}`} />
              <ActionGroup>
                <Action
                  label={reco.suggested_action ? `Execute · ${reco.suggested_action}` : "Execute"}
                  icon={Play}
                  tone="primary"
                  capability={cap}
                  forceDisabled={!canExec || busyId === reco.recommendation_id}
                  reason={canExec ? null
                              : (applic.reason || "CAPABILITY_UNAVAILABLE")}
                  onRun={() => onExecute(reco)}
                  testid={`reco-execute-${reco.recommendation_id}`}
                />
              </ActionGroup>
            </div>
            <div className="evops-hint" style={{ marginTop: 8 }}>
              {reco.rationale || reco.reason
                  || "Why NivXRay XDR recommends this: rationale not surfaced by the synthesizer."}
            </div>
            <div style={{ marginTop: 10 }}>
              <Provenance chain={chain} testid={`reco-prov-${reco.recommendation_id}`} />
            </div>
            {fired && (
              <div
                className="evops-mono"
                data-testid={`reco-flash-${reco.recommendation_id}`}
                style={{ marginTop: 12, padding: 10,
                            border: `1px solid ${flash.ok
                                ? "var(--evops-ev-actioned-fg)"
                                : "var(--evops-ev-unavail-fg)"}`,
                            color: flash.ok
                                ? "var(--evops-ev-actioned-fg)"
                                : "var(--evops-ev-unavail-fg)" }}>
                <strong>{flash.result_state}</strong>
                {flash.vendor_action_id
                  ? <> · vendor_action_id {flash.vendor_action_id}</>
                  : null}
                {flash.evidence_event_id
                  ? <> · evidence {flash.evidence_event_id}</>
                  : null}
                {flash.detail
                  ? <div style={{ marginTop: 4 }}>{flash.detail}</div>
                  : null}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
