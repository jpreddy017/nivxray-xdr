/**
 * InvestigationPivots · Task 3A.
 *
 * Three operational questions, answered by the SERVER and rendered here
 * without interpretation:
 *
 *   1. Telemetry & detection sources — where this incident's belief came
 *      from (product · DSM · collector · detection · endpoint sensor).
 *   2. IOC investigation — the observables the record carries, and for each
 *      one the providers that can be used, per capability.
 *   3. Recommended investigation pivots — deterministic and strictly
 *      artifact-derived: reason → supporting evidence → available action.
 *
 * Rules held in this file:
 *   · No URL is built here. `native_consoles` and every external action URL
 *     come from `/api/incidents/:id/pivots`, which refuses to guess a vendor
 *     console route and refuses to render a pivot the tenant has not
 *     configured. The six states stay distinct.
 *   · External navigation is ANALYST-INITIATED and confirmed: the analyst is
 *     told which third party is about to receive the observable before the
 *     tab opens. NivXRay sends nothing server-side and uses no credential.
 *   · `AUTO_ENRICHMENT` and `EXTERNAL_PIVOT` are reported as two independent
 *     capabilities, so a later enrichment adapter appears in this same
 *     surface without a redesign.
 */
import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowUpRight, ExternalLink, ShieldAlert } from "lucide-react";

import { NxInvSection, NxInvTable, NxInvEmpty, NxState, NxChip, NxButton,
         NxEmpty } from "@/xdr/nx";
import { getIncidentPivots } from "@/lib/incidentsApi";
import { apiErrorText } from "@/xdr/nx/apiError";

const AUTO = "AUTO_ENRICHMENT";
const PIVOT = "EXTERNAL_PIVOT";

const hostOf = (url) => {
  try { return new URL(url).host; } catch { return url; }
};

/** The external-egress gate. An external verification is never a silent
 *  outbound request: the analyst sees the third party and the observable
 *  that reaches it, and confirms. */
function EgressConfirm({ action, observable, onCancel, testid }) {
  return (
    <div className="nx-alert" data-testid={testid}
         data-egress-host={hostOf(action.url)}
         style={{ display: "grid", gap: 6 }}>
      <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <ShieldAlert size={13} />
        <b>External verification · {action.label}</b>
      </span>
      <span>
        Opening <span className="mono">{hostOf(action.url)}</span> in a new tab
        sends <span className="mono">{observable}</span> to a third party.
        NivXRay uses no credential and sends nothing on your behalf.
      </span>
      <span style={{ display: "flex", gap: 6 }}>
        <NxButton testid={`${testid}-confirm`}
                  onClick={() => {
                    window.open(action.url, "_blank", "noopener,noreferrer");
                    onCancel();
                  }}>
          Open {action.label} <ExternalLink size={12} />
        </NxButton>
        <NxButton testid={`${testid}-cancel`} onClick={onCancel}>
          Cancel
        </NxButton>
      </span>
    </div>
  );
}

/** One row of actions for one observable. */
function ActionRow({ actions, observable, testid }) {
  const navigate = useNavigate();
  const [pending, setPending] = useState(null);
  if (!actions?.length) return null;
  return (
    <div style={{ display: "grid", gap: 6 }}>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {actions.map((a) => {
          const key = `${a.kind}-${a.provider}`;
          if (a.state !== "AVAILABLE") {
            return (
              <span key={key} style={{ display: "inline-flex", gap: 4,
                                        alignItems: "center" }}
                    data-testid={`${testid}-blocked-${a.provider}`}>
                <NxChip tone="not_connected" variant="dashed" size="sm">
                  {a.label}
                </NxChip>
                <NxState value={a.state} reason={a.reason}
                         testid={`${testid}-state-${a.provider}`} />
              </span>
            );
          }
          if (a.kind === "INTERNAL") {
            return (
              <NxButton key={key} title={a.reason}
                        testid={`${testid}-internal-${a.provider}`}
                        onClick={() => navigate(a.to)}>
                {a.label} <ArrowUpRight size={12} />
              </NxButton>
            );
          }
          return (
            <NxButton key={key} title={a.reason}
                      testid={`${testid}-external-${a.provider}`}
                      onClick={() => setPending(a)}>
              {a.label} <ExternalLink size={12} />
            </NxButton>
          );
        })}
      </div>
      {pending && (
        <EgressConfirm action={pending} observable={observable}
                       onCancel={() => setPending(null)}
                       testid={`${testid}-egress`} />
      )}
    </div>
  );
}

export default function InvestigationPivots({ incident,
                                              testid = "incident-pivots" }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try { setData(await getIncidentPivots(incident.id)); }
    catch (e) {
      setError(apiErrorText(e, "Investigation pivots could not be resolved."));
    } finally { setLoading(false); }
  }, [incident.id]);
  useEffect(() => { load(); }, [load]);

  if (loading) {
    return <NxInvSection title="Investigation pivots" testid={`${testid}-loading`}>
      <div className="inv-sec__b--pad">Resolving pivots…</div>
    </NxInvSection>;
  }
  if (error) {
    return (
      <NxInvSection title="Investigation pivots" testid={`${testid}-error`}>
        <div className="inv-sec__b--pad">
          <NxEmpty title="NOT AUTHORIZED OR NOT AVAILABLE" hint={error} />
        </div>
      </NxInvSection>
    );
  }

  const origin = data.telemetry_origin || {};
  const observables = data.observables || [];
  const consoles = data.native_consoles || [];
  const recs = data.recommendations || [];
  const verifiable = observables.filter((o) => o.externally_verifiable);

  return (
    <div className="inv" data-testid={testid}>
      {/* ── 1 · Telemetry & detection sources ───────────────────── */}
      <NxInvSection
        title="Telemetry & detection sources"
        subtitle="what produced this incident · every row states the field it was read from"
        actions={<NxState value={origin.state} reason={origin.note}
                          testid={`${testid}-origin-state`} />}
        testid={`${testid}-origin`}
      >
        <NxInvTable
          testid={`${testid}-origin-table`}
          rowKey={(r) => r.origin_kind}
          columns={[
            { key: "origin_kind", label: "Stage", width: 150 },
            { key: "state", label: "State", width: 130,
              render: (r) => <NxState value={r.state} reason={r.detail}
                                      testid={`${testid}-origin-${r.origin_kind.toLowerCase()}-state`} /> },
            { key: "label", label: "Identity" },
            { key: "detail", label: "Recorded fact" },
            { key: "read_from", label: "Read from", width: 240 },
          ]}
          rows={origin.sources || []}
        />
        <div className="inv-sec__b--pad"
             style={{ fontSize: 11, color: "var(--nx-muted)" }}>
          {origin.note}
        </div>
      </NxInvSection>

      {/* ── 2 · IOC investigation ───────────────────────────────── */}
      <NxInvSection
        title="IOC investigation"
        subtitle="observables this incident records · verification is analyst-initiated"
        actions={<NxChip tone="neutral" size="sm">
          {verifiable.length} verifiable of {observables.length}
        </NxChip>}
        testid={`${testid}-iocs`}
      >
        {observables.length === 0 ? (
          <div className="inv-sec__b--pad">
            <NxInvEmpty
              title="This incident records no observable"
              body="Nothing in the incident's iocs field can be verified externally. NivXRay states that rather than offering a lookup with no subject."
              testid={`${testid}-iocs-empty`} />
          </div>
        ) : (
          <div className="inv-sec__b--pad" style={{ display: "grid", gap: 14 }}>
            {observables.map((o, i) => (
              <div key={`${o.kind}-${o.value}`}
                   data-testid={`${testid}-ioc-${i}`}
                   data-ioc-kind={o.kind}
                   style={{ display: "grid", gap: 6, paddingBottom: 10,
                            borderBottom: "1px solid var(--nx-divider)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8,
                              flexWrap: "wrap" }}>
                  <NxChip tone="low" size="sm">{o.kind}</NxChip>
                  <span className="mono" style={{ fontSize: 12.5,
                                                  color: "var(--nx-text)" }}>
                    {o.value}
                  </span>
                  <span style={{ flex: 1 }} />
                  <span style={{ fontSize: 11, color: "var(--nx-muted)" }}>
                    {o.source_field}
                  </span>
                </div>
                {o.externally_verifiable ? (
                  <ActionRow actions={o.actions} observable={o.value}
                             testid={`${testid}-ioc-${i}-actions`} />
                ) : (
                  <span style={{ fontSize: 11.5, color: "var(--nx-muted)" }}
                        data-testid={`${testid}-ioc-${i}-no-provider`}>
                    No external provider verifies a {o.kind} · investigate it
                    inside NivXRay instead.
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </NxInvSection>

      {/* ── 3 · Native consoles (integration-gated) ─────────────── */}
      <NxInvSection
        title="Native console pivots"
        subtitle="offered only where this tenant's own integration record declares the console route and the incident carries the identifier"
        testid={`${testid}-consoles`}
      >
        <NxInvTable
          testid={`${testid}-consoles-table`}
          rowKey={(r) => r.vendor_key}
          columns={[
            { key: "name", label: "Console", width: 240 },
            { key: "state", label: "State", width: 180,
              render: (r) => <NxState value={r.state} reason={r.reason}
                                      testid={`${testid}-console-${r.vendor_key}-state`} /> },
            { key: "required_identifier", label: "Requires", width: 150 },
            { key: "reason", label: "Why" },
            { key: "open", label: "", width: 130,
              render: (r) => (r.state === "AVAILABLE" && r.url ? (
                <NxButton
                  testid={`${testid}-console-${r.vendor_key}-open`}
                  title={`Opens ${hostOf(r.url)} in a new tab`}
                  onClick={() => window.open(r.url, "_blank",
                                             "noopener,noreferrer")}>
                  Open console <ExternalLink size={12} />
                </NxButton>
              ) : null) },
          ]}
          rows={consoles}
        />
      </NxInvSection>

      {/* ── 4 · Recommended investigation pivots ────────────────── */}
      <NxInvSection
        title="Recommended investigation pivots"
        subtitle={recs.length
          ? "derived deterministically from this incident's artifacts — reason, evidence, then the actions that are actually available"
          : "no artifact on this incident justifies a pivot"}
        actions={recs.length
          ? <NxChip tone="neutral" size="sm">{recs.length}</NxChip> : null}
        testid={`${testid}-recommended`}
      >
        {recs.length === 0 ? (
          <div className="inv-sec__b--pad">
            <NxInvEmpty
              title="Nothing is recommended"
              body="No observable or endpoint identity on this incident supports a pivot NivXRay can honestly offer. No model runs here, so an empty list is a true statement rather than generic advice."
              testid={`${testid}-recommended-empty`} />
          </div>
        ) : (
          <div className="inv-sec__b--pad" style={{ display: "grid", gap: 14 }}>
            {recs.map((r, i) => (
              <div key={r.id} data-testid={`${testid}-rec-${i}`}
                   style={{ display: "grid", gap: 4, paddingBottom: 10,
                            borderBottom: "1px solid var(--nx-divider)" }}>
                <strong style={{ fontSize: 12.5, color: "var(--nx-text)" }}>
                  {r.title}
                </strong>
                <span style={{ fontSize: 11.5, color: "var(--nx-text-dim)" }}
                      data-testid={`${testid}-rec-${i}-reason`}>
                  Reason · {r.reason}
                </span>
                <span style={{ fontSize: 11, color: "var(--nx-muted)" }}
                      data-testid={`${testid}-rec-${i}-evidence`}>
                  Evidence ·{" "}
                  {(r.evidence || []).map((e) => `${e.kind} ${e.ref}`)
                    .join(" · ") || "no evidence reference recorded"}
                </span>
                <ActionRow actions={r.actions} observable={r.observable?.value}
                           testid={`${testid}-rec-${i}-actions`} />
              </div>
            ))}
          </div>
        )}
      </NxInvSection>

      {/* ── Provider capability register ────────────────────────── */}
      <NxInvSection
        title="Provider capability register"
        subtitle="AUTO_ENRICHMENT (server-side, event-driven) and EXTERNAL_PIVOT (analyst-initiated deep link) are two independent capabilities"
        testid={`${testid}-providers`}
      >
        <NxInvTable
          testid={`${testid}-providers-table`}
          rowKey={(r) => r.key}
          columns={[
            { key: "name", label: "Provider", width: 220 },
            { key: "classification", label: "Class", width: 170 },
            { key: "observables", label: "Observables", width: 200,
              render: (r) => (r.observables || []).join(" · ") },
            { key: AUTO, label: "Auto enrichment", width: 180,
              render: (r) => <NxState value={r.capabilities[AUTO].state}
                                      reason={r.capabilities[AUTO].reason}
                                      testid={`${testid}-provider-${r.key}-auto`} /> },
            { key: PIVOT, label: "External pivot", width: 170,
              render: (r) => <NxState value={r.capabilities[PIVOT].state}
                                      reason={r.capabilities[PIVOT].reason}
                                      testid={`${testid}-provider-${r.key}-pivot`} /> },
          ]}
          rows={data.providers || []}
        />
        <div className="inv-sec__b--pad"
             style={{ fontSize: 11, color: "var(--nx-muted)" }}>
          No enrichment adapter is registered in this build, so every
          provider that could support server-side enrichment reports
          <strong> not implemented</strong> — a statement about NivXRay, not
          about the provider. Tenant integrations visible to this incident:{" "}
          <span className="mono" data-testid={`${testid}-tenant-integrations`}>
            {(data.tenant_integrations || []).join(", ") || "none"}
          </span>
        </div>
      </NxInvSection>
    </div>
  );
}
