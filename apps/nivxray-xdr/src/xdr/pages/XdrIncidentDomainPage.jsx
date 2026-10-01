/**
 * XdrIncidentDomainPage · `/xdr/incidents/:id/domain/:domainKey`
 *
 * The incident-scoped domain surface: the incident stays anchored in the
 * page header (so the analyst never loses which record they are in), then
 * the domain states — truthfully — what it can and cannot answer.
 *
 * Task 2 migration: rebuilt on `xdr/nx/` primitives. The bespoke context
 * strip, the hand-rolled state badge and the legacy `--faint/--panel2/.btn`
 * palette are gone; state tokens now render through `NxState`, which keeps
 * the backend token in `data-nx-state`.
 *
 * Nothing about the data changed. `identity/network/email/cloud` are NOT
 * CONNECTED, `files` has NOT ESTABLISHED an incident-scoped file lane, and
 * `endpoints` pivots to the resolver, which either resolves an
 * authoritative endpoint or refuses explicitly.
 */
import React, { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ArrowUpRight, Radar } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import {
  NxPageShell, NxSection, NxFacts, NxKeyFact, NxState, NxButton, NxEmpty,
  NxSkeleton, NxVerdict, NxEntity,
} from "@/xdr/nx";
import { DOMAIN_META } from "@/xdr/domains/domainMeta";
import { getIncident } from "@/lib/incidentsApi";
import { isCrossOrigin, productHref } from "@/productOrigins";
import { apiErrorText } from "@/xdr/nx/apiError";

export default function XdrIncidentDomainPage() {
  const { id, domainKey } = useParams();
  const navigate = useNavigate();
  const [incident, setIncident] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancel = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const data = await getIncident(id);
        if (!cancel) setIncident(data);
      } catch (e) {
        if (!cancel) setError(apiErrorText(e, "Failed to load incident."));
      } finally {
        if (!cancel) setLoading(false);
      }
    })();
    return () => { cancel = true; };
  }, [id]);

  const meta = DOMAIN_META[domainKey];
  const ep = incident?.endpoint_campaign || null;
  const host = ep?.hostname
    || incident?.ssot?.investigation_object?.host
    || incident?.ssot?.investigation_object?.device?.hostname
    || null;

  const openTrajectory = () => {
    const qs = new URLSearchParams({ incident_id: String(id) });
    if (host) qs.set("device", host);
    const path = `/edr/trajectory?${qs.toString()}`;
    if (isCrossOrigin("edr")) window.location.assign(productHref("edr", path));
    else navigate(path);
  };

  return (
    <XdrShell>
      <NxPageShell
        eyebrow={`Incident · ${incident?.number || id}`}
        title={meta ? `${meta.label} domain` : "Unknown domain"}
        description={meta?.subtitle
          || "This domain key is not part of the incident domain taxonomy."}
        testid="xdr-incident-domain-page"
        action={
          <NxButton onClick={() => navigate(`/xdr/incidents/${id}`)}
                    testid="xdr-domain-back-to-incident">
            Back to incident <ArrowUpRight size={13} />
          </NxButton>
        }
      >
        {loading && (
          <div data-testid="xdr-incident-domain-loading">
            <NxSkeleton width="52%" height={14} />
          </div>
        )}

        {!loading && error && (
          <NxEmpty title="This incident could not be loaded"
                   hint={String(error)}
                   data-testid="xdr-incident-domain-error" />
        )}

        {!loading && !error && !meta && (
          <NxEmpty title="NOT AVAILABLE"
                   hint={`Unknown domain "${domainKey}". The incident domain taxonomy is fixed: endpoints, identity, files, network, email, cloud.`}
                   data-testid="xdr-incident-domain-unknown" />
        )}

        {!loading && !error && incident && meta && (
          <>
            <NxSection title="Incident context"
                       aside={meta.label}
                       testid="xdr-incident-domain-context">
              <NxFacts columns={3}>
                <NxKeyFact label="Incident" mono
                           value={incident.number || incident.id}
                           testid="xdr-domain-ctx-incident" />
                <NxKeyFact label="Verdict"
                           value={<NxVerdict
                             value={incident.verdict_card?.verdict
                               || incident.severity}
                             title={incident.verdict_card?.reason} />}
                           testid="xdr-domain-ctx-verdict" />
                <NxKeyFact label="State"
                           value={<NxState value={incident.state} />}
                           testid="xdr-domain-ctx-state" />
                <NxKeyFact label="Customer" value={incident.tenant}
                           reason="No customer attribution on this record"
                           testid="xdr-domain-ctx-customer" />
                <NxKeyFact label="Endpoint"
                           value={ep && (ep.hostname || ep.endpoint_id)
                             ? <NxEntity kind="device"
                                         value={ep.hostname || ep.endpoint_id}
                                         secondary={ep.hostname
                                           ? ep.endpoint_id : null} />
                             : null}
                           reason="This incident cites no endpoint"
                           testid="xdr-domain-ctx-endpoint" />
                <NxKeyFact label="Last activity" mono
                           value={ep?.last_activity_at
                             || incident.updated_at || null}
                           reason="Not recorded"
                           testid="xdr-domain-ctx-activity" />
              </NxFacts>
            </NxSection>

            <DomainBody incident={incident} meta={meta} host={host}
                        onOpenTrajectory={openTrajectory} />
          </>
        )}
      </NxPageShell>
    </XdrShell>
  );
}

function DomainBody({ incident, meta, host, onOpenTrajectory }) {
  if (!meta.connected) {
    return (
      <NxSection title={meta.label}
                 aside={<NxState value="NOT_CONNECTED"
                                 reason={`integration required · ${meta.integration}`}
                                 testid="xdr-domain-state-not_connected" />}
                 note={`Cross-incident ${meta.label.toLowerCase()} telemetry is
                        not wired for this tenant. NivXRay XDR does not
                        fabricate it — this state is shown so an empty pane is
                        never read as a positive security conclusion.`}
                 testid={`xdr-incident-domain-body-${meta.key}`}>
        <NxFacts columns={2}>
          <NxKeyFact label="Integration required" value={meta.integration}
                     testid="xdr-domain-integration" />
          <NxKeyFact label="Scope to configure" mono
                     value={incident?.tenant || incident?.user_email || null}
                     reason="No tenant recorded on this incident"
                     testid="xdr-domain-scope" />
        </NxFacts>
        <ol className="nx-sec-note" style={{ margin: "8px 0 10px 18px" }}>
          <li>Configure the <b>{meta.integration}</b> connector in
              Administration → Integrations.</li>
          <li>Point it at this tenant's scope.</li>
          <li>Re-open the <b>{meta.label}</b> domain on this incident.</li>
        </ol>
        <NxButton variant="primary"
                  onClick={() => { window.location.href = "/xdr/admin/integrations"; }}
                  testid={`xdr-incident-domain-${meta.key}-configure`}>
          Open Administration → Integrations
        </NxButton>
      </NxSection>
    );
  }

  if (meta.key === "endpoints") {
    return (
      <NxSection title="Endpoints"
                 aside={host ? null
                   : <NxState value="NOT_ESTABLISHED"
                              reason="no endpoint host on this incident" />}
                 note="Device Trajectory is the temporal investigation surface
                       for this domain. The resolver either resolves an
                       authoritative endpoint entity or refuses explicitly —
                       it never opens an empty canvas."
                 testid="xdr-incident-domain-body-endpoints">
        <NxFacts columns={2}>
          <NxKeyFact label="Projected host" mono value={host}
                     reason="Resolved from the observation substrate instead"
                     testid="xdr-domain-endpoints-host" />
          <NxKeyFact label="Detection rules"
                     value={(incident?.endpoint_campaign?.rule_ids || [])
                       .join(", ") || null}
                     reason="No endpoint rule recorded"
                     testid="xdr-domain-endpoints-rules" />
        </NxFacts>
        <NxButton variant="primary" onClick={onOpenTrajectory}
                  testid="xdr-domain-endpoints-open-trajectory">
          <Radar size={12} /> Open Device Trajectory
        </NxButton>
      </NxSection>
    );
  }

  if (meta.key === "files") {
    return (
      <NxSection title="Files"
                 aside={<NxState value="NOT_ESTABLISHED"
                                 reason="no incident-scoped file lane"
                                 testid="xdr-domain-state-not_established" />}
                 note="Artifact intelligence · IUE Lane C. File evidence for
                       this incident is currently surfaced inside the
                       incident's Suspicious Elements table on the Overview; a
                       file-only projection (hash reputation, signer, PE
                       metadata, cross-incident appearance) does not exist
                       yet."
                 testid="xdr-incident-domain-body-files">
        <NxButton onClick={() => { window.location.href =
                    `/xdr/incidents/${incident.id}?tab=evidence`; }}
                  testid="xdr-domain-files-open-evidence">
          Open incident evidence <ArrowUpRight size={13} />
        </NxButton>
      </NxSection>
    );
  }

  return null;
}
