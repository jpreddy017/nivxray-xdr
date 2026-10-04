/**
 * IncidentEntities · the entities this incident can actually cite, with
 * their pivots and — only where the platform can execute one — a response.
 *
 * Entities are read from the incident record: `endpoint_campaign` for the
 * endpoint identity and `iocs` for observables. Nothing is inferred: an
 * entity class the record does not carry is simply absent, and the section
 * says so in words instead of showing a zero.
 */
import React from "react";
import { useNavigate } from "react-router-dom";

import { NxEntity, NxButton, NxSection, NxChip } from "@/xdr/nx";
import { pivotsFor } from "./investigationPivots";

/** IOC bucket → entity class. Unknown buckets stay generic, never guessed. */
const ENTITY_KIND = {
  host: "device", hostname: "device", device: "device", server: "server",
  ip: "ip", ipv4: "ip", ipv6: "ip", url: "url", domain: "domain",
  fqdn: "domain", user: "user", username: "user", account: "identity",
  file: "file", filename: "file", path: "file", folder: "folder",
  hash: "hash", sha256: "hash", sha1: "hash", md5: "hash",
  process: "process", command: "command", cmdline: "command",
  script: "file", registry: "registry", email: "mail", mailbox: "mail",
};

export function incidentEntities(incident) {
  const out = [];
  const ep = incident?.endpoint_campaign || null;
  if (ep && (ep.hostname || ep.endpoint_id)) {
    out.push({ kind: "device", value: ep.hostname || ep.endpoint_id,
               id: ep.endpoint_id || null,
               secondary: ep.hostname ? ep.endpoint_id : null,
               source: "endpoint_campaign" });
  }
  Object.entries(incident?.iocs || {}).forEach(([bucket, values]) => {
    (Array.isArray(values) ? values : [values]).forEach((v) => {
      if (v == null || v === "") return;
      if (out.some((e) => e.value === v)) return;
      out.push({ kind: ENTITY_KIND[bucket] || "data", value: String(v),
                 secondary: bucket, source: `iocs.${bucket}` });
    });
  });
  return out;
}

export default function IncidentEntities({ incident, canRespond,
                                           onRespond,
                                           title = "Affected entities",
                                           testid = "incident-entities" }) {
  const navigate = useNavigate();
  const entities = incidentEntities(incident);

  return (
    <NxSection
      title={title}
      aside={entities.length ? `${entities.length} cited` : null}
      note={entities.length === 0
        ? "This incident's record cites no entity. Entities appear here only when the platform observed them — an uncited class is not zero."
        : "Every entity below is read from the incident record; the source field is stated so the claim can be checked."}
      testid={testid}
    >
      {entities.map((e, i) => {
        const pivots = pivotsFor(e, incident);
        const respondable = canRespond === true && e.kind === "device"
          && !!e.id;
        return (
          <div key={`${e.kind}-${e.value}-${i}`}
               className="nx-ent-row"
               style={{ display: "flex", alignItems: "center", gap: 10,
                        flexWrap: "wrap", padding: "6px 0",
                        borderBottom: "1px solid var(--nx-divider)" }}
               data-testid={`${testid}-row-${i}`}>
            <NxEntity kind={e.kind} value={e.value} secondary={e.secondary}
                      boxed testid={`${testid}-entity-${i}`} />
            <NxChip tone="neutral" variant="dashed"
                    title={`read from ${e.source}`}>
              {e.source}
            </NxChip>
            <span style={{ flex: 1 }} />
            {pivots.map((p) => (
              <NxButton key={p.label} onClick={() => navigate(p.to)}
                        title={p.why}
                        testid={`${testid}-pivot-${i}-${p.label
                          .toLowerCase().replace(/[^a-z]+/g, "-")}`}>
                {p.label}
              </NxButton>
            ))}
            {respondable && (
              <NxButton variant="primary" onClick={() => onRespond(e)}
                        title="Request a response against this endpoint. Approval, dispatch, execution and independent verification remain five separate facts."
                        testid={`${testid}-respond-${i}`}>
                Respond
              </NxButton>
            )}
            {!respondable && e.kind !== "device" && (
              <NxChip tone="not_run" variant="dashed"
                      title="No enforcement plane is connected for this entity class, so no action is offered rather than offering one that cannot execute.">
                No response plane
              </NxChip>
            )}
          </div>
        );
      })}
    </NxSection>
  );
}
