/**
 * IncidentContextPane · the contextual detail an analyst reads WITHOUT
 * leaving the queue.
 *
 * Every block is a second authoritative read of `GET /api/incidents/{id}`:
 * verdict derivation, entities, the detections that contributed, evidence
 * pointers per domain, the derivation chain and the worklog. Nothing is
 * synthesised — an absent fact renders as absence with the platform's
 * reason, and a count is never shown as `0` when it was never measured.
 */
import React from "react";
import {
  NxChip, NxSection, NxFacts, NxKeyFact, NxTokenList, NxMetric, NxButton,
  NxEntity, NxEntityList, NxAttackChain, NxInvTable,
  NxVerdict, NxPriority, NxRisk, NxLifecycle, NxProvenanceChip,
} from "@/xdr/nx";

/** IOC bucket name → the entity class the console draws it as. */
const ENTITY_KIND = {
  host: "device", hostname: "device", device: "device", server: "server",
  ip: "ip", ipv4: "ip", ipv6: "ip", url: "domain", domain: "domain",
  fqdn: "domain", user: "user", username: "user", account: "identity",
  file: "file", filename: "file", path: "file", folder: "folder",
  hash: "hash", sha256: "hash", sha1: "hash", md5: "hash",
  process: "process", command: "command", cmdline: "command",
  registry: "registry", email: "mail", mailbox: "mail",
};

export function Absent({ children = "Not recorded", title }) {
  return <span className="nx-unavail" title={title}>{children}</span>;
}

/** Entities the record can genuinely cite, kept in their own classes. */
function entitiesOf(detail) {
  const out = [];
  const ep = detail?.endpoint_campaign || null;
  if (ep && (ep.hostname || ep.endpoint_id)) {
    out.push({
      kind: "device",
      value: ep.hostname || ep.endpoint_id,
      secondary: ep.hostname ? ep.endpoint_id : null,
    });
  }
  const iocs = detail?.iocs || {};
  Object.entries(iocs).forEach(([bucket, values]) => {
    (Array.isArray(values) ? values : [values]).forEach((v) => {
      if (v == null || v === "") return;
      if (out.some((e) => e.value === v)) return;
      out.push({ kind: ENTITY_KIND[bucket] || "data", value: String(v),
                 secondary: bucket });
    });
  });
  return out;
}

const DETECTION_COLUMNS = [
  { key: "rule", label: "Rule", width: 190 },
  { key: "effect", label: "Label effect", width: 120 },
  { key: "weight", label: "Weight", width: 80, num: true },
  { key: "hits", label: "Hits", width: 62, num: true },
  { key: "why", label: "Contribution" },
];

export default function IncidentContextPane({ row, detail, loading, error,
                                              onPivotTab }) {
  if (error) {
    return (
      <div className="nx-dt-error" role="alert"
           data-testid="incident-flyout-error">
        <strong>This incident could not be loaded.</strong>
        <span>{String(error)}</span>
      </div>
    );
  }

  const d = detail || {};
  const vc = d.verdict_card || {};
  const v2 = d.verdict_stage2 || {};
  const assets = d.assets || {};
  const pointers = d.evidence_pointers || [];
  const withEvidence = pointers.filter((p) => p.status === "available");
  const signals = v2.contributing_signals || [];
  const entities = entitiesOf(d);
  const rules = d.endpoint_campaign?.rule_ids || [];

  return (
    <div data-testid="incident-flyout-body">
      <div className="nx-eh-chips" style={{ marginBottom: 14 }}>
        <NxVerdict value={vc.verdict || row.severity}
                   title={vc.reason} testid="flyout-verdict" />
        <NxPriority priority={row.priority} testid="flyout-priority" />
        <NxRisk score={row.verdict?.risk_score ?? v2.risk_score}
                testid="flyout-risk" />
        <NxLifecycle value={d.state || row.state} testid="flyout-state" />
        <NxProvenanceChip provenance={d.provenance || row.provenance}
                          basis={d.provenance_basis || row.provenance_basis}
                          isReal={d.provenance_is_real ?? row.provenance_is_real}
                          testid="flyout-provenance" />
      </div>

      <div className="nx-sec-actions" data-testid="incident-pivot-tabs"
           style={{ display: "flex", flexWrap: "wrap", gap: 6,
                    marginBottom: 14 }}>
        {[["overview", "Overview"], ["story", "Attack Story"],
          ["timeline", "Timeline"], ["evidence", "Evidence"],
          ["entities", "Entities"], ["detections", "Detections"],
          ["mitre", "MITRE"], ["response", "Response"],
          ["activity", "Activity"], ["report", "Report"]].map(([k, label]) => (
          <NxButton key={k} onClick={() => onPivotTab(k)}
                    testid={`incident-pivot-${k}`}>
            {label}
          </NxButton>
        ))}
      </div>

      <NxSection title="Verdict, cited" testid="flyout-verdict-section">
        <NxFacts columns={2}>
          <NxKeyFact label="Engine" mono
                     value={v2.engine || vc.engine || row.detection_source}
                     testid="flyout-fact-engine" />
          <NxKeyFact label="Risk score"
                     value={(v2.risk_score ?? row.verdict?.risk_score) == null
                       ? null : `${v2.risk_score ?? row.verdict.risk_score}/100`}
                     reason="Detection risk only — NivXRay computes no
                             asset-weighted incident score"
                     testid="flyout-fact-risk" />
          <NxKeyFact label="Confidence"
                     value={v2.confidence || row.confidence}
                     testid="flyout-fact-confidence" />
          <NxKeyFact label="Derivation"
                     value={vc.reason || d.verdict_summary?.reason}
                     reason="No verdict derivation was recorded"
                     testid="flyout-fact-derivation" />
        </NxFacts>
        <div style={{ marginTop: 10 }}>
          <NxTokenList values={v2.provenance_chain || []}
                       empty="No derivation chain recorded"
                       testid="flyout-derivation-chain" />
        </div>
      </NxSection>

      <NxSection title="Entities"
                 aside={entities.length ? `${entities.length} cited` : null}
                 note={entities.length === 0
                   ? "This record cites no entity. The queue projects only entities the platform actually observed."
                   : null}
                 testid="flyout-entities">
        {entities.length > 0 && (
          <div style={{ display: "grid", gap: 6 }}>
            {entities.map((e, i) => (
              <NxEntity key={`${e.kind}-${e.value}-${i}`} {...e} boxed
                        testid={`flyout-entity-${i}`} />
            ))}
          </div>
        )}
      </NxSection>

      <NxSection title="Detections that contributed"
                 aside={signals.length ? `${signals.length}` : null}
                 note={signals.length === 0
                   ? "No contributing detection is recorded on this incident."
                   : null}
                 testid="flyout-detections">
        {signals.length > 0 && (
          <NxInvTable
            columns={DETECTION_COLUMNS}
            rows={signals.map((s, i) => ({
              _k: s.rule_id || i,
              rule: <span className="nx-mono">{s.rule_id || "—"}</span>,
              effect: <NxChip tone="medium" variant="tinted">
                        {s.label_effect || "not stated"}
                      </NxChip>,
              weight: s.weight == null
                ? <Absent>—</Absent> : `+${s.weight}`,
              hits: s.hits == null ? <Absent>—</Absent> : s.hits,
              why: s.description || <Absent />,
            }))}
            rowKey={(r) => r._k}
            testid="flyout-detections-table"
          />
        )}
        {rules.length > 0 && (
          <div style={{ marginTop: 10 }}>
            <NxTokenList values={rules} testid="flyout-endpoint-rules" />
          </div>
        )}
      </NxSection>

      <NxSection title="Impacted assets"
                 note={Object.keys(assets).length === 0
                   ? "No asset roll-up on this record." : null}
                 testid="flyout-assets">
        {Object.keys(assets).length > 0 && (
          <div className="nx-grid4">
            {["hosts", "users", "processes", "files", "network"].map((k) => (
              <NxMetric key={k} label={k} value={assets[k] ?? null}
                        reason="Not counted on this record"
                        testid={`flyout-asset-${k}`} />
            ))}
          </div>
        )}
      </NxSection>

      <NxSection title="MITRE ATT&CK"
                 aside={(d.mitre || []).length
                   ? `${d.mitre.length}` : null}
                 note={(d.mitre || []).length === 0
                   ? "No technique is mapped to this incident." : null}
                 testid="flyout-mitre">
        {(d.mitre || []).length > 0 && (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {d.mitre.map((m, i) => (
              <NxChip key={m.id || i} tone="purple" variant="tinted"
                      title={m.name}>
                {m.id}{m.name ? ` · ${m.name}` : ""}
              </NxChip>
            ))}
          </div>
        )}
      </NxSection>

      <NxSection title="Evidence"
                 aside={pointers.length
                   ? `${withEvidence.length} of ${pointers.length} domains`
                   : null}
                 note={pointers.length === 0
                   ? "No evidence pointer on this record." : null}
                 testid="flyout-evidence">
        {pointers.length > 0 && (
          <div style={{ display: "grid", gap: 8 }}>
            {pointers.map((p) => (
              <div key={p.domain}
                   style={{ display: "flex", gap: 10, alignItems: "flex-start" }}
                   data-testid={`flyout-evidence-${p.domain}`}>
                <NxChip tone={p.status === "available" ? "available"
                            : p.status === "not_connected" ? "not_connected"
                            : "no_evidence"}
                        variant={p.status === "available" ? "tinted" : "dashed"}>
                  {p.label}
                </NxChip>
                <span style={{ fontSize: 11.5, color: "var(--nx-text-dim)",
                               lineHeight: 1.5, minWidth: 0,
                               overflowWrap: "anywhere" }}>
                  {p.reason}
                </span>
              </div>
            ))}
          </div>
        )}
        <NxFacts columns={2}>
          <NxKeyFact label="Canonical evidence rows"
                     value={d.canonical_evidence_ids?.length
                       ?? row.evidence_count ?? null}
                     reason="Evidence was not counted on this record"
                     testid="flyout-fact-evidence-count" />
          <NxKeyFact label="Correlation matches"
                     value={d.correlation_match_ids?.length ?? null}
                     reason="No correlation match recorded"
                     testid="flyout-fact-correlations" />
        </NxFacts>
      </NxSection>

      <NxSection title="Attack progression" testid="flyout-progression">
        {loading
          ? <Absent>loading…</Absent>
          : <NxAttackChain nodes={d.attack_progression}
                           testid="flyout-attack-chain" />}
      </NxSection>

      <NxSection title="Worklog"
                 aside={(d.state_history || []).length
                   ? `${d.state_history.length} entries` : null}
                 note={(d.state_history || []).length === 0
                   ? "No state transition is recorded for this incident."
                   : null}
                 testid="flyout-worklog">
        {(d.state_history || []).length > 0 && (
          <NxFacts columns={1}>
            {d.state_history.slice(-4).reverse().map((h, i) => (
              <NxKeyFact key={`${h.at}-${i}`}
                         label={h.at || "Time not recorded"}
                         value={`${h.state || "state not stated"} · ${
                           h.actor || "actor not recorded"}`}
                         reason={h.reason || h.note || null}
                         testid={`flyout-worklog-${i}`} />
            ))}
          </NxFacts>
        )}
      </NxSection>
    </div>
  );
}
