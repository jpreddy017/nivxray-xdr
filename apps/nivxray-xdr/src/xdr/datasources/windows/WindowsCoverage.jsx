/**
 * Windows · Coverage, as a security-operations workspace.
 *
 * POTENTIAL and EFFECTIVE coverage are two different claims and are never
 * merged. `Potential coverage: 21 rules` alongside
 * `Effective coverage: NOT VERIFIED` is the honest reading of a channel
 * with applicable content and no proven telemetry.
 *
 * Four equations this surface refuses to make:
 *   channel configured  ≠ coverage
 *   telemetry received  ≠ detectable
 *   a rule existing     ≠ protection
 *   zero detections     ≠ no coverage
 *
 * Presentation rule: a table row states FACTS. The citation chain
 * (channel → schema/event types → required fields → detection rules →
 * ATT&CK mapping → operational state → supporting evidence) lives in the
 * contextual pane, not printed into the row.
 */
import React, { useEffect, useMemo, useState } from "react";
import { NxDataTable, NxFlyout, NxKeyFact, NxFacts, NxMetricStrip, NxRaw,
         NxSection, NxState, NxTabs, NxTechnical, NxTokenList,
         measured } from "@/xdr/nx";
import { getWindowsCoverage, isTenantRequired } from "./windowsApi";

const VIEWS = [
  { key: "channel", label: "By channel" },
  { key: "attack", label: "By ATT&CK" },
  { key: "rule", label: "By rule" },
];

const BUCKET_OF = {
  available_now: "AVAILABLE_NOW",
  potential: "POTENTIAL",
  blocked: "BLOCKED",
};

function ChannelPane({ row, onClose }) {
  if (!row) return null;
  return (
    <NxFlyout open title={row.label} eyebrow="Coverage, cited"
              onClose={onClose} width={720} testid="wx-coverage-pane">
      <NxSection title="Why NivXRay believes this"
                 note="channel → schema/event types → required fields →
                       detection rules → ATT&CK mapping → operational state →
                       supporting evidence">
        <NxFacts>
          <NxKeyFact label="Telemetry" value={<NxState value={row.telemetry} />} />
          <NxKeyFact label="Parsing" value={<NxState value={row.parsing} />} />
          <NxKeyFact label="Normalization"
                     value={<NxState value={row.normalization} />} />
          <NxKeyFact label="Required fields"
                     value={<NxState value={row.required_fields} />} />
          <NxKeyFact label="Potential coverage"
                     value={`${measured(row.potential_rules)} rule(s)`} />
          <NxKeyFact label="Effective coverage"
                     value={<NxState value={row.effective_state} />}
                     reason={row.effective_basis} />
          <NxKeyFact label="Blocked rules"
                     value={measured(row.blocked_rules)} mono />
          <NxKeyFact label="ATT&CK techniques"
                     value={measured(row.attack_techniques)} mono />
          <NxKeyFact label="Detections fired"
                     value={measured(row.detections_fired)} mono />
        </NxFacts>
      </NxSection>

      <NxSection title="Prerequisites" testid="wx-coverage-prereqs">
        <NxDataTable rows={row.prerequisites || []} searchable={false}
                     rowKey={(r) => r.prerequisite} pageSize={50}
                     emptyTitle="No prerequisite is declared"
                     testid="wx-prereq-table"
                     columns={[
          { key: "prerequisite", header: "Prerequisite", width: "220px",
            render: (r) => <span className="nx-mono">{r.prerequisite}</span> },
          { key: "state", header: "State", width: "150px",
            render: (r) => <NxState value={r.state} reason={r.detail} /> },
          { key: "blocker", header: "Blocker",
            render: (r) => (r.blocker
              ? <span>{r.blocker}</span>
              : <span className="nx-absent">—</span>) },
        ]} />
      </NxSection>

      {row.evidence_gaps?.length > 0 && (
        <NxSection title="Evidence gaps · this deployment must fix these"
                   testid="wx-coverage-gaps">
          <NxTokenList values={row.evidence_gaps} limit={20} />
        </NxSection>
      )}
      {row.content_gaps?.length > 0 && (
        <NxSection title="Content gaps"
                   note="A rule cites a field this channel does not carry. That
                         is a content-authoring fact, not an onboarding failure,
                         and it is reported separately so the two are never
                         confused.">
          <NxTokenList values={row.content_gaps} limit={20} />
        </NxSection>
      )}

      <NxTechnical>
        <NxRaw>{JSON.stringify(row, null, 2)}</NxRaw>
      </NxTechnical>
    </NxFlyout>
  );
}

function TechniquePane({ row, onClose }) {
  if (!row) return null;
  return (
    <NxFlyout open title={row.technique_name || row.technique_id}
              eyebrow={row.technique_id} onClose={onClose} width={700}
              testid="wx-technique-pane">
      <NxSection title="Coverage for this technique">
        <NxFacts>
          <NxKeyFact label="Coverage"
                     value={<NxState value={row.coverage_state} />} />
          <NxKeyFact label="Tactic" value={row.tactic} />
          <NxKeyFact label="Prerequisite state"
                     value={<NxState value={row.prerequisite_state} />} />
          <NxKeyFact label="Required telemetry"
                     value={<NxTokenList values={row.required_telemetry} />} />
          <NxKeyFact label="Detection rules"
                     value={(row.detection_content || []).length} mono />
          <NxKeyFact label="Last detection" value={row.last_detection_at} mono
                     reason={row.last_detection_at ? null
                       : "no detection has fired for this technique in the analysis window"} />
        </NxFacts>
      </NxSection>
      <NxSection title="Detection content">
        <NxDataTable rows={row.detection_content || []} searchable={false}
                     rowKey={(r) => r.rule_id} pageSize={50}
                     emptyTitle="No deployed rule maps to this technique"
                     testid="wx-technique-rules"
                     columns={[
          { key: "name", header: "Detection rule", width: "300px",
            render: (r) => r.name },
          { key: "state", header: "State", width: "150px",
            render: (r) => <NxState value={r.coverage_state} /> },
          { key: "blocker", header: "Blocker",
            render: (r) => (r.blocker
              ? <span>{r.blocker}</span>
              : <span className="nx-absent">—</span>) },
        ]} />
      </NxSection>
    </NxFlyout>
  );
}

export default function WindowsCoverage({ onPivotChannel }) {
  const [state, setState] = useState({ loading: true, data: null, error: null });
  const [view, setView] = useState("channel");
  const [channelRow, setChannelRow] = useState(null);
  const [techniqueRow, setTechniqueRow] = useState(null);

  useEffect(() => {
    getWindowsCoverage()
      .then((d) => setState({ loading: false, data: d, error: null }))
      .catch((e) => setState({ loading: false, data: null, error: e.message }));
  }, []);

  const d = state.data;

  const channelRows = useMemo(() => {
    if (!d) return [];
    return Object.keys(BUCKET_OF).flatMap((k) =>
      (d[k] || []).map((r) => ({ ...r, bucket: BUCKET_OF[k] })));
  }, [d]);

  const ruleRows = useMemo(() => {
    if (!d) return [];
    const rows = [];
    for (const t of d.attack || []) {
      for (const c of t.detection_content || []) {
        rows.push({
          id: `${t.technique_id}::${c.rule_id}`,
          rule_id: c.rule_id,
          name: c.name,
          severity: c.severity,
          technique_id: t.technique_id,
          technique_name: t.technique_name,
          required_telemetry: t.required_telemetry || [],
          state: c.coverage_state,
          blocker: c.blocker,
          last_detection_at: t.last_detection_at,
        });
      }
    }
    return rows;
  }, [d]);

  return (
    <div className="wx-stack" data-testid="wx-coverage">
      {state.error && !isTenantRequired(state.error) && (
        <NxSection variant="card" title="This view could not load"
                   testid="wx-coverage-error">
          <p className="nx-sec-note">{state.error}</p>
        </NxSection>
      )}

      {d && (
        <>
          <NxMetricStrip testid="wx-coverage-metrics" items={[
            { label: "Available now", value: (d.available_now || []).length },
            { label: "Potential", value: (d.potential || []).length },
            { label: "Blocked", value: (d.blocked || []).length },
            { label: "ATT&CK techniques mapped", value: (d.attack || []).length },
            { label: "Detection rules mapped", value: ruleRows.length },
          ]} />

          <NxSection variant="inset" title="What this model does not say"
                     note="Four equations an enterprise XDR must never make.">
            <NxTokenList values={d.model?.never_equate} limit={8}
                         testid="wx-coverage-model" />
          </NxSection>

          <NxTabs tabs={VIEWS} active={view} onChange={setView}
                  testid="wx-coverage-views" />

          {view === "channel" && (
            <NxSection variant="card" title="Coverage by channel"
                       note="AVAILABLE NOW requires evidence. POTENTIAL names
                             the unmet prerequisite. BLOCKED names the exact
                             blocker. None is inferred from a detection having
                             fired."
                       testid="wx-coverage-by-channel">
              <NxDataTable rows={channelRows} loading={state.loading}
                           rowKey={(r) => r.channel} onRowClick={setChannelRow}
                           searchPlaceholder="Search channel or blocker"
                           emptyTitle="No channel carries a coverage assessment"
                           testid="wx-coverage-channel-table"
                           columns={[
                { key: "label", header: "Channel", width: "210px",
                  value: (r) => r.label,
                  render: (r) => (
                    <span title={r.channel}>
                      <strong>{r.label}</strong>
                      <div className="nx-absent nx-mono">{r.channel}</div>
                    </span>) },
                { key: "telemetry", header: "Collection", width: "130px",
                  render: (r) => <NxState value={r.telemetry} /> },
                { key: "parsing", header: "Parsing", width: "120px",
                  render: (r) => <NxState value={r.parsing} /> },
                { key: "normalization", header: "Evidence", width: "140px",
                  render: (r) => <NxState value={r.normalization} /> },
                { key: "required_fields", header: "Required fields",
                  width: "140px",
                  render: (r) => <NxState value={r.required_fields} /> },
                { key: "potential_rules", header: "Rules", width: "90px",
                  align: "right",
                  value: (r) => r.potential_rules ?? -1,
                  render: (r) => measured(r.potential_rules) },
                { key: "attack_techniques", header: "ATT&CK", width: "90px",
                  align: "right",
                  value: (r) => r.attack_techniques ?? -1,
                  render: (r) => measured(r.attack_techniques) },
                { key: "effective_state", header: "Effective coverage",
                  width: "160px",
                  render: (r) => <NxState value={r.effective_state}
                                          reason={r.effective_basis} /> },
                { key: "detections_fired", header: "Last detection",
                  width: "120px", align: "right",
                  value: (r) => r.detections_fired ?? -1,
                  render: (r) => (r.detections_fired
                    ? `${measured(r.detections_fired)} fired`
                    : <span className="nx-absent">none</span>) },
                { key: "attention", header: "Attention",
                  value: (r) => (r.evidence_gaps || []).join(","),
                  render: (r) => ((r.evidence_gaps || []).length
                    ? <NxTokenList values={r.evidence_gaps} limit={2} />
                    : <span className="nx-absent">—</span>) },
              ]} />
            </NxSection>
          )}

          {view === "attack" && (
            <NxSection variant="card" title="Coverage by ATT&CK technique"
                       note={d.model?.attack_note}
                       testid="wx-coverage-by-attack">
              <NxDataTable rows={d.attack || []} loading={state.loading}
                           rowKey={(r) => r.technique_id}
                           onRowClick={setTechniqueRow}
                           searchPlaceholder="Search technique, tactic, id"
                           emptyTitle="No deployed rule carries an ATT&CK mapping for these channels"
                           testid="wx-coverage-attack-table"
                           columns={[
                { key: "tactic", header: "Tactic", width: "170px",
                  render: (r) => (r.tactic
                    || <span className="nx-absent">—</span>) },
                { key: "technique_id", header: "Technique", width: "130px",
                  render: (r) => (
                    <span className="nx-mono">{r.technique_id}</span>) },
                { key: "technique_name", header: "Name", width: "260px",
                  render: (r) => (r.technique_name
                    || <span className="nx-absent">—</span>) },
                { key: "rules", header: "Rules", width: "80px", align: "right",
                  value: (r) => (r.detection_content || []).length,
                  render: (r) => (r.detection_content || []).length },
                { key: "required_telemetry", header: "Required telemetry",
                  width: "230px",
                  value: (r) => (r.required_telemetry || []).join(","),
                  render: (r) => <NxTokenList values={r.required_telemetry}
                                              limit={3} /> },
                { key: "coverage_state", header: "Coverage", width: "150px",
                  render: (r) => <NxState value={r.coverage_state} /> },
                { key: "prerequisite_state", header: "Prerequisite",
                  width: "150px",
                  render: (r) => <NxState value={r.prerequisite_state} /> },
                { key: "last_detection_at", header: "Last detection",
                  width: "180px",
                  value: (r) => r.last_detection_at || "",
                  render: (r) => (r.last_detection_at
                    ? <span className="nx-mono">{r.last_detection_at}</span>
                    : <span className="nx-absent">—</span>) },
              ]} />
            </NxSection>
          )}

          {view === "rule" && (
            <NxSection variant="card" title="Coverage by detection rule"
                       note="A rule is listed once per technique it maps to.
                             Channel attribution is stated as the telemetry the
                             technique requires — the platform does not claim a
                             rule/channel binding it cannot cite."
                       testid="wx-coverage-by-rule">
              <NxDataTable rows={ruleRows} loading={state.loading}
                           rowKey={(r) => r.id}
                           searchPlaceholder="Search rule, technique, blocker"
                           emptyTitle="No detection rule maps to these channels"
                           testid="wx-coverage-rule-table"
                           columns={[
                { key: "name", header: "Detection rule", width: "300px",
                  render: (r) => (
                    <span>
                      <strong>{r.name}</strong>
                      <div className="nx-absent nx-mono">{r.rule_id}</div>
                    </span>) },
                { key: "severity", header: "Severity", width: "110px",
                  value: (r) => r.severity || "",
                  render: (r) => (r.severity
                    ? <NxState value={r.severity} />
                    : <span className="nx-absent">—</span>) },
                { key: "required_telemetry", header: "Required evidence",
                  width: "230px",
                  value: (r) => r.required_telemetry.join(","),
                  render: (r) => <NxTokenList values={r.required_telemetry}
                                              limit={3} /> },
                { key: "technique_id", header: "ATT&CK", width: "120px",
                  render: (r) => (
                    <span className="nx-mono" title={r.technique_name}>
                      {r.technique_id}
                    </span>) },
                { key: "state", header: "State", width: "150px",
                  render: (r) => <NxState value={r.state}
                                          reason={r.blocker} /> },
                { key: "blocker", header: "Blocker",
                  render: (r) => (r.blocker
                    ? <span>{r.blocker}</span>
                    : <span className="nx-absent">—</span>) },
                { key: "last_detection_at", header: "Last fired",
                  width: "180px",
                  value: (r) => r.last_detection_at || "",
                  render: (r) => (r.last_detection_at
                    ? <span className="nx-mono">{r.last_detection_at}</span>
                    : <span className="nx-absent">never</span>) },
              ]} />
            </NxSection>
          )}
        </>
      )}

      <ChannelPane row={channelRow} onClose={() => setChannelRow(null)} />
      <TechniquePane row={techniqueRow} onClose={() => setTechniqueRow(null)} />
      {onPivotChannel && null}
    </div>
  );
}
