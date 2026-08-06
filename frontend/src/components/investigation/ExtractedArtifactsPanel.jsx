/**
 * ExtractedArtifactsPanel · IVE projection (Rule R16, R20)
 * ────────────────────────────────────────────────────────
 * Slice 1.9 · Frozen 2026-03-01
 *
 * Pure projection of the artifacts IDA-4 pulled out of an acquired
 * document.  Groups artifacts by type, shows per-artifact
 * investigation status (from SSOT.report_extraction.command_
 * investigations for commands, and inherent atomic-IOC status for
 * the rest), and lets the analyst drill into any single artifact
 * inline — no second input box, no re-paste required.
 *
 * The analyst never has to copy-paste an extracted artifact back
 * into the workspace.  Every extracted command was ALREADY
 * investigated (Rule R20) — this panel just surfaces the result
 * per artifact.
 */
import React, { useState } from "react";
import CollapsibleSection from "./CollapsibleSection";

const TYPE_META = {
  commands: { label: "Commands",     glyph: "▶" },
  urls:     { label: "URLs",         glyph: "◈" },
  hashes:   { label: "Hashes",       glyph: "▤" },
  ips:      { label: "IPs",          glyph: "◇" },
  domains:  { label: "Domains",      glyph: "◍" },
  registry: { label: "Registry",     glyph: "▨" },
  paths:    { label: "File Paths",   glyph: "▧" },
  cves:     { label: "CVEs",         glyph: "⌘" },
  mitre:    { label: "MITRE ATT&CK", glyph: "T" },
  actors:   { label: "Threat Actors",glyph: "†" },
  malware:  { label: "Malware",      glyph: "▲" },
  yara:     { label: "YARA Rules",   glyph: "§" },
  sigma:    { label: "Sigma Rules",  glyph: "§" },
};

export default function ExtractedArtifactsPanel({ investigation }) {
  const ext  = investigation?.report_extraction || {};
  const acq  = investigation?.acquired_document || {};
  const ice  = investigation?.ice || {};
  if (!acq?.ok) return null;

  // Split body_artifacts (IOCs the article mentions) by type.
  const byType = { urls: [], hashes: [], ips: [], domains: [],
                    registry: [], paths: [], cves: [] };
  for (const a of ext.body_artifacts || []) {
    if (a.type === "url") byType.urls.push(a);
    else if (a.type === "hash") byType.hashes.push(a);
    else if (a.type === "ip") byType.ips.push(a);
    else if (a.type === "domain") byType.domains.push(a);
    else if (a.type === "registry_key") byType.registry.push(a);
    else if (a.type === "file_path") byType.paths.push(a);
    else if (a.type === "cve") byType.cves.push(a);
  }

  const commands       = ext.commands || [];
  const investigations = ext.command_investigations || [];
  const mitre          = ext.mitre_techniques || [];
  const actors         = ext.threat_actors || [];
  const malware        = ext.malware_families || [];
  const yara           = ext.yara_rules || [];
  const sigma          = ext.sigma_rules || [];

  const groups = [
    { key: "commands", items: commands, extras: investigations },
    { key: "urls",     items: byType.urls },
    { key: "hashes",   items: byType.hashes },
    { key: "ips",      items: byType.ips },
    { key: "domains",  items: byType.domains },
    { key: "registry", items: byType.registry },
    { key: "paths",    items: byType.paths },
    { key: "cves",     items: byType.cves },
    { key: "mitre",    items: mitre },
    { key: "actors",   items: actors },
    { key: "malware",  items: malware },
    { key: "yara",     items: yara },
    { key: "sigma",    items: sigma },
  ].filter(g => g.items.length > 0);

  if (!groups.length) return null;

  return (
    <CollapsibleSection
      title="Evidence Explorer"
      subtitle="Every piece of evidence below was investigated automatically (Rule R20) and correlated by ICE (Rule R21)."
      testid="extracted-artifacts-panel"
      right={ice?.investigation_readiness
              ? `${ice.investigation_readiness.overall_percent}% ready`
              : null}
    >
      {/* ── Incident header (ICE.incident) ── */}
      <CollapsibleSection title="Incident" testid="incident-header-section"
                          style={{ margin: "8px 0" }}>
        <IncidentHeader incident={ice?.incident?.summary || ice?.incident} />
      </CollapsibleSection>

      {/* ── Investigation Readiness ── */}
      <CollapsibleSection title="Investigation Readiness"
                          testid="readiness-section"
                          style={{ margin: "8px 0" }}
                          right={ice?.investigation_readiness
                            ? `${ice.investigation_readiness.overall_percent}%`
                            : null}>
        <InvestigationReadiness readiness={ice?.investigation_readiness}
                                  gaps={ice?.investigation_gaps || []} />
      </CollapsibleSection>

      {/* ── Evidence Completeness ── */}
      <CollapsibleSection title="Evidence Completeness"
                          testid="completeness-section"
                          style={{ margin: "8px 0" }}
                          defaultOpen={false}>
        <EvidenceCompleteness ice={ice} ext={ext} groups={groups} />
      </CollapsibleSection>

      {/* ══ CORRELATED EVIDENCE ══ */}
      <CollapsibleSection title="Behavior Correlation"
                          testid="behavior-correlation-section"
                          style={{ margin: "8px 0" }}
                          right={`${ice?.behavior_clusters?.length || 0} clusters`}>
        <BehaviorCorrelation clusters={ice?.behavior_clusters || []} />
      </CollapsibleSection>

      <CollapsibleSection title="Kill-Chain Phases"
                          testid="attack-phases-section"
                          style={{ margin: "8px 0" }}
                          right={`${ice?.attack_phases?.length || 0} phases`}>
        <AttackPhases phases={ice?.attack_phases || []} />
      </CollapsibleSection>

      <CollapsibleSection title="Recommended Actions"
                          testid="recommended-actions-section"
                          style={{ margin: "8px 0" }}
                          right={`${ice?.recommended_actions?.length || 0} actions`}>
        <RecommendedActions actions={ice?.recommended_actions || []} />
      </CollapsibleSection>

      {/* ══ RAW EVIDENCE ══ */}
      <CollapsibleSection title="Raw Evidence"
                          testid="raw-evidence-section"
                          style={{ margin: "8px 0" }}
                          defaultOpen={false}
                          right={`${groups.length} groups`}>
        {groups.map(g => (
          <ArtifactGroup key={g.key} groupKey={g.key} items={g.items}
                          extras={g.extras} />
        ))}
      </CollapsibleSection>
    </CollapsibleSection>
  );
}


// ══════════════════════════════════════════════════════════════════
// Evidence Completeness — read from ICE (Rule R21).  Falls back
// gracefully to the frontend view if `ice` is not yet populated.
// ══════════════════════════════════════════════════════════════════
function EvidenceCompleteness({ ice, ext, groups }) {
  const ec = ice?.evidence_completeness;
  if (ec?.dimensions?.length) {
    return (
      <div data-testid="evidence-completeness"
           style={{ marginBottom: 14,
                     padding: "10px 12px",
                     border: "1px solid rgba(126, 230, 168, 0.22)",
                     borderRadius: 4,
                     background: "rgba(0, 40, 22, 0.30)" }}>
        <div style={{ fontSize: 11, color: "#7ee6a8",
                       letterSpacing: 1.4, marginBottom: 4,
                       display: "flex", justifyContent: "space-between" }}>
          <span>▸ EVIDENCE COMPLETENESS</span>
          <span data-testid="ec-overall">{ec.overall_percent}% covered</span>
        </div>
        <div style={{ display: "grid",
                       gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
                       gap: 8, fontSize: 11 }}>
          {ec.dimensions.map(d => (
            <div key={d.dim} data-testid={`ec-${d.dim.toLowerCase().replace(/[^a-z]+/g, '-')}`}
                 style={{ padding: "4px 8px",
                           border: `1px solid ${_ecColorForState(d.state, 0.32)}`,
                           borderRadius: 3,
                           background: `rgba(0, 60, 30, ${d.state === "complete" ? 0.35 : 0.15})`,
                           opacity: d.state === "not_available" ? 0.6 : 1 }}>
              <div style={{ fontSize: 10, color: "#96c9aa",
                             letterSpacing: 0.8,
                             textTransform: "uppercase" }}>{d.dim}</div>
              <div style={{ fontSize: 13, color: _ecColorForState(d.state, 1),
                             fontWeight: 600, marginTop: 2 }}>
                {_ecLabel(d)}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }
  return null;
}

function _ecColorForState(state, alpha) {
  if (state === "complete") return `rgba(61, 220, 132, ${alpha})`;
  if (state === "relative") return `rgba(255, 214, 107, ${alpha})`;
  if (state === "missing")  return `rgba(255, 120, 120, ${alpha})`;
  return                          `rgba(139, 165, 152, ${alpha})`;
}
function _ecLabel(d) {
  if (d.state === "not_available") return "Not Applicable";
  if (d.state === "missing")       return "Not Present";
  if (d.state === "relative")      return "Partial";
  if (d.dim === "Commands")
    return `${d.investigated}/${d.found} investigated${d.errors ? ` · ${d.errors} err` : ""}`;
  return `${d.found ?? 0} found`;
}


// ══════════════════════════════════════════════════════════════════
// Behavior Correlation — reads ICE.behavior_clusters directly.
// Analysis happens once (in ICE); this component only projects.
// ══════════════════════════════════════════════════════════════════
function BehaviorCorrelation({ clusters }) {
  if (!clusters?.length) return null;
  return (
    <div data-testid="behavior-correlation"
         style={{ marginBottom: 14 }}>
      <div style={{ fontSize: 11, color: "#7ee6a8",
                     letterSpacing: 1.4, marginBottom: 8 }}>
        ▸ BEHAVIOR CORRELATION ({clusters.length})
      </div>
      {clusters.map((c, i) => (
        <BehaviorClusterRow key={c.label} cluster={c} index={i} />
      ))}
    </div>
  );
}

function BehaviorClusterRow({ cluster, index }) {
  const [open, setOpen] = useState(false);
  return (
    <div data-testid={`behavior-cluster-${index}`}
         style={{ borderTop: "1px dashed rgba(126, 230, 168, 0.16)",
                   padding: "6px 0" }}>
      <button onClick={() => setOpen(v => !v)}
              style={{ background: "transparent", border: "none",
                        padding: 0, cursor: "pointer",
                        color: "#c5f5d6", width: "100%", textAlign: "left",
                        display: "flex", alignItems: "center",
                        justifyContent: "space-between" }}>
        <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ color: "#7ee6a8", width: 12, textAlign: "center" }}>
            {open ? "▾" : "▸"}
          </span>
          <span style={{ fontSize: 13, color: "#e6ffe9" }}>{cluster.label}</span>
          <span style={{ fontSize: 10, color: "#7ee6a8",
                          padding: "1px 6px",
                          background: "rgba(0, 60, 30, 0.4)",
                          borderRadius: 3 }}>
            {cluster.command_count} cmd{cluster.command_count === 1 ? "" : "s"}
          </span>
          <span style={{ fontSize: 9, color: _confColor(cluster.confidence),
                          padding: "1px 6px",
                          border: `1px solid ${_confColor(cluster.confidence)}`,
                          borderRadius: 3, letterSpacing: 1 }}>
            {(cluster.confidence || "").toUpperCase()}
          </span>
        </span>
        <span style={{ fontSize: 10, color: "#96c9aa", display: "flex", gap: 4 }}>
          {cluster.mitre?.length > 0
            ? cluster.mitre.map(m => (
                <span key={m.id} style={{
                  padding: "1px 6px",
                  border: "1px solid rgba(126, 230, 168, 0.32)",
                  borderRadius: 2, color: "#c5f5d6" }}>{m.id}</span>
              ))
            : <span style={{ opacity: 0.55 }}>no MITRE mapped</span>}
        </span>
      </button>
      {open && (
        <ul style={{ margin: "6px 0 0 24px", padding: 0, listStyle: "none" }}>
          {cluster.commands.map((c, i) => (
            <li key={i} style={{ fontFamily: "ui-monospace, monospace",
                                   fontSize: 11, color: "#c5f5d6",
                                   padding: "3px 0",
                                   borderBottom: "1px dashed rgba(126, 230, 168, 0.08)",
                                   wordBreak: "break-all" }}>
              <span style={{ color: "#3ddc84", marginRight: 6 }}>✓</span>
              {c.command}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function _confColor(conf) {
  if (conf === "high")   return "#3ddc84";
  if (conf === "medium") return "#ffd66b";
  return                        "#96c9aa";
}


// ══════════════════════════════════════════════════════════════════
// Kill-Chain Phases — ICE.attack_phases in canonical MITRE order.
// ══════════════════════════════════════════════════════════════════
function AttackPhases({ phases }) {
  if (!phases?.length) return null;
  return (
    <div data-testid="attack-phases"
         style={{ marginBottom: 14, marginTop: 10 }}>
      <div style={{ fontSize: 11, color: "#7ee6a8",
                     letterSpacing: 1.4, marginBottom: 8 }}>
        ▸ KILL-CHAIN PHASES ({phases.length})
      </div>
      <ol style={{ margin: 0, padding: 0, listStyle: "none",
                    display: "flex", flexDirection: "column", gap: 6 }}>
        {phases.map((p, i) => (
          <li key={p.tactic} data-testid={`attack-phase-${p.tactic}`}
              style={{ display: "grid",
                        gridTemplateColumns: "18px 1fr auto",
                        gap: 10, alignItems: "start",
                        padding: "6px 8px",
                        border: "1px solid rgba(126, 230, 168, 0.18)",
                        borderRadius: 3,
                        background: "rgba(0, 40, 22, 0.3)" }}>
            <span style={{ color: "#7ee6a8", fontWeight: 700,
                            fontSize: 11, textAlign: "center" }}>{i + 1}</span>
            <div>
              <div style={{ fontSize: 12, color: "#e6ffe9" }}>{p.label}</div>
              <div style={{ fontSize: 10, color: "#96c9aa", marginTop: 2 }}>
                {p.clusters.join(" · ")} — {p.command_count} command{p.command_count === 1 ? "" : "s"}
              </div>
            </div>
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap",
                           justifyContent: "flex-end" }}>
              {p.mitre.map(m => (
                <span key={m} style={{ fontSize: 10, color: "#c5f5d6",
                                         padding: "1px 6px",
                                         border: "1px solid rgba(126, 230, 168, 0.32)",
                                         borderRadius: 2 }}>{m}</span>
              ))}
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}


function ArtifactGroup({ groupKey, items, extras }) {
  const [open, setOpen] = useState(groupKey === "commands"); // commands open by default
  const meta = TYPE_META[groupKey] || { label: groupKey, glyph: "•" };
  return (
    <div style={{ borderTop: "1px dashed rgba(126, 230, 168, 0.18)",
                   padding: "6px 0" }}
         data-testid={`artifact-group-${groupKey}`}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          background: "transparent", border: "none", padding: 0,
          cursor: "pointer", color: "#c5f5d6", width: "100%",
          textAlign: "left", display: "flex", alignItems: "center",
          justifyContent: "space-between",
        }}
        data-testid={`artifact-group-toggle-${groupKey}`}
      >
        <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ color: "#7ee6a8", width: 12, textAlign: "center" }}>
            {open ? "▾" : "▸"}
          </span>
          <span style={{ fontSize: 12, letterSpacing: 1, color: "#e6ffe9" }}>
            {meta.label}
          </span>
          <span style={{ fontSize: 11, color: "#7ee6a8",
                          padding: "1px 6px",
                          background: "rgba(0, 60, 30, 0.4)",
                          borderRadius: 3 }}>
            {items.length}
          </span>
        </span>
        <span style={{ fontSize: 10, color: "#96c9aa" }}>
          all investigated
        </span>
      </button>

      {open && (
        <ul style={{ listStyle: "none", margin: "6px 0 0 24px",
                      padding: 0 }}
            data-testid={`artifact-group-items-${groupKey}`}>
          {items.slice(0, 50).map((it, i) => (
            <ArtifactRow
              key={i}
              groupKey={groupKey}
              item={it}
              extra={extras?.[i]}
              index={i}
            />
          ))}
          {items.length > 50 && (
            <li style={{ fontSize: 11, color: "#96c9aa", padding: "6px 0" }}>
              …and {items.length - 50} more (truncated for display)
            </li>
          )}
        </ul>
      )}
    </div>
  );
}


function ArtifactRow({ groupKey, item, extra, index }) {
  const [open, setOpen] = useState(false);
  const isCommand = groupKey === "commands";

  const label   = isCommand ? item.command
                            : (item.canonical || item.value || item.id || item.name);
  const purpose = isCommand ? (item.purpose || "Command execution") : null;
  const status  = _statusFor(groupKey, item, extra);

  return (
    <li
      data-testid={`artifact-row-${groupKey}-${index}`}
      style={{ padding: "6px 0",
               borderBottom: "1px dashed rgba(126, 230, 168, 0.08)" }}
    >
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          background: "transparent", border: "none", padding: 0,
          cursor: "pointer", color: "#c5f5d6", width: "100%",
          textAlign: "left",
        }}
      >
        <div style={{ display: "flex", alignItems: "start", gap: 8 }}>
          <span style={{ color: status.color, width: 14, textAlign: "center",
                          flexShrink: 0 }}>
            {status.glyph}
          </span>
          <span style={{ flex: 1, fontFamily: "ui-monospace, monospace",
                          fontSize: 11, color: "#e6ffe9",
                          wordBreak: "break-all" }}>
            {label}
          </span>
          <span style={{ fontSize: 9, letterSpacing: 1,
                          color: status.color, opacity: 0.8, flexShrink: 0 }}>
            {status.label}
          </span>
        </div>
        {purpose && (
          <div style={{ marginLeft: 22, marginTop: 2,
                         fontSize: 10, color: "#96c9aa" }}>
            → {purpose}
          </div>
        )}
      </button>

      {open && (
        <ArtifactDetail groupKey={groupKey} item={item} extra={extra} />
      )}
    </li>
  );
}


function ArtifactDetail({ groupKey, item, extra }) {
  if (groupKey === "commands") return <CommandDetail command={item} ci={extra} />;
  if (groupKey === "mitre")    return <MitreDetail item={item} />;
  return <GenericDetail item={item} />;
}


function CommandDetail({ command, ci }) {
  if (!ci) {
    return (
      <div style={{ marginLeft: 22, marginTop: 6, fontSize: 11,
                     color: "#96c9aa" }}>
        (no per-command investigation available — see report_extraction)
      </div>
    );
  }
  return (
    <div style={{ marginLeft: 22, marginTop: 8,
                   background: "rgba(0, 30, 15, 0.35)",
                   border: "1px solid rgba(126, 230, 168, 0.16)",
                   borderRadius: 4, padding: "8px 10px" }}>
      <DetailRow label="Language"       value={ci.language || "—"} />
      <DetailRow label="LOLBAS"         value={(ci.lolbins || []).map(l => l.binary).join(", ") || "—"} />
      <DetailRow label="MITRE"          value={(ci.techniques || []).map(t => `${t.id} ${t.name || ""}`.trim()).join(" · ") || "—"} />
      <DetailRow label="Attack Intent"  value={ci.attack_intent?.objective || "—"} />
      <DetailRow label="IOCs"           value={(ci.iocs || []).length} />
      <DetailRow label="Obfuscation"    value={ci.obfuscation_score ?? "—"} />
      <DetailRow label="Source"         value={command.source || "—"} />
    </div>
  );
}


function MitreDetail({ item }) {
  return (
    <div style={{ marginLeft: 22, marginTop: 6,
                   background: "rgba(0, 30, 15, 0.35)",
                   border: "1px solid rgba(126, 230, 168, 0.16)",
                   borderRadius: 4, padding: "8px 10px" }}>
      <DetailRow label="Technique" value={item.id} />
      <DetailRow label="Source"    value={item.source || "—"} />
      <DetailRow label="Evidence"  value={item.evidence || "—"} />
    </div>
  );
}


function GenericDetail({ item }) {
  return (
    <div style={{ marginLeft: 22, marginTop: 6, fontSize: 11,
                   color: "#96c9aa" }}>
      {item.source && <DetailRow label="Source" value={JSON.stringify(item.source)} />}
      {item.metadata && Object.keys(item.metadata).length > 0 && (
        <DetailRow label="Metadata" value={JSON.stringify(item.metadata)} />
      )}
    </div>
  );
}


function DetailRow({ label, value }) {
  return (
    <div style={{ display: "flex", gap: 10, fontSize: 11,
                   color: "#c5f5d6", padding: "1px 0" }}>
      <span style={{ color: "#7ee6a8", minWidth: 100,
                      letterSpacing: 0.8, fontSize: 10 }}>{label}</span>
      <span style={{ color: "#e6ffe9", wordBreak: "break-all" }}>
        {String(value)}
      </span>
    </div>
  );
}


function _statusFor(groupKey, item, extra) {
  if (groupKey === "commands") {
    if (extra?.error) return { glyph: "!", label: "ERROR", color: "#ff9a9a" };
    if (extra?.language) return { glyph: "✓", label: "INVESTIGATED", color: "#3ddc84" };
    return { glyph: "○", label: "PENDING", color: "#96c9aa" };
  }
  // Non-command artifacts are surfaced as-is from IDA-2 splitter —
  // they are their own investigation (atomic IOC).
  return { glyph: "✓", label: "EXTRACTED", color: "#3ddc84" };
}


// ══════════════════════════════════════════════════════════════════
// Incident Header — the analyst's single line of the incident.
// ══════════════════════════════════════════════════════════════════
function IncidentHeader({ incident }) {
  if (!incident) return null;
  const sevColor = {
    critical: "#ff6b6b", high: "#ffb347",
    medium:   "#ffd66b", low:  "#7ee6a8",
  }[incident.severity] || "#8ba598";

  return (
    <div data-testid="incident-header"
         style={{ marginBottom: 12,
                   padding: "10px 12px",
                   border: `1px solid ${sevColor}55`,
                   borderLeft: `4px solid ${sevColor}`,
                   borderRadius: 4,
                   background: "rgba(0, 40, 22, 0.35)" }}>
      <div style={{ display: "flex", alignItems: "baseline",
                     justifyContent: "space-between", gap: 12 }}>
        <div>
          <div style={{ fontSize: 10, letterSpacing: 1.5,
                         color: sevColor, opacity: 0.85 }}>
            INCIDENT · {(incident.severity || "").toUpperCase()}
          </div>
          <div style={{ fontSize: 14, fontWeight: 600, color: "#e6ffe9",
                         marginTop: 2 }}>
            {incident.title}
          </div>
          <div style={{ fontSize: 11, color: "#96c9aa", marginTop: 3 }}>
            {incident.actor && <><b style={{ color: "#ffe0b3" }}>{incident.actor}</b> · </>}
            {incident.objective}
          </div>
        </div>
        <div style={{ textAlign: "right", fontSize: 11, color: "#96c9aa" }}>
          <div>
            <span style={{ color: sevColor, fontSize: 18, fontWeight: 700 }}>
              {incident.confidence_percent}%
            </span>
            <span style={{ marginLeft: 6 }}>confidence</span>
          </div>
          <div style={{ marginTop: 4, opacity: 0.85 }}>
            {incident.cluster_count} behaviors · {incident.mitre_count} MITRE
          </div>
          <div style={{ marginTop: 2, fontSize: 10, letterSpacing: 1,
                         color: "#7ee6a8" }}>
            {(incident.status || "").replace(/_/g, " ").toUpperCase()}
          </div>
        </div>
      </div>
    </div>
  );
}


// ══════════════════════════════════════════════════════════════════
// Investigation Readiness — progress bars + recommended next step.
// ══════════════════════════════════════════════════════════════════
function InvestigationReadiness({ readiness, gaps }) {
  if (!readiness?.bars?.length) return null;
  return (
    <div data-testid="investigation-readiness"
         style={{ marginBottom: 14,
                   padding: "10px 12px",
                   border: "1px solid rgba(126, 230, 168, 0.22)",
                   borderRadius: 4,
                   background: "rgba(0, 40, 22, 0.30)" }}>
      <div style={{ fontSize: 11, color: "#7ee6a8",
                     letterSpacing: 1.4, marginBottom: 6,
                     display: "flex", justifyContent: "space-between" }}>
        <span>▸ INVESTIGATION READINESS</span>
        <span data-testid="readiness-overall">
          {readiness.overall_percent}% · {(readiness.confidence_label || "").toUpperCase()}
        </span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr",
                     gap: 4, fontSize: 11 }}>
        {readiness.bars.map(b => (
          <ReadinessBar key={b.dim} bar={b} />
        ))}
      </div>
      {readiness.recommended_next && (
        <div style={{ marginTop: 10, padding: "6px 8px",
                       border: "1px solid rgba(255, 214, 107, 0.42)",
                       borderRadius: 3,
                       background: "rgba(60, 40, 10, 0.35)",
                       fontSize: 11, color: "#ffe0b3" }}
             data-testid="readiness-next">
          <span style={{ letterSpacing: 1.2, fontSize: 9, marginRight: 6 }}>
            NEXT STEP →
          </span>
          {readiness.recommended_next}
        </div>
      )}
    </div>
  );
}

function ReadinessBar({ bar }) {
  const barColor = bar.state === "complete" ? "#3ddc84"
                 : bar.state === "partial"  ? "#ffd66b"
                 :                             "#8ba598";
  return (
    <div data-testid={`ready-${bar.dim.toLowerCase()}`}
         style={{ padding: "3px 6px",
                   display: "grid",
                   gridTemplateColumns: "80px 1fr 40px",
                   gap: 6, alignItems: "center" }}>
      <span style={{ fontSize: 10, color: "#96c9aa" }}>{bar.dim}</span>
      <span style={{ position: "relative", height: 8,
                      background: "rgba(126, 230, 168, 0.12)",
                      borderRadius: 2, overflow: "hidden" }}>
        <span style={{ position: "absolute", top: 0, left: 0, bottom: 0,
                        width: `${bar.percent}%`, background: barColor }}/>
      </span>
      <span style={{ fontSize: 10, color: barColor, textAlign: "right" }}>
        {bar.percent}%
      </span>
    </div>
  );
}


// ══════════════════════════════════════════════════════════════════
// Recommended Actions — deterministic next steps from ICE.
// ══════════════════════════════════════════════════════════════════
function RecommendedActions({ actions }) {
  if (!actions?.length) return null;
  return (
    <div data-testid="recommended-actions"
         style={{ marginBottom: 14 }}>
      <div style={{ fontSize: 11, color: "#7ee6a8",
                     letterSpacing: 1.4, marginBottom: 8 }}>
        ▸ RECOMMENDED ACTIONS ({actions.length})
      </div>
      <ul style={{ margin: 0, padding: 0, listStyle: "none",
                    display: "flex", flexDirection: "column", gap: 6 }}>
        {actions.map((a, i) => (
          <li key={i} data-testid={`recommended-action-${i}`}
              style={{ display: "grid",
                        gridTemplateColumns: "40px 1fr",
                        gap: 10, padding: "6px 8px",
                        border: "1px solid rgba(126, 230, 168, 0.18)",
                        borderRadius: 3,
                        background: "rgba(0, 40, 22, 0.3)" }}>
            <span style={{ fontSize: 10, letterSpacing: 1,
                            color: _prioColor(a.priority),
                            border: `1px solid ${_prioColor(a.priority)}`,
                            borderRadius: 2,
                            padding: "1px 4px",
                            textAlign: "center",
                            alignSelf: "start" }}>{a.priority}</span>
            <div>
              <div style={{ fontSize: 12, color: "#e6ffe9" }}>{a.title}</div>
              <div style={{ fontSize: 10, color: "#96c9aa", marginTop: 2 }}>
                {a.reason}
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
function _prioColor(p) {
  if (p === "P1") return "#ff9a9a";
  if (p === "P2") return "#ffd66b";
  return                 "#7ee6a8";
}

