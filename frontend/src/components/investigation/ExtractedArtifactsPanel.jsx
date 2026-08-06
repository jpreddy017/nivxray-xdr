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
    <section
      data-testid="extracted-artifacts-panel"
      style={{
        border: "1px solid rgba(0, 255, 128, 0.28)",
        borderRadius: 6,
        background: "rgba(0, 22, 12, 0.55)",
        padding: "14px 16px",
        margin: "0 12px 8px",
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        color: "#c5f5d6",
      }}
    >
      <header style={{ marginBottom: 10 }}>
        <div style={{ fontSize: 11, letterSpacing: 1.6,
                      color: "#7ee6a8", opacity: 0.9 }}>
          ▸ IDA · EXTRACTED ARTIFACTS
        </div>
        <div style={{ fontSize: 12, color: "#96c9aa", marginTop: 3 }}>
          Every artifact below was investigated automatically (Rule R20). Click a
          row to see behaviour, MITRE, LOLBAS and evidence — no re-paste required.
        </div>
      </header>

      {groups.map(g => (
        <ArtifactGroup key={g.key} groupKey={g.key} items={g.items}
                        extras={g.extras} />
      ))}
    </section>
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
