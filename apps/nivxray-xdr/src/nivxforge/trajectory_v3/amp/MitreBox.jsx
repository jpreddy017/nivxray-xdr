// The production "MITRE | ATT&CK" box (old AmpEventDetails precedent: red header bar, Tactics / Techniques, ◇ empty states),
// plus the old console's Observables and Observed Activity blocks, rendered from E1's own attribution (ev.e3_attack).
import React, { useState } from "react";
import { ATTACK_ATTRIBUTION, ATTACK_CATALOGUE_VERSION, SEMANTICS, sevTone, TACTIC_ID, TACTIC_LABEL } from "./attack";
import { C } from "./theme";

const RED = "#b3261e", RED_BODY = "rgba(120,20,20,.32)", RED_LABEL = "#ff8a80";
const none = (testid, text) => <div data-testid={testid} style={{ color: C.muted, fontSize: 12.5, marginTop: 2 }}>◇ {text}</div>;
const label = (t) => <div style={{ color: RED_LABEL, fontWeight: 700, fontSize: 12, marginTop: 8 }}>{t}</div>;
const chip = (tone) => ({ display: "inline-block", margin: "4px 6px 0 0", padding: "2px 8px", borderRadius: 4, fontSize: 12, border: `1px solid ${tone}`, background: C.panel, color: C.text, textDecoration: "none" });

function Technique({ t, sev, type, onHeat }) {
  const [card, setCard] = useState(false);
  return (
    <span style={{ position: "relative", display: "inline-block" }} onMouseEnter={() => setCard(true)} onMouseLeave={() => setCard(false)}>
      <a data-testid="dt-mitre-link" data-status={t.status} href={t.url} target="_blank" rel="noopener noreferrer" style={chip(sevTone(sev, C))}>
        <b style={{ fontFamily: "ui-monospace, Menlo, monospace" }}>{t.technique}</b> {t.display} ↗</a>
      {card && <span data-testid="dt-attack-hovercard" style={{ position: "absolute", left: 0, top: "100%", zIndex: 30, width: 300, background: C.tip, border: `1px solid ${C.line}`,
        borderRadius: 6, padding: "8px 10px", fontSize: 12, lineHeight: 1.5, color: C.text, boxShadow: "0 10px 30px rgba(0,0,0,.5)" }}>
        <b>{t.technique} {t.display}</b><br />{t.description || "No description in the catalogue."}<br />
        <span style={{ color: C.muted }}>{type} · ATT&amp;CK Enterprise v{t.catalogue_version} · {SEMANTICS}</span></span>}
      <span style={{ display: "block", color: C.muted, fontSize: 11 }}>{t.url?.replace("https://", "")}
        <button type="button" data-testid="dt-open-heatmap" onClick={() => onHeat(t.status === "active" ? t.technique : t.replacement || t.technique)}
          style={{ background: "none", border: 0, color: C.accent, cursor: "pointer", fontSize: 11, marginLeft: 6 }}>Open in ATT&amp;CK HeatMap ↗</button></span>
    </span>
  );
}

export function MitreBox({ it, onHeat }) {
  const a = it.ev.e3_attack, tacs = a?.tactics || [], techs = a?.techniques || [], src = a?.sources || [];
  const mismatch = a && a.catalogue_version !== ATTACK_CATALOGUE_VERSION;
  return (
    <div data-testid="dt-sec-mitre" data-attributed={a ? "true" : "false"} style={{ border: `1px solid ${RED}`, borderRadius: 3, overflow: "hidden", margin: "6px 0 10px" }}>
      <div style={{ background: RED, color: "#fff", fontSize: 11.5, fontWeight: 800, letterSpacing: ".6px", padding: "4px 8px" }}>MITRE | ATT&amp;CK</div>
      <div style={{ background: RED_BODY, padding: "4px 10px 9px" }}>
        {label("Tactics")}
        {!tacs.length ? none("dt-mitre-tactics-none", "no tactic attributed") : tacs.map((k) => (
          <a key={k} data-testid="dt-mitre-tactic-link" href={`https://attack.mitre.org/tactics/${TACTIC_ID[k]}/`} target="_blank" rel="noopener noreferrer"
            style={chip(sevTone(a.severity, C))}>{TACTIC_LABEL[k] || k} <span style={{ color: C.muted }}>{TACTIC_ID[k]}</span></a>))}
        {tacs.length > 0 && !a.tactic_ids?.length && <div style={{ color: C.muted, fontSize: 11 }}>Tactics derived from the techniques via the ATT&amp;CK v{a.catalogue_version} catalogue.</div>}
        {label("Techniques")}
        {!techs.length ? none("dt-mitre-techniques-none", "no technique attributed to this observation. Absence of an attribution is not evidence that no technique was used.")
          : techs.map((t) => <Technique key={t.technique} t={t} sev={a.severity} type={a.type} onHeat={onHeat} />)}
        {a && <div style={{ marginTop: 8, fontSize: 12, color: C.text, display: "grid", gridTemplateColumns: "118px minmax(0,1fr)", gap: "2px 6px" }}>
          <span style={{ color: C.muted }}>Attribution</span>
          <span data-testid="dt-attack-type">{a.type === "Heuristic" ? "Heuristic — ingest keyword tag, not a detection" : a.type}</span>
          <span style={{ color: C.muted }}>Mapping source</span>
          <span data-testid="dt-attack-source" style={{ overflowWrap: "anywhere" }}>{src.length ? src.map((s) => [s.rule_id && `rule ${s.rule_id}`, s.rule_name, s.rule_version && `v${s.rule_version}`, s.engine].filter(Boolean).join(" · ")).join("; ") : `E1 ${a.basis}`}</span>
          <span style={{ color: C.muted }}>Confidence</span>
          <span>{src.find((s) => s.confidence != null)?.confidence ?? "not provided by source"}</span>
          <span style={{ color: C.muted }}>ATT&amp;CK version</span>
          <span data-testid="dt-attack-version">ATT&amp;CK Enterprise v{a.catalogue_version}{mismatch ? ` (UI catalogue v${ATTACK_CATALOGUE_VERSION}: VERSION MISMATCH)` : ""}</span>
        </div>}
        {a && <div data-testid="dt-attack-note" style={{ color: C.muted, fontSize: 11.5, marginTop: 6 }}>{SEMANTICS}</div>}
        <div style={{ color: C.muted, fontSize: 10.5, marginTop: 6 }}>{ATTACK_ATTRIBUTION}</div>
      </div>
    </div>
  );
}

export function ObservedBlocks({ it }) {
  const e = it.ev, files = e.file_artefacts || [];
  const act = e.command_line || e.file || e.network || e.process;
  return (
    <div style={{ margin: "0 0 10px", fontSize: 12.5 }}>
      <div data-testid="dt-observables"><b>Observables</b>
        {!files.length ? none("dt-observables-none", "no file artefact was reported with this observation.")
          : files.map((f, i) => <div key={i} style={{ overflowWrap: "anywhere" }}>{f.path || "path not reported"} <span style={{ color: C.muted }}>{f.sha256 ? `SHA-256 ${f.sha256}` : "SHA-256 not reported"}</span></div>)}
      </div>
      <div data-testid="dt-observed-activity" style={{ marginTop: 8 }}><b>Observed Activity</b>
        <div style={{ display: "grid", gridTemplateColumns: "118px minmax(0,1fr)", gap: 6 }}>
          <span style={{ color: C.muted }}>{it.kind.label}</span>
          <span data-testid="dt-observed-activity-text" style={{ fontFamily: "ui-monospace, Menlo, monospace", fontSize: 12, overflowWrap: "anywhere" }}>{act || "Not reported"}</span>
        </div>
      </div>
    </div>
  );
}
