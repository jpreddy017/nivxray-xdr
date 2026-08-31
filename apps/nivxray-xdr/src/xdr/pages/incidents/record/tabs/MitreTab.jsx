/**
 * MitreTab · Layer 3 v2 · light-first MITRE ATT&CK view.
 *
 * Groups `incident.mitre` by tactic using the local
 * TECHNIQUES_BY_TACTIC / TECHNIQUE_INDEX registries.  Renders one
 * light card per tactic with the observed techniques underneath.
 * Confidence is inferred from stage-2 confidence bucket + technique
 * count; never fabricated.
 */
import React from "react";
import { Target } from "lucide-react";
import {
  KILL_CHAIN, TECHNIQUES_BY_TACTIC, TECHNIQUE_INDEX,
} from "@/xdr/mitre/mitreTactics";

// Look up which tactic contains a given technique id.
const TECH_TO_TACTIC = (() => {
  const out = {};
  for (const [tactic, techs] of Object.entries(TECHNIQUES_BY_TACTIC)) {
    for (const t of techs) out[t.id] = tactic;
  }
  return out;
})();

const TACTIC_LABEL = (() => {
  const out = {};
  for (const t of KILL_CHAIN) out[t.key] = t.label;
  return out;
})();

// Normalise every incident.mitre element into {tacticKey, techId, techName}.
function normalize(mitre) {
  const rows = [];
  for (const m of (mitre || [])) {
    let tactic = null, techId = null, techName = null;
    if (typeof m === "string") {
      const s = m.trim();
      if (/^T\d/.test(s)) techId = s;
      else               tactic = s.toLowerCase();
    } else if (m && typeof m === "object") {
      tactic  = String(m.tactic_id || m.tactic || m.tacticId
                          || "").toLowerCase() || null;
      techId  = m.technique_id || m.technique || m.id || null;
      techName = m.name || null;
    }
    if (techId && !tactic) tactic = TECH_TO_TACTIC[techId] || null;
    if (techId && !techName) {
      const meta = TECHNIQUE_INDEX?.[techId];
      if (meta) techName = meta.name;
    }
    rows.push({ tactic, techId, techName });
  }
  return rows;
}

function confidenceBucket(bucket, count) {
  const b = String(bucket || "").toLowerCase();
  if (b === "high")   return "high";
  if (b === "medium") return "medium";
  if (b === "low")    return "low";
  return count >= 3 ? "medium" : count > 0 ? "low" : "low";
}

export default function MitreTab({ incident }) {
  const rows = normalize(incident.mitre);
  const conf = incident.verdict_stage2?.confidence_bucket
    || incident.confidence || null;

  // Group by tactic — preserve KILL_CHAIN ordering.
  const byTactic = new Map();
  for (const r of rows) {
    if (!r.tactic) continue;
    if (!byTactic.has(r.tactic)) byTactic.set(r.tactic, []);
    byTactic.get(r.tactic).push(r);
  }

  const orderedTactics = KILL_CHAIN
    .map(t => ({
      key: t.key, label: t.label,
      techs: byTactic.get(t.key) || [],
    }))
    .filter(t => t.techs.length > 0);

  if (orderedTactics.length === 0) {
    return (
      <div data-testid="xdr-record-mitre" className="rl-empty">
        NO EVIDENCE — no MITRE techniques have been projected onto
        this incident yet.
        <span className="kbd">Techniques appear as engines produce evidence</span>
      </div>
    );
  }

  const summary = {
    tactics:    orderedTactics.length,
    techniques: orderedTactics.reduce((a, t) => a + t.techs.length, 0),
    confidence: conf ? String(conf).toUpperCase() : "NOT_RUN",
  };

  return (
    <div data-testid="xdr-record-mitre">
      <div className="rl-metric-grid" style={{ marginBottom: 12 }}>
        <div className="rl-metric info">
          <div className="k">Tactics</div>
          <div className="v">{summary.tactics}</div>
          <div className="sub">of {KILL_CHAIN.length} in ATT&amp;CK</div>
        </div>
        <div className="rl-metric info">
          <div className="k">Techniques</div>
          <div className="v">{summary.techniques}</div>
          <div className="sub">projected on this case</div>
        </div>
        <div className={`rl-metric ${conf ? "info" : "na"}`}>
          <div className="k">Confidence</div>
          <div className="v">{summary.confidence}</div>
          <div className="sub">stage-2 verdict bucket</div>
        </div>
      </div>

      {orderedTactics.map(t => (
        <div key={t.key} className="rl-tactic-group"
              data-testid={`xdr-record-mitre-tactic-${t.key}`}>
          <div className="rl-tactic-head">
            <Target size={14} color="var(--rl-purple)" />
            <span className="rl-tactic-badge">{t.key.toUpperCase()}</span>
            <span className="rl-tactic-name">{TACTIC_LABEL[t.key] || t.label}</span>
            <span className="rl-tactic-count">
              {t.techs.length} technique{t.techs.length === 1 ? "" : "s"}
            </span>
          </div>
          {t.techs.map((r, i) => {
            const c = confidenceBucket(conf, t.techs.length);
            return (
              <div key={i} className="rl-technique-row"
                    data-testid={`xdr-record-mitre-tech-${r.techId || i}`}>
                <span className="rl-technique-id">{r.techId || "—"}</span>
                <span className="rl-technique-name">
                  {r.techName || (r.techId
                    ? "(technique name not in local registry)"
                    : "(unspecified technique)")}
                </span>
                <span className={`rl-technique-conf ${c}`}>{c}</span>
              </div>
            );
          })}
        </div>
      ))}

      <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--rl-faint)",
                      fontFamily: "var(--rs-mono)", letterSpacing: 0.2 }}>
        Techniques sourced from authoritative NivXRay projection · never fabricated.
      </div>
    </div>
  );
}
