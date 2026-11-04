/**
 * AttackTab — dedicated ATT&CK view.
 *
 * Reads `investigation.attack_mapping`:
 *   · Coverage Wheel (per-tactic bars, deterministic level 1..3)
 *   · Technique cards grouped by tactic
 *   · Kill-chain overview (every canonical tactic, covered ✓ / gap ○)
 *   · MITRE Navigator layer JSON download
 *   · STIX 2.1 export (piggybacks the existing report endpoint)
 */
import { useMemo } from "react";
import { useParams } from "react-router-dom";
import { T } from "../theme";
import api from "@/lib/api";

const TACTIC_LABELS = {
  reconnaissance:       "Reconnaissance",
  resource_development: "Resource Development",
  initial_access:       "Initial Access",
  execution:            "Execution",
  persistence:          "Persistence",
  privilege_escalation: "Privilege Escalation",
  defense_evasion:      "Defense Evasion",
  credential_access:    "Credential Access",
  discovery:            "Discovery",
  lateral_movement:     "Lateral Movement",
  collection:           "Collection",
  command_and_control:  "Command & Control",
  exfiltration:         "Exfiltration",
  impact:               "Impact",
};


function CoverageBar({ tac }) {
  const barColor = tac.level >= 3 ? "#F87171"
                 : tac.level === 2 ? "#F5A34C" : "#7DB1D6";
  const pct = Math.min(1, tac.unique / 5);
  return (
    <div className="flex items-center gap-3 text-[11px]"
         data-testid={`coverage-bar-${tac.tactic}`}>
      <span className="font-mono" style={{ color: T.inkDim, minWidth: 160 }}>
        {TACTIC_LABELS[tac.tactic] || tac.tactic}
      </span>
      <div className="flex-1 h-2.5 rounded overflow-hidden"
           style={{ background: T.paper2 }}>
        <div style={{ width: `${pct * 100}%`, height: "100%",
                      background: `linear-gradient(90deg, ${barColor}44, ${barColor})` }} />
      </div>
      <span className="font-mono font-bold" style={{ color: T.ink, minWidth: 28,
                                                     textAlign: "right" }}>
        {tac.unique}
      </span>
    </div>
  );
}


function KillChainRow({ node }) {
  const covered = node.covered;
  return (
    <div className="flex items-center gap-2 text-[11px]"
         data-testid={`killchain-${node.tactic}`}>
      <span className="text-[13px] font-bold"
            style={{ color: covered ? "#4ADE80" : T.inkFaint, minWidth: 16 }}>
        {covered ? "✓" : "○"}
      </span>
      <span className="font-mono"
            style={{ color: covered ? T.ink : T.inkFaint, minWidth: 180 }}>
        {TACTIC_LABELS[node.tactic] || node.tactic}
      </span>
      <div className="flex flex-wrap gap-1 flex-1">
        {node.techniques.slice(0, 4).map(t => (
          <span key={t} className="text-[9px] font-mono px-1 py-0.5 rounded"
                style={{ background: T.paper2, color: T.inkDim,
                         border: `1px solid ${T.line}` }}>
            {t}
          </span>
        ))}
        {node.techniques.length > 4 && (
          <span className="text-[9px] font-mono" style={{ color: T.inkFaint }}>
            +{node.techniques.length - 4}
          </span>
        )}
      </div>
    </div>
  );
}


function downloadJSON(name, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)],
                        { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}


export default function AttackTab({ inv }) {
  const { caseId } = useParams();
  const am = inv?.attack_mapping;

  const summary = useMemo(() => am?.coverage_summary || {}, [am]);
  const tactics    = am?.tactics    || [];
  const techniques = am?.techniques || [];
  const killChain  = am?.kill_chain || [];

  if (!am) {
    return <div className="p-12 text-[11px]" style={{ color: T.inkFaint }}
                data-testid="attack-tab-empty">
      No ATT&amp;CK mapping available for this case.
    </div>;
  }

  const exportNavigator = () =>
    downloadJSON(`${caseId}-nivxray-navigator.json`, am.navigator);

  const exportSTIX = async () => {
    try {
      const r = await api.get(`/v2/report/${encodeURIComponent(caseId)}.stix.json`,
                              { responseType: "blob" });
      const url = URL.createObjectURL(r.data);
      const a = document.createElement("a");
      a.href = url; a.download = `${caseId}-nivxray.stix.json`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert("STIX export failed: " + (e?.message || e));
    }
  };

  return (
    <div data-testid="attack-tab" className="max-w-5xl mx-auto py-8 px-6 space-y-8">
      {/* Header + export buttons */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <div className="text-[10px] tracking-[2px] font-bold mb-1"
               style={{ color: T.inkMute }}>MITRE ATT&amp;CK · ENTERPRISE</div>
          <div className="text-[22px] font-bold" style={{ color: T.ink }}>
            Attack Mapping
          </div>
          <div className="text-[12px] mt-1" style={{ color: T.inkDim }}>
            {summary.unique_tactics} tactic(s) · {summary.unique_techniques} technique(s)
            · {summary.unique_bases} unique base technique(s) covered
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={exportNavigator}
                  data-testid="btn-export-navigator"
                  className="text-[11px] px-3 py-1.5 rounded font-mono hover:opacity-80"
                  style={{ background: T.paper2, color: T.ink,
                           border: `1px solid ${T.line}` }}>
            Export Navigator JSON
          </button>
          <button onClick={exportSTIX}
                  data-testid="btn-export-stix"
                  className="text-[11px] px-3 py-1.5 rounded font-mono hover:opacity-80"
                  style={{ background: T.paper2, color: T.ink,
                           border: `1px solid ${T.line}` }}>
            Export STIX 2.1
          </button>
        </div>
      </div>

      {/* Coverage bars */}
      <section data-testid="attack-coverage-section">
        <div className="text-[9px] tracking-[1.5px] font-bold mb-2"
             style={{ color: T.inkMute }}>TACTIC COVERAGE</div>
        <div className="space-y-1.5">
          {tactics.length === 0 && (
            <div className="text-[11px]" style={{ color: T.inkFaint }}>
              No tactics covered — device appears benign.
            </div>
          )}
          {tactics.map(t => <CoverageBar key={t.tactic} tac={t} />)}
        </div>
      </section>

      {/* Kill chain */}
      <section data-testid="attack-killchain-section">
        <div className="text-[9px] tracking-[1.5px] font-bold mb-2"
             style={{ color: T.inkMute }}>KILL CHAIN</div>
        <div className="space-y-1"
             style={{ background: T.paper2, border: `1px solid ${T.line}`,
                      borderRadius: 6, padding: 12 }}>
          {killChain.map(n => <KillChainRow key={n.tactic} node={n} />)}
        </div>
      </section>

      {/* Techniques grouped by tactic */}
      <section data-testid="attack-techniques-section">
        <div className="text-[9px] tracking-[1.5px] font-bold mb-2"
             style={{ color: T.inkMute }}>TECHNIQUES BY TACTIC</div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {tactics.map(t => (
            <div key={t.tactic}
                 data-testid={`technique-group-${t.tactic}`}
                 className="rounded-md p-3"
                 style={{ background: T.paper2, border: `1px solid ${T.line}` }}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] font-bold" style={{ color: T.ink }}>
                  {TACTIC_LABELS[t.tactic] || t.tactic}
                </span>
                <span className="text-[10px] font-mono" style={{ color: T.inkMute }}>
                  {t.unique} technique · {t.count} event
                </span>
              </div>
              <div className="flex flex-wrap gap-1">
                {t.techniques.map(tech => (
                  <span key={tech.id}
                        title={`${tech.count} event(s)`}
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                        style={{ background: T.paper, color: T.inkDim,
                                 border: `1px solid ${T.line}` }}>
                    {tech.id}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <div className="text-[10px] font-mono pt-4 border-t"
           style={{ color: T.inkFaint, borderColor: T.line }}>
        {techniques.length} technique(s) mapped · deterministic · read directly from the IKG
      </div>
    </div>
  );
}
