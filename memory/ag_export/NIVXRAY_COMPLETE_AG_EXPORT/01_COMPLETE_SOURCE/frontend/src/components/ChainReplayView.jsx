/**
 * ChainReplayView — read-only viewer for a persisted multi-stage chain
 * investigation loaded from history.
 *
 * Feb-2026 spec (P0 Chain Persistence):
 *   • Default rehydrate mode. Renders per-stage input + output + engine +
 *     confidence, plus the aggregate SOC verdict (family, kill-chain, IOCs,
 *     MITRE, LOLBAS, YARA) exactly like ChainStageEditor would after RUN.
 *   • Zero side effects on the workspace — this is a snapshot.
 *   • Provides a "Restore to Workspace" button that, after an unsaved-changes
 *     confirm, hands the stages back to the workspace so they can be edited.
 *   • Provides a "Close" button that dismisses the viewer.
 *
 * Props:
 *   record        object   — full history document (kind === "chain")
 *   onRestore     ()=>void — called when the analyst wants to edit the chain
 *   onClose       ()=>void — dismiss the viewer
 */
import { AlertTriangle, BookmarkPlus, ChevronDown, ChevronRight, Download, ExternalLink, FileJson, Play, X } from "lucide-react";
import { useState } from "react";
import api from "@/lib/api";
import { foldPowerShell } from "@/lib/powershellFolder";

export default function ChainReplayView({ record, onRestore, onClose }) {
  const [drillOpen, setDrillOpen] = useState({});
  const [savingKb, setSavingKb] = useState(false);
  const [kbResult, setKbResult] = useState(null); // { slug, bucket_size, created }
  const [kbError, setKbError] = useState("");
  const [exportingStix, setExportingStix] = useState(false);
  const [stixError, setStixError] = useState("");
  const [stixOk, setStixOk] = useState("");
  if (!record || record.kind !== "chain") return null;

  const saveAsKbTemplate = async () => {
    setSavingKb(true);
    setKbError("");
    setKbResult(null);
    try {
      const r = await api.post("/kb/save-from-investigation", {
        investigation_id: record.id,
        synth: true,
      });
      setKbResult(r.data);
    } catch (e) {
      setKbError(e?.response?.data?.detail || e?.message || "failed to save KB template");
    }
    setSavingKb(false);
  };

  const exportStix21 = async () => {
    setExportingStix(true);
    setStixError("");
    setStixOk("");
    try {
      // Fetch bundle JSON, then trigger client-side download so the analyst
      // gets a properly-named .json file without a round-trip through the
      // /download attachment endpoint (works even behind proxies).
      const r = await api.post("/report/stix/investigation", {
        investigation_id: record.id,
        tlp: "AMBER",
      });
      const bundle = r.data;
      const blob = new Blob([JSON.stringify(bundle, null, 2)], {
        type: "application/vnd.oasis.stix+json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `nivxforge_stix_${record.id.slice(0, 8)}_${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setStixOk(`STIX 2.1 bundle downloaded · ${(bundle.objects || []).length} objects · TLP:AMBER`);
    } catch (e) {
      setStixError(e?.response?.data?.detail || e?.message || "STIX export failed");
    }
    setExportingStix(false);
  };

  const stages = record.stages || [];
  const agg = record.aggregate || {};
  const stageLabels = record.stage_labels || [];
  const familyLabel = agg?.family?.family;
  const familyConf = agg?.family?.confidence;
  const verdict = agg?.risk?.verdict;
  const score = agg?.risk?.score;
  const level = agg?.risk?.level;

  return (
    <div data-testid="chain-replay-view" className="nvx-card" style={{ marginTop: 12, borderColor: "var(--accent)", scrollMarginTop: 80 }}>
      <div className="nvx-card-head" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div className="mono" style={{ fontSize: 11, letterSpacing: "0.22em", color: "var(--accent)" }}>
          ▸ CHAIN REPLAY · READ-ONLY ({stages.length} STAGES)
          {record.starred && <span style={{ marginLeft: 8, color: "#e2cc50" }}>★</span>}
          {record.run_count > 1 && (
            <span style={{ marginLeft: 8, color: "var(--text-mute)" }}>×{record.run_count} runs</span>
          )}
        </div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <button
            className="nvx-btn sm"
            onClick={saveAsKbTemplate}
            disabled={savingKb}
            data-testid="btn-chain-replay-save-kb"
            title="Distil this chain into a Knowledge Base template with playbook + hunt queries."
            style={{ borderColor: "var(--warn)", color: savingKb ? "var(--text-mute)" : "var(--warn)" }}
          >
            <BookmarkPlus size={11} /> {savingKb ? "SAVING…" : "SAVE AS KB TEMPLATE"}
          </button>
          <button
            className="nvx-btn sm"
            onClick={exportStix21}
            disabled={exportingStix}
            data-testid="btn-chain-replay-export-stix"
            title="Export a STIX 2.1 bundle (Indicators, Malware, Attack Patterns, Observed Data, Relationships, Kill Chain, TLP:AMBER) for import into OpenCTI, MISP, Sentinel, Splunk ES, QRadar."
            style={{ borderColor: "var(--accent)", color: exportingStix ? "var(--text-mute)" : "var(--accent)" }}
          >
            <FileJson size={11} /> {exportingStix ? "BUILDING…" : "EXPORT STIX 2.1"}
          </button>
          <button
            className="nvx-btn primary sm"
            onClick={onRestore}
            data-testid="btn-chain-replay-restore"
            title="Restore this chain to the workspace for editing. Prompts to confirm if you have unsaved changes."
          >
            <Play size={11} /> RESTORE TO WORKSPACE
          </button>
          <button
            className="nvx-btn sm ghost"
            onClick={onClose}
            data-testid="btn-chain-replay-close"
          >
            <X size={11} /> CLOSE
          </button>
        </div>
      </div>

      {(stixOk || stixError) && (
        <div
          data-testid="chain-replay-stix-status"
          style={{
            padding: "8px 12px",
            borderTop: "1px solid var(--border)",
            background: stixError ? "rgba(255,80,80,0.10)" : "rgba(90,180,160,0.10)",
            fontSize: 11,
            color: stixError ? "var(--high)" : "var(--accent)",
            display: "flex", alignItems: "center", gap: 8,
          }}
        >
          {stixError ? (
            <>
              <AlertTriangle size={12} />
              <span data-testid="chain-replay-stix-error">STIX export failed · {stixError}</span>
            </>
          ) : (
            <>
              <Download size={12} />
              <span data-testid="chain-replay-stix-ok">{stixOk}</span>
            </>
          )}
        </div>
      )}

      {(kbResult || kbError) && (
        <div
          data-testid="chain-replay-kb-status"
          style={{
            padding: "8px 12px",
            borderTop: "1px solid var(--border)",
            borderBottom: "1px solid var(--border)",
            background: kbError ? "rgba(255,80,80,0.10)" : "rgba(226,126,93,0.10)",
            fontSize: 11,
            color: kbError ? "var(--high)" : "var(--warn)",
            display: "flex", alignItems: "center", gap: 8,
          }}
        >
          {kbError ? (
            <>
              <AlertTriangle size={12} />
              <span data-testid="chain-replay-kb-error">KB template failed · {kbError}</span>
            </>
          ) : (
            <>
              <BookmarkPlus size={12} />
              <span data-testid="chain-replay-kb-ok">
                {kbResult.created ? "▪ NEW KB ARCHETYPE" : "▸ KB TEMPLATE REFRESHED"}
                {" — slug "}<span className="mono" style={{ color: "var(--accent)" }}>{kbResult.slug}</span>
                {" · cluster size "}{kbResult.bucket_size}
              </span>
              <a
                href={`/kb#${kbResult.slug}`}
                target="_self"
                data-testid="link-chain-replay-kb-open"
                style={{ color: "var(--accent)", display: "inline-flex", alignItems: "center", gap: 3, marginLeft: "auto" }}
              >
                OPEN IN KB <ExternalLink size={10} />
              </a>
            </>
          )}
        </div>
      )}

      <div className="nvx-card-body" style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {stages.map((s, idx) => {
          // Deterministic constant folding for DISPLAY ONLY — raw preview
          // stays on the backend.  Un-obfuscates `'S'+'ys'+'tem.Net.WebClient'`
          // and backticked identifiers so the analyst reads the real
          // command instead of the operator's evasion trick.
          const rawInput  = (s.input_preview || "").slice(0, 400);
          const foldedIn  = foldPowerShell(rawInput);
          const rawOutput = (s.output || "").slice(0, 4000);
          const foldedOut = foldPowerShell(rawOutput);
          return (
          <div key={idx} data-testid={`chain-replay-stage-${idx}`} style={{
            border: "1px solid var(--border)", borderRadius: 4, padding: 8,
            background: "rgba(0,0,0,0.15)",
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <span className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.20em" }}>
                STAGE {idx}{stageLabels[idx] ? ` · ${stageLabels[idx]}` : ""}
                {(foldedIn.changed || foldedOut.changed) && (
                  <span data-testid={`chain-replay-normalized-${idx}`}
                        title="Constant-folded for display: quoted-string concatenation and backtick escapes were resolved. Raw command is preserved on the backend."
                        style={{
                          marginLeft: 8, padding: "1px 6px",
                          background: "rgba(126,227,201,0.15)",
                          border: "1px solid #7ee3c9", color: "#7ee3c9",
                          fontSize: 9, letterSpacing: "0.14em", borderRadius: 3,
                        }}>
                    NORMALIZED
                  </span>
                )}
              </span>
              <span className="mono" style={{ fontSize: 10, color: "var(--text-mute)" }}>
                engine=<span style={{ color: "var(--accent)" }}>{s.engine || "n/a"}</span>
                {" · "}conf=<span style={{ color: (s.confidence ?? 0) >= 60 ? "var(--ok)" : "var(--warn)" }}>{s.confidence ?? 0}/100</span>
                {s.reached_shellcode && <span style={{ color: "var(--high)" }}> · SHELLCODE</span>}
                {s.corrupt_payload && <span style={{ color: "var(--high)" }}> · <AlertTriangle size={9} /> CORRUPT</span>}
              </span>
            </div>
            <pre style={{
              background: "rgba(0,0,0,0.3)", padding: 6, margin: 0,
              maxHeight: 100, overflow: "auto", fontSize: 10, borderRadius: 3,
              whiteSpace: "pre-wrap", wordBreak: "break-all",
            }} data-testid={`chain-replay-input-${idx}`}>{foldedIn.text}</pre>
            <div style={{ marginTop: 6 }}>
              <button
                className="nvx-btn sm ghost"
                style={{ padding: "2px 6px" }}
                onClick={() => setDrillOpen((o) => ({ ...o, [idx]: !o[idx] }))}
                data-testid={`btn-chain-replay-drill-${idx}`}
              >
                {drillOpen[idx] ? <ChevronDown size={10} /> : <ChevronRight size={10} />} DECODED OUTPUT
              </button>
              {drillOpen[idx] && (
                <pre style={{
                  background: "rgba(0,0,0,0.3)", padding: 6, marginTop: 4,
                  maxHeight: 200, overflow: "auto", fontSize: 10, borderRadius: 3,
                  whiteSpace: "pre-wrap", wordBreak: "break-all",
                }} data-testid={`chain-replay-output-${idx}`}>
                  {foldedOut.text}
                  {s.output_truncated ? "\n\n… (truncated in storage — RESTORE and re-run for full output)" : ""}
                </pre>
              )}
            </div>
          </div>
          );
        })}
      </div>

      <div className="nvx-card-body" style={{ borderTop: "1px solid var(--border)", background: "rgba(0,0,0,0.20)" }}>
        <div className="mono" style={{ fontSize: 11, letterSpacing: "0.22em", color: "var(--accent)", marginBottom: 8 }}>
          ▸ AGGREGATE — UNIFIED SOC VERDICT (SAVED)
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 8, marginBottom: 10 }}>
          {familyLabel && (
            <div data-testid="chain-replay-family">
              <div className="mono" style={{ fontSize: 9, letterSpacing: "0.18em", color: "var(--text-mute)" }}>MALWARE FAMILY</div>
              <div style={{ fontSize: 13, color: "var(--high)", fontWeight: 700 }}>{familyLabel}</div>
              <div style={{ fontSize: 10, color: "var(--text-mute)" }}>confidence {familyConf}%</div>
            </div>
          )}
          <div data-testid="chain-replay-verdict">
            <div className="mono" style={{ fontSize: 9, letterSpacing: "0.18em", color: "var(--text-mute)" }}>VERDICT</div>
            <div style={{
              fontSize: 13,
              color: level === "high" ? "var(--high)" : level === "medium" ? "var(--warn)" : "var(--ok)",
              fontWeight: 700,
            }}>
              {verdict || "—"} · {score ?? 0}/100
            </div>
            <div style={{ fontSize: 10, color: "var(--text-mute)" }}>{stages.length} stages · chain-amplified</div>
          </div>
          <div data-testid="chain-replay-iocs">
            <div className="mono" style={{ fontSize: 9, letterSpacing: "0.18em", color: "var(--text-mute)" }}>MERGED IOCs</div>
            <div style={{ fontSize: 11, color: "var(--text)" }}>
              {Object.entries(agg.iocs || {}).filter(([, v]) => v?.length).map(([k, v]) => (
                <span key={k} style={{ marginRight: 8 }}>{k}: <span style={{ color: "var(--accent)" }}>{v.length}</span></span>
              ))}
            </div>
          </div>
          <div>
            <div className="mono" style={{ fontSize: 9, letterSpacing: "0.18em", color: "var(--text-mute)" }}>MITRE / LOLBAS / YARA</div>
            <div style={{ fontSize: 11, color: "var(--text)" }}>
              {(agg.mitre || []).length}T · {(agg.lolbas || []).length}L · {(agg.yara || []).length}Y
            </div>
          </div>
        </div>

        {(agg.kill_chain || []).length > 0 && (
          <div style={{ marginBottom: 10 }}>
            <div className="mono" style={{ fontSize: 9, letterSpacing: "0.18em", color: "var(--text-mute)", marginBottom: 4 }}>
              KILL CHAIN (MITRE ATT&CK ORDERING)
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {agg.kill_chain.map((k, i) => (
                <span key={i} data-testid={`chain-replay-kc-${k.id}`} style={{
                  fontSize: 10, padding: "3px 7px", borderRadius: 3,
                  background: "rgba(226,126,93,0.10)", border: "1px solid var(--warn)",
                  color: "var(--warn)",
                }} title={`${k.technique} · first seen: Stage ${k.stage}`}>
                  {k.id} <span style={{ color: "var(--text-mute)" }}>· S{k.stage}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        {Object.entries(agg.iocs || {}).filter(([, v]) => v?.length).map(([k, v]) => (
          <div key={k} style={{ marginBottom: 6, fontSize: 10.5 }}>
            <span className="mono" style={{ color: "var(--text-mute)", letterSpacing: "0.14em" }}>{k.toUpperCase()} ▸ </span>
            {v.slice(0, 20).map((x, i) => (
              <span key={i} style={{ color: "var(--accent)", marginRight: 8, fontFamily: "JetBrains Mono, monospace" }}>{x}</span>
            ))}
          </div>
        ))}

        {/* Duplicate action row at the bottom so RESTORE/CLOSE remain reachable
            even if the top of the card is scrolled behind the sticky header. */}
        <div style={{ display: "flex", gap: 6, justifyContent: "flex-end", marginTop: 12, paddingTop: 10, borderTop: "1px dashed var(--border)" }}>
          <button
            className="nvx-btn primary sm"
            onClick={onRestore}
            data-testid="btn-chain-replay-restore-bottom"
            title="Restore this chain to the workspace for editing."
          >
            <Play size={11} /> RESTORE TO WORKSPACE
          </button>
          <button
            className="nvx-btn sm ghost"
            onClick={onClose}
            data-testid="btn-chain-replay-close-bottom"
          >
            <X size={11} /> CLOSE
          </button>
        </div>
      </div>
    </div>
  );
}
