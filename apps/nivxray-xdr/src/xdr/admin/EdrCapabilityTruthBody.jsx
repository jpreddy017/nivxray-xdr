/**
 * NivXForge EDR · Capability Truth panel.
 *
 * Directive §14: the console must not be able to claim a capability the
 * registry denies. This panel is the registry, rendered — it holds no
 * opinion of its own and hardcodes no status. Everything on screen comes
 * from GET /api/edr/wave0/capabilities.
 *
 * It shows `effective_state`, not `declared_state`. Where the two differ
 * the downgrade reason is shown inline, because the interesting fact is
 * not that a capability is incomplete but WHY the stronger claim is not
 * supported by evidence in this repository.
 */
import React, { useEffect, useMemo, useState } from "react";
import { AlertTriangle, ShieldCheck, ShieldOff } from "lucide-react";
import api from "@/lib/api";

const PLANES = [
  ["", "All planes"],
  ["AGENT", "Plane A · Endpoint agent"],
  ["BACKEND", "Plane B · EDR backend"],
  ["EXPERIENCE", "Plane C · Analyst console"],
];

const PROVEN = new Set(["OPERATIONAL", "PRODUCTION_READY",
                        "END_TO_END_VALIDATED"]);
const PARTIAL = new Set(["GOLDEN_CORPUS_VALIDATED", "SYNTHETIC_VALIDATED",
                         "REAL_ENDPOINT_VALIDATED", "BACKEND_IMPLEMENTED",
                         "UI_IMPLEMENTED"]);

const epFor = (s) => (PROVEN.has(s) ? "evidence_present"
  : PARTIAL.has(s) ? "unknown" : "capability_unavailable");

const Cell = ({ v }) => (
  <span className="mono" style={{
    fontSize: 9.5,
    color: v === "PRESENT" ? "var(--text-dim)"
      : v === "PARTIAL" ? "#E8B931"
      : v === "NOT_APPLICABLE" ? "var(--faint)" : "#8C5A5A",
  }}>{v === "NOT_APPLICABLE" ? "n/a" : v.toLowerCase()}</span>
);

export default function EdrCapabilityTruthBody() {
  const [rows, setRows] = useState(null);
  const [meta, setMeta] = useState(null);
  const [taxonomy, setTaxonomy] = useState(null);
  const [plane, setPlane] = useState("");
  const [err, setErr] = useState(null);

  useEffect(() => {
    Promise.all([
      api.get("/edr/wave0/capabilities"),
      api.get("/edr/wave0/filter-taxonomy"),
    ]).then(([caps, tax]) => {
      setRows(caps.data.capabilities || []);
      setMeta(caps.data.summary || null);
      setTaxonomy(tax.data);
    }).catch((e) => setErr(e?.message || String(e)));
  }, []);

  const shown = useMemo(
    () => (rows || []).filter((r) => !plane || r.plane === plane), [rows, plane]);

  if (err) {
    return (
      <div style={{ padding: 14 }} data-testid="edr-capability-truth-error">
        <span className="nx-ep" data-ep="capability_unavailable" data-known="true">
          ⊘ REGISTRY UNREACHABLE
        </span>
        <div style={{ marginTop: 6, fontSize: 10.5, color: "var(--faint)" }}>
          {err} — no capability status is shown rather than a stale one.
        </div>
      </div>
    );
  }
  if (!rows) {
    return <div style={{ padding: 14, fontSize: 11, color: "var(--faint)" }}
                data-testid="edr-capability-truth-loading">
             Reading the capability registry…
           </div>;
  }

  return (
    <div style={{ padding: "10px 12px 18px" }}
         data-testid="edr-capability-truth">
      <div style={{ display: "flex", gap: 14, flexWrap: "wrap",
                    alignItems: "center", marginBottom: 10 }}>
        {meta && (
          <>
            <Stat label="Capabilities graded" value={meta.total}
                  testid="edr-cap-total" />
            <Stat label="Operational" value={meta.operational}
                  ep={meta.operational ? "evidence_present" : "no_evidence"}
                  testid="edr-cap-operational" />
            <Stat label="Telemetry missing"
                  value={meta.by_gap_class?.TELEMETRY_MISSING ?? 0}
                  ep="capability_unavailable" testid="edr-cap-telemetry-gap" />
            <Stat label="Driver missing"
                  value={meta.by_gap_class?.CONTROL_DRIVER_MISSING ?? 0}
                  ep="capability_unavailable" testid="edr-cap-driver-gap" />
            <Stat label="UI only" value={meta.by_gap_class?.UI_ONLY ?? 0}
                  ep="capability_unavailable" testid="edr-cap-ui-only" />
            <Stat label="Sensors registered" value={meta.sensors_registered}
                  ep={meta.sensors_registered ? "evidence_present"
                                              : "no_evidence"}
                  testid="edr-cap-sensors" />
          </>
        )}
      </div>

      {meta && (
        <div style={{ fontSize: 10, color: "var(--faint)", lineHeight: 1.6,
                      marginBottom: 10, maxWidth: 900 }}
             data-testid="edr-cap-grading-rule">
          {meta.grading_rule}
        </div>
      )}

      {taxonomy && !taxonomy.complete && (
        <div style={{ display: "flex", gap: 8, alignItems: "flex-start",
                      border: "1px solid #4A3A16", background: "#1A1508",
                      padding: "8px 10px", borderRadius: 4, marginBottom: 12,
                      maxWidth: 900 }}
             data-testid="edr-cap-taxonomy-disclosure">
          <AlertTriangle size={13} style={{ color: "#E8B931", flexShrink: 0,
                                            marginTop: 1 }} />
          <div style={{ fontSize: 10.5, lineHeight: 1.6,
                        color: "var(--text-dim)" }}>
            <strong>Filter taxonomy incomplete</strong> —{" "}
            {taxonomy.registered_item_count}/{taxonomy.expected_item_count}{" "}
            baseline items registered. {taxonomy.disclosure}
            <div style={{ color: "var(--faint)", marginTop: 3 }}>
              {taxonomy.provenance}
            </div>
          </div>
        </div>
      )}

      <div style={{ display: "flex", gap: 6, marginBottom: 10,
                    flexWrap: "wrap" }}>
        {PLANES.map(([k, label]) => (
          <button key={k || "all"}
                  className={`btn ${plane === k ? "" : "ghost"}`}
                  onClick={() => setPlane(k)}
                  style={{ fontSize: 10, padding: "3px 9px" }}
                  data-testid={`edr-cap-plane-${k.toLowerCase() || "all"}`}>
            {label}
          </button>
        ))}
      </div>

      <div style={{ overflowX: "auto" }}>
        <table className="mono" style={{ width: "100%", borderCollapse:
                "collapse", fontSize: 10 }}>
          <thead>
            <tr style={{ color: "var(--faint)", textAlign: "left" }}>
              {["Capability", "Effective state", "Gap", "contract", "backend",
                "ui", "telemetry", "driver", "test", "e2e", "Evidence"]
                .map((h) => (
                  <th key={h} style={{ padding: "4px 7px", fontSize: 8.5,
                                       fontWeight: 800, letterSpacing: ".4px",
                                       textTransform: "uppercase",
                                       borderBottom: "1px solid #212B36",
                                       whiteSpace: "nowrap" }}>{h}</th>
                ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.capability_id}
                  style={{ borderBottom: "1px solid #161D24" }}
                  data-testid={`edr-cap-row-${r.capability_id}`}>
                <td style={{ padding: "5px 7px", maxWidth: 260 }}>
                  <div style={{ color: "var(--text)" }}>{r.name}</div>
                  <div style={{ color: "var(--faint)", fontSize: 9 }}>
                    {r.capability_id}
                  </div>
                </td>
                <td style={{ padding: "5px 7px", whiteSpace: "nowrap" }}>
                  <span className="nx-ep" data-ep={epFor(r.effective_state)}
                        data-known="true" style={{ fontSize: 8.5 }}>
                    {r.effective_state}
                  </span>
                  {r.downgrade_reason && (
                    <div style={{ color: "#E8B931", fontSize: 9,
                                  marginTop: 2, whiteSpace: "normal",
                                  maxWidth: 240, lineHeight: 1.5 }}>
                      declared {r.declared_state} — {r.downgrade_reason}
                    </div>
                  )}
                </td>
                <td style={{ padding: "5px 7px", whiteSpace: "nowrap" }}>
                  {r.gap_class === "NONE"
                    ? <ShieldCheck size={11} style={{ color: "#3D8B5F" }} />
                    : <span style={{ color: "#8C5A5A", fontSize: 9 }}>
                        <ShieldOff size={10} style={{ marginRight: 3,
                                                      verticalAlign: -1 }} />
                        {r.gap_class.replace(/_/g, " ").toLowerCase()}
                      </span>}
                </td>
                {["contract_status", "backend_status", "ui_status",
                  "telemetry_status", "control_driver_status", "test_status",
                  "e2e_status"].map((k) => (
                    <td key={k} style={{ padding: "5px 7px",
                                         whiteSpace: "nowrap" }}>
                      <Cell v={r[k]} />
                    </td>
                  ))}
                <td style={{ padding: "5px 7px", maxWidth: 300 }}>
                  <div style={{ color: "var(--cyan)", fontSize: 9,
                                wordBreak: "break-all", lineHeight: 1.5 }}>
                    {r.evidence_reference || "—"}
                  </div>
                  {r.honest_note && (
                    <div style={{ color: "var(--faint)", fontSize: 9,
                                  marginTop: 2, whiteSpace: "normal",
                                  lineHeight: 1.5 }}>
                      {r.honest_note}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const Stat = ({ label, value, ep, testid }) => (
  <div data-testid={testid}>
    <div style={{ color: "var(--faint)", fontSize: 8.5, fontWeight: 800,
                  textTransform: "uppercase", letterSpacing: ".4px" }}>
      {label}
    </div>
    {ep ? (
      <span className="nx-ep" data-ep={ep} data-known="true"
            style={{ fontSize: 11, marginTop: 3, display: "inline-block" }}>
        {value}
      </span>
    ) : (
      <div className="mono" style={{ color: "var(--text)", fontSize: 15,
                                     fontWeight: 800, marginTop: 2 }}>
        {value}
      </div>
    )}
  </div>
);
