/**
 * ActivityTab · reads canonical Activity Inventory for the incident.
 *
 * This tab is intentionally read-only in Slice 1 — the operational
 * canvas already ships in `/edr/trajectory`.  We show the analyst
 * the counts + a deep link into the full canvas.
 */
import React, { useEffect, useState } from "react";
import { ExternalLink, Activity, Loader2 } from "lucide-react";

import api from "@/lib/api";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

const KINDS = [
  { key: "process",  label: "Processes" },
  { key: "file",     label: "Files" },
  { key: "network",  label: "Network" },
  { key: "registry", label: "Registry" },
  { key: "identity", label: "Identities" },
  { key: "system",   label: "Systems" },
];

export default function ActivityTab({ incident }) {
  const [inv, setInv]         = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        // Slice 1 · pass just the case id.  The projector tolerates an
        // absent timeline and returns an empty inventory (deterministic,
        // rule #13).  Later slices will fuse in real timelines.
        const { data } = await api.post("/activity/inventory",
                                            { case_id: incident?.id || null });
        if (!cancelled) setInv(data);
      } catch (e) {
        if (!cancelled) setError(e?.response?.data?.detail || e?.message || "Failed to load activity.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  const countByKind = React.useMemo(() => {
    const counts = Object.fromEntries(KINDS.map((k) => [k.key, 0]));
    const entities = inv?.entities || [];
    entities.forEach((e) => {
      if (counts[e.kind] != null) counts[e.kind] += 1;
    });
    return counts;
  }, [inv]);

  const total = (inv?.entities || []).length;

  return (
    <section
      data-testid={T.activityPane}
      style={{ display: "flex", flexDirection: "column", gap: 14 }}
    >
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        gap: 12, flexWrap: "wrap",
      }}>
        <div>
          <div style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 11, letterSpacing: "0.18em",
            color: "rgba(148,163,184,0.85)", textTransform: "uppercase",
          }}>
            Canonical Activity Inventory
          </div>
          <div style={{ marginTop: 4, fontSize: 12,
                          color: "rgba(148,163,184,0.65)" }}>
            One canonical object drives every panel (owner rule&nbsp;#19).
            Full temporal canvas lives at <code style={{ color: "#c4b5fd" }}>/edr/trajectory</code>.
          </div>
        </div>
        <button
          type="button"
          onClick={() => window.open("/edr/trajectory", "_blank", "noopener,noreferrer")}
          className="nvx-btn sm"
          style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
        >
          Open Device Trajectory <ExternalLink size={12} />
        </button>
      </div>

      <div
        data-testid={T.activityInventoryStatus}
        style={{
          padding: 14,
          border: "1px solid rgba(148,163,184,0.14)",
          borderRadius: 10,
          background: "linear-gradient(160deg, rgba(15,23,42,0.72), rgba(2,6,23,0.62))",
        }}
      >
        {loading && (
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8,
                          color: "rgba(148,163,184,0.85)",
                          fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}>
            <Loader2 size={13} className="spin" /> Loading inventory …
          </div>
        )}
        {!loading && error && (
          <div style={{ color: "#fca5a5", fontSize: 12,
                          fontFamily: "JetBrains Mono, monospace" }}>
            {String(error)}
          </div>
        )}
        {!loading && !error && (
          <>
            <div style={{
              display: "inline-flex", alignItems: "center", gap: 8,
              fontSize: 12, color: "rgba(203,213,225,0.85)",
              fontFamily: "JetBrains Mono, monospace",
            }}>
              <Activity size={14} style={{ color: "#67e8f9" }} />
              {total === 0
                ? "No canonical entities projected for this incident yet."
                : `${total} canonical entit${total === 1 ? "y" : "ies"} · fused across ${KINDS.length} kinds`}
            </div>
            <div style={{
              marginTop: 12,
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
              gap: 8,
            }}>
              {KINDS.map((k) => (
                <div key={k.key} style={{
                  padding: "10px 12px",
                  borderRadius: 8,
                  border: "1px solid rgba(148,163,184,0.14)",
                  background: "rgba(2,6,23,0.5)",
                }}>
                  <div style={{ fontSize: 10, letterSpacing: "0.14em",
                                  color: "rgba(148,163,184,0.7)",
                                  fontFamily: "JetBrains Mono, monospace",
                                  textTransform: "uppercase" }}>
                    {k.label}
                  </div>
                  <div style={{ marginTop: 4, fontSize: 22, fontWeight: 800,
                                  color: countByKind[k.key] > 0 ? "#e2e8f0" : "rgba(148,163,184,0.55)",
                                  fontFamily: "JetBrains Mono, monospace" }}>
                    {countByKind[k.key]}
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
      <style>{`@keyframes ac-spin { from { transform: rotate(0); } to { transform: rotate(360deg); } }
                .spin { animation: ac-spin 1s linear infinite; }`}</style>
    </section>
  );
}
