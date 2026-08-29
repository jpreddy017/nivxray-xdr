/**
 * ActivityTab · XDR skin.
 *
 * Reads canonical Activity Inventory (rule #19) and shows the counts.
 * The full temporal canvas lives at /edr/trajectory — this tab surfaces
 * a deep link to open it in a new browser tab (owner telemetry rule).
 */
import React, { useEffect, useMemo, useState } from "react";
import { ExternalLink, Loader2 } from "lucide-react";

import api from "@/lib/api";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

const KINDS = [
  { key: "process",  label: "Processes",  accent: "var(--xpurple)" },
  { key: "file",     label: "Files",      accent: "var(--xcyan)"   },
  { key: "network",  label: "Network",    accent: "var(--xcyan)"   },
  { key: "registry", label: "Registry",   accent: "var(--xamber)"  },
  { key: "identity", label: "Identities", accent: "var(--xmint)"   },
  { key: "system",   label: "Systems",    accent: "var(--xtext)"   },
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
        // The projector expects a timeline; pass an empty one so the
        // response is a valid (empty) inventory rather than a 422.
        const { data } = await api.post("/activity/inventory", {
          case_id:  incident?.id || null,
          timeline: { events: [] },
        });
        if (!cancelled) setInv(data);
      } catch (e) {
        if (!cancelled) setError(e?.response?.data?.detail || e?.message || "Failed to load activity.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  // The projector returns `entities` as a dict keyed by kind
  // ({process:[…], file:[…], …}).  We count per-kind directly.
  const counts = useMemo(() => {
    const c = Object.fromEntries(KINDS.map((k) => [k.key, 0]));
    const entitiesByKind = inv?.entities;
    if (entitiesByKind && typeof entitiesByKind === "object") {
      KINDS.forEach((k) => {
        const arr = entitiesByKind[k.key];
        c[k.key] = Array.isArray(arr) ? arr.length : 0;
      });
    }
    return c;
  }, [inv]);
  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  return (
    <div data-testid={T.activityPane}>
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 10 }}>
        <div className="grow">
          <div className="section-title">Canonical Activity Inventory</div>
          <div className="x-subtle" style={{ marginTop: 4 }}>
            One canonical object drives every panel (owner rule #19).
            Full temporal canvas lives at <span className="mono" style={{ color: "var(--xcyan)" }}>/edr/trajectory</span>.
          </div>
        </div>
        <button
          type="button"
          className="btn primary"
          onClick={() => window.open("/edr/trajectory", "_blank", "noopener,noreferrer")}
        >
          Open Device Trajectory <ExternalLink size={11} />
        </button>
      </div>

      <div className="panel2" style={{ padding: 14 }} data-testid={T.activityInventoryStatus}>
        {loading && (
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, color: "var(--xtext-dim)" }}>
            <Loader2 size={13} className="spin" /> Loading inventory …
          </div>
        )}
        {!loading && error && (
          <div style={{ color: "#ff9494", fontFamily: "var(--xmono)", fontSize: 11.5 }}>
            {String(error)}
          </div>
        )}
        {!loading && !error && (
          <>
            <div style={{ color: "var(--xtext-dim)", fontSize: 12 }}>
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
                <div
                  key={k.key}
                  className="panel2"
                  style={{ padding: "10px 12px", background: "var(--xpanel)" }}
                >
                  <div style={{
                    fontSize: 9.5, letterSpacing: ".3px",
                    textTransform: "uppercase", color: "var(--xmuted)",
                    fontWeight: 700,
                  }}>{k.label}</div>
                  <div style={{
                    marginTop: 4,
                    fontFamily: "var(--xmono)", fontSize: 20, fontWeight: 800,
                    color: counts[k.key] > 0 ? k.accent : "var(--xfaint)",
                  }}>{counts[k.key]}</div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
