/**
 * XdrIncidentDomainPage · Slice 7.
 *
 * Route: `/xdr/incidents/:id/domain/:domainKey`
 *
 * The Incident-scoped domain-detail screen — the destination of the
 * Overview → Domain-card click.  Renders the persistent
 * IncidentContextStrip at the top, then a domain-specific body.
 *
 * Slice-7 scope: page shell + all six domain routes wired.
 *   - endpoints: honest placeholder pointing to Slice 8 rewrite
 *     (the Slice 6 canvas moves under the incident in Slice 8;
 *     surfacing a placeholder here avoids duplicating information
 *     architecture while §5 is still open).
 *   - identity / network / email / cloud: NOT CONNECTED honest state.
 *   - files: SEARCHED honest state (consumes /api/edr/detections
 *     but no incident-scoped file-only projection yet).
 *
 * Guardrail: every honest state carries provenance + integration
 * instruction — never a generic empty pane.
 */
import React, { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  Loader2, Radar, Info, Wifi, Mail, Cloud, Fingerprint, FileText, Cpu,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import IncidentContextStrip from "@/xdr/components/IncidentContextStrip";
import { DOMAIN_META } from "@/xdr/domains/domainMeta";
import { getIncident } from "@/lib/incidentsApi";

const STATE_BADGE = {
  not_observed:    { label: "NOT OBSERVED",    color: "var(--yellow)" },
  not_established: { label: "NOT ESTABLISHED", color: "var(--amber)"  },
  not_available:   { label: "NOT AVAILABLE",   color: "var(--muted)"  },
  not_connected:   { label: "NOT CONNECTED",   color: "var(--faint)"  },
};

function StateBadge({ state }) {
  const m = STATE_BADGE[state] || STATE_BADGE.not_available;
  return (
    <span data-testid={`xdr-domain-state-${state}`} style={{
      display: "inline-block", padding: "2px 7px", borderRadius: 3,
      border: `1px solid ${m.color}`, color: m.color,
      fontFamily: "var(--xmono)", fontSize: 9.5, letterSpacing: ".4px",
      fontWeight: 800, textTransform: "uppercase",
    }}>{m.label}</span>
  );
}

export default function XdrIncidentDomainPage() {
  const { id, domainKey } = useParams();
  const navigate = useNavigate();
  const [incident, setIncident] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancel = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const data = await getIncident(id);
        if (!cancel) setIncident(data);
      } catch (e) {
        if (!cancel) setError(e?.response?.data?.detail || e?.message
                                  || "Failed to load incident.");
      } finally {
        if (!cancel) setLoading(false);
      }
    })();
    return () => { cancel = true; };
  }, [id]);

  const meta = DOMAIN_META[domainKey];

  return (
    <XdrShell>
      {loading && (
        <div className="x-empty" data-testid="xdr-incident-domain-loading">
          <Loader2 size={13} className="spin"
                    style={{ verticalAlign: "middle", marginRight: 6 }} />
          Loading incident …
        </div>
      )}
      {!loading && error && (
        <div className="x-empty" style={{ color: "#ff9494" }}
              data-testid="xdr-incident-domain-error">{String(error)}</div>
      )}
      {!loading && !error && !meta && (
        <div className="x-empty" data-testid="xdr-incident-domain-unknown">
          <b>NOT AVAILABLE</b> — Unknown domain <span className="mono">{domainKey}</span>.
        </div>
      )}
      {!loading && !error && incident && meta && (
        <>
          <IncidentContextStrip incident={incident} domainLabel={meta.label} />
          <DomainBody incident={incident}
                        meta={meta}
                        onOpenTrajectory={() => {
                          const inv = incident?.ssot?.investigation_object || {};
                          const host = inv.host || (inv.device && inv.device.hostname);
                          if (!host) return;
                          navigate(`/xdr/endpoints/${encodeURIComponent(host)}/trajectory`);
                        }} />
        </>
      )}
    </XdrShell>
  );
}

function DomainBody({ incident, meta, onOpenTrajectory }) {
  const inv = incident?.ssot?.investigation_object || {};
  const host = inv.host || (inv.device && inv.device.hostname);

  // NOT CONNECTED domains: honest state with clear integration hint.
  if (!meta.connected) {
    return (
      <section className="panel" style={{ padding: 16 }}
                data-testid={`xdr-incident-domain-body-${meta.key}`}>
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                        marginBottom: 10 }}>
          <meta.icon size={14} style={{ color: "var(--faint)" }} />
          <h2 className="page-h1" style={{ margin: 0 }}>{meta.label}</h2>
          <StateBadge state="not_connected" />
        </div>
        <div style={{ color: "var(--muted)", fontSize: 12, marginBottom: 10 }}>
          {meta.subtitle}
        </div>
        <div style={{
          padding: 12, border: "1px dashed var(--border)", borderRadius: 5,
          background: "var(--panel2)", color: "var(--text-dim)", fontSize: 11.5,
          lineHeight: 1.6,
        }}>
          <b style={{ color: "var(--text)" }}>Integration required · {meta.integration}</b>
          <div style={{ marginTop: 6 }}>
            Cross-incident <b>{meta.label}</b> telemetry is not wired for this
            tenant yet.  NivXRay XDR does not fabricate {meta.label.toLowerCase()}
            {" "}evidence — we surface this state instead so the analyst never
            reads an empty pane as a positive security conclusion.
          </div>
          <div style={{ marginTop: 8 }}>
            <span className="mono" style={{ color: "var(--faint)",
                                                  fontSize: 10.5 }}>
              To enable this domain natively:
            </span>
            <ol style={{ margin: "4px 0 0 20px", padding: 0,
                            color: "var(--text-dim)", fontSize: 11 }}>
              <li>Configure the <b>{meta.integration}</b> connector in Administration → Integrations.</li>
              <li>Point it at the tenant's <span className="mono">{incident?.tenant_id
                    || incident?.user_email || "workspace"}</span> scope.</li>
              <li>Return to this Incident and re-open the <b>{meta.label}</b> domain.</li>
            </ol>
          </div>
          <div style={{ marginTop: 12 }}>
            <a href="/xdr/admin/integrations" className="btn primary"
                  style={{ padding: "5px 10px", textDecoration: "none" }}
                  data-testid={`xdr-incident-domain-${meta.key}-configure`}>
              Open Administration → Integrations
            </a>
          </div>
        </div>
      </section>
    );
  }

  // ENDPOINTS domain — native trajectory canvas landing.
  if (meta.key === "endpoints") {
    return (
      <section className="panel" style={{ padding: 16 }}
                data-testid="xdr-incident-domain-body-endpoints">
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                        marginBottom: 10 }}>
          <Cpu size={14} style={{ color: "var(--mint)" }} />
          <h2 className="page-h1" style={{ margin: 0 }}>Endpoints</h2>
        </div>
        <div style={{ color: "var(--muted)", fontSize: 12, marginBottom: 12 }}>
          Forge EDR · process · file · registry · trajectory.  Backed by the
          existing NivXRay Activity Inventory and Stage-2 Verdict evidence.
        </div>
        {host ? (
          <div style={{
            display: "flex", alignItems: "center", gap: 10, padding: 12,
            border: "1px solid var(--border)", borderRadius: 5,
            background: "var(--panel2)",
          }}>
            <Info size={13} style={{ color: "var(--cyan)" }} />
            <div style={{ flex: 1, fontSize: 11.5, color: "var(--text-dim)" }}>
              <b style={{ color: "var(--text)" }}>Device Trajectory Canvas</b>
              {" — "}temporal investigation surface for{" "}
              <span className="mono" style={{ color: "var(--mint)" }}>{host}</span>.
              The canvas is currently reachable at its incident-anchored path
              below.  A rewrite to entity-per-row + tri-directional pane sync
              (Slice 8) lands next.
            </div>
            <button
              className="btn primary" style={{ padding: "5px 10px" }}
              onClick={onOpenTrajectory}
              data-testid="xdr-domain-endpoints-open-trajectory"
            >
              <Radar size={11} /> Open Device Trajectory
            </button>
          </div>
        ) : (
          <div style={{ padding: 12,
                            border: "1px dashed var(--border)", borderRadius: 5,
                            background: "var(--panel2)",
                            color: "var(--text-dim)", fontSize: 11.5 }}>
            <StateBadge state="not_available" />
            <div style={{ marginTop: 6 }}>
              This incident's SSOT does not carry an authoritative endpoint
              host.  Trajectory cannot be opened without one — we do not
              synthesise a device identity.
            </div>
          </div>
        )}
      </section>
    );
  }

  // FILES domain — connected but no incident-scoped file projection yet.
  if (meta.key === "files") {
    return (
      <section className="panel" style={{ padding: 16 }}
                data-testid="xdr-incident-domain-body-files">
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                        marginBottom: 10 }}>
          <FileText size={14} style={{ color: "var(--cyan)" }} />
          <h2 className="page-h1" style={{ margin: 0 }}>Files</h2>
          <StateBadge state="not_established" />
        </div>
        <div style={{ color: "var(--muted)", fontSize: 12, marginBottom: 12 }}>
          Artifact intelligence · IUE Lane C.  Read from the same authoritative
          detections surface as the Suspicious Elements table on the incident
          Overview.
        </div>
        <div style={{
          padding: 12, border: "1px solid var(--border)", borderRadius: 5,
          background: "var(--panel2)", color: "var(--text-dim)", fontSize: 11.5,
          lineHeight: 1.6,
        }}>
          A dedicated file-lane projection has <b>NOT ESTABLISHED</b> a
          file-only view for this incident yet.  File evidence is currently
          surfaced inside the incident's <b>Suspicious Elements</b> table on
          the Overview.  A native file-domain view (with hash reputation,
          signer, PE metadata, and cross-incident file appearance) is
          scheduled for Slice 13.
        </div>
      </section>
    );
  }

  // Fallback — shouldn't hit in this slice.
  return null;
}
