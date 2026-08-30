/**
 * IntegrationsBody · Slice 10.1 — Enhanced Integrations UI.
 *
 * Two sections, matching the owner-approved
 * nivxray-one-xdr-console_Workspace_Enhanced.html mockup:
 *
 *   1. CONNECTED SOURCES — a live table of authoritative telemetry
 *      sources projected from the existing /admin/osint/services API.
 *      Columns: Source · Type · Status · Volume · Last Event.
 *      Honest states surface here: NO MATCHING EVIDENCE when the
 *      tenant has none.
 *
 *   2. ADD INTEGRATION — a static catalog of 12 telemetry categories
 *      the analyst can request.  Clicking a tile does NOT fake a
 *      Save/Connect operation — it opens a honest "NOT CONNECTED"
 *      dialog that names the authoritative backend surface required
 *      to wire the integration.
 *
 * Quality bar (locked): never claim CrowdStrike Falcon / Palo Alto /
 * Okta / M365 telemetry is flowing unless the authoritative
 * /admin/osint/services or a future connector API actually reports
 * that it is.
 */
import React, { useState } from "react";
import {
  Monitor, Database, Flame, Globe, FileText, Mail,
  User as UserIcon, Cloud as CloudIcon, Puzzle, Command as CmdIcon,
  Link2, Wrench, X, Plug, CheckCircle2, AlertTriangle,
} from "lucide-react";

// 12-tile telemetry catalog (matches the mockup order).
const CATALOG = [
  { key: "edr",    label: "EDR / Endpoint",   icon: Monitor,   note: "CrowdStrike / SentinelOne / Defender / SEP" },
  { key: "siem",   label: "SIEM",             icon: Database,  note: "Splunk / Sentinel / Chronicle / Elastic" },
  { key: "fw",     label: "Firewall",         icon: Flame,     note: "Palo Alto / Fortinet / Check Point" },
  { key: "net",    label: "Network",          icon: Globe,     note: "Zeek / NDR / packet mirror" },
  { key: "dns",    label: "DNS",              icon: FileText,  note: "Umbrella / Infoblox / DNS resolver logs" },
  { key: "email",  label: "Email",            icon: Mail,      note: "M365 / Google Workspace / Proofpoint" },
  { key: "id",     label: "Identity",         icon: UserIcon,  note: "Entra ID / Okta / Active Directory" },
  { key: "cloud",  label: "Cloud",            icon: CloudIcon, note: "AWS / Azure / GCP control plane" },
  { key: "saas",   label: "SaaS",             icon: Puzzle,    note: "Salesforce / Slack / Box" },
  { key: "app",    label: "Application",      icon: CmdIcon,   note: "Custom app · runtime signals" },
  { key: "api",    label: "API",              icon: Link2,     note: "REST / webhook · outbound events" },
  { key: "custom", label: "Custom Telemetry", icon: Wrench,    note: "Arbitrary JSON · ad-hoc parser" },
];

// Map a raw OSINT-service row (or any future connector row) into
// the columns the mockup shows.  Non-destructive: never invent
// volume / last-event when the payload doesn't carry them — surface
// them as N/A instead.
function normaliseSource(r) {
  const rawStatus = String(r.status || r.state || (r.enabled ? "connected" : "unknown")).toLowerCase();
  let status = "unknown";
  if (rawStatus === "connected" || rawStatus === "healthy" || rawStatus === "active" || r.enabled === true) status = "connected";
  else if (rawStatus === "degraded" || rawStatus === "warning") status = "degraded";
  else if (rawStatus === "disconnected" || rawStatus === "down" || r.enabled === false) status = "disconnected";
  return {
    id:     r.id || r.name || r.service,
    source: r.name || r.service || r.provider || "—",
    type:   r.type || r.category || r.kind || "—",
    status,
    volume:      r.volume  || r.events_per_day || r.eps || null,
    last_event:  r.last_event || r.last_check || r.last_seen || null,
  };
}

function StatusPill({ status }) {
  const map = {
    connected:    { label: "Connected",    color: "var(--mint)",   Icon: CheckCircle2 },
    degraded:     { label: "Degraded",     color: "var(--amber)",  Icon: AlertTriangle },
    disconnected: { label: "Disconnected", color: "#ff5b5b",        Icon: X },
    unknown:      { label: "Unknown",      color: "var(--faint)",  Icon: AlertTriangle },
  }[status] || { label: status, color: "var(--faint)", Icon: AlertTriangle };
  const I = map.Icon;
  return (
    <span data-testid={`xdr-integrations-status-${status}`} style={{
      color: map.color, fontWeight: 700, fontSize: 11,
      display: "inline-flex", alignItems: "center", gap: 5,
    }}>
      <I size={11} /> {map.label}
    </span>
  );
}

export default function IntegrationsBody({ rows }) {
  const [active, setActive] = useState(null);
  const normalised = (rows || []).map(normaliseSource);
  const activeCount = normalised.filter((r) => r.status === "connected").length;

  return (
    <div data-testid="xdr-admin-integrations-body">
      {/* Section 1 — Connected Sources */}
      <section className="panel" style={{ padding: 0, marginBottom: 14,
                                                overflow: "hidden" }}
                data-testid="xdr-integrations-connected">
        <div style={{
          padding: "10px 14px", borderBottom: "1px solid var(--border)",
          background: "var(--panel2)",
          display: "flex", alignItems: "center", gap: 10,
        }}>
          <div style={{
            fontFamily: "var(--xmono)", fontSize: 10, letterSpacing: ".4px",
            fontWeight: 800, color: "var(--muted)", textTransform: "uppercase",
          }}>Connected Sources</div>
          <span style={{ flex: 1 }} />
          <span className="mono" style={{ color: "var(--mint)", fontSize: 10.5,
                                                fontWeight: 700 }}>
            {activeCount} active
          </span>
        </div>
        {normalised.length === 0 ? (
          <div className="x-empty" style={{ padding: 20 }}>
            <b>NO MATCHING EVIDENCE</b> — No telemetry sources are wired
            for this tenant yet.  Pick a category below to request one.
          </div>
        ) : (
          <table className="x-table" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th>Source</th>
                <th>Type</th>
                <th>Status</th>
                <th>Volume</th>
                <th>Last Event</th>
              </tr>
            </thead>
            <tbody>
              {normalised.map((r) => (
                <tr key={r.id} data-testid={`xdr-integrations-row-${r.id}`}>
                  <td style={{ color: "var(--text)", fontWeight: 700 }}>
                    {r.source}
                  </td>
                  <td className="mono" style={{ color: "var(--text-dim)" }}>
                    {r.type}
                  </td>
                  <td><StatusPill status={r.status} /></td>
                  <td className="mono" style={{ color: "var(--text-dim)" }}>
                    {r.volume ? String(r.volume) : (
                      <span style={{ color: "var(--faint)", fontSize: 10 }}>
                        N/A · not reported by API
                      </span>
                    )}
                  </td>
                  <td className="mono" style={{ color: "var(--muted)" }}>
                    {r.last_event
                      ? String(r.last_event).slice(0, 19).replace("T", " ")
                      : <span style={{ color: "var(--faint)", fontSize: 10 }}>N/A</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* Section 2 — Add Integration catalog */}
      <section className="panel" style={{ padding: 14 }}
                data-testid="xdr-integrations-catalog">
        <div style={{
          fontFamily: "var(--xmono)", fontSize: 10, letterSpacing: ".4px",
          fontWeight: 800, color: "var(--muted)", textTransform: "uppercase",
          marginBottom: 12,
        }}>
          Add Integration — What do you want to connect?
        </div>
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
          gap: 10,
        }}>
          {CATALOG.map((c) => (
            <button
              key={c.key}
              type="button"
              className="btn"
              onClick={() => setActive(c)}
              data-testid={`xdr-integrations-tile-${c.key}`}
              style={{
                display: "flex", flexDirection: "column",
                alignItems: "center", justifyContent: "center",
                padding: "18px 12px", gap: 8, minHeight: 96,
                border: "1px solid var(--border)", borderRadius: 6,
                background: "var(--panel2)",
                transition: "border-color .12s, background .12s",
              }}
              title={c.note}
            >
              <c.icon size={20} style={{ color: "var(--purple)" }} />
              <span style={{ fontSize: 11.5, color: "var(--text-dim)",
                                fontWeight: 700 }}>{c.label}</span>
            </button>
          ))}
        </div>
      </section>

      {/* Honest NOT CONNECTED modal — no fake save action */}
      {active && (
        <div
          role="dialog"
          data-testid="xdr-integrations-modal"
          style={{
            position: "fixed", inset: 0, background: "rgba(0,0,0,.7)",
            display: "flex", alignItems: "center", justifyContent: "center",
            zIndex: 60, padding: 20,
          }}
          onClick={() => setActive(null)}
        >
          <div className="panel" onClick={(e) => e.stopPropagation()}
                style={{ maxWidth: 480, padding: 20 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10,
                            marginBottom: 10 }}>
              <active.icon size={18} style={{ color: "var(--purple)" }} />
              <h2 style={{ margin: 0, color: "var(--text)", fontSize: 15 }}>
                Add {active.label} integration
              </h2>
              <span style={{ flex: 1 }} />
              <button className="btn ghost" onClick={() => setActive(null)}
                        style={{ padding: 4 }}
                        data-testid="xdr-integrations-modal-close">
                <X size={13} />
              </button>
            </div>
            <div style={{
              display: "inline-block", padding: "2px 7px", borderRadius: 3,
              border: `1px solid var(--faint)`, color: "var(--faint)",
              fontFamily: "var(--xmono)", fontSize: 9.5, letterSpacing: ".4px",
              fontWeight: 800, textTransform: "uppercase", marginBottom: 10,
            }}>NOT CONNECTED</div>
            <div style={{ color: "var(--text-dim)", fontSize: 12,
                            lineHeight: 1.6, marginBottom: 10 }}>
              A native <b>{active.label}</b> connector for NivXRay XDR is
              not wired yet.  <span className="mono">{active.note}</span>.
            </div>
            <div style={{ color: "var(--text-dim)", fontSize: 11.5,
                            lineHeight: 1.6, marginBottom: 12 }}>
              NivXRay XDR does not fake a Save/Connect step.  To actually
              wire this source, an authoritative backend connector must
              be provisioned — the console will surface real
              <span className="mono"> /admin/*</span> API rows here once
              it exists.
            </div>
            <div style={{
              padding: 10, background: "var(--panel2)",
              border: "1px solid var(--border)", borderRadius: 4,
              fontSize: 10.5, color: "var(--faint)",
              fontFamily: "var(--xmono)",
            }}>
              request-id: {active.key}-{Date.now().toString(36)}
            </div>
            <div style={{ marginTop: 14, textAlign: "right" }}>
              <button className="btn primary" onClick={() => setActive(null)}
                        style={{ padding: "5px 12px" }}
                        data-testid="xdr-integrations-modal-ok">
                <Plug size={11} /> Understood
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
