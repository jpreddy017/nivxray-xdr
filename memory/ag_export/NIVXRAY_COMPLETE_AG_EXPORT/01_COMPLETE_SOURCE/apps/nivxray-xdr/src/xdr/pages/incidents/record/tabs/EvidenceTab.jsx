/**
 * EvidenceTab · Layer 3 v2 · light-first domain evidence cards.
 *
 * Reads authoritative `incident.evidence_pointers` (already
 * projected by the backend) and renders each of the six SOC domains
 * as a light card with a semantic status pill:
 *
 *   RELATED       — the domain has produced evidence for this case
 *   SEARCHED      — the domain was queried but produced no hits
 *   NO EVIDENCE   — the domain applies but no evidence was found
 *   NOT CONNECTED — the underlying integration is not configured
 *
 * Zero fabrication — states come straight from the backend pointer.
 */
import React from "react";
import {
  Monitor, User, FileText, Network, Mail, Cloud, ArrowRight,
} from "lucide-react";

const DOMAINS = [
  { key: "endpoint",  label: "Endpoint", Icon: Monitor,
    sub: "Forge EDR · process · file · registry · trajectory" },
  { key: "identity",  label: "Identity", Icon: User,
    sub: "ITDR · authentication · privilege" },
  { key: "file",      label: "Files",    Icon: FileText,
    sub: "Artifact intelligence · IUE lane C" },
  { key: "network",   label: "Network",  Icon: Network,
    sub: "NDR · DNS · flow · beacon" },
  { key: "email",     label: "Email",    Icon: Mail,
    sub: "Message · sender · attachment · URL" },
  { key: "cloud",     label: "Cloud",    Icon: Cloud,
    sub: "IaaS · SaaS control plane · CASB" },
];

const STATUS_ORDER = ["related", "searched", "no_evidence", "not_connected"];

function normalizeStatus(p) {
  if (!p) return "not_connected";
  // Backend pointers carry `available` (bool), `bullets` (evidence list) and
  // `reason` (why not available).  Map them onto the four semantic states.
  const bullets = Array.isArray(p.bullets) ? p.bullets : [];
  if (p.available === false) {
    // If the reason mentions "not connected" or "not configured",
    // treat as NOT_CONNECTED.  Otherwise NO_EVIDENCE.
    const r = String(p.reason || "").toLowerCase();
    if (r.includes("not connected") || r.includes("not configured") || r.includes("integration"))
      return "not_connected";
    return "no_evidence";
  }
  if (bullets.length > 0) return "related";
  return "searched";
}

export default function EvidenceTab({ incident }) {
  // Group pointers by domain (backend may emit synonymous keys).
  const byDomain = React.useMemo(() => {
    const alias = {
      edr: "endpoint",  endpoint: "endpoint",
      itdr: "identity", identity: "identity",
      file: "file",     files:    "file",
      ndr:  "network",  network:  "network",
      email:"email",
      cloud:"cloud",
    };
    const map = {};
    for (const p of (incident.evidence_pointers || [])) {
      const k = alias[p.domain] || p.domain;
      if (!map[k]) map[k] = { bullets: [], reason: null, available: null,
                                open_href: null };
      const bullets = Array.isArray(p.bullets) ? p.bullets : [];
      map[k].bullets.push(...bullets);
      if (p.reason)                map[k].reason = p.reason;
      if (p.available === false)   map[k].available = false;
      if (p.available === true && map[k].available !== false)
                                    map[k].available = true;
      if (p.open_href)             map[k].open_href = p.open_href;
    }
    return map;
  }, [incident.evidence_pointers]);

  return (
    <div data-testid="xdr-record-evidence">
      <div className="rl-section" style={{ marginBottom: 12 }}>
        <div className="rl-section-title">Incident evidence across domains</div>
        <div className="rl-domain-grid" data-testid="xdr-record-evidence-grid">
          {DOMAINS.map(d => {
            const p = byDomain[d.key];
            const status = normalizeStatus(p);
            const count = (p?.bullets?.length) || 0;
            return (
              <div key={d.key} className={`rl-domain-card ${status}`}
                    data-testid={`xdr-record-evidence-${d.key}`}
                    data-status={status}>
                <div className="rl-domain-head">
                  <span className="rl-domain-icon"><d.Icon size={16} /></span>
                  <span className="rl-domain-name">{d.label}</span>
                  <span className={`rl-domain-status ${status}`}>
                    {status === "related"      && "RELATED"}
                    {status === "searched"     && "SEARCHED"}
                    {status === "no_evidence"  && "NO EVIDENCE"}
                    {status === "not_connected" && "NOT CONNECTED"}
                  </span>
                </div>
                <div className="rl-domain-sub">{d.sub}</div>
                <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                  <span className={`rl-domain-count ${count === 0 ? "dim" : ""}`}>
                    {count === 0
                      ? (status === "not_connected" ? "—" : "0")
                      : count}
                  </span>
                  <span style={{ fontSize: 10.5, color: "var(--rl-muted)",
                                  fontFamily: "var(--rs-mono)" }}>
                    {count === 1 ? "detection" : "detections"}
                    {status === "searched" && " · scope tightly bounded"}
                    {status === "not_connected" && " · integration required"}
                  </span>
                </div>
                {p?.reason && status !== "related" && (
                  <div style={{ fontSize: 11, color: "var(--rl-text-dim)",
                                  fontFamily: "var(--rs-mono)", lineHeight: 1.55 }}>
                    {p.reason}
                  </div>
                )}
                <div className="rl-domain-actions">
                  <button
                    type="button"
                    className="rl-domain-link"
                    disabled={status !== "related"}
                    data-testid={`xdr-record-evidence-${d.key}-open`}
                    onClick={() => {
                      if (p?.open_href && typeof window !== "undefined")
                        window.open(p.open_href, "_blank");
                    }}
                    style={{ opacity: status === "related" ? 1 : 0.4 }}
                  >
                    {status === "related" ? "Open" : "Explore"}
                    <ArrowRight size={11} />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
        <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--rl-faint)",
                        fontFamily: "var(--rs-mono)", letterSpacing: 0.2 }}>
          Evidence counts sourced from authoritative NivXRay APIs · never fabricated.
        </div>
      </div>
    </div>
  );
}

// Ordering helper if consumers want to sort domains by status severity.
export { STATUS_ORDER };
