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
import { useNavigate } from "react-router-dom";
import {
  Monitor, User, FileText, Network, Mail, Cloud, ArrowRight,
} from "lucide-react";
import { productHref, productMode } from "@/productOrigins";

/**
 * PR-XDR-0 · resolve a pointer's `deep_link` into a real destination.
 * `/xdr/*` → in-product SPA navigation. `/edr/*` → the NivXForge EDR
 * product, resolved through `productOrigins`. Anything else has no
 * destination in this product and the control stays disabled rather than
 * opening a tab that lands nowhere.
 */
function openTarget(p) {
  const link = p?.deep_link;
  if (!link || typeof link !== "string") return null;
  if (link.startsWith("/xdr/")) return { to: link, mode: "IN_PRODUCT" };
  if (link.startsWith("/edr")) {
    const to = productHref("edr", link);
    return { to,
             mode: productMode("edr") === "CONFIGURED"
                     ? "CROSS_PRODUCT" : "IN_PRODUCT" };
  }
  return null;
}

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
  // PR-XDR-0 · read the AUTHORITATIVE backend contract. The pointer carries
  // `status` ∈ {available, no_matching_evidence, not_connected,
  // not_available} plus `bullets` and `reason`. This tab previously keyed
  // off `p.available`, a field the backend never emits, so an unconnected
  // domain fell through to "SEARCHED · scope tightly bounded" — a claim
  // that we queried a domain we cannot query.
  const bullets = Array.isArray(p.bullets) ? p.bullets : [];
  const status  = String(p.status || "");
  if (status === "available") return bullets.length > 0 ? "related" : "searched";
  if (status === "not_connected" || status === "not_available")
    return "not_connected";
  if (status === "no_matching_evidence") return "no_evidence";
  // No status field at all (older payload): fall back to the reason text.
  const r = String(p.reason || "").toLowerCase();
  if (r.includes("not connected") || r.includes("not configured")
      || r.includes("integration") || r.includes("not enabled"))
    return "not_connected";
  if (bullets.length > 0) return "related";
  return "no_evidence";
}

export default function EvidenceTab({ incident }) {
  const navigate = useNavigate();
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
      if (!map[k]) map[k] = { bullets: [], reason: null, status: null,
                                deep_link: null, domain: p.domain };
      const bullets = Array.isArray(p.bullets) ? p.bullets : [];
      map[k].bullets.push(...bullets);
      if (p.reason)     map[k].reason = p.reason;
      if (p.status)     map[k].status = p.status;
      // PR-XDR-0 · the backend field is `deep_link`. This tab used to read
      // `open_href`, which the backend never emits, so the Open control was
      // dead on every domain card.
      if (p.deep_link)  map[k].deep_link = p.deep_link;
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
                    disabled={!openTarget(p)}
                    data-testid={`xdr-record-evidence-${d.key}-open`}
                    data-open-to={openTarget(p)?.to || undefined}
                    data-open-mode={openTarget(p)?.mode || undefined}
                    onClick={() => {
                      const t = openTarget(p);
                      if (!t) return;
                      // PR-XDR-0 · same-product destinations stay in the SPA
                      // (shell mounted, no new tab). A NivXForge EDR target is
                      // a different product, so it resolves through
                      // `productOrigins` and only opens a tab when that
                      // product genuinely lives at another origin.
                      if (t.mode === "CROSS_PRODUCT")
                        window.open(t.to, "_blank", "noopener,noreferrer");
                      else navigate(t.to);
                    }}
                    style={{ opacity: openTarget(p) ? 1 : 0.4 }}
                  >
                    {openTarget(p) ? "Open" : "Explore"}
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
