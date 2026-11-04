/**
 * OverviewTab · Incident Evidence Across Domains (XDR skin).
 *
 * Reference: §edom-grid / §edom-card. Left-border color denotes state:
 *   • cyan  = related (has evidence, deep link available)
 *   • faint = searched (no telemetry hits recorded)
 *   • dashed faint = notconnected (integration not present for tenant)
 *
 * PR-XDR-0 · launch buttons navigate IN-PRODUCT (the NivXRay XDR shell
 * stays mounted). Only a NivXForge EDR destination may open a new tab, and
 * only when that product genuinely lives at another origin.
 */
import React from "react";
import { useNavigate } from "react-router-dom";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";
import { productHref, productMode } from "@/productOrigins";

/**
 * PR-XDR-0 · a pointer's `deep_link` must be a canonical in-product
 * NivXRay XDR route, or a NivXForge EDR route resolved through
 * `productOrigins`. Anything else has no destination and the launch
 * control stays disabled instead of opening a tab that lands nowhere.
 */
function openTarget(p) {
  const link = p?.deep_link;
  if (!link || typeof link !== "string") return null;
  if (link.startsWith("/xdr/")) return { to: link, mode: "IN_PRODUCT" };
  if (link.startsWith("/edr")) {
    return { to: productHref("edr", link),
             mode: productMode("edr") === "CONFIGURED"
                     ? "CROSS_PRODUCT" : "IN_PRODUCT" };
  }
  return null;
}

const DOMAIN_LABELS = {
  edr:       "EDR",
  ndr:       "NDR",
  identity:  "IDENTITY",
  cloud:     "CLOUD",
  email:     "EMAIL",
  web:       "WEB",
  workspace: "WORKSPACE",
};

/** Classify a pointer into the reference `edom-card` state class. */
function classifyPointer(p) {
  if (p.status === "available")  return "related";
  // Slice 1: no "searched" state signal yet; treat unconnected domains
  // as `notconnected` when we know the tenant lacks the integration,
  // and `searched` (dim) when we simply have no evidence for it.
  return "notconnected";
}

export default function OverviewTab({ incident }) {
  const navigate = useNavigate();
  const pointers = incident?.evidence_pointers || [];

  return (
    <div data-testid={T.overviewPane}>
      <div className="section-title" style={{ marginBottom: 8 }}>
        Incident Evidence Across Domains
      </div>
      <div style={{
        marginBottom: 12,
        color: "var(--xmuted)", fontSize: 11.5, lineHeight: 1.5,
      }}>
        Each card opens the full domain surface in a new browser tab.
        Unconnected integrations are shown honestly — no fake placeholders.
      </div>

      <div className="edom-grid" data-testid={T.domainCards}>
        {pointers.map((p) => {
          const cls = classifyPointer(p);
          const available = p.status === "available" && !!p.deep_link;
          const domainKey = p.domain || "workspace";
          const displayCount = domainKey === "edr" && available ? "OPEN" : (available ? "→" : "—");
          return (
            <div
              key={domainKey}
              className={`edom-card ${cls}`}
              data-testid={T.domainCard(domainKey)}
            >
              <div className="edom-top">
                <span className="edom-name">
                  {DOMAIN_LABELS[domainKey] || domainKey.toUpperCase()}
                </span>
                <span className="edom-count">{displayCount}</span>
              </div>
              <div className="edom-why">
                <b>{p.label}</b>
                {p.hint && <><br /><span>{p.hint}</span></>}
                {!available && p.reason && (
                  <><br /><span style={{ fontStyle: "italic" }}>{p.reason}</span></>
                )}
              </div>
              <button
                type="button"
                className="edom-open"
                data-testid={T.domainLaunch(domainKey)}
                disabled={!available || !openTarget(p)}
                data-open-to={openTarget(p)?.to || undefined}
                data-open-mode={openTarget(p)?.mode || undefined}
                onClick={() => {
                  const t = openTarget(p);
                  if (!available || !t) return;
                  if (t.mode === "CROSS_PRODUCT")
                    window.open(t.to, "_blank", "noopener,noreferrer");
                  else navigate(t.to);
                }}
              >
                {available && openTarget(p) ? "Open →" : "Not available"}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
