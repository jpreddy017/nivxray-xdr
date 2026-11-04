/**
 * NxVendorIcon · third-party product identity, or an honest neutral.
 *
 * An analyst should recognise an integrated product before reading its
 * name — but only from the AUTHENTIC asset. Where no official asset has
 * been verified, this renders a neutral NivX container carrying the
 * product's textual identity and marks itself `data-nx-icon-state`
 * so the gap is auditable in the DOM instead of being papered over with a
 * look-alike.
 */
import React from "react";
import { OFFICIAL, resolveIntegrationIcon } from "./integrations/iconRegistry";
import "./nx-vendor.css";

export default function NxVendorIcon({ id, name, size = 20, withLabel = false,
                                       testid }) {
  const decl = resolveIntegrationIcon(id);
  const label = name || decl?.product || String(id || "Unknown product");
  const official = decl && decl.state === OFFICIAL && decl.asset;
  const initial = label.trim().charAt(0).toUpperCase();

  return (
    <span className="nx-vi" data-testid={testid || `nx-vendor-${id || "unknown"}`}
          data-nx-icon-state={decl ? decl.state : "UNREGISTERED"}
          title={official ? label : `${label} · official icon not verified`}>
      <span className="nx-vi-frame" style={{ width: size + 8, height: size + 8 }}>
        {official ? (
          /* The asset is served verbatim: never recoloured, never redrawn. */
          <img className="nx-vi-img" src={decl.asset} alt={label}
               width={size} height={size} loading="lazy" />
        ) : (
          <span className="nx-vi-neutral" aria-hidden="true">{initial}</span>
        )}
      </span>
      {withLabel && <span className="nx-vi-label">{label}</span>}
    </span>
  );
}
