/**
 * Extension Registry — the authoritative NivXRay XDR capability index.
 *
 * Manifests ship as JSON under docs/extensions/**\/*.json and are
 * loaded eagerly by Vite.  This module surfaces:
 *
 *   · listAll()             — every registered manifest
 *   · listByType(type)      — filter by canonical type
 *   · listByLifecycle(ls)   — INSTALLED, ENABLED, DEPRECATED, …
 *   · installedIndex()      — { capability_id → manifest } quick lookup
 *   · coverage()            — one row per canonical type + counts
 *
 * Everything is READ-ONLY here.  Install / configure / test / enable
 * lifecycle mutations belong to a future control-plane API; today the
 * hub renders manifests + provides the wizard shell.  This is
 * consistent with the owner directive: "governed adapters, not
 * arbitrary uploaded code."
 */
import {
  EXTENSION_TYPES, validateManifest,
} from "./extensionContract";

// Eager-load every manifest.  Manifests are pure JSON — no code.
const _modules = import.meta.glob(
  "../../../docs/extensions/**/*.json",
  { eager: true, import: "default" });


function _loadManifests() {
  const out = [];
  for (const [path, m] of Object.entries(_modules)) {
    if (!m || !m.capability_id) continue;
    out.push({ ...m, _path: path });
  }
  return out.sort((a, b) => a.capability_id.localeCompare(b.capability_id));
}

const MANIFESTS = _loadManifests();


export function listAll() { return MANIFESTS; }

export function listByType(type) {
  return MANIFESTS.filter((m) => m.type === type);
}

export function listByLifecycle(ls) {
  return MANIFESTS.filter((m) => m.lifecycle === ls);
}

export function get(id) {
  return MANIFESTS.find((m) => m.capability_id === id) || null;
}

export function installedIndex() {
  const out = {};
  for (const m of MANIFESTS) {
    if (["INSTALLED", "CONFIGURED", "TESTED", "ENABLED",
             "DISABLED", "DEPRECATED"].includes(m.lifecycle))
      out[m.capability_id] = m;
  }
  return out;
}

export function coverage() {
  const t = {};
  for (const type of EXTENSION_TYPES) t[type] = { total: 0, enabled: 0, available: 0 };
  for (const m of MANIFESTS) {
    if (!t[m.type]) t[m.type] = { total: 0, enabled: 0, available: 0 };
    t[m.type].total += 1;
    if (m.lifecycle === "ENABLED") t[m.type].enabled += 1;
    if (m.lifecycle === "AVAILABLE") t[m.type].available += 1;
  }
  return t;
}


/** Validate the entire registry at load time — every manifest must
 *  parse into a valid contract.  Returns [{ id, ok, missing, invalid }]. */
export function validateAll() {
  return MANIFESTS.map((m) => {
    const v = validateManifest(m);
    return { id: m.capability_id, ok: v.valid,
                 missing: v.missing, invalid: v.invalid };
  });
}
