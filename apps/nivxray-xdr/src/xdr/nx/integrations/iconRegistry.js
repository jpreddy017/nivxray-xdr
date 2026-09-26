/**
 * Integration icon REGISTRY · the single place a third-party product
 * identity is declared.
 *
 * OWNER DIRECTIVE (2026-06): a real integration must carry the AUTHENTIC
 * vendor/product icon obtained from an official vendor source. We do not
 * draw approximations, initials in circles, generic shields or invented
 * logos, and we never recolour, stretch or redraw a trademark.
 *
 * Verification states — every entry declares one, and the UI behaves
 * differently for each:
 *   OFFICIAL    · asset retrieved from an official vendor source, stored
 *                 under `public/vendors/` with its provenance recorded.
 *   UNVERIFIED  · no official asset has been verified yet → the console
 *                 renders a NEUTRAL NivX container with the product name.
 *                 It must NEVER be replaced by a look-alike.
 *   NOT_A_VENDOR· a NivXRay-native concept. It has no vendor identity and
 *                 uses the NivX icon family (`NxEntityIcon`) instead.
 *
 * `asset` is a path under the app's `public/` root, so it is served as-is
 * and is never inlined or transformed.
 */

export const OFFICIAL = "OFFICIAL";
export const UNVERIFIED = "UNVERIFIED";
export const NOT_A_VENDOR = "NOT_A_VENDOR";

const entry = ({ vendor, product, asset = null, source = null,
                 verified_at = null, variants = null,
                 state = UNVERIFIED, usage = "integration-identity",
                 aliases = [] }) => ({
  vendor, product, asset, source, verified_at, variants, state, usage,
  aliases,
});

/**
 * vendor_id → product_id → declaration.
 *
 * Every row below is currently `UNVERIFIED`: no official asset file has
 * been retrieved into this repository yet. That is a deliberate, visible
 * statement of fact — the console shows the neutral container and the
 * product name until a verified asset with recorded provenance lands.
 */
export const INTEGRATION_ICONS = {
  cisco: {
    "cisco-xdr": entry({ vendor: "Cisco", product: "Cisco XDR",
      aliases: ["cisco_xdr", "ciscoxdr"] }),
    "secure-endpoint": entry({ vendor: "Cisco",
      product: "Cisco Secure Endpoint", aliases: ["amp", "cisco-amp"] }),
    duo: entry({ vendor: "Cisco", product: "Duo" }),
  },
  "palo-alto": {
    "cortex-xdr": entry({ vendor: "Palo Alto Networks",
      product: "Cortex XDR", aliases: ["cortex", "cortex_xdr", "paloalto"] }),
    "cortex-xsiam": entry({ vendor: "Palo Alto Networks",
      product: "Cortex XSIAM" }),
  },
  microsoft: {
    "defender-xdr": entry({ vendor: "Microsoft",
      product: "Microsoft Defender XDR",
      aliases: ["defender", "mdxdr", "m365d"] }),
    "defender-endpoint": entry({ vendor: "Microsoft",
      product: "Microsoft Defender for Endpoint",
      aliases: ["mde", "defender-for-endpoint"] }),
    "defender-identity": entry({ vendor: "Microsoft",
      product: "Microsoft Defender for Identity" }),
    "defender-office": entry({ vendor: "Microsoft",
      product: "Microsoft Defender for Office 365" }),
    sysmon: entry({ vendor: "Microsoft", product: "Sysmon",
      aliases: ["microsoft-sysmon"] }),
    windows: entry({ vendor: "Microsoft", product: "Windows",
      aliases: ["windows-eventlog", "windows-security-evd"] }),
    entra: entry({ vendor: "Microsoft", product: "Microsoft Entra ID" }),
    azure: entry({ vendor: "Microsoft", product: "Microsoft Azure" }),
    m365: entry({ vendor: "Microsoft", product: "Microsoft 365",
      aliases: ["m365-unified-audit"] }),
  },
  crowdstrike: {
    falcon: entry({ vendor: "CrowdStrike", product: "CrowdStrike Falcon",
      aliases: ["crowdstrike-falcon"] }),
  },
  sentinelone: {
    singularity: entry({ vendor: "SentinelOne",
      product: "SentinelOne Singularity", aliases: ["s1"] }),
  },
  elastic: {
    security: entry({ vendor: "Elastic", product: "Elastic Security" }),
    fleet: entry({ vendor: "Elastic", product: "Elastic Fleet" }),
  },
  splunk: {
    splunk: entry({ vendor: "Splunk", product: "Splunk" }),
  },
  aws: {
    cloudtrail: entry({ vendor: "AWS", product: "AWS CloudTrail",
      aliases: ["aws-cloudtrail"] }),
    guardduty: entry({ vendor: "AWS", product: "Amazon GuardDuty" }),
  },
  google: {
    gcp: entry({ vendor: "Google Cloud", product: "Google Cloud" }),
  },
  okta: {
    okta: entry({ vendor: "Okta", product: "Okta" }),
  },
  snort: {
    snort: entry({ vendor: "Snort", product: "Snort",
      aliases: ["snort-eve"] }),
  },
  linux: {
    auditd: entry({ vendor: "Linux", product: "auditd",
      aliases: ["linux-auditd"] }),
  },
  nivxray: {
    edr: entry({ vendor: "NivXRay", product: "NivXRay EDR",
      state: NOT_A_VENDOR,
      aliases: ["nivxforge-linux-sensor", "nivxray-edr"] }),
    collector: entry({ vendor: "NivXRay", product: "NivXRay Collector",
      state: NOT_A_VENDOR, aliases: ["cef-leef"] }),
  },
};

//: alias → "vendor/product", built once.
const ALIAS = (() => {
  const map = {};
  for (const [v, products] of Object.entries(INTEGRATION_ICONS)) {
    for (const [p, decl] of Object.entries(products)) {
      const key = `${v}/${p}`;
      map[p] = key;
      map[key] = key;
      for (const a of decl.aliases || []) map[a] = key;
      map[decl.product.toLowerCase()] = key;
    }
  }
  return map;
})();

/**
 * Resolve any identifier the backend uses for a product to its icon
 * declaration. An unknown identifier returns `null` — the caller renders
 * the neutral container, never a guess.
 */
export function resolveIntegrationIcon(id) {
  if (!id) return null;
  const key = ALIAS[String(id).trim().toLowerCase()];
  if (!key) return null;
  const [v, p] = key.split("/");
  return { id: key, ...INTEGRATION_ICONS[v][p] };
}

/** Audit helper: every declaration with its verification state. */
export function integrationIconInventory() {
  const rows = [];
  for (const [v, products] of Object.entries(INTEGRATION_ICONS)) {
    for (const [p, d] of Object.entries(products)) {
      rows.push({ id: `${v}/${p}`, ...d });
    }
  }
  return rows;
}
