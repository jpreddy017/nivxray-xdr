/**
 * XDR PRODUCTION BUILD GUARD · Phase 2 (owner decision 4a)
 *
 * Inspects the COMPILED artifacts in dist/ — never the source .env — and exits
 * non-zero so Vercel fails the deployment rather than shipping a bundle that
 * would route production analysts at preview data.
 *
 * Checks
 *   1. zero preview origins            (preview.emergentagent.com, localhost, :8001)
 *   2. the expected production API origin is actually present
 *   3. no origin outside the allow-list is baked in (unauthorised API base)
 *   4. no edr.nivxforge.com dependency  (Phase 2 is XDR ONLY · decision 5b)
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const EXPECTED_API =
  process.env.XDR_GUARD_EXPECTED_API || "https://nivxray.nivxforge.com";

// Origins that legitimately appear in the bundle (docs links, CDNs, schemas).
const ALLOWED_HOSTS = new Set([
  new URL(EXPECTED_API).host,
  "attack.mitre.org",
  "car.mitre.org",
  "d3fend.mitre.org",
  "www.w3.org",
  "react.dev",
  "reactrouter.com",
  "github.com",
  "raw.githubusercontent.com",
  "lolbas-project.github.io",
  "gtfobins.github.io",
  "www.virustotal.com",
  "otx.alienvault.com",
  "urlscan.io",
  "www.abuseipdb.com",
  "bazaar.abuse.ch",
  "urlhaus.abuse.ch",
  "threatfox.abuse.ch",
  "www.hybrid-analysis.com",
  "learn.microsoft.com",
  "docs.microsoft.com",
  "nvd.nist.gov",
  "cve.mitre.org",
  "www.cisa.gov",
  "sigmahq.io",
  "yara.readthedocs.io",
  "capev2.readthedocs.io",
  "schemas.vercel.sh",
  "fonts.googleapis.com",
  "fonts.gstatic.com",
  // Verified 2026-09-08 by inspecting dist/: these are INPUT PLACEHOLDERS and
  // documentation links in the connector/adopt UI, never a live API base.
  //   falcon.crowdstrike.com                     → capability-registry doc link
  //   api-yourorg.xdr.us.paloaltonetworks.com    → Cortex base-url placeholder
  //   reactjs.org                                → React error-message doc link
  "falcon.crowdstrike.com",
  "api-yourorg.xdr.us.paloaltonetworks.com",
  "reactjs.org",
]);

// RFC 2606 reserved names can only ever be placeholders (e.g. the
// "https://vendor.example.com/api/events" and "https://example.com/hook"
// placeholders in the connector forms), so they can never be a real API base.
const isReservedPlaceholder = (host) =>
  /(^|\.)(example\.(com|net|org)|invalid|test|localhost)$/.test(host);

const PREVIEW_PATTERNS = [
  "preview.emergentagent.com",
  "localhost:8001",
  "127.0.0.1:8001",
  "0.0.0.0:8001",
];

const FORBIDDEN_PHASE2 = ["edr.nivxforge.com"];

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (/\.(js|css|html|map)$/.test(entry)) out.push(p);
  }
  return out;
}

const dist = new URL("../dist", import.meta.url).pathname;
let files;
try {
  files = walk(dist);
} catch {
  console.error("\nXDR PRODUCTION BUILD GUARD · FAILED\n  dist/ not found — run the build first\n");
  process.exit(1);
}

const failures = [];
const notes = [];

let previewHits = 0;
for (const f of files) {
  const body = readFileSync(f, "utf8");
  for (const pat of PREVIEW_PATTERNS) {
    const n = body.split(pat).length - 1;
    if (n) {
      previewHits += n;
      failures.push(`preview origin "${pat}" appears ${n}x in ${f.replace(dist, "dist")}`);
    }
  }
  for (const pat of FORBIDDEN_PHASE2) {
    const n = body.split(pat).length - 1;
    if (n) failures.push(`Phase-2 forbidden host "${pat}" appears ${n}x in ${f.replace(dist, "dist")}`);
  }
}
if (!previewHits) notes.push(`ok · no preview origin embedded (${files.length} artifacts scanned)`);
if (!failures.some((f) => f.includes("edr.nivxforge.com")))
  notes.push("ok · no edr.nivxforge.com dependency (Phase 2 is XDR only)");

let expectedHits = 0;
const foreign = new Map();
for (const f of files) {
  const body = readFileSync(f, "utf8");
  expectedHits += body.split(EXPECTED_API).length - 1;
  for (const m of body.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?/gi)) {
    const host = m[1].toLowerCase();
    if (!ALLOWED_HOSTS.has(host) && !isReservedPlaceholder(host))
      foreign.set(host, (foreign.get(host) || 0) + 1);
  }
}
if (expectedHits === 0) failures.push(`expected production API origin ${EXPECTED_API} is ABSENT from the bundle`);
else notes.push(`ok · API origin ${EXPECTED_API} · ${expectedHits} reference(s)`);

if (foreign.size) {
  for (const [host, n] of [...foreign].sort((a, b) => b[1] - a[1]))
    failures.push(`unauthorised origin baked in: ${host} (${n}x) — add to ALLOWED_HOSTS only if it is not an API base`);
} else {
  notes.push("ok · no unauthorised origin outside the allow-list");
}

// 5 · deployment provenance: the product scope MUST be declared. Owner decision
// 5b removed the cross-host /edr/* redirects, so productScope.js is the only
// remaining thing keeping NivXForge EDR off the XDR hostname.
try {
  const info = JSON.parse(readFileSync(join(dist, "build-info.json"), "utf8"));
  if (info.product_scope !== "xdr")
    failures.push(`build-info.json product_scope is "${info.product_scope}" — must be "xdr", or /edr/* would render EDR on the XDR host`);
  else notes.push('ok · product scope declared "xdr" (EDR paths cannot render here)');
  if (info.api_origin !== EXPECTED_API)
    failures.push(`build-info.json api_origin is "${info.api_origin}" — expected ${EXPECTED_API}`);
} catch {
  failures.push("dist/build-info.json missing or unreadable — build via scripts/vercel-build.sh");
}

console.log("");
for (const n of notes) console.log("  " + n);
if (failures.length) {
  console.error("\nXDR PRODUCTION BUILD GUARD · FAILED");
  for (const f of failures) console.error("  ✗ " + f);
  console.error("");
  process.exit(1);
}
console.log("\nXDR PRODUCTION BUILD GUARD · PASSED\n");
