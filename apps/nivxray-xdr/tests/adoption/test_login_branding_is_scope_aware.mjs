#!/usr/bin/env node
/**
 * P0-EDR · Login branding must be PRODUCT-SCOPE SPECIFIC.
 *
 * Regression gate for the production defect: `edr.nivxforge.com/login`
 * rendered "NIVXRAY XDR" / "EXTENDED DETECTION & RESPONSE" even though the
 * deployment reported `product_scope=edr`. Root cause was a hard-coded
 * default `product = "NIVXRAY_XDR"` on the shared `/login` route plus a
 * hard-coded "XDR" wordmark and tagline in the brand lockup.
 *
 * Two layers, so neither a behavioural nor a textual regression can slip:
 *   1. BEHAVIOUR — import productScope.js twice with different
 *      REACT_APP_PRODUCT_SCOPE values and assert the resolved brand.
 *   2. SOURCE    — assert the login page and brand lockup no longer contain
 *      a hard-coded product identity.
 *
 * Usage: node tests/adoption/test_login_branding_is_scope_aware.mjs
 * Exit 0 = green, 1 = broken.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(__dirname, "../../src");
const failures = [];
const notes = [];

const ok = (cond, msg) => (cond ? notes.push("ok · " + msg)
                                : failures.push(msg));

/** Load productScope.js fresh under a given deployment scope. */
async function loadScope(scope) {
  process.env.REACT_APP_PRODUCT_SCOPE = scope;
  const url = `${path.join(SRC, "productScope.js")}?scope=${scope}-${Math.random()}`;
  return import(url);
}

// ── 1 · behaviour ────────────────────────────────────────────────
const edr = await loadScope("edr");
const xdr = await loadScope("xdr");
const unscoped = await loadScope("");

// EDR deployment — required rendering (owner spec).
ok(edr.PRODUCT_SCOPE === "edr", "edr build resolves PRODUCT_SCOPE=edr");
ok(edr.BRAND.suffix === "EDR",
   `edr wordmark suffix must be "EDR" (got "${edr.BRAND.suffix}") — the live defect showed "XDR"`);
ok(`NIVXRAY ${edr.BRAND.suffix}` === "NIVXRAY EDR",
   'edr primary brand renders "NIVXRAY EDR"');
ok(`${edr.BRAND.name} ${edr.BRAND.nameSuffix}` === "NivXRay EDR",
   'edr login card product name renders "NivXRay EDR"');
ok(edr.BRAND.subtitle.toUpperCase() === "ENDPOINT DETECTION & RESPONSE",
   'edr subtitle renders "ENDPOINT DETECTION & RESPONSE"');
ok(edr.BRAND.taglineLead === "ENDPOINT",
   'edr lockup tagline reads "ENDPOINT DETECTION / RESPONSE"');
ok(edr.BRAND.documentTitle === "NivXRay EDR",
   'edr document title is "NivXRay EDR"');

// XDR deployment — must be preserved EXACTLY as shipped.
ok(xdr.BRAND.suffix === "XDR", "xdr wordmark suffix preserved as XDR");
ok(`${xdr.BRAND.name} ${xdr.BRAND.nameSuffix}` === "NivXRay XDR",
   'xdr login card product name preserved as "NivXRay XDR"');
ok(xdr.BRAND.subtitle.toUpperCase() === "EXTENDED DETECTION & RESPONSE",
   "xdr subtitle preserved");
ok(xdr.BRAND.taglineLead === "EXTENDED", "xdr lockup tagline preserved");
ok(xdr.BRAND.documentTitle === "NivXRay XDR", "xdr document title preserved");

// The two products must never resolve to the same identity.
ok(edr.BRAND.suffix !== xdr.BRAND.suffix,
   "edr and xdr resolve to DIFFERENT brands");
ok(edr.BRAND.documentTitle !== xdr.BRAND.documentTitle,
   "edr and xdr resolve to different document titles");

// An unscoped (combined/preview) build keeps the XDR identity.
ok(unscoped.BRAND.suffix === "XDR",
   "unscoped/preview build keeps the XDR identity");

// brandFor() must be explicit and must not leak the ambient scope.
ok(xdr.brandFor("edr").suffix === "EDR" && edr.brandFor("xdr").suffix === "XDR",
   "brandFor(scope) is explicit and ignores the ambient scope");

// ── 2 · source · no hard-coded product identity ──────────────────
const login = fs.readFileSync(path.join(SRC, "pages/LoginPage.jsx"), "utf8");
const lockup = fs.readFileSync(
  path.join(SRC, "components/brand/NivxrayBrand.jsx"), "utf8");
const main = fs.readFileSync(path.join(SRC, "main.jsx"), "utf8");

ok(!/product = "NIVXRAY_XDR"/.test(login),
   "LoginPage no longer hard-codes the XDR product as its default");
ok(/PRODUCT_SCOPE === "edr"/.test(login),
   "LoginPage derives its default product from the deployment scope");
ok(!/NivXForge <span/.test(login) && !/>NivXRay <span/.test(login),
   "LoginPage no longer hard-codes a product name in JSX");
ok(/brand\.nameSuffix/.test(login) && /brand\.subtitle/.test(login),
   "LoginPage renders its product name and subtitle from the brand table");
ok(!/EXTENDED  DETECTION/.test(lockup),
   "brand lockup no longer hard-codes the EXTENDED tagline");
ok(/brand\.suffix/.test(lockup) && /brand\.taglineLead/.test(lockup),
   "brand lockup renders its wordmark and tagline from the brand table");
ok(/document\.title = BRAND\.documentTitle/.test(main),
   "the document title is set from the deployment scope at boot");
// Authentication behaviour must be untouched by a branding change.
ok(/await login\(email, pw\)/.test(login),
   "credential exchange unchanged (login(email, pw))");
ok(/returnTo\.startsWith\(isEdr \? "\/edr" : "\/xdr"\)/.test(login),
   "returnTo cross-product guard unchanged");

console.log("");
for (const n of notes) console.log("  " + n);
if (failures.length) {
  console.error("\nLOGIN BRANDING SCOPE GATE · FAILED");
  for (const f of failures) console.error("  ✗ " + f);
  console.error("");
  process.exit(1);
}
console.log(`\nLOGIN BRANDING SCOPE GATE · PASSED (${notes.length} checks)\n`);
