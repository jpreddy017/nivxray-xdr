/**
 * Regression guard — every API Keys request must carry the tenant context.
 *
 * 2026-06 P0: `X-Tenant-Id` was sent on CREATE only, so a key persisted under
 * `nivx-prod-1` while the list/rotate/revoke/delete calls fell back to tenant
 * `"default"` and the surface reported `PROVISIONED 0`. The record was never
 * lost — it was queried under the wrong tenant.
 *
 * This asserts the property statically, so a future edit cannot silently drop
 * the header from any single call and re-break create-then-list.
 *
 *   node apps/nivxray-xdr/tests/adoption/test_api_keys_tenant_header.mjs
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SURFACES = [
  ["ApiKeysBody.jsx",    "\\/xdr\\/api-keys"],
  ["CollectorsBody.jsx", "\\/xdr\\/collectors"],
];

const failures = [];
let calls = [];
let src = "";

for (const [file, route] of SURFACES) {
  const text = readFileSync(resolve(here, "../../src/xdr/admin/" + file), "utf8");
  src += text;
  const re = new RegExp(
    `api\\.(get|post|delete|put|patch)\\(\\s*(\`|")(${route}[^\`"]*)\\2([\\s\\S]{0,140})`, "g");
  const found = [...text.matchAll(re)];
  if (found.length === 0) {
    failures.push(`no ${route} calls found in ${file} — did it move or change shape?`);
  }
  calls = calls.concat(found);
}

for (const [, method, , url, rest] of calls) {
  const carriesTenant = rest.includes("hdrs()") || rest.includes("X-Tenant-Id");
  if (!carriesTenant) {
    failures.push(`api.${method}("${url}") does not pass the tenant context ` +
                  `(expected hdrs() or an explicit X-Tenant-Id header)`);
  }
}

// The five surfaces that must all be tenant-scoped.
for (const required of ["api.get(", "/rotate", "/revoke", "api.delete(",
                        "/start", "/stop", "/test", "disable"]) {
  if (!src.includes(required)) {
    failures.push(`expected call site missing from the file: ${required}`);
  }
}

// The enable/disable toggle URL embeds a nested quote, so the call-site regex
// cannot reach it — assert it structurally instead.
if (!/\$\{r\.enabled \? "disable" : "enable"\}`,\s*\n?\s*null, hdrs\(\)\)/.test(src)) {
  failures.push("collector enable/disable toggle does not carry the tenant context");
}
// The protocols catalog read must be tenant-scoped too.
if (!/api\.get\("\/xdr\/collectors\/protocols\/catalog", hdrs\(\)\)/.test(src)) {
  failures.push("protocols catalog read does not carry the tenant context");
}

// Both surfaces must hold their own tenant state and re-load when it changes.
if ((src.match(/const \[tenant,\s*setTenant\]\s*= useState\(/g) || []).length < 2) {
  failures.push("surface-level `tenant` state missing on one of the surfaces");
}
if (!/\}, \[refresh, tenant\]\)/.test(src)) {
  failures.push("CollectorsBody load effect does not re-run when `tenant` changes");
}
if ((src.match(/const hdrs = \(\) => \(\{ headers: \{ "X-Tenant-Id": tenant \} \}\)/g)
     || []).length < 2) {
  failures.push("`hdrs()` helper missing on one of the surfaces");
}
// Reload when the tenant changes, otherwise the list shows another tenant's view.
if (!/\}, \[tick, tenant\]\)/.test(src)) {
  failures.push("the load effect does not re-run when `tenant` changes");
}
// The create modal must still require the typed confirmation.
if (!src.includes("confirm_tenant_id") || !src.includes("!tenantOk")) {
  failures.push("the tenant double-confirmation guard was weakened");
}

console.log(`checked ${calls.length} tenant-scoped call sites across ` +
            `${SURFACES.map(([f]) => f).join(", ")}`);
for (const [, method, , url, rest] of calls) {
  const ok = rest.includes("hdrs()") || rest.includes("X-Tenant-Id");
  console.log(`  ${ok ? "PASS" : "FAIL"}  api.${method}("${url}")`);
}

if (failures.length) {
  console.error("\nFAILED:");
  for (const f of failures) console.error("  - " + f);
  process.exit(1);
}
console.log("\nPASS — every API Keys request carries the tenant context.");
