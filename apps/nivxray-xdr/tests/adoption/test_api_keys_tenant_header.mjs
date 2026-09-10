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
const FILE = resolve(here, "../../src/xdr/admin/ApiKeysBody.jsx");
const src = readFileSync(FILE, "utf8");

const failures = [];

// Every axios call to /xdr/api-keys, with the remainder of its argument list.
const calls = [...src.matchAll(
  /api\.(get|post|delete|put|patch)\(\s*(`|")(\/xdr\/api-keys[^`"]*)\2([^;]*)/g,
)];

if (calls.length === 0) {
  failures.push("no /xdr/api-keys calls found — did the file move or change shape?");
}

for (const [, method, , url, rest] of calls) {
  const carriesTenant = rest.includes("hdrs()") || rest.includes("X-Tenant-Id");
  if (!carriesTenant) {
    failures.push(`api.${method}("${url}") does not pass the tenant context ` +
                  `(expected hdrs() or an explicit X-Tenant-Id header)`);
  }
}

// The five surfaces that must all be tenant-scoped.
for (const required of ["api.get(", "/rotate", "/revoke", "api.delete("]) {
  if (!src.includes(required)) {
    failures.push(`expected call site missing from the file: ${required}`);
  }
}

// The tenant must be a single source of truth the whole surface reads.
if (!/const \[tenant, setTenant\] = useState\(/.test(src)) {
  failures.push("surface-level `tenant` state is missing");
}
if (!/const hdrs = \(\) => \(\{ headers: \{ "X-Tenant-Id": tenant \} \}\)/.test(src)) {
  failures.push("`hdrs()` helper is missing or no longer binds X-Tenant-Id to `tenant`");
}
// Reload when the tenant changes, otherwise the list shows another tenant's view.
if (!/\}, \[tick, tenant\]\)/.test(src)) {
  failures.push("the load effect does not re-run when `tenant` changes");
}
// The create modal must still require the typed confirmation.
if (!src.includes("confirm_tenant_id") || !src.includes("!tenantOk")) {
  failures.push("the tenant double-confirmation guard was weakened");
}

console.log(`checked ${calls.length} /xdr/api-keys call sites in ApiKeysBody.jsx`);
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
