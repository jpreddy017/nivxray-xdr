#!/usr/bin/env node
/**
 * PR-XDR-0 · NAVIGATION INTEGRITY GATE for NivXRay XDR.
 *
 * The defect class this guards: a control that claims to open a NivXRay XDR
 * capability but calls `window.open()` on a base-app path that does not
 * exist in this bundle (`/analyze`, `/threat-intel`, `/documents`,
 * `/heatmap`, `/analyst`, `/history`, `/v2/irg/...`). The SPA catch-all
 * bounces that new tab straight back to the incident queue, so the analyst
 * gets a second tab of where they already were — a dead control.
 *
 * Four layers so neither a behavioural nor a textual regression can slip:
 *   1. no `external:` navigation class in NivXRay XDR product navigation
 *   2. `window.open` is allow-listed per call site, with a written reason
 *   3. no forbidden base-app navigation literal anywhere in src/
 *   4. the pivot builder exposes only `/xdr/*` destinations
 *
 * Usage: node tests/adoption/test_no_external_product_navigation.mjs
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

function walk(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else if (/\.(jsx?|tsx?)$/.test(e.name)) out.push(p);
  }
  return out;
}
const files = walk(SRC);
const rel = (f) => path.relative(SRC, f);

/**
 * Strip comments and JSX prose before matching. The gate must fail on
 * NAVIGATION, not on a comment that documents the defect it removed —
 * otherwise the only way to keep the guard green is to stop explaining
 * the fix, which is the wrong incentive.
 */
const code = (f) => fs.readFileSync(f, "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .replace(/^\s*\/\/.*$/gm, "")
  .replace(/([^:])\/\/[^"'`\n]*$/gm, "$1");

// NivXForge EDR sites deliberately NOT touched by PR-XDR-0. The owner
// scoped this PR to NivXRay XDR navigation and forbade NivXForge EDR
// changes without an approved cross-product navigation contract. These are
// DISCLOSED, not fixed, and must be reported as remaining dead pivots.
const OUT_OF_SCOPE_EDR = new Set([
  "nivxforge/pages/EdrProcessTreePage.jsx",
]);

// ── 1 · the `external` navigation class must not exist ───────────
for (const f of files) {
  const src = code(f);
  ok(!/external:\s*true/.test(src),
     `${rel(f)} must not declare an \`external: true\` navigation target`);
}

// ── 2 · window.open allow-list, each with a written reason ───────
// Only cross-PRODUCT hand-off may open a tab, and only through
// productOrigins / WORKSPACE_URL. Everything else must navigate in-product.
const WINDOW_OPEN_ALLOWED = {
  "components/WorkspaceLaunch.jsx":
    "Workspace NivXMachines is a separate deployment at its own origin; "
    + "gated on REACT_APP_WORKSPACE_URL and renders NOT CONFIGURED otherwise.",
  "components/incidents/tabs/ActivityTab.jsx":
    "NivXForge EDR trajectory hand-off, resolved through productOrigins.",
  "components/incidents/tabs/OverviewTab.jsx":
    "NivXForge EDR pointer only, resolved through productOrigins; every "
    + "/xdr/* pointer navigates in-product.",
  "xdr/pages/incidents/record/tabs/EvidenceTab.jsx":
    "NivXForge EDR domain card only, resolved through productOrigins.",
  "xdr/pages/XdrIncidentsPage.jsx":
    "Operator-invoked 'open incident in new tab/window' on an in-product "
    + "/xdr/incidents/:id path — not cross-product navigation.",
  "nivxforge/trajectory/EdrDeviceTrajectoryPage.jsx":
    "NivXForge EDR product surface, pivots built by xdr/lib/pivots.js.",
  "xdr/design/MitreCoverageRow.jsx":
    "attack.mitre.org reference link (external documentation, not a product).",
  "xdr/design/MitreTabV2.jsx":
    "attack.mitre.org reference link (external documentation, not a product).",
  "xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx":
    "PRE-EXISTING, NOT AUDITED BY PR-XDR-0 — two generic open() helpers; "
    + "scheduled for the PR-XDR-1 rail/IA pass.",
  "xdr/pages/incidents/record/tabs/ReportTab.jsx":
    "PRE-EXISTING, NOT AUDITED BY PR-XDR-0 — opens a generated report blob "
    + "URL, not product navigation.",
};
for (const f of files) {
  const src = code(f);
  if (!/window\.open\(/.test(src)) continue;
  const r = rel(f);
  ok(Object.prototype.hasOwnProperty.call(WINDOW_OPEN_ALLOWED, r),
     `${r} calls window.open() but is not in the allow-list with a reason`);
}
for (const r of Object.keys(WINDOW_OPEN_ALLOWED)) {
  // A guard that matches nothing is worse than no guard: the allow-list may
  // not rot into entries for files that no longer call window.open().
  const p = path.join(SRC, r);
  ok(fs.existsSync(p) && /window\.open\(/.test(code(p)),
     `allow-list entry ${r} must still call window.open()`);
}

// ── 3 · forbidden base-app navigation literals ───────────────────
// These paths exist only in the base NivXRay app. Navigating to them from
// the NivXRay XDR bundle produces a dead tab.
const FORBIDDEN = [
  /["'`]\/analyze(?:[?#"'`])/,
  /["'`]\/threat-intel(?:[?#"'`])/,
  /["'`]\/documents(?:[?#"'`])/,
  /["'`]\/heatmap["'`]/,
  /["'`]\/analyst(?:[?#"'`])/,
  /["'`]\/history\?/,
  /["'`]\/v2\/irg\//,
];
for (const f of files) {
  const r = rel(f);
  const src = code(f);
  for (const re of FORBIDDEN) {
    const hit = re.test(src);
    if (hit && OUT_OF_SCOPE_EDR.has(r)) {
      // Disclosed, not silently tolerated.
      notes.push(`DISCLOSED · ${r} still carries ${re} — NivXForge EDR `
                 + "surface, out of PR-XDR-0 scope by owner instruction");
      continue;
    }
    ok(!hit,
       `${r} contains a forbidden base-app navigation literal ${re}`);
  }
}

// ── 4 · the pivot builder exposes only in-product destinations ───
const pivot = code(path.join(SRC, "xdr/components/Pivot.jsx"));
const tos = [...pivot.matchAll(/\bto:\s*[`"']([^`"']*)/g)].map((m) => m[1]);
ok(tos.length > 0, "Pivot.jsx still declares pivot destinations");
for (const t of tos) {
  ok(t.startsWith("/xdr/"),
     `Pivot destination "${t}" must be a canonical /xdr/* route`);
}
ok(/data-state="PIVOT_DESTINATION_NOT_AVAILABLE"/.test(pivot),
   "Pivot.jsx renders an honest, named absence for capabilities with no "
   + "NivXRay XDR destination");
ok(/useNavigate/.test(pivot) && !/window\.location\.assign/.test(pivot),
   "Pivot.jsx navigates in-product with useNavigate (no full page reload)");

// ── 5 · the rail must not carry an external navigation branch ────
const shell = code(path.join(SRC, "xdr/XdrShell.jsx"));
ok(!/const openExternal/.test(shell),
   "XdrShell.jsx must not define openExternal()");
ok(/EXTERNAL_NAVIGATION_FORBIDDEN/.test(shell),
   "XdrShell.jsx fails closed if an `external` rail item is reintroduced");

// ── report ───────────────────────────────────────────────────────
console.log(`\nPR-XDR-0 navigation integrity · ${notes.length} checks passed`);
if (failures.length) {
  console.error(`\nFAILED · ${failures.length}`);
  for (const f of failures) console.error("  ✗ " + f);
  process.exit(1);
}
console.log("PASSED · no external product navigation in NivXRay XDR\n");
