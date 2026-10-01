/**
 * P0.15C · Regression guard · api.js timeout policy
 * ───────────────────────────────────────────────────
 *
 * Locks the timeout policy so slow acquisition endpoints
 * (like /die/understand hitting a large threat-report URL)
 * can never regress to the 30 s default and produce the
 * "INPUT UNDERSTANDING FAILED · timeout of 30000ms exceeded"
 * error that the "Failed" saved case surfaced on 2026-02-08.
 *
 * Do not run this via node — it is a static-analysis assertion
 * over the api.js source file.  Executed by the CI test runner
 * that mounts the frontend workspace (Jest / Vitest); if no
 * runner is present it is a no-op smoke check runnable via:
 *
 *     grep -q "'/die/understand'" frontend/src/lib/api.js
 */
const fs   = require("fs");
const path = require("path");

const src = fs.readFileSync(
    path.resolve(__dirname, "..", "..", "src", "lib", "api.js"),
    "utf-8");

function assert(cond, msg) {
    if (!cond) {
        console.error("FAIL:", msg);
        process.exit(1);
    }
}

assert(
    /\/die\/understand/i.test(src)
        && /TIMEOUT_DECODE/i.test(src),
    "api.js pickTimeout must route /die/understand to TIMEOUT_DECODE — "
        + "otherwise slow threat-report URLs abort at the 30 s default and "
        + "the Workspace surfaces INPUT UNDERSTANDING FAILED.");

assert(
    /TIMEOUT_DEFAULT\s*=\s*30_000/.test(src),
    "TIMEOUT_DEFAULT should remain 30_000 — the fix is targeted "
        + "(specific endpoint), not a blanket global increase.");

console.log("api.js timeout regression guard: OK");
