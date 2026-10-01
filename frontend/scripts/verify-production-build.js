#!/usr/bin/env node
/**
 * Workspace production build guard — OWNER LOCK · Phase 1.
 *
 * Runs AFTER `yarn build` and FAILS the build (exit 1) if the emitted
 * artefact is not safe to serve as the production NivXMachines Workspace.
 *
 * Scope is deliberately narrow: it protects THIS migration and nothing
 * else. It is not a general linter and must not grow into one.
 *
 * The four conditions are approved by the owner:
 *   1. a Preview Emergent URL is embedded
 *   2. a /v2/* shadow flag is unexpectedly enabled
 *   3. the required production backend URL is absent
 *   4. an obviously wrong environment origin is embedded
 *
 * Why an artefact check and not an env check: CRA inlines env vars at
 * build time, and this project has a precedence trap — craco.config.js
 * calls dotenv at module load, so `.env` beats `.env.production`. A
 * `.env.production` was tried during the migration and was SILENTLY
 * IGNORED: the build still inlined the preview backend URL 22 times.
 * Reading process.env here would therefore have agreed with a build that
 * was already wrong. Only the emitted bundle tells the truth.
 */
const fs = require("fs");
const path = require("path");

const BUILD = path.resolve(__dirname, "..", "build");
const JS_DIR = path.join(BUILD, "static", "js");

// Origins this artefact is allowed to talk to. Extend ONLY with a
// deliberate owner decision — Phase 4 adds the permanent API hostname.
const ALLOWED_API_ORIGINS = [
  "https://nivxray.nivxforge.com", // TEMPORARY_MIGRATION_DEPENDENCY (Phase 1)
];

const FLAGS = [
  "REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE",
  "REACT_APP_NIVX_FLAG_CASE_ENGINE",
  "REACT_APP_NIVX_FLAG_VERDICT_ENGINE_V3",
];

const failures = [];
const notes = [];

function readBundle() {
  if (!fs.existsSync(JS_DIR)) {
    failures.push(`no build output at ${JS_DIR} — did yarn build run?`);
    return "";
  }
  return fs
    .readdirSync(JS_DIR)
    .filter((f) => f.endsWith(".js"))
    .map((f) => fs.readFileSync(path.join(JS_DIR, f), "utf8"))
    .join("\n");
}

function countAll(haystack, needle) {
  let n = 0;
  let i = haystack.indexOf(needle);
  while (i !== -1) {
    n += 1;
    i = haystack.indexOf(needle, i + needle.length);
  }
  return n;
}

const js = readBundle();

if (js) {
  // -- 1 · no preview origin may ship --------------------------------
  const preview = js.match(/https:\/\/[a-z0-9-]+\.preview\.emergentagent\.com/g) || [];
  if (preview.length) {
    const uniq = [...new Set(preview)];
    failures.push(
      `PREVIEW ORIGIN EMBEDDED · ${preview.length} occurrence(s) of ` +
        `${uniq.join(", ")}. The production Workspace would read the ` +
        `PREVIEW database while appearing healthy.`
    );
  } else {
    notes.push("no preview origin embedded");
  }

  // -- 3 · the production backend URL must be present ----------------
  const inlined = [...new Set(
    (js.match(/REACT_APP_BACKEND_URL:"([^"]*)"/g) || []).map((m) =>
      m.replace(/^REACT_APP_BACKEND_URL:"/, "").replace(/"$/, "")
    )
  )];

  if (!inlined.length || inlined.every((v) => !v)) {
    failures.push(
      "REACT_APP_BACKEND_URL ABSENT OR EMPTY in the emitted bundle. " +
        "Every API call would resolve against `undefined/api`."
    );
  } else {
    // -- 4 · and it must be an approved origin -----------------------
    const bad = inlined.filter((v) => !ALLOWED_API_ORIGINS.includes(v));
    if (bad.length) {
      failures.push(
        `UNAPPROVED API ORIGIN EMBEDDED · ${bad.join(", ")}. ` +
          `Approved: ${ALLOWED_API_ORIGINS.join(", ")}. ` +
          `Extending this list is an owner decision.`
      );
    } else {
      notes.push(
        `API origin ${inlined.join(", ")} · ` +
          `${countAll(js, inlined[0])} reference(s)`
      );
    }
    if (inlined.length > 1) {
      failures.push(
        `MORE THAN ONE API ORIGIN EMBEDDED · ${inlined.join(", ")}. ` +
          "The artefact is built from mixed configuration."
      );
    }
  }

  // -- 2 · shadow flags must not be on ------------------------------
  for (const flag of FLAGS) {
    const vals = [...new Set(
      (js.match(new RegExp(flag + ':"([^"]*)"', "g")) || []).map((m) =>
        m.replace(new RegExp("^" + flag + ':"'), "").replace(/"$/, "")
      )
    )];
    const on = vals.filter((v) => v === "shadow" || v === "enabled");
    if (on.length) {
      failures.push(
        `SHADOW FLAG ENABLED · ${flag}="${on.join(",")}". The /v2/* ` +
          "shadow surfaces would be live in production (owner decision: OFF)."
      );
    } else {
      notes.push(`${flag}=${vals.length ? vals.join(",") : "absent (→ disabled)"}`);
    }
  }
}

for (const n of notes) console.log(`  ok   · ${n}`);

if (failures.length) {
  console.error("\nWORKSPACE PRODUCTION BUILD GUARD · FAILED\n");
  failures.forEach((f, i) => console.error(`  ${i + 1}. ${f}`));
  console.error(
    "\nBuild rejected. Fix the build configuration — do not bypass this guard.\n"
  );
  process.exit(1);
}

console.log("\nWORKSPACE PRODUCTION BUILD GUARD · PASSED\n");
