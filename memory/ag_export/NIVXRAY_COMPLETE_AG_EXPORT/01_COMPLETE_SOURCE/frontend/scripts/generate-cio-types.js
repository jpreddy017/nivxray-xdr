/**
 * ADR-0020 · CIO type-generation script.
 *
 * Reads the canonical schema from the running backend (or the local
 * file) and emits `src/nivxforge/types/cio.ts`. The frontend never
 * hand-writes CIO types — this eliminates drift between backend and
 * frontend by construction.
 *
 * Usage:
 *   node scripts/generate-cio-types.js
 *
 * The output file is a Lab 2.0 artifact only; the legacy Workspace
 * continues to consume `types/cio.js` (JSDoc typedefs) untouched.
 */
const fs = require("fs");
const path = require("path");
const { compile } = require("json-schema-to-typescript");

const SCHEMA_PATH = path.resolve(
  __dirname,
  "../../backend/nivxforge/schemas/cio.schema.v1.json"
);
const OUT_PATH = path.resolve(
  __dirname,
  "../src/nivxforge/types/cio.ts"
);

async function main() {
  if (!fs.existsSync(SCHEMA_PATH)) {
    console.error(`[cio-types] Schema not found at ${SCHEMA_PATH}`);
    process.exit(1);
  }
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf-8"));
  const ts = await compile(schema, "CIO", {
    additionalProperties: false,
    bannerComment: `/**
 * AUTO-GENERATED — DO NOT EDIT BY HAND.
 *
 * Source of truth: /api/schemas/v1/cio.schema.json
 *                  (backend/nivxforge/schemas/cio.schema.v1.json)
 * Regenerate with: yarn gen:cio
 *
 * ADR-0014 · ADR-0020
 */`,
    style: {
      singleQuote: false,
      semi: true,
      trailingComma: "es5",
    },
  });
  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, ts, "utf-8");
  console.log(`[cio-types] Wrote ${OUT_PATH} (${ts.length} bytes)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
