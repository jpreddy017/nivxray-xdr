/**
 * ATT&CK lane order regression test.
 *
 * The trajectory diagram MUST always render tactics in MITRE
 * ATT&CK lifecycle order — never sorted alphabetically, never
 * reordered dynamically.  Analysts build muscle memory around
 * this sequence; any drift would silently break their scan
 * pattern.
 *
 * Run:
 *   node --test src/components/__tests__/mitreLaneOrder.test.mjs
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import url from "node:url";


const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const SOURCE = fs.readFileSync(
    path.join(__dirname, "..", "investigation", "TrajectoryDiagram.jsx"),
    "utf8"
);


const EXPECTED = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
];


test("MITRE_LANES follow the ATT&CK lifecycle order", () => {
    // Extract every `id: "..."` line inside the MITRE_LANES literal.
    const start = SOURCE.indexOf("const MITRE_LANES = [");
    const end   = SOURCE.indexOf("];", start);
    assert.ok(start >= 0 && end > start, "MITRE_LANES literal not found");
    const block = SOURCE.slice(start, end);
    const ids = [...block.matchAll(/id:\s*"([^"]+)"/g)].map((m) => m[1]);
    assert.deepEqual(ids, EXPECTED);
});


test("MITRE_LANES has exactly 14 entries", () => {
    const start = SOURCE.indexOf("const MITRE_LANES = [");
    const end   = SOURCE.indexOf("];", start);
    const block = SOURCE.slice(start, end);
    const ids = [...block.matchAll(/id:\s*"([^"]+)"/g)].map((m) => m[1]);
    assert.equal(ids.length, 14);
});
