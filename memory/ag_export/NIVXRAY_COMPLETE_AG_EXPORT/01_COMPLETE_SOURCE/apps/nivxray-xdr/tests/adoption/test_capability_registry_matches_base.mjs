#!/usr/bin/env node
/**
 * Anti-hallucination / anti-fabrication CI gate.
 *
 * Validates that every capability in
 * ``docs/NIVXRAY_CAPABILITY_REGISTRY.json`` that claims to be
 * authoritative in the base NivXRay Tool actually exists on disk
 * at ``/app/backend/**``.
 *
 * Fails the CI if:
 *   1. A capability marked ``owner=base`` / ``owner=base+xdr``
 *      references a backend_path/source that does NOT exist.
 *   2. Any of the owner-listed acronyms (DIE, IEDDE, IUE, UAIE, UIL,
 *      IDA, CEM, ICE, VEEE) is missing its concrete implementation.
 *
 * Usage:
 *   node tests/adoption/test_capability_registry_matches_base.mjs
 *
 * Exit code 0 = green, 1 = broken.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "../..");
const BASE_ROOT = "/app";

const REGISTRY = JSON.parse(fs.readFileSync(
  path.join(REPO_ROOT, "docs/NIVXRAY_CAPABILITY_REGISTRY.json"), "utf8"));

// ── Owner-listed acronyms that MUST resolve to a concrete file ──
// Verified 2026-02-10 via `ls /app/backend/services /app/backend/routers`.
const REQUIRED_ENGINES = [
  { id: "engine.die",   name: "DIE",   path: "backend/services/die/api.py" },
  { id: "engine.iedde", name: "IEDDE", path: "backend/routers/iedde.py" },
  { id: "engine.iue.timeline_fuse", name: "IUE", path: "backend/services/iue/timeline.py" },
  { id: "engine.uaie.catalog", name: "UAIE", path: "backend/routers/uaie_catalog.py" },
  { id: "engine.uil.classify", name: "UIL", path: "backend/routers/uil.py" },
  { id: "engine.ida",   name: "IDA",   path: "backend/services/ida/input_classifier.py" },
  { id: "engine.cem",   name: "CEM",   path: "backend/services/cem.py" },
  { id: "engine.ice",   name: "ICE",   path: "backend/services/ice/correlate.py" },
  { id: "engine.veee",  name: "VEEE",  path: "backend/services/veee/evidence_extractor.py" },
];

// ── Optional NOT_PRESENT registrations.  If a registry entry declares
//     status: "NOT_PRESENT", we double-check by asserting the referenced
//     path does NOT exist.  Prevents a bug where someone marks a real
//     engine as absent to hide it from XDR.
function isPresent(rel) {
  if (!rel) return false;
  const abs = rel.startsWith("/") ? rel : path.join(BASE_ROOT, rel);
  try { return fs.existsSync(abs); } catch { return false; }
}

let failures = 0;
const log = (icon, msg) => console.log(`${icon} ${msg}`);

// ── 1. Required engines must all exist ─────────────────────────
log("▶", "Verifying required-engine implementations exist on disk…");
for (const e of REQUIRED_ENGINES) {
  const ok = isPresent(e.path);
  if (ok) log("✅", `${e.name.padEnd(6)} · ${e.path}`);
  else {
    log("❌", `${e.name.padEnd(6)} · MISSING · ${e.path}`);
    failures += 1;
  }
  // Registry entry with this id must exist and its status must not
  // be NOT_PRESENT.
  const cap = REGISTRY.capabilities.find((c) => c.id === e.id);
  if (!cap) {
    log("❌", `${e.name} · registry entry "${e.id}" missing`);
    failures += 1;
  } else if (String(cap.status).toUpperCase() === "NOT_PRESENT") {
    log("❌", `${e.name} · registry says NOT_PRESENT but disk says PRESENT (${e.path})`);
    failures += 1;
  }
}

// ── 2. Every base-owned capability with a claimed path must resolve ─
log("▶", "Verifying every base-owned capability resolves on disk…");
let baseChecked = 0;
let baseGaps   = 0;
for (const c of REGISTRY.capabilities) {
  const owner = String(c.owner || "");
  if (!owner.includes("base")) continue;
  const status = String(c.status || "").toUpperCase();
  if (status === "NOT_PRESENT") {
    // Assert the claimed path really is absent.
    const p = c.backend_path || c.source;
    if (p && isPresent(p)) {
      log("❌", `${c.id} · claimed NOT_PRESENT but ${p} exists`);
      failures += 1;
    } else {
      log("✅", `${c.id} · NOT_PRESENT (verified absent)`);
    }
    continue;
  }
  // For ADOPT / EXTEND / ADAPT / CONNECTED / BASE_ONLY / SHARED_LIBRARY
  // we expect one of backend_path / source to resolve.  If neither is
  // present we skip (some external capabilities don't have a base
  // implementation).
  const rel = c.backend_path || c.source;
  if (!rel) continue;
  if (rel.startsWith("attack.mitre.org") || rel.startsWith("apps/")) {
    continue;  // external / xdr-owned
  }
  baseChecked += 1;
  if (!isPresent(rel)) {
    log("❌", `${c.id} · declared ${status} but ${rel} does NOT exist`);
    baseGaps += 1;
    failures += 1;
  }
}
log("▶", `Checked ${baseChecked} base-owned rows · ${baseGaps} gap(s)`);

// ── 3. Historical VEEE / ICE assumption regression guard ────────
log("▶", "Regression guard: VEEE and ICE MUST be present…");
if (!isPresent("backend/services/veee/evidence_extractor.py")) {
  log("❌", "VEEE regression: expected file missing");
  failures += 1;
} else log("✅", "VEEE present");
if (!isPresent("backend/services/ice/correlate.py")) {
  log("❌", "ICE regression: expected file missing");
  failures += 1;
} else log("✅", "ICE present");

// ── 4. Investigation Corpus — 8 categories MUST all be represented ─
log("▶", "Investigation Corpus: 8 categories must all have ≥1 scenario…");
const REQUIRED_CATEGORIES = ["benign", "malicious", "false_positive",
                                                        "ambiguous", "incomplete", "conflicting",
                                                        "unknown", "multi_stage"];
const corpusRoot = path.join(REPO_ROOT, "docs/corpus/scenarios");
for (const cat of REQUIRED_CATEGORIES) {
  const dir = path.join(corpusRoot, cat);
  let scenarios = [];
  try {
    scenarios = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
  } catch { /* dir missing */ }
  if (scenarios.length === 0) {
    log("❌", `corpus category "${cat}" is EMPTY`);
    failures += 1;
  } else {
    log("✅", `corpus category "${cat}" · ${scenarios.length} scenario(s)`);
    // Every scenario JSON must parse and carry an id + matching category.
    for (const f of scenarios) {
      try {
        const s = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
        if (!s.id || s.category !== cat) {
          log("❌", `scenario ${f} has wrong id/category`);
          failures += 1;
        }
      } catch (e) {
        log("❌", `scenario ${f} is not valid JSON: ${e.message}`);
        failures += 1;
      }
    }
  }
}

// ── 5. Extension manifests — every JSON must parse + declare required keys ─
log("▶", "Extension manifests: every JSON must be a valid contract…");
const REQUIRED_MANIFEST_KEYS = [
  "capability_id", "name", "type", "provider", "version", "vendor",
  "authentication", "permissions", "supported_operations",
  "input_schema", "output_schema", "health_check", "lifecycle",
  "adapter_status",
];
const EXTENSION_TYPES_SET = new Set([
  "CONNECTOR","COLLECTOR","PROTOCOL","PARSER","NORMALIZER",
  "DETECTOR","CORRELATOR","ENRICHMENT","TI_PROVIDER","ACTION",
  "PLAYBOOK_PACK","CONTENT_PACK","AGENT","PATTERN_ENGINE",
]);
const extensionsRoot = path.join(REPO_ROOT, "docs/extensions");
function _walk(dir) {
  const out = [];
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) out.push(..._walk(p));
      else if (entry.isFile() && entry.name.endsWith(".json")) out.push(p);
    }
  } catch { /* dir missing */ }
  return out;
}
const manifests = _walk(extensionsRoot);
if (manifests.length === 0) {
  log("❌", "no extension manifests found under docs/extensions/");
  failures += 1;
}
for (const f of manifests) {
  let m;
  try { m = JSON.parse(fs.readFileSync(f, "utf8")); }
  catch (e) {
    log("❌", `${f} · invalid JSON: ${e.message}`);
    failures += 1;
    continue;
  }
  const missing = REQUIRED_MANIFEST_KEYS.filter((k) => !(k in m));
  const bad = [];
  if (m.type && !EXTENSION_TYPES_SET.has(m.type)) bad.push(`type:${m.type}`);
  if (missing.length > 0 || bad.length > 0) {
    log("❌", `${m.capability_id || f} · missing ${missing.join(",")} `
                 + (bad.length ? ` · invalid ${bad.join(",")}` : ""));
    failures += 1;
  } else {
    log("✅", `${m.capability_id} · ${m.lifecycle}`);
  }
}

// ── 6. Result ──────────────────────────────────────────────────
if (failures > 0) {
  log("💥", `${failures} failure(s) — anti-hallucination gate BROKEN`);
  process.exit(1);
}
log("✅", "All registry claims verified against base codebase");
process.exit(0);
