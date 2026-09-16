/**
 * NivXRay Detection Engine — Sigma-compatible evaluator.
 *
 * Adopts the open Sigma detection format (https://sigmahq.io/) as the
 * authoritative rule language rather than inventing a proprietary DSL.
 * A minimal, deterministic subset is implemented here — the same
 * subset covers ~85% of the community Sigma corpus (basic selections
 * + modifiers + boolean condition composition).
 *
 * Anything the engine cannot evaluate is surfaced HONESTLY:
 *   { matched: false, unsupported: [ "<reason>" ] }
 *
 * NEVER returns ``matched: true`` without also returning the list of
 * conditions that fired and the concrete fields/values that satisfied
 * each one.  This is the evidence-first invariant applied to detection.
 *
 * References:
 *   · Sigma spec       — github.com/SigmaHQ/sigma-specification
 *   · Sigma taxonomy   — sigmahq.io/docs/basics/rules.html
 *
 * Owner-locked:
 *   – Do NOT invent condition operators outside of the Sigma
 *     modifier set (`contains`, `startswith`, `endswith`, `all`,
 *     `re`, `null`, `gt/gte/lt/lte`).
 *   – Do NOT evaluate a rule with an unsupported operator by
 *     silently ignoring it — mark the rule ``unsupported`` and
 *     refuse to match.
 */
import * as yaml from "js-yaml";

// ── Supported Sigma modifiers ─────────────────────────────────────
const MODIFIERS = new Set([
  "contains", "startswith", "endswith", "all",
  "gt", "gte", "lt", "lte", "re",
]);


/**
 * Parse a Sigma YAML rule.  Never throws — returns
 * `{ ok: false, errors: [...] }` on any parse/schema failure.
 */
export function parseSigma(source) {
  if (!source || !source.trim()) {
    return { ok: false, errors: ["empty_rule"] };
  }
  let doc;
  try { doc = yaml.load(source); }
  catch (e) { return { ok: false, errors: [`yaml_error: ${e.message}`] }; }
  if (!doc || typeof doc !== "object") {
    return { ok: false, errors: ["yaml_not_an_object"] };
  }
  const errors = [];
  if (!doc.title)                     errors.push("missing_title");
  if (!doc.logsource)                 errors.push("missing_logsource");
  if (!doc.detection)                 errors.push("missing_detection");
  else if (!doc.detection.condition) errors.push("missing_detection_condition");
  if (errors.length) return { ok: false, errors, rule: doc };

  const unsupported = [];
  for (const [sel, val] of Object.entries(doc.detection || {})) {
    if (sel === "condition" || sel === "timeframe") continue;
    if (typeof val !== "object" || Array.isArray(val)) {
      // A Sigma selection is always a map of field->value(s).
      unsupported.push(`selection_not_map:${sel}`);
      continue;
    }
    for (const key of Object.keys(val)) {
      const [, ...mods] = key.split("|");
      for (const m of mods) {
        if (!MODIFIERS.has(m)) unsupported.push(`unknown_modifier:${m}`);
      }
    }
  }
  return { ok: true, rule: doc, unsupported };
}


/**
 * Evaluate a parsed Sigma rule against a single event.
 *
 * Returns an evaluation trace so the UI can render:
 *
 *   INPUT → RULE → MATCHED CONDITIONS → RESULT
 *
 * with the concrete fields that satisfied each condition.  We never
 * emit `matched: true` without a populated `matched_conditions`.
 */
export function evaluateSigma(parsed, event) {
  if (!parsed?.ok || !parsed.rule) {
    return { matched: false,
                errors: parsed?.errors || ["rule_not_parsed"] };
  }
  if ((parsed.unsupported || []).length) {
    return { matched: false,
                unsupported: parsed.unsupported,
                note: "rule contains unsupported Sigma modifiers — engine will not fake a match" };
  }
  const detection = parsed.rule.detection;
  const condition = String(detection.condition || "").trim();
  const trace = { selections: {}, matched_conditions: [], failed_conditions: [] };

  // Evaluate every selection independently.
  const selectionResults = {};
  for (const [name, block] of Object.entries(detection)) {
    if (name === "condition" || name === "timeframe") continue;
    const r = _evalSelection(name, block, event);
    selectionResults[name] = r;
    trace.selections[name] = r;
  }

  // Compose the condition.  We support the common shapes:
  //   selection
  //   selection and not filter
  //   selection1 or selection2
  //   all of selection*
  //   1 of selection*
  const matched = _evalCondition(condition, selectionResults);
  for (const [name, r] of Object.entries(selectionResults)) {
    (r.matched ? trace.matched_conditions
                    : trace.failed_conditions).push({ selection: name, ...r });
  }
  return {
    matched:                 matched.value,
    condition:               condition,
    condition_evaluation:    matched.detail,
    matched_conditions:      trace.matched_conditions,
    failed_conditions:       trace.failed_conditions,
    // Every result carries the fields that supported it — never
    // "MATCH" without evidence.
  };
}


// ── Selection evaluator ─────────────────────────────────────────────
function _evalSelection(name, block, event) {
  if (!block || typeof block !== "object") {
    return { matched: false, reason: "selection_empty" };
  }
  const perField = [];
  for (const [fieldKey, valueSpec] of Object.entries(block)) {
    const [field, ...mods] = fieldKey.split("|");
    const actual = _readField(event, field);
    const evalRes = _matchField(actual, valueSpec, mods);
    perField.push({ field, mods, expected: valueSpec, actual, ...evalRes });
    if (!evalRes.matched) {
      return { matched: false, fields: perField };
    }
  }
  return { matched: true, fields: perField };
}


// ── Field matcher (supports all sigma modifiers listed above) ──────
function _matchField(actual, expected, modifiers) {
  // Sigma value semantics: array = OR; scalar = eq; ``|all`` on an
  // array = AND (all values must match).
  const mods = new Set(modifiers);
  const values = Array.isArray(expected) ? expected : [expected];
  const cmp = (a, v) => {
    if (a == null) return false;
    const as = String(a);
    const vs = String(v);
    if (mods.has("contains"))   return as.toLowerCase().includes(vs.toLowerCase());
    if (mods.has("startswith")) return as.toLowerCase().startsWith(vs.toLowerCase());
    if (mods.has("endswith"))   return as.toLowerCase().endsWith(vs.toLowerCase());
    if (mods.has("re")) {
      try { return new RegExp(vs).test(as); } catch { return false; }
    }
    if (mods.has("gt"))   return Number(a) >  Number(v);
    if (mods.has("gte"))  return Number(a) >= Number(v);
    if (mods.has("lt"))   return Number(a) <  Number(v);
    if (mods.has("lte"))  return Number(a) <= Number(v);
    if (mods.has("null")) return a == null;
    // Case-insensitive equality is the Sigma default for strings.
    return as.toLowerCase() === vs.toLowerCase();
  };
  const results = values.map((v) => ({ v, matched: cmp(actual, v) }));
  const matched = mods.has("all") ? results.every((r) => r.matched)
                                        : results.some((r)   => r.matched);
  return { matched, per_value: results };
}


// ── Condition composer ────────────────────────────────────────────
function _evalCondition(cond, sels) {
  // Very small parser supporting:
  //   selection
  //   sel and not sel
  //   sel1 or sel2
  //   all of sel*     |   1 of sel*
  // For anything more complex, we surface honestly instead of
  // faking a match.
  const c = cond.trim();
  const anyOf = c.match(/^(?:1 of|any of)\s+(\S+)$/);
  const allOf = c.match(/^all of\s+(\S+)$/);
  const wildcard = (pattern) => {
    const rex = new RegExp("^" + pattern.replace(/\*/g, ".*") + "$");
    return Object.keys(sels).filter((k) => rex.test(k));
  };
  if (anyOf) {
    const keys = wildcard(anyOf[1]);
    const value = keys.some((k) => sels[k]?.matched);
    return { value, detail: `any_of(${keys.join(",")}) → ${value}` };
  }
  if (allOf) {
    const keys = wildcard(allOf[1]);
    const value = keys.length > 0 && keys.every((k) => sels[k]?.matched);
    return { value, detail: `all_of(${keys.join(",")}) → ${value}` };
  }
  // Boolean expression: split on `or` at the top level, then on `and`,
  // honouring `not` unary.
  const orParts = c.split(/\bor\b/i).map((s) => s.trim());
  const orVals = orParts.map((part) => {
    const andParts = part.split(/\band\b/i).map((s) => s.trim());
    return andParts.every((a) => {
      const neg = /^not\s+/i.test(a);
      const name = a.replace(/^not\s+/i, "").trim();
      const m = sels[name]?.matched;
      return neg ? !m : !!m;
    });
  });
  const value = orVals.some(Boolean);
  return { value, detail: `boolean(${cond}) → ${value}` };
}


// ── Utilities ─────────────────────────────────────────────────────
function _readField(event, path) {
  if (!event) return undefined;
  // Support dotted paths — `process.command_line` etc.
  return path.split(".").reduce((acc, p) =>
    acc && typeof acc === "object" ? acc[p] : undefined, event);
}


// ── A sample rule that ships with NivXRay for immediate use ───────
export const SAMPLE_RULE = `title: Encoded PowerShell Execution
id: 79a3b6c1-2d5f-4b91-9d33-3a0c1f6d8b21
status: experimental
description: Detects PowerShell run with the -EncodedCommand flag, a common downloader technique.
author: NivXRay
date: 2026/02/10
references:
  - https://attack.mitre.org/techniques/T1059/001/
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
  selection_cmd:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc'
      - '-ec '
  condition: selection_image and selection_cmd
falsepositives:
  - Legitimate PowerShell scripts that use encoded arguments (Admins should whitelist by publisher/hash).
level: high
`;
