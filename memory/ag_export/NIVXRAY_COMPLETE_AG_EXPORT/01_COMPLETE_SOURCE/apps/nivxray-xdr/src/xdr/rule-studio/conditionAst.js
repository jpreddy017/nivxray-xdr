/**
 * NivXRay Rule Studio · Canonical Condition AST
 *
 * The visual builder never manipulates Sigma JSON directly.  It edits
 * a canonical AST, which is then deterministically serialized to a
 * Sigma-compatible detection body.  This intermediate layer lets us
 * later serialize the SAME AST to expressions Sigma cannot represent
 * natively (correlation / CVE / behavior / anomaly) without
 * redesigning the Rule Studio.
 *
 * Layers:
 *
 *   Visual Builder  →  Canonical Condition AST  →  Validation
 *                                              →  Sigma-compatible JSON
 *                                              →  xdr_detection_rules (DRAFT)
 *
 * Every rule persists as `emits=OBSERVATION · verdict_capable=false`
 * — the AST layer does not decide semantics, only shape.
 */

const uid = () => `${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;

// ────────────────────────────────────────────────────────────────
// Field-type → allowed operator whitelist (deterministic, honest).
// A field type MUST use operators that make semantic sense for it —
// e.g. `int` allows gte/lte, `enum` does not allow contains, `bool`
// only allows equals.  These are enforced in the UI so invalid
// combinations are impossible to author.
// ────────────────────────────────────────────────────────────────
export const OPERATORS_BY_TYPE = {
  string:   ["equals", "not_equals", "contains", "startswith", "endswith", "regex", "in"],
  path:     ["equals", "contains", "startswith", "endswith", "regex", "in"],
  hash:     ["equals", "in"],
  ip:       ["equals", "in", "contains"],
  int:      ["equals", "not_equals", "gte", "lte", "in"],
  enum:     ["equals", "not_equals", "in"],
  bool:     ["equals"],
  datetime: ["gte", "lte"],
};

export const OPERATOR_LABEL = {
  equals:     "equals",
  not_equals: "does not equal",
  contains:   "contains",
  startswith: "starts with",
  endswith:   "ends with",
  regex:      "matches regex",
  in:         "is one of",
  gte:        "≥",
  lte:        "≤",
};

// Sigma modifier mapping · deterministic.  `equals` is the bare form.
const SIGMA_MODIFIER = {
  equals:     "",
  not_equals: "",           // negated by prefixing key with `not_` selection
  contains:   "|contains",
  startswith: "|startswith",
  endswith:   "|endswith",
  regex:      "|re",
  in:         "",           // array value = implicit "any of"
  gte:        "|gte",
  lte:        "|lte",
};

// ────────────────────────────────────────────────────────────────
// AST factories
// ────────────────────────────────────────────────────────────────
export function makeCondition({ field = "", operator = "equals",
                                 value = "", fieldType = "string" } = {}) {
  return { type: "condition", id: uid(), field, operator, value, fieldType };
}

export function makeGroup({ op = "AND", children = [] } = {}) {
  return { type: "group", id: uid(), op, children };
}

export function makeRootGroup() {
  return makeGroup({ op: "AND", children: [makeCondition()] });
}

// ────────────────────────────────────────────────────────────────
// Field-schema resolution — pulls type + enum values + example from
// the lane schema returned by `/api/xdr/rule-studio/lanes/{lane}/schema`
// so the value input can render the correct control.
// ────────────────────────────────────────────────────────────────
export function resolveFieldMeta(laneSchema, fieldKey) {
  const fields = laneSchema?.fields || [];
  return fields.find((f) => f.key === fieldKey) || null;
}

export function defaultOperatorForField(fieldMeta) {
  if (!fieldMeta) return "equals";
  const allowed = OPERATORS_BY_TYPE[fieldMeta.type] || OPERATORS_BY_TYPE.string;
  return allowed[0];
}

// ────────────────────────────────────────────────────────────────
// Immutable AST update helpers · never mutate in place.
// ────────────────────────────────────────────────────────────────
export function updateNode(root, id, patch) {
  if (root.id === id) return { ...root, ...patch };
  if (root.type !== "group") return root;
  return { ...root, children: root.children.map((c) => updateNode(c, id, patch)) };
}

export function addChild(root, parentId, child) {
  if (root.type !== "group") return root;
  if (root.id === parentId) {
    return { ...root, children: [...root.children, child] };
  }
  return { ...root, children: root.children.map((c) => addChild(c, parentId, child)) };
}

export function removeNode(root, id) {
  if (root.type !== "group") return root;
  const filtered = root.children.filter((c) => c.id !== id)
                                .map((c) => removeNode(c, id));
  return { ...root, children: filtered };
}

export function convertToGroup(root, id, op = "AND") {
  // Wrap an existing leaf in a group so nested logic can be authored.
  if (root.type !== "group") return root;
  return {
    ...root,
    children: root.children.map((c) => {
      if (c.id === id && c.type === "condition") {
        return makeGroup({ op, children: [c] });
      }
      return convertToGroup(c, id, op);
    }),
  };
}

// ────────────────────────────────────────────────────────────────
// AST validation · returns an array of {nodeId, message}.  UI blocks
// submission until validation is empty.
// ────────────────────────────────────────────────────────────────
export function validateAst(root, laneSchema) {
  const errors = [];
  const walk = (node) => {
    if (node.type === "group") {
      if (!node.children.length) {
        errors.push({ nodeId: node.id, message: "Group must contain at least one condition" });
      }
      node.children.forEach(walk);
      return;
    }
    if (!node.field) {
      errors.push({ nodeId: node.id, message: "Field is required" });
      return;
    }
    const meta = resolveFieldMeta(laneSchema, node.field);
    const allowedOps = OPERATORS_BY_TYPE[meta?.type || "string"] || [];
    if (meta && !allowedOps.includes(node.operator)) {
      errors.push({ nodeId: node.id,
                    message: `Operator "${node.operator}" is not valid for ${meta.type}` });
    }
    // Value semantics per operator
    if (node.operator === "in") {
      const arr = coerceInList(node.value);
      if (!arr.length) errors.push({ nodeId: node.id,
                                     message: "Provide at least one value (comma-separated)" });
    } else if (typeof node.value === "string" && node.value.trim() === "") {
      // bool always resolves to a real true/false; other types require input
      if (meta?.type !== "bool") {
        errors.push({ nodeId: node.id, message: "Value is required" });
      }
    } else if (meta?.type === "int" && node.operator !== "in") {
      if (Number.isNaN(Number(node.value))) {
        errors.push({ nodeId: node.id, message: "Value must be a number" });
      }
    } else if (meta?.type === "ip" && node.operator === "equals") {
      if (!isPlausibleIp(node.value)) {
        errors.push({ nodeId: node.id, message: "Value does not look like an IP" });
      }
    } else if (meta?.type === "hash" && node.operator === "equals") {
      if (!isPlausibleHash(node.value)) {
        errors.push({ nodeId: node.id, message: "Value does not look like a hash (hex, ≥16 chars)" });
      }
    } else if (meta?.type === "enum" && meta.values) {
      if (node.operator === "equals" || node.operator === "not_equals") {
        if (!meta.values.includes(String(node.value))) {
          errors.push({ nodeId: node.id,
                        message: `Value must be one of: ${meta.values.join(", ")}` });
        }
      }
    } else if (meta?.type === "regex" || node.operator === "regex") {
      try { new RegExp(String(node.value)); }
      catch { errors.push({ nodeId: node.id, message: "Invalid regex" }); }
    }
  };
  walk(root);
  return errors;
}

function coerceInList(v) {
  if (Array.isArray(v)) return v.filter((x) => String(x).trim() !== "");
  return String(v || "").split(",").map((x) => x.trim()).filter(Boolean);
}

function isPlausibleIp(v) {
  const s = String(v || "").trim();
  return /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(s)
      || /^[0-9a-f:]+(\/\d{1,3})?$/i.test(s);
}

function isPlausibleHash(v) {
  const s = String(v || "").trim();
  return /^[0-9a-f]{16,}$/i.test(s);
}

// ────────────────────────────────────────────────────────────────
// AST → Sigma-compatible detection body
//
// Strategy: every leaf condition becomes its own named selection
// (`sel_1`, `sel_2`, …).  The top-level group is serialized into a
// boolean expression using `and`, `or`, and grouping parentheses.  The
// result is 100% compatible with SigmaHQ grammar for the operators
// this UI produces.  Any operator not representable in Sigma (future
// correlation / behavioral operators) will short-circuit via
// `sigma_compatible=false` and use the `native_ast` field only.
// ────────────────────────────────────────────────────────────────
export function serializeAstToDetection(root) {
  const selections = {};
  let selCounter = 0;

  const nameFor = () => {
    selCounter += 1;
    return `sel_${selCounter}`;
  };

  const emitLeaf = (leaf) => {
    const modifier = SIGMA_MODIFIER[leaf.operator] ?? "";
    const key = `${leaf.field}${modifier}`;
    let value = leaf.value;
    if (leaf.operator === "in") {
      value = coerceInList(leaf.value);
    } else if (leaf.fieldType === "int") {
      const n = Number(value);
      value = Number.isNaN(n) ? value : n;
    } else if (leaf.fieldType === "bool") {
      value = String(value) === "true";
    }
    const selName = nameFor();
    selections[selName] = { [key]: value };
    // `not_equals` is expressed by negating the selection in the condition.
    if (leaf.operator === "not_equals") {
      return { expr: `not ${selName}` };
    }
    return { expr: selName };
  };

  const walk = (node) => {
    if (node.type === "condition") return emitLeaf(node);
    const parts = node.children.map(walk).map((r) => r.expr);
    const joiner = node.op === "OR" ? " or " : " and ";
    const expr = parts.length === 0 ? "false"
                : parts.length === 1 ? parts[0]
                : `(${parts.join(joiner)})`;
    return { expr };
  };

  const top = walk(root);
  return {
    ...selections,
    condition: top.expr,
    // Keep the raw AST alongside — analysts can round-trip in future.
    native_ast: root,
  };
}

// ────────────────────────────────────────────────────────────────
// Sigma detection → AST (best-effort).  Used ONLY to bootstrap the
// builder from a template.  Anything we can't parse fills into a
// single starter condition so the analyst is never blocked.
// ────────────────────────────────────────────────────────────────
export function detectionToAst(detection, laneSchema) {
  if (!detection || typeof detection !== "object") return makeRootGroup();
  if (detection.native_ast) return detection.native_ast;

  // Simple case: one selection block, condition == "selection"
  const selKeys = Object.keys(detection).filter((k) => k !== "condition"
                                                     && k !== "native_ast");
  const groups = [];
  for (const sel of selKeys) {
    const block = detection[sel];
    if (!block || typeof block !== "object") continue;
    for (const [rawKey, rawVal] of Object.entries(block)) {
      const [field, mod] = rawKey.split("|");
      let operator = "equals";
      if (mod === "contains") operator = "contains";
      else if (mod === "startswith") operator = "startswith";
      else if (mod === "endswith") operator = "endswith";
      else if (mod === "re") operator = "regex";
      else if (mod === "gte") operator = "gte";
      else if (mod === "lte") operator = "lte";
      else if (Array.isArray(rawVal)) operator = "in";
      const meta = resolveFieldMeta(laneSchema, field);
      groups.push(makeCondition({
        field,
        operator,
        value: Array.isArray(rawVal) ? rawVal.join(", ")
                                     : (rawVal === undefined ? "" : String(rawVal)),
        fieldType: meta?.type || "string",
      }));
    }
  }
  if (!groups.length) return makeRootGroup();
  return makeGroup({ op: "AND", children: groups });
}
