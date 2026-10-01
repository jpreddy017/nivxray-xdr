/**
 * VisualConditionBuilder — recursive, type-aware, no-JSON UI.
 *
 * Consumes:  lane schema returned by
 *   GET /api/xdr/rule-studio/lanes/{lane}/schema
 * Produces:  a Canonical Condition AST (see conditionAst.js).
 *
 * Rendering rules:
 *   · Group = box with AND / OR toggle · "+ condition" · "+ group" ·
 *     "delete" (unless it is the root).
 *   · Condition = row with field picker (searchable) · operator
 *     dropdown (filtered by field type) · typed value input
 *     (enum → select · bool → toggle · in → chip list · else input) ·
 *     nest button · delete.
 *
 * Every interactive element carries data-testid.
 */
import React, { useMemo, useState } from "react";
import { Plus, Trash2, GitBranch, Search, AlertCircle } from "lucide-react";

import {
  OPERATORS_BY_TYPE,
  OPERATOR_LABEL,
  addChild,
  convertToGroup,
  defaultOperatorForField,
  makeCondition,
  makeGroup,
  removeNode,
  resolveFieldMeta,
  updateNode,
  validateAst,
} from "./conditionAst";


export default function VisualConditionBuilder({ ast, setAst,
                                                 laneSchema, testIdPrefix = "vcb" }) {
  const errors = useMemo(() => validateAst(ast, laneSchema),
                         [ast, laneSchema]);
  const errorMap = useMemo(() => {
    const m = {};
    for (const e of errors) {
      if (!m[e.nodeId]) m[e.nodeId] = [];
      m[e.nodeId].push(e.message);
    }
    return m;
  }, [errors]);

  return (
    <div data-testid={`${testIdPrefix}-root`}>
      <GroupNode node={ast}
                 setAst={setAst}
                 ast={ast}
                 laneSchema={laneSchema}
                 depth={0}
                 isRoot
                 errorMap={errorMap}
                 testIdPrefix={testIdPrefix} />
      {errors.length > 0 && (
        <div style={errBanner} data-testid={`${testIdPrefix}-validation`}>
          <AlertCircle size={11} /> {errors.length} validation issue{errors.length > 1 ? "s" : ""} — resolve before creating rule
        </div>
      )}
    </div>
  );
}


function GroupNode({ node, ast, setAst, laneSchema, depth, isRoot,
                    errorMap, testIdPrefix }) {
  const swapOp = () => setAst(updateNode(ast, node.id,
                                      { op: node.op === "AND" ? "OR" : "AND" }));
  const addCondition = () => setAst(addChild(ast, node.id, makeCondition()));
  const addSubGroup  = () => setAst(addChild(ast, node.id,
                                    makeGroup({ op: "AND", children: [makeCondition()] })));
  const remove       = () => setAst(removeNode(ast, node.id));

  return (
    <div data-testid={`${testIdPrefix}-group-${node.id}`}
         style={{ ...groupBox,
                  borderColor: node.op === "OR" ? "#a78bfa" : "var(--cyan)",
                  marginLeft: depth === 0 ? 0 : 10 }}>
      <div style={groupHead}>
        <button type="button"
                data-testid={`${testIdPrefix}-group-op-${node.id}`}
                onClick={swapOp}
                style={{ ...opBadge,
                         color: node.op === "OR" ? "#a78bfa" : "var(--cyan)",
                         borderColor: node.op === "OR" ? "#a78bfa" : "var(--cyan)" }}>
          {node.op}
        </button>
        <span style={{ fontSize: 9.5, color: "var(--faint)",
                       fontFamily: "var(--mono)", flex: 1 }}>
          {node.op === "OR" ? "any of the following match"
                            : "all of the following match"}
        </span>
        <button type="button"
                data-testid={`${testIdPrefix}-add-cond-${node.id}`}
                onClick={addCondition}
                style={smallBtn} title="Add condition">
          <Plus size={10} /> condition
        </button>
        <button type="button"
                data-testid={`${testIdPrefix}-add-group-${node.id}`}
                onClick={addSubGroup}
                style={smallBtn} title="Add nested group">
          <GitBranch size={10} /> group
        </button>
        {!isRoot && (
          <button type="button"
                  data-testid={`${testIdPrefix}-remove-${node.id}`}
                  onClick={remove}
                  style={{ ...smallBtn, color: "#f87171" }}>
            <Trash2 size={10} />
          </button>
        )}
      </div>

      {node.children.length === 0 && (
        <div style={{ padding: "4px 8px", fontSize: 10.5, color: "var(--faint)",
                      fontFamily: "var(--mono)" }}
             data-testid={`${testIdPrefix}-empty-${node.id}`}>
          Group is empty — click "+ condition" or "+ group".
        </div>
      )}

      {node.children.map((child, i) => (
        <div key={child.id}>
          {i > 0 && (
            <div style={{ padding: "2px 8px", fontSize: 9.5, color: "var(--faint)",
                          fontFamily: "var(--mono)", fontWeight: 700 }}>
              {node.op}
            </div>
          )}
          {child.type === "group"
            ? <GroupNode node={child} ast={ast} setAst={setAst}
                         laneSchema={laneSchema} depth={depth + 1}
                         errorMap={errorMap} testIdPrefix={testIdPrefix} />
            : <ConditionNode node={child} ast={ast} setAst={setAst}
                             laneSchema={laneSchema}
                             errorMap={errorMap}
                             testIdPrefix={testIdPrefix} />
          }
        </div>
      ))}
    </div>
  );
}


function ConditionNode({ node, ast, setAst, laneSchema, errorMap,
                         testIdPrefix }) {
  const meta = resolveFieldMeta(laneSchema, node.field);
  const fieldType = meta?.type || node.fieldType || "string";
  const allowedOps = OPERATORS_BY_TYPE[fieldType] || OPERATORS_BY_TYPE.string;

  const setField = (fieldKey) => {
    const m = resolveFieldMeta(laneSchema, fieldKey);
    const t = m?.type || "string";
    const nextOp = (OPERATORS_BY_TYPE[t] || []).includes(node.operator)
                    ? node.operator : defaultOperatorForField(m);
    // Reset value on type change to avoid invalid state
    let nextValue = node.value;
    if (fieldType !== t) nextValue = t === "bool" ? "false" : "";
    setAst(updateNode(ast, node.id,
      { field: fieldKey, fieldType: t, operator: nextOp, value: nextValue }));
  };
  const setOp = (op) => setAst(updateNode(ast, node.id, { operator: op }));
  const setVal = (value) => setAst(updateNode(ast, node.id, { value }));
  const remove = () => setAst(removeNode(ast, node.id));
  const nest   = () => setAst(convertToGroup(ast, node.id, "AND"));

  const errs = errorMap[node.id] || [];
  return (
    <div data-testid={`${testIdPrefix}-cond-${node.id}`}
         style={{ ...condRow,
                  borderColor: errs.length ? "#f87171" : "var(--border)" }}>
      <FieldPicker value={node.field}
                   onChange={setField}
                   laneSchema={laneSchema}
                   testId={`${testIdPrefix}-field-${node.id}`} />
      <select value={node.operator}
              onChange={(e) => setOp(e.target.value)}
              data-testid={`${testIdPrefix}-op-${node.id}`}
              style={selectStyle}>
        {allowedOps.map((op) => (
          <option key={op} value={op}>{OPERATOR_LABEL[op] || op}</option>
        ))}
      </select>
      <ValueInput fieldType={fieldType}
                  meta={meta}
                  operator={node.operator}
                  value={node.value}
                  onChange={setVal}
                  testId={`${testIdPrefix}-val-${node.id}`} />
      <button type="button"
              data-testid={`${testIdPrefix}-nest-${node.id}`}
              onClick={nest}
              style={smallBtn} title="Wrap in a nested group">
        <GitBranch size={10} />
      </button>
      <button type="button"
              data-testid={`${testIdPrefix}-remove-${node.id}`}
              onClick={remove}
              style={{ ...smallBtn, color: "#f87171" }}>
        <Trash2 size={10} />
      </button>
      {errs.length > 0 && (
        <div style={{ flexBasis: "100%", fontSize: 10, color: "#f87171",
                      fontFamily: "var(--mono)", padding: "2px 6px" }}
             data-testid={`${testIdPrefix}-err-${node.id}`}>
          {errs.join(" · ")}
        </div>
      )}
    </div>
  );
}


function FieldPicker({ value, onChange, laneSchema, testId }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const fields = laneSchema?.fields || [];
  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return fields;
    return fields.filter((f) => f.key.toLowerCase().includes(s)
                             || (f.description || "").toLowerCase().includes(s));
  }, [q, fields]);

  return (
    <div style={{ position: "relative", minWidth: 220 }}>
      <button type="button"
              data-testid={testId}
              onClick={() => setOpen((o) => !o)}
              style={{ ...selectStyle, textAlign: "left", cursor: "pointer",
                       color: value ? "var(--cyan)" : "var(--faint)" }}>
        {value || "Pick a field…"}
      </button>
      {open && (
        <div style={pickerPanel} data-testid={`${testId}-panel`}>
          <div style={{ display: "flex", gap: 4, alignItems: "center",
                        padding: "4px 6px", borderBottom: "1px solid var(--border)" }}>
            <Search size={10} style={{ color: "var(--faint)" }} />
            <input autoFocus value={q}
                   onChange={(e) => setQ(e.target.value)}
                   placeholder="Search fields…"
                   data-testid={`${testId}-search`}
                   style={{ ...selectStyle, border: "none", padding: 2 }} />
          </div>
          <div style={{ maxHeight: 240, overflow: "auto" }}>
            {filtered.map((f) => (
              <div key={f.key}
                   data-testid={`${testId}-opt-${f.key}`}
                   onClick={() => { onChange(f.key); setOpen(false); setQ(""); }}
                   style={{ padding: "4px 8px", cursor: "pointer",
                            borderBottom: "1px solid var(--border)",
                            fontFamily: "var(--mono)", fontSize: 10.5 }}
                   onMouseEnter={(e) => e.currentTarget.style.background = "var(--panel2)"}
                   onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                <div style={{ color: "var(--cyan)" }}>{f.key}</div>
                <div style={{ color: "var(--faint)", fontSize: 9.5 }}>
                  {f.type}{f.example ? ` · e.g. ${f.example}` : ""}{f.description ? ` · ${f.description}` : ""}
                </div>
              </div>
            ))}
            {filtered.length === 0 && (
              <div style={{ padding: 8, fontSize: 10, color: "var(--faint)",
                            fontFamily: "var(--mono)" }}>
                No fields match "{q}"
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}


function ValueInput({ fieldType, meta, operator, value, onChange, testId }) {
  if (operator === "in") {
    return (
      <input value={Array.isArray(value) ? value.join(", ") : (value || "")}
             onChange={(e) => onChange(e.target.value)}
             placeholder="value1, value2, value3"
             data-testid={testId}
             style={inputStyle} />
    );
  }
  if (fieldType === "enum" && meta?.values) {
    return (
      <select value={String(value ?? "")}
              onChange={(e) => onChange(e.target.value)}
              data-testid={testId}
              style={selectStyle}>
        <option value="">— pick —</option>
        {meta.values.map((v) => <option key={v} value={v}>{v}</option>)}
      </select>
    );
  }
  if (fieldType === "bool") {
    return (
      <select value={String(value)}
              onChange={(e) => onChange(e.target.value)}
              data-testid={testId}
              style={selectStyle}>
        <option value="true">true</option>
        <option value="false">false</option>
      </select>
    );
  }
  if (fieldType === "int") {
    return (
      <input type="number" value={value ?? ""}
             onChange={(e) => onChange(e.target.value)}
             placeholder={meta?.example || "0"}
             data-testid={testId}
             style={inputStyle} />
    );
  }
  if (fieldType === "datetime") {
    return (
      <input type="datetime-local" value={value || ""}
             onChange={(e) => onChange(e.target.value)}
             data-testid={testId}
             style={inputStyle} />
    );
  }
  return (
    <input value={value ?? ""}
           onChange={(e) => onChange(e.target.value)}
           placeholder={meta?.example || "value"}
           data-testid={testId}
           style={inputStyle} />
  );
}


// ── styles ─────────────────────────────────────────────────────
const inputStyle = {
  flex: 1, minWidth: 120, padding: "4px 8px",
  background: "var(--panel2)", border: "1px solid var(--border)",
  color: "var(--text)", fontSize: 11, borderRadius: 3,
  fontFamily: "var(--mono)", boxSizing: "border-box",
};
const selectStyle = {
  padding: "4px 6px", background: "var(--panel2)",
  border: "1px solid var(--border)", color: "var(--text)",
  fontSize: 11, borderRadius: 3, fontFamily: "var(--mono)",
  minWidth: 110, boxSizing: "border-box",
};
const smallBtn = {
  padding: "3px 6px", fontSize: 10, background: "var(--panel2)",
  border: "1px solid var(--border)", color: "var(--text-dim)",
  borderRadius: 3, cursor: "pointer", display: "inline-flex",
  alignItems: "center", gap: 3, fontFamily: "var(--mono)",
};
const groupBox = {
  border: "1px dashed var(--cyan)", borderRadius: 3, padding: 8,
  marginBottom: 6, background: "rgba(56,189,248,0.03)",
};
const groupHead = {
  display: "flex", gap: 6, alignItems: "center", marginBottom: 6,
  flexWrap: "wrap",
};
const opBadge = {
  padding: "2px 8px", fontSize: 10, fontFamily: "var(--mono)",
  fontWeight: 700, border: "1px solid", borderRadius: 2,
  background: "var(--panel)", cursor: "pointer",
};
const condRow = {
  display: "flex", gap: 6, alignItems: "center", padding: 6,
  background: "var(--panel)", border: "1px solid",
  borderRadius: 3, marginBottom: 4, flexWrap: "wrap",
};
const pickerPanel = {
  position: "absolute", top: "100%", left: 0, right: 0, marginTop: 2,
  background: "var(--panel)", border: "1px solid var(--border)",
  borderRadius: 3, zIndex: 20, minWidth: 300,
};
const errBanner = {
  padding: "4px 8px", fontSize: 10.5, fontFamily: "var(--mono)",
  color: "#f87171", border: "1px solid #f87171", borderRadius: 3,
  marginTop: 6, display: "flex", alignItems: "center", gap: 4,
};
