/**
 * NxFilter · ONE filter grammar for every operational surface.
 *
 * Two things every analyst filter must do and most hand-rolled ones do not:
 *   · show what is currently constraining the view (an invisible filter is
 *     how an analyst concludes "there is nothing there"), and
 *   · let each constraint be removed individually.
 *
 * The active-filter chips are therefore part of the primitive, not an
 * optional decoration.
 */
import React from "react";
import { X } from "lucide-react";
import { NxField, NxToolbar, NxButton, nxSlug } from "./NxOps";
import "./nx-ops.css";

/**
 * @param fields  [{ key, label, type?: "text"|"select", options?, placeholder? }]
 * @param value   { [key]: string }
 */
export default function NxFilter({ fields = [], value = {}, onChange,
                                   onApply = null, onClear = null,
                                   right = null, testid = "nx-filter" }) {
  const active = fields
    .filter((f) => value[f.key] !== undefined && value[f.key] !== "")
    .map((f) => ({ ...f, current: value[f.key] }));

  const set = (key, v) => onChange({ ...value, [key]: v });

  return (
    <div className="nx-filter" data-testid={testid}>
      <NxToolbar testid={`${testid}-toolbar`} right={
        <>
          {right}
          {onApply && (
            <NxButton variant="primary" testid={`${testid}-apply`}
                      onClick={() => onApply(value)}>Search</NxButton>
          )}
          {onClear && (
            <NxButton testid={`${testid}-clear`} onClick={onClear}
                      disabled={active.length === 0}>Clear</NxButton>
          )}
        </>}>
        {fields.map((f) => (
          <NxField label={f.label} key={f.key}
                   testid={`${testid}-field-${nxSlug(f.key)}`}>
            {f.type === "select" ? (
              <select value={value[f.key] ?? ""}
                      data-testid={`${testid}-${nxSlug(f.key)}`}
                      onChange={(e) => set(f.key, e.target.value)}>
                {(f.options || []).map((o) => (
                  <option key={String(o.value)} value={o.value}>
                    {o.label}
                  </option>))}
              </select>
            ) : (
              <input value={value[f.key] ?? ""} placeholder={f.placeholder || ""}
                     data-testid={`${testid}-${nxSlug(f.key)}`}
                     onChange={(e) => set(f.key, e.target.value)}
                     onKeyDown={(e) => {
                       if (e.key === "Enter" && onApply) onApply(value);
                     }} />
            )}
          </NxField>
        ))}
      </NxToolbar>

      {active.length > 0 && (
        <div className="nx-filter-active" data-testid={`${testid}-active`}>
          <span className="nx-tb-label">Constraining this view</span>
          {active.map((f) => (
            <button type="button" className="nx-filter-chip" key={f.key}
                    data-testid={`${testid}-chip-${nxSlug(f.key)}`}
                    onClick={() => set(f.key, "")}>
              <span className="nx-filter-chip-k">{f.label}</span>
              <span className="nx-filter-chip-v">{String(f.current)}</span>
              <X size={10} />
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
