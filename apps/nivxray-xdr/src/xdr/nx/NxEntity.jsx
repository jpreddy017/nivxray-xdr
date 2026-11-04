/**
 * NxEntity · one way to render an entity reference anywhere in the product.
 *
 * An entity is a semantic class (device, user, process, file, hash, ip,
 * domain, …), a primary identifier, an optional secondary fact, and — when
 * the platform can genuinely resolve it — a pivot. It carries the NivX icon
 * family, never a third-party vendor's artwork.
 *
 * Identifier strength is stated, never implied: a device known only by a
 * hostname is not the same claim as one with an agent id, so `strength`
 * renders as an explicit state instead of being silently upgraded.
 */
import React from "react";
import NxEntityIcon from "./NxEntityIcon";
import NxState from "./NxOpsState";
import "./nx-ops.css";

export default function NxEntity({ kind, value, secondary = null,
                                   strength = null, mono = true,
                                   onPivot = null, boxed = false, testid }) {
  const absent = value === null || value === undefined || value === "";
  const body = (
    <span className="nx-ent-body">
      <span className={`nx-ent-value${mono ? " nx-mono" : ""}`}>
        {absent ? <span className="nx-absent">—</span> : value}
      </span>
      {secondary && <span className="nx-ent-secondary">{secondary}</span>}
    </span>
  );
  return (
    <span className="nx-ent" data-nx-entity-kind={kind}
          data-testid={testid || `nx-entity-${kind}`}>
      <NxEntityIcon kind={kind} boxed={boxed} />
      {onPivot && !absent
        ? <button type="button" className="nx-ent-pivot"
                  onClick={(e) => { e.stopPropagation(); onPivot(value); }}>
            {body}
          </button>
        : body}
      {strength && <NxState value={strength} size="sm" />}
    </span>
  );
}

/** Several entities on one line, with an honest overflow count. */
export function NxEntityList({ entities = [], limit = 4, onPivot = null,
                                testid = "nx-entities" }) {
  if (!entities.length) {
    return <span className="nx-absent" data-testid={`${testid}-empty`}>—</span>;
  }
  return (
    <span className="nx-ent-list" data-testid={testid}>
      {entities.slice(0, limit).map((e, i) => (
        <NxEntity key={`${e.kind}-${e.value}-${i}`} {...e} onPivot={onPivot} />
      ))}
      {entities.length > limit && (
        <span className="nx-absent">+{entities.length - limit}</span>
      )}
    </span>
  );
}
