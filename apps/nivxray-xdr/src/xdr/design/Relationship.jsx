/**
 * <Relationship> — Round 24.9 primitive.
 *
 * Renders a witnessed edge between two entities.  The edge state
 * is REQUIRED — you may not draw a relationship without declaring
 * whether it is evidenced or unavailable.
 *
 *   <Relationship
 *     from={<Entity kind="adapter" name="Cortex XDR" />}
 *     via="ingest"
 *     to={<Entity kind="source" name="prod-tenant" />}
 *     state="observed"
 *   />
 */
import React from "react";

export default function Relationship({
  from,
  via,
  to,
  state = "unavailable",
  testid,
}) {
  return (
    <span
      className="evops-relationship"
      data-state={state}
      data-testid={testid}
    >
      {from}
      <span className="evops-relationship__connector">
        <span aria-hidden>—</span>
        <span>{via}</span>
        <span aria-hidden>→</span>
      </span>
      {to}
    </span>
  );
}

