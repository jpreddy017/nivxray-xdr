/**
 * <Entity> — Round 24.9 primitive.
 *
 * Represents ONE operational object: adapter, host, user, rule,
 * source, etc.  Renders the human-readable NAME using humanist
 * typography and the machine ID in monospace beneath — never
 * mixed.
 *
 *   <Entity kind="adapter" name="Cortex XDR" id="cortex-xdr" />
 *
 * Rules:
 *   · `kind` is required and drives the icon accent — no ad-hoc
 *     colour.
 *   · `id` is optional; when present it renders in the machine
 *     face on its own line.  Never render the id in isolation
 *     without the name.
 *   · `href` opts the entity into keyboard-navigable link
 *     grammar (uses <button> under the hood — no anchor styling
 *     surprises).
 */
import React from "react";
import { Plug, Server, User, ShieldCheck, Database } from "lucide-react";

const ICON_BY_KIND = {
  adapter: Plug,
  host:    Server,
  user:    User,
  rule:    ShieldCheck,
  source:  Database,
};

export default function Entity({
  kind,
  name,
  id = null,
  size = "md",
  icon,
  onSelect = null,
  testid,
}) {
  const IconCmp = icon || ICON_BY_KIND[kind] || Plug;
  const Wrapper = onSelect ? "button" : "span";
  const wrapperProps = onSelect
    ? { type: "button", onClick: onSelect, className: "nx-link" }
    : {};
  return (
    <Wrapper
      {...wrapperProps}
      className={`evops-entity ${size === "lg" ? "evops-entity--large" : ""}`}
      data-kind={kind}
      data-testid={testid}
    >
      <span className="evops-entity__icon" aria-hidden>
        <IconCmp size={size === "lg" ? 16 : 13} />
      </span>
      <span className="evops-entity__body">
        <span className="evops-entity__name">{name}</span>
        {id && <span className="evops-entity__id">{id}</span>}
      </span>
    </Wrapper>
  );
}

