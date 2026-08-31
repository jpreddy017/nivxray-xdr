/**
 * NxIkgGlyph · §7 IKG relationship affordance.
 *
 * Renders **only** when `linked === true`.  A missing glyph is
 * itself the honest signal (the entity is not IKG-linked).  Never
 * greyed-out, never "coming soon".
 */
import React from "react";
import { Waypoints } from "lucide-react";

export default function NxIkgGlyph({ linked = false, onClick, title = "View in Investigation Graph", ...rest }) {
  if (!linked) return null;
  return (
    <button
      type="button"
      className="nx-ikg"
      onClick={onClick}
      title={title}
      aria-label={title}
      {...rest}
    >
      <Waypoints size={12} strokeWidth={2} />
    </button>
  );
}
