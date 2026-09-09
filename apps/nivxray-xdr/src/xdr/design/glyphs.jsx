/**
 * NivXRay XDR · Security-Ontology Glyph Library · v1.0
 * ---------------------------------------------------------------
 * The alphabet of the NivXRay XDR Visual Language System.  Each
 * glyph:
 *
 *   · draws on a 24×24 grid with 1.5px stroke
 *   · renders correctly at 12 / 16 / 24 / 32 px
 *   · expresses ONE security ontology concept
 *   · inherits colour from `currentColor` so it reads any surface
 *
 * Adding a new security concept REQUIRES a new glyph here AND a
 * corresponding entry in `/app/memory/VISUAL_LANGUAGE.md` §2.
 * Lucide is not a substitute for ontology-level concepts.
 *
 * ─────────────────────────────────────────────────────────────
 * Public API:
 *   <Glyph name="incident" size={16} />
 *   Glyph.Incident, Glyph.Host, Glyph.User, …
 * ─────────────────────────────────────────────────────────────
 */
import React from "react";


const svgProps = (size, extra) => ({
  width: size,
  height: size,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  ...extra,
});


/* ---------------------- ontology glyphs ---------------------- */

export const IncidentGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="incident">
    {/* Notched shield · warning corner cut */}
    <path d="M12 2.5 4.5 5.5V12c0 4.4 3 8.1 7.5 9.5 4.5-1.4 7.5-5.1 7.5-9.5V5.5L15 4" />
    <path d="M12 8v4.5" />
    <circle cx="12" cy="15.5" r="0.9" fill="currentColor" stroke="none" />
  </svg>
);

export const AlertGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="alert">
    <path d="M12 3 4 20h16Z" />
    <path d="M12 10v4" />
    <circle cx="12" cy="17" r="0.9" fill="currentColor" stroke="none" />
  </svg>
);

export const DetectionGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="detection">
    {/* Crosshair inside square */}
    <rect x="3.5" y="3.5" width="17" height="17" rx="1" />
    <circle cx="12" cy="12" r="3" />
    <path d="M12 2v3M12 19v3M2 12h3M19 12h3" />
  </svg>
);

export const HostGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="host">
    {/* Server chassis · two horizontal slots */}
    <rect x="3.5" y="4.5" width="17" height="6" rx="1" />
    <rect x="3.5" y="13.5" width="17" height="6" rx="1" />
    <circle cx="7" cy="7.5" r="0.7" fill="currentColor" stroke="none" />
    <circle cx="7" cy="16.5" r="0.7" fill="currentColor" stroke="none" />
    <path d="M10 7.5h7M10 16.5h7" />
  </svg>
);

export const UserGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="user">
    {/* Hexagonal head + bust */}
    <path d="M12 3l4 2.3v4.6L12 12.2 8 9.9V5.3Z" />
    <path d="M4 21c0-4 3.6-6.5 8-6.5S20 17 20 21" />
  </svg>
);

export const ProcessGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="process">
    {/* Squared-tooth cog with centred dot */}
    <path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1" />
    <rect x="8" y="8" width="8" height="8" rx="0.8" />
    <circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none" />
  </svg>
);

export const FileGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="file">
    {/* Document + corner fold + hash line */}
    <path d="M6 3h8l4 4v14H6Z" />
    <path d="M14 3v4h4" />
    <path d="M9 13h6M9 16h4" />
  </svg>
);

export const NetworkGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="network">
    {/* Three linked nodes */}
    <circle cx="5" cy="6" r="2" />
    <circle cx="19" cy="6" r="2" />
    <circle cx="12" cy="18" r="2" />
    <path d="M6.6 7.5l4 8.5M17.4 7.5l-4 8.5M7 6h10" />
  </svg>
);

export const DomainGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="domain">
    {/* Globe · single meridian */}
    <circle cx="12" cy="12" r="8.5" />
    <path d="M3.5 12h17" />
    <path d="M12 3.5c2.5 2.7 3.8 5.7 3.8 8.5s-1.3 5.8-3.8 8.5c-2.5-2.7-3.8-5.7-3.8-8.5s1.3-5.8 3.8-8.5Z" />
  </svg>
);

export const IpGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="ip">
    {/* Squared address with dot separators */}
    <rect x="3" y="7" width="18" height="10" rx="1" />
    <circle cx="8"  cy="12" r="0.8" fill="currentColor" stroke="none" />
    <circle cx="12" cy="12" r="0.8" fill="currentColor" stroke="none" />
    <circle cx="16" cy="12" r="0.8" fill="currentColor" stroke="none" />
  </svg>
);

export const EvidenceGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="evidence">
    {/* Stacked layered plates */}
    <path d="M4 8l8-4 8 4-8 4Z" />
    <path d="M4 12l8 4 8-4" />
    <path d="M4 16l8 4 8-4" />
  </svg>
);

export const TechniqueGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="technique">
    {/* Tag shape with anchor hole */}
    <path d="M3.5 4.5h9l8 8-9 9-8-8Z" />
    <circle cx="7" cy="8" r="1.4" />
  </svg>
);

export const TacticGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="tactic">
    {/* Chevron progress marker */}
    <path d="M4 6l6 6-6 6" />
    <path d="M12 6l6 6-6 6" />
  </svg>
);

export const ResponseGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="response">
    {/* Bolt inside shield */}
    <path d="M12 2.5 4.5 5.5V12c0 4.4 3 8.1 7.5 9.5 4.5-1.4 7.5-5.1 7.5-9.5V5.5Z" />
    <path d="M12.6 7l-3 6h2.4l-.6 4 3-6h-2.4Z" fill="currentColor" stroke="none" />
  </svg>
);

export const VerdictGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="verdict">
    {/* Diamond with check */}
    <path d="M12 3l9 9-9 9-9-9Z" />
    <path d="M8.5 12.2l2.3 2.3 4.7-4.7" />
  </svg>
);

export const ProvenanceGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="provenance">
    {/* Three linked breadcrumb dots */}
    <circle cx="5"  cy="12" r="2" />
    <circle cx="12" cy="12" r="2" />
    <circle cx="19" cy="12" r="2" />
    <path d="M7 12h3M14 12h3" />
  </svg>
);

export const CorrelationGlyph = ({ size = 16, ...p }) => (
  <svg {...svgProps(size, p)} data-glyph="correlation">
    {/* Two intersecting arcs = correlated signals */}
    <path d="M3 12c4-9 14-9 18 0" />
    <path d="M3 12c4 9 14 9 18 0" />
    <circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none" />
  </svg>
);


/* ------------- named-lookup + default barrel export ------------- */

const REGISTRY = {
  incident:    IncidentGlyph,
  alert:       AlertGlyph,
  detection:   DetectionGlyph,
  host:        HostGlyph,
  user:        UserGlyph,
  process:     ProcessGlyph,
  file:        FileGlyph,
  network:     NetworkGlyph,
  domain:      DomainGlyph,
  ip:          IpGlyph,
  evidence:    EvidenceGlyph,
  technique:   TechniqueGlyph,
  tactic:      TacticGlyph,
  response:    ResponseGlyph,
  verdict:     VerdictGlyph,
  provenance:  ProvenanceGlyph,
  correlation: CorrelationGlyph,
};


/**
 * <Glyph name="incident" size={16} /> · dynamic glyph resolver.
 * Falls back to `null` (renders nothing) if the name is not part
 * of the ontology — never substitutes a random Lucide icon.
 */
export default function Glyph({ name, size = 16, ...rest }) {
  const G = REGISTRY[String(name || "").toLowerCase()];
  if (!G) return null;
  return <G size={size} {...rest} />;
}

Glyph.registry = REGISTRY;
