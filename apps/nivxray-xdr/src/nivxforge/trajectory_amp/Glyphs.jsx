import React from "react";
import { PAL } from "./model";

// Original NivXForge glyphs (drawn around 0,0). Shape encodes the event kind; color encodes semantics.
const PAGE = "M-4,-5 h5 l3,3 v7 h-8 z";
const ink = { stroke: PAL.bg, strokeWidth: 1.2, fill: "none" };

function pageWith(color, inner) {
  return <g><path d={PAGE} fill={color} stroke={PAL.bg} strokeWidth={0.8} />{inner}</g>;
}

const SHAPES = {
  PROCESS_START: (c) => <circle r={4.6} fill={c} stroke={PAL.bg} strokeWidth={0.8} />,
  PROCESS_END: (c) => <rect x={-4} y={-4} width={8} height={8} fill={PAL.bg} stroke={c} strokeWidth={1.8} />,
  FILE_CREATE: (c) => pageWith(c, <path d="M-2,1.5 h4 M0,-0.5 v4" {...ink} />),
  FILE_WRITE: (c) => pageWith(c, <path d="M-2.5,0 h5 M-2.5,2.5 h5" {...ink} />),
  FILE_MOVE: (c) => pageWith(c, <path d="M-2.5,1.5 h4 m-1.5,-1.5 l1.5,1.5 l-1.5,1.5" {...ink} />),
  FILE_DELETE: (c) => pageWith(c, <path d="M-2,-0.5 l4,4 M2,-0.5 l-4,4" {...ink} />),
  FILE_EXECUTE: (c) => pageWith(c, <path d="M-1.5,-0.5 l3.5,2 l-3.5,2 z" fill={PAL.bg} />),
  NETWORK_CONNECT: (c) => <path d="M0,-5 L5,0 L0,5 L-5,0 Z" fill={c} stroke={PAL.bg} strokeWidth={0.8} />,
  DNS_QUERY: (c) => <path d="M0,-4.5 L4.5,0 L0,4.5 L-4.5,0 Z" fill={PAL.bg} stroke={c} strokeWidth={1.6} />,
  MATCH: () => <g><path d="M0,-5.5 L5.5,4.5 L-5.5,4.5 Z" fill={PAL.amber} stroke={PAL.bg} strokeWidth={0.8} />
    <path d="M0,-2 v3.2 M0,2.6 v0.6" stroke={PAL.bg} strokeWidth={1.3} /></g>,
  RETRO: () => <g><path d="M3.8,-2 A4.2,4.2 0 1 0 4,2" fill="none" stroke={PAL.accent} strokeWidth={1.6} />
    <path d="M1.8,-3.6 L4.4,-2.2 L4.8,-5.2" fill="none" stroke={PAL.accent} strokeWidth={1.4} /></g>,
  APPROVAL: () => <g><path d="M-3.8,-5 h7.6 l-7.6,10 h7.6 z" fill="none" stroke={PAL.accent} strokeWidth={1.4} />
    <path d="M-1.6,2.6 h3.2" stroke={PAL.accent} strokeWidth={1.4} /></g>,
  LATE: () => <g><circle r={3.6} fill={PAL.bg} stroke={PAL.muted} strokeWidth={1.2} />
    <path d="M0,-2 v2 h1.8" fill="none" stroke={PAL.muted} strokeWidth={1.1} /></g>,
};

export function Glyph({ kind, color = PAL.neutral }) {
  const f = SHAPES[kind];
  return f ? f(color) : <circle r={3.5} fill={color} />;
}

export function GlyphIcon({ kind, color, size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="-7 -7 14 14" aria-hidden="true" style={{ flexShrink: 0 }}>
      <Glyph kind={kind} color={color} />
    </svg>
  );
}

export function ConnectorIcon({ dash, mark }) {
  return (
    <svg width={34} height={14} aria-hidden="true" style={{ flexShrink: 0 }}>
      <path d="M2,7 H32" stroke={PAL.text} strokeWidth={1.5} strokeDasharray={dash || undefined} />
      {mark && <text x={17} y={5} fill={PAL.amber} fontSize={9} textAnchor="middle">{mark}</text>}
    </svg>
  );
}
