/**
 * Original event artwork, functionally equivalent to the Cisco Secure
 * Endpoint trajectory glyphs.
 *
 * Cisco's icon assets are proprietary and cannot be reproduced, so each
 * activity type gets an equivalent shape that carries the same
 * information: WHAT happened (shape) and its DISPOSITION (colour).
 * Every glyph is drawn inside a 14×14 box centred on (0,0).
 */
import React from "react";

import { C } from "./ampModel";

const S = 4.2;   // half-extent of the glyph box (Cisco draws small
                 // outline marks, not filled dots)

/** Shape per canonical event kind. Anything unmapped gets a neutral
 *  observation mark rather than a shape that would imply a category. */
function Shape({ type, color, filled }) {
  const stroke = color;
  const fill = filled ? color : "transparent";
  const sw = 1.05;
  const p = { stroke, strokeWidth: sw, fill: "none",
              strokeLinejoin: "round", strokeLinecap: "round" };
  switch (type) {
    case "process_create":
      return (
        <>
          <rect x={-S} y={-S} width={S * 2} height={S * 2} rx={1.2}
                fill={fill} stroke={stroke} strokeWidth={sw} />
          <path d={`M ${-1.9} ${-2.9} L ${2.4} 0 L ${-1.9} ${2.9} Z`}
                fill={stroke} stroke="none" />
        </>
      );
    case "process_exit":
      return (
        <>
          <rect x={-S} y={-S} width={S * 2} height={S * 2} rx={1.2}
                fill={fill} stroke={stroke} strokeWidth={sw} />
          <path d={`M -2.6 -2.6 L 2.6 2.6 M 2.6 -2.6 L -2.6 2.6`}
                {...p} stroke={stroke} />
        </>
      );
    case "file_create":
    case "file_write":
    case "file_modify":
    case "file_delete":
    case "file": {
      const page = `M ${-4} ${-S} L 1.4 ${-S} L 4 ${-2.6} L 4 ${S} L ${-4} ${S} Z`;
      return (
        <>
          <path d={page} fill={fill} stroke={stroke} strokeWidth={sw} />
          <path d="M 1.4 -5.6 L 1.4 -2.6 L 4 -2.6" {...p} />
          {type === "file_delete"
            ? <path d="M -3 3.6 L 3 -3.4" {...p}
                    stroke={stroke} />
            : <path d="M -2 0.4 L 2 0.4 M -2 2.6 L 1 2.6" {...p}
                    stroke={stroke} />}
        </>
      );
    }
    case "image_load":
      return (
        <>
          <rect x={-S} y={-S} width={S * 2} height={S * 2} rx={1.2}
                fill={fill} stroke={stroke} strokeWidth={sw} />
          <path d="M 0 3.2 L 0 -2.6 M -2.2 -0.6 L 0 -2.9 L 2.2 -0.6"
                {...p} stroke={stroke} />
        </>
      );
    case "network_connect":
      return (
        <>
          <circle r={S} fill={fill} stroke={stroke} strokeWidth={sw} />
          <path d="M -3.2 1.6 L 2.4 -2.4 M 0.1 -2.9 L 2.9 -2.9 L 2.9 -0.2"
                {...p} stroke={stroke} />
        </>
      );
    case "network_listen":
      return (
        <>
          <circle r={S} fill={fill} stroke={stroke} strokeWidth={sw} />
          <path d="M -2.8 2.2 A 4 4 0 0 1 2.8 -2.4 M -0.9 2.4 A 2 2 0 0 1 1 0.4"
                {...p} stroke={stroke} />
        </>
      );
    case "dns_query":
    case "dns":
      return (
        <>
          <circle r={S} fill={fill} stroke={stroke} strokeWidth={sw} />
          <path d="M -5.4 0 L 5.4 0 M 0 -5.5 A 3.4 5.5 0 0 0 0 5.5 A 3.4 5.5 0 0 0 0 -5.5"
                {...p} stroke={stroke} />
        </>
      );
    case "detection":
      return (
        <>
          <path d={`M 0 ${-S - 0.4} L ${S + 0.6} ${S} L ${-S - 0.6} ${S} Z`}
                fill={color} stroke={color} strokeWidth={sw} />
          <path d="M 0 -2.2 L 0 1.4" stroke="#FFFFFF" strokeWidth={1.5}
                strokeLinecap="round" />
          <circle cx={0} cy={3.3} r={0.95} fill="#FFFFFF" />
        </>
      );
    case "registry_value_set":
      return (
        <>
          <rect x={-S} y={-S} width={S * 2} height={S * 2} rx={1.2}
                fill={fill} stroke={stroke} strokeWidth={sw} />
          <path d="M -2.8 -1.8 L 2.8 -1.8 M -2.8 1.4 L 0.6 1.4"
                {...p} stroke={stroke} />
        </>
      );
    case "service_install":
      return (
        <>
          <circle r={S} fill={fill} stroke={stroke} strokeWidth={sw} />
          <path d="M 0 -3.4 L 0 3.4 M -3.4 0 L 3.4 0"
                {...p} stroke={stroke} />
        </>
      );
    case "memory_alloc":
      return (
        <>
          <rect x={-S} y={-3.6} width={S * 2} height={7.2} rx={1}
                fill={fill} stroke={stroke} strokeWidth={sw} />
          <path d="M -2 -3.6 L -2 3.6 M 1.4 -3.6 L 1.4 3.6"
                {...p} stroke={stroke} />
        </>
      );
    case "kernel_event":
      return (
        <>
          <rect x={-4} y={-4} width={8} height={8} rx={0.8}
                fill={fill} stroke={stroke} strokeWidth={sw} />
          <path d="M -5.8 -2 L -4 -2 M -5.8 2 L -4 2 M 4 -2 L 5.8 -2 M 4 2 L 5.8 2"
                {...p} />
        </>
      );
    case "cloud_iam_action":
      return (
        <path d="M -4.6 2.6 A 2.4 2.4 0 0 1 -3.6 -1.9 A 3.3 3.3 0 0 1 2.6 -1.6 A 2.2 2.2 0 0 1 4.4 2.6 Z"
             fill={fill} stroke={stroke} strokeWidth={sw}
             strokeLinejoin="round" />
      );
    default:
      return <circle r={4} fill={fill} stroke={stroke} strokeWidth={sw} />;
  }
}

/**
 * One trajectory glyph.
 *
 * `count > 1` reproduces Cisco's icon aggregation: overlapping activity
 * collapses to a single mark carrying the number, so a burst never
 * reads as one event.
 */
export default function EventGlyph({ event, color, count = 1, red = false,
                                     selected = false }) {
  return (
    <g>
      {selected && (
        <circle r={8.4} fill="rgba(31,134,208,0.16)" stroke="#1F86D0"
                strokeWidth={1} />
      )}
      {red && (
        <circle r={7.4} fill={C.maliciousHalo} stroke={color}
                strokeWidth={1.2} />
      )}
      <Shape type={event.event_type} color={color} filled={false} />
      {count > 1 && (
        <>
          <circle cx={5.6} cy={-5.6} r={4.4} fill="#5F6B77" />
          <text x={5.6} y={-3.9} textAnchor="middle" fontSize={5.8}
                fill="#FFFFFF" fontWeight={700}>
            {count > 99 ? "+" : count}
          </text>
        </>
      )}
    </g>
  );
}

/** Compromise marker on the time axis — Cisco puts a red mark above the
 *  trajectory at the instant of a compromise event. */
export function CompromiseMarker({ color = C.malicious }) {
  return (
    <g>
      <circle r={5.2} fill={C.maliciousHalo} stroke={color}
              strokeWidth={1.4} />
      <line x1={-3.4} y1={3.4} x2={3.4} y2={-3.4} stroke={color}
            strokeWidth={1.4} />
    </g>
  );
}

/** Legend rows — the glyph vocabulary, stated rather than implied. */
export const LEGEND_TYPES = [
  "process_create", "process_exit", "file_write", "file_delete",
  "network_connect", "network_listen", "dns_query", "detection",
  "registry_value_set", "service_install", "memory_alloc",
  "kernel_event", "cloud_iam_action",
];

export { Shape };
