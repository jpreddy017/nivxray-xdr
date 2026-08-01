import React, { memo } from "react";
import { Handle, Position } from "@xyflow/react";
import { iconFor, toneFor } from "../iconMap";

/**
 * Icon-driven card node. Two line-limited paragraphs, one tone accent, one
 * lucide glyph. Confidence dot on the right if provided.
 *
 * data: { title, subtitle, kind, subKind, class, confidence, hot, hitCount,
 *         severity, tacticLane }
 */
export const StageNode = memo(function StageNode({ data, selected }) {
  const Icon = iconFor({ kind: data.kind, subKind: data.subKind, attrs: { ioc_kind: data.subKind } });
  const tone = toneFor(data);
  const conf = typeof data.confidence === "number" ? data.confidence : null;

  return (
    <div
      className={`eg-node eg-tone-${tone}${data.hot ? " eg-hot" : ""}${selected ? " eg-sel" : ""}`}
      data-testid={`eg-node-${data.id || data.title || tone}`}
    >
      <Handle type="target" position={Position.Left} className="eg-handle" isConnectable={false} />
      <div className="eg-node-icon">
        <Icon size={18} strokeWidth={1.8} />
      </div>
      <div className="eg-node-body">
        <div className="eg-node-title" title={data.title}>{data.title}</div>
        {data.subtitle ? (
          <div className="eg-node-sub" title={data.subtitle}>{data.subtitle}</div>
        ) : null}
      </div>
      {data.badgeText ? (
        <div className="eg-node-badge" title={data.badgeTitle || ""}>{data.badgeText}</div>
      ) : null}
      {conf !== null ? (
        <div className="eg-node-conf" title={`${conf}% confidence`}>
          <span className="eg-conf-dot" style={{ opacity: Math.max(0.2, conf / 100) }} />
        </div>
      ) : null}
      <Handle type="source" position={Position.Right} className="eg-handle" isConnectable={false} />
    </div>
  );
});
