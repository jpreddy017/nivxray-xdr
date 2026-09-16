// EDR Device Trajectory · Left Rail — INVENTORY (not a category list).
// Owner architecture lock (2026-08-26):
//   The left panel is NOT a category list.  It is the inventory of
//   things that actually happened / existed on the endpoint.
//   Categories are merely GROUPING HEADERS.
//
// Original NivXRay visual language.  Functional workflow mirrors
// a serious EDR analyst inventory — not a mimicry of any product.
import React, { useMemo, useState } from "react";

// Owner-mandated grouping (SYSTEM · ACTIVITY · NETWORK · EXTERNAL).
// Kinds map to grouping headers — headers appear only when the
// underlying inventory is non-empty (never a category placeholder).
const GROUPS = [
  { id: "system",   label: "System",            kinds: ["system", "identity"] },
  { id: "activity", label: "Files & Processes", kinds: ["process", "file", "registry"] },
  { id: "network",  label: "Network",           kinds: ["network"] },
];

const KIND_ICON = {
  process:  "◆",
  file:     "▤",
  network:  "◈",
  registry: "◐",
  identity: "◉",
  system:   "▢",
};

export const EntityInventory = ({ inventory, selectedEntityId, onSelect }) => {
  const ents = inventory?.entities || {};

  // Build a flat list per group so entities — not kinds — are the
  // primary content.  Preserve deterministic ordering.
  const groupsWithEntities = useMemo(() => {
    return GROUPS.map((g) => {
      const items = [];
      for (const k of g.kinds) {
        for (const e of ents[k] || []) items.push({ ...e, _kind: k });
      }
      items.sort((a, b) => (a.display_name || "").localeCompare(b.display_name || ""));
      return { ...g, items };
    }).filter((g) => g.items.length > 0);
  }, [ents]);

  const total = useMemo(
    () => groupsWithEntities.reduce((s, g) => s + g.items.length, 0),
    [groupsWithEntities],
  );

  return (
    <div data-testid="entity-inventory" style={styles.rail}>
      <div style={styles.railHeader}>
        <div style={styles.railTitle}>Activity Inventory</div>
        <div style={styles.railCount}>{total} entities observed</div>
      </div>

      {groupsWithEntities.length === 0 && (
        <div style={styles.empty}>no activity observed on this endpoint yet</div>
      )}

      {groupsWithEntities.map((g) => (
        <div key={g.id} style={styles.group} data-testid={`inventory-group-${g.id}`}>
          <div style={styles.groupHeader}>
            <span>{g.label}</span>
            <span style={styles.groupCount}>{g.items.length}</span>
          </div>
          <div style={styles.entityList}>
            {g.items.map((e) => (
              <button
                key={e.entity_id}
                data-testid={`inventory-entity-${e.entity_id}`}
                onClick={() => onSelect && onSelect(e)}
                style={{
                  ...styles.entityBtn,
                  background: selectedEntityId === e.entity_id
                    ? "rgba(90,140,220,0.20)" : "transparent",
                  borderLeftColor: selectedEntityId === e.entity_id
                    ? "#5a8cdc" : "transparent",
                }}
              >
                <span style={styles.entityIcon}>{KIND_ICON[e._kind] || "·"}</span>
                <span style={styles.entityBody}>
                  <span style={styles.entityName}>{e.display_name}</span>
                  <span style={styles.entityMeta}>
                    {(e.event_ids?.length || 0)} event{(e.event_ids?.length || 0) === 1 ? "" : "s"}
                    {e.first_seen ? ` · ${new Date(e.first_seen).toLocaleTimeString()}` : ""}
                  </span>
                </span>
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

const styles = {
  rail: {
    background: "#0f0f14",
    borderRight: "1px solid #23232b",
    height: "100%",
    overflowY: "auto",
    fontFamily: "ui-monospace, monospace",
    fontSize: 12,
    color: "#d0d0d5",
  },
  railHeader: {
    padding: "12px 16px",
    borderBottom: "1px solid #23232b",
    background: "#0d0d12",
  },
  railTitle: {
    fontSize: 10, textTransform: "uppercase", letterSpacing: 2,
    color: "#a0a0aa", marginBottom: 2,
  },
  railCount: { fontSize: 10, opacity: 0.5 },
  empty: {
    padding: 24, textAlign: "center", opacity: 0.5,
    fontSize: 11, fontStyle: "italic",
  },
  group: { padding: "8px 0", borderBottom: "1px solid #1a1a20" },
  groupHeader: {
    padding: "8px 16px",
    display: "flex", justifyContent: "space-between",
    fontSize: 10, textTransform: "uppercase", letterSpacing: 1.5,
    color: "#7a7a85",
  },
  groupCount: {
    opacity: 0.6, background: "#1a1a20",
    padding: "1px 8px", borderRadius: 10, fontSize: 10,
  },
  entityList: { padding: "2px 0" },
  entityBtn: {
    all: "unset", cursor: "pointer", width: "100%",
    boxSizing: "border-box",
    display: "flex", gap: 10, alignItems: "center",
    padding: "6px 16px 6px 12px",
    borderLeft: "3px solid transparent",
  },
  entityIcon: {
    width: 16, height: 16, textAlign: "center",
    color: "#5a8cdc", flexShrink: 0, fontSize: 12,
  },
  entityBody: { display: "flex", flexDirection: "column" },
  entityName: { fontSize: 12, color: "#e5e5ea" },
  entityMeta: { fontSize: 10, opacity: 0.5, marginTop: 2 },
};

export default EntityInventory;
