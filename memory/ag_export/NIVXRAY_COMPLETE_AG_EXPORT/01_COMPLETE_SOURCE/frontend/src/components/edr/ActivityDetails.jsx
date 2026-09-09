// EDR Device Trajectory · Right Details panel
// Owner rule #12: pre-populated even before a trajectory node is clicked.
// Clicking an entity (left) OR an event (canvas) selects the same
// underlying activity object.
import React from "react";

const _row = (k, v) => v == null || v === "" ? null : (
  <div key={k} style={styles.row}>
    <span style={styles.rowKey}>{k}</span>
    <span style={styles.rowVal}>{String(v)}</span>
  </div>
);

const _kv_or_hash = (label, v) => v ? _row(label, v) : null;

export const ActivityDetails = ({ inventory, verdict,
                                     selectedEntity, selectedEvent,
                                     onEventClick, onEntitySelect }) => {

  if (!inventory) {
    return <div data-testid="details-empty" style={styles.emptyBox}>
      No inventory yet.
    </div>;
  }

  const totalEntities = Object.values(inventory.entities || {})
    .reduce((s, arr) => s + arr.length, 0);
  const totalEvents = (inventory.events || []).length;

  // Pre-populated summary if nothing selected.
  if (!selectedEntity && !selectedEvent) {
    return (
      <div data-testid="details-summary" style={styles.wrap}>
        <div style={styles.section}>
          <div style={styles.sectionTitle}>Activity Overview</div>
          {_row("Case",       inventory.case_id || "—")}
          {_row("Span start", inventory.span_start || "—")}
          {_row("Span end",   inventory.span_end || "—")}
          {_row("Entities",   totalEntities)}
          {_row("Events",     totalEvents)}
        </div>
        <div style={styles.section}>
          <div style={styles.sectionTitle}>Recent Activity</div>
          {(inventory.events || []).slice(-8).reverse().map((ev) => (
            <button key={ev.event_id}
                     data-testid={`details-recent-${ev.event_id}`}
                     onClick={() => onEventClick && onEventClick(ev)}
                     style={styles.eventBtn}>
              <div style={styles.evTop}>
                <span style={styles.evAction}>{ev.action || "event"}</span>
                <span style={styles.evTs}>{ev.timestamp || "no ts"}</span>
              </div>
              <div style={styles.evSummary}>{ev.display_summary}</div>
              <div style={styles.evMeta}>lane: {ev.lane} · kind: {ev.kind}</div>
            </button>
          ))}
        </div>
      </div>
    );
  }

  // Selected entity details (owner rule #13 · only fields backed by evidence)
  if (selectedEntity) {
    const a = selectedEntity.attributes || {};
    const entityEvents = (inventory.events || [])
      .filter((e) => selectedEntity.event_ids?.includes(e.event_id));
    return (
      <div data-testid={`details-entity-${selectedEntity.entity_id}`} style={styles.wrap}>
        <div style={styles.section}>
          <div style={styles.sectionTitle}>
            {selectedEntity.kind.toUpperCase()}
          </div>
          <div style={styles.entityHeading}>{selectedEntity.display_name}</div>
          {_row("Entity ID",   selectedEntity.entity_id)}
          {_row("First seen",  selectedEntity.first_seen)}
          {_row("Last seen",   selectedEntity.last_seen)}
          {_row("Events",      selectedEntity.event_ids?.length || 0)}
          {selectedEntity.parent_entity_id && _row(
            "Parent entity", selectedEntity.parent_entity_id)}
          {(selectedEntity.child_entity_ids || []).length > 0 && _row(
            "Child entities",
            selectedEntity.child_entity_ids.join(", "))}
        </div>

        <div style={styles.section}>
          <div style={styles.sectionTitle}>Attributes (evidence-backed)</div>
          {_row("PID",              a.pid)}
          {_row("User",             a.user)}
          {_row("Integrity",        a.integrity)}
          {_row("Path",             a.path)}
          {_row("Command line",     a.command_line)}
          {_kv_or_hash("SHA-256",   a.sha256)}
          {_kv_or_hash("SHA-1",     a.sha1)}
          {_kv_or_hash("MD5",       a.md5)}
          {_row("Signer",           a.signer)}
          {_row("Signature",        a.signature_status)}
          {_row("Destination",      a.destination)}
          {_row("Host",             a.host)}
          {_row("Port",             a.port)}
          {_row("Registry value",   a.value_name)}
          {_row("Registry data",    a.value_data)}
          {_row("Artifact type",    a.artifact_type)}
          {_row("File size",        a.size)}
          {_row("MIME",             a.mime)}
        </div>

        <div style={styles.section}>
          <div style={styles.sectionTitle}>Events ({entityEvents.length})</div>
          {entityEvents.slice(0, 20).map((ev) => (
            <button key={ev.event_id}
                     data-testid={`details-entity-event-${ev.event_id}`}
                     onClick={() => onEventClick && onEventClick(ev)}
                     style={styles.eventBtn}>
              <div style={styles.evTop}>
                <span style={styles.evAction}>{ev.action || "event"}</span>
                <span style={styles.evTs}>{ev.timestamp}</span>
              </div>
              <div style={styles.evSummary}>{ev.display_summary}</div>
            </button>
          ))}
        </div>
      </div>
    );
  }

  // Selected event details
  if (selectedEvent) {
    const cf = selectedEvent.canonical_fields || {};
    return (
      <div data-testid={`details-event-${selectedEvent.event_id}`} style={styles.wrap}>
        <div style={styles.section}>
          <div style={styles.sectionTitle}>Event</div>
          <div style={styles.entityHeading}>
            {selectedEvent.display_summary || selectedEvent.action}
          </div>
          {_row("Event ID",   selectedEvent.event_id)}
          {_row("Timestamp",  selectedEvent.timestamp || "no timestamp")}
          {_row("Kind",       selectedEvent.kind)}
          {_row("Lane",       selectedEvent.lane)}
          {_row("Action",     selectedEvent.action)}
          {selectedEvent.entity_id && (
            <button
              data-testid="details-pivot-entity"
              onClick={() => {
                const ent = (inventory.entities?.[selectedEvent.kind] || [])
                  .find((e) => e.entity_id === selectedEvent.entity_id);
                if (ent && onEntitySelect) onEntitySelect(ent);
              }}
              style={styles.pivotBtn}
            >
              → View entity ({selectedEvent.entity_id})
            </button>
          )}
        </div>
        <div style={styles.section}>
          <div style={styles.sectionTitle}>Canonical fields</div>
          {Object.entries(cf).map(([k, v]) => _row(k, v))}
        </div>
        <div style={styles.section}>
          <div style={styles.sectionTitle}>Provenance chain</div>
          {(selectedEvent.provenance_chain || []).map((p, i) => (
            <div key={i} style={styles.provStep}>{p}</div>
          ))}
        </div>
      </div>
    );
  }

  return null;
};

const styles = {
  wrap: {
    background: "#131318", padding: "12px 16px", height: "100%",
    overflowY: "auto", color: "#d0d0d5",
    fontFamily: "ui-monospace, monospace", fontSize: 12,
  },
  emptyBox: { padding: 24, opacity: 0.5, textAlign: "center" },
  section: {
    marginBottom: 16, paddingBottom: 12,
    borderBottom: "1px solid #23232b",
  },
  sectionTitle: {
    fontSize: 10, textTransform: "uppercase", letterSpacing: 2,
    opacity: 0.5, marginBottom: 8,
  },
  entityHeading: {
    fontSize: 16, fontWeight: 700, marginBottom: 8, color: "#e5e5ea",
  },
  row: { display: "flex", marginBottom: 3, fontSize: 11 },
  rowKey: { width: 120, opacity: 0.6, flexShrink: 0 },
  rowVal: { flex: 1, wordBreak: "break-all", color: "#e5e5ea" },
  eventBtn: {
    all: "unset", cursor: "pointer",
    display: "block", width: "100%",
    padding: "6px 8px", marginBottom: 4,
    background: "rgba(0,0,0,0.25)", borderRadius: 4,
    borderLeft: "2px solid #5a8cdc",
  },
  evTop: { display: "flex", justifyContent: "space-between",
            fontSize: 10, opacity: 0.7 },
  evAction: { fontWeight: 700 },
  evTs: { opacity: 0.6 },
  evSummary: { fontSize: 12, marginTop: 2 },
  evMeta: { fontSize: 10, opacity: 0.5, marginTop: 2 },
  pivotBtn: {
    all: "unset", cursor: "pointer",
    color: "#5a8cdc", fontSize: 11, marginTop: 6, display: "block",
  },
  provStep: {
    fontSize: 10, opacity: 0.7, fontFamily: "ui-monospace,monospace",
    marginBottom: 2, wordBreak: "break-all",
  },
};

export default ActivityDetails;
