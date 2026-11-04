/**
 * InvestigationLanes — Round 12 · Investigation Fabric UI (read-only).
 *
 * Renders the six honest lanes returned by
 *   GET /api/admin/content-supply-chain/investigation/:incident_id
 *
 *   Timeline · Process Tree · Evidence Graph · Device Trajectory ·
 *   Attack Story · ATT&CK
 *
 * Every lane can be:
 *   READY   — real data available (rendered)
 *   MINIMAL — partial data (rendered, warning tint)
 *   EMPTY   — no data available; the exact backend `reason` is shown
 *
 * No lane is ever invented in the UI.  A lane's state comes from
 * the backend projection only.
 */
import React, { useEffect, useState } from "react";
import { Clock, GitBranch, Share2, MapPin, BookOpen, Target,
                CheckCircle2, Circle, AlertTriangle } from "lucide-react";
import api from "@/lib/api";


const LANE_META = {
  timeline:          { label: "Timeline",          icon: Clock },
  process_tree:      { label: "Process Tree",      icon: GitBranch },
  evidence_graph:    { label: "Evidence Graph",    icon: Share2 },
  device_trajectory: { label: "Device Trajectory", icon: MapPin },
  attack_story:      { label: "Attack Story",      icon: BookOpen },
  attck:             { label: "ATT&CK",            icon: Target },
};

const STATE_COLOR = {
  READY:   "var(--mint)",
  MINIMAL: "var(--amber)",
  EMPTY:   "var(--faint)",
};


function LaneCard({ name, lane }) {
  const meta = LANE_META[name] || { label: name, icon: Circle };
  const Icon = meta.icon;
  const color = STATE_COLOR[lane.state] || "var(--faint)";
  return (
    <div data-testid={`investigation-lane-${name}`}
              style={{ border: "1px solid var(--border)", borderRadius: 4,
                              padding: 10, background: "var(--panel2)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <Icon size={12} style={{ color: "var(--cyan)" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 12,
                          color: "var(--text)" }}>{meta.label}</b>
        <span style={{ flex: 1 }} />
        <span style={{
          padding: "1px 6px", border: `1px solid ${color}`,
          color, borderRadius: 2, fontFamily: "var(--mono)",
          fontSize: 9.5, fontWeight: 700, textTransform: "uppercase",
          letterSpacing: ".3px",
        }}>{lane.state}</span>
      </div>

      {lane.state === "EMPTY" && (
        <div style={{ marginTop: 6, fontFamily: "var(--mono)",
                            fontSize: 10.5, color: "var(--faint)",
                            lineHeight: 1.5 }}>
          {lane.reason || "no data"}
        </div>
      )}

      {name === "timeline" && lane.state === "READY" && (
        <ul style={ulReset}>
          {lane.events.map((e, i) => (
            <li key={i} style={{ ...liRow, borderLeft:
                    `2px solid ${STATE_COLOR.READY}` }}>
              <span style={monoLabel}>{e.at?.slice(0,19) || "—"}</span>
              <span style={{ ...monoValue,
                                    color: "var(--cyan)" }}>{e.stage}</span>
              <span style={monoValue}>{e.summary}</span>
            </li>
          ))}
        </ul>
      )}

      {name === "evidence_graph" && lane.state === "READY" && (
        <div style={{ marginTop: 6 }}>
          <div style={monoLabel}>Nodes ({lane.nodes.length}) · Edges ({lane.edges.length})</div>
          <ul style={ulReset}>
            {lane.nodes.map((n, i) => (
              <li key={i} style={{ ...liRow, fontSize: 10.5 }}>
                <span style={{ ...monoLabel, color: "var(--cyan)" }}>
                  {n.kind}
                </span>
                <span style={{ ...monoValue, color: "var(--text)" }}>
                  {n.label || n.id}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {name === "attack_story" && lane.state === "READY" && (
        <div style={{ marginTop: 6 }}>
          {lane.chapters.map((c, i) => (
            <div key={i} style={{ marginBottom: 6 }}>
              <div style={{ ...monoLabel, color: "var(--cyan)" }}>
                {c.title}
              </div>
              <div style={{ fontFamily: "var(--sans)", fontSize: 11.5,
                                    color: "var(--text-dim)", lineHeight: 1.5 }}>
                {c.content}
              </div>
            </div>
          ))}
        </div>
      )}

      {name === "attck" && lane.state === "READY" && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap",
                            marginTop: 6 }}>
          {lane.techniques.map((t, i) => (
            <span key={i} style={{
              padding: "2px 8px", border: "1px solid var(--cyan)",
              color: "var(--cyan)", borderRadius: 2,
              fontFamily: "var(--mono)", fontSize: 10, fontWeight: 700,
            }}>{t.id}</span>
          ))}
        </div>
      )}
    </div>
  );
}


export default function InvestigationLanes({ incidentId, testid }) {
  const [data, setData] = useState(null);
  const [err,  setErr]  = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!incidentId) return;
    setLoading(true); setErr(null); setData(null);
    (async () => {
      try {
        const r = await api.get(
          `/admin/content-supply-chain/investigation/${incidentId}`);
        setData(r.data);
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.message || "unavailable");
      } finally {
        setLoading(false);
      }
    })();
  }, [incidentId]);

  if (!incidentId) {
    return (
      <div data-testid={testid || "investigation-lanes"}
                className="panel"
                style={{ padding: 12, fontFamily: "var(--mono)",
                                fontSize: 11, color: "var(--faint)" }}>
        No incident selected — replay the golden pipeline to materialise one.
      </div>
    );
  }

  if (loading) {
    return (
      <div data-testid={testid || "investigation-lanes"}
                className="panel"
                style={{ padding: 12, fontFamily: "var(--mono)",
                                fontSize: 11, color: "var(--faint)" }}>
        Projecting Investigation Fabric for {incidentId}…
      </div>
    );
  }

  if (err || !data) {
    return (
      <div data-testid={testid || "investigation-lanes"}
                className="panel"
                style={{ padding: 12, fontFamily: "var(--mono)",
                                fontSize: 11, color: "var(--amber)" }}>
        {err || "no data"}
      </div>
    );
  }

  return (
    <div data-testid={testid || "investigation-lanes"}
              className="panel"
              style={{ padding: "14px 16px", marginTop: 14,
                              borderLeft: "3px solid var(--cyan)" }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 10, marginBottom: 10,
      }}>
        <span style={{
          fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
          letterSpacing: ".6px", textTransform: "uppercase",
          color: "var(--cyan)",
        }}>
          Investigation Fabric · {data.incident_id}
        </span>
        <span style={{ flex: 1 }} />
        <span style={{ fontFamily: "var(--mono)", fontSize: 11,
                            color: "var(--text-dim)" }}>
          {data.lanes_ready} / {data.lanes_total} lanes with data
        </span>
      </div>

      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
        gap: 10,
      }}>
        {Object.entries(data.lanes).map(([name, lane]) => (
          <LaneCard key={name} name={name} lane={lane} />
        ))}
      </div>

      <div style={{ marginTop: 10, fontFamily: "var(--mono)",
                          fontSize: 9.5, color: "var(--faint)",
                          lineHeight: 1.5 }}>
        {data.honesty_note}
      </div>
    </div>
  );
}


const ulReset = { listStyle: "none", padding: 0, margin: "6px 0 0" };
const liRow = {
  padding: "4px 8px", marginBottom: 3,
  display: "grid", gridTemplateColumns: "auto auto 1fr",
  gap: 8, fontFamily: "var(--mono)", fontSize: 10.5,
};
const monoLabel = {
  fontSize: 9, color: "var(--faint)", textTransform: "uppercase",
  letterSpacing: ".3px", fontFamily: "var(--mono)", fontWeight: 700,
};
const monoValue = {
  color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 10.5,
};
