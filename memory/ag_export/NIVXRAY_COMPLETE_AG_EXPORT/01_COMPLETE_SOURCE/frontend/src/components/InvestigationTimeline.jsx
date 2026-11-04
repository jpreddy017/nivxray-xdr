import { useState, useEffect } from "react";
import { RefreshCw, Clock, CheckCircle2, AlertTriangle, XCircle, Info } from "lucide-react";
import api from "@/lib/api";

/**
 * InvestigationTimeline — Feb-2026 #5.
 *
 * Vertical chronological event log. Renders in the Workspace sidebar and
 * shows every meaningful action per investigation:
 *   decode | correction | corpus-promote | benchmark | gate-block |
 *   taxii-push | threat-intel | sample-library-promote | error | note
 *
 * Props:
 *   investigationId: string  (default "adhoc")
 *   refreshKey: any          bump to force reload (e.g., after a correction)
 *   testidPrefix: string
 */
const KIND_ICON = {
  decode: Info,
  correction: AlertTriangle,
  "corpus-promote": CheckCircle2,
  benchmark: CheckCircle2,
  "gate-block": XCircle,
  "taxii-push": Info,
  "threat-intel": Info,
  "sample-library-promote": CheckCircle2,
  error: XCircle,
  note: Info,
};

const SEV_COLOR = {
  info: "#94a3b8",
  success: "#7ee3c9",
  warn: "#f59e0b",
  fail: "#f87171",
};

function EventRow({ event, isLast }) {
  const Icon = KIND_ICON[event.kind] || Info;
  const color = SEV_COLOR[event.severity] || SEV_COLOR.info;
  return (
    <div
      style={{ display: "flex", gap: 10, position: "relative", paddingBottom: isLast ? 0 : 12 }}
      data-testid={`timeline-event-${event.kind}`}
    >
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
        <div
          style={{
            width: 24, height: 24, borderRadius: "50%",
            background: "rgba(15,23,42,0.8)",
            border: `2px solid ${color}`,
            display: "flex", alignItems: "center", justifyContent: "center",
            zIndex: 2,
          }}
        >
          <Icon size={12} color={color} />
        </div>
        {!isLast && (
          <div
            style={{
              width: 2, flex: 1,
              background: "rgba(148,163,184,0.20)",
              minHeight: 12,
            }}
          />
        )}
      </div>
      <div style={{ flex: 1, minWidth: 0, paddingBottom: 4 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <span
            style={{
              fontFamily: "monospace",
              fontSize: 9,
              color: "#94a3b8",
              letterSpacing: 0.5,
              textTransform: "uppercase",
            }}
          >
            {event.kind}
          </span>
          <span style={{ fontSize: 10, color: "#64748b" }}>
            {event.created_at?.slice(11, 19)}
          </span>
        </div>
        <div style={{ fontSize: 12, color: "#c9d1d9", fontWeight: 500, marginTop: 2 }}>
          {event.title}
        </div>
        {event.summary && (
          <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 2, wordBreak: "break-word" }}>
            {event.summary}
          </div>
        )}
        {event.actor && (
          <div style={{ fontSize: 10, color: "#64748b", marginTop: 2 }}>
            by {event.actor}
          </div>
        )}
      </div>
    </div>
  );
}

export default function InvestigationTimeline({
  investigationId,
  input,
  refreshKey,
  testidPrefix = "investigation-timeline",
}) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showRecent, setShowRecent] = useState(false);
  const [derivedIid, setDerivedIid] = useState(null);

  // If caller passed an `input` payload, derive the deterministic
  // investigation_id (= sha256(input)[:16]) using SubtleCrypto so we can
  // scope the timeline without another round-trip.
  useEffect(() => {
    let cancelled = false;
    if (!input) { setDerivedIid(null); return; }
    (async () => {
      try {
        const buf = new TextEncoder().encode(input);
        const digest = await crypto.subtle.digest("SHA-256", buf);
        const hex = Array.from(new Uint8Array(digest))
          .map((b) => b.toString(16).padStart(2, "0")).join("");
        if (!cancelled) setDerivedIid(hex.slice(0, 16));
      } catch {
        if (!cancelled) setDerivedIid(null);
      }
    })();
    return () => { cancelled = true; };
  }, [input]);

  const effectiveIid = investigationId || derivedIid || "adhoc";

  const load = async () => {
    setLoading(true);
    try {
      const url = showRecent
        ? "/timeline/recent?limit=30"
        : `/timeline/events?investigation_id=${encodeURIComponent(effectiveIid)}&limit=50`;
      const r = await api.get(url);
      setEvents(r.data.events || []);
    } catch (e) {
      setEvents([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  // `load` is stable within this component's closure; re-running on scope /
  // refreshKey / effectiveIid change is the exact intended semantic.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effectiveIid, refreshKey, showRecent]);

  return (
    <div className="nvx-card" data-testid={testidPrefix} style={{ marginBottom: 12 }}>
      <div className="nvx-card-head">
        <div className="nvx-card-title">
          <Clock size={12} style={{ marginRight: 6 }} />
          INVESTIGATION TIMELINE
        </div>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
          <button
            className="nvx-btn sm ghost"
            onClick={() => setShowRecent((v) => !v)}
            data-testid={`${testidPrefix}-toggle-scope`}
            style={{ fontSize: 10 }}
          >
            {showRecent ? "This investigation" : "All recent"}
          </button>
          <button
            className="nvx-btn sm ghost"
            onClick={load}
            disabled={loading}
            data-testid={`${testidPrefix}-refresh`}
            style={{ fontSize: 10 }}
          >
            <RefreshCw size={11} />
          </button>
        </div>
      </div>
      <div className="nvx-card-body">
        {events.length === 0 ? (
          <div style={{ fontSize: 11, color: "#94a3b8", padding: "6px 4px" }}>
            {loading ? "Loading…" : "No events recorded yet."}
          </div>
        ) : (
          <div>
            {events.map((e, i) => (
              <EventRow key={e._id || i} event={e} isLast={i === events.length - 1} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
