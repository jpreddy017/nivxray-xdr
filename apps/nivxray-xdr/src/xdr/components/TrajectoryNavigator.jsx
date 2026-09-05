/**
 * TrajectoryNavigator · Cisco Secure Endpoint (AMP) navigator paradigm.
 *
 * ALL temporal navigation for the Device Trajectory happens here — not
 * on the canvas.  There is no wheel zoom, no pan shortcut and no
 * double-click reset anywhere in this surface, by design: in a dense
 * SOC portal those hijack viewport scroll and create accidental zoom
 * states.
 *
 * Structure (top → bottom):
 *   1. Filters + scoped search  (regex /foo/gim · CIDR · SHA-256 · name)
 *   2. Activity sparkline       (per-day event volume)
 *   3. 30-day ribbon            (day cells · red = compromise, blue = search hit)
 *   4. 24-hour ribbon           (selected day · dual-handle sliding window)
 *
 * Honest-state contract: day cells, dots and bars are counts of
 * persisted observations.  Days with no observations render empty —
 * never interpolated.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, Search } from "lucide-react";

import {
  severityTier, TIER_MALICIOUS, TIER_ATTRIBUTED, TIER_COLOR, TELEMETRY_CYAN, IOC_RED,
} from "@/xdr/lib/trajectoryModel";

/** Log-scaled dot radius — a day with 40 events must not read the same
 *  as a day with 2, and a linear scale flattens both. */
const dotR = (n, max) => {
  if (!n) return 0;
  return 3 + Math.round((Math.log1p(n) / Math.log1p(Math.max(1, max))) * 4);
};

const DAYS = 30;
const DAY_MS = 86400000;
const MONTHS = ["JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"];

const dayKey = (ms) => new Date(ms).toISOString().slice(0, 10);
const startOfDayUTC = (ms) => Date.UTC(
  new Date(ms).getUTCFullYear(), new Date(ms).getUTCMonth(), new Date(ms).getUTCDate());

/** Compile the navigator query into a predicate. Never throws. */
export function compileQuery(q) {
  const raw = (q || "").trim();
  if (!raw) return null;

  // /pattern/flags
  const rx = raw.match(/^\/(.*)\/([gimsuy]*)$/);
  if (rx) {
    try {
      const re = new RegExp(rx[1], rx[2].replace("g", ""));
      return { kind: "regex", test: (s) => re.test(s) };
    } catch { return { kind: "invalid", test: () => false }; }
  }

  // IPv4 CIDR
  const cidr = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (cidr) {
    const bits = Number(cidr[2]);
    if (bits >= 0 && bits <= 32) {
      const toInt = (ip) => ip.split(".").reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      const net = (toInt(cidr[1]) & mask) >>> 0;
      return {
        kind: "cidr",
        test: (s) => {
          const found = String(s).match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
          return found.some((ip) => ((toInt(ip) & mask) >>> 0) === net);
        },
      };
    }
  }

  // SHA-256
  if (/^[a-f0-9]{64}$/i.test(raw)) {
    const needle = raw.toLowerCase();
    return { kind: "sha256", test: (s) => s.toLowerCase().includes(needle) };
  }

  const needle = raw.toLowerCase();
  return { kind: "text", test: (s) => s.toLowerCase().includes(needle) };
}

/** Fields the navigator search is scoped to — all persisted. */
export function searchCorpus(e) {
  return [e.title, e.process, e.file, e.path, e.command_line, e.user,
          e.sha256, e.observation_kind, e.incident_id]
    .filter(Boolean).join(" ");
}

export default function TrajectoryNavigator({
  events, matchedIds, query, onQueryChange,
  selectedDay, onSelectDay, viewStart, viewEnd, onWindowChange,
  onSelectEvent, cursorTs, filterCount = 0, onOpenFilters,
}) {
  const [collapsed, setCollapsed] = useState(false);
  const [dropping, setDropping] = useState(false);
  const [dropError, setDropError] = useState(null);

  /** Drop a file → compute its SHA-256 locally and search for it.
   *  The file is never uploaded; only the digest is used. */
  const onDrop = useCallback(async (e) => {
    e.preventDefault();
    setDropping(false);
    setDropError(null);
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    if (!window.crypto?.subtle) {
      setDropError("⊘ SHA-256 unavailable — requires a secure context");
      return;
    }
    try {
      const buf = await file.arrayBuffer();
      const digest = await window.crypto.subtle.digest("SHA-256", buf);
      const hex = Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0")).join("");
      onQueryChange(hex);
    } catch {
      setDropError("⊘ Could not read the dropped file");
    }
  }, [onQueryChange]);

  const dayRef = useRef(null);
  const hourRef = useRef(null);
  const [hourW, setHourW] = useState(700);
  const [drag, setDrag] = useState(null);

  useEffect(() => {
    if (!hourRef.current) return;
    const ro = new ResizeObserver((en) => {
      const w = en[0]?.contentRect?.width;
      if (w) setHourW(Math.max(320, Math.floor(w)));
    });
    ro.observe(hourRef.current);
    return () => ro.disconnect();
  }, []);

  // ── 30-day model, anchored on the latest observed day ─────────────
  const days = useMemo(() => {
    const ts = events.map((e) => new Date(e.timestamp).getTime())
                      .filter(Number.isFinite);
    const anchor = ts.length ? startOfDayUTC(Math.max(...ts))
                              : startOfDayUTC(Date.now());
    const byDay = new Map();
    for (const e of events) {
      const t = new Date(e.timestamp).getTime();
      if (!Number.isFinite(t)) continue;
      const k = dayKey(t);
      if (!byDay.has(k)) byDay.set(k, { total: 0, compromise: 0, attributed: 0, hits: 0 });
      const rec = byDay.get(k);
      rec.total += 1;
      if (rec.minTs === undefined || t < rec.minTs) rec.minTs = t;
      if (rec.maxTs === undefined || t > rec.maxTs) rec.maxTs = t;
      if (!rec.firstEvent || t < new Date(rec.firstEvent.timestamp).getTime()) {
        rec.firstEvent = e;
      }
      const tier = severityTier(e);
      if (tier === TIER_MALICIOUS) {
        rec.compromise += 1;
        if (!rec.firstCompromise) rec.firstCompromise = e;
      } else if (tier === TIER_ATTRIBUTED) {
        rec.attributed += 1;
        if (!rec.firstCompromise) rec.firstCompromise = e;
      }
      if (matchedIds?.has(e.id)) rec.hits += 1;
    }
    const out = [];
    for (let i = DAYS - 1; i >= 0; i--) {
      const ms = anchor - i * DAY_MS;
      const k = dayKey(ms);
      const rec = byDay.get(k) || { total: 0, compromise: 0, attributed: 0, hits: 0 };
      out.push({ ms, key: k, ...rec, d: new Date(ms) });
    }
    return out;
  }, [events, matchedIds]);

  const maxTotal = Math.max(1, ...days.map((d) => d.total));
  const maxCompromise = Math.max(1, ...days.map((d) => d.compromise));
  const maxAttributed = Math.max(1, ...days.map((d) => d.attributed));
  const maxHits = Math.max(1, ...days.map((d) => d.hits));
  const dayStart = selectedDay ?? days[days.length - 1]?.ms ?? startOfDayUTC(Date.now());
  const dayEnd = dayStart + DAY_MS;

  // ── 24-hour ribbon geometry ───────────────────────────────────────
  const PAD = 6;
  const innerW = Math.max(1, hourW - PAD * 2);
  const xOfHour = useCallback(
    (t) => PAD + ((Math.min(Math.max(t, dayStart), dayEnd) - dayStart) / DAY_MS) * innerW,
    [dayStart, dayEnd, innerW]);
  const tOfX = useCallback(
    (x) => dayStart + ((Math.min(Math.max(x, PAD), PAD + innerW) - PAD) / innerW) * DAY_MS,
    [dayStart, innerW]);

  const xs = xOfHour(viewStart);
  const xe = xOfHour(viewEnd);

  const down = (mode) => (e) => {
    e.preventDefault();
    e.currentTarget.setPointerCapture?.(e.pointerId);
    setDrag({ mode, px: e.clientX, vs: viewStart, ve: viewEnd });
  };
  const move = (e) => {
    if (!drag) return;
    const rect = hourRef.current.getBoundingClientRect();
    const lx = e.clientX - rect.left;
    if (drag.mode === "left") {
      onWindowChange(Math.min(tOfX(lx), drag.ve - 60000), drag.ve);
    } else if (drag.mode === "right") {
      onWindowChange(drag.vs, Math.max(tOfX(lx), drag.vs + 60000));
    } else {
      const dMs = ((e.clientX - drag.px) / innerW) * DAY_MS;
      const dur = drag.ve - drag.vs;
      let s = Math.min(Math.max(drag.vs + dMs, dayStart), dayEnd - dur);
      onWindowChange(s, s + dur);
    }
  };
  const up = () => setDrag(null);

  const hourEvents = useMemo(() => events.filter((e) => {
    const t = new Date(e.timestamp).getTime();
    return t >= dayStart && t < dayEnd;
  }), [events, dayStart, dayEnd]);

  /** Bin the day's observations so overlapping dots become ONE dot
   *  whose radius scales with the count — AMP sizes dots relative to
   *  the number of events, and 27 observations inside one minute must
   *  not read as a single event. */
  const hourDots = useMemo(() => {
    const BINS = 240;                     // 6-minute resolution
    const bins = new Map();
    for (const e of hourEvents) {
      const t = new Date(e.timestamp).getTime();
      const i = Math.min(BINS - 1, Math.floor(((t - dayStart) / DAY_MS) * BINS));
      const hit = matchedIds?.has(e.id);
      const k = `${i}:${hit ? 1 : 0}`;
      if (!bins.has(k)) bins.set(k, { i, hit, n: 0, t, members: [], tier: 0 });
      const b = bins.get(k);
      b.n += 1;
      b.members.push(e);
      b.tier = Math.max(b.tier, severityTier(e));
      if (t < b.t) b.t = t;
    }
    const max = Math.max(1, ...Array.from(bins.values()).map((b) => b.n));
    return Array.from(bins.values()).map((b) => ({
      ...b,
      r: 2 + Math.round((b.n / max) * 4),
      primary: b.members.slice().sort(
        (x, y) => new Date(x.timestamp) - new Date(y.timestamp))[0],
    }));
  }, [hourEvents, dayStart, matchedIds]);


  const compiled = compileQuery(query);

  /** 30-day ribbon click. A compromise day focuses the compromise
   *  itself; any other day opens the full 24 h. */
  const onDayClick = useCallback((d) => {
    onSelectDay(d.ms);
    if (d.compromise > 0 && d.firstCompromise) {
      const t = new Date(d.firstCompromise.timestamp).getTime();
      onWindowChange(t - 30 * 60000, t + 30 * 60000);
      onSelectEvent?.(d.firstCompromise);
    } else {
      // The page owns full-day selection; calling onWindowChange here
      // would re-clamp it to the observed extent.
      onSelectDay(d.ms);
    }
  }, [onSelectDay, onWindowChange, onSelectEvent]);

  /** Double-click a day → tightest observed window on that day. */
  const onDayDouble = useCallback((d) => {
    if (d.minTs === undefined) return;
    onSelectDay(d.ms);
    const pad = Math.max(1000, (d.maxTs - d.minTs) * 0.05);
    onWindowChange(d.minTs - pad, d.maxTs + pad);
    if (d.firstEvent) onSelectEvent?.(d.firstEvent);
  }, [onSelectDay, onWindowChange, onSelectEvent]);

  /** 24-hour ribbon dot click → ±15 min bracket + select the cluster's
   *  primary (earliest) observation, which populates Activity Details. */
  const onDotClick = useCallback((dot) => {
    const t = dot.t;
    onWindowChange(t - 15 * 60000, t + 15 * 60000);
    if (dot.primary) onSelectEvent?.(dot.primary);
  }, [onWindowChange, onSelectEvent]);

  const onDotDouble = useCallback((dot) => {
    if (!dot.members?.length) return;
    const ts = dot.members.map((m) => new Date(m.timestamp).getTime());
    const lo = Math.min(...ts);
    const hi = Math.max(...ts);
    const pad = Math.max(1000, (hi - lo) * 0.05);
    onWindowChange(lo - pad, hi + pad);
    if (dot.primary) onSelectEvent?.(dot.primary);
  }, [onWindowChange, onSelectEvent]);

  return (
    <section className="panel" style={{ padding: 0 }}
              data-testid="xdr-trajectory-navigator">
      {/* 1 · Filters + scoped search */}
      <div style={{ display: "flex", alignItems: "center", gap: 8,
                      padding: "7px 9px",
                      borderBottom: "1px solid var(--border)" }}>
        <button className="btn" style={{ padding: "3px 7px", fontSize: 10 }}
                  onClick={() => setCollapsed((v) => !v)}
                  data-testid="xdr-navigator-collapse">
          <ChevronDown size={11}
                        style={{ transform: collapsed ? "rotate(-90deg)" : "none" }} />
        </button>
        <span className="section-title" style={{ margin: 0 }}>Navigator</span>
        <div style={{ position: "relative", flex: 1 }}
              onDragOver={(e) => { e.preventDefault(); setDropping(true); }}
              onDragLeave={() => setDropping(false)}
              onDrop={onDrop}
              data-testid="xdr-navigator-dropzone">
          <Search size={11} style={{ position: "absolute", left: 8, top: 7,
                                          color: "var(--faint)" }} />
          <input
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            placeholder={dropping
              ? "Drop a file to compute its SHA-256 …"
              : "Search Device Trajectory — /regex/gim · 10.0.0.0/24 · SHA-256 · file or process name · drop a file"}
            className="mono"
            style={{ width: "100%", padding: "4px 8px 4px 24px", fontSize: 10.5,
                      background: dropping ? "rgba(60,232,184,0.10)" : "var(--panel2)",
                      color: "var(--text)",
                      border: `1px solid ${dropping ? "var(--mint)" : "var(--border)"}`,
                      borderRadius: 4 }}
            data-testid="xdr-navigator-search"
          />
        </div>
        {dropError && (
          <span className="mono" style={{ fontSize: 10, color: "#ff9494" }}
                  data-testid="xdr-navigator-drop-error">{dropError}</span>
        )}
        {query && (
          <span className="mono" style={{ fontSize: 10,
                    color: compiled?.kind === "invalid" ? "#ff9494" : "var(--cyan)" }}
                  data-testid="xdr-navigator-search-status">
            {compiled?.kind === "invalid"
              ? "invalid regex"
              : `${matchedIds?.size || 0} match${(matchedIds?.size || 0) === 1 ? "" : "es"} · ${compiled?.kind}`}
          </span>
        )}
        <button className="btn"
                style={{ padding: "3px 9px", fontSize: 10,
                         borderColor: filterCount ? "var(--cyan)" : undefined,
                         color: filterCount ? "var(--cyan)" : undefined }}
                onClick={onOpenFilters}
                title="Cisco Secure Endpoint filter matrix"
                data-testid="xdr-navigator-filters">
          Filters {filterCount ? `(${filterCount})` : ""} <ChevronDown size={10} />
        </button>
      </div>

      {!collapsed && (
        <div style={{ padding: "8px 9px 10px" }}>
          {/* 2 · Activity sparkline */}
          <svg width="100%" height={22} style={{ display: "block" }}
                data-testid="xdr-navigator-sparkline" preserveAspectRatio="none"
                viewBox={`0 0 ${DAYS} 22`}>
            <polyline
              points={days.map((d, i) => `${i + 0.5},${21 - (d.total / maxTotal) * 19}`).join(" ")}
              fill="none" stroke={TELEMETRY_CYAN} strokeWidth={0.9}
              vectorEffect="non-scaling-stroke" />
          </svg>

          {/* 3 · 30-day ribbon */}
          <div ref={dayRef}
                style={{ display: "grid",
                          gridTemplateColumns: `repeat(${DAYS}, 1fr)`, gap: 1 }}
                data-testid="xdr-navigator-day-ribbon">
            {days.map((d) => {
              const active = d.ms === dayStart;
              const has = d.total > 0;
              return (
                <button key={d.key}
                          onClick={() => onDayClick(d)}
                          onDoubleClick={() => onDayDouble(d)}
                          title={`${d.key} · ${d.total} observation${d.total === 1 ? "" : "s"}`
                                  + (has ? " · click to focus, double-click to fit" : "")}
                          style={{
                            height: 30, padding: 0, cursor: has ? "pointer" : "default",
                            background: active ? "#152131" : has ? "#0F151C" : "#0A0E13",
                            border: `1px solid ${active ? "#3A6B9E" : "#212B36"}`,
                            display: "flex", flexDirection: "column",
                            alignItems: "center", justifyContent: "center", gap: 2,
                          }}
                          data-testid={`xdr-navigator-day-${d.key}`}>
                  {d.compromise > 0 && (
                    <span title={`${d.compromise} compromise event${d.compromise === 1 ? "" : "s"}`}
                           style={{ width: dotR(d.compromise, maxCompromise) * 2,
                                    height: dotR(d.compromise, maxCompromise) * 2,
                                    borderRadius: "50%", background: IOC_RED }} />
                  )}
                  {d.attributed > 0 && (
                    <span title={`${d.attributed} technique-attributed observation${d.attributed === 1 ? "" : "s"}`}
                           style={{ width: dotR(d.attributed, maxAttributed) * 2,
                                    height: dotR(d.attributed, maxAttributed) * 2,
                                    borderRadius: "50%",
                                    background: TIER_COLOR[TIER_ATTRIBUTED] }}
                           data-testid={`xdr-navigator-attributed-${d.key}`} />
                  )}
                  {d.hits > 0 && (
                    <span title={`${d.hits} search match${d.hits === 1 ? "" : "es"}`}
                           style={{ width: dotR(d.hits, maxHits) * 2,
                                    height: dotR(d.hits, maxHits) * 2,
                                    borderRadius: "50%", background: TELEMETRY_CYAN }}
                           data-testid={`xdr-navigator-hit-${d.key}`} />
                  )}
                </button>
              );
            })}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: `repeat(${DAYS}, 1fr)`,
                          gap: 1, marginTop: 2 }}>
            {days.map((d) => (
              <div key={d.key} className="mono"
                    style={{ fontSize: 8, textAlign: "center",
                              color: d.ms === dayStart ? "#cfd6e2" : "var(--faint)" }}>
                {d.d.getUTCDate()}
              </div>
            ))}
          </div>
          <div className="mono" style={{ fontSize: 8.5, color: "var(--faint)",
                                              marginTop: 1 }}>
            {MONTHS[days[0].d.getUTCMonth()]}
            {days[0].d.getUTCMonth() !== days[DAYS - 1].d.getUTCMonth() &&
              ` → ${MONTHS[days[DAYS - 1].d.getUTCMonth()]}`}
          </div>

          {/* 4 · 24-hour ribbon for the selected day */}
          <div style={{ marginTop: 10 }}>
            <div ref={hourRef} style={{ width: "100%" }}>
              <svg width={hourW} height={34}
                    style={{ display: "block", touchAction: "none" }}
                    onPointerMove={move} onPointerUp={up} onPointerLeave={up}
                    data-testid="xdr-navigator-hour-ribbon">
                {/* 24 bordered hour cells, matching the 30-day grid. */}
                {Array.from({ length: 24 }, (_, h) => (
                  <rect key={h} x={PAD + (h / 24) * innerW} y={6}
                        width={innerW / 24} height={26}
                        fill="#0F151C" stroke="#212B36" strokeWidth={0.8} />
                ))}

                {/* Observation dots, stacked red-over-blue inside the cells. */}
                {hourDots.map((d) => (
                  <circle key={`${d.i}-${d.hit}`}
                          cx={PAD + ((d.i + 0.5) / 240) * innerW}
                          cy={d.hit ? 24 : 14} r={d.r}
                          fill={d.hit ? TELEMETRY_CYAN : TIER_COLOR[d.tier]}
                          pointerEvents="none" />
                ))}

                {/* The UNSELECTED span is masked with diagonal hatching;
                      the active window is simply left clear.  No outline,
                      no calipers. */}
                <defs>
                  <pattern id="nx-nav-hatch" width="6" height="6"
                            patternUnits="userSpaceOnUse"
                            patternTransform="rotate(45)">
                    <rect width="6" height="6" fill="rgba(10,13,19,0.82)" />
                    <line x1="0" y1="0" x2="0" y2="6"
                          stroke="rgba(120,132,150,0.30)" strokeWidth="1.4" />
                  </pattern>
                </defs>
                <rect x={PAD} y={6} width={Math.max(0, xs - PAD)} height={26}
                      fill="url(#nx-nav-hatch)" pointerEvents="none" />
                <rect x={xe} y={6} width={Math.max(0, PAD + innerW - xe)} height={26}
                      fill="url(#nx-nav-hatch)" pointerEvents="none" />

                {/* Invisible drag targets: band shifts, edges resize. */}
                <rect x={xs} y={6} width={Math.max(1, xe - xs)} height={26}
                      fill="transparent"
                      style={{ cursor: "grab" }} onPointerDown={down("band")}
                      data-testid="xdr-navigator-band" />
                {[["left", xs], ["right", xe]].map(([side, x]) => (
                  <rect key={side} x={x - 5} y={0} width={10} height={34}
                        fill="transparent" style={{ cursor: "ew-resize" }}
                        onPointerDown={down(side)}
                        data-testid={`xdr-navigator-handle-${side}`} />
                ))}

                {/* Active-timestamp cursor line. */}
                {cursorTs != null && cursorTs >= dayStart && cursorTs < dayEnd && (
                  <line x1={xOfHour(cursorTs)} y1={2} x2={xOfHour(cursorTs)} y2={32}
                        stroke="#cfd6e2" strokeWidth={1.2} pointerEvents="none"
                        data-testid="xdr-navigator-cursor" />
                )}

                {/* Clickable dot targets on top. */}
                {hourDots.map((d) => (
                  <circle key={`hit-${d.i}-${d.hit}`}
                          cx={PAD + ((d.i + 0.5) / 240) * innerW}
                          cy={d.hit ? 24 : 14} r={Math.max(5, d.r + 2)}
                          fill="transparent"
                          style={{ cursor: "pointer", pointerEvents: "auto" }}
                          onClick={() => onDotClick(d)}
                          onDoubleClick={(ev) => { ev.stopPropagation(); onDotDouble(d); }}
                          data-testid={`xdr-navigator-hour-dot-${d.i}`}>
                    <title>
                      {d.n} observation{d.n === 1 ? "" : "s"} · click to focus ±15 min,
                      double-click to fit
                    </title>
                  </circle>
                ))}
              </svg>
              {/* Hour labels BELOW the ribbon, with the date under the left
                    edge — the AMP layout. */}
              <div style={{ display: "grid",
                              gridTemplateColumns: `repeat(24, 1fr)`,
                              marginTop: 1, padding: `0 ${PAD}px` }}>
                {Array.from({ length: 24 }, (_, h) => (
                  <div key={h} className="mono"
                        style={{ fontSize: 8, color: "var(--faint)",
                                  textAlign: "left" }}>
                    {h === 0 ? "0:00" : h}
                  </div>
                ))}
              </div>
              <div className="mono" style={{ fontSize: 8.5, color: "var(--faint)",
                                                  marginTop: 1 }}>
                {MONTHS[new Date(dayStart).getUTCMonth()]}{" "}
                {new Date(dayStart).getUTCDate()}
              </div>
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 5 }}>
              <button className="btn" style={{ padding: "2px 7px", fontSize: 9.5 }}
                        onClick={() => onWindowChange(dayStart, dayEnd)}
                        title="Snap the window to this day's observed activity"
                        data-testid="xdr-navigator-full-day">
                Fit to observations
              </button>
              <span className="mono" style={{ fontSize: 9,
                                                  color: "var(--faint)",
                                                  alignSelf: "center" }}>
                {hourEvents.length} observation{hourEvents.length === 1 ? "" : "s"} on this day
              </span>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
