/**
 * DT2-1 · pointer / wheel normalization.
 *
 *   RAW INPUT → DEVICE NORMALIZATION → INTENT → NORMALIZED DELTA
 *             → BOUNDED SENSITIVITY → VIEWPORT TRANSITION
 *
 * Reference classification:
 *   · Cisco publicly documents timeline navigation, a 30-day history, a
 *     bottom scrollbar and stepped zoom (click a bar to expand, click
 *     again for a 60-minute window)  [PUBLICLY OBSERVED]
 *   · Cisco publishes NOTHING about wheel sensitivity, deltaMode
 *     handling, trackpad gain or per-gesture clamping. Everything in
 *     this file is a NIVXFORGE DESIGN DECISION.
 *
 * Source classification only selects a GAIN. Every clamp below applies
 * regardless of classification, so a misclassified device is still
 * bounded — the classification can never cause runaway movement.
 */

export const DELTA_MODE = { PIXEL: 0, LINE: 1, PAGE: 2 };

/** A "line" and a "page" are not pixels. Firefox reports LINE, some
 *  remote-desktop stacks report PAGE. Both are converted explicitly
 *  instead of being treated as pixel deltas. */
export const LINE_TO_PX = 16;
export const PAGE_TO_PX = 400;

export const INTENT = {
  ZOOM: "ZOOM",
  TIME_PAN: "TIME_PAN",
  LANE_SCROLL: "LANE_SCROLL",
};

export const SOURCE = {
  MOUSE_WHEEL: "MOUSE_WHEEL_LIKE",
  TRACKPAD: "TRACKPAD_LIKE",
  UNKNOWN: "SOURCE_UNKNOWN",
};

/** Below this pixel magnitude a PIXEL-mode event looks like a
 *  high-resolution trackpad frame rather than a wheel notch. */
export const TRACKPAD_MAGNITUDE_CEILING = 40;

export function normalizeDelta(value, deltaMode) {
  const v = Number.isFinite(value) ? value : 0;
  const mode = Number.isInteger(deltaMode) ? deltaMode : DELTA_MODE.PIXEL;
  if (mode === DELTA_MODE.LINE) return v * LINE_TO_PX;
  if (mode === DELTA_MODE.PAGE) return v * PAGE_TO_PX;
  return v;
}

export function classifySource(ev) {
  const mode = Number.isInteger(ev?.deltaMode) ? ev.deltaMode
    : DELTA_MODE.PIXEL;
  if (mode === DELTA_MODE.LINE || mode === DELTA_MODE.PAGE) {
    return { source: SOURCE.MOUSE_WHEEL, basis: "DELTA_MODE_NOT_PIXEL" };
  }
  const dx = Math.abs(Number(ev?.deltaX) || 0);
  const dy = Math.abs(Number(ev?.deltaY) || 0);
  const mag = Math.max(dx, dy);
  if (mag === 0) return { source: SOURCE.UNKNOWN, basis: "ZERO_DELTA" };
  if (mag < TRACKPAD_MAGNITUDE_CEILING || !Number.isInteger(mag)) {
    return { source: SOURCE.TRACKPAD,
             basis: "PIXEL_MODE_LOW_OR_FRACTIONAL_MAGNITUDE_HEURISTIC" };
  }
  return { source: SOURCE.MOUSE_WHEEL,
           basis: "PIXEL_MODE_NOTCH_MAGNITUDE_HEURISTIC" };
}

export function classifyIntent(ev) {
  if (ev?.ctrlKey || ev?.metaKey) return INTENT.ZOOM;
  if (ev?.shiftKey) return INTENT.TIME_PAN;
  const dx = Math.abs(normalizeDelta(ev?.deltaX, ev?.deltaMode));
  const dy = Math.abs(normalizeDelta(ev?.deltaY, ev?.deltaMode));
  if (dx > dy * 1.2 && dx > 1) return INTENT.TIME_PAN;
  return INTENT.LANE_SCROLL;
}

export function normalizeWheel(ev) {
  const { source, basis } = classifySource(ev);
  const intent = classifyIntent(ev);
  const dxPx = normalizeDelta(ev?.deltaX, ev?.deltaMode);
  const dyPx = normalizeDelta(ev?.deltaY, ev?.deltaMode);
  /** shift + vertical wheel is the mouse affordance for a horizontal
   *  gesture, so the pan magnitude comes from deltaY in that case. */
  const panPx = (ev?.shiftKey && Math.abs(dxPx) < Math.abs(dyPx))
    ? dyPx : dxPx;
  return { source, sourceBasis: basis, intent, dxPx, dyPx, panPx,
           deltaMode: Number.isInteger(ev?.deltaMode) ? ev.deltaMode
             : DELTA_MODE.PIXEL };
}

export const clampAbs = (v, limit) => {
  const l = Math.abs(limit);
  if (!Number.isFinite(v)) return 0;
  return Math.sign(v) * Math.min(Math.abs(v), l);
};

/** Bounded sensitivity constants. SMALL input → SMALL movement;
 *  MEDIUM → proportional; VERY LARGE → BOUNDED. */
export const GOV = {
  PAN_GAIN: { [SOURCE.MOUSE_WHEEL]: 0.35, [SOURCE.TRACKPAD]: 0.85,
              [SOURCE.UNKNOWN]: 0.35 },
  /** One event may never move the window by more than 8 % of itself. */
  PAN_MAX_FRACTION_PER_EVENT: 0.08,
  /** A burst may never move it by more than 30 % per budget window. */
  PAN_MAX_FRACTION_PER_WINDOW: 0.3,
  LANE_GAIN: { [SOURCE.MOUSE_WHEEL]: 0.5, [SOURCE.TRACKPAD]: 1,
               [SOURCE.UNKNOWN]: 0.5 },
  LANE_MAX_ROWS_PER_EVENT: 6,
  LANE_MAX_ROWS_PER_WINDOW: 24,
  /** One discrete zoom level per notch-equivalent of scrolling. */
  ZOOM_STEP_PX: 120,
  ZOOM_MAX_STEPS_PER_EVENT: 1,
  ZOOM_MIN_INTERVAL_MS: 55,
  BUDGET_WINDOW_MS: 120,
};

const gainFor = (table, source) => table[source] ?? table[SOURCE.UNKNOWN];

/** Rolling-budget governor. This is what makes a 60 Hz trackpad burst
 *  bounded instead of catapulting the analyst across the timeline. */
export function createGovernor(now = () => Date.now()) {
  let panHist = [];
  let laneHist = [];
  let laneAcc = 0;
  let zoomAcc = 0;
  let lastZoomAt = -Infinity;

  const prune = (hist, t) =>
    hist.filter((e) => t - e.t < GOV.BUDGET_WINDOW_MS);
  const spent = (hist) => hist.reduce((s, e) => s + Math.abs(e.amt), 0);

  return {
    governPan(panPx, viewportPx, source) {
      const t = now();
      panHist = prune(panHist, t);
      const raw = (panPx / Math.max(1, viewportPx))
        * gainFor(GOV.PAN_GAIN, source);
      let f = clampAbs(raw, GOV.PAN_MAX_FRACTION_PER_EVENT);
      const left = Math.max(
        0, GOV.PAN_MAX_FRACTION_PER_WINDOW - spent(panHist));
      f = clampAbs(f, left);
      if (f !== 0) panHist.push({ t, amt: f });
      return f;
    },

    governLane(dyPx, rowPx, source) {
      const t = now();
      laneHist = prune(laneHist, t);
      laneAcc += (dyPx / Math.max(1, rowPx)) * gainFor(GOV.LANE_GAIN, source);
      const whole = Math.trunc(laneAcc);
      if (whole === 0) return 0;
      let step = clampAbs(whole, GOV.LANE_MAX_ROWS_PER_EVENT);
      const left = Math.max(
        0, GOV.LANE_MAX_ROWS_PER_WINDOW - spent(laneHist));
      step = clampAbs(step, Math.floor(left));
      /** A clamped burst drops its remainder instead of banking it —
       *  banked excess would replay as a delayed runaway. */
      laneAcc = (step === whole) ? laneAcc - whole : 0;
      if (step !== 0) laneHist.push({ t, amt: step });
      return step;
    },

    /** Returns discrete zoom steps. Positive = zoom OUT (wider span). */
    governZoom(dyPx) {
      zoomAcc += dyPx;
      if (Math.abs(zoomAcc) < GOV.ZOOM_STEP_PX) return 0;
      const t = now();
      if (t - lastZoomAt < GOV.ZOOM_MIN_INTERVAL_MS) {
        zoomAcc = clampAbs(zoomAcc, GOV.ZOOM_STEP_PX);
        return 0;
      }
      let steps = Math.trunc(zoomAcc / GOV.ZOOM_STEP_PX);
      zoomAcc = 0;
      steps = clampAbs(steps, GOV.ZOOM_MAX_STEPS_PER_EVENT);
      lastZoomAt = t;
      return steps;
    },

    reset() {
      panHist = []; laneHist = []; laneAcc = 0; zoomAcc = 0;
      lastZoomAt = -Infinity;
    },
  };
}
