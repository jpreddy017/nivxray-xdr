/**
 * canvas_engine/core/viewport.js
 *
 * Framework-agnostic viewport math for the Investigation Canvas Engine.
 * ALL functions are pure — no React, no Konva, no DOM. This is the layer
 * that gets unit-tested. Every gesture (pan, zoom, fit) is a pure
 * transformation on the `{offset, scale, size}` triple.
 *
 * Per CANVAS_ENGINE_ARCHITECTURE.md §7.
 */

/** clamp a number to [lo, hi]. */
export const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

/**
 * Clamp a proposed offset so the content rectangle can never fully leave
 * the viewport. Leaves a 20 px "peek" so users always see anchor content.
 */
export function clampOffset(offset, scale, size, contentH, contentW) {
  const contentPxW = contentW * scale;
  const contentPxH = contentH * scale;
  const minX = Math.min(0, size.w - contentPxW - 20);
  const minY = Math.min(0, size.h - contentPxH - 20);
  return {
    x: clamp(offset.x, minX, 20),
    y: clamp(offset.y, minY, 0),
  };
}

/**
 * Anchor-preserving zoom. The point under `pointer` (in screen px) MUST
 * stay under `pointer` after the scale change.
 *
 * `factor > 1` = zoom in. Returns new `{offset, scale}`.
 */
export function zoomAround(vp, factor, pointer) {
  const oldScale = vp.scale;
  const newScale = clamp(oldScale * factor, 0.15, 6);
  if (newScale === oldScale) return vp;

  // World point currently under the pointer
  const worldX = (pointer.x - vp.offset.x) / oldScale;
  const worldY = (pointer.y - vp.offset.y) / oldScale;

  return {
    ...vp,
    scale: newScale,
    offset: {
      x: pointer.x - worldX * newScale,
      y: pointer.y - worldY * newScale,
    },
  };
}

/**
 * Fit the content rectangle into the viewport with a `pad` px inset.
 * Returns `{offset, scale}` such that the content fills the viewport
 * without cropping.
 */
export function fit(contentRect, size, pad = 20) {
  const sX = (size.w - pad * 2) / Math.max(contentRect.w, 1);
  const sY = (size.h - pad * 2) / Math.max(contentRect.h, 1);
  const scale = clamp(Math.min(sX, sY), 0.15, 1);
  return {
    scale,
    offset: {
      x: pad + (size.w - pad * 2 - contentRect.w * scale) / 2,
      y: pad + (size.h - pad * 2 - contentRect.h * scale) / 2,
    },
  };
}

/**
 * Is a world-space point inside the current viewport (± `margin`)?
 * Used by virtualization to decide whether to paint an item.
 */
export function isInViewport(worldX, worldY, vp, marginPx = 200) {
  const vx = worldX * vp.scale + vp.offset.x;
  const vy = worldY * vp.scale + vp.offset.y;
  return (
    vx > -marginPx && vx < vp.size.w + marginPx &&
    vy > -marginPx && vy < vp.size.h + marginPx
  );
}

/**
 * Given the current viewport, return the world-space rectangle currently
 * visible (± margin) so consumers can filter their entity / event lists
 * before rendering.
 */
export function visibleWorldRect(vp, marginPx = 200) {
  return {
    x0: (-vp.offset.x - marginPx) / vp.scale,
    x1: (-vp.offset.x + vp.size.w + marginPx) / vp.scale,
    y0: (-vp.offset.y - marginPx) / vp.scale,
    y1: (-vp.offset.y + vp.size.h + marginPx) / vp.scale,
  };
}
