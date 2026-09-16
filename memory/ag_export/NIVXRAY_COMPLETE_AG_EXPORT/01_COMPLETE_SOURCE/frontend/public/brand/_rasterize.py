#!/usr/bin/env python3
"""Rasterize NivXRay + NivXForge brand SVGs to PNG (transparent + dark) and JPG.

Outputs (in /app/frontend/public/brand/):
  NivXRay:
    nivxray-mark-{256,512,1024}.png       (transparent)
    nivxray-mark-dark-512.png             (#101112 bg)
    nivxray-mark-1024.jpg                 (#101112 bg)
    nivxray-logo-{700,1400,2800}.png      (transparent, 3.5:1)
    nivxray-logo-dark-1400.png            (#101112 bg)
    nivxray-logo-2800.jpg                 (#101112 bg)

  NivXForge:
    nivxforge-mark-{256,512,1024}.png     (transparent)
    nivxforge-mark-dark-512.png           (#101112 bg)
    nivxforge-mark-1024.jpg               (#101112 bg)
    nivxforge-logo-{700,1400,2800}.png    (transparent, 3.5:1)
    nivxforge-logo-dark-1400.png          (#101112 bg)
    nivxforge-logo-2800.jpg               (#101112 bg)

  Favicons (NivXRay only, primary product):
    favicon-32.png, favicon-192.png, apple-touch-icon-180.png
"""
from __future__ import annotations
import io
from pathlib import Path

import cairosvg
from PIL import Image

BRAND = Path("/app/frontend/public/brand")
BG = (16, 17, 18, 255)  # #101112


def render_transparent(svg: Path, out: Path, w: int, h: int | None = None):
    kw = {"output_width": w}
    if h is not None:
        kw["output_height"] = h
    out.write_bytes(cairosvg.svg2png(url=str(svg), **kw))
    print(f"  {out.name}  ({w}px)")


def render_on_bg(svg: Path, out: Path, w: int, h: int | None = None,
                 bg=BG, jpg: bool = False):
    kw = {"output_width": w}
    if h is not None:
        kw["output_height"] = h
    fg = Image.open(io.BytesIO(cairosvg.svg2png(url=str(svg), **kw))).convert("RGBA")
    canvas = Image.new("RGBA", fg.size, bg)
    canvas.alpha_composite(fg)
    if jpg:
        canvas.convert("RGB").save(out, "JPEG", quality=92, optimize=True)
    else:
        canvas.save(out, "PNG", optimize=True)
    print(f"  {out.name}  ({w}px, {'JPG' if jpg else 'PNG on dark'})")


def render_family(prefix: str, mark_svg: Path, logo_svg: Path,
                  logo_ratio: float = 3.5):
    print(f"→ {prefix} · mark")
    for w in (256, 512, 1024):
        render_transparent(mark_svg, BRAND / f"{prefix}-mark-{w}.png", w, w)
    render_on_bg(mark_svg, BRAND / f"{prefix}-mark-dark-512.png", 512, 512)
    render_on_bg(mark_svg, BRAND / f"{prefix}-mark-1024.jpg", 1024, 1024, jpg=True)

    print(f"→ {prefix} · wordmark (ratio {logo_ratio}:1)")
    for w in (700, 1400, 2800):
        render_transparent(logo_svg, BRAND / f"{prefix}-logo-{w}.png",
                           w, int(w / logo_ratio))
    render_on_bg(logo_svg, BRAND / f"{prefix}-logo-dark-1400.png",
                 1400, int(1400 / logo_ratio))
    render_on_bg(logo_svg, BRAND / f"{prefix}-logo-2800.jpg",
                 2800, int(2800 / logo_ratio), jpg=True)


def main():
    # NivXRay — primary product
    render_family("nivxray",
                  BRAND / "nivxray-mark.svg",
                  BRAND / "nivxray-logo.svg",
                  logo_ratio=3.5)

    # NivXForge — parent brand
    render_family("nivxforge",
                  BRAND / "nivxforge-mark.svg",
                  BRAND / "nivxforge-logo.svg",
                  logo_ratio=3.5)

    print("→ Favicons + Apple touch icon (NivXRay)")
    render_transparent(BRAND / "nivxray-mark.svg", BRAND / "favicon-32.png", 32, 32)
    render_transparent(BRAND / "nivxray-mark.svg", BRAND / "favicon-192.png", 192, 192)
    render_on_bg(BRAND / "nivxray-mark.svg", BRAND / "apple-touch-icon-180.png", 180, 180)

    print("Done.")


if __name__ == "__main__":
    main()
