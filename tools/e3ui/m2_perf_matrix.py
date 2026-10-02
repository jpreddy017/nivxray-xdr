"""M2 performance matrix over ?perf=N client-side fixture rows (not evidence). Same render path as real data."""
import asyncio, json
from playwright.async_api import async_playwright

D = open("/tmp/shell_dir").read().strip()
B = f"https://edr-forge-complete.preview.emergentagent.com/{D}/index.html"
SCROLL = """async () => { const g = document.querySelector('[data-testid="v3-grid"]'); const ts = [];
  for (let i = 0; i < 30; i++) { const t = performance.now(); g.scrollLeft += 400; g.scrollTop += 60;
    await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))); ts.push(performance.now() - t); }
  ts.sort((a, b) => a - b); return { median: ts[15], p95: ts[28] }; }"""


async def main():
    out = []
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path="/usr/bin/chromium", args=["--no-sandbox"])
        pg = await b.new_page(viewport={"width": 2000, "height": 1300})
        for n in (100, 1000, 5000, 10000, 50000):
            await pg.goto("about:blank")
            t = await pg.evaluate("performance.timeOrigin")
            await pg.goto(f"{B}?device=perf&perf={n}")
            await pg.wait_for_selector('[data-testid^="v3-marker-"]', timeout=120000)
            ready = await pg.evaluate("performance.now()")
            perf = await pg.evaluate("window.__v3perf")
            dom = await pg.evaluate("document.querySelectorAll('[data-testid^=\"v3-marker-\"]').length")
            sc = await pg.evaluate(SCROLL)
            t0 = await pg.evaluate("performance.now()")
            await pg.locator('[data-testid^="v3-marker-"]').nth(2).click()
            await pg.wait_for_selector('[data-testid="v3-activity-details"]')
            click = await pg.evaluate("performance.now()") - t0
            heap = await pg.evaluate("performance.memory ? Math.round(performance.memory.usedJSHeapSize/1048576) : null")
            out.append({"events": n, "first_marker_ms": round(ready), "model_ms": perf.get("model"), "gen_ms": perf.get("gen"), "rows": perf.get("rows"),
                        "cols": perf.get("cols"), "dom_markers": dom, "scroll_frame_median_ms": round(sc["median"], 1), "scroll_frame_p95_ms": round(sc["p95"], 1),
                        "select_to_details_ms": round(click), "heap_mb": heap})
            print(out[-1], flush=True)
        await b.close()
    json.dump(out, open("/app/.e3ui-harness/shots_m2/perf_matrix.json", "w"), indent=1)

asyncio.run(main())
