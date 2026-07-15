"""CLI: capture workflow-step screenshots for the NivXRay Docs Generator.

Usage
-----
Run from `/app/backend/`:

    python scripts/capture_docs_screenshots.py \
        --base-url $REACT_APP_BACKEND_URL \
        --email admin@nivxray.com \
        --password 'NivXRay#2026!' \
        --workflow encoded_powershell

Or capture every workflow with a `capture:` block:

    python scripts/capture_docs_screenshots.py --all

YAML integration
----------------
A workflow can declare optional per-step capture instructions:

    capture:
      login: true                    # log in via /login before Step 1
      steps:
        - url: /workspace            # relative to base_url, defaults to /
          wait_for: '[data-testid="input-textarea"]'
          selector: '#candidate-explorer'   # optional — clip to element
          click_before: '[data-testid="show-explorer"]'   # optional pre-action
          type_into:                        # optional pre-action
            selector: '[data-testid="input-textarea"]'
            text: 'AAAAAA=='
          full_page: false           # default: false
        - url: /workspace
          selector: '.candidate-explorer-card'
        ...

Screenshots land in:
    /app/backend/docs/screenshots/<workflow_id>/step_<n>.png

The Docs page and the PDF generator will surface these automatically
if they exist. Missing screenshots are ignored — safe no-op.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from playwright.async_api import async_playwright

# Allow both `python scripts/capture_docs_screenshots.py` and `python -m` styles.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

WORKFLOWS_DIR = ROOT / "docs" / "workflows"
FEATURES_DIR = ROOT / "docs" / "features"
OUT_DIR = ROOT / "docs" / "screenshots"


def _load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or None
    except Exception as e:
        print(f"[warn] failed to load {path.name}: {e}", file=sys.stderr)
        return None


def _resolve_url(base: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")


async def _login(page, base_url: str, email: str, password: str) -> None:
    await page.goto(_resolve_url(base_url, "/login"), wait_until="domcontentloaded")
    await page.wait_for_timeout(800)
    await page.fill('input[type="email"]', email)
    await page.fill('input[type="password"]', password)
    await page.click('button[type="submit"]')
    await page.wait_for_timeout(2000)


async def _run_step(page, base_url: str, step_cfg: Dict[str, Any],
                     out_path: Path) -> bool:
    url = _resolve_url(base_url, step_cfg.get("url", "/"))
    await page.goto(url, wait_until="domcontentloaded")
    if step_cfg.get("wait_for"):
        try:
            await page.wait_for_selector(step_cfg["wait_for"], timeout=8000)
        except Exception:
            pass
    await page.wait_for_timeout(step_cfg.get("delay_ms", 700))

    # Fill the input FIRST so any decode/action button becomes enabled,
    # THEN click. Screenshot delay is honoured by the outer `delay_ms`
    # for post-click renders below.
    ti = step_cfg.get("type_into")
    if ti and ti.get("selector") and ti.get("text") is not None:
        try:
            await page.fill(ti["selector"], ti["text"])
            await page.wait_for_timeout(400)
        except Exception as e:
            print(f"[warn] type_into failed: {e}", file=sys.stderr)

    if step_cfg.get("click_before"):
        try:
            await page.click(step_cfg["click_before"], force=True, timeout=6000)
            # Give the button-driven action time to render before we shoot.
            await page.wait_for_timeout(step_cfg.get("post_click_ms", 1200))
        except Exception as e:
            print(f"[warn] click_before failed: {e}", file=sys.stderr)

    selector = step_cfg.get("selector")
    kwargs: Dict[str, Any] = {"path": str(out_path), "type": "png"}
    if not selector:
        kwargs["full_page"] = bool(step_cfg.get("full_page", False))
        await page.screenshot(**kwargs)
    else:
        try:
            el = await page.query_selector(selector)
            if el:
                await el.screenshot(path=str(out_path), type="png")
            else:
                kwargs["full_page"] = bool(step_cfg.get("full_page", False))
                await page.screenshot(**kwargs)
        except Exception:
            await page.screenshot(**kwargs)

    return out_path.exists()


async def capture_workflow(base_url: str, email: str, password: str,
                            workflow_id: str) -> Dict[str, Any]:
    return await _capture_doc(base_url, email, password,
                               workflow_id, "workflow")


async def capture_feature(base_url: str, email: str, password: str,
                           feature_id: str) -> Dict[str, Any]:
    return await _capture_doc(base_url, email, password,
                               feature_id, "feature")


async def _capture_doc(base_url: str, email: str, password: str,
                        doc_id: str, kind: str) -> Dict[str, Any]:
    base_dir = FEATURES_DIR if kind == "feature" else WORKFLOWS_DIR
    yaml_path = base_dir / f"{doc_id}.yaml"
    if not yaml_path.exists():
        return {"id": doc_id, "kind": kind, "error": f"{kind} yaml not found"}

    data = _load_yaml(yaml_path) or {}
    capture_cfg = data.get("capture") or {}
    step_cfgs: List[Dict[str, Any]] = capture_cfg.get("steps") or []
    if not step_cfgs:
        return {"id": doc_id, "kind": kind, "skipped": True,
                "reason": "no `capture.steps` block in YAML"}

    out_dir = OUT_DIR / doc_id
    out_dir.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        ctx = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await ctx.new_page()

        if capture_cfg.get("login"):
            await _login(page, base_url, email, password)

        captured: List[str] = []
        for i, step in enumerate(step_cfgs, 1):
            out = out_dir / f"step_{i}.png"
            ok = await _run_step(page, base_url, step, out)
            if ok:
                captured.append(out.name)

        await browser.close()

    return {"id": doc_id, "kind": kind,
            "captured": captured, "out_dir": str(out_dir)}


async def main_async(args) -> int:
    base = args.base_url or os.environ.get("REACT_APP_BACKEND_URL", "")
    if not base:
        try:
            with open("/app/frontend/.env") as f:
                for line in f:
                    if line.startswith("REACT_APP_BACKEND_URL="):
                        base = line.split("=", 1)[1].strip()
                        break
        except Exception:
            pass
    if not base:
        print("error: --base-url required (or REACT_APP_BACKEND_URL env)",
              file=sys.stderr)
        return 2

    email = args.email or os.environ.get("NIVXRAY_ADMIN_EMAIL", "admin@nivxray.com")
    password = args.password or os.environ.get("NIVXRAY_ADMIN_PASSWORD", "")
    if not password:
        print("error: --password required (or NIVXRAY_ADMIN_PASSWORD env)",
              file=sys.stderr)
        return 2

    workflow_targets: List[str] = []
    feature_targets: List[str] = []
    if args.all:
        workflow_targets = [p.stem for p in sorted(WORKFLOWS_DIR.glob("*.yaml"))]
        feature_targets = [p.stem for p in sorted(FEATURES_DIR.glob("*.yaml"))]
    if args.workflow:
        workflow_targets.append(args.workflow)
    if args.feature:
        feature_targets.append(args.feature)
    if not workflow_targets and not feature_targets:
        print("error: pass --workflow ID, --feature ID, or --all", file=sys.stderr)
        return 2

    for wf in workflow_targets:
        result = await capture_workflow(base, email, password, wf)
        print(result)
    for ft in feature_targets:
        result = await capture_feature(base, email, password, ft)
        print(result)
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Capture NivXRay docs screenshots")
    p.add_argument("--base-url", help="Frontend base URL")
    p.add_argument("--email", help="Admin email")
    p.add_argument("--password", help="Admin password")
    p.add_argument("--workflow", help="Workflow id to capture")
    p.add_argument("--feature", help="Feature id to capture")
    p.add_argument("--all", action="store_true",
                   help="Capture every feature & workflow with a `capture:` block")
    return p


if __name__ == "__main__":
    args = build_arg_parser().parse_args()
    sys.exit(asyncio.run(main_async(args)))
