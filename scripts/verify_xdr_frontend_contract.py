#!/usr/bin/env python3
"""XDR production frontend verification — the owner's Full Check.

Read-only. No credential, no key minted, no write of any kind.

    python3 scripts/verify_xdr_frontend_contract.py --mode baseline  # BEFORE the commit
    python3 scripts/verify_xdr_frontend_contract.py --mode verify    # AFTER Vercel rebuilds

Static + cross-product gates only. The interactive gates (modal renders,
mismatch disables submit, match enables it, list/rotate/revoke/delete still
work) are driven separately in a real browser.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

XDR = "https://xdr.nivxforge.com"
EDR = "https://edr.nivxforge.com"
WORKSPACE = "https://nivxray.nivxforge.com"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/126.0 Safari/537.36 nivxray-frontend-verify")

REPORT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "test_reports", "xdr_frontend_baseline.json")
CONTRACT = ("confirm_tenant_id", "allow_new_tenant",
            "xdr-api-key-add-tenant-confirm")
FORBIDDEN_ORIGINS = ("preview.emergentagent.com", "localhost:8001",
                     "127.0.0.1:8001")


def get(url: str) -> tuple[int, bytes]:
    r = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(r, timeout=45) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:                                        # noqa: BLE001
        return 0, str(e).encode()


def probe() -> dict:
    out: dict = {}

    st, body = get(f"{XDR}/build-info.json")
    out["xdr_build_info"] = {"status": st}
    if st == 200:
        try:
            out["xdr_build_info"].update(json.loads(body))
        except Exception:                                         # noqa: BLE001
            out["xdr_build_info"]["parse_error"] = True

    st, body = get(f"{XDR}/xdr")
    html = body.decode(errors="replace")
    out["xdr_spa"] = {"status": st, "html_sha256": hashlib.sha256(body).hexdigest()[:16]}
    assets = sorted(set(re.findall(r"assets/[A-Za-z0-9_.\-]+\.js", html)))
    out["xdr_entry_assets"] = assets

    # The admin surface is a lazy chunk, so walk the chunk graph from the entry.
    seen: set[str] = set()
    queue = list(assets)
    contract_hits: dict[str, list[str]] = {}
    forbidden_hits: dict[str, list[str]] = {}
    total_bytes = 0
    # Admin chunks first: the API-keys surface is a lazy chunk and a naive
    # breadth-first walk with a low cap could miss it and report a FALSE
    # negative. Verified against production: the contract lives in
    # assets/XdrAdminPage-*.js.
    queue.sort(key=lambda a: (0 if "Admin" in a else 1, a))
    while queue and len(seen) < 150:
        a = queue.pop(0)
        if a in seen:
            continue
        seen.add(a)
        st_a, b = get(f"{XDR}/{a}")
        if st_a != 200:
            continue
        total_bytes += len(b)
        text = b.decode(errors="replace")
        hits = [c for c in CONTRACT if c in text]
        if hits:
            contract_hits[a] = hits
        bad = [f for f in FORBIDDEN_ORIGINS if f in text]
        if bad:
            forbidden_hits[a] = bad
        for nxt in re.findall(r'"\./([A-Za-z0-9_.\-]+\.js)"', text):
            if f"assets/{nxt}" not in seen:
                queue.append(f"assets/{nxt}")
        queue.sort(key=lambda a: (0 if "Admin" in a else 1, a))
    out["chunks_scanned"] = len(seen)
    out["chunk_bytes"] = total_bytes
    out["contract_hits"] = contract_hits
    out["forbidden_origin_hits"] = forbidden_hits

    st, body = get(f"{EDR}/build-info.json")
    out["edr_build_info"] = {"status": st}
    if st == 200:
        try:
            out["edr_build_info"].update(json.loads(body))
        except Exception:                                         # noqa: BLE001
            pass

    st, body = get(f"{WORKSPACE}/")
    m = re.search(r"static/js/main\.[A-Za-z0-9]+\.js", body.decode(errors="replace"))
    out["workspace"] = {"status": st, "bundle": m.group(0) if m else None}

    st, body = get(f"{WORKSPACE}/api/health")
    out["workspace_api"] = {"status": st, "body": body.decode()[:120]}
    return out


def gates(p: dict, base: dict | None) -> list[tuple[str, bool, str]]:
    g: list[tuple[str, bool, str]] = []

    bi = p.get("xdr_build_info", {})
    g.append(("XDR build-info reachable", bi.get("status") == 200,
              str(bi.get("built_at"))))
    if base:
        old = base.get("xdr_build_info", {}).get("built_at")
        g.append((f"XDR build-info timestamp is NEW (was {old})",
                  bool(bi.get("built_at")) and bi.get("built_at") != old,
                  str(bi.get("built_at"))))
    g.append(("XDR product_scope == xdr", bi.get("product_scope") == "xdr",
              str(bi.get("product_scope"))))
    g.append(("XDR api_origin == production backend",
              bi.get("api_origin") == WORKSPACE, str(bi.get("api_origin"))))
    # ADVISORY, not a hard gate.  `cross_product_origins` is a *provenance*
    # field and the vercel-build.sh on branch conflict_310826_2116 does not
    # write it (verified in the heredoc at line 28).  Its absence says nothing
    # about the artifact.  The invariant it summarised is enforced instead by
    # the "no preview/localhost API origin" gate below, which MEASURES the
    # shipped chunks directly rather than trusting a self-reported field.
    if bi.get("cross_product_origins") is not None:
        g.append(("XDR cross_product_origins == 0",
                  bi.get("cross_product_origins") == 0,
                  str(bi.get("cross_product_origins"))))
    else:
        print("ADVISORY  build-info omits cross_product_origins "
              "(branch build script does not emit it) — the invariant is "
              "measured directly by the forbidden-origin scan instead")

    g.append(("XDR /xdr serves 200", p.get("xdr_spa", {}).get("status") == 200,
              str(p.get("xdr_spa", {}).get("status"))))

    hits = p.get("contract_hits") or {}
    found = {c for v in hits.values() for c in v}
    for c in CONTRACT:
        g.append((f"live bundle contains {c}", c in found,
                  ",".join(k for k, v in hits.items() if c in v) or "NOT FOUND"))

    fb = p.get("forbidden_origin_hits") or {}
    g.append(("no preview/localhost API origin in production bundle", not fb,
              json.dumps(fb) if fb else "clean"))

    if base:
        g.append(("EDR build-info UNCHANGED",
                  p.get("edr_build_info") == base.get("edr_build_info"),
                  str(p.get("edr_build_info", {}).get("built_at"))))
        g.append(("Workspace bundle UNCHANGED",
                  p.get("workspace", {}).get("bundle")
                  == base.get("workspace", {}).get("bundle"),
                  str(p.get("workspace", {}).get("bundle"))))
    g.append(("Workspace API still 200",
              p.get("workspace_api", {}).get("status") == 200,
              str(p.get("workspace_api", {}).get("status"))))
    return g


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("baseline", "verify"), required=True)
    args = ap.parse_args()
    p = probe()
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)

    if args.mode == "baseline":
        with open(REPORT, "w") as f:
            json.dump(p, f, indent=2)
        print(json.dumps(p, indent=2))
        print(f"\nbaseline written -> {REPORT}")
        return 0

    base = json.load(open(REPORT)) if os.path.exists(REPORT) else None
    print(json.dumps({k: v for k, v in p.items() if k != "contract_hits"},
                     indent=2))
    print(f"\ncontract_hits: {json.dumps(p.get('contract_hits'), indent=2)}")
    print("\n── GATES ──")
    failed = [n for n, ok, _ in gates(p, base) if not ok]
    for name, ok, detail in gates(p, base):
        print(f"{'PASS' if ok else 'FAIL'}  {name}  [{detail}]")
    print("\nVERDICT: " + ("XDR FRONTEND CONTRACT PASS" if not failed
                           else f"FAIL ({len(failed)}) — ROLL BACK to "
                                "dpl_44tFN3uDajSgSrcRawrviJchJq1N"))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
