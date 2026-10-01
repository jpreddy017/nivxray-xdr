"""URLScan.io provider · URL / domain / IP reputation & related scans."""
from __future__ import annotations
import os
from typing import Any, Dict

import httpx

from ..schema import ProviderResult, ProviderVerdict
from .base import pending_result, error_result, unknown_result

name = "urlscan"
SUPPORTED_KINDS = ("url", "domain", "ip")

_ENDPOINT_SEARCH = "https://urlscan.io/api/v1/search/"


async def lookup(kind: str, value: str,
                   http: httpx.AsyncClient) -> ProviderResult:
    key = os.environ.get("URLSCAN_API_KEY")
    if not key:
        return pending_result(name, "URLScan API key not configured")

    # URLScan search DSL — build a targeted query per kind.
    if kind == "url":
        q = f'page.url:"{value}"'
    elif kind == "domain":
        q = f'page.domain:"{value}" OR domain:"{value}"'
    elif kind == "ip":
        q = f'page.ip:"{value}" OR ip:"{value}"'
    else:
        return unknown_result(name, "unsupported kind")

    try:
        r = await http.get(
            _ENDPOINT_SEARCH,
            params={"q": q, "size": 20},
            headers={"API-Key": key},
            timeout=8.0,
        )
    except Exception as e:
        return error_result(name, f"{type(e).__name__}: {e!s}")

    if r.status_code in (401, 403):
        return pending_result(name, "URLScan API key rejected")
    if r.status_code == 429:
        # URLScan free tier is 1000 searches / day. Surface rate-limit
        # as a distinct `pending`-flavoured state so the analyst knows
        # to try again rather than assuming URLScan says "clean".
        return ProviderResult(
            verdict=ProviderVerdict(
                provider=name, verdict="unknown",
                detail="rate limited (retry later)",
                source="pending", score=0.0,
            ),
        )
    if r.status_code >= 400:
        return error_result(name, f"HTTP {r.status_code}")

    try:
        payload: Dict[str, Any] = r.json()
    except Exception as e:
        return error_result(name, f"non-JSON: {e!s}")

    results = payload.get("results") or []
    if not results:
        return ProviderResult(
            verdict=ProviderVerdict(provider=name, verdict="clean",
                                       detail="no matching scans",
                                       source="live", score=0.0),
        )

    malicious = 0
    verdicts_found: list = []
    families: list = []
    campaigns: list = []
    related_domains: list = []
    related_ips: list = []
    related_urls: list = []
    references: list = []
    first_seen, last_seen = None, None

    for row in results[:20]:
        v = (row.get("verdicts") or {}).get("overall") or {}
        if v.get("malicious"):
            malicious += 1
        verdicts_found.append(v.get("score"))
        task = row.get("task") or {}
        page = row.get("page") or {}
        t = task.get("time")
        if t:
            first_seen = min(first_seen, t) if first_seen else t
            last_seen  = max(last_seen,  t) if last_seen  else t
        if row.get("_id"):
            references.append(f"https://urlscan.io/result/{row['_id']}/")
        if page.get("domain") and page["domain"] != value:
            related_domains.append(page["domain"])
        if page.get("ip") and page["ip"] != value:
            related_ips.append(page["ip"])
        if page.get("url") and page["url"] != value:
            related_urls.append(page["url"])
        for br in (row.get("brand") or []):
            if br.get("name"): campaigns.append(br["name"])

    total = len(results)
    ratio_score = malicious / total if total else 0.0
    verdict = "malicious"  if ratio_score >= 0.3 else \
                "suspicious" if malicious      >= 1 else \
                "clean"
    score = min(1.0, ratio_score + (0.4 if malicious else 0.0))

    detail = f"{malicious}/{total} scans flagged malicious"

    return ProviderResult(
        verdict=ProviderVerdict(
            provider=name, verdict=verdict, detail=detail,
            source="live", score=score,
        ),
        first_seen=first_seen,
        last_seen=last_seen,
        families=families,
        campaigns=list(dict.fromkeys(campaigns))[:10],
        related_urls=list(dict.fromkeys(related_urls))[:10],
        related_domains=list(dict.fromkeys(related_domains))[:10],
        related_ips=list(dict.fromkeys(related_ips))[:10],
        references=references[:5],
    )
