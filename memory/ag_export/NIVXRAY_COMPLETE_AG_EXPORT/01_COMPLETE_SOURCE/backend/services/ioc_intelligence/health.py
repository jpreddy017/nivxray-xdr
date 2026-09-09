"""
IOC Intelligence · provider health check (2026-03-02)
─────────────────────────────────────────────────────
Startup-time inspection of every enrichment provider.  Reports which
credentials are present, which are missing, and which providers are
therefore live vs pending.  Runs deterministically without touching
the network — no calls happen here; we only inspect env vars.

Consumed by:
  · server.py startup log  → visible boot receipt
  · GET /api/ioc/health    → live status widget under IOC Intelligence
"""
from __future__ import annotations
import os
from typing import Any, Dict, List

# Provider → env-var(s) accepted.  First present env var wins.
_PROVIDER_ENV: Dict[str, List[str]] = {
    "virustotal":      ["VT_API_KEY", "VIRUSTOTAL_API_KEY"],
    "abuseipdb":       ["ABUSEIPDB_API_KEY"],
    "urlscan":         ["URLSCAN_API_KEY"],
    "hybrid-analysis": ["HYBRID_ANALYSIS_API_KEY"],
    "malwarebazaar":   ["ABUSE_CH_AUTH_KEY", "MALWAREBAZAAR_KEY"],
    "threatfox":       ["ABUSE_CH_AUTH_KEY", "THREATFOX_KEY"],
    "urlhaus":         ["ABUSE_CH_AUTH_KEY", "URLHAUS_KEY"],
}


def provider_health() -> List[Dict[str, Any]]:
    """Deterministic snapshot of provider configuration."""
    out: List[Dict[str, Any]] = []
    for name, envs in _PROVIDER_ENV.items():
        present = next((e for e in envs if os.environ.get(e)), None)
        out.append({
            "provider":  name,
            "state":     "live" if present else "pending",
            "env":       present or envs[0],
            "detail":    "credentials configured" if present
                          else f"missing env: {envs[0]}",
        })
    return out


def format_boot_receipt() -> str:
    """One-liner receipt for the server boot log."""
    rows = provider_health()
    live = [r["provider"] for r in rows if r["state"] == "live"]
    miss = [r["provider"] for r in rows if r["state"] == "pending"]
    parts = [f"IOC providers → {len(live)}/{len(rows)} live"]
    if live: parts.append("✓ " + ", ".join(sorted(live)))
    if miss: parts.append("✗ " + ", ".join(sorted(miss)))
    return " · ".join(parts)
