"""
Predefined Collector Catalog
============================

A curated list of "operationally common" collector templates so a
brand-new tenant can adopt endpoint / network / DNS / web / cloud /
identity collection without having to learn the protocol matrix.

Each catalog entry is a TEMPLATE, not a running collector.  Operators
instantiate one via `POST /api/xdr/collectors` with the referenced
`protocol` and a tenant-specific config.

The catalog is deterministic, license-free (NivXRay public content),
and honest about implementation status.  Templates whose underlying
protocol is SCAFFOLD are surfaced as SCAFFOLD in the UI.

Categories:
  * ENDPOINT   — Windows / Linux / macOS agents, EDR
  * NETWORK    — firewall / IDS / NDR / router / switch
  * DNS        — resolvers, protective DNS
  * WEB        — proxies, WAFs
  * CLOUD      — AWS / GCP / Azure audit + workload
  * IDENTITY   — Okta / AzureAD / IdP
  * EMAIL      — Mail security / O365 / Google Workspace
  * CONTAINER  — Kubernetes / OCI runtimes
"""
from __future__ import annotations

CATALOG = [
    # ── ENDPOINT ──────────────────────────────────────────────────
    {
        "id":            "cat_endpoint_syslog",
        "category":      "ENDPOINT",
        "display_name":  "Linux Endpoint (syslog / auditd)",
        "description":   "Receive syslog + auditd events from Linux endpoints via a syslog UDP/TCP listener.",
        "protocol":      "syslog",
        "default_port":  514,
        "recommended_parser": "syslog-rfc5424",
        "recommended_normalization_profile": "ecs-endpoint",
        "example_data_source_kind": "linux_endpoint",
        "expected_events_per_endpoint": "5-500/min",
    },
    {
        "id":            "cat_endpoint_wef",
        "category":      "ENDPOINT",
        "display_name":  "Windows Endpoint (WEF / Sysmon)",
        "description":   "Windows Event Forwarding subscription — Security, Sysmon, PowerShell operational channels.",
        "protocol":      "wef",
        "default_port":  5985,
        "recommended_parser": "wef-evtx",
        "recommended_normalization_profile": "ecs-windows-eventlog",
        "example_data_source_kind": "windows_endpoint",
        "expected_events_per_endpoint": "20-800/min",
    },
    {
        "id":            "cat_endpoint_edr",
        "category":      "ENDPOINT",
        "display_name":  "EDR Vendor Adapter (CrowdStrike / Defender / SentinelOne)",
        "description":   "Vendor EDR streaming adapter — process / file / registry / network events.",
        "protocol":      "edr",
        "default_port":  None,
        "recommended_parser": "edr-vendor",
        "recommended_normalization_profile": "ecs-endpoint",
        "example_data_source_kind": "edr_platform",
        "expected_events_per_endpoint": "500-50000/min",
    },
    # ── NETWORK ──────────────────────────────────────────────────
    {
        "id":            "cat_network_syslog_firewall",
        "category":      "NETWORK",
        "display_name":  "Firewall (Palo Alto / Fortinet / Check Point)",
        "description":   "Ingest firewall traffic and threat logs via syslog CEF.",
        "protocol":      "syslog",
        "default_port":  514,
        "recommended_parser": "cef",
        "recommended_normalization_profile": "ecs-network-firewall",
        "example_data_source_kind": "firewall",
        "expected_events_per_appliance": "500-50000/min",
    },
    {
        "id":            "cat_network_ndr_kafka",
        "category":      "NETWORK",
        "display_name":  "NDR / Zeek / Suricata (Kafka)",
        "description":   "Consume network detection events from Kafka (Zeek/Suricata pipelines).",
        "protocol":      "kafka",
        "default_port":  9092,
        "recommended_parser":"json",
        "recommended_normalization_profile":"ecs-network-flow",
        "example_data_source_kind": "ndr_platform",
        "expected_events_per_endpoint": "10000+/min",
    },
    {
        "id":            "cat_network_otlp",
        "category":      "NETWORK",
        "display_name":  "OpenTelemetry Collector (OTLP)",
        "description":   "Native OTLP receiver for logs and traces.",
        "protocol":      "otlp",
        "default_port":  4317,
        "recommended_parser": "otlp",
        "recommended_normalization_profile":"otel",
        "example_data_source_kind": "otlp_pipeline",
    },
    # ── DNS ──────────────────────────────────────────────────────
    {
        "id":            "cat_dns_syslog_resolver",
        "category":      "DNS",
        "display_name":  "DNS Resolver (BIND / Unbound / Windows DNS)",
        "description":   "Ingest resolver query logs via syslog or file tailing.",
        "protocol":      "syslog",
        "default_port":  514,
        "recommended_parser": "dns-query-log",
        "recommended_normalization_profile":"ecs-dns",
        "example_data_source_kind": "dns_resolver",
    },
    {
        "id":            "cat_dns_protective_rest",
        "category":      "DNS",
        "display_name":  "Protective DNS (Cisco Umbrella / Cloudflare Gateway)",
        "description":   "Poll Protective DNS provider REST API for allow/block events.",
        "protocol":      "rest",
        "default_port":  443,
        "recommended_parser": "json",
        "recommended_normalization_profile":"ecs-dns",
        "example_data_source_kind": "protective_dns",
    },
    # ── WEB ──────────────────────────────────────────────────────
    {
        "id":            "cat_web_proxy_webhook",
        "category":      "WEB",
        "display_name":  "Web Proxy / SWG (Zscaler / Netskope)",
        "description":   "Push web proxy access + threat events via signed webhook.",
        "protocol":      "webhook",
        "default_port":  443,
        "recommended_parser": "json",
        "recommended_normalization_profile":"ecs-http",
        "example_data_source_kind": "secure_web_gateway",
    },
    {
        "id":            "cat_web_waf_rest",
        "category":      "WEB",
        "display_name":  "WAF (Cloudflare / AWS WAF / F5)",
        "description":   "Poll WAF platform for firewall events + bot attribution.",
        "protocol":      "rest",
        "default_port":  443,
        "recommended_parser": "json",
        "recommended_normalization_profile":"ecs-http-waf",
        "example_data_source_kind": "waf",
    },
    # ── CLOUD ────────────────────────────────────────────────────
    {
        "id":            "cat_cloud_aws_cloudtrail",
        "category":      "CLOUD",
        "display_name":  "AWS CloudTrail",
        "description":   "Poll AWS CloudTrail management + data events from S3/EventBridge.",
        "protocol":      "cloud",
        "default_port":  None,
        "recommended_parser": "aws-cloudtrail-json",
        "recommended_normalization_profile":"ecs-cloud-aws",
        "example_data_source_kind": "cloud_aws",
    },
    {
        "id":            "cat_cloud_gcp_audit",
        "category":      "CLOUD",
        "display_name":  "GCP Cloud Audit Logs",
        "description":   "Consume GCP Cloud Audit Logs via Pub/Sub.",
        "protocol":      "cloud",
        "default_port":  None,
        "recommended_parser": "gcp-audit-json",
        "recommended_normalization_profile":"ecs-cloud-gcp",
        "example_data_source_kind": "cloud_gcp",
    },
    {
        "id":            "cat_cloud_azure_activity",
        "category":      "CLOUD",
        "display_name":  "Azure Activity + Sign-in Logs",
        "description":   "Ingest Azure Activity + Entra sign-in logs via Event Hub.",
        "protocol":      "cloud",
        "default_port":  None,
        "recommended_parser": "azure-activity-json",
        "recommended_normalization_profile":"ecs-cloud-azure",
        "example_data_source_kind": "cloud_azure",
    },
    # ── IDENTITY ─────────────────────────────────────────────────
    {
        "id":            "cat_identity_okta_rest",
        "category":      "IDENTITY",
        "display_name":  "Okta System Log",
        "description":   "Poll Okta System Log for authentication and admin events.",
        "protocol":      "rest",
        "default_port":  443,
        "recommended_parser": "okta-syslog-json",
        "recommended_normalization_profile":"ecs-identity",
        "example_data_source_kind": "identity_provider",
    },
    {
        "id":            "cat_identity_entra_webhook",
        "category":      "IDENTITY",
        "display_name":  "Entra ID / AzureAD",
        "description":   "Ingest Entra ID audit + sign-in events via Event Hub webhook.",
        "protocol":      "webhook",
        "default_port":  443,
        "recommended_parser": "entra-json",
        "recommended_normalization_profile":"ecs-identity",
        "example_data_source_kind": "identity_provider",
    },
    # ── EMAIL ────────────────────────────────────────────────────
    {
        "id":            "cat_email_o365_rest",
        "category":      "EMAIL",
        "display_name":  "Microsoft 365 Defender for O365",
        "description":   "Poll M365 Defender API for email + attachment events.",
        "protocol":      "rest",
        "default_port":  443,
        "recommended_parser": "m365-defender-json",
        "recommended_normalization_profile":"ecs-email",
        "example_data_source_kind": "email_gateway",
    },
    # ── CONTAINER ────────────────────────────────────────────────
    {
        "id":            "cat_container_k8s_audit",
        "category":      "CONTAINER",
        "display_name":  "Kubernetes Audit + Falco",
        "description":   "Ingest K8s audit + Falco runtime events via webhook/OTLP.",
        "protocol":      "otlp",
        "default_port":  4317,
        "recommended_parser": "k8s-audit-json",
        "recommended_normalization_profile":"ecs-container",
        "example_data_source_kind": "container_platform",
    },
]


def catalog_by_category() -> dict:
    out: dict = {}
    for e in CATALOG:
        out.setdefault(e["category"], []).append(e)
    return out


def summary() -> dict:
    cats = catalog_by_category()
    return {
        "total": len(CATALOG),
        "categories": sorted(cats),
        "per_category_count": {k: len(v) for k, v in cats.items()},
    }
