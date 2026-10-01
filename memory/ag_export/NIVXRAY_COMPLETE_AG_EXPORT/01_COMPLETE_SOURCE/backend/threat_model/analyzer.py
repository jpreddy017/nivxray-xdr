"""NivXRay Threat-Model Analyzer — deterministic engine (Feb 2026).

Given a parsed Mermaid diagram, produces:

  * Component-type inference (web / api / db / cache / queue / …)
  * Attack-path enumeration (BFS from every EXT/DMZ node to every DATA/INT
    node, capped at depth 6).
  * MITRE ATT&CK mapping per component + per edge.
  * STRIDE-per-edge classification for trust-boundary crossings.
  * Detection recommendations (Sigma / KQL / hunt query ideas).
  * Overall risk score (0-100) + level (safe / low / medium / high /
    critical) grounded in evidence — no LLM required.

The engine is the SOURCE OF TRUTH. LLM enrichment (MoE panel) may run on
top of the deterministic report to add analyst-grade colour, but must not
override severities or drop findings.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from threat_model.parser import ParsedDiagram, MermaidNode, MermaidEdge


# ─── Component-type inference rules (label keyword → kind) ───────────────
_KIND_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\b(user|customer|browser|client|mobile|attacker)\b", re.I), "actor"),
    (re.compile(r"\b(waf|cdn|cloudflare|cloudfront|akamai)\b", re.I),         "waf"),
    (re.compile(r"\b(load\s*balancer|lb|elb|alb|nlb|nginx|haproxy)\b", re.I),  "lb"),
    (re.compile(r"\b(auth|iam|okta|auth0|keycloak|oauth|jwt|sso)\b", re.I),    "auth"),
    (re.compile(r"\b(api|gateway|graphql|grpc|rest|edge)\b", re.I),            "api"),
    (re.compile(r"\b(web|frontend|ui|spa|nextjs|react|angular)\b", re.I),      "web"),
    (re.compile(r"\b(worker|job|task|cron|scheduler)\b", re.I),                "worker"),
    (re.compile(r"\b(queue|kafka|sqs|rabbit|nats|pubsub|kinesis)\b", re.I),     "queue"),
    (re.compile(r"\b(cache|redis|memcache|elasticache)\b", re.I),               "cache"),
    (re.compile(r"\b(db|database|sql|mysql|postgres|mongo|dynamo|rds)\b", re.I),"db"),
    (re.compile(r"\b(s3|blob|object.*store|gcs|azure.*blob|minio)\b", re.I),   "object-store"),
    (re.compile(r"\b(secret|vault|kms|hsm|keystore)\b", re.I),                  "secret-store"),
    (re.compile(r"\b(log|siem|splunk|elk|datadog|prometheus)\b", re.I),         "telemetry"),
    (re.compile(r"\b(ai|llm|openai|claude|gemini|bedrock|inference)\b", re.I),  "llm"),
    (re.compile(r"\b(external|internet|third.?party|vendor|partner)\b", re.I),  "external"),
]

# ─── Component → MITRE ATT&CK primary techniques ─────────────────────────
_KIND_MITRE: Dict[str, List[Dict[str, str]]] = {
    "actor":         [{"id": "T1566", "technique": "Phishing", "tactic": "Initial Access"}],
    "waf":           [{"id": "T1190", "technique": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "lb":            [{"id": "T1190", "technique": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "auth":          [{"id": "T1078", "technique": "Valid Accounts", "tactic": "Initial Access"},
                       {"id": "T1110", "technique": "Brute Force", "tactic": "Credential Access"}],
    "api":           [{"id": "T1190", "technique": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                       {"id": "T1059", "technique": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "web":           [{"id": "T1189", "technique": "Drive-by Compromise", "tactic": "Initial Access"},
                       {"id": "T1055", "technique": "Process Injection", "tactic": "Defense Evasion"}],
    "worker":        [{"id": "T1053", "technique": "Scheduled Task/Job", "tactic": "Persistence"}],
    "queue":         [{"id": "T1090", "technique": "Proxy", "tactic": "Command and Control"}],
    "cache":         [{"id": "T1005", "technique": "Data from Local System", "tactic": "Collection"}],
    "db":            [{"id": "T1005", "technique": "Data from Local System", "tactic": "Collection"},
                       {"id": "T1213", "technique": "Data from Info Repositories", "tactic": "Collection"}],
    "object-store":  [{"id": "T1530", "technique": "Data from Cloud Storage", "tactic": "Collection"}],
    "secret-store":  [{"id": "T1552", "technique": "Unsecured Credentials", "tactic": "Credential Access"}],
    "telemetry":     [{"id": "T1562.008", "technique": "Disable Cloud Logs", "tactic": "Defense Evasion"}],
    "llm":           [{"id": "T1552", "technique": "Prompt Injection / Secret Leak", "tactic": "Credential Access"}],
    "external":      [{"id": "T1199", "technique": "Trusted Relationship", "tactic": "Initial Access"}],
}

# ─── STRIDE rules for trust-boundary edges ───────────────────────────────
_STRIDE_TABLE = {
    ("EXT", "DMZ"):  ["Spoofing", "Tampering", "Denial of Service"],
    ("EXT", "INT"):  ["Spoofing", "Tampering", "Elevation of Privilege"],
    ("EXT", "DATA"): ["Information Disclosure", "Tampering"],
    ("DMZ", "INT"):  ["Elevation of Privilege", "Tampering"],
    ("DMZ", "DATA"): ["Information Disclosure"],
    ("INT", "DATA"): ["Information Disclosure", "Repudiation"],
}


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: str          # critical | high | medium | low | info
    component: Optional[str] = None
    edge: Optional[Dict[str, str]] = None
    mitre: List[str] = field(default_factory=list)
    stride: List[str] = field(default_factory=list)
    detections: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "description": self.description,
            "severity": self.severity, "component": self.component,
            "edge": self.edge, "mitre": list(self.mitre),
            "stride": list(self.stride), "detections": list(self.detections),
        }


# ─── Kind inference + graph annotation ───────────────────────────────────
def _infer_kind(label: str) -> str:
    for rx, kind in _KIND_RULES:
        if rx.search(label):
            return kind
    return "service"


def _annotate(diag: ParsedDiagram) -> None:
    for n in diag.nodes.values():
        if not n.kind:
            n.kind = _infer_kind(f"{n.id} {n.label}")


# ─── Attack-path enumeration ─────────────────────────────────────────────
def _enumerate_paths(diag: ParsedDiagram, max_depth: int = 6,
                      max_paths: int = 30) -> List[List[str]]:
    """BFS from EXT/actor nodes to DATA / secret-store / db nodes."""
    adj: Dict[str, List[str]] = defaultdict(list)
    for e in diag.edges:
        adj[e.src].append(e.dst)

    entries = [n.id for n in diag.nodes.values()
                if n.zone == "EXT" or n.kind in ("actor", "external")]
    if not entries:
        # No explicit external node — treat every node with no incoming edge
        # as an entry point (best-effort external surface).
        incoming = {e.dst for e in diag.edges}
        entries = [n.id for n in diag.nodes.values() if n.id not in incoming]

    crown_jewels = {
        n.id for n in diag.nodes.values()
        if n.zone == "DATA" or n.kind in ("db", "object-store", "secret-store")
    }
    if not crown_jewels:
        # No crown jewels? Fall back to any leaf.
        outgoing = {e.src for e in diag.edges}
        crown_jewels = {n.id for n in diag.nodes.values() if n.id not in outgoing}

    paths: List[List[str]] = []
    for start in entries:
        # BFS with path memory
        q = deque([[start]])
        while q and len(paths) < max_paths:
            path = q.popleft()
            if len(path) > max_depth:
                continue
            tail = path[-1]
            if tail in crown_jewels and len(path) > 1:
                paths.append(path)
                continue
            for nxt in adj.get(tail, []):
                if nxt in path:
                    continue  # avoid cycles
                q.append(path + [nxt])
    return paths


# ─── Per-component + per-edge findings ───────────────────────────────────
def _detection_for_kind(kind: str, label: str) -> List[str]:
    lbl = label.lower()
    d: List[str] = []
    if kind == "api":
        d.append("Alert on burst of 5xx OR 4xx spikes per IP; rate-limit unauth callers.")
        d.append("KQL: ApiEvents | summarize errcnt=count() by ClientIP | where errcnt > 100")
    if kind == "auth":
        d.append("Sigma: multiple failed logins from same IP within 60s (brute-force).")
        d.append("Alert on token/JWT with unusual `aud` or missing `exp`.")
    if kind == "db":
        d.append("Enable query-log auditing; alert on `SELECT *` on PII tables.")
        d.append("KQL: DbLogins | where SourceIP !in known_service_ips | count")
    if kind == "object-store":
        d.append("Alert on ListBucket by non-service IAM principals.")
        d.append("Sigma: S3 GetObject burst from a single IAM role within 5 min.")
    if kind == "secret-store":
        d.append("KMS decrypt volume anomaly per role; secret-fetch by non-workload principal.")
    if kind == "lb" or kind == "waf":
        d.append("Alert on WAF rule bypass attempts (SQLi / XSS pattern hits blocked).")
    if kind == "queue":
        d.append("Alert on publish rate anomalies; check for topic-hopping across partitions.")
    if "public" in lbl or "internet" in lbl:
        d.append("Perimeter TLS enforce; block deprecated cipher suites.")
    return d


def _severity_for_edge(src: MermaidNode, dst: MermaidNode) -> str:
    """Higher severity when the crossing exposes more sensitive assets."""
    if not src.zone or not dst.zone:
        return "medium"
    if src.zone == "EXT" and dst.zone == "DATA":
        return "critical"
    if src.zone == "EXT" and dst.zone == "INT":
        return "high"
    if src.zone == "DMZ" and dst.zone in ("INT", "DATA"):
        return "high"
    if src.zone == "INT" and dst.zone == "DATA":
        return "medium"
    return "low"


def analyze(diag: ParsedDiagram) -> Dict[str, Any]:
    """Run the deterministic threat-model analysis over a parsed diagram."""
    _annotate(diag)
    findings: List[Finding] = []

    # 1) Component findings — per-node MITRE mapping + detection ideas.
    for n in diag.nodes.values():
        mitre = _KIND_MITRE.get(n.kind or "service", [])
        detections = _detection_for_kind(n.kind or "service", n.label)
        if not mitre and not detections:
            continue
        sev = "high" if (n.zone == "DATA" or n.kind in ("secret-store", "db")) else \
              "medium" if n.kind in ("api", "auth", "lb", "waf") else "low"
        findings.append(Finding(
            id=f"COMP-{n.id}",
            title=f"{(n.kind or 'service').upper()} · {n.label}",
            description=(f"Component {n.label} classified as `{n.kind}`. Zone={n.zone or 'unmarked'}. "
                          f"Attack surface: {', '.join(t['technique'] for t in mitre) or 'generic service'}."),
            severity=sev,
            component=n.id,
            mitre=[t["id"] for t in mitre],
            detections=detections,
        ))

    # Per-transition remediation library (Feb-2026 v5 audit fix — bug #3).
    # Placed BEFORE the trust-boundary loop so the description-builder can
    # reference it. Previously every trust-boundary crossing carried the
    # same generic "mTLS + deny-by-default" text; now each transition +
    # destination-kind gets a tailored recommendation.
    _TM_REMEDIATION_LIB = {
        ("EXT", "DMZ"):  "WAF-inspected TLS 1.3 termination · rate-limit at CDN · GeoIP + ASN allow-list · Bot management",
        ("EXT", "INT"):  "Direct EXT→INT is HIGH RISK · route through DMZ reverse-proxy · mTLS + SPIFFE identity + JWT audience-pinning",
        ("EXT", "DATA"): "CRITICAL · never expose DATA to EXT directly · require signed pre-authorised URLs OR proxy through INT service",
        ("DMZ", "INT"):  "mTLS with rotating short-TTL certs · service-mesh (Istio / Linkerd) sidecar policy · request-scoped OAuth2 tokens",
        ("DMZ", "DATA"): "STRONG isolation · DMZ services must proxy through an INT tier · row-level ACLs enforced at DB (not app)",
        ("INT", "DATA"): "Least-privilege DB user per service · TLS to DB · secrets rotated ≥90d · query allow-list at proxy layer (ProxySQL / RDS Proxy)",
        ("INT", "INT"):  "Service-mesh mTLS + workload-identity · deny-by-default authz policy · circuit breakers to prevent lateral spread",
        ("INT", "EXT"):  "Egress proxy with domain allow-list (e.g. squid) · block direct outbound IPs · monitor DNS exfiltration",
        ("DATA", "EXT"): "CRITICAL · data exfiltration path · require signed URLs with 1h TTL · alert on any DATA→EXT flow in SIEM",
    }
    _TM_KIND_DEFENCE = {
        "db":            "Enable slow-query log → SIEM · DAM/Imperva-style query anomaly detection",
        "cache":         "Redis AUTH + ACLs · disable CONFIG/EVAL from apps · TLS on wire",
        "queue":         "Kafka ACLs per topic · schema registry · dead-letter monitoring",
        "secret-store":  "Vault dynamic secrets · leaf-cert authentication · audit every fetch",
        "s3":            "Bucket policy deny-public · KMS-encrypt at rest · CloudTrail data-events on",
        "auth":          "MFA-required · OAuth2 device-code · TPM/HSM-backed keys · rotate JWKs quarterly",
    }

    # 2) Edge findings — trust-boundary crossings with STRIDE + severity.
    for e in diag.edges:
        src = diag.nodes.get(e.src)
        dst = diag.nodes.get(e.dst)
        if not src or not dst or e.kind != "trust-boundary":
            continue
        stride = _STRIDE_TABLE.get((src.zone or "", dst.zone or ""), [])
        sev = _severity_for_edge(src, dst)
        # MITRE picks: combine dst-kind + a generic Initial-Access technique.
        mitre_ids = [t["id"] for t in _KIND_MITRE.get(dst.kind or "service", [])[:2]]
        if src.zone == "EXT":
            mitre_ids = list(dict.fromkeys(["T1190", "T1078"] + mitre_ids))
        findings.append(Finding(
            id=f"EDGE-{e.src}-{e.dst}",
            title=f"Trust-boundary crossing · {src.zone} → {dst.zone} ({src.label} → {dst.label})",
            description=(f"Edge `{src.label} → {dst.label}` crosses from {src.zone} into {dst.zone}. "
                          f"STRIDE risks: {', '.join(stride) or 'general'}. "
                          f"Ensure mTLS + explicit deny-by-default authorisation on this hop."
                          + (f" · {_TM_REMEDIATION_LIB.get((src.zone or '', dst.zone or ''), '')}" if _TM_REMEDIATION_LIB.get((src.zone or '', dst.zone or '')) else "")
                          + (f" · {_TM_KIND_DEFENCE.get(dst.kind or '', '')}" if _TM_KIND_DEFENCE.get(dst.kind or '') else "")),
            severity=sev,
            edge={"src": e.src, "dst": e.dst, "label": e.label},
            mitre=mitre_ids,
            stride=stride,
            detections=[
                f"Alert on unexpected client IPs to `{dst.label}` from outside `{dst.zone}` allow-list.",
                f"Log all denied auth attempts at `{dst.label}` and route to SIEM.",
            ],
        ))

    # 3) Attack paths — enumerate EXT/actor → DATA/db/secret-store.
    paths = _enumerate_paths(diag)
    attack_paths: List[Dict[str, Any]] = []
    for p in paths:
        crosses = 0
        stride_set: Set[str] = set()
        for a, b in zip(p, p[1:]):
            src = diag.nodes.get(a); dst = diag.nodes.get(b)
            if src and dst and src.zone and dst.zone and src.zone != dst.zone:
                crosses += 1
                stride_set.update(
                    _STRIDE_TABLE.get((src.zone, dst.zone), []))
        # Terminal-kind severity.
        term = diag.nodes.get(p[-1])
        sev = "critical" if (term and (term.zone == "DATA" or term.kind in ("secret-store", "db"))) \
              else "high" if crosses >= 2 else "medium"
        attack_paths.append({
            "nodes": [{"id": nid, "label": diag.nodes[nid].label,
                        "zone": diag.nodes[nid].zone, "kind": diag.nodes[nid].kind}
                       for nid in p if nid in diag.nodes],
            "hops": len(p) - 1,
            "trust_crossings": crosses,
            "stride": sorted(stride_set),
            "severity": sev,
            "terminal": p[-1],
        })

    # 4) Overall risk score.
    sev_weight = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
    raw_score = sum(sev_weight.get(f.severity, 0) for f in findings)
    raw_score += sum(15 if p["severity"] == "critical" else
                      8 if p["severity"] == "high" else 3
                      for p in attack_paths)
    score = min(100, raw_score)
    level = ("critical" if score >= 75 else "high" if score >= 50 else
              "medium" if score >= 25 else "low" if score >= 10 else "safe")

    # 5) Deduplicate MITRE for report header.
    mitre_all = sorted({m for f in findings for m in f.mitre})

    return {
        "diagram": diag.to_dict(),
        "findings": [f.to_dict() for f in findings],
        "attack_paths": attack_paths,
        "risk": {"score": score, "level": level},
        "mitre_summary": mitre_all,
        "counts": {
            "nodes": len(diag.nodes),
            "edges": len(diag.edges),
            "trust_boundary_edges": sum(1 for e in diag.edges if e.kind == "trust-boundary"),
            "attack_paths": len(attack_paths),
            "findings": len(findings),
        },
    }
