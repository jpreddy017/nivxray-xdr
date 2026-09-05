# NivXRay Enterprise Reachability Model Specification

> **Document Type:** Graph Reachability Specification  
> **Status:** Authoritative  
> **Package:** `backend/security_state/reachability/`  

---

## 1. Multidimensional Reachability Graph

Reachability calculates what an attacker *could* compromise based on current footholds:

- **Identity Reachability**: Compromised user token &rarr; available role assignments &rarr; cloud subscriptions.
- **Credential Reachability**: Dumped hashes/tickets &rarr; systems where those accounts hold local admin rights.
- **Network Reachability**: Routing tables, firewall rules, and open ports between foothold and target subnets.
- **Application & SaaS Reachability**: Active browser cookies and OAuth tokens granting SaaS API access.
- **Backup & Storage Reachability**: Paths to NAS repository, S3 buckets, and virtualization hosts.

---

## 2. Classification of Reachability Status

Every target asset path is classified as:
- `CURRENTLY_REACHABLE`: Open network route and active valid credential credentials held.
- `POTENTIALLY_REACHABLE`: Attacker is one privilege escalation or credential dump away.
- `CONDITIONALLY_REACHABLE`: Requires bypassing specific non-default controls (e.g. secondary MFA).
- `BLOCKED`: Explicitly blocked by verified network micro-segmentation or IAM boundary.
- `UNKNOWN`: Telemetry gap prevents determination.
