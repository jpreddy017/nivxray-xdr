# Semantic Alias Registry — Governance

*Effective 2026-02-XX · Owner-authored process document.*

The Semantic Alias Registry is a **governed architectural asset**, not
a dictionary. Every entry has an outsized effect on downstream
investigation behaviour because the entire semantic pipeline flows
through it. This document codifies the process by which new aliases
enter the registry and how versions are cut.

---

## 1 · Guiding Principle

> **Precision is more important than coverage.**
> An ambiguous alias is worse than a missing alias.

The Semantic Field Mapper (Stage 3) will *not* silently guess.
An unmapped field is a supported success state, not a failure.

---

## 2 · Promotion Pipeline

Every proposed new alias travels through five gates in order:

```
     Observed
        │
        ▼
     Frequency
        │
        ▼
Cross-vendor occurrence
        │
        ▼
   Human review
        │
        ▼
Registry promotion
```

### 2.1 · Observed

The surface field name must have been **encountered in real
telemetry** (customer sample, alien-corpus sanitisation, vendor
integration exercise). Synthetic examples do not qualify.

Evidence recorded:
- source telemetry family (e.g. Windows Security, Zeek conn log, …)
- date first observed
- sample payload path (sanitised)

### 2.2 · Frequency

The field must be **repeatably present** in that telemetry family
— not a one-off from a single record. Recorded evidence:
- number of records containing the field
- fraction of the corpus in which the field appears

### 2.3 · Cross-vendor occurrence

The field must appear in **≥ 3 independent telemetry families**
before it is promoted to the shared registry. Fields observed in
only one vendor are eligible only for a **vendor-scoped alias
extension** (a separate future construct, not the shared registry).

Evidence recorded:
- list of telemetry families where the field is present

### 2.4 · Human review

An architect / senior analyst must review the proposal against:

- **Ambiguity:** does the field's normalized form collide with a
  different canonical concept? If yes → reject.
- **Semantic conflict:** could the same surface plausibly mean
  different things in different families? If yes → reject or
  scope narrowly.
- **Improvement:** does adding this alias unblock analyst-defensible
  mappings for real fixtures? If no → defer.
- **Confidence declaration:** what is the intrinsic base confidence?
  (`1.00` = universally unambiguous, `0.90` = strong but rare edge
  cases, `0.80` = context-dependent.)

### 2.5 · Registry promotion

Only after all four prior gates pass is the alias added to
`semantic_alias_registry.py`. Promotion produces:

- A new alias row in `_FOUNDATIONAL_ALIASES`
- A regression test in `test_semantic_alias_registry.py` covering
  the new alias explicitly
- A soak fixture (real or sanitised) exercising the mapping
- A CHANGELOG entry naming the alias, its concept, its confidence,
  and the telemetry families that justified its promotion

---

## 3 · Registry Versioning

The registry is versioned by the string constant
`SEMANTIC_ALIAS_REGISTRY_VERSION` (currently
`semantic_alias_registry_v1`).

### 3.1 · Backward-compatible changes (patch)

Additive-only changes that never rename or remove an alias may
share the current version. A promotion that satisfies §2 falls
into this category.

### 3.2 · Breaking changes (major version)

Any of the following requires a version bump (`v2`, `v3`, …):

- Removing an alias
- Renaming an alias
- Changing the concept a surface maps to
- Changing the declared confidence such that downstream mapping
  behaviour materially shifts
- Introducing a new normalization rule

When the version is bumped:

- Every downstream artifact that records `registry_version` continues
  to reflect the version *it* consumed
- A migration note lands in `CHANGELOG.md`
- The Parity Comparator (see `test_cem_parity.py`) reruns the golden
  corpus and any parity delta becomes a Verified Defect until it is
  either accepted (with rationale) or fixed

---

## 4 · Anti-Pattern Catalogue

Explicit list of things that **must not** happen:

- ✗ Adding an alias to make a single test pass
- ✗ Adding an alias to increase mapping-rate metrics without
  cross-vendor evidence
- ✗ Adding a vendor-branded name (e.g. `crowdstrike_hostname`) —
  vendor identity is enrichment metadata, never a registry alias
- ✗ Adding a low-confidence alias to catch "fuzzy" cases — the
  Semantic Field Mapper's shape and sibling signals already model
  fuzziness deterministically
- ✗ Removing an alias to "clean up" — removals require a major
  version bump

---

## 5 · Current Backlog (soak-report surfaced)

Fields observed in the alien corpus that appear *inferentially* to
carry canonical concepts but are **not yet in v1**:

| Surface | Concept | Family | Status |
|---|---|---|---|
| `requester_ip` | IP | SaaS audit log | ⏸ pending — needs 2 more families |
| `operator_login` | User | ICS/OT SCADA | ⏸ pending — needs 2 more families |
| `supervisor_host` | Host | ICS/OT SCADA | ⏸ pending — needs 2 more families |
| `gateway_ip` | IP | IoT/Edge | ⏸ pending — needs 2 more families |
| `peer_ip` | IP | Cloud-native | ⏸ pending — needs 2 more families |

These are candidates for a future `semantic_alias_registry_v2` —
none are promoted until they meet the cross-vendor threshold.

---

*This document is the source of truth for registry evolution.
Amendments require owner approval.*
