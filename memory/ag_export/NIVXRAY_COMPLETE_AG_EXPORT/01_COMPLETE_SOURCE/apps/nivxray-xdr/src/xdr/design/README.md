# NivXRay Evidence Operations Design System

**Round 24.9** — the grammar that turns NivXRay from a collection of
admin surfaces into one coherent evidence-first product.

## Why this exists

Before Round 24.9, every admin section — Parsers, Normalization,
Users & Roles, API Keys, Webhooks, Response Strategies, Platform
Health — inherited the same _card → counter → table_ template, so
every page in the product looked like a variation of the same admin
console. That is a grammar problem, not a colour problem.

This module introduces **five semantic primitives** that encode
_meaning_ instead of _shape_.  A page that composes NivXRay
primitives cannot accidentally slip back into the CRUD-registry
aesthetic — the primitives do not know how to render one.

## Primitives

| Primitive         | What it declares                                      |
|-------------------|-------------------------------------------------------|
| `<Entity>`        | An identity of an operational object (adapter, host, user, rule, source). Human name in humanist type, machine id in mono. |
| `<EvidenceState>` | The truth-state of a fact _or_ the capability tier of an adapter. Closed enum only — no free strings. |
| `<Provenance>`    | The derivation chain (Telemetry → Canonical → Correlation → Mapping). Missing layers render as `not present` — never fabricated. |
| `<Relationship>`  | A witnessed edge between two entities. Required `state`. |
| `<Action>`        | An operator command bound to a capability. Disabled actions carry an honest inline reason. |

## Prohibitions (locked)

- No gradients, no elevation abuse, no decorative shadows.
- No purple as the dominant colour.
- No generic card grids or "card → counter → table" templates.
- No fabricated timestamps, seeded counters or estimated states.
- No monospace for human-readable labels — monospace is reserved
  for machine values (IDs, hashes, timestamps, endpoints).
- No `data-state` value outside the closed enums exported here.

## Feature flag

The design system ships **behind a feature flag** while it
displaces the legacy admin grammar one surface at a time.

```
VITE_XDR_DESIGN_V2=1           # or:
window.location.search?design=v2
```

`?design=v1` forces the legacy UI in a session even when the env
flag is on — useful for regression comparison.

Reference surface: `IntegrationControlCenter` (`/xdr/admin/integrations`).

## Migration order (owner-locked)

1. Integration Control Center *(this round · reference implementation)*
2. Recommendations tab
3. MITRE tab
4. Incident header
5. Remaining admin surfaces (Parsers, Normalization, API Keys, Webhooks, …)

Once step 5 lands, the feature flag is removed and legacy bodies are
deleted in the same commit.
