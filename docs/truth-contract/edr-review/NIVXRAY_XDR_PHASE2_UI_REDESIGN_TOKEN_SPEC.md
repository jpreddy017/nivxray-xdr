# NivXRay XDR · Phase 2 UI Redesign — Design Token Specification & Delivery Record

**Owner authorisation:** 2026-09-05 — "OWNER DECISION — EXPAND UI REDESIGN NOW"
**Design system name:** *Deterministic Obsidian & Kinetic Amber* (`/app/design_guidelines.json`)
**Scope fence:** Incident Queue · Incident Investigation record (Attack Story / Evidence Graph) ·
MSS Dashboard · Investigation Workspace. No engine touched (IUE, ICE, VEEE, IKG, canonical
evidence, detection content, decoder, Security State, UBAE, Sandbox, Suricata, mal-20, Stage 11).

---

## 1. Theme architecture

Dark is the **default**. Light is a **preserved, working toggle** — not removed.

```
.xdr-console                         → DARK   (default)
.xdr-console[data-nx-theme="light"]  → LIGHT  (toggle, persisted in localStorage 'nx.theme')
```

Owner-set constraint: *"Treat dark/light as one complete token system. Do not ship a partial
theme."* Implementation therefore does **not** patch component colours — it re-declares the
token layer in `nx/nx-theme.css`, loaded last, and every hard-coded colour in the in-scope
surfaces was migrated to a token. A component that hard-codes a colour cannot theme and is
now treated as a grammar violation.

### 1.1 Surfaces — four real elevations (not one slab)

| Token | Dark | Light | Use |
|---|---|---|---|
| `--nx-surf-canvas` | `#0B0E14` | `#F8FAFC` | application ground |
| `--nx-surf-primary` | `#121721` | `#FFFFFF` | dominant work surface |
| `--nx-surf-inset` | `#0E131C` | `#F1F5F9` | controls, wells, sub-sections |
| `--nx-surf-raised` | `#1A212D` | `#FFFFFF` | popovers, drawers, graph nodes |
| `--nx-surf-hover` | `#222B3A` | `#E2E8F0` | row / control hover |
| `--nx-graph-bg` | `#090C12` | `#FBFBF9` | graph canvas |

### 1.2 Text, borders, focus

| Token | Dark | Light |
|---|---|---|
| `--nx-text` | `#F1F5F9` | `#0F172A` |
| `--nx-text-dim` | `#CBD5E1` | `#475569` |
| `--nx-muted` | `#94A3B8` | `#475569` |
| `--nx-faint` | `#7C8AA0` | `#5C6879` |
| `--nx-bd-quiet` | `rgba(255,255,255,.08)` | `#E2E8F0` |
| `--nx-bd-strong` | `rgba(255,255,255,.14)` | `#CBD5E1` |
| `--nx-focus` | `#38BDF8` | `#0284C7` |
| `--nx-on-accent` | `#0B0E14` | `#FFFFFF` |

### 1.3 Accent

Amber `#F59E0B` (dark) / `#B45309` (light) is the single signal accent — deliberately **not**
the generic SaaS violet the owner rejected. Cyan `#06B6D4` and emerald `#10B981` are secondary.

### 1.4 Type system

| Role | Family |
|---|---|
| Display | `Outfit` |
| Body | `IBM Plex Sans` |
| Technical / machine facts | `JetBrains Mono` |

Inter / Roboto / system-sans are explicitly not used as the primary voice. Every machine-emitted
fact (ids, timestamps, hashes, states, coverage figures) is monospaced; every human-authored
sentence is Plex Sans. The reader can tell what the machine said from what a person said.

---

## 2. Priority ladder (owner-locked 2026-09-05)

Owner defect: *"P1 red colour, P2 red colour"* — the chip reused the pale severity **text**
colours as its **fill**, so P1/P2 collapsed into the same salmon.

| Rank | Meaning | Dark fill | Light fill | Glyph |
|---|---|---|---|---|
| P1 | CRITICAL | `#EF4444` | `#DC2626` | ▰▰▰▰ |
| P2 | HIGH | `#F97316` | `#EA580C` | ▰▰▰▱ |
| P3 | MEDIUM | `#EAB308` | `#CA8A04` | ▰▰▱▱ |
| P4 | LOW | `#14B8A6` | `#0D9488` | ▰▱▱▱ |
| P5 | INFORMATIONAL | `#94A3B8` | `#64748B` | ▱▱▱▱ |

Rank is **never carried by colour alone** — the glyph makes it survive greyscale and
colour-blindness. Severity reuses the same ladder so the two columns cannot contradict.

---

## 3. Relationship grammar (locked · epistemic, not decorative)

Derived **only** from authoritative backing on the edge (`state`, `evidence_refs[]`,
`finding_ids[]`, `timestamp`). Nothing renders without a citation.

| Class | Line | Marker | Token | Derivation |
|---|---|---|---|---|
| OBSERVED | solid 1px | — | `--nx-rel-observed` | API `state=OBSERVED`, 1 evidence ref |
| SUPPORTED | solid 2px | ◆ | `--nx-rel-supported` | `state=OBSERVED` **and** ≥2 distinct refs |
| INFERRED | dashed | ◇ | `--nx-rel-inferred` | API `state=SUPPORTED` (engine-derived, never observed) |
| POSSIBLE | dotted | ? | `--nx-rel-possible` | `state=POSSIBLE` / candidate |
| UNKNOWN / GAP | broken neutral | ? | `--nx-rel-gap` | `state=NOT_OBSERVED` |
| CONTRADICTED | struck | ⊘ | `--nx-rel-contradicted` | negative evidence |

**Direction rule:** an arrowhead is drawn *only* when the edge carries an ordering fact
(a timestamp, or an ordering relation: SPAWNED / EXECUTED / CREATED / WROTE / MODIFIED /
TRIGGERED / CONNECTED_TO / AUTHENTICATED_TO). Everything else renders undirected.

**Removed:** the previous implementation forced every primary-path edge to a solid glowing
amber arrow regardless of backing — it asserted confirmed causality the backend never claimed.
Primary-path membership now changes **emphasis only** (width / opacity) and can never upgrade
an edge's class, line style or direction.

---

## 4. Epistemic vocabulary (locked — the product differentiator)

`◆ EVIDENCE PRESENT` · `◇ NO EVIDENCE` · `? UNKNOWN` · `○ NOT RUN` · `⊘ CAPABILITY UNAVAILABLE`

Tokens: `--nx-ep-present / -none / -unknown / -notrun / -nocap` (+ `-bg`, `-bd`).

---

## 5. Component grammar delivered

| Component | Behaviour |
|---|---|
| Evidence node | circular disc: type token inside, epistemic ring (dashed when NOT_OBSERVED), disposition dot top-right, finding-count badge top-left, label + epistemic state beneath, double ring reserved for aggregates |
| Graph camera | drag-to-pan, on-canvas vertical nav rail (zoom in / out / fit / reset), keyboard `←↑→↓` `+` `−` `0`; **mouse wheel deliberately does not zoom** (owner request) |
| Narrative rail | 240–260px chronological rail built from `graph.timeline` — real timestamp, relation, endpoints, epistemic class and the API's own `reason`; `◇ NO ORDERED EVIDENCE` block when the backend ordered nothing |
| Evidence Inspector | key/value facts straight from `/inspector` and `/attack-graph`; nothing displayed that is not in the response |
| INVESTIGATE actions | interactive **only** when the backend sets `available: true` with a pivot; everything else is genuinely disabled and labelled `⊘ CAPABILITY UNAVAILABLE` |
| Coverage diagnostics | collapsed drawer; only evidence + telemetry coverage stay visible |
| Relationship legend | persistent strip — the caveat is carried by the grammar, not by a caption |
| Provenance attribution | eyebrow pill (was a 90px disc that long labels overflowed) |

---

## 6. Accessibility verification (measured, not asserted)

Contrast ratios computed against the surface each token actually renders on.

**Dark on `#121721`:** text 16.4 · text-dim 12.1 · muted 7.0 · faint 5.1 · accent 8.4 ·
focus 8.4 · critical 9.5 · high 10.6 · medium 13.6 · low 14.2 · ep-present 7.1 · rel-observed 7.0
**Light on `#FFFFFF`:** text 17.9 · text-dim 7.6 · faint 5.7 · accent 5.0 · critical 8.3 ·
high 5.5 · medium 5.3 · low 6.7
**Priority chips (fill vs its own foreground ink):** dark — P1 5.1, P2 6.9, P3 10.1, P4 7.8,
P5 7.5. Light — P1 4.8 (white ink), P2 5.1, P3 6.2, P4 4.9 (dark ink), P5 4.8 (white ink).

All ≥ 4.5:1. Three token values were changed *because* the measurement failed
(dark `--nx-faint` 3.77→5.13, light accent 3.19→5.02, light priority foreground per rank).

---

## 7. Files changed

**Backend**
- `detection_content/telemetry/windows_security_dsm.py` — `_windows_basename()`; `process.name` is the executable name, full path stays in `process.executable_path`
- `services/dashboard_lenses.py` — `resolve_tenant_scope()`; `_scope()` is tenant-authorized, not ownership-gated
- `routers/incidents.py` — honest-empty for anonymous, `assignment` filter, cross-tenant denial on `customer`
- `services/evidence_inspector/service.py` — `_ACTION_PIVOTS` + `_decorate_action()`
- `tests/test_xdr_mss.py`, `tests/test_xdr_dashboard.py`, `tests/test_xdr_incident_queue.py` — authenticate + `doc_type` seeds
- `tests/test_iteration_81_review.py` — new acceptance module (added by the testing agent)

**Frontend**
- `nx/nx-theme.css` **(new)** — the complete dual-theme token system
- `nx/nx-tokens.css`, `nx/nx-epistemic.css`, `nx/NxChip.jsx`
- `XdrShell.jsx` — theme state + toggle
- `xdr-console.css`, `nx/nx-page.css`, `design/tokens.css`, `pages/incidents/queue-theme.css`, `pages/incidents/record/record-theme.css`
- `pages/incidents/record/tabs/AttackGraphTab.jsx` — grammar, nodes, camera, rail, drawer, pivots
- `pages/incidents/record/tabs/ReportTab.jsx` — full token migration (was a white slab in dark mode)
- `components/EvidenceInspector.jsx`, `design/SharedEvidenceInspector.jsx`, `components/chips/index.jsx`
- `pages/XdrIncidentsPage.jsx`, `pages/incidents/PriorityStrip.jsx`, `pages/incidents/IncidentPreviewDrawer.jsx`
- `pages/XdrIncidentDetailPage.jsx` — passes `onNavigateTab` for inspector pivots

---

## 8. Explicitly NOT delivered in this batch

Stated plainly so the owner review is not misled:

1. **12-tab regrouping** of the incident record into 4 groups with counts — designed, not built.
2. **Verdict arithmetic matrix** (contributor-by-contributor derivation) — designed, not built.
3. **MSS Dashboard and Investigation Workspace layout restructure** — they inherited the token
   system and are theme-correct, but their information hierarchy is unchanged.
4. **Aggregate / count-badge collapsed nodes** — the rendering grammar exists; the backend
   projection emits no aggregate members, so nothing is collapsed (no fabricated density).
5. **IKG write path** — owner deferred: judge presentation first.
6. Report tab narration takes ~8.8s end-to-end (LLM narration gateway); it renders a loading
   state until then.
