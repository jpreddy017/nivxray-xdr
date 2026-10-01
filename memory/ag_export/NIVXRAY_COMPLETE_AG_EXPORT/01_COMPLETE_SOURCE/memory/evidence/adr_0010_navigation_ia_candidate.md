# ADR-0010 · Evidence Pile · Top Navigation & Information Architecture (candidate)

**Status:** Not yet drafted. Evidence accumulating from 2026-02-28
operator feedback.

**Signals collected so far:**

1. **Top-nav reorganization (2026-02-28)** — operator proposed collapsing
   the 9-tab top nav to a coherent 7-tab shape:
   `WORKSPACE · LAB · TRAJECTORY · BATCH · HEATMAP · TOOLS · LEARN · ADMIN`
   (down from `WORKSPACE · AUTO INVESTIGATE · TRAJECTORY · BATCH · HEATMAP ·
   DOCUMENTS · NIVXFORGE · TOOLS · LEARN`).

2. **DOCUMENTS → ADMIN move (2026-02-28)** — operator confirmed a
   consistent decision across two messages: Documents should not be a
   top-level tab; move it inside Admin alongside Admin Panel, Training
   Inbox, Model Studio, Sample Library.

3. **Adaptive Pipeline live progress (2026-02-28)** — operator suggested
   showing analysts a mini progress indicator DURING the request
   (`✓ Input Detection · ✓ Decode · ✓ PowerShell Analysis · …`) rather
   than only surfacing the completed `stages_executed` afterwards.
   The CIM already carries the machine-readable `stages_executed` list;
   this is a progressive-rendering UX addition, not a schema change.

4. **Tools menu breakdown (2026-02-28)** — operator sketched:
   `Tools · Command Analyzer · Threat Intelligence · Threat Hunting ·
    IOC Extractor · URL Analyzer · Hash Lookup · YARA Tools · Sigma Tools ·
    Encoders / Decoders · More…`.
   Caveat: if Command Analyzer is the primary analyst-differentiator,
   it may belong under `Lab`, not `Tools`. Decision deferred.

5. **Learn menu breakdown (2026-02-28)** — operator sketched:
   `Learn · Practice Lab · Learner · Knowledge Base · Documentation ·
    Release Notes · Tutorials`. Rename `Docs` → `Documentation` for
   naming consistency.

6. **Rating comparison (2026-02-28)** — operator rated the proposed IA
   at **9.7/10**, up from the earlier ~6.8/10 for the pre-Lab layout.

**Why this is not folded into ADR-0009:**

ADR-0009 §3 explicitly says "No changes to Workspace pages" and "No
pixel-perfect UI redesign — the point is the *object*, not the pixels."
Reorganizing Workspace's top nav + moving Documents into Admin touches
Workspace pages and is a non-trivial IA change. Doing it inside ADR-0009
would break the locked small-scope promise.

**Rec priority (per operator 2026-02-28):**

- ADR-0007 Verdict Gating (⭐⭐⭐⭐⭐) — correctness before presentation
- Narrative Composer (⭐⭐⭐⭐☆) — analyst experience once CIM is live
- ADR-0010 (this) (⭐⭐⭐☆☆) — nav evolves, doesn't change correctness
- History section (⭐⭐⭐☆☆) — valuable but non-blocking

**Draft trigger:** operator explicit go-ahead. Do NOT auto-draft without it.
