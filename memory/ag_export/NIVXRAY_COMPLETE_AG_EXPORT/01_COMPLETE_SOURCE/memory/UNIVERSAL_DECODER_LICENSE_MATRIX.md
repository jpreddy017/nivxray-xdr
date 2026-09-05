# UNIVERSAL_DECODER_LICENSE_MATRIX.md

**P0-1B · Phase 1 · License compatibility matrix · owner-locked 2026-09-02.**

Companion documents: `UNIVERSAL_DECODER_SOURCE_INVENTORY.md`,
`UNIVERSAL_DECODER_COVERAGE_MATRIX.md`.
Scope contract: `/app/memory/P0_1B_SCOPE.md`.

**Purpose:** every harvestable source, its license, what NivXRay
is permitted to do with it, and the operational rules for Phase 2.

**Owner rule (LOCKED):**
> Preserve Apache-2.0 / MIT / GPL obligations. If GPL is
> incompatible, extract behavioural knowledge + test vectors +
> write a clean-room XDR-native implementation.

**Rule of thumb — three harvest tiers:**

- **Tier 1 · Code re-use permitted (with attribution)** —
  Apache-2.0, MIT, BSD-2/3-Clause, ISC, Unlicense, CC0.
- **Tier 2 · Knowledge + test-vector harvest only (clean-room
  reimplementation)** — GPL-2.0+, GPL-3.0+, AGPL, LGPL (when
  static-linked), CC BY-SA (share-alike), CC BY-NC (non-commercial).
- **Tier 3 · Documentation only** — Unspecified, "all rights
  reserved", proprietary.

---

## 1 · Per-source license classification

| Source | License | Tier | Code re-use | Knowledge re-use | Test-vector re-use | Runtime dependency | Notes |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| **CyberChef** (gchq) | Apache-2.0 (Crown Copyright) | **1** | ✅ (must preserve NOTICE) | ✅ | ✅ | ❌ (never bridge) | 401 ops. Reference-only at Phase 1; clean-room preferred for consistency. Static-safe subset only. |
| **Invoke-Obfuscation** (danielbohannon) | Apache-2.0 | **1** | ✅ (preserve NOTICE) | ✅ | ✅ | ❌ (PowerShell runtime dep + offensive) | OFFENSIVE tool; every technique it produces is a case we must handle. Do NOT execute the module — treat as documentation + generator to build vectors offline. |
| **Invoke-DOSfuscation** (danielbohannon) | Apache-2.0 | **1** | ✅ (preserve NOTICE) | ✅ | ✅ | ❌ | OFFENSIVE, same rule. Test harness may be used offline to *generate* labelled samples; do not import at runtime. |
| **PowerDecode** (Malandrone) | **GPL-3.0** | **2** | ❌ | ✅ | ✅ | ❌ (incompatible + dynamic) | Knowledge/test-vectors only. Clean-room reimplementation mandatory. GPL contagion risk if any snippet is copied. |
| **PSDecode** (R3MRUM) | **UNSPECIFIED** (no LICENSE file) | **3** | ❌ | 🟡 (public documentation only) | ❌ (safest — do not import) | ❌ | Treat as "all rights reserved" until author clarifies. Study public README + published papers only. |
| **CMD-DeObfuscator** (bobbystacksmash) | BSD 3-Clause | **1** | ✅ (preserve LICENSE + copyright notice; "no endorsement" clause) | ✅ | ✅ | ❌ (Node.js runtime dep) | The most relevant Plane-B-CMD reference. Clean-room preferred but direct algorithm re-use permissible with BSD attribution. |
| **batch_deobfuscator** (DissectMalware) | MIT | **1** | ✅ (preserve LICENSE) | ✅ | ✅ | ❌ (Python — could import, but per scope: **NO runtime bridge**) | Attribution required. |
| **batch_deobfuscator** (TargetPackage fork) | MIT | **1** | ✅ (preserve LICENSE from both original + fork) | ✅ | ✅ | ❌ | Fork adds features; preserve both attributions. |
| **batch_deobfuscator** (gdesmar fork) | MIT | **1** | ✅ (preserve LICENSE from both) | ✅ | ✅ | ❌ | Same rules. |
| **BatchAlchemy** | BSD 3-Clause | **1** | ✅ (preserve LICENSE + notice) | ✅ | ✅ | ❌ (Tree-sitter native binding is heavy — do not adopt) | Tree-sitter grammar is the interesting artifact. |
| **LOLBAS Project** | CC BY-SA-4.0 | **2** | ✅ (share-alike triggers if we redistribute the *catalogue*, not each entry as knowledge) | ✅ | ✅ | ❌ (already partially mirrored in `services/die/lolbas.py`) | Attribution required. Share-alike means any DERIVED CATALOGUE we publish must be CC BY-SA-4.0. Using it inside NivXRay as private knowledge is fine. |
| **GTFOBins** | CC BY-NC-SA-4.0 | **2** | 🟡 (NC — non-commercial; check NivXRay licensing model) | ✅ | ✅ | ❌ | The **NC** (non-commercial) clause is the risk. If NivXRay ships commercially, use knowledge only, don't redistribute the dataset. |
| **LOOBins** | MIT | **1** | ✅ | ✅ | ✅ | ❌ | For future Mach-O phase. |
| **MITRE ATT&CK STIX** | Apache-2.0 | **1** | ✅ (already integrated) | ✅ | ✅ | 🟡 (bundled) | Already deep in `backend/mitre_catalogue/`. |

---

## 2 · Detailed obligations per license family

### 2.1 · Apache-2.0
- Preserve `LICENSE` and `NOTICE` files verbatim in an `ATTRIBUTION/`
  folder inside the repository.
- State significant modifications.
- Do NOT use the licensor's trademarks (e.g., "CyberChef", "GCHQ",
  "Daniel Bohannon", "Malandrone") in a way that suggests endorsement.
- Grant covers patent claims necessarily infringed by the
  contribution (safe for these tools).

### 2.2 · MIT
- Preserve the copyright notice and permission notice verbatim in
  every source file that contains re-used code, or in a top-level
  `ATTRIBUTION/` file.
- No further obligations.

### 2.3 · BSD 3-Clause
- Preserve copyright notice, disclaimer, and the "no endorsement"
  clause.
- **CRITICAL:** neither the name of the copyright holder nor the
  names of contributors may be used to endorse products without
  written permission. Applies to CMD-DeObfuscator and BatchAlchemy.

### 2.4 · GPL-3.0 (PowerDecode)
- **Contagion rule:** any derivative work that links to GPL code
  becomes GPL-3.0 itself.
- NivXRay MUST NOT link to, import, or copy PowerDecode source.
- Knowledge (technique descriptions, published papers) is not
  copyrighted expression — free to study and reimplement clean-room.
- Test vectors (raw obfuscated inputs) are typically not
  copyrightable when they are minimal factual examples; when in
  doubt, regenerate our own equivalents (Invoke-Obfuscation /
  Invoke-DOSfuscation can produce many).

### 2.5 · CC BY-SA-4.0 (LOLBAS)
- Attribution required.
- **Share-alike:** if we redistribute the CATALOGUE (or a derivative
  catalogue) publicly, the redistribution must be CC BY-SA-4.0.
  Using it privately as a knowledge base inside NivXRay is
  permitted with attribution.

### 2.6 · CC BY-NC-SA-4.0 (GTFOBins)
- Attribution required.
- **Non-commercial:** if NivXRay ships commercially, we may only
  use GTFOBins as PRIVATE KNOWLEDGE (i.e. baked-in awareness that
  `perl` can spawn a shell), not as a redistributed catalogue.
- Prefer LOOBins-style MIT re-implementation for the Unix knowledge
  base.

### 2.7 · Unspecified / no LICENSE (PSDecode)
- Under U.S. and most jurisdictions' copyright law, unspecified
  license = "all rights reserved."
- Do NOT copy code.
- Reading the public README and published papers is permissible.
- Do NOT re-host source. Do NOT import as dependency.

---

## 3 · Ops rules for Phase 2 (Universal Decoder Engine implementation)

1. **NO runtime dependency on any external project.** The engine is
   XDR-owned. Bridges are forbidden regardless of license.
2. **Directory:** all attribution lives under
   `/app/backend/services/decoder/ATTRIBUTION/` (or top-level
   `ATTRIBUTION/` if broader). Files: `LICENSE.<source>.txt`,
   `NOTICE.<source>.txt` where applicable.
3. **File header:** every file inside `services/decoder/` that
   incorporates ideas from an external source MUST carry a comment:
   ```
   # NivXRay clean-room implementation.
   # Knowledge referenced from: <source> (<license>).
   # No code copied. Behavioural equivalence verified by test-vector
   # regression only.
   ```
4. **Do NOT combine GPL-derived knowledge with Apache/MIT/BSD code
   in a way that could be re-characterised as a derivative work
   under GPL.** In practice this means: keep the PowerDecode
   knowledge-harvest artifacts as *test vectors + technique
   descriptions*, not as source snippets.
5. **Trademark hygiene:** do NOT market or describe features as
   "CyberChef-compatible", "PowerDecode-compatible",
   "Invoke-Obfuscation-compatible" in a way that implies
   endorsement. Compatible-by-test-vector is fine; endorsement
   framing is not.
6. **Test vectors — raw command lines are facts, not expression.**
   Copying an obfuscated command line as an *input* to a test is
   safe. Copying source code that transforms it is licensed and
   subject to the tables above.
7. **Regeneration path:** where a license is restrictive, use
   Invoke-Obfuscation / Invoke-DOSfuscation (Apache-2.0) OFFLINE
   in an isolated environment to *regenerate our own* labelled
   test corpus. The generated commands are our own artifacts, not
   derivatives of the generator's source code.
8. **All command-line testing is STATIC** — the license status
   does not change this rule. Even Apache-2.0 tools like Invoke-*
   must NEVER be executed on production or CI: they are OFFENSIVE
   generators that must be run only inside an isolated environment
   solely to emit labelled samples.

---

## 4 · License-driven priority for Phase 2

Given the license landscape, the harvest priority order (highest
value / lowest legal friction first) is:

1. **Invoke-DOSfuscation** (Apache-2.0, generator) — regenerate
   thousands of labelled CMD samples in an offline environment.
   Direct feed for the tommy-aa.lol regression family.
2. **Invoke-Obfuscation** (Apache-2.0, generator) — same for
   PowerShell.
3. **batch_deobfuscator** (MIT) — study Python reference
   implementation; regenerate benign + malicious CMD vectors with
   labelled expected reconstruction.
4. **CMD-DeObfuscator** (BSD-3) — study the two-mode approach
   (delayed_expansion / expand_inline). Clean-room our own
   equivalent under `services/decoder/cmd/`.
5. **BatchAlchemy** (BSD-3) — study the Tree-sitter grammar as a
   spec; do NOT import Tree-sitter.
6. **CyberChef** (Apache-2.0) — extract test vectors for every
   static-safe operation. Study the "Magic" auto-classifier as an
   idea; clean-room our own.
7. **LOLBAS** (CC BY-SA-4.0) — expand
   `services/die/lolbas.py`; keep it private (no public
   redistribution triggers share-alike).
8. **PowerDecode** (GPL-3.0) — knowledge + published paper only.
   No code inspection beyond behavioural analysis.
9. **PSDecode** (Unspecified) — documentation only.

---

## 5 · Attribution file template

For each Tier-1 source whose test vectors or ideas we harvest,
Phase-2 must produce:

`/app/backend/services/decoder/ATTRIBUTION/<source>.md`

```
# <Source name>

Upstream:   <URL>
Version:    <commit / release>
License:    <SPDX identifier>

Copied?     No / Yes (files: ...)
Studied?    Yes — see docs/decoder/<source>_notes.md
Vectors?    N samples imported into tests/corpus/plane_<A|B>/<source>/

LICENSE (verbatim upstream):
<paste>
```

For Tier-2 sources (GPL / CC-SA-NC) the file additionally records:

```
Contamination risk: <describe>
Isolation rule:     <how our code stays clean-room>
```

---

## 6 · Summary

- **8 external sources classified.** 5 Tier-1 (Apache/MIT/BSD),
  2 Tier-2 (GPL/CC-SA-NC), 1 Tier-3 (unspecified).
- **Runtime dependency count remains 0.** By owner rule, this is
  non-negotiable.
- **Legal harvest path is clear for every source.** No blockers.
- **The most restrictive source (PowerDecode · GPL-3.0) is not
  needed for the tommy-aa.lol sample or the P0-1B primary target;
  it is a bonus knowledge source for the PowerShell Phase-2
  extension.**

**End of Phase 1 deliverables. Awaiting formal Phase-1 acceptance
before Phase-2 kick-off. STOPPED.**
