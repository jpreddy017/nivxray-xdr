# GATE 12 · UI/UX RELEASE QUALITY — TWO-THEME CORRECTNESS · **PASS**

Owner report: *"Light/Dark button is not applying for the entire
NivXForge EDR."* Owner instruction: fix it at the authoritative
design/token layer, no route-by-route CSS patching, then verify tokens,
persistence, contrast and BOTH themes visually on the running SPA.

## Root cause — two layers, both structural

1. **The EDR console declared its palette unconditionally dark.**
   `nivxforge.css` opened with `.nvf-console { --bg: #0A0C11; --text:
   #E7E9EF; … }` and there was **no light block at all**. The only light
   block in the app was `.xdr-console[data-nx-theme="light"]` in
   `nx/nx-theme.css`, which cannot reach `.nvf-console`. The toggle wrote
   `nx.theme`, flipped `data-nx-theme` and broadcast `nx-theme`
   correctly — and then nothing repainted, because no rule consumed the
   attribute inside `/edr/*`.

2. **A nested console reset the palette for its own subtree.**
   `NivXForgeConsole` renders the product chrome as
   `.nvf-console.nvf-product[data-nx-theme]` and the body as a SECOND
   element that is also `.nvf-console` (`.nvf-embedded`) with **no**
   `data-nx-theme`. Because the dark block is keyed on the class, the
   inner element re-declared every token back to dark. Measured live
   before the fix: outer `background: rgb(245,248,251)` (light) and inner
   `rgb(10,12,17)` (dark) **in the same render** — which is exactly why
   only the top bar changed and the whole workspace stayed dark.

3. Secondary: **38 literal colours in the two CSS files** and **38 more
   inline in the page JSX** (`style={{ color: "#ff9494" }}` etc.) painted
   over the tokens, so even a correct light block would have left
   dark-on-light text behind.

## Fix (design layer only — no page-level theming)

* `nivxforge.css`
  * the dark block gained the **semantic tokens the literals were
    standing in for**: `--surf-hover · --surf-active ·
    --surf-accent-soft · --surf-row-hover · --surf-row-sel · --surf-th ·
    --surf-chip · --mint-soft · --border-hover · --on-accent ·
    --ring-cyan · --sk-a · --sk-b · --link` and the state tints
    `--ok/warn/bad/info/att-{bd,bg}`;
  * ONE new light block —
    `.nvf-console[data-nx-theme="light"], .nvf-product[data-nx-theme="light"],
    [data-nx-theme="light"] .nvf-console` — the third selector is what
    stops a nested console from resetting the theme;
  * green stays reserved for verified-healthy, cyan for
    selection/action, amber for attention, red for refusal, violet for
    ATT&CK in both themes.
* `nvf-ops.css` + all EDR page JSX: every literal replaced by the token
  it stood for (`tools/nvf_theme_tokenise.py`,
  `tools/nvf_theme_inline_tokenise.py`, both idempotent).
  `grep -E "#[0-9a-fA-F]{3,8}"` over the two stylesheets now matches
  **only the two token declaration blocks**, and zero literals remain in
  the non-trajectory EDR JSX.
* `globals.css`: the document canvas follows `html[data-nx-theme]`, so a
  console shorter than the viewport no longer sits on the other theme.
* `NivXForgeConsole.jsx` and `XdrShell.jsx`: both now write the theme to
  `document.documentElement` **in an effect**, not only inside the
  toggle, so first paint after a reload is already correct. The
  Device Trajectory renderer was left alone — it already carried a real
  two-theme palette (`trajectory/ampModel.js` `DARK`/`LIGHT`).

## Evidence

**Design-token gate (new).** `scripts/nvf_contrast_audit.py` reads the
real values out of `nivxforge.css`, splits the dark and light blocks, and
measures every foreground against every surface in BOTH themes:
4 text tokens + 7 accents × 11 surfaces + 3 seam tiers.

```
$ python scripts/nvf_contrast_audit.py
0 contrast failure(s)
```

It **failed 68 pairs on first run** and those were real defects, not
gate noise — including the pre-existing dark theme, which had never been
measured: `--faint` was **2.46:1** on the canvas (metadata, timestamps,
`N/I` badges) and `--border` was **1.31:1** (table structure barely
visible). Token corrections, applied in the token layer for both themes:

| token | before | after | worst-case ratio after |
|---|---|---|---|
| dark `--muted` | `#78808F` | `#8C95A6` | 5.44:1 |
| dark `--faint` | `#4A5162` | `#7E8797` | 4.53:1 |
| dark `--border` | `#212736` | `#343D4F` | 1.50:1 |
| dark `--border-sf` | `#191E2A` | `#2A3242` | 1.27:1 |
| dark `--border-hover` | `#2C3547` | `#3C4557` | 1.70:1 |
| light `--mint` | `#047857` | `#046B4E` | 5.29:1 |
| light `--cyan` | `#0E7490` | `#0B6076` | 5.78:1 |
| light `--amber` | `#A85B08` | `#8F4D06` | 5.27:1 |
| light `--yellow` | `#8A6008` | `#7A5407` | 5.50:1 |
| light `--border` | `#C3CDDA` | `#AEBBCC` | 1.58:1 |
| light `--border-sf` | `#DCE3EC` | `#C3CDDA` | 1.30:1 |

Floors: text and accents **≥4.5:1** on every surface (accents are 9.4-10 px
bold, so they are held to the text floor, not the large-text one);
`--border` / `--border-hover` **≥1.4:1**; `--border-sf` **≥1.25:1** —
declared in the script as a *sub-frame divider inside an already framed
surface*, which is a stated two-tier seam model, not a lowered bar.

`scripts/nx_contrast_audit.py` (the XDR gate) re-run: **0 failures**, so
the shared platform theme was not disturbed.

**Build.** `yarn build` in `/app/apps/nivxray-xdr` → **PASS** (after the
token work, after the inline work, and after the contrast corrections).

**Live SPA verification** on the preview host, real login
(`admin@nivxray.com`), `localStorage.nx.theme` pre-set per run so the
FIRST paint is the theme under test (persistence, not just the toggle):

| surface | dark | light |
|---|---|---|
| Computers · 222 rows, KPI rail, status tokens, contextual pane | PASS | PASS |
| Computers · fail-closed `FLEET UNAVAILABLE / TENANT_REQUIRED` refusal | PASS | PASS |
| Sensor Downloads · package cards, artifact rows, silent-install code block | PASS | PASS |
| Add device · 7-step stepper, radio group, disabled `Generate enrolment`, `NO CUSTOMER SELECTED` refusal | — | PASS |
| Device workspace · Overview + `DEVICE UNAVAILABLE` state | — | PASS |
| Device workspace · Trajectory (207,567 observations, navigator band, lane canvas, empty-window statement) | — | PASS |
| Device workspace · Command Intelligence (metric rail, 142 rows, `EVALUATED NO MATCH` tokens) | — | PASS |
| Events · `NOT IMPLEMENTED` hatched surface with its reason | — | PASS |
| Sidebar · active / hover / disabled `N/I` rows | PASS | PASS |

Element-level proof that the nested-console defect is closed (same page,
light theme):

```
[{'cls': 'nvf-console nvf-product theme-light', 'bg': 'rgb(245, 248, 251)'},
 {'cls': 'nvf-console nvf-embedded',            'bg': 'rgb(245, 248, 251)'}]
```

## Honest residue

* Captures were taken at 1920×800. The two responsive breakpoints
  (`≤1280`, `≤1080`, contextual pane → stacked) were **not** photographed
  in both themes.
* The XDR console's own surfaces were not re-reviewed in this pass — its
  gate (`nx_contrast_audit.py`) is green and its theme block was
  untouched, but "every XDR surface in both themes" is a different,
  larger review.
