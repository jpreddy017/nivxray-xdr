/**
 * LabV2 · self-contained CSS scoped to `.labv2`.
 * Extracted verbatim from the approved HTML prototype
 * (`nivxray-lab-ui.html`) plus the enhancement-pass additions
 * (sticky summary, intake, hover popovers, demo badge, animated
 * active stage node).
 */
export const LABV2_CSS = `
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
  --shadow-1:none;--shadow-2:0 8px 24px rgba(0,0,0,.5);
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
.labv2 .input-badge{font-family:var(--font-mono);font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;padding:2px 7px;border-radius:var(--r-sm);border:1px solid var(--border);color:var(--mint);background:var(--wash)}
.labv2 .demo-badge{font-family:var(--font-mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;padding:2px 6px;border-radius:var(--r-sm);border:1px dashed var(--border-strong);color:var(--fg3);background:transparent}
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
.labv2 .canvas{display:flex;flex-direction:column;min-width:0;min-height:0;background:var(--canvas);position:relative;overflow:hidden}
.labv2 .lensbar{display:flex;align-items:center;gap:var(--s1);height:40px;flex:0 0 40px;padding:0 var(--s5);border-bottom:1px solid var(--border)}
.labv2 .lens-btn{padding:4px 10px;border-radius:var(--r-md);font-size:13px;color:var(--fg3);display:flex;align-items:center;gap:6px}
.labv2 .lens-btn .k{font-family:var(--font-mono);font-size:10px;font-weight:600;color:var(--fg2);opacity:.75;padding:1px 4px;border:1px solid var(--border-strong);border-radius:var(--r-sm);letter-spacing:.02em}
.labv2 .lens-btn:hover{color:var(--fg);background:var(--sunken)}
.labv2 .lens-btn.on{color:var(--fg);font-weight:500;background:var(--wash)}
.labv2 .lens-btn.on .k{color:var(--mint);opacity:1;border-color:var(--mint)}

.labv2 .lens{display:none;flex:1;min-height:0;overflow-y:auto;padding:var(--s8) var(--s6);opacity:0;transition:opacity var(--dur-base) var(--ease)}
.labv2 .lens.on{display:block;opacity:1}
.labv2 .lens-head{margin-bottom:var(--s6)}
.labv2 .lens-head h2{font-size:18px;line-height:26px;font-weight:600;letter-spacing:-.01em}
.labv2 .lens-head p{font-size:13px;color:var(--fg3);margin-top:2px}

/* STORY */
.labv2 .prose{max-width:68ch}
.labv2 .prose p{font-size:15px;line-height:24px;margin-bottom:var(--s5);color:var(--fg)}
.labv2 .prose p.lede{font-size:18px;line-height:29px;font-weight:500;letter-spacing:-.01em;color:var(--fg)}
.labv2 .prose hr{border:none;border-top:1px solid var(--border);margin:var(--s5) 0}
.labv2 .prose .quiet, .labv2 .prose p.quiet{color:var(--fg2)}
.labv2 .ev{position:relative;font-family:var(--font-mono);font-size:11px;letter-spacing:.02em;padding:1px 5px;border:1px solid var(--border-strong);border-radius:var(--r-sm);color:var(--fg2);background:var(--raised);vertical-align:1px;margin:0 1px;cursor:pointer;transition:transform var(--dur-fast) var(--ease),border-color var(--dur-fast) var(--ease),color var(--dur-fast) var(--ease)}
.labv2 .ev:hover{border-color:var(--mint);color:var(--mint);transform:translateY(-1px)}
.labv2 .ev.sel{border-color:var(--mint);background:var(--wash);color:var(--mint)}
.labv2 .inline-link{color:var(--fg2);border-bottom:1px solid var(--border-strong);font-size:13px;font-family:var(--font-mono);text-decoration:none}
.labv2 .inline-link:hover{color:var(--mint);border-color:var(--mint)}
.labv2 .story-foot{margin-top:var(--s8);padding-top:var(--s5);border-top:1px solid var(--border);max-width:68ch;display:flex;gap:var(--s6)}
.labv2 .story-foot .stat{flex:1;padding:var(--s2);border-radius:var(--r-md);text-align:left;transition:background var(--dur-fast) var(--ease)}
.labv2 .story-foot .stat:hover{background:var(--sunken)}
.labv2 .story-foot .v{font-size:20px;font-weight:600;letter-spacing:-.02em;margin-top:2px}

/* Sticky story summary */
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
.labv2 .n-box.sel{stroke:var(--mint);stroke-width:2}
.labv2 .graph-node:hover .n-box{stroke:var(--mint)}
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
.labv2 .tempty{border:1px dashed var(--border);border-radius:var(--r-lg);padding:var(--s3);font-family:var(--font-mono);font-size:11px;color:var(--fg3);text-align:center;line-height:16px;max-width:820px}
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

/* Intake */
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

/* Evidence hover popover */
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

/* Intake strip · new spec (INPUT label · AUTO INVESTIGATE + DECODE + CLEAR) */
.labv2 .intake-strip{border-bottom:1px solid var(--border);background:var(--canvas);padding:var(--s5) var(--s5) var(--s4)}
.labv2 .intake-strip .intake-head{display:flex;align-items:center;justify-content:space-between;gap:var(--s4);margin-bottom:var(--s3)}
.labv2 .intake-strip .intake-title{display:flex;align-items:baseline;gap:var(--s3)}
.labv2 .intake-strip .pulse-dot{width:8px;height:8px;border-radius:50%;background:var(--mint);align-self:center;box-shadow:0 0 0 3px var(--wash);animation:pulseStage 1.8s var(--ease) infinite}
.labv2 .intake-strip .intake-label{font-family:var(--font-mono);font-size:13px;font-weight:600;letter-spacing:.16em;color:var(--fg)}
.labv2 .intake-strip .intake-count{font-size:12px;color:var(--fg3);letter-spacing:.04em}
.labv2 .intake-strip .intake-cta{display:flex;align-items:center;gap:var(--s2)}
.labv2 .intake-strip .cta{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--r-md);font-family:var(--font-mono);font-size:11.5px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;border:1px solid transparent;transition:background var(--dur-fast) var(--ease),border-color var(--dur-fast) var(--ease),color var(--dur-fast) var(--ease),opacity var(--dur-fast) var(--ease);cursor:pointer;white-space:nowrap}
.labv2 .intake-strip .cta .ico{font-size:13px;line-height:1;color:currentColor}
.labv2 .intake-strip .cta.primary{background:var(--mint);color:var(--fg-inv);border-color:var(--mint);box-shadow:0 0 0 1px var(--mint) inset,0 4px 14px -4px var(--mint)}
.labv2 .intake-strip .cta.primary:hover:not(:disabled){filter:brightness(1.05)}
.labv2 .intake-strip .cta.secondary{background:transparent;color:var(--mint);border-color:var(--mint)}
.labv2 .intake-strip .cta.secondary:hover:not(:disabled){background:var(--wash)}
.labv2 .intake-strip .cta.ghost{background:transparent;color:var(--fg3);border-color:var(--border-strong)}
.labv2 .intake-strip .cta.ghost:hover:not(:disabled){color:var(--crit);border-color:var(--crit)}
.labv2 .intake-strip .cta:disabled{opacity:.35;cursor:not-allowed}

.labv2 .intake-strip .intake-frame{position:relative;border:1px solid var(--border);border-radius:var(--r-lg);background:var(--raised);transition:border-color var(--dur-fast) var(--ease)}
.labv2 .intake-strip .intake-frame:focus-within{border-color:var(--mint)}
.labv2 .intake-strip textarea{width:100%;min-height:120px;max-height:280px;background:transparent;color:var(--fg);border:none;padding:var(--s4) 84px var(--s4) var(--s4);font-family:var(--font-mono);font-size:13px;line-height:22px;resize:vertical;outline:none}
.labv2 .intake-strip textarea::placeholder{color:var(--fg3)}
.labv2 .intake-strip .intake-corner{position:absolute;top:8px;right:8px;display:flex;flex-direction:column;gap:4px}
.labv2 .intake-strip .icon-btn{width:26px;height:26px;display:grid;place-items:center;border-radius:var(--r-sm);border:1px solid var(--border);background:var(--canvas);color:var(--fg3);font-size:12px;cursor:pointer;transition:border-color var(--dur-fast) var(--ease),color var(--dur-fast) var(--ease)}
.labv2 .intake-strip .icon-btn:hover:not(:disabled){color:var(--mint);border-color:var(--mint)}
.labv2 .intake-strip .icon-btn:disabled{opacity:.35;cursor:not-allowed}
.labv2 .intake-strip .intake-err{margin-top:var(--s2);font-family:var(--font-mono);font-size:11px;color:var(--crit)}


/* Executive card + grid */
.labv2 .exec-card{border:1px solid var(--border);border-radius:var(--r-xl);background:var(--raised);padding:var(--s4) var(--s5);max-width:960px}
.labv2 .exec-row{display:flex;gap:var(--s6);flex-wrap:wrap}
.labv2 .exec-cell{flex:1;min-width:150px}
.labv2 .exec-verdict{font-size:18px;font-weight:600;letter-spacing:-.01em;color:var(--crit);margin-top:4px}
.labv2 .exec-val{font-size:14px;font-weight:500;color:var(--fg);margin-top:4px}
.labv2 .exec-reason{margin-top:var(--s4);padding-top:var(--s3);border-top:1px solid var(--border);font-size:13px;line-height:19px;color:var(--fg2)}
.labv2 .exec-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:var(--s5);max-width:960px;margin-top:var(--s6)}
.labv2 .exec-block{border:1px solid var(--border);border-radius:var(--r-lg);padding:var(--s4);background:var(--raised)}
.labv2 .exec-block .lbl{margin-bottom:var(--s3);display:block}
.labv2 .exec-line{display:grid;grid-template-columns:auto 1fr;gap:var(--s3);align-items:baseline;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px;line-height:18px;color:var(--fg)}
.labv2 .exec-line:last-child{border-bottom:none}
.labv2 .exec-line .t{font-size:13px}
.labv2 .exec-line .e{display:inline-flex;gap:3px;margin-left:var(--s2);flex-wrap:wrap}
.labv2 .exec-line .g{font-size:12px;padding-top:1px}
.labv2 .exec-line .w{font-family:var(--font-mono);font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--crit);padding-top:1px}
.labv2 .exec-line .w.later{color:var(--fg3)}
.labv2 .ioc-kind{font-family:var(--font-mono);font-size:10.5px;letter-spacing:.06em;color:var(--fg3);padding:1px 6px;border:1px solid var(--border);border-radius:var(--r-sm);background:var(--canvas)}
.labv2 .exec-foot{margin-top:var(--s6);max-width:960px}

/* OSINT · IOC intelligence */
.labv2 .ioc-list{display:flex;flex-direction:column;gap:var(--s3);max-width:960px}
.labv2 .ioc-card{border:1px solid var(--border);border-radius:var(--r-lg);background:var(--raised);padding:var(--s4)}
.labv2 .ioc-card .ioc-h{display:flex;align-items:center;gap:var(--s3);margin-bottom:var(--s2)}
.labv2 .ioc-card .ioc-value{font-size:13px;font-weight:500;color:var(--fg)}
.labv2 .ioc-meta{display:flex;gap:var(--s5);font-family:var(--font-mono);font-size:11px;color:var(--fg3);margin-bottom:var(--s3);flex-wrap:wrap}
.labv2 .ioc-meta b{color:var(--fg2);font-weight:500}
.labv2 .ioc-providers{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:var(--s2)}
.labv2 .ioc-prov{display:flex;align-items:baseline;gap:6px;padding:6px var(--s3);border:1px solid var(--border);border-radius:var(--r-md);background:var(--canvas);font-size:12px}
.labv2 .ioc-prov .prov-name{font-weight:500;color:var(--fg)}
.labv2 .ioc-prov .prov-state{font-family:var(--font-mono);font-size:10.5px;color:var(--fg3);margin-left:auto}
.labv2 .ioc-prov.hit .prov-state{color:var(--crit)}
.labv2 .ioc-prov.hit{border-color:var(--crit)}
.labv2 .ioc-prov .prov-detail{font-family:var(--font-mono);font-size:10.5px;color:var(--fg3);width:100%;margin-top:2px}
.labv2 .ioc-foot{margin-top:var(--s3);display:flex;align-items:center}

@media (max-width:1400px){.labv2 .body{grid-template-columns:var(--spine) 1fr 320px}}
@media (max-width:1180px){.labv2 .body{grid-template-columns:56px 1fr 320px}.labv2 .spine .txt,.labv2 .spine > .lbl{display:none}.labv2 .stage{grid-template-columns:24px;justify-content:center;padding:0}.labv2 .stage .txt{padding-bottom:26px}.labv2 .stage .rail{height:34px}}
@media (max-width:900px){.labv2 .body{grid-template-columns:56px 1fr}.labv2 .findings{display:none}.labv2 .tactics{grid-template-columns:repeat(2,1fr)}}
@media (prefers-reduced-motion:reduce){.labv2 *{transition-duration:0ms!important;animation:none!important}}
`;
