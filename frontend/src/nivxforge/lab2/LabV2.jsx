/**
 * NivXRay · Lab v2 — Investigation Workspace (ADR-0022 · §8)
 *
 * PURE PROJECTION OF THE CIO.
 * All content in every panel is projected from `view` (produced by
 * `labv2.projector.js` from the Canonical Investigation Object).
 * When no CIO is active, the projector returns the coherent demo
 * case (`ev-01…ev-11`) so the workspace still renders.
 *
 * This file owns UI only: layout, styles, interactions, and the 13
 * enhancement passes (A–M). It knows nothing about backend routes or
 * pipeline logic.
 */
import React, { useCallback, useEffect, useRef, useState } from "react";
import { LABV2_CSS } from "./labv2.styles";
import { listLenses, getLensByShortcut } from "./LensRegistry";

// ═══════════════════════════════════════════════════════════════
// Small primitives
// ═══════════════════════════════════════════════════════════════
function EvChip({ id, selected, onEnter, onLeave, onClick }) {
  return (
    <button
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
}

/**
 * Renders a paragraph whose text may contain evidence markers of the
 * form "ev-XX" or "EV_XX" — every such token is replaced with an
 * <EvChip>. Everything else is inert text.
 */
function StoryParagraph({ text, selEv, onEnter, onLeave, onClick, kind }) {
  const parts = String(text || "").split(/(ev[-_]\d{2,3}|EV_\d{2,3})/g);
  return (
    <p className={kind === "quiet" ? "quiet" : kind === "lede" ? "lede" : undefined}>
      {parts.map((p, i) => {
        if (/^(ev[-_]|EV_)\d{2,3}$/.test(p)) {
          const id = p.replace("_", "-").toLowerCase();
          return (
            <EvChip
              key={i}
              id={id}
              selected={selEv === id}
              onEnter={onEnter}
              onLeave={onLeave}
              onClick={onClick}
            />
          );
        }
        return <React.Fragment key={i}>{p}</React.Fragment>;
      })}
    </p>
  );
}

// ═══════════════════════════════════════════════════════════════
// LabV2 main component
// ═══════════════════════════════════════════════════════════════
export default function LabV2({ view, onAnalyze, isAnalyzing = false, analyzeError = "" }) {
  const [theme, setTheme] = useState("nightwatch");
  const [density, setDensity] = useState("comfortable");
  const [lens, setLens] = useState("exec");
  const [selEv, setSelEv] = useState(view?.defaultEv || "ev-07");
  const [pop, setPop] = useState(null);
  const [showSticky, setShowSticky] = useState(false);
  const [intake, setIntake] = useState("");
  const [copyOk, setCopyOk] = useState(false);
  const fileRef = useRef(null);

  const scrollPos = useRef({});
  const lensRefs = {
    exec: useRef(null),
    source: useRef(null),
    story: useRef(null),
    behavior: useRef(null),
    attack: useRef(null),
    osint: useRef(null),
    raw: useRef(null),
  };

  // Reset selected evidence when the view (=CIO) changes.
  useEffect(() => {
    if (view?.defaultEv) setSelEv(view.defaultEv);
  }, [view?.defaultEv]);

  // Enhancement C · preserve scroll per lens
  const showLens = useCallback(
    (target) => {
      if (target === lens) return;
      const outEl = lensRefs[lens]?.current;
      if (outEl) scrollPos.current[lens] = outEl.scrollTop;
      setLens(target);
      requestAnimationFrame(() => {
        const inEl = lensRefs[target]?.current;
        if (inEl) inEl.scrollTop = scrollPos.current[target] || 0;
      });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [lens]
  );

  // Keyboard shortcuts driven by the Lens Registry (ADR-0025).
  useEffect(() => {
    const h = (e) => {
      const tag = e.target?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;
      const lens = getLensByShortcut(e.key);
      if (lens) {
        showLens(lens.id);
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

  const scrollToStoryEv = useCallback((id) => {
    const el = lensRefs.story.current?.querySelector(`[data-ev="${id}"]`);
    if (el && el.scrollIntoView) el.scrollIntoView({ behavior: "smooth", block: "center" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onEvClick = useCallback(
    (id) => {
      setSelEv(id);
      if (lens === "story") scrollToStoryEv(id);
    },
    [lens, scrollToStoryEv]
  );

  const onEvEnter = useCallback((id, target) => {
    const rect = target.getBoundingClientRect();
    setPop({ id, top: rect.top - 8, left: rect.left });
  }, []);
  const onEvLeave = useCallback(() => setPop(null), []);

  const onStoryScroll = useCallback(() => {
    const el = lensRefs.story.current;
    if (!el) return;
    setShowSticky(el.scrollTop > 96);
  }, []);

  const submitInvestigate = useCallback(() => {
    if (!intake.trim() || isAnalyzing) return;
    // No mode override — let the Input Understanding Engine
    // (backend /api/understand) decide which pipeline runs.
    onAnalyze?.(intake);
  }, [intake, isAnalyzing, onAnalyze]);

  const copyIntake = useCallback(async () => {
    if (!intake) return;
    try {
      await navigator.clipboard.writeText(intake);
      setCopyOk(true);
      setTimeout(() => setCopyOk(false), 1200);
    } catch {
      /* noop */
    }
  }, [intake]);

  const clearIntake = useCallback(() => setIntake(""), []);

  const onUpload = useCallback((e) => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => setIntake(String(reader.result || ""));
    reader.readAsText(f);
    e.target.value = "";
  }, []);

  // Guard: view is always provided (Lab2InvestigateRenderer wraps).
  if (!view) return null;

  const sel = view.ev[selEv] || Object.values(view.ev)[0] || { s: "", t: "", c: "", sup: [] };
  const evChipProps = { selEv, onEnter: onEvEnter, onLeave: onEvLeave, onClick: onEvClick };

  return (
    <div className="labv2" data-theme={theme} data-density={density} data-testid="labv2-root">
      <style>{LABV2_CSS}</style>

      {/* ── TOP BAR ─────────────────────────────────────────── */}
      <header className="topbar">
        <div className="mark" data-testid="labv2-brand">
          <span className="logo-tile" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 20 V4 L20 20 V4" />
            </svg>
          </span>
          <span className="brand-copy">
            <span className="wordmark">NivX<span className="ray">Ray</span> <span className="lab-tag">Lab 2.0</span></span>
          </span>
        </div>
        <div className="case-id">
          {view.hasCase ? (
            <>
              <span className="mono">{view.caseId}</span>
              <span className="sep">·</span>
              <span data-testid="labv2-case-file">{view.file}</span>
              <span className="sep">·</span>
              <span className="mono">{view.time}</span>
              <span className="sep">·</span>
              <span className="input-badge" data-testid="labv2-input-type-badge">{view.inputType}</span>
            </>
          ) : (
            <span className="mono" style={{ color: "var(--fg3)", letterSpacing: ".08em" }} data-testid="labv2-idle-label">
              NO ACTIVE CASE · PASTE INPUT BELOW
            </span>
          )}
        </div>
        <div className="spacer" />
        {view.hasCase ? (
          <div className="verdict-pill" data-testid="labv2-verdict-pill">
            ▲ {view.verdict.label}
            <span className="conf">{view.verdict.dots} {view.verdict.bucket}</span>
          </div>
        ) : null}
        <div className="spacer" />
        <button className="tb-btn" data-testid="labv2-palette" onClick={() => alert("Command palette — every lens, entity, technique and action is reachable here.")}>⌘K</button>
        <button className="tb-btn" data-testid="labv2-density" onClick={() => setDensity((d) => (d === "compact" ? "comfortable" : "compact"))}>
          {density === "compact" ? "COMFORTABLE" : "COMPACT"}
        </button>
        <button className="tb-btn" data-testid="labv2-theme" onClick={() => setTheme((t) => (t === "nightwatch" ? "daylight" : "nightwatch"))}>
          {theme === "nightwatch" ? "☾ NIGHTWATCH" : "☀ DAYLIGHT"}
        </button>
        <div className="avatar">JP</div>
      </header>

      <div className="body">
        {/* ── CASE SPINE ─────────────────────────────────────── */}
        <nav className="spine" data-testid="labv2-spine">
          <div className="lbl">Case spine</div>
          {view.stages.map((s) => (
            <button key={s.id} className={`stage ${s.state}`} data-testid={`stage-${s.id}`} onClick={() => showLens(s.lens)}>
              <div className="rail"><span className="node" /></div>
              <div className="txt"><div className="name">{s.name}</div><div className="meta">{s.meta}</div></div>
            </button>
          ))}
        </nav>

        {/* ── CANVAS ──────────────────────────────────────────── */}
        <main className="canvas">
          {/* Persistent Intake · designed to match the operator's spec. */}
          <div className="intake-strip" data-testid="labv2-intake">
            <div className="intake-head">
              <div className="intake-title">
                <span className="pulse-dot" aria-hidden />
                <span className="intake-label">INPUT</span>
                <span className="intake-count mono">{intake.length} chars</span>
              </div>
              <div className="intake-cta">
                <button
                  className="cta primary"
                  data-testid="labv2-analyze"
                  onClick={submitInvestigate}
                  disabled={!intake.trim() || isAnalyzing}
                  title="Investigate — the tool auto-detects Cisco XDR · CrowdStrike · Defender · Sentinel · QRadar · Splunk · Sysmon · Windows Event · PowerShell · CMD · Bash · Base64 · STIX · YARA · Email headers · IOC lists · unknown"
                >
                  <span className="ico">✦</span>
                  <span>{isAnalyzing ? "INVESTIGATING…" : "INVESTIGATE"}</span>
                </button>
                <button
                  className="cta ghost"
                  data-testid="labv2-clear"
                  onClick={clearIntake}
                  disabled={!intake}
                  title="Clear the input"
                >
                  <span className="ico">🗑</span>
                  <span>CLEAR</span>
                </button>
              </div>
            </div>
            <div className="intake-frame">
              <textarea
                data-testid="labv2-intake-textarea"
                placeholder="Paste anything — PowerShell, base64/hex, AES/RC4 ciphertext, JWT, PE/ELF headers, gzip/bzip2/LZMA, obfuscated JS, defanged IOCs, Cisco XDR / CrowdStrike / Defender / Sentinel / QRadar / Splunk / Sysmon / Windows Event JSON, STIX bundles, YARA / Sigma output, email headers, IOC lists…"
                value={intake}
                onChange={(e) => setIntake(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                    e.preventDefault();
                    submitInvestigate();
                  }
                }}
              />
              <div className="intake-corner">
                <input
                  ref={fileRef}
                  type="file"
                  accept=".txt,.log,.json,.xml,.csv,.md,.ps1,.sh,.bat,.evtx,.stix,.yar,.yara,.eml"
                  onChange={onUpload}
                  style={{ display: "none" }}
                  data-testid="labv2-file-input"
                />
                <button className="icon-btn" data-testid="labv2-copy" onClick={copyIntake} disabled={!intake} title="Copy input">
                  {copyOk ? "✓" : "⎘"}
                </button>
                <button className="icon-btn" data-testid="labv2-upload" onClick={() => fileRef.current?.click()} title="Upload file">
                  ⤒
                </button>
                <button className="icon-btn" data-testid="labv2-delete" onClick={clearIntake} disabled={!intake} title="Delete input">
                  🗑
                </button>
              </div>
            </div>
            {analyzeError ? <div className="intake-err" data-testid="labv2-analyze-err">{analyzeError}</div> : null}
          </div>

          <div className="lensbar" role="tablist">
            {listLenses().map((b) => (
              <button
                key={b.id}
                className={`lens-btn${lens === b.id ? " on" : ""}`}
                data-testid={`lens-btn-${b.id}`}
                onClick={() => showLens(b.id)}
              >
                <span className="k">{b.shortcut}</span>{b.title}
              </button>
            ))}
          </div>

          {/* EXECUTIVE SUMMARY · the correlating final tab */}
          <section
            className={`lens${lens === "exec" ? " on" : ""}`}
            id="exec"
            ref={lensRefs.exec}
            data-testid="lens-exec"
          >
            <div className="lens-head">
              <h2>Executive Summary</h2>
              <p>Analyst-style correlation across every panel of the investigation.</p>
            </div>

            <div className="exec-card">
              <div className="exec-row">
                <div className="exec-cell">
                  <div className="lbl">Verdict</div>
                  <div className="exec-verdict">▲ {view.verdict.label}</div>
                </div>
                <div className="exec-cell">
                  <div className="lbl">Confidence</div>
                  <div className="exec-val">{view.verdict.dots} <span className="mono">{view.verdict.pct}%</span> · {view.verdict.bucket}</div>
                </div>
                <div className="exec-cell">
                  <div className="lbl">Input type</div>
                  <div className="exec-val">{view.inputType}</div>
                </div>
                <div className="exec-cell">
                  <div className="lbl">Elapsed</div>
                  <div className="exec-val mono">{view.stats.elapsed}</div>
                </div>
              </div>
              {view.verdict.reason ? <div className="exec-reason">{view.verdict.reason}</div> : null}
            </div>

            {/* Executive narrative — analyst-style prose. */}
            <div className="prose" style={{ marginTop: "var(--s6)" }}>
              {view.story && view.story.length > 0 ? (
                view.story.slice(0, 3).map((p, i) => (
                  <StoryParagraph key={i} text={p.text} kind={p.kind} {...evChipProps} />
                ))
              ) : (
                <p className="quiet">
                  No analyst narrative yet — the summary composer will populate this once the investigation completes.
                </p>
              )}
            </div>

            {/* Correlated key findings + IOCs · one screen for leadership */}
            <div className="exec-grid">
              <div className="exec-block">
                <div className="lbl">Key Findings ({view.findings.length})</div>
                {view.findings.length === 0 ? (
                  <div className="quiet mono">No key findings extracted.</div>
                ) : (
                  view.findings.slice(0, 6).map((f, i) => (
                    <div key={i} className="exec-line">
                      <span className={`g ${f.g}`}>{f.gly}</span>
                      <span>
                        <span className="t">{f.t}</span>
                        {f.evs && f.evs.length > 0 ? (
                          <span className="e">
                            {f.evs.slice(0, 4).map((id) => (
                              <EvChip key={id} id={id} selected={selEv === id} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                            ))}
                          </span>
                        ) : null}
                      </span>
                    </div>
                  ))
                )}
              </div>

              <div className="exec-block">
                <div className="lbl">Observed IOCs ({view.osint.length})</div>
                {view.osint.length === 0 ? (
                  <div className="quiet mono">No indicators extracted.</div>
                ) : (
                  view.osint.slice(0, 6).map((o) => (
                    <div key={o.node_id} className="exec-line">
                      <span className="ioc-kind">{(o.kind || "ioc").replace(/^external_ioc_/, "").toUpperCase()}</span>
                      <span className="mono">{o.value}</span>
                    </div>
                  ))
                )}
              </div>

              <div className="exec-block">
                <div className="lbl">Recommended Actions ({view.actions.length})</div>
                {view.actions.length === 0 ? (
                  <div className="quiet mono">No recommendations from the engine.</div>
                ) : (
                  view.actions.map((a, i) => (
                    <div key={i} className="exec-line">
                      <span className={`w ${a.wCls || ""}`}>{a.w}</span>
                      <span>{a.n}</span>
                    </div>
                  ))
                )}
              </div>

              <div className="exec-block">
                <div className="lbl">Unknowns ({view.unknowns.length})</div>
                {view.unknowns.map((u, i) => (
                  <div key={i} className="exec-line">
                    <span className="g unk">○</span>
                    <span>{u.t}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="exec-foot">
              <span className="lbl">Decoded output preview</span>
              {view.decodeLadder && view.decodeLadder.length > 0 ? (
                <div className="code" style={{ marginTop: "var(--s3)", maxHeight: 240, overflow: "auto" }}>
                  {view.decodeLadder[view.decodeLadder.length - 1].code}
                </div>
              ) : (
                <div className="quiet mono" style={{ marginTop: "var(--s2)" }}>
                  Input was already in canonical form or the engine detected no decode layers.
                </div>
              )}
            </div>
          </section>

          {/* STORY */}
          <section className={`lens${lens === "story" ? " on" : ""}`} id="story" ref={lensRefs.story} onScroll={onStoryScroll} data-testid="lens-story">
            <div className={`sticky-summary${showSticky ? " show" : ""}`}>
              <span className="pill">▲ {view.verdict.label} <span style={{ opacity: 0.7 }}>{view.verdict.dots}</span></span>
              <span className="st"><b>{view.stats.obs}</b> obs</span>
              <span className="st"><b>{view.stats.beh}</b> behaviors</span>
              <span className="st"><b>{view.stats.tech}</b> techniques</span>
              <span className="st"><b>{view.stats.unk}</b> unknowns</span>
            </div>

            <div className="lens-head">
              <h2>What happened</h2>
              <p>Generated from the Canonical Investigation Object. Every clause is traceable.</p>
            </div>

            <div className="prose">
              {view.story.map((p, i) => (
                <React.Fragment key={i}>
                  <StoryParagraph text={p.text} kind={p.kind} {...evChipProps} />
                  {i < view.story.length - 1 && p.kind !== "quiet" ? <hr /> : null}
                </React.Fragment>
              ))}
            </div>

            <div className="story-foot" data-testid="labv2-story-foot">
              <button className="stat" data-testid="stat-obs" onClick={() => showLens("source")}>
                <div className="lbl">Observations</div><div className="v num">{view.stats.obs}</div>
              </button>
              <button className="stat" data-testid="stat-beh" onClick={() => showLens("behavior")}>
                <div className="lbl">Behaviors</div><div className="v num">{view.stats.beh}</div>
              </button>
              <button className="stat" data-testid="stat-tech" onClick={() => showLens("attack")}>
                <div className="lbl">Techniques</div><div className="v num">{view.stats.tech}</div>
              </button>
              <button className="stat" data-testid="stat-unk">
                <div className="lbl">Unknowns</div><div className="v num">{view.stats.unk}</div>
              </button>
              <div className="stat">
                <div className="lbl">Elapsed</div><div className="v num">{view.stats.elapsed}</div>
              </div>
            </div>
          </section>

          {/* SOURCE (decode ladder) */}
          <section className={`lens${lens === "source" ? " on" : ""}`} id="source" ref={lensRefs.source} data-testid="lens-source">
            <div className="lens-head">
              <h2>Decode ladder</h2>
              <p>The recipe the engine already found. Climb it to audit each transform.</p>
            </div>

            {view.decodeLadder && view.decodeLadder.length > 0 ? (
              view.decodeLadder.map((r, i) => (
                <div key={i}>
                  <div className="rung">
                    <div className="rung-head">
                      <span className="l">{r.layer}</span>
                      <span className="n">{r.name}</span>
                      <span className="m">{r.meta}</span>
                    </div>
                    <div className="code">{r.code}</div>
                  </div>
                  {i < view.decodeLadder.length - 1 ? (
                    <div className="transform"><span className="arrow">↓</span> transform<span className="conf">confident</span></div>
                  ) : null}
                </div>
              ))
            ) : (
              <div className="tempty">
                No decode chain was produced for this investigation. Either the input was already in
                canonical form (a structured incident, event log, or IOC list) or the engine did not
                detect an encoding layer. This does not affect the verdict.
              </div>
            )}
          </section>

          {/* BEHAVIOR — G1 decode chain + G2 attack chain */}
          <section className={`lens${lens === "behavior" ? " on" : ""}`} id="behavior" ref={lensRefs.behavior} data-testid="lens-behavior">
            <div className="lens-head">
              <h2>Behaviour graphs</h2>
              <p>Two graphs projected from <code style={{ fontFamily: "var(--font-mono)" }}>cio.evidence_graph</code>. G1 shows the layer-by-layer unwrapping recipe. G2 shows the causal attack chain.</p>
            </div>

            {/* G1 · Decode chain */}
            <div className="graph-block" data-testid="graph-block-decode">
              <div className="graph-title">
                <span className="tag mint">G1</span>
                <h3>Decode chain</h3>
                <span className="quiet">layer-by-layer unwrapping · linear</span>
              </div>
              {view.decodeGraph && !view.decodeGraph.empty ? (
                <div className="graph-wrap" data-testid="graph-wrap-decode">
                  <svg
                    width={view.decodeGraph.width}
                    height={view.decodeGraph.height}
                    viewBox={`0 0 ${view.decodeGraph.width} ${view.decodeGraph.height}`}
                    preserveAspectRatio="xMidYMid meet"
                    style={{ display: "block" }}
                  >
                    <defs>
                      <marker id="ah-dec" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
                        <path d="M0,0 L9,4.5 L0,9 z" fill="var(--mint)" />
                      </marker>
                    </defs>
                    <g className="edge hot" style={{ stroke: "var(--mint)" }}>
                      {view.decodeGraph.edges.map((e, i) => (
                        <path key={i} d={e.path} markerEnd="url(#ah-dec)" style={{ stroke: "var(--mint)" }} />
                      ))}
                    </g>
                    <g>
                      {view.decodeGraph.nodes.map((n) => (
                        <g
                          key={n.id}
                          className="graph-node"
                          data-testid={`decode-node-${n.id}`}
                          style={{ cursor: "pointer" }}
                          onClick={() => onEvClick(n.id)}
                        >
                          <rect className={`n-box${selEv === n.id ? " sel" : ""}`} x={n.x} y={n.y} width={n.w} height={n.h} rx="6" />
                          <text className="n-t" x={n.x + 16} y={n.y + 24}>{n.title}</text>
                          <text className="n-s" x={n.x + 16} y={n.y + 44}>{n.subtitle} · {n.id}</text>
                        </g>
                      ))}
                    </g>
                  </svg>
                </div>
              ) : (
                <div className="tempty">No decode layers were unwrapped for this investigation.</div>
              )}
            </div>

            {/* G2 · Attack Chain */}
            <div className="graph-block" data-testid="graph-block-attack" style={{ marginTop: "var(--s6)" }}>
              <div className="graph-title">
                <span className="tag crit">G2</span>
                <h3>Attack chain</h3>
                <span className="quiet">causal graph across capability lanes</span>
              </div>
              {view.attackGraph && !view.attackGraph.empty ? (
                <div className="graph-wrap" data-testid="graph-wrap-attack">
                  <svg
                    width={view.attackGraph.width}
                    height={view.attackGraph.height}
                    viewBox={`0 0 ${view.attackGraph.width} ${view.attackGraph.height}`}
                    preserveAspectRatio="xMidYMid meet"
                    style={{ display: "block" }}
                  >
                    <defs>
                      <marker id="ah" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
                        <path d="M0,0 L9,4.5 L0,9 z" fill="currentColor" />
                      </marker>
                      <marker id="ah-hot" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
                        <path d="M0,0 L9,4.5 L0,9 z" fill="var(--crit)" />
                      </marker>
                    </defs>
                    <g>
                      {view.attackGraph.lanes.map((lane) => (
                        <React.Fragment key={lane.id}>
                          <rect className="lane-bg" x="0" y={lane.y} width={view.attackGraph.width} height={lane.height || 96} rx="8" />
                          <text className="lane-lbl" x="16" y={lane.y + 22}>{lane.label}</text>
                        </React.Fragment>
                      ))}
                    </g>
                    <g className="edge">
                      {view.attackGraph.edges.filter((e) => !e.hot).map((e, i) => (
                        <path key={`c${i}`} d={e.path} markerEnd="url(#ah)" />
                      ))}
                    </g>
                    <g className="edge hot">
                      {view.attackGraph.edges.filter((e) => e.hot).map((e, i) => (
                        <path key={`h${i}`} d={e.path} markerEnd="url(#ah-hot)" />
                      ))}
                    </g>
                    <g>
                      {view.attackGraph.lanes.flatMap((lane) =>
                        lane.nodes.map((n) => (
                          <g
                            key={n.id}
                            className="graph-node"
                            data-testid={`attack-node-${n.id}`}
                            style={{ cursor: "pointer" }}
                            onClick={() => onEvClick(n.id)}
                          >
                            <rect className={`n-box${n.hot ? " hot" : ""}${selEv === n.id ? " sel" : ""}`} x={n.x} y={n.y} width={n.w} height={n.h} rx="6" />
                            <text className="n-t" x={n.x + 16} y={n.y + 24}>{n.title}</text>
                            <text className="n-s" x={n.x + 16} y={n.y + 44}>{n.subtitle} · {n.id}</text>
                          </g>
                        ))
                      )}
                    </g>
                    {view.attackGraph.chainLabel ? (
                      <text className="chain-lbl" x="40" y={view.attackGraph.height - 18}>{view.attackGraph.chainLabel}</text>
                    ) : null}
                  </svg>
                </div>
              ) : (
                <div className="tempty">
                  No behavioural evidence was extracted for this investigation. The attack chain stays empty until the engine
                  attaches non-decode nodes to <code style={{ fontFamily: "var(--font-mono)" }}>cio.evidence_graph</code>.
                </div>
              )}
            </div>

            <p className="quiet" style={{ marginTop: "var(--s4)", maxWidth: "820px", fontSize: 12 }}>
              Both graphs render straight from the CIO evidence graph. Node clicks synchronise the evidence chip across every
              lens in the workspace.
            </p>
          </section>

          {/* ATT&CK */}
          <section className={`lens${lens === "attack" ? " on" : ""}`} id="attack" ref={lensRefs.attack} data-testid="lens-attack">
            <div className="lens-head">
              <h2>Observed path</h2>
              <p>Only tactics present in this case. Full matrix and Navigator JSON on demand.</p>
            </div>
            <div className="tactics">
              {Object.entries(view.attack.columns).map(([tactic, techs]) => (
                <div key={tactic} className="tcol">
                  <div className="lbl">{tactic}</div>
                  {techs.length > 0 ? (
                    techs.map((t) => (
                      <button key={t.id} className="tcard" data-testid={`tcard-${t.id}`}>
                        <div className="id">{t.id}</div>
                        <div className="nm">{t.nm}</div>
                        <div className="row">
                          {(t.evs || []).map((id) => (
                            <EvChip key={id} id={id} selected={selEv === id} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                          ))}
                          <span className="conf-dots" style={{ marginLeft: "auto" }}>{t.dots}</span>
                        </div>
                      </button>
                    ))
                  ) : (
                    <div className="tempty" data-testid={`attack-empty-${tactic}`}>
                      No ATT&amp;CK techniques were confidently identified for this tactic. This does not imply benign activity.
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>

          {/* OSINT — IOC threat intelligence */}
          <section className={`lens${lens === "osint" ? " on" : ""}`} id="osint" ref={lensRefs.osint} data-testid="lens-osint">
            <div className="lens-head">
              <h2>OSINT · IOC intelligence</h2>
              <p>Every indicator observed in this investigation, alongside its threat-intel enrichment.</p>
            </div>
            {view.osint.length === 0 ? (
              <div className="tempty">
                No indicators were extracted for this investigation. When the engine surfaces URLs,
                domains, IPs, hashes, or file paths, they appear here with reputation and provider hits.
              </div>
            ) : (
              <div className="ioc-list">
                {view.osint.map((o) => (
                  <div key={o.node_id} className="ioc-card" data-testid={`ioc-${o.node_id}`}>
                    <div className="ioc-h">
                      <span className="ioc-kind">{(o.kind || "ioc").replace(/^external_ioc_/, "").toUpperCase()}</span>
                      <span className="ioc-value mono">{o.value}</span>
                      <span className="conf-dots" style={{ marginLeft: "auto" }}>
                        {"●".repeat(Math.round(o.confidence / 20))}
                        {"○".repeat(5 - Math.round(o.confidence / 20))}
                      </span>
                    </div>
                    <div className="ioc-meta">
                      {o.first_seen ? <span>First seen · <b>{o.first_seen}</b></span> : null}
                      {o.last_seen ? <span>Last seen · <b>{o.last_seen}</b></span> : null}
                      {o.reputation ? <span>Reputation · <b>{o.reputation}</b></span> : null}
                    </div>
                    <div className="ioc-providers">
                      {o.providers.map((p, i) => (
                        <div key={i} className={`ioc-prov ${p.state}`}>
                          <span className="prov-name">{p.name}</span>
                          <span className="prov-state">
                            {p.state === "hit" ? "● HIT" : p.state === "pending" ? "○ pending" : p.state === "no-hash" ? "— no hash" : p.state}
                          </span>
                          {p.detail ? <span className="prov-detail">{p.detail}</span> : null}
                        </div>
                      ))}
                    </div>
                    <div className="ioc-foot">
                      <EvChip id={o.node_id} selected={selEv === o.node_id} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                      <span className="quiet mono" style={{ marginLeft: "var(--s2)" }}>
                        Providers will be wired to live threat-intel APIs in a future slice · shape ready.
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* RAW SOURCE — the original input verbatim */}
          <section className={`lens${lens === "raw" ? " on" : ""}`} id="raw" ref={lensRefs.raw} data-testid="lens-raw">
            <div className="lens-head">
              <h2>Source</h2>
              <p>The exact bytes submitted to the engine. Read-only.</p>
            </div>
            <div className="code" style={{ maxWidth: "100%", maxHeight: "60vh", overflow: "auto" }}>
              {view.rawInput || "No source input recorded for this investigation."}
            </div>
          </section>
        </main>

        {/* ── FINDINGS PANEL ─────────────────────────────────── */}
        <aside className="findings" data-testid="labv2-findings">
          <div className="sect">
            <div className="sect-h"><span className="lbl">Verdict ledger</span></div>
            <div className="ledger">
              <div className="ledger-top">
                <div className="v">▲ {view.verdict.label}</div>
                <div className="c">
                  <span className="lbl">Confidence</span>
                  <span className="conf-dots">{view.verdict.dots}</span>
                  <span className="lbl" style={{ color: "var(--fg2)" }}>{view.verdict.bucket}</span>
                </div>
              </div>
              {view.ledger.length === 0 ? (
                <div style={{ padding: "var(--s3) var(--s4)", color: "var(--fg3)", fontSize: 12 }}>
                  No contributing evidence recorded yet.
                </div>
              ) : (
                view.ledger.map((r, i) => (
                  <button key={i} className="lrow" data-testid={`ledger-row-${i}`}>
                    <span className={`sign ${r.cls}`}>{r.sign}</span>
                    <span>
                      <span className="t">{r.t}</span>
                      {r.evs && r.evs.length > 0 ? (
                        <span className="e">
                          {r.evs.map((id) => (
                            <EvChip key={id} id={id} selected={selEv === id} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                          ))}
                        </span>
                      ) : null}
                    </span>
                  </button>
                ))
              )}
              {view.verdict.reason ? (
                <div className="ledger-note">{view.verdict.reason}</div>
              ) : null}
              <div className="ledger-foot">
                <button className="corr">Correct</button>
                <button className="corr">Partial</button>
                <button className="corr">Wrong</button>
              </div>
            </div>
          </div>

          <div className="sect">
            <div className="sect-h"><span className="lbl">Findings</span><span className="c">{view.findings.length}</span></div>
            {view.findings.length === 0 ? (
              <div style={{ padding: "var(--s2)", color: "var(--fg3)", fontSize: 12 }}>
                No key findings were extracted from this investigation.
              </div>
            ) : (
              view.findings.map((f, i) => (
                <button key={i} className="frow" data-testid={`finding-${i}`}>
                  <span className={`g ${f.g}`}>{f.gly}</span>
                  <span>
                    <span className="t">{f.t}</span>
                    <span className="sub">{f.sub}</span>
                    {f.evs && f.evs.length > 0 ? (
                      <span className="e">
                        {f.evs.map((id) => (
                          <EvChip key={id} id={id} selected={selEv === id} onEnter={onEvEnter} onLeave={onEvLeave} onClick={onEvClick} />
                        ))}
                      </span>
                    ) : null}
                  </span>
                </button>
              ))
            )}
          </div>

          <div className="sect">
            <div className="sect-h"><span className="lbl">Unknowns</span><span className="c">{view.unknowns.length}</span></div>
            {view.unknowns.map((u, i) => (
              <button key={i} className="frow" data-testid={`unknown-${i}`}>
                <span className="g unk">○</span>
                <span>
                  <span className="t">{u.t}</span>
                  {u.sub ? <span className="sub">{u.sub}</span> : null}
                </span>
              </button>
            ))}
          </div>

          <div className="sect">
            <div className="sect-h"><span className="lbl">Next actions</span><span className="c">{view.actions.length}</span></div>
            {view.actions.length === 0 ? (
              <div style={{ padding: "var(--s2)", color: "var(--fg3)", fontSize: 12 }}>
                No recommended actions yet. The engine will populate this section once summary composition completes.
              </div>
            ) : (
              view.actions.map((a, i) => (
                <button key={i} className="act" data-testid={`action-${i}`}>
                  <div className="h">
                    <span className="n">{a.n}</span>
                    <span className={`w${a.wCls ? ` ${a.wCls}` : ""}`}>{a.w}</span>
                  </div>
                  {a.b ? <div className="b">{a.b}</div> : null}
                </button>
              ))
            )}
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
        <div className="code" data-testid="evbar-code" dangerouslySetInnerHTML={{ __html: sel.c }} />
        <div className="supports">
          <span className="lbl">Supports</span>
          {(sel.sup || []).map((s) => (<span className="tag" key={s}>{s}</span>))}
        </div>
      </footer>

      {/* ── Evidence hover popover (Enhancement E) ──────────── */}
      {pop && view.ev[pop.id] ? (
        <div className="ev-pop show" style={{ top: pop.top, left: pop.left, transform: "translate(0, -100%)" }}>
          <div className="id">{pop.id}</div>
          <div className="snip" dangerouslySetInnerHTML={{ __html: view.ev[pop.id].c }} />
          <div className="sups">
            {(view.ev[pop.id].sup || []).map((s) => (<span className="tag" key={s}>{s}</span>))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
