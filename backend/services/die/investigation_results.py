"""
DIE · Investigation Results Renderer
────────────────────────────────────
Frozen 2026-03-01 as part of IUE v2.0.

The Investigation Results renderer replaces the legacy "OUTPUT" pane.
Whenever the IUE decides that the input does not require decoding
(plain PowerShell, CMD, Bash, vendor report, IOC list, Sigma, …) OR
when decoding has already been performed, the Workspace displays a
deterministic *investigation view* built from:

  · Input Understanding Engine     — input type, encoding, decode
                                     decision, extracted counts
  · Preprocessor                    — per-command stages + families +
                                     tactics + MITRE + commonly-
                                     observed-in
  · DIE analyze envelope           — LOLBAS, IOCs, MITRE
  · DKP (Decoder Knowledge Pack)   — family recognition + confidence
  · Attack Intent                  — deterministic threat objective

Everything below is deterministic — no LLM, no network, no
randomness.  Same paste → same investigation result text.

The renderer emits BOTH:
  · `output` — a plain-text formatted view suitable for the pane
  · `object` — a structured Canonical Investigation Object (SSOT)
              that downstream engines will consume in v2.1.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from .preprocessor import preprocess as preprocess_input
from .input_understanding import understand as understand_input
from .input_health import check_health as _check_health
from .canonical import build_confidence_breakdown, build_plan
from .behavior_explainer import explain_stage as _explain_stage, explain_chain as _explain_chain
from .lolbas import lolbas_lookup, LOLBAS_REGISTRY  # noqa: F401
from .ioc_semantic import extract_iocs
from .intent import classify_intent_from_analyze
from .api import analyze
# ── IDA · Intelligent Document Analyzer (Rule R14) ──
# Slice 1 · IDA-1 Input Classifier + IDA-2 Artifact Splitter.
# The IUE remains the classifier of record; IDA contributes a
# deterministic artifact decomposition + IDA verdict on top.
from services.ida import (
    classify_artifact_input as _ida_classify,
    acquire_url as _ida_acquire,
    understand_document as _ida_understand,
    extract_all as _ida_extract,
    investigate_all_artifacts as _ida_investigate_all,
    merge_artifact_investigations as _ida_merge,
)
from services.ice import correlate as _ice_correlate


# ── Formatting helpers ────────────────────────────────────────────
_H1_WIDTH = 62
_H1_BORDER = "═" * _H1_WIDTH
_H2_BORDER = "─" * _H1_WIDTH


def _h1(title: str) -> str:
    return f"{_H1_BORDER}\n{title.upper()}\n{_H1_BORDER}"


def _h2(title: str) -> str:
    return f"{_H2_BORDER}\n{title}\n{_H2_BORDER}"


def _kv(label: str, value: Any, indent: int = 0) -> str:
    pad = " " * indent
    return f"{pad}{label:<20} {value}"


def _bullet(text: str, indent: int = 2) -> str:
    return f"{' ' * indent}• {text}"


def _empty(section: str) -> str:
    return f"  (none)"


# ── Renderer ──────────────────────────────────────────────────────
def render(input_text: str) -> Dict[str, Any]:
    """Render the full Investigation Results view for an input paste.

    Returns ``{output: str, object: dict}`` where ``output`` is the
    formatted text destined for the Workspace pane and ``object`` is
    the Canonical Investigation Object (SSOT) for downstream engines.

    ── Rule R23 · Complete Decoding Contract ──
    Any exception raised by an internal decoder / adapter / engine
    is caught here and returned as a `partial_ssot` envelope so the
    frontend always receives a valid, projectable payload.  A single
    decoder crash NEVER black-screens the workspace.
    """
    try:
        return _render_impl(input_text)
    except Exception as _exc:                     # pragma: no cover
        import logging, traceback
        logging.getLogger("nivxray.render").exception(
            "investigation_results.render failed — returning partial_ssot")
        return {
            "output": "▲ Partial investigation — an internal decoder failed. "
                       "Analyst receives a safe partial payload per Rule R23.",
            "object": {
                "metadata":       {"schema": "investigation-v1",
                                     "partial": True},
                "input":          {"raw": input_text or ""},
                "decode_status":  {
                    "failed":     True,
                    "reason":     type(_exc).__name__,
                    "detail":     str(_exc)[:400],
                    "trace":      traceback.format_exc(limit=5)[:2000],
                },
                "commands":       [],
                "iocs":           {},
                "mitre":          [],
                "artifacts":      [],
                "acquired_document": {},
                "acquisition_plan":  [],
                "incident":       None,
                "narrative":      {},
            },
        }


def _render_impl(input_text: str) -> Dict[str, Any]:
    """Actual render implementation (see ``render`` for R23 wrapper)."""
    src = input_text or ""

    # ══════════════════════════════════════════════════════════════
    # Rule R24 · Investigation Performance Contract
    # Every investigation MUST emit an immutable, projectable
    # `performance{}` block covering:
    #   · per-stage backend timings
    #   · peak memory usage (RSS + tracemalloc)
    #   · decode-recursion layer telemetry (layer / bytes / ratio)
    #   · truncation flags (did we hit any R23 cap?)
    #   · engine health (which engines succeeded / failed)
    # Frontend timings (layout / render / paint) are merged in
    # after the workspace receives its first repaint via
    # `POST /api/telemetry/frontend`.
    # ══════════════════════════════════════════════════════════════
    import time as _t
    import tracemalloc as _tm
    import resource as _res
    _T0 = _t.perf_counter()
    _tm_started = False
    try:
        if not _tm.is_tracing():
            _tm.start()
            _tm_started = True
    except Exception:  # pragma: no cover
        pass
    _timings: Dict[str, float] = {}
    _budgets: Dict[str, float] = {   # ms — per-stage warning threshold
        "health":              50.0,
        "iue":                150.0,
        "preprocessor":       800.0,
        "die_analyze":        400.0,
        "iocs":                80.0,
        "lolbins":             40.0,
        "mitre_merge":         40.0,
        "intent":              60.0,
        "ida":                200.0,
        "acquisition":       1200.0,
        "artifacts":           60.0,
        "narrative":          120.0,
        "ice_correlate":      400.0,
        "paste_synthesis":    200.0,
    }
    _warnings: List[str] = []
    _engine_health: Dict[str, str] = {}
    def _stage(name: str, fn):
        _s = _t.perf_counter()
        try:
            result = fn()
            _engine_health[name] = "ok"
        except Exception as _e:
            # R23 · never let a single engine fail the pipeline.
            _engine_health[name] = f"error:{type(_e).__name__}:{str(_e)[:120]}"
            _warnings.append(f"{name} raised {type(_e).__name__}")
            raise
        finally:
            elapsed_ms = (_t.perf_counter() - _s) * 1000.0
            _timings[name] = round(elapsed_ms, 2)
            budget = _budgets.get(name)
            if budget is not None and elapsed_ms > budget:
                _warnings.append(f"{name}={elapsed_ms:.0f}ms > budget {budget:.0f}ms")
        return result

    # 0) Stage-0 · Input Health Check (IUE v2.0 · Layer 0)
    health = _stage("health", lambda: _check_health(src))

    # 1) IUE — classification + plan
    understanding = _stage("iue", lambda: understand_input(src, execute=False))
    u_dict = understanding.to_dict()

    # 2) Preprocessor — stages + artifacts + relationships
    pre = _stage("preprocessor", lambda: preprocess_input(src))

    # 3) DIE analyze — LOLBAS, MITRE, IOCs, DKP
    env = _stage("die_analyze", lambda: analyze(src))

    # 3b) R23/R24 · Recursive peel — IOCs and behaviors in DEEPER
    # layers (e.g. the URL hidden inside a gzip-inside-b64-inside-
    # -EncodedCommand loader) must ALSO be extracted.  We peel the
    # raw input a second time here so the outer `analyze` result
    # can be augmented with anything found in the recovered payload.
    from services.die.preprocessor.recursive_decoder import peel_recursively as _peel
    _peeled_deep, _ = _peel(src)
    if _peeled_deep == src:
        _peeled_deep = ""     # no new layers → nothing to augment

    # 4) Attack intent — deferred (needs augmented techniques)
    intent: Dict[str, Any] = {}

    # 5) Aggregate IOCs — canonical shape.  Union of:
    #    · outer `analyze` output (raw-input IOCs), and
    #    · deep recursive-peel IOCs (inner-layer URLs / IPs / hashes
    #      that only appear AFTER we've peeled base64+gzip+utf16).
    def _iocs_stage():
        outer_iocs = env.get("iocs") or extract_iocs(src)
        combined = list(outer_iocs)
        # Deep-layer IOCs — dedupe by (kind, value).
        seen = {((i.get("kind") or "").lower(), i.get("value") or "")
                  for i in combined}
        if _peeled_deep and _peeled_deep != src:
            try:
                deep_iocs = extract_iocs(_peeled_deep)
            except Exception:  # pragma: no cover
                deep_iocs = []
            for di in (deep_iocs or []):
                key = ((di.get("kind") or "").lower(), di.get("value") or "")
                if key not in seen and key[1]:
                    di["source"] = di.get("source") or "recursive_peel"
                    combined.append(di)
                    seen.add(key)
        by_kind: Dict[str, List[str]] = {}
        for i in combined:
            k = (i.get("kind") or "unknown").lower()
            v = i.get("value") or i.get("indicator") or ""
            if v:
                by_kind.setdefault(k, []).append(v)
        return combined, by_kind
    iocs, ioc_by_kind = _stage("iocs", _iocs_stage)

    # 6) LOLBAS surfaced by the analyze envelope + augmented from
    # preprocessor stages so every extracted LOLBIN (tar / msedge /
    # python / …) appears in the SSOT + Threat Analysis sidebar.
    lolbins = list(env.get("lolbins") or [])
    seen_bins = {(lb.get("binary") or "").lower() for lb in lolbins}
    for s in pre.stages:
        cmd = (s.normalized_command or "") + " " + (s.raw_excerpt or "")
        for bin_hint in ("tar", "msedge", "chrome", "brave", "firefox",
                         "python", "python3", "pythonw", "node",
                         "ruby", "perl", "java", "javaw"):
            import re as _re
            if _re.search(rf"(?i)(?<![\w-])(?:{bin_hint})(?:\.exe)?\b", cmd):
                key = bin_hint + ".exe"
                if key not in seen_bins:
                    lolbins.append({"binary": key, "mitre": list(s.mitre or [])})
                    seen_bins.add(key)

    # 7) MITRE surfaced by the analyze envelope + augmented with the
    # deterministic MITRE codes attached to every recognised family
    # stage.  This guarantees the SSOT.mitre[] contains techniques
    # for every stage — not just those the PS-AST + LOLBAS classic
    # path picked up.
    techniques = list(env.get("techniques") or [])
    seen_mitre = {(t.get("id") or "").upper() for t in techniques}
    for s in pre.stages:
        for mid in (s.mitre or []):
            mid_up = (mid or "").upper()
            if not mid_up or mid_up in seen_mitre:
                continue
            techniques.append({
                "id":         mid,
                "name":       s.title or "",
                "tactic":     s.tactic or "",
                "evidence":   s.normalized_command or s.raw_excerpt,
                "source":     "preprocessor.stage",
            })
            seen_mitre.add(mid_up)

    # Now re-run intent classification with the augmented technique
    # list so the objective + progress reflect ALL stages, not just
    # the ones the classic PS-AST / LOLBAS mapper caught.
    # We strip ``chain`` from the passed env so the wrapper uses the
    # augmented ``techniques[].tactic`` values instead of the raw
    # chain's per-step tactic guesses (which are mostly
    # "Uncategorised" for LOLBAS host lines).
    env_augmented = {k: v for k, v in env.items() if k != "chain"}
    env_augmented["techniques"] = techniques
    env_augmented["dkp_matches"] = env.get("dkp_matches") or []
    intent = classify_intent_from_analyze(env_augmented) or {}

    # 8) DKP matches
    dkp_matches = env.get("dkp_matches") or []

    # 9) IDA · Slice 1 · Artifact decomposition + IDA verdict.
    # Later slices (URL fetch, content understanding, threat report
    # extraction) will augment `artifacts[]` in-place without any
    # consumer changing.  Rule R14: IDA is the ONLY engine writing
    # to `artifacts[]`.
    ida_verdict = _ida_classify(src)

    # 9b) Rule R19 · Acquirable Resources Must Be Acquired.
    # When IDA classifies the paste as an acquirable URL AND IDA-3
    # is available, we fetch → understand → extract synchronously
    # so the SSOT carries REAL evidence, not a queued plan.
    ida_class = ida_verdict.get("ida_class") or ""
    url_intent = ida_verdict.get("url_intent") or {}
    acquired_dict: Dict[str, Any] = {}
    document_profile: Dict[str, Any] = {}
    report_extraction: Dict[str, Any] = {}
    completed_steps: List[str] = []          # plan-step ids that actually ran to `done`

    _ACQUIRABLE_CLASSES = ("threat_report_url", "code_snippet_url",
                            "repository_url", "file_resource_url")
    if ida_class in _ACQUIRABLE_CLASSES and url_intent.get("acquirable"):
        # Use the first URL artifact's canonical form (there's exactly one
        # for a bare-URL paste, by classification).
        url_art = next((a for a in ida_verdict.get("artifacts", []) if a.get("type") == "url"), None)
        target = (url_art or {}).get("canonical") or src.strip()
        acquired = _ida_acquire(target)
        acquired_dict = acquired.to_dict()
        completed_steps.append("ida-3")

        if acquired.ok:
            document_profile = _ida_understand(acquired.article_text, acquired.to_dict())
            completed_steps.append("ida-3.5")

            report_extraction = _ida_extract(
                acquired.article_text,
                acquired.structured_blocks,
            )
            # Rule R20 · Extracted artifacts are investigation seeds.
            # Feed every extracted command back through the DIE
            # analyzer so behaviour / MITRE / LOLBAS / IOCs / DKP land
            # in the consolidated SSOT — not just a display list.
            command_investigations = _ida_investigate_all(
                report_extraction.get("commands") or [],
            )
            report_extraction["command_investigations"] = command_investigations
            report_extraction["investigation_summary"]  = _ida_merge(command_investigations)

            # Promote the aggregated LOLBAS / MITRE hits from every
            # per-command investigation into the top-level SSOT so
            # the Threat Analysis panels light up.  Provenance is
            # preserved via `source=command` on the technique record
            # (Rule R14 · IDA always tags provenance).
            summary = report_extraction["investigation_summary"]
            seen_lb = {(lb.get("binary") or "").lower() for lb in lolbins}
            for lb in summary.get("lolbins_union", []):
                if lb["binary"] not in seen_lb:
                    lolbins.append({
                        "binary":  lb["binary"],
                        "mitre":   lb.get("mitre") or [],
                    })
                    seen_lb.add(lb["binary"])
            seen_t = {(t.get("id") or "").upper() for t in techniques}
            for t in summary.get("techniques_union", []):
                tid = t["id"].upper()
                if tid not in seen_t:
                    techniques.append({
                        "id":       tid,
                        "name":     t.get("name") or "",
                        "tactic":   "",
                        "evidence": "",
                        "source":   "ida.command_investigation",
                    })
                    seen_t.add(tid)
            # Rule R14 · IDA-4 body_artifacts are IOCs the article
            # published — promote them into the top-level SSOT.iocs so
            # SummaryLens, TIShield, and the IOC Intelligence engine
            # can enrich them.  Deduplicate against any IOC already
            # collected from the raw input.
            _seen_iocs = {(k, v) for k, vs in ioc_by_kind.items() for v in vs}
            for a in (report_extraction.get("body_artifacts") or []):
                t   = (a.get("type") or "").lower()
                val = (a.get("value") or "").strip()
                if not t or not val:
                    continue
                # Map IDA-2 artifact types → canonical IOC kinds.
                kind = {
                    "url": "url", "hash": "hash", "ip": "ip",
                    "domain": "domain", "registry_key": "registry",
                    "file_path": "path", "cve": "cve",
                }.get(t)
                if not kind:
                    continue
                if (kind, val) in _seen_iocs:
                    continue
                ioc_by_kind.setdefault(kind, []).append(val)
                _seen_iocs.add((kind, val))
            # ida-4 fans out into multiple named plan steps; mark them
            # all `done` since the single extractor pass produced them.
            completed_steps.extend([
                "ida-4-cmds", "ida-4-mitre", "ida-4-iocs",
                "ida-4-time", "ida-4-malw", "ida-4-cve",
                "ida-4-detect", "ida-6", "die", "ssot", "report",
            ])

            # 2026-02-09 · Promote IOCs surfaced by the CHAIN decode
            # ("CyberChef recipe" applied to each extracted command)
            # into the top-level SSOT.iocs so the analyst's IOC panel
            # shows the C2 IP that was buried 4 encoding layers deep.
            # Deduplicate against IOCs already collected.
            for _inv in (report_extraction.get("command_investigations") or []):
                _peeled = _inv.get("peeled_iocs") or {}
                for _kind, _vals in _peeled.items():
                    for _val in (_vals or []):
                        _v = (_val or "").strip()
                        if not _v:
                            continue
                        if (_kind, _v) in _seen_iocs:
                            continue
                        ioc_by_kind.setdefault(_kind, []).append(_v)
                        _seen_iocs.add((_kind, _v))

    # ── P0a (ADR-0014g) · Analyst-Paste evidence projection ───────
    # When the IDA classification is non-acquirable (e.g. atomic_ioc_url,
    # ioc_list, command_chain, mixed_artifacts, single_command, none),
    # the URL-acquired branch above did NOT run — leaving
    # report_extraction = {}.  However, IDA and the preprocessor
    # ALREADY extracted evidence into local variables (`stages`,
    # `techniques`, `ioc_by_kind`, `ida_verdict.artifacts`).  We
    # project this evidence into the same shape `_ida_extract`
    # produces, so downstream consumers (report renderers,
    # summary_narrative, evidence_confidence) see identical field
    # names regardless of paste vs URL origin.  No re-extraction,
    # no new inference, no IDA/DIE/router/registry/IUE change.
    if not report_extraction:
        _paste_artifacts = list(ida_verdict.get("artifacts") or [])
        _paste_commands  = [_command_to_ssot(_s) for _s in pre.stages]
        # Flatten ioc_by_kind {kind: [value,...]} into artifact-shaped
        # dicts so `body_artifacts` reflects the total IOC surface.
        _seen_art_keys = {(a.get("type"), a.get("canonical") or a.get("value"))
                           for a in _paste_artifacts}
        for _kind, _vals in (ioc_by_kind or {}).items():
            for _v in _vals:
                if (_kind, _v) in _seen_art_keys:
                    continue
                _paste_artifacts.append({"type": _kind, "value": _v,
                                          "canonical": _v,
                                          "source": "preprocessor.ioc"})
                _seen_art_keys.add((_kind, _v))
        report_extraction = {
            "body_artifacts":     _paste_artifacts,
            "mitre_techniques":   list(techniques),
            "cves":               [],
            "threat_actors":      [],
            "malware_families":   [],
            "commands":           _paste_commands,
            "timeline":           [],
            "yara_rules":         [],
            "sigma_rules":        [],
            "hash_context":       {},
            "behaviors":          [],
            "totals": {
                "artifacts": len(_paste_artifacts),
                "mitre":     len(techniques),
                "cves":      0,
                "actors":    0,
                "malware":   0,
                "commands":  len(_paste_commands),
                "timeline":  0,
                "yara":      0,
                "sigma":     0,
                "behaviors": 0,
            },
            "source":             "paste_projection",   # provenance flag
        }

    # ── Build the OUTPUT text ─────────────────────────────────────
    lines: List[str] = []

    # HERO
    lines.append(_h1("Investigation Results"))
    lines.append("")
    lines.append(u_dict.get("hero_sentence") or u_dict.get("label", ""))
    lines.append("")

    # ── INVESTIGATION PIPELINE (URL inputs · Rule R19 + R20 + R21) ──
    # Analyst-visible narration of the full IDA → recursive investigation
    # → ICE flow.  Only rendered when acquisition actually happened;
    # for command inputs it's silent so nothing extra appears.
    if acquired_dict.get("ok"):
        _rext  = report_extraction or {}
        _sum   = _rext.get("investigation_summary") or {}
        _tot   = _rext.get("totals") or {}
        n_cmds = len(_rext.get("commands") or [])
        n_iocs = len(_rext.get("body_artifacts") or [])
        n_investigated = _sum.get("commands_analyzed", 0)

        lines.append(_h1("Investigation Pipeline"))
        lines.append("")
        lines.append(f"  ▸ SOURCE         URL · {acquired_dict.get('sitename') or 'unknown vendor'}")
        lines.append(f"                    {acquired_dict.get('title') or ''}")
        lines.append(f"  ▸ ACQUIRED       {acquired_dict.get('fetched_bytes', 0):,} bytes HTML"
                      f" · {acquired_dict.get('article_chars', 0):,} chars extracted"
                      f" · {acquired_dict.get('duration_ms', 0)} ms")
        lines.append(f"  ▸ EXTRACTED      {n_cmds} commands · {n_iocs} IOCs"
                      f" · {_tot.get('mitre', 0)} MITRE · {_tot.get('actors', 0)} actors"
                      f" · {_tot.get('malware', 0)} malware · {_tot.get('timeline', 0)} timeline")
        lines.append(f"  ▸ INVESTIGATED   {n_investigated}/{n_cmds} commands · "
                      f"{len(_sum.get('lolbins_union', []))} LOLBAS · "
                      f"{len(_sum.get('techniques_union', []))} MITRE (from recursive investigation)")
        lines.append(f"  ▸ CORRELATED     (see Incident block below · Rule R21)")
        lines.append("")

        # Per-command line-item view (Rule R20 · every extracted command
        # is recursively investigated, so surface it in the OUTPUT too).
        if n_cmds > 0:
            lines.append(_h1("Extracted Commands (recursively investigated · Rule R20)"))
            lines.append("")
            _cis = _rext.get("command_investigations") or []
            for _i, _cmd in enumerate(_rext.get("commands") or []):
                _ci = _cis[_i] if _i < len(_cis) else {}
                _status = "✓ INVESTIGATED" if _ci.get("language") and not _ci.get("error") else "○ pending"
                _lolb = ", ".join(lb.get("binary","") for lb in (_ci.get("lolbins") or []))
                _mit  = ", ".join(t.get("id","") for t in (_ci.get("techniques") or []))
                lines.append(f"  {_status}  {_cmd.get('command','')[:110]}")
                lines.append(f"    → {_cmd.get('purpose','')}")
                _det = []
                if _ci.get("language"): _det.append(f"lang={_ci['language']}")
                if _lolb:               _det.append(f"lolbas={_lolb}")
                if _mit:                _det.append(f"mitre={_mit}")
                if _det:
                    lines.append(f"    · {' · '.join(_det)}")
            lines.append("")

    # ── INPUT HEALTH (Stage-0 · IUE Layer 0) ──
    lines.append(_h1("Input Health"))
    lines.append("")
    if not health.issues:
        lines.append("  ✓ Valid input")
        lines.append("  ✓ No corruption detected")
        lines.append("  ✓ Ready for investigation")
        lines.append("")
    else:
        sev_glyph = {"error": "✗", "warn": "⚠", "info": "ℹ"}
        for issue in health.issues:
            glyph = sev_glyph.get(issue.severity, "•")
            lines.append(f"  {glyph} {issue.label} — {issue.detail}")
            if issue.evidence:
                lines.append(f"      evidence: {issue.evidence}")
        lines.append("")
    lines.append(_kv("Bytes Received", f"{health.bytes:,}", indent=2))
    lines.append(_kv("Pipeline Ready", "YES" if health.ready else "NO — see errors above", indent=2))
    lines.append("")

    # ── INPUT UNDERSTANDING ──
    lines.append(_h1("Input Understanding"))
    lines.append("")
    lines.append(_kv("Input Type",       u_dict.get("label", "?")))
    lines.append(_kv("Classification",   u_dict.get("input_type", "?")))
    lines.append(_kv("Confidence",       f"{int((u_dict.get('confidence') or 0) * 100)}%"))
    lines.append(_kv("Language",         (env.get("language") or "n/a")))
    lines.append(_kv("Decode Required",  "YES" if u_dict.get("decode_required") else "NO"))
    if u_dict.get("decode_reason"):
        lines.append(_kv("Decode Reason",    u_dict["decode_reason"]))
    lines.append(_kv("Next Engine",      u_dict.get("next_engine", "?")))
    lines.append("")

    contents = u_dict.get("contents") or {}
    lines.append("Extracted Contents")
    lines.append(_kv("Commands",       contents.get("commands", 0), indent=2))
    lines.append(_kv("Executables",    contents.get("executables", 0), indent=2))
    lines.append(_kv("Registry Keys",  contents.get("registry_keys", 0), indent=2))
    lines.append(_kv("File Paths",     contents.get("file_paths", 0), indent=2))
    lines.append(_kv("URLs",           contents.get("urls", 0), indent=2))
    lines.append(_kv("IPs",            contents.get("ips", 0), indent=2))
    lines.append(_kv("Hashes",         contents.get("hashes", 0), indent=2))
    lines.append(_kv("Process Edges",  contents.get("process_edges", 0), indent=2))
    lines.append(_kv("Stages",         contents.get("stages", 0), indent=2))
    lines.append("")

    reasoning = u_dict.get("reasoning") or []
    if reasoning:
        lines.append("Reasoning")
        for r in reasoning:
            lines.append(_bullet(r))
        lines.append("")

    # ── COMMAND ANALYSIS ──
    lines.append(_h1("Command Analysis"))
    lines.append("")
    stages = pre.stages
    # 2026-02-09 · URL path — when the input is a URL, `pre.stages` is
    # empty (no direct command to parse), but the acquired article's
    # extracted commands live in `report_extraction.commands`.  Render
    # a compact summary of each so the analyst sees them in the main
    # COMMAND ANALYSIS panel too — not just in the pipeline block.
    _rext_cmds = (report_extraction or {}).get("commands") or [] if acquired_dict.get("ok") else []
    if not stages and _rext_cmds:
        _rext_investigations = (report_extraction or {}).get("command_investigations") or []
        for _i, _c in enumerate(_rext_cmds, start=1):
            _ci = _rext_investigations[_i - 1] if _i - 1 < len(_rext_investigations) else {}
            title = (_c.get("purpose") or _c.get("command","")[:80])
            lines.append(_h2(f"Command {_i} · {title}"))
            lines.append("")
            lines.append(_kv("Command",   _c.get("command","")[:200]))
            lines.append(_kv("Head",      _c.get("head","")))
            lines.append(_kv("Purpose",   _c.get("purpose","")))
            _tech = [t.get("id","") for t in (_ci.get("techniques") or [])]
            if _tech:
                lines.append(_kv("MITRE",     ", ".join(_tech)))
            _lolb = [lb.get("binary","") for lb in (_ci.get("lolbins") or [])]
            if _lolb:
                lines.append(_kv("LOLBAS",    ", ".join(_lolb)))
            if _ci.get("language"):
                lines.append(_kv("Language",  _ci["language"]))
            lines.append(_kv("Source",    _c.get("source","")))
            # ── DECODED PAYLOAD (PowerShell -EncodedCommand base64) ──
            _rp = _ci.get("recovered_payload")
            if _rp:
                lines.append("")
                lines.append(_kv("Encoded blob",  f'{_ci.get("recovered_blob_len",0):,} chars → base64/{_ci.get("recovered_encoding","?")}'))
                lines.append("  Decoded PowerShell:")
                for _ln in _rp.splitlines()[:30]:
                    lines.append(f"    {_ln[:200]}")
                if len(_rp.splitlines()) > 30:
                    lines.append(f"    … ({len(_rp.splitlines()) - 30} more lines)")

            # ── CHAINED MULTI-LAYER DECODE STAGES ("CyberChef recipe") ──
            _stages = _ci.get("decode_stages") or []
            if _stages:
                lines.append("")
                lines.append("  Chained Decode Stages")
                for _sidx, _st in enumerate(_stages, start=1):
                    lines.append(
                        f"    ▸ Stage {_sidx}  {_st.get('stage',''):<24} "
                        f"{_st.get('bytes_in',0):>7} → {_st.get('bytes_out',0):>7} bytes "
                        f"({_st.get('elapsed_ms',0)} ms)"
                    )
            _pfinal = _ci.get("peeled_final") or ""
            if _pfinal:
                lines.append("")
                lines.append("  Final Peeled Payload (all layers removed):")
                for _ln in _pfinal.splitlines()[:30]:
                    lines.append(f"    {_ln[:200]}")
                if len(_pfinal.splitlines()) > 30:
                    lines.append(f"    … ({len(_pfinal.splitlines()) - 30} more lines)")
            _pips = ((_ci.get("peeled_iocs") or {}).get("ips") or [])
            if _pips:
                lines.append("")
                lines.append(f"  🎯 IOCs surfaced from peeled payload: {', '.join(_pips)}")
            lines.append("")
    elif not stages:
        lines.append("  (no commands recognised)")
        lines.append("")
    else:
        for i, s in enumerate(stages, start=1):
            title = s.title or (s.normalized_command or "")[:80]
            lines.append(_h2(f"Command {i} · {title}"))
            lines.append("")
            if s.normalized_command and s.normalized_command != title:
                lines.append(_kv("Command",   s.normalized_command[:200]))
            if s.objective:
                lines.append(_kv("Purpose",   s.objective))
            if s.tactic:
                lines.append(_kv("Tactic",    s.tactic))
            if s.mitre:
                lines.append(_kv("MITRE",     ", ".join(s.mitre)))
            if s.command_family:
                lines.append(_kv("Family",    s.command_family))
            if s.commonly_observed_in:
                lines.append(_kv("Commonly Observed In",
                               ", ".join(s.commonly_observed_in[:5])))
            lines.append(_kv("Confidence",  f"{int(s.confidence * 100)}%"))
            risk = _risk_for_tactic(s.tactic)
            if risk:
                lines.append(_kv("Risk",      risk))

            # ── What This Does — deterministic plain-English ──
            expl = _explain_stage(s.to_dict())
            if expl.get("intro") or expl.get("bullets") or expl.get("why"):
                lines.append("")
                lines.append("  What This Does")
                if expl.get("intro"):
                    lines.append(_bullet(expl["intro"], indent=4))
                for b in expl.get("bullets") or []:
                    lines.append(_bullet(b, indent=4))
                if expl.get("why"):
                    lines.append("")
                    lines.append(_bullet("Why it matters: " + expl["why"], indent=4))

            if s.evidence:
                lines.append("")
                lines.append("  Evidence")
                for e in s.evidence[:5]:
                    lines.append(_bullet(e, indent=4))
            lines.append("")

    # ── OVERALL BEHAVIOUR CHAIN ──
    chain_expl = _explain_chain([s.to_dict() for s in stages])
    if chain_expl:
        lines.append(_h1("Overall Behaviour"))
        lines.append("")
        lines.append(chain_expl)
        lines.append("")

    # ── IOC ANALYSIS ──
    lines.append(_h1("IOC Analysis"))
    lines.append("")
    if not ioc_by_kind:
        lines.append("  (no IOCs extracted)")
        lines.append("")
    else:
        for kind in ("ip", "url", "domain", "hash", "email",
                     "file_path", "registry", "service"):
            values = ioc_by_kind.get(kind) or []
            if not values:
                continue
            label = {
                "ip":         "IPs",
                "url":        "URLs",
                "domain":     "Domains",
                "hash":       "Hashes",
                "email":      "Emails",
                "file_path":  "File Paths",
                "registry":   "Registry Keys",
                "service":    "Services",
            }.get(kind, kind.capitalize())
            lines.append(_h2(label))
            for v in values[:15]:
                lines.append(_bullet(v))
            if len(values) > 15:
                lines.append(_bullet(f"… and {len(values) - 15} more"))
            lines.append("")

    # ── LOLBAS ANALYSIS ──
    lines.append(_h1("LOLBAS Analysis"))
    lines.append("")
    if not lolbins:
        lines.append("  (no LOLBAS binaries observed)")
        lines.append("")
    else:
        seen = set()
        for lb in lolbins:
            binary = (lb.get("binary") or "").lower()
            if binary in seen or not binary:
                continue
            seen.add(binary)
            entry = lolbas_lookup(binary) or {}
            lines.append(_h2(binary))
            legit = entry.get("legit") or entry.get("legitimate") or ""
            abuse = entry.get("abuse")  or entry.get("observed_abuse") or ""
            mitre = entry.get("mitre")  or lb.get("mitre") or []
            detection = entry.get("detection") or entry.get("detection_ideas") or []
            if legit:  lines.append(_kv("Legitimate Purpose", legit))
            if abuse:  lines.append(_kv("Observed Abuse", abuse))
            if mitre:  lines.append(_kv("MITRE", ", ".join(mitre)))
            if detection:
                lines.append("")
                lines.append("  Detection Ideas")
                for d in (detection[:4] if isinstance(detection, list) else [detection]):
                    lines.append(_bullet(d, indent=4))
            lines.append("")

    # ── MITRE COVERAGE ──
    lines.append(_h1("MITRE ATT&CK Coverage"))
    lines.append("")
    if not techniques:
        lines.append("  (no MITRE techniques mapped)")
        lines.append("")
    else:
        by_tactic: Dict[str, List[Dict[str, Any]]] = {}
        for t in techniques:
            tac = t.get("tactic") or t.get("tactic_name") or "Other"
            by_tactic.setdefault(tac, []).append(t)
        for tactic in sorted(by_tactic.keys()):
            lines.append(_h2(tactic))
            for t in by_tactic[tactic][:15]:
                tid = t.get("id") or ""
                name = t.get("name") or ""
                ev = t.get("evidence") or ""
                bullet = f"{tid} — {name}" if name else tid
                lines.append(_bullet(bullet))
                if ev:
                    lines.append(f"      evidence: {ev}")
            lines.append("")

    # ── DKP MATCHES ──
    if dkp_matches:
        lines.append(_h1("Decoder Knowledge Pack (DKP)"))
        lines.append("")
        for m in dkp_matches[:10]:
            name = m.get("name") or m.get("family") or m.get("id") or "?"
            conf = m.get("confidence")
            conf_str = f"{int(conf * 100)}%" if isinstance(conf, (int, float)) else "?"
            lines.append(_h2(f"{name}  ·  {conf_str}"))
            desc = m.get("description") or m.get("summary") or ""
            if desc:
                lines.append(desc)
            observed = m.get("commonly_observed_in") or []
            if observed:
                lines.append("")
                lines.append(_kv("Commonly Observed In",
                               ", ".join(observed[:5])))
            lines.append("")

    # ── SUMMARY ──
    lines.append(_h1("Summary"))
    lines.append("")
    lines.append(_kv("Threat Objective",   intent.get("primary_objective") or intent.get("objective") or "Undetermined"))
    lines.append(_kv("Attack Progress",    f"{intent.get('progress_pct', 0)}%"))

    # Build the Canonical confidence breakdown here so every consumer
    # (pane text + SSOT) reads the same values.
    ioc_kinds_dict = ioc_by_kind
    conf_break = build_confidence_breakdown(
        health=health.to_dict(),
        understanding=u_dict,
        preprocessor=pre.to_dict(),
        lolbas=lolbins,
        mitre=techniques,
        dkp=dkp_matches,
        iocs=ioc_kinds_dict,
        intent=intent,
    )

    lines.append(_kv("Confidence",         f"{conf_break.overall}% · {conf_break.label}"))
    lines.append(_kv("Commands Extracted", contents.get("commands", 0)))
    lines.append(_kv("LOLBAS",             len({(lb.get('binary') or '').lower() for lb in lolbins if lb.get('binary')})))
    lines.append(_kv("MITRE Techniques",   len(techniques)))
    lines.append(_kv("IOCs",               sum(len(v) for v in ioc_by_kind.values())))
    lines.append("")

    # ── CONFIDENCE EXPLANATION (Rule R10 · analyst-visible) ──
    lines.append(_h1("Confidence Explanation"))
    lines.append("")
    lines.append(_kv("Overall", f"{conf_break.overall}% · {conf_break.label}"))
    lines.append("")
    lines.append("Signals")
    _glyph = {"passed": "✓", "partial": "◐", "missing": "✗",
              "skipped": "○"}
    for sig in conf_break.signals:
        g = _glyph.get(sig.status, "•")
        line = f"  {g} {sig.label:<22} {sig.status.upper()}"
        if sig.detail:
            line += f" — {sig.detail}"
        lines.append(line)
    lines.append("")
    lines.append("")

    # Not-attribution disclaimer (WORKSPACE_ARCHITECTURE_RULES.md · R5).
    lines.append("Not attribution — historical prevalence only.")
    lines.append("Every conclusion links back to extracted evidence.")
    lines.append("")

    output = "\n".join(lines)

    # ── Canonical Investigation Object (SSOT) ──
    plan = build_plan(
        understanding=u_dict,
        preprocessor=pre.to_dict(),
        health=health.to_dict(),
    )
    canonical: Dict[str, Any] = {
        "metadata": {
            "version":         "1.0",
            "schema":          "investigation-v1",
            "engine_version":  "iue-2.0.0-slice-3",
            # ── Rule R17 · Investigation Reproducibility ──
            # Record the semantic version of every engine that
            # touched the investigation so a re-run against the same
            # input + versions produces a byte-identical SSOT.
            "engine_versions": {
                "iue":            "2.0.0",
                "die":            "1.4.0",
                "preprocessor":   "1.5.0",
                "bee":            "1.0.0",
                "intent":         "1.2.0",
                "narrative":      "1.1.0",
                "ida":            "1.0.0-slice-1",
            },
            "ruleset_version": "2026.03.01",
            "input_bytes":     len(src),
            "language":        env.get("language"),
        },
        "input":               {"raw": src},
        "health":              health.to_dict(),
        "profiling":           {
            "input_type":      u_dict.get("input_type"),
            "label":           u_dict.get("label"),
            "confidence":      u_dict.get("confidence"),
            "reasoning":       u_dict.get("reasoning"),
            "contents":        contents,
        },
        "understanding":       u_dict,
        "plan":                plan,
        "commands":            [_command_to_ssot(s) for s in stages],
        "iocs":                ioc_by_kind,
        "lolbas":              [_lolbas_to_ssot(lb) for lb in lolbins],
        "mitre":               techniques,
        "dkp":                 dkp_matches,
        # ── IDA (Slice 1 · IDA-1 + IDA-2 + URL Intent) ──
        # Rule R14: IDA is the ONLY engine allowed to acquire /
        # split artifacts.  Every artifact carries IDA-7 provenance
        # (offset, length, line, extractor) so evidence surfaces can
        # jump to the exact excerpt without re-parsing.
        "artifacts":           ida_verdict.get("artifacts", []),
        "artifact_summary":    ida_verdict.get("summary", {}),
        "ida":                 {
            "ida_class":  ida_verdict.get("ida_class", "none"),
            "confidence": ida_verdict.get("confidence", 0.0),
            "reasoning":  ida_verdict.get("reasoning", []),
            # URL Intent (Slice 1.6) — populated when the paste is a
            # bare URL.  Tells the frontend and downstream engines
            # what KIND of resource this URL is and whether IDA-3
            # will acquire it.
            "url_intent": ida_verdict.get("url_intent"),
        },
        "acquisition_plan":    _build_acquisition_plan(ida_verdict, completed_steps),
        # ── IDA-3 · Resource Acquisition Engine (Rule R19) ──
        # Only present when IDA-3 ran.  Empty dict otherwise.
        "acquired_document":   acquired_dict,
        # ── IDA-3.5 · Content Understanding ──
        "document_profile":    document_profile,
        # ── IDA-4 · Threat Report Extractors ──
        "report_extraction":   report_extraction,
        "preprocessor":        pre.to_dict(),
        "intent":              intent,
        # R12 · include the deterministic analyst narrative in the SSOT
        # so the frontend can retrieve everything in ONE fetch.
        "narrative":           _build_narrative(pre.to_dict()),
        "behaviour":           {
            "chain":            _explain_chain([s.to_dict() for s in stages]),
            "stages":           [_explain_stage(s.to_dict()) for s in stages],
        },
        # ── Rule R18 · Behavior Explanation Everywhere ──
        # Top-level explanations array + coverage metric.  Every
        # recognised command_family produces one entry.  IOC / MITRE /
        # LOLBAS explanation templates will fill this array in
        # subsequent BEE slices.
        "explanations":        _build_explanations_top_level(stages),
        "explanation_coverage": _build_explanation_coverage(stages),
        "confidence":          {
            "overall":      conf_break.overall,
            "label":        conf_break.label,
            "ai_inference": conf_break.ai_inference,
            "signals":      [s.__dict__ for s in conf_break.signals],
        },
        "engines_selected":    u_dict.get("engines_selected", []),
        "engines_skipped":     u_dict.get("engines_skipped", []),
    }

    # Rule R21 · v3 · The Incident is the SSOT.  Correlator emits BOTH
    # the unified `incident{}` (recommended surface for every future
    # projection: NIST IR, executive dashboard, STIX, PDF export) AND
    # the flat per-piece `ice{}` block (kept for backwards-compat with
    # existing projections built against the earlier shape).  New
    # projections MUST consume `SSOT.incident`.
    ice_block = _stage("ice_correlate", lambda: _ice_correlate(canonical))
    canonical["ice"]      = ice_block
    canonical["incident"] = ice_block.get("incident")

    # ── P0c-A (ADR-0014h) · Lift P0a body_artifacts into incident.iocs
    # Restores the canonical evidence contract at the producer boundary.
    # Only touches `incident.iocs` when:
    #   (a) the P0a paste-projection actually ran (source flag set), AND
    #   (b) `incident.iocs` is currently None/empty (never overwrites
    #       an existing ICE-populated value — URL-acquired path stays
    #       byte-identical because it never enters this branch).
    # No producer/consumer contract change beyond this one field.
    if (report_extraction.get("source") == "paste_projection"
            and canonical.get("incident") is not None
            and not (canonical["incident"].get("iocs") or [])):
        _paste_body_artifacts = report_extraction.get("body_artifacts") or []
        if _paste_body_artifacts:
            canonical["incident"]["iocs"] = list(_paste_body_artifacts)

    # ── Rule R22 · Paste-Only Synthesis ────────────────────────────
    def _do_paste_synth():
        try:
            from services.reasoning.paste_synthesis import synthesize as _paste_synthesize
            _paste_synthesize(canonical)
        except Exception:  # pragma: no cover — synthesis is additive
            pass
    _stage("paste_synthesis", _do_paste_synth)

    # ── Rule R24 · Investigation Performance Contract ─────────────
    total_ms = (_t.perf_counter() - _T0) * 1000.0
    peak_kb  = 0
    try:
        peak_kb = _res.getrusage(_res.RUSAGE_SELF).ru_maxrss  # KB on Linux
    except Exception:  # pragma: no cover
        peak_kb = 0
    tm_peak_mb = 0.0
    try:
        if _tm.is_tracing():
            _, peak_bytes = _tm.get_traced_memory()
            tm_peak_mb = round(peak_bytes / (1024 * 1024), 2)
        if _tm_started:
            _tm.stop()
    except Exception:  # pragma: no cover
        pass

    # ── R24 · guarantee #5 — Decode recursion telemetry ─────────
    # Layer-by-layer trace emitted by the DIE preprocessor (Base64,
    # UTF-16LE, GZip, ZLib, PowerShell constant folding, …).
    _decode_layers: List[Dict[str, Any]] = []
    try:
        _dl = getattr(pre, "decode_layers", None)
        if isinstance(_dl, list):
            _decode_layers = list(_dl)
    except Exception:  # pragma: no cover
        pass

    _truncation = {
        "behaviors_capped": bool((canonical.get("incident") or {}).get("truncated_behaviors")),
        "budget_hit":       total_ms > 3000.0,
    }

    # ── R24 · guarantee #3 — Backend ↔ Frontend correlation ID ──
    # Every render receives a UUID that the frontend echoes back on
    # POST /api/telemetry/frontend so backend + frontend timings for
    # THIS EXACT investigation can always be joined.
    import uuid as _uuid
    telemetry_id = f"telem_{_uuid.uuid4().hex[:16]}"

    performance = {
        "telemetry_id":     telemetry_id,
        "backend_ms":       round(total_ms, 2),
        "stages_ms":        _timings,
        "warnings":         _warnings,
        "budget_total_ms":  3000.0,
        "budget_hit":       total_ms > 3000.0,
        "peak_memory_mb":   tm_peak_mb,
        "peak_rss_kb":      int(peak_kb),
        "decode_layers":    _decode_layers,
        "truncation":       _truncation,
        "engine_health":    _engine_health,
        "input_bytes":      len(src.encode("utf-8", "replace")),
        # Frontend timings arrive via `POST /api/telemetry/frontend`
        # with the SAME `telemetry_id` so the two halves can always
        # be joined for a per-investigation performance record.
        "frontend_layout_ms": None,
        "frontend_render_ms": None,
        "frontend_paint_ms":  None,
        "frontend_total_ms":  None,
    }
    canonical.setdefault("metadata", {})
    canonical["metadata"]["performance"]       = performance
    # Backward-compat alias so existing consumers reading the old
    # `pipeline_timings` name continue to work unchanged.
    canonical["metadata"]["pipeline_timings"]  = {
        "total_ms":         performance["backend_ms"],
        "stages_ms":        performance["stages_ms"],
        "warnings":         performance["warnings"],
        "budget_total_ms":  performance["budget_total_ms"],
        "budget_hit":       performance["budget_hit"],
    }
    if total_ms > 1500.0 or _warnings:
        import logging as _log
        _log.getLogger("nivxray.telemetry").info(
            "render total=%.0fms peak=%.1fMB layers=%d warnings=%s stages=%s",
            total_ms, tm_peak_mb, len(_decode_layers), _warnings, _timings,
        )

    return {"output": output, "object": canonical}


def _build_narrative(pre_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic analyst narrative — invoked inline so the SSOT
    carries the executive summary / Sigma / YARA / MITRE-matrix /
    threat-actor context alongside every other section."""
    try:
        from .analyst_narrative import generate as _gen
        return _gen(pre_bundle) or {}
    except Exception:
        return {}


# ── Helpers ───────────────────────────────────────────────────────
def _risk_for_tactic(tactic: Optional[str]) -> Optional[str]:
    if not tactic:
        return None
    return {
        "Impact":               "Critical",
        "Command and Control":  "High",
        "Exfiltration":         "High",
        "Lateral Movement":     "High",
        "Persistence":          "High",
        "Defense Evasion":      "Medium",
        "Execution":            "Medium",
        "Discovery":            "Medium",
        "Initial Access":       "High",
    }.get(tactic, "Medium")


def _command_to_ssot(stage) -> Dict[str, Any]:
    d = stage.to_dict() if hasattr(stage, "to_dict") else dict(stage)
    expl = _explain_stage(d)
    return {
        "id":                    stage.id,
        "index":                 stage.index,
        "title":                 stage.title,
        "kind":                  stage.kind,
        "objective":             stage.objective,
        "tactic":                stage.tactic,
        "mitre":                 list(stage.mitre or []),
        "family":                stage.command_family,
        "commonly_observed_in":  list(stage.commonly_observed_in or []),
        "normalized_command":    stage.normalized_command,
        "raw_excerpt":           stage.raw_excerpt,
        "line_number":           stage.line_number,
        "confidence":            stage.confidence,
        "risk":                  _risk_for_tactic(stage.tactic),
        "explanation":           expl,     # {intro, bullets[], why}
    }


def _build_explanations_top_level(stages) -> List[Dict[str, Any]]:
    """Rule R18 · lift per-stage explanations into a top-level SSOT
    array so consumers (IVE Evidence Projection, exports, APIs)
    read a single reusable list — not scattered fields on commands[].
    Additional target kinds (IOC clusters, MITRE, LOLBAS, YARA, …)
    fill this array in subsequent BEE slices.
    """
    out: List[Dict[str, Any]] = []
    for s in stages:
        expl = _explain_stage(s.to_dict())
        if not (expl.get("intro") or expl.get("bullets") or expl.get("why")):
            continue
        out.append({
            "id":              f"expl-cmd-{s.index:03d}",
            "target_kind":     "command",
            "target_id":       s.id,
            "family":          s.command_family,
            "what_this_does":  [expl["intro"]] + list(expl.get("bullets") or []),
            "why_it_matters":  expl.get("why", ""),
            "evidence":        [s.normalized_command or s.raw_excerpt or ""],
            "coverage":        1.0 if expl.get("bullets") else 0.5,
            "template_id":     f"bee.{s.command_family}.v1"
                               if s.command_family else "bee.none",
        })
    return out


def _build_explanation_coverage(stages) -> Dict[str, Any]:
    """Rule R18 · emit the coverage metric consumed by the
    Investigation Quality Gate.  Recognised = has command_family.
    Explained = a BEE template produced ≥ 1 bullet."""
    recognised = [s for s in stages if s.command_family]
    explained: List[Any] = []
    gaps: List[str] = []
    for s in recognised:
        expl = _explain_stage(s.to_dict())
        if expl.get("bullets") or expl.get("intro"):
            explained.append(s)
        else:
            gaps.append(f"{s.id}:{s.command_family}")
    pct = int(round((len(explained) / len(recognised)) * 100)) if recognised else 100
    return {
        "recognised_targets": len(recognised),
        "explained":          len(explained),
        "percentage":         pct,
        "gaps":               gaps,
    }


def _lolbas_to_ssot(lb: Dict[str, Any]) -> Dict[str, Any]:
    binary = (lb.get("binary") or "").lower()
    entry = lolbas_lookup(binary) or {}
    return {
        "binary":            binary,
        "legit":             entry.get("legit") or entry.get("legitimate", ""),
        "abuse":             entry.get("abuse")  or entry.get("observed_abuse", ""),
        "mitre":             entry.get("mitre")  or lb.get("mitre") or [],
        "detection":         entry.get("detection") or entry.get("detection_ideas") or [],
    }



# ══════════════════════════════════════════════════════════════════
# Acquisition Plan (SSOT projection · Slice 1.6)
# ══════════════════════════════════════════════════════════════════
# When IDA classifies the paste as an acquirable URL, we surface the
# concrete IDA pipeline (steps IDA-3 → IDA-3.5 → IDA-4) as an
# `acquisition_plan[]` block in the SSOT so the frontend can render
# the CORRECT investigation plan instead of the legacy
# "atomic-ioc-passthrough" surface.  Rule R14: only IDA writes here.
#
# Every step carries `status ∈ {done, running, pending, skipped}`.
# In Slice 1.6 only IDA-1 + IDA-2 are `done`; the network-bound
# slices are `pending` until IDA-3 ships.  The frontend renders
# `pending` as greyed-out with a "queued" badge — the analyst sees
# the plan the platform intends to execute, not an empty screen.

_ACQ_STEP_TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
    "threat_report_url": [
        {"id": "ida-1", "title": "Identify Input",                 "engine": "IDA-1 Input Classifier",   "detail": "Classify the paste as a bare URL."},
        {"id": "ida-2", "title": "Determine Resource Type",        "engine": "IDA-1 URL Intent",         "detail": "Match host against vendor knowledge pack; confirm threat-report intent."},
        {"id": "ida-3", "title": "Acquire Resource",               "engine": "IDA-3 URL Fetcher",        "detail": "Safe HTTPS fetch of the article HTML."},
        {"id": "ida-3.5", "title": "Understand Document",          "engine": "IDA-3.5 Content Understanding", "detail": "Detect vendor, sections, capabilities, timeline / MITRE / YARA / Sigma presence."},
        {"id": "ida-4-cmds",   "title": "Extract Commands",        "engine": "IDA-4 Threat Report Extractors", "detail": "Pull PowerShell / cmd / bash / LOLBAS command samples."},
        {"id": "ida-4-mitre",  "title": "Extract MITRE ATT&CK",    "engine": "IDA-4",                    "detail": "Extract technique IDs referenced in the article."},
        {"id": "ida-4-iocs",   "title": "Extract IOCs",            "engine": "IDA-4",                    "detail": "Extract hashes, URLs, IPs, domains, registry keys, file paths."},
        {"id": "ida-4-time",   "title": "Extract Timeline",        "engine": "IDA-4",                    "detail": "Extract campaign / incident timeline events."},
        {"id": "ida-4-malw",   "title": "Extract Malware / Threat Actor / Victim", "engine": "IDA-4",   "detail": "Named-entity extraction over the article body."},
        {"id": "ida-4-cve",    "title": "Extract CVEs",            "engine": "IDA-4",                    "detail": "Extract CVE identifiers referenced in the article."},
        {"id": "ida-4-detect", "title": "Extract YARA / Sigma",    "engine": "IDA-4",                    "detail": "Extract detection rules published in the article."},
        {"id": "ida-6",  "title": "Build Knowledge Graph",         "engine": "IDA-6 Semantic Relationship Builder", "detail": "Connect commands ↔ MITRE ↔ IOCs ↔ malware ↔ actor ↔ victim ↔ timeline."},
        {"id": "die",    "title": "Route Commands to DIE",         "engine": "DIE",                      "detail": "Decode any obfuscated command samples found in the article."},
        {"id": "ssot",   "title": "Assemble SSOT",                 "engine": "SSOT",                     "detail": "Unify every extractor's output into the Canonical Investigation Object."},
        {"id": "report", "title": "Generate Investigation Report", "engine": "IVE",                      "detail": "Project the NIST IR sections + Evidence Completeness surface."},
    ],
    "code_snippet_url": [
        {"id": "ida-1", "title": "Identify Input",           "engine": "IDA-1 Input Classifier", "detail": "Classify the paste as a bare URL."},
        {"id": "ida-2", "title": "Determine Resource Type",  "engine": "IDA-1 URL Intent",       "detail": "Match host against paste-host knowledge pack; confirm code-snippet intent."},
        {"id": "ida-3", "title": "Acquire Snippet",          "engine": "IDA-3 URL Fetcher",      "detail": "Fetch the raw paste content."},
        {"id": "ida-4-cmds", "title": "Route Snippet to DIE",  "engine": "DIE",                   "detail": "Decode + analyse the snippet as though it were pasted directly."},
        {"id": "ida-4-iocs", "title": "Extract IOCs",         "engine": "IDA-4",                 "detail": "Extract any IOCs embedded in the snippet."},
        {"id": "ssot",  "title": "Assemble SSOT",             "engine": "SSOT",                  "detail": "Merge into the Canonical Investigation Object."},
    ],
    "repository_url": [
        {"id": "ida-1", "title": "Identify Input",           "engine": "IDA-1 Input Classifier", "detail": "Classify the paste as a bare URL."},
        {"id": "ida-2", "title": "Determine Resource Type",  "engine": "IDA-1 URL Intent",       "detail": "Match host against repository-host knowledge pack."},
        {"id": "ida-3", "title": "Enumerate Repository",     "engine": "IDA-3 URL Fetcher",      "detail": "Fetch README + top-level files; enumerate suspicious payloads."},
        {"id": "ida-4-cmds",   "title": "Extract Commands",  "engine": "IDA-4",                  "detail": "Pull command samples from README / scripts."},
        {"id": "ida-4-iocs",   "title": "Extract IOCs",      "engine": "IDA-4",                  "detail": "Extract IOCs referenced in the repo."},
        {"id": "ssot",  "title": "Assemble SSOT",            "engine": "SSOT",                   "detail": "Merge into the Canonical Investigation Object."},
    ],
    "file_resource_url": [
        {"id": "ida-1", "title": "Identify Input",           "engine": "IDA-1 Input Classifier", "detail": "Classify the paste as a bare URL."},
        {"id": "ida-2", "title": "Determine Resource Type",  "engine": "IDA-1 URL Intent",       "detail": "URL points at a direct-file / cloud-drive resource."},
        {"id": "ida-3", "title": "Safe Download",            "engine": "IDA-3 URL Fetcher",      "detail": "Safe-download the file (size + type sandbox)."},
        {"id": "die",   "title": "Route File to DIE",        "engine": "DIE",                    "detail": "Hand the downloaded bytes to DIE for magic-byte + decoder analysis."},
        {"id": "ida-4-iocs", "title": "Extract IOCs",        "engine": "IDA-4",                  "detail": "Extract IOCs from the file (once decoded)."},
        {"id": "ssot",  "title": "Assemble SSOT",            "engine": "SSOT",                   "detail": "Merge into the Canonical Investigation Object."},
    ],
    "ioc_portal_url": [
        {"id": "ida-1", "title": "Identify Input",              "engine": "IDA-1 Input Classifier", "detail": "Classify the paste as a bare URL."},
        {"id": "ida-2", "title": "Determine Resource Type",     "engine": "IDA-1 URL Intent",       "detail": "Host is an IOC / reputation portal."},
        {"id": "ioc",   "title": "Route to IOC / OSINT Lane",   "engine": "IOCE",                    "detail": "No acquisition — hand the URL to the reputation lookup lane."},
    ],
    "atomic_ioc_url": [
        {"id": "ida-1", "title": "Identify Input",              "engine": "IDA-1 Input Classifier", "detail": "Classify the paste as a bare URL."},
        {"id": "ida-2", "title": "Determine Resource Type",     "engine": "IDA-1 URL Intent",       "detail": "URL does not match any acquirable-resource category."},
        {"id": "ioc",   "title": "Route to IOC / OSINT Lane",   "engine": "IOCE",                    "detail": "Treat as atomic URL IOC; run reputation checks."},
    ],
}

# What is currently implemented in the platform.  Every id NOT in
# this set defaults to `pending` (queued for a future IDA slice).
_ACQ_STEP_STATUS: Dict[str, str] = {
    "ida-1": "done",
    "ida-2": "done",
    # `ida-3` is a real endpoint in Slice 1.6 as a *placeholder*
    # (returns "not implemented yet") — surfaced as pending until the
    # network fetcher lands.
    "ida-3":       "pending",
    "ida-3.5":     "pending",
    "ida-4-cmds":  "pending",
    "ida-4-mitre": "pending",
    "ida-4-iocs":  "pending",
    "ida-4-time":  "pending",
    "ida-4-malw":  "pending",
    "ida-4-cve":   "pending",
    "ida-4-detect":"pending",
    "ida-6":       "pending",
    "die":         "pending",
    "ssot":        "pending",
    "report":      "pending",
    "ioc":         "pending",
}


def _build_acquisition_plan(ida_verdict: Dict[str, Any],
                             completed_steps: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Deterministic acquisition-plan projection.

    `completed_steps` is the list of step ids that actually ran to
    completion during THIS request (populated by the IDA-3/3.5/4
    acquisition pass).  When a step id is present in the list we
    override the template's default `pending` status with `done` —
    that's how the analyst sees the plan progress live instead of a
    static "queued" list.

    Empty list when the IDA verdict is not a URL class — the SSOT
    already carries commands / iocs / mitre for those inputs.
    """
    ida_class = ida_verdict.get("ida_class") or ""
    template = _ACQ_STEP_TEMPLATES.get(ida_class)
    if not template:
        return []
    done_set = set(completed_steps or ())
    return [
        {
            "id":     step["id"],
            "title":  step["title"],
            "engine": step["engine"],
            "detail": step["detail"],
            "status": "done" if step["id"] in done_set
                              else _ACQ_STEP_STATUS.get(step["id"], "pending"),
        }
        for step in template
    ]
