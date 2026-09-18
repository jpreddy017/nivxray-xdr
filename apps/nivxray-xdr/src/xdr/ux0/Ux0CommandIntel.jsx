/**
 * E2E-UX0 · Command Intelligence composition (blueprint §3.6).
 *
 * This panel replaces the rejected `<pre>{JSON.stringify(res)}</pre>`. It is
 * the SAME composition in both containers (flyout from an incident artifact,
 * and the standalone `/xdr/intelligence/command` page) — only the container
 * changes.
 *
 * It calls the REAL `POST /api/analyze/command` and renders the real contract,
 * including the Lane B honesty fields: `decode_status`,
 * `unresolved_expressions[]` and `canonical_decoded_artifact`. Raw JSON exists
 * exactly once, inside `Technical details`, collapsed.
 */
import React, { useCallback, useEffect, useState } from "react";
import { Zap, AlertTriangle } from "lucide-react";

import api from "@/lib/api";
import { NxVerdict, NxProvenanceChip, NxEmpty } from "@/xdr/nx";
import { Panel, TechnicalDetails } from "./Ux0Parts";
import { CI_SAMPLE } from "./ux0Fixtures";

const STATUS_COPY = {
  RECOVERED: "Every layer resolved to a fixed point.",
  PARTIALLY_RECOVERED: "Some layers resolved; constructs listed below were not evaluated.",
  LIMIT_REACHED: "Recursive decoding stopped at the layer budget with work still pending.",
  AMBIGUOUS: "Multiple payload candidates tied — an analyst must choose.",
  DETECTED: "Encoded material was identified but not autonomously decoded.",
  FAILED: "Decoding was attempted and produced no usable output.",
  UNSUPPORTED: "The construct is outside the supported grammar.",
  NOT_REQUIRED: "No encoded or obfuscated construct was identified.",
};

export default function Ux0CommandIntel({ initial = CI_SAMPLE, compact = false }) {
  const [input, setInput] = useState(initial);
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const run = useCallback(async (span, value) => {
    const text = (value ?? input).trim();
    if (!text) return;
    setBusy(true); setErr(null);
    try {
      const r = await api.post("/analyze/command", {
        input: text, ...(span ? { force_decode_span: span } : {}),
      });
      setRes(r?.data || null);
    } catch (x) {
      setErr(x?.response?.data?.detail || x?.message || "analysis failed");
      setRes(null);
    } finally { setBusy(false); }
  }, [input]);

  useEffect(() => { run(null, initial); /* eslint-disable-next-line */ }, [initial]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14,
                   marginTop: compact ? 0 : 18 }}
         data-testid="ux0-command-intel">
      <Panel title="Command under analysis" testid="ux0-ci-input">
        {compact ? (
          <div className="ux0-mono" data-testid="ux0-ci-observed"
               style={{ fontSize: 11.5, lineHeight: 1.6 }}>{input}</div>
        ) : (
          <textarea className="ux0-input" rows={3} value={input}
                    onChange={(e) => setInput(e.target.value)}
                    data-testid="ux0-ci-textarea" />
        )}
        <button type="button" className="ux0-btn ux0-btn--primary"
                style={{ marginTop: 10 }} disabled={busy}
                onClick={() => run(null)} data-testid="ux0-ci-analyse">
          <Zap size={13} /> {busy ? "Analysing…" : compact ? "Re-analyse" : "Analyse"}
        </button>
      </Panel>

      {err && (
        <Panel title="Analysis unavailable" testid="ux0-ci-error">
          <NxEmpty compact title="The command analyser did not respond."
                   hint={String(err)} />
        </Panel>
      )}

      {res && <CiBody res={res} compact={compact} onForce={(s) => run(s)} />}
    </div>
  );
}

function CiBody({ res, onForce, compact = false }) {
  const status = res.decode_status || "NOT_REQUIRED";
  const canon = res.canonical_decoded_artifact || {};
  const unresolved = res.unresolved_expressions || [];
  const ps = res.parsed_structure || {};
  const verdict = deriveVerdict(res);

  return (
    <>
      <Panel title="Assessment" flush testid="ux0-ci-assessment">
        <div className={`ux0-assess${verdict === "benign" ? " is-clean" : ""}`}>
          <div className="ux0-assess__row">
            <NxVerdict value={verdict} testid="ux0-ci-verdict" />
            <span className="ux0-status" data-s={status} data-testid="ux0-ci-status">
              {status.replace(/_/g, " ")}
            </span>
            <span style={{ fontSize: 11.5, color: "var(--nx-muted)",
                            fontFamily: "var(--nx-font-mono)" }}>
              {ps.interpreter} · {ps.tokenizer} · {ps.shell_token_count ?? ps.token_count} shell tokens
            </span>
          </div>
          <p className="ux0-prose" data-testid="ux0-ci-summary">
            {res.behavior_summary} {STATUS_COPY[status] || ""}
          </p>
          {res.decode_status_reason && (
            <div style={{ fontSize: 11.5, color: "var(--nx-text-dim)" }}>
              {res.decode_status_reason}
            </div>
          )}
        </div>
      </Panel>

      {res.needs_choice && (
        <Panel title="Analyst decision required" testid="ux0-ci-choice">
          <p className="ux0-prose">{res.choice_reason}</p>
          <div className="ux0-chiprow" style={{ marginTop: 10 }}>
            {(res.identified_payloads || []).map((p, i) => (
              <button key={i} type="button" className="ux0-proof"
                      onClick={() => onForce(p.span)}
                      data-testid={`ux0-ci-choice-${i}`}>
                decode {p.role} · {String(p.span).slice(0, 34)}…
              </button>
            ))}
          </div>
        </Panel>
      )}

      <Panel title="Execution flow" flush testid="ux0-ci-flow">
        <div className="ux0-flow">
          {buildFlow(res).map((s, i) => (
            <div key={i} className="ux0-flow__step" data-testid={`ux0-ci-flow-${i}`}>
              <span className="ux0-flow__n">{i + 1}</span>
              <span className="ux0-flow__k">{s.stage}</span>
              <span className="ux0-flow__v">{s.value}</span>
              <NxProvenanceChip provenance={s.provenance} />
            </div>
          ))}
        </div>
      </Panel>

      <div className={compact ? "ux0-stack" : "ux0-grid"} style={{ marginTop: 0 }}>
        <div className={compact ? "" : "ux0-col8"}
             style={compact ? { display: "flex", flexDirection: "column", gap: 14 } : undefined}>
          <Panel title="Decoded artifact" testid="ux0-ci-artifact">
            <div className="ux0-artifact">
              {!canon.promoted && (
                <div className="ux0-artifact__warn" data-testid="ux0-ci-not-promoted">
                  <AlertTriangle size={15} style={{ flexShrink: 0, marginTop: 1 }} />
                  <span><strong>Not promoted as the canonical payload.</strong>{" "}
                    {canon.reason}</span>
                </div>
              )}
              {(canon.text || canon.candidate_text) ? (
                <pre className="ux0-pre" data-testid="ux0-ci-artifact-body">
                  {canon.text || canon.candidate_text}
                </pre>
              ) : (
                <NxEmpty compact title="No artifact was recovered."
                         hint={canon.reason || "Nothing in this command required decoding."} />
              )}
              {canon.artifact_class && (
                <div style={{ marginTop: 8, fontSize: 11,
                               fontFamily: "var(--nx-font-mono)",
                               color: "var(--nx-muted)" }}>
                  class {canon.artifact_class} · depth {canon.depth ?? 0} ·
                  source {canon.source_role || "—"}
                </div>
              )}
            </div>
          </Panel>

          {unresolved.length > 0 && (
            <Panel title={`Not evaluated (${unresolved.length})`} flush
                   testid="ux0-ci-unresolved"
                   right={<span style={{ fontSize: 11, color: "var(--nx-high)" }}>
                     these constructs block a full recovery
                   </span>}>
              <div className="ux0-unres">
                {unresolved.map((u, i) => (
                  <div key={i} className="ux0-unres__row"
                       data-testid={`ux0-ci-unresolved-${i}`}>
                    <span className="ux0-unres__k">{u.kind}</span>
                    <span className="ux0-unres__v">
                      {u.expression}
                      <div style={{ color: "var(--nx-faint)", marginTop: 2,
                                     fontFamily: "var(--nx-font-body)", fontSize: 11 }}>
                        {u.reason}
                      </div>
                    </span>
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </div>

        <div className={compact ? "" : "ux0-col4"}
             style={compact ? { display: "flex", flexDirection: "column", gap: 14 } : undefined}>
          <Panel title="What it does" testid="ux0-ci-behaviours">
            {(res.behaviors || []).length ? (
              <ul className="ux0-bullets">
                {res.behaviors.map((b, i) => <li key={i}>{b.detail}</li>)}
              </ul>
            ) : (
              <NxEmpty compact title="No high-risk behaviour classified."
                       hint="The command matched no downloader, executor or persistence pattern." />
            )}
          </Panel>

          <Panel title="Indicators" testid="ux0-ci-iocs">
            <Iocs iocs={res.iocs} />
          </Panel>

          <Panel title="ATT&CK · evidence-backed only" testid="ux0-ci-mitre">
            <Attack res={res} />
          </Panel>

          <Panel title="Artifact classes" flush testid="ux0-ci-classes">
            <div className="ux0-unres">
              {(res.identified_payloads || []).length ? (
                res.identified_payloads.map((p, i) => (
                  <div key={i} className="ux0-unres__row">
                    <span className="ux0-unres__k">{p.artifact_class}</span>
                    <span className="ux0-unres__v">
                      {String(p.span).slice(0, 44)}…
                      <div style={{ color: "var(--nx-faint)", marginTop: 2,
                                     fontFamily: "var(--nx-font-body)", fontSize: 11 }}>
                        {p.role} · {p.auto_decoded ? "decoded" : "not decoded"}
                      </div>
                    </span>
                  </div>
                ))
              ) : (
                <div style={{ padding: 14 }}>
                  <NxEmpty compact title="No payload candidates."
                           hint="Nothing in this command line looked encoded." />
                </div>
              )}
            </div>
          </Panel>
        </div>
      </div>

      <Panel title="Decoder chain" flush testid="ux0-ci-chain">
        <div className="ux0-unres">
          {(res.decode_chains || []).length ? (
            res.decode_chains.map((d, i) => (
              <div key={i} className="ux0-unres__row">
                <span className="ux0-unres__k">
                  {d.encoding} · depth {d.depth ?? 0}
                </span>
                <span className="ux0-unres__v">
                  {d.role}
                  {(d.chains || []).flatMap((c) => c.steps || []).map((s, j) => (
                    <div key={j} style={{ color: "var(--nx-faint)", marginTop: 3,
                                           fontFamily: "var(--nx-font-body)",
                                           fontSize: 11 }}>
                      {s.op}
                      {s.complete === false && (
                        <strong style={{ color: "var(--nx-high)" }}> · incomplete</strong>
                      )} — {s.reason}
                    </div>
                  ))}
                </span>
              </div>
            ))
          ) : (
            <div style={{ padding: 14 }}>
              <NxEmpty compact title="No decode was performed."
                       hint="Either nothing was encoded, or every candidate was a fragment of a runtime-assembled value." />
            </div>
          )}
        </div>
      </Panel>

      <TechnicalDetails json={res} testid="ux0-ci-tech" />
    </>
  );
}

/* ── derivations (presentation only — no analysis happens here) ─────────── */

function deriveVerdict(res) {
  if (res.amsi_bypass?.detected) return "malicious";
  const tags = new Set((res.behaviors || []).map((b) => b.tag));
  if (tags.has("in-memory-execute") || tags.has("download-and-execute")) return "malicious";
  if ((res.decode_chains || []).length || tags.size) return "suspicious";
  return "benign";
}

function buildFlow(res) {
  const ps = res.parsed_structure || {};
  const out = [];
  if (ps.executable_span?.text) {
    out.push({
      stage: "Observed", provenance: "observed",
      value: `${ps.executable_span.text} ${(ps.switches || []).join(" ")}`.trim(),
    });
  }
  const ast = res.ast_deobfuscation || {};
  const frags = (res.identified_payloads || [])
    .filter((p) => p.artifact_class === "FRAGMENT").length;
  if (frags || ast.semantic_transformations) {
    out.push({
      stage: "Constructed", provenance: "reconstructed",
      value: frags
        ? `${frags} literal fragment(s) are operands of a value assembled at runtime`
        : `${ast.semantic_transformations} semantic transformation(s) applied`,
    });
  }
  (res.decode_chains || [])
    .filter((d) => d.encoding !== "ps-ast")
    .forEach((d) => out.push({
      stage: `Decoded L${(d.depth ?? 0) + 1}`, provenance: "decoded",
      value: `${d.encoding} · ${d.role} → ${(d.final_output || "").slice(0, 120)}`,
    }));
  (res.execution_flow || []).slice(0, 6).forEach((e) => out.push({
    stage: "Executed", provenance: "inferred",
    value: `${e.label}  ·  ${e.mitre_id}  ·  ${e.severity}`,
  }));
  if (!out.length) {
    out.push({ stage: "Observed", provenance: "observed",
               value: res.original_command || "—" });
  }
  return out;
}

function Iocs({ iocs }) {
  const groups = [["urls", "URL"], ["ips", "IP"], ["domains", "Domain"],
                  ["paths", "Path"], ["regkeys", "Registry"]];
  const present = groups.filter(([k]) => (iocs?.[k] || []).length);
  if (!present.length) {
    return <NxEmpty compact title="No indicators extracted."
                    hint="No network, path or registry indicator appeared in any recovered layer." />;
  }
  return present.map(([k, label]) => (
    <div key={k} style={{ marginBottom: 8 }}>
      <div className="ux0-fact__k">{label}</div>
      {iocs[k].slice(0, 6).map((v) => (
        <div key={v} className="ux0-mono" style={{ fontSize: 11.5, marginTop: 2 }}>{v}</div>
      ))}
    </div>
  ));
}

function Attack({ res }) {
  const cited = new Map();
  (res.execution_flow || []).forEach((e) => {
    if (e.mitre_id && !cited.has(e.mitre_id)) cited.set(e.mitre_id, e.evidence);
  });
  (res.amsi_bypass?.techniques || []).forEach((t) => {
    if (t.mitre_id && !cited.has(t.mitre_id)) cited.set(t.mitre_id, t.name);
  });
  const uncited = (res.mitre || []).filter((m) => !cited.has(m.id));
  if (!cited.size) {
    return <NxEmpty compact title="No technique could cite its evidence."
                    hint={uncited.length
                      ? `${uncited.length} technique(s) were suggested without a citable artifact and are withheld.`
                      : "No ATT&CK technique matched a recovered layer."} />;
  }
  return (
    <>
      {[...cited.entries()].map(([id, ev]) => (
        <div key={id} style={{ marginBottom: 8 }}>
          <span className="ux0-mono" style={{ fontWeight: 600 }}>{id}</span>
          <div style={{ fontSize: 11, color: "var(--nx-muted)", marginTop: 2 }}>
            cited by: {ev}
          </div>
        </div>
      ))}
      {uncited.length > 0 && (
        <div style={{ fontSize: 11, color: "var(--nx-faint)", marginTop: 6 }}>
          {uncited.length} further technique(s) had no citable artifact and are
          withheld rather than shown.
        </div>
      )}
    </>
  );
}
