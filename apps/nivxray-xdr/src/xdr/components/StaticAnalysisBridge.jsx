/**
 * StaticAnalysisBridge · P1.7
 *
 * The Sandbox pivot, wired to the ONE hash-keyed static-analysis
 * contract that exists in this repository:
 *
 *   GET /api/v2/decoded-artifacts/{sha256}      → persisted AnalystReport
 *   GET /api/v2/decoded-artifacts/stats/summary → store size
 *
 * (backend/routers/decoded_artifacts.py → v2/decoded_artifacts.py)
 *
 * Two keys are looked up, because the store is keyed on the digest of
 * the analysed input:
 *   1. FILE DIGEST — `event.sha256` as recorded by the sensor.
 *   2. COMMAND-LINE DIGEST — sha256 of the observed command line,
 *      computed in-browser.  That is the store's own key scheme
 *      (verified: sha256(command_line) === artifact.sha256), so this is
 *      a lookup, not a derivation of new evidence.
 *
 * Boundaries stated in the UI, never worked around:
 *   • Static only.  No dynamic detonation runtime is configured.
 *   • Read-only.  There is no submit-by-hash route, because static
 *     analysis needs the bytes and telemetry carries only a digest;
 *     acquiring bytes needs a sensor we do not have.
 *   • 404 is an evidence statement (`◇ NO STATIC ANALYSIS RECORD`).
 *     A transport/route failure is the capability failure
 *     (`⊘ … CONTRACT NOT VERIFIED`).
 */
import React, { useEffect, useState } from "react";
import { X, FlaskConical, Loader2 } from "lucide-react";

import { getDecodedArtifact, getDecodedArtifactStats } from "@/nivxforge/edrApi";

const BANNER = "STATIC MALWARE ANALYSIS ONLY · DYNAMIC DETONATION RUNTIME NOT CONFIGURED";

function Row({ k, v }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "132px 1fr", gap: 8,
                  alignItems: "baseline", marginBottom: 5 }}>
      <div style={{ color: "var(--faint)", fontSize: 9.5, fontWeight: 800,
                    textTransform: "uppercase", letterSpacing: ".3px" }}>{k}</div>
      <div className="mono" style={{ color: "var(--text-dim)", fontSize: 10.5,
                                     wordBreak: "break-all" }}>{v}</div>
    </div>
  );
}

function HashLookup({ title, sha256, keyNote, storeSize, testid }) {
  const [state, setState] = useState({ status: "idle" });

  useEffect(() => {
    let cancel = false;
    if (!sha256) { setState({ status: "no_hash" }); return undefined; }
    setState({ status: "loading" });
    (async () => {
      try {
        const res = await getDecodedArtifact(sha256);
        if (cancel) return;
        if (res.status === 404) setState({ status: "not_found" });
        else setState({ status: "found",
                        artifact: res.data?.artifact || res.data });
      } catch (e) {
        const code = e?.response?.status;
        if (cancel) return;
        setState({ status: "unavailable",
                   error: e?.response?.data?.detail || e?.message, code });
      }
    })();
    return () => { cancel = true; };
  }, [sha256]);

  const a = state.artifact || {};

  return (
    <section style={{ border: "1px solid #212B36", borderRadius: 4,
                      padding: 10, marginBottom: 10, background: "#0D1218" }}
             data-testid={testid}>
      <div className="section-title" style={{ marginBottom: 6 }}>{title}</div>
      <Row k="Lookup key" v={sha256 || <span className="nx-ep" data-ep="no_evidence"
                                             data-known="true">◇ NOT AVAILABLE</span>} />
      <Row k="Key source" v={keyNote} />

      {state.status === "no_hash" && (
        <div className="nx-ep" data-ep="no_evidence" data-known="true"
             style={{ display: "block", marginTop: 6 }}>
          ◇ THIS OBSERVATION CARRIES NO SUCH DIGEST — NOTHING IS DERIVED
        </div>
      )}

      {state.status === "loading" && (
        <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                       marginTop: 6 }}>
          <Loader2 size={11} className="spin"
                   style={{ verticalAlign: "middle", marginRight: 5 }} />
          Querying the decoded-artifact store …
        </div>
      )}

      {state.status === "unavailable" && (
        <div style={{ marginTop: 6 }} data-testid={`${testid}-unavailable`}>
          <div className="nx-ep" data-ep="capability_unavailable" data-known="true"
               style={{ display: "block" }}>
            ⊘ CAPABILITY UNAVAILABLE — STATIC ANALYSIS API CONTRACT NOT VERIFIED
          </div>
          <div className="mono" style={{ marginTop: 5, fontSize: 10, color: "#ff9494" }}>
            {state.code ? `HTTP ${state.code} · ` : ""}
            {String(state.error || "route did not respond")}
          </div>
        </div>
      )}

      {state.status === "not_found" && (
        <div style={{ marginTop: 6 }} data-testid={`${testid}-not-found`}>
          <div className="nx-ep" data-ep="no_evidence" data-known="true"
               style={{ display: "block" }}>
            ◇ NO STATIC ANALYSIS RECORD FOR THIS DIGEST
          </div>
          <div style={{ marginTop: 5, fontSize: 10.5, color: "var(--text-dim)",
                        lineHeight: 1.7 }}>
            The store holds <span className="mono">{storeSize ?? "—"}</span> analysed
            artifacts and this digest is not among them. It is keyed on inputs the
            static pipeline has already processed — not a reputation service — so it
            returns nothing rather than a guess.
          </div>
        </div>
      )}

      {state.status === "found" && (
        <div style={{ marginTop: 6 }} data-testid={`${testid}-found`}>
          <div className="nx-ep" data-ep="evidence_present" data-known="true"
               style={{ display: "block", marginBottom: 7 }}>
            ◆ STATIC ANALYSIS RECORD PRESENT
          </div>
          <Row k="Verdict" v={a.verdict || "◇"} />
          <Row k="Risk score" v={a.risk_score != null ? `${a.risk_score}/100` : "◇"} />
          <Row k="Decode layers" v={a.trace_layers ?? "◇"} />
          <Row k="Pipeline" v={a.pipeline_version || "◇"} />
          <Row k="Analysed binary" v={a.command_binary || "◇"} />
          {a.command_line && (
            <Row k="Analysed input"
                 v={<span style={{ display: "block", whiteSpace: "pre-wrap" }}>
                      {String(a.command_line).slice(0, 700)}
                    </span>} />
          )}
          <Row k="ATT&CK (ICE)"
               v={(a.mitre_ids || []).length ? a.mitre_ids.join(", ") : "◇"} />
          <Row k="IOCs (IUE)"
               v={a.iocs_summary && Object.keys(a.iocs_summary).length
                   ? Object.entries(a.iocs_summary)
                       .map(([k, v]) => `${k}: ${(v || []).join(", ")}`).join(" · ")
                   : "◇"} />
          <Row k="First seen" v={a.provenance?.first_seen || "◇"} />
          <Row k="Reuses" v={a.provenance?.hit_count ?? "◇"} />
          <details style={{ marginTop: 6 }}>
            <summary className="mono" style={{ fontSize: 9.8, cursor: "pointer",
                                               color: "var(--faint)" }}>
              Raw artifact record
            </summary>
            <pre className="mono" style={{ fontSize: 9, maxHeight: 240,
                                           overflow: "auto", marginTop: 6,
                                           color: "var(--text-dim)" }}>
              {JSON.stringify(a, null, 1).slice(0, 8000)}
            </pre>
          </details>
        </div>
      )}
    </section>
  );
}

export default function StaticAnalysisBridge({ event, onClose }) {
  const [store, setStore] = useState(null);
  const [cmdDigest, setCmdDigest] = useState({ status: "idle" });

  useEffect(() => {
    let cancel = false;
    (async () => {
      try {
        const s = await getDecodedArtifactStats();
        if (!cancel) setStore(s);
      } catch { /* store size is contextual only */ }
    })();
    return () => { cancel = true; };
  }, []);

  const cmd = event?.command_line || null;
  useEffect(() => {
    let cancel = false;
    if (!cmd) { setCmdDigest({ status: "none" }); return undefined; }
    if (!window.crypto?.subtle) {
      setCmdDigest({ status: "unavailable" });
      return undefined;
    }
    (async () => {
      const buf = new TextEncoder().encode(cmd);
      const d = await window.crypto.subtle.digest("SHA-256", buf);
      const hex = Array.from(new Uint8Array(d))
        .map((b) => b.toString(16).padStart(2, "0")).join("");
      if (!cancel) setCmdDigest({ status: "ok", hex });
    })();
    return () => { cancel = true; };
  }, [cmd]);

  if (!event) return null;
  const filename = event.file || event.process || event.title || null;

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 60,
                  background: "rgba(4,6,10,0.66)", display: "flex",
                  justifyContent: "flex-end" }}
         onClick={onClose}
         data-testid="edr-static-analysis-overlay">
      <aside onClick={(e) => e.stopPropagation()}
             style={{ width: 540, maxWidth: "94vw", height: "100%",
                      background: "#0B0F14", borderLeft: "1px solid #212B36",
                      overflow: "auto", padding: 14 }}
             data-testid="edr-static-analysis-drawer">
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                      marginBottom: 10 }}>
          <FlaskConical size={14} style={{ color: "var(--mint)" }} />
          <div className="section-title" style={{ flex: 1, margin: 0 }}>
            Static Analysis Bridge
          </div>
          <button className="btn" style={{ padding: "2px 6px" }} onClick={onClose}
                  data-testid="edr-static-analysis-close"><X size={11} /></button>
        </div>

        <div className="nx-ep" data-ep="capability_unavailable" data-known="true"
             style={{ marginBottom: 10, display: "block" }}
             data-testid="edr-static-analysis-banner">
          {BANNER}
        </div>

        <Row k="Subject" v={filename || <span className="nx-ep" data-ep="no_evidence"
                                              data-known="true">◇ NO FILENAME RECORDED</span>} />
        <Row k="Observation"
             v={event.event_iid || event.evidence_ref?.event_iid || "◇"} />
        <Row k="Contract"
             v="GET /api/v2/decoded-artifacts/{sha256} · read-only" />

        <div style={{ height: 10 }} />

        <HashLookup
          title="1 · File content digest"
          sha256={event.file_sha256}
          keyNote="artefacts.file[].sha256 — the only content-digest field in the observation contract"
          storeSize={store?.total_artifacts}
          testid="edr-static-lookup-file" />

        <HashLookup
          title="2 · Command-line digest"
          sha256={cmdDigest.status === "ok" ? cmdDigest.hex : null}
          keyNote={cmdDigest.status === "ok"
            ? "sha256 of the observed command line — the store's own key scheme"
            : cmdDigest.status === "unavailable"
              ? "⊘ SubtleCrypto unavailable — requires a secure context"
              : "◇ no command line was captured on this observation"}
          storeSize={store?.total_artifacts}
          testid="edr-static-lookup-cmdline" />

        <HashLookup
          title="3 · Observation record digest"
          sha256={event.input_digest}
          keyNote="event.raw.sha256 (== input_sha256) — digests the ingested observation record, NOT a file"
          storeSize={store?.total_artifacts}
          testid="edr-static-lookup-input" />

        <div style={{ padding: 10, background: "#11161D",
                      border: "1px solid #212B36", borderRadius: 4 }}>
          <div className="nx-ep" data-ep="capability_unavailable" data-known="true">
            ⊘ SENSOR OFFLINE — NO ACQUISITION DRIVER
          </div>
          <div style={{ marginTop: 6, fontSize: 10.5, color: "var(--text-dim)",
                        lineHeight: 1.7 }}>
            Submitting this subject for a fresh analysis would require the file
            bytes. Endpoint telemetry carries digests only and no file-fetch
            driver is registered on this device, so no submission is attempted
            and no result is synthesised.
          </div>
        </div>

        <div className="mono" style={{ marginTop: 14, fontSize: 9,
                                       color: "var(--faint)", lineHeight: 1.7 }}>
          Store: {store
            ? `${store.total_artifacts} artifacts · ${store.total_reuses} reuses · avg ${store.avg_trace_layers} decode layers`
            : "—"}
          <br />
          Dynamic detonation (hypervisor runtime, in-guest hooking, PCAP
          capture) is NOT IMPLEMENTED. No emulated behaviour is shown.
        </div>
      </aside>
    </div>
  );
}
