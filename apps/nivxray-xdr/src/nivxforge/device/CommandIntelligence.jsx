/**
 * Command Intelligence — OBSERVED endpoint command execution.
 *
 * Source authority (verified before wiring): `/api/edr/endpoint-commands`
 * reads the immutable raw sensor evidence (`activity=PROCESS`), its
 * detection derivations and the content-addressed decoder store.
 *
 * `/edr/response/actions` is a DIFFERENT authority — commands the
 * platform SENT to a sensor — and is deliberately not read here, because
 * a dispatched response action is not evidence that the endpoint executed
 * a command.
 *
 * The chain rendered per row is exactly the evidence chain:
 *   parent → process → raw command → decoder → decoded command
 *   → canonical evidence → detection → ATT&CK
 * A link with no evidence is drawn dashed and labelled, never inferred.
 */
import React, { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Search } from "lucide-react";

import { getEndpointCommands } from "@/nivxforge/onboardingApi";
import { Ago, Kpi, NA, Refusal, Skeleton, StateChip }
  from "@/nivxforge/components/OpsPrimitives";
import { apiErrorText } from "@/xdr/nx/apiError";

const WINDOWS = [{ h: 24, l: "24h" }, { h: 168, l: "7d" }, { h: 720, l: "30d" }];

function Link({ k, v, present, testid }) {
  return (
    <div className="lnk" data-evidence={present ? "present" : "absent"}
         data-testid={testid}>
      <div className="k">{k}</div>
      <div className="v">{present ? v : <NA label="NOT OBSERVED" />}</div>
    </div>
  );
}

function CommandRow({ row }) {
  const [open, setOpen] = useState(false);
  const det = row.detection || {};
  const dec = row.decode || {};
  const techniques = (dec.mitre_hints || []).reduce((acc, h) => {
    if (h?.id && !acc.some((x) => x.id === h.id)) acc.push(h);
    return acc;
  }, []);

  return (
    <div className="ci-row" data-testid={`edr-cmd-${row.raw_id}`}
         data-detection={det.state} data-decode={dec.state}>
      <div className="ci-h" onClick={() => setOpen((o) => !o)}
           data-testid={`edr-cmd-toggle-${row.raw_id}`}>
        {open ? <ChevronDown size={12} color="var(--faint)" />
              : <ChevronRight size={12} color="var(--faint)" />}
        <StateChip token={det.state}
                   testid={`edr-cmd-detstate-${row.raw_id}`} />
        {dec.state === "DECODED"
          ? <StateChip token="DECODED" tone="info" /> : null}
        <span className="t" title={row.command_line}>{row.command_line}</span>
        {techniques.slice(0, 2).map((t) => (
          <span className="chip att" key={t.id}>{t.id}</span>))}
        <span className="ts"><Ago iso={row.observed_at} /></span>
      </div>

      {open ? (
        <div className="ci-body" data-testid={`edr-cmd-body-${row.raw_id}`}>
          <div className="chain" data-testid={`edr-cmd-chain-${row.raw_id}`}>
            <Link k="Parent process" present={!!row.parent?.image}
                  v={`${row.parent?.image || ""}${row.parent?.lookup_state
                    ? ` · ${row.parent.lookup_state}` : ""}`} />
            <Link k="Process" present={!!row.image}
                  v={`${row.image} · pid ${row.pid}`} />
            <Link k="Raw command" present={!!row.command_line}
                  v={`sha256 ${String(row.command_sha256).slice(0, 12)}…`} />
            <Link k="Decoder" present={dec.state === "DECODED"}
                  v={`${(dec.layers || []).length} layer(s)`} />
            <Link k="Decoded command" present={!!dec.decoded_command}
                  v={dec.decoded_command} />
            <Link k="Canonical evidence"
                  present={!!(row.canonical_event_ids || []).length}
                  v={(row.canonical_event_ids || []).join(", ")} />
            <Link k="Detection" present={det.state === "DETECTION_MATCHED"}
                  v={(det.rule_ids || []).join(", ") || det.verdict} />
            <Link k="ATT&CK" present={techniques.length > 0}
                  v={techniques.map((t) => t.id).join(", ")} />
          </div>

          <div className="ci-grid">
            <div>
              <div className="section-title" style={{ marginBottom: 6 }}>
                Process
              </div>
              <div className="kv">
                <span className="k">Image</span>
                <span className="v">{row.image_path || row.image || <NA />}</span>
                <span className="k">PID / PPID</span>
                <span className="v">{row.pid} / {row.ppid ?? <NA />}</span>
                <span className="k">User</span>
                <span className="v">{row.user || <NA label="NOT OBSERVED" />}</span>
                <span className="k">Image SHA-256</span>
                <span className="v">{row.sha256 || <NA label="NOT OBSERVED" />}</span>
                <span className="k">Started</span>
                <span className="v">{row.start_time || <NA label="NOT OBSERVED" />}</span>
                <span className="k">Observed</span>
                <span className="v">{row.observed_at}</span>
                <span className="k">Collection</span>
                <span className="v">{row.collection_method || <NA />}</span>
                <span className="k">Evidence trust</span>
                <span className="v"><StateChip token={row.trust_state} tone="ok" /></span>
              </div>
              {row.not_observed?.length ? (
                <div className="basis" style={{ marginTop: 8 }}>
                  The sensor explicitly did not observe:{" "}
                  {row.not_observed.join(", ")}.
                </div>
              ) : null}
            </div>

            <div>
              <div className="section-title" style={{ marginBottom: 6 }}>
                Decoder provenance
              </div>
              {dec.state === "DECODED" ? (
                <>
                  <div className="cmd" style={{ paddingRight: 10 }}
                       data-testid={`edr-cmd-decoded-${row.raw_id}`}>
                    {dec.decoded_command}
                  </div>
                  <div style={{ marginTop: 8 }}>
                    {(dec.layers || []).map((l, i) => (
                      <div className="file-row" key={i}>
                        <span className="nm">L{l.layer} · {l.decoder}</span>
                        <span className="sz">
                          {l.confidence != null
                            ? `conf ${l.confidence}` : "conf —"}
                        </span>
                        <span className="sha" title={l.why}>{l.why}</span>
                      </div>
                    ))}
                  </div>
                  {dec.lolbas?.length ? (
                    <div className="chipline" style={{ marginTop: 8 }}>
                      {dec.lolbas.map((h, i) => (
                        <span className="chip" key={i}>
                          LOLBAS {h.binary} · {h.technique_id}
                        </span>))}
                    </div>
                  ) : null}
                </>
              ) : (
                <div className="basis" data-testid={`edr-cmd-nodecode-${row.raw_id}`}>
                  <StateChip token="DECODE_NOT_RECORDED" />
                  <div style={{ marginTop: 7 }}>{dec.basis}</div>
                </div>
              )}
            </div>

            <div>
              <div className="section-title" style={{ marginBottom: 6 }}>
                Detection
              </div>
              <div className="kv">
                <span className="k">State</span>
                <span className="v"><StateChip token={det.state} /></span>
                <span className="k">Rules</span>
                <span className="v">
                  {det.rule_ids?.length ? det.rule_ids.join(", ")
                    : <NA label="NONE CITED" />}
                </span>
                <span className="k">Verdict</span>
                <span className="v">{det.verdict || <NA label="NOT RECORDED" />}</span>
                <span className="k">Engine</span>
                <span className="v">{det.engine || <NA label="NOT RECORDED" />}</span>
              </div>
              <div className="basis" style={{ marginTop: 8 }}>{det.basis}</div>
            </div>

            <div>
              <div className="section-title" style={{ marginBottom: 6 }}>
                Observed children in this window
              </div>
              {row.children_observed?.length ? (
                row.children_observed.map((c, i) => (
                  <div className="file-row" key={i}>
                    <span className="nm">{c.image} · {c.pid}</span>
                    <span className="sha" title={c.command_line}>
                      {c.command_line}
                    </span>
                  </div>))
              ) : (
                <div className="basis">
                  No child process was observed in this window. This is an
                  absence of a citation inside the window, not proof that the
                  process spawned nothing.
                </div>
              )}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default function CommandIntelligence({ endpointId }) {
  const [hours, setHours] = useState(24);
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [q, setQ] = useState("");
  const [only, setOnly] = useState("all");

  useEffect(() => {
    let live = true;
    setData(null); setErr(null);
    getEndpointCommands(endpointId, hours, 200)
      .then((d) => { if (live) setData(d); })
      .catch((e) => { if (live) setErr(apiErrorText(e, "commands unavailable")); });
    return () => { live = false; };
  }, [endpointId, hours]);

  const rows = useMemo(() => {
    const all = data?.commands || [];
    const needle = q.trim().toLowerCase();
    return all.filter((r) => {
      if (only === "detected" && r.detection?.state !== "DETECTION_MATCHED") return false;
      if (only === "decoded" && r.decode?.state !== "DECODED") return false;
      if (!needle) return true;
      return [r.command_line, r.image, r.user, r.decode?.decoded_command]
        .some((v) => String(v || "").toLowerCase().includes(needle));
    });
  }, [data, q, only]);

  if (err) {
    return <Refusal title="Command evidence unavailable" body={err}
                    testid="edr-commands-refusal" />;
  }

  return (
    <div data-testid="edr-command-intelligence">
      {data ? (
        <div className="kpi-rail">
          <Kpi label="Observed executions" value={data.count}
               testid="edr-cmd-kpi-count" />
          <Kpi label="Distinct commands" value={data.distinct_commands}
               testid="edr-cmd-kpi-distinct" />
          <Kpi label="Detection matched" value={data.detected_count}
               tone={data.detected_count ? "red" : undefined}
               testid="edr-cmd-kpi-detected" />
          <Kpi label="Decoded" value={data.decoded_count} tone="mint"
               testid="edr-cmd-kpi-decoded" />
          <Kpi label="ATT&CK techniques"
               value={(data.attack_techniques || []).length}
               testid="edr-cmd-kpi-attack" />
          <Kpi label="Raw events scanned" value={data.raw_events_scanned}
               testid="edr-cmd-kpi-scanned" />
        </div>
      ) : null}

      <div className="ops-toolbar" style={{ borderRadius: "var(--radius)",
                                            marginBottom: 12 }}>
        <div className="ops-search">
          <Search size={11} color="var(--faint)" />
          <input value={q} onChange={(e) => setQ(e.target.value)}
                 placeholder="command · image · user · decoded text"
                 data-testid="edr-commands-search" />
        </div>
        <div className="seg" data-testid="edr-commands-filter">
          {[["all", "All"], ["detected", "Detected"], ["decoded", "Decoded"]]
            .map(([k, l]) => (
              <button key={k} data-on={String(only === k)}
                      data-testid={`edr-commands-only-${k}`}
                      onClick={() => setOnly(k)}>{l}</button>))}
        </div>
        <div className="seg" data-testid="edr-commands-window">
          {WINDOWS.map((w) => (
            <button key={w.h} data-on={String(hours === w.h)}
                    data-testid={`edr-commands-window-${w.h}`}
                    onClick={() => setHours(w.h)}>{w.l}</button>))}
        </div>
        <div className="ops-count">
          {rows.length} shown{data?.truncated ? " · window truncated" : ""}
        </div>
      </div>

      {data && (data.attack_techniques || []).length ? (
        <div className="panel" style={{ padding: "10px 13px", marginBottom: 12 }}
             data-testid="edr-commands-attack">
          <div className="section-title" style={{ marginBottom: 7 }}>
            ATT&amp;CK techniques cited by decoder evidence
          </div>
          <div className="chipline">
            {data.attack_techniques.map((t) => (
              <span className="chip att" key={t.id}
                    title={`${t.tactic || ""} · ${t.commands} command(s)`}>
                {t.id} · {t.technique} ({t.commands})
              </span>))}
          </div>
        </div>
      ) : null}

      {!data ? <Skeleton rows={8} testid="edr-commands-loading" /> : null}

      {data && data.state === "ENDPOINT_NOT_RESOLVED" ? (
        <div className="x-empty" data-testid="edr-commands-unresolved">
          {data.note}
        </div>
      ) : null}

      {data && data.state !== "ENDPOINT_NOT_RESOLVED" && rows.length === 0 ? (
        <div className="x-empty" data-testid="edr-commands-empty">
          No command execution evidence matches this filter inside the last{" "}
          {hours}h. {data.raw_events_scanned} raw event(s) were read. An empty
          window is an absence of observed execution, not a statement that
          nothing ran.
        </div>
      ) : null}

      {rows.map((r) => <CommandRow row={r} key={r.raw_id} />)}

      {data?.note ? (
        <div className="basis" style={{ marginTop: 10 }}
             data-testid="edr-commands-authority">
          {data.note} Source: <span className="mono">{data.source}</span>
        </div>
      ) : null}
    </div>
  );
}
