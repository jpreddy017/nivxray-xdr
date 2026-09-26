/**
 * Add Device — the real onboarding workflow, one screen.
 *
 *   Choose Windows → Download sensor → Generate enrolment
 *   → Install command → Waiting for endpoint → Authenticated telemetry
 *   → CONNECTED
 *
 * The credential this screen mints is deliberately weak on purpose: it is
 * single-use, short-lived, tenant-bound and scoped to ENROLMENT ONLY. It
 * is not a collector/API key, it is never stored by the console, and it is
 * never embedded in the reusable installer. The endpoint receives its own
 * unique device credential from the platform at enrolment.
 *
 * CONNECTED is never claimed by this screen. It is read back from the
 * fleet, which requires authenticated telemetry inside the sensor's own
 * declared cadence.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { CheckCircle2, Download, KeyRound, Loader2, ShieldAlert } from "lucide-react";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { API_BASE } from "@/lib/api";
import { activeTenant } from "@/lib/tenant";
import { downloadArtifact, getComputers, getSensorPackages, mintEnrollmentToken }
  from "@/nivxforge/onboardingApi";
import { Ago, CopyBlock, NA, Refusal, Skeleton, StateChip }
  from "@/nivxforge/components/OpsPrimitives";
import { apiErrorText } from "@/xdr/nx/apiError";
import "@/nivxforge/nvf-ops.css";

const BACKEND_ORIGIN = String(API_BASE || "").replace(/\/api\/?$/, "");

const STEPS = [
  { key: "choose",    t: "Choose Windows" },
  { key: "download",  t: "Download sensor" },
  { key: "enrol",     t: "Generate enrolment" },
  { key: "install",   t: "Install command" },
  { key: "waiting",   t: "Waiting for endpoint" },
  { key: "telemetry", t: "Authenticated telemetry" },
  { key: "connected", t: "CONNECTED" },
];

function installCommand(pkg, tenant, token) {
  return "powershell -ExecutionPolicy Bypass -File "
    + `.\\${pkg?.entrypoint || "Install-NivXForgeSensor.ps1"}`
    + ` -BackendUrl ${BACKEND_ORIGIN || "<backend url>"}`
    + ` -TenantId ${tenant || "<tenant>"}`
    + ` -EnrollmentToken ${token || "<enrolment token>"}`;
}

export default function EdrAddDevicePage() {
  const nav = useNavigate();
  const tenant = activeTenant();
  const [packages, setPackages] = useState(null);
  const [pkgId, setPkgId] = useState(null);
  const [err, setErr] = useState(null);
  const [downloaded, setDownloaded] = useState([]);
  const [token, setToken] = useState(null);      // plaintext, memory only
  const [minting, setMinting] = useState(false);
  const [baseline, setBaseline] = useState(null);
  const [watching, setWatching] = useState(false);
  const [observed, setObserved] = useState(null);
  const [now, setNow] = useState(Date.now());
  const timer = useRef(null);

  useEffect(() => {
    let live = true;
    getSensorPackages()
      .then((d) => {
        if (!live) return;
        setPackages(d);
        const first = (d.packages || []).find((p) => p.available);
        if (first) setPkgId(first.id);
      })
      .catch((e) => live && setErr(apiErrorText(e, "packages unavailable")));
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => { live = false; window.clearInterval(t); };
  }, []);

  const pkg = useMemo(
    () => (packages?.packages || []).find((p) => p.id === pkgId) || null,
    [packages, pkgId]);

  const poll = useCallback(async () => {
    try {
      const d = await getComputers(24);
      const rows = d.computers || [];
      const fresh = baseline
        ? rows.filter((r) => !baseline.has(r.endpoint_id))
        : [];
      if (fresh.length) {
        fresh.sort((a, b) => String(b.last_seen || "")
          .localeCompare(String(a.last_seen || "")));
        setObserved(fresh[0]);
        if (fresh[0].status === "CONNECTED") setWatching(false);
      }
    } catch (e) {
      setErr(apiErrorText(e, "fleet read refused"));
    }
  }, [baseline]);

  useEffect(() => {
    if (!watching) {
      if (timer.current) { window.clearInterval(timer.current); timer.current = null; }
      return undefined;
    }
    poll();
    timer.current = window.setInterval(poll, 8000);
    return () => { if (timer.current) window.clearInterval(timer.current); };
  }, [watching, poll]);

  const mint = async () => {
    setMinting(true); setErr(null);
    try {
      const fleet = await getComputers(24);
      setBaseline(new Set((fleet.computers || []).map((r) => r.endpoint_id)));
      const t = await mintEnrollmentToken({
        label: `console add-device · ${pkg?.id || "windows"}`,
        ttlSeconds: 3600,
      });
      setToken(t);
      setWatching(true);
    } catch (e) {
      setErr(apiErrorText(e, "enrolment token refused"));
    } finally {
      setMinting(false);
    }
  };

  const expiresIn = token?.expires_at
    ? Math.max(0, Math.round((Date.parse(token.expires_at) - now) / 1000))
    : null;

  const stage = observed?.status === "CONNECTED" ? "connected"
    : observed?.telemetry?.last_telemetry_at ? "telemetry"
    : observed ? "waiting"
    : token ? "install"
    : downloaded.length ? "enrol"
    : pkg ? "download" : "choose";
  const stageIndex = STEPS.findIndex((s) => s.key === stage);

  return (
    <NivXForgeConsole activeTab="computers">
      <div className="ops-head">
        <div>
          <span className="eyebrow">Fleet operations</span>
          <h1 className="ttl">Add device</h1>
          <div className="sub">
            One reusable installer, one bounded enrolment credential per
            computer. The console never issues a permanent API credential,
            and it never reports a computer as CONNECTED — that state is read
            back from authenticated telemetry.
          </div>
        </div>
        <div className="spacer" />
        <div className="ops-actions">
          <button className="btn" data-testid="edr-add-back"
                  onClick={() => nav("/edr/computers")}>Back to Computers</button>
        </div>
      </div>

      <div className="steps" data-testid="edr-add-steps" data-stage={stage}>
        {STEPS.map((s, i) => (
          <div className="step" key={s.key}
               data-testid={`edr-add-step-${s.key}`}
               data-state={i === stageIndex ? "active"
                 : i < stageIndex ? "done" : "idle"}>
            <div className="n">STEP {i + 1}</div>
            <div className="t">{s.t}</div>
          </div>
        ))}
      </div>

      {err ? <Refusal title="Onboarding refused" body={err}
                      testid="edr-add-refusal" /> : null}
      {!tenant ? (
        <Refusal
          testid="edr-add-no-tenant"
          title="No customer selected"
          body={"Enrolment is tenant-bound, so the console will not mint a "
            + "credential without an explicitly selected customer. Choose a "
            + "customer in the header first — the platform has no default "
            + "tenant."} />
      ) : null}
      {!packages && !err ? <Skeleton rows={6} testid="edr-add-loading" /> : null}

      {packages ? (
        <div className="ci-grid" style={{ alignItems: "start" }}>
          {/* 1 · platform */}
          <div className="panel" style={{ padding: "12px 14px" }}
               data-testid="edr-add-choose">
            <div className="section-title" style={{ marginBottom: 8 }}>
              1 · Platform
            </div>
            {(packages.packages || []).map((p) => (
              <label key={p.id}
                     style={{ display: "flex", gap: 9, alignItems: "flex-start",
                              padding: "7px 0", cursor: p.available
                                ? "pointer" : "not-allowed",
                              opacity: p.available ? 1 : .6,
                              borderBottom: "1px solid var(--border-sf)" }}
                     data-testid={`edr-add-pkg-${p.id}`}>
                <input type="radio" name="pkg" disabled={!p.available}
                       checked={pkgId === p.id}
                       onChange={() => setPkgId(p.id)}
                       style={{ marginTop: 3, accentColor: "var(--mint)" }} />
                <span style={{ minWidth: 0 }}>
                  <span style={{ display: "block", fontSize: 11.8,
                                 fontWeight: 700, color: "var(--text)" }}>
                    {p.display_name}
                  </span>
                  <span style={{ display: "flex", gap: 6, marginTop: 4,
                                 flexWrap: "wrap" }}>
                    <StateChip token={p.state} />
                    {p.sensor_version
                      ? <span className="chip mint">v{p.sensor_version}</span>
                      : null}
                  </span>
                  {!p.available ? (
                    <span className="basis"
                          style={{ display: "block", marginTop: 6 }}>
                      {p.state_reason}
                    </span>
                  ) : null}
                </span>
              </label>
            ))}
          </div>

          {/* 2 · download */}
          <div className="panel" style={{ padding: "12px 14px" }}
               data-testid="edr-add-download">
            <div className="section-title" style={{ marginBottom: 8 }}>
              2 · Download the sensor
            </div>
            {pkg?.available ? (
              <>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {(pkg.files || []).map((f) => (
                    <button className="btn mint" key={f.name}
                            data-testid={`edr-add-download-${f.name}`}
                            onClick={async () => {
                              try {
                                await downloadArtifact(pkg.id, f.name);
                                setDownloaded((d) => (d.includes(f.name)
                                  ? d : [...d, f.name]));
                              } catch (e) {
                                setErr(apiErrorText(e, "download refused"));
                              }
                            }}>
                      <Download size={11} /> {f.name}
                    </button>
                  ))}
                </div>
                <div className="basis" style={{ marginTop: 10 }}>
                  Every artifact was scanned for embedded credential shapes
                  before it was offered. Copy both files to the Windows host —
                  the same build is valid for every computer.
                </div>
                {downloaded.length ? (
                  <div style={{ marginTop: 9 }} data-testid="edr-add-downloaded">
                    <StateChip token="DOWNLOADED" tone="ok" />{" "}
                    <span className="mono" style={{ fontSize: 10.4 }}>
                      {downloaded.join(" · ")}
                    </span>
                  </div>
                ) : null}
              </>
            ) : (
              <div className="basis" data-testid="edr-add-download-unavailable">
                {pkg ? pkg.state_reason
                  : "Select an available build to download the sensor."}
              </div>
            )}
          </div>

          {/* 3 · enrolment credential */}
          <div className="panel" style={{ padding: "12px 14px" }}
               data-testid="edr-add-enrol">
            <div className="section-title" style={{ marginBottom: 8 }}>
              3 · Generate the enrolment credential
            </div>
            {!token ? (
              <>
                <button className="btn mint" disabled={!pkg?.available || minting || !tenant}
                        onClick={mint} data-testid="edr-add-mint">
                  {minting ? <Loader2 size={11} className="spin" />
                    : <KeyRound size={11} />}
                  {minting ? "Minting…" : "Generate enrolment token"}
                </button>
                <div className="basis" style={{ marginTop: 10 }}>
                  Single use · expires in 1 hour · bound to customer{" "}
                  <strong>{tenant || "—"}</strong> · enrolment purpose only.
                  It authorises nothing else, and it is shown exactly once.
                </div>
              </>
            ) : (
              <>
                <CopyBlock testid="edr-add-token"
                           label="Enrolment token (shown once)"
                           text={token.token || token.enrollment_token || ""} />
                <div className="kv" style={{ marginTop: 10 }}>
                  <span className="k">Customer</span>
                  <span className="v">{tenant}</span>
                  <span className="k">Expires in</span>
                  <span className="v" data-testid="edr-add-token-ttl">
                    {expiresIn === null ? <NA label="NOT DECLARED" />
                      : expiresIn > 0 ? `${Math.floor(expiresIn / 60)}m `
                        + `${expiresIn % 60}s` : "EXPIRED"}
                  </span>
                  <span className="k">Uses</span>
                  <span className="v">single use</span>
                  <span className="k">Authority</span>
                  <span className="v">enrolment only</span>
                </div>
                <div className="basis" style={{ marginTop: 10,
                                                borderLeftColor: "var(--amber)" }}>
                  <ShieldAlert size={10} style={{ verticalAlign: -1,
                                                  marginRight: 5,
                                                  color: "var(--amber)" }} />
                  This value is held in this browser tab only. It is not
                  persisted by the console and cannot be retrieved again —
                  mint a new one if it is lost.
                </div>
              </>
            )}
          </div>

          {/* 4 · install command */}
          <div className="panel" style={{ padding: "12px 14px" }}
               data-testid="edr-add-install">
            <div className="section-title" style={{ marginBottom: 8 }}>
              4 · Run elevated on the endpoint
            </div>
            <CopyBlock testid="edr-add-install-command"
                       text={installCommand(pkg, tenant,
                         token?.token || token?.enrollment_token)} />
            <div className="basis" style={{ marginTop: 10 }}>
              Run in an <strong>elevated</strong> PowerShell session from the
              folder containing both downloaded files. The platform mints the
              endpoint identity and a per-device credential during this call —
              the installer itself carries neither.
            </div>
          </div>

          {/* 5 · observed result */}
          <div className="panel" style={{ padding: "12px 14px",
                                          gridColumn: "1 / -1" }}
               data-testid="edr-add-observe">
            <div className="section-title" style={{ marginBottom: 8 }}>
              5 · What the platform has actually observed
            </div>
            {!token ? (
              <div className="basis" data-testid="edr-add-observe-idle">
                Nothing is being watched yet. Generate an enrolment credential
                to start watching this customer's fleet for a new computer.
              </div>
            ) : !observed ? (
              <div style={{ display: "flex", alignItems: "center", gap: 9 }}
                   data-testid="edr-add-waiting">
                <Loader2 size={13} color="var(--cyan)" />
                <span style={{ fontSize: 11.6, color: "var(--text-dim)" }}>
                  Waiting for an endpoint to present this token. The fleet is
                  polled every 8 seconds; no state is assumed until the
                  platform records the enrolment.
                </span>
              </div>
            ) : (
              <div className="ci-grid">
                <div className="kv">
                  <span className="k">Computer</span>
                  <span className="v" data-testid="edr-add-observed-host">
                    {observed.hostname || observed.endpoint_id}
                  </span>
                  <span className="k">Endpoint</span>
                  <span className="v">{observed.endpoint_id}</span>
                  <span className="k">Enrolment</span>
                  <span className="v">
                    <StateChip token={observed.enrollment_state} tone="ok" />
                  </span>
                  <span className="k">Status</span>
                  <span className="v">
                    <StateChip token={observed.status}
                               testid="edr-add-observed-status" />
                  </span>
                  <span className="k">Last telemetry</span>
                  <span className="v">
                    <Ago iso={observed.telemetry?.last_telemetry_at} />
                  </span>
                </div>
                <div>
                  <div className="basis">{observed.status_basis}</div>
                  <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
                    <button className="btn mint"
                            data-testid="edr-add-open-device"
                            onClick={() => nav(
                              `/edr/computers/${encodeURIComponent(observed.endpoint_id)}`)}>
                      {observed.status === "CONNECTED"
                        ? <CheckCircle2 size={11} /> : null}
                      Open device
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      ) : null}
    </NivXForgeConsole>
  );
}
