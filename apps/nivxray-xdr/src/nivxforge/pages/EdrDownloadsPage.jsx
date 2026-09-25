/**
 * Management → Downloads.
 *
 * Every artifact shown here EXISTS on disk: version, byte size and
 * SHA-256 are read from the file the backend would actually serve, and a
 * build that is missing, incomplete or carries an embedded credential
 * shape is refused instead of offered. There is no Download control
 * for a package the server has not declared available.
 */
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Download, KeyRound, ShieldCheck, Terminal } from "lucide-react";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { downloadArtifact, getSensorPackages } from "@/nivxforge/onboardingApi";
import { CopyBlock, Kpi, NA, Refusal, Skeleton, StateChip }
  from "@/nivxforge/components/OpsPrimitives";
import { apiErrorText } from "@/xdr/nx/apiError";
import "@/nivxforge/nvf-ops.css";

const kb = (n) => (n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);

function Package({ pkg }) {
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);
  const run = async (name) => {
    setBusy(name); setErr(null);
    try { await downloadArtifact(pkg.id, name); }
    catch (e) { setErr(apiErrorText(e, "download refused")); }
    finally { setBusy(null); }
  };
  return (
    <div className="pkg" data-available={String(!!pkg.available)}
         data-testid={`edr-package-${pkg.id}`} data-state={pkg.state}>
      <div className="ph">
        <span className="n">{pkg.display_name}</span>
        <span className="arch">{pkg.architecture}</span>
        <span style={{ marginLeft: "auto" }}>
          <StateChip token={pkg.state}
                     testid={`edr-package-state-${pkg.id}`} />
        </span>
      </div>
      <div className="pb">
        <div className="kv">
          <span className="k">Sensor version</span>
          <span className="v">{pkg.sensor_version || <NA label="NOT BUILT" />}</span>
          <span className="k">Release</span>
          <span className="v"><StateChip token={pkg.release_status} /></span>
          <span className="k">Code signing</span>
          <span className="v">
            <StateChip token={pkg.signing_status}
                       title="Signing state as recorded for this build" />
          </span>
          <span className="k">Credential-free</span>
          <span className="v">
            {pkg.credential_free
              ? <StateChip token="VERIFIED" tone="ok"
                           title="the artifact was scanned for embedded credential shapes" />
              : <StateChip token="REFUSED" tone="bad" />}
          </span>
          <span className="k">Supported OS</span>
          <span className="v">
            {pkg.supported_windows?.length
              ? <span className="chipline">
                  {pkg.supported_windows.map((w) => (
                    <span className="chip" key={w}>{w}</span>))}
                </span>
              : <NA label="NOT DECLARED" />}
          </span>
          {pkg.requires?.length ? (
            <>
              <span className="k">Requires</span>
              <span className="v">
                <span className="chipline">
                  {pkg.requires.map((r) => (
                    <span className="chip" key={r}>{r}</span>))}
                </span>
              </span>
            </>
          ) : null}
        </div>

        {pkg.files?.length ? (
          <div>
            <div className="section-title" style={{ marginBottom: 4 }}>
              Artifacts on disk
            </div>
            {pkg.files.map((f) => (
              <div className="file-row" key={f.name}
                   data-testid={`edr-artifact-${pkg.id}-${f.name}`}>
                <span className="nm">{f.name}</span>
                <span className="sz">{kb(f.size_bytes)}</span>
                <span className="sha" title={`sha256 ${f.sha256}`}>
                  sha256 {f.sha256.slice(0, 16)}…
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="basis" data-testid={`edr-package-empty-${pkg.id}`}>
            {pkg.state_reason}
          </div>
        )}

        {pkg.silent_install ? (
          <CopyBlock label="Silent install" text={pkg.silent_install}
                     testid={`edr-silent-install-${pkg.id}`} />
        ) : null}
        {err ? <Refusal title="Download refused" body={err}
                        testid={`edr-download-error-${pkg.id}`} /> : null}
      </div>
      <div className="pf">
        {pkg.available
          ? (pkg.files || []).map((f) => (
              <button className="btn mint" key={f.name} disabled={busy === f.name}
                      onClick={() => run(f.name)}
                      data-testid={`edr-download-${pkg.id}-${f.name}`}>
                <Download size={11} />
                {busy === f.name ? "Downloading…" : f.name}
              </button>))
          : (
            <span className="basis" data-testid={`edr-no-download-${pkg.id}`}>
              No download is offered: {pkg.state_reason}
            </span>
          )}
      </div>
    </div>
  );
}

export default function EdrDownloadsPage() {
  const nav = useNavigate();
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    let live = true;
    getSensorPackages()
      .then((d) => { if (live) setData(d); })
      .catch((e) => { if (live) setErr(apiErrorText(e, "packages unavailable")); });
    return () => { live = false; };
  }, []);

  const pkgs = data?.packages || [];
  return (
    <NivXForgeConsole activeTab="downloads">
      <div className="ops-head">
        <div>
          <span className="eyebrow">Management</span>
          <h1 className="ttl">Sensor Downloads</h1>
          <div className="sub">
            One reusable build per architecture. The installer carries
            <strong> no tenant credential</strong> — each installation receives
            its own device identity and credential at enrolment, so the same
            file can be handed to every computer.
          </div>
        </div>
        <div className="spacer" />
        <div className="ops-actions">
          <button className="btn" data-testid="edr-downloads-to-computers"
                  onClick={() => nav("/edr/computers")}>
            <ShieldCheck size={11} /> Computers
          </button>
          <button className="btn mint" data-testid="edr-downloads-add-device"
                  onClick={() => nav("/edr/computers/add")}>
            <KeyRound size={11} /> Add device
          </button>
        </div>
      </div>

      {err ? <Refusal title="Downloads unavailable" body={err}
                      testid="edr-downloads-refusal" /> : null}
      {!data && !err ? <Skeleton rows={7} testid="edr-downloads-loading" /> : null}

      {data ? (
        <>
          <div className="kpi-rail" data-testid="edr-downloads-kpis">
            <Kpi label="Available builds" value={data.available} tone="mint"
                 testid="edr-kpi-available" />
            <Kpi label="Architectures" value={pkgs.length}
                 testid="edr-kpi-architectures" />
            <Kpi label="Installer contract" value="CREDENTIAL-FREE" tone="mint"
                 title={data.installer_contract}
                 testid="edr-kpi-contract" />
          </div>

          <div className="panel" style={{ padding: "11px 13px", marginBottom: 14 }}
               data-testid="edr-onboarding-workflow">
            <div className="section-title" style={{ marginBottom: 7 }}>
              <Terminal size={10} style={{ verticalAlign: -1, marginRight: 5 }} />
              Onboarding sequence
            </div>
            <div className="steps">
              {(data.onboarding_workflow || []).map((s, i) => (
                <div className="step" key={i} data-state="idle">
                  <div className="n">STEP {i + 1}</div>
                  <div className="t">{s}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="pkg-grid" data-testid="edr-package-grid">
            {pkgs.map((p) => <Package pkg={p} key={p.id} />)}
          </div>
        </>
      ) : null}
    </NivXForgeConsole>
  );
}
