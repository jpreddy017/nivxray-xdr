/**
 * Management → Downloads · the NivXForge Connector release catalog.
 *
 * A connector is a released PRODUCT ARTIFACT. It is built once, its
 * identity is disclosed, and the SAME bytes install on every device.
 * Choosing a Version and a Group produces DEPLOYMENT CONTEXT around that
 * released artifact — an install invocation and a bounded, tenant-bound
 * enrolment credential. Nothing is recompiled per endpoint, per group or
 * per tenant, and the response proves it by returning the unchanged
 * artifact identity.
 *
 * A release with no legitimate artifact reads ARTIFACT NOT PUBLISHED.
 * No download is ever fabricated.
 */
import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Download, KeyRound, PackageCheck, RefreshCw, ShieldCheck,
         Terminal } from "lucide-react";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { createDeployment, downloadReleaseArtifact, listConnectorReleases,
         listDeployments, listGroups } from "@/nivxforge/managementApi";
import { Ago, CopyBlock, Kpi, NA, OpsTable, Refusal, Skeleton, StateChip }
  from "@/nivxforge/components/OpsPrimitives";
import { apiErrorText } from "@/xdr/nx/apiError";
import "@/nivxforge/nvf-ops.css";

const kb = (n) => (n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);

const TONE = {
  PUBLISHED: "ok",
  ARTIFACT_NOT_PUBLISHED: "void",
  ARTIFACT_INCOMPLETE: "warn",
  ARTIFACT_REFUSED_EMBEDDED_CREDENTIAL: "bad",
  PREVIEW_NOT_FOR_PRODUCTION: "warn",
  NOT_RELEASED: "void",
  SUPPORTED: "ok",
  UNSIGNED: "warn",
};

function Release({ release, selected, onSelect }) {
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);
  const run = async (name) => {
    setBusy(name); setErr(null);
    try { await downloadReleaseArtifact(release.release_id, name); }
    catch (e) { setErr(apiErrorText(e, "download refused")); }
    finally { setBusy(null); }
  };
  return (
    <div className="pkg" data-available={String(!!release.download_available)}
         data-state={release.artifact_state}
         data-sel={selected ? "true" : "false"}
         data-testid={`edr-release-${release.release_id}`}>
      <div className="ph">
        <span className="n">{release.product}</span>
        <span className="arch">
          {release.architecture} · v{release.connector_version
            || "NOT RELEASED"}
        </span>
        <span style={{ marginLeft: "auto" }}>
          <StateChip token={release.artifact_state}
                     tone={TONE[release.artifact_state]}
                     title={release.artifact_state_reason}
                     testid={`edr-release-state-${release.release_id}`} />
        </span>
      </div>
      <div className="pb">
        <div className="kv">
          <span className="k">Channel</span>
          <span className="v"><StateChip token={release.channel}
                                         tone={TONE[release.channel]} /></span>
          <span className="k">Support status</span>
          <span className="v"><StateChip token={release.support_status}
                                         tone={TONE[release.support_status]} /></span>
          <span className="k">Released</span>
          <span className="v">{release.release_date
            || <NA label="NOT RELEASED" />}</span>
          <span className="k">End of support</span>
          <span className="v">{release.end_of_support
            || <NA label="NOT DECLARED" />}</span>
          <span className="k">Code signing</span>
          <span className="v"><StateChip token={release.signing_status}
                                         tone={TONE[release.signing_status]} /></span>
          <span className="k">Artifact identity</span>
          <span className="v mono" style={{ wordBreak: "break-all" }}>
            {release.artifact_identity
              ? release.artifact_identity.slice(0, 32) + "…"
              : <NA label="NO ARTIFACT" />}
          </span>
          <span className="k">Redistributable</span>
          <span className="v">
            {release.redistributable
              ? <StateChip token="ONE BUILD FOR EVERY DEVICE" tone="ok"
                           title="the artifact is never rebuilt per endpoint,
                                  group or tenant" />
              : <NA label="NOT PUBLISHED" />}
          </span>
          <span className="k">Supported OS</span>
          <span className="v">
            {release.supported_os?.length
              ? <span className="chipline">
                  {release.supported_os.map((w) => (
                    <span className="chip" key={w}>{w}</span>))}
                </span>
              : <NA label="NOT DECLARED" />}
          </span>
        </div>

        {release.release_notes?.length ? (
          <div style={{ marginTop: 8 }}>
            <div className="section-title" style={{ marginBottom: 4 }}>
              Release notes
            </div>
            {release.release_notes.map((n, i) => (
              <div className="basis" key={i}>· {n}</div>))}
          </div>
        ) : null}

        {Object.keys(release.declared_capabilities || {}).length ? (
          <div style={{ marginTop: 8 }}>
            <div className="section-title" style={{ marginBottom: 4 }}>
              Declared capability of THIS release
            </div>
            <div className="chipline">
              {Object.entries(release.declared_capabilities).map(([k, v]) => (
                <span className={`chip ${v ? "mint" : ""}`} key={k}
                      title={v ? "declared supported"
                        : "NOT supported by this release — a policy asking "
                          + "for it is recorded as requested and reported as "
                          + "not enforced"}>
                  {v ? "" : "◇ "}{k.replace(/_/g, " ")}
                </span>))}
            </div>
          </div>
        ) : null}

        {release.artifact_files?.length ? (
          <div style={{ marginTop: 8 }}>
            <div className="section-title" style={{ marginBottom: 4 }}>
              Released artifact
            </div>
            {release.artifact_files.map((f) => (
              <div className="file-row" key={f.name}
                   data-testid={`edr-release-artifact-${release.release_id}-${f.name}`}>
                <span className="nm">{f.name}</span>
                <span className="sz">{kb(f.size_bytes)}</span>
                <span className="sha" title={`sha256 ${f.sha256}`}>
                  sha256 {f.sha256.slice(0, 16)}…
                </span>
              </div>))}
          </div>
        ) : (
          <div className="basis" style={{ marginTop: 8 }}
               data-testid={`edr-release-empty-${release.release_id}`}>
            {release.artifact_state_reason}
          </div>
        )}
        {err ? <Refusal title="Download refused" body={err}
                        testid={`edr-release-error-${release.release_id}`} />
          : null}
      </div>
      <div className="pf">
        {release.download_available
          ? (release.artifact_files || []).map((f) => (
              <button className="btn" key={f.name} disabled={busy === f.name}
                      onClick={() => run(f.name)}
                      data-testid={`edr-release-download-${release.release_id}-${f.name}`}>
                <Download size={11} />
                {busy === f.name ? "Downloading…" : f.name}
              </button>))
          : (
            <span className="basis"
                  data-testid={`edr-release-no-download-${release.release_id}`}>
              No download is offered: {release.artifact_state_reason}
            </span>
          )}
        {release.download_available ? (
          <button className="btn mint" onClick={() => onSelect(release)}
                  data-testid={`edr-release-deploy-${release.release_id}`}>
            <PackageCheck size={11} /> Deploy this version
          </button>
        ) : null}
      </div>
    </div>
  );
}

function DeploymentBuilder({ release, groups, onCreated, onCancel }) {
  const [groupId, setGroupId] = useState(groups[0]?.id || "");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [out, setOut] = useState(null);

  const group = groups.find((g) => g.id === groupId);

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const d = await createDeployment({
        release_id: release.release_id, group_id: groupId,
        label: label || null, ttl_seconds: 86400 });
      setOut(d); onCreated();
    } catch (e) { setErr(apiErrorText(e, "deployment refused")); }
    finally { setBusy(false); }
  };

  return (
    <div className="panel" style={{ padding: "11px 13px", marginBottom: 14 }}
         data-testid="edr-deployment-builder">
      <div className="ops-head" style={{ marginBottom: 6 }}>
        <div className="section-title">
          <Terminal size={10} style={{ verticalAlign: -1, marginRight: 5 }} />
          Deploy {release.product} v{release.connector_version}
        </div>
        <div className="spacer" />
        <button className="btn" onClick={onCancel}
                data-testid="edr-deployment-cancel">Close</button>
      </div>

      {!out ? (
        <>
          <div className="kv">
            <span className="k">Group</span>
            <span className="v">
              <select value={groupId} onChange={(e) => setGroupId(e.target.value)}
                      data-testid="edr-deployment-group">
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name} · {g.endpoint_count} computers
                  </option>))}
              </select>
            </span>
            <span className="k">Applicable policy</span>
            <span className="v" data-testid="edr-deployment-policy">
              {group?.policy_id
                ? <span className="mono">{group.policy_id}</span>
                : <NA label="POLICY UNASSIGNED" reason="this group carries no
                    policy; computers joining it will honestly report
                    POLICY UNASSIGNED" />}
            </span>
            <span className="k">Label</span>
            <span className="v">
              <input value={label} onChange={(e) => setLabel(e.target.value)}
                     placeholder="Wave 1 · finance laptops"
                     data-testid="edr-deployment-label" />
            </span>
          </div>
          <div className="basis" style={{ marginTop: 8 }}>
            The group travels with the enrolment credential, server-side. The
            released artifact is unchanged — its SHA-256 stays identical, so
            one download serves every computer in this wave.
          </div>
          {err ? <Refusal title="Deployment refused" body={err}
                          testid="edr-deployment-error" /> : null}
          <div className="ops-actions" style={{ marginTop: 10 }}>
            <button className="btn mint" disabled={busy || !groupId}
                    onClick={submit} data-testid="edr-deployment-create">
              <KeyRound size={11} />
              {busy ? "Creating…" : "Create deployment"}
            </button>
          </div>
        </>
      ) : (
        <div data-testid="edr-deployment-result">
          <div className="kv">
            <span className="k">Deployment</span>
            <span className="v mono">{out.deployment.deployment_id}</span>
            <span className="k">Group</span>
            <span className="v">{out.deployment.group_name}</span>
            <span className="k">Policy</span>
            <span className="v">
              {out.policy_preview.policy_name
                ? `${out.policy_preview.policy_name} · v${out.policy_preview.version}`
                : <NA label={out.policy_preview.state} />}
            </span>
            <span className="k">Artifact identity</span>
            <span className="v mono" style={{ wordBreak: "break-all" }}>
              {out.artifact.artifact_identity}
            </span>
            <span className="k">Connector rebuilt</span>
            <span className="v">
              <StateChip token="NO — SAME RELEASED BYTES" tone="ok"
                         testid="edr-deployment-no-rebuild" />
            </span>
            <span className="k">Credential expires</span>
            <span className="v">
              {out.deployment.enrollment_token_expires_at}
            </span>
          </div>
          <div style={{ marginTop: 10 }}>
            <CopyBlock label="Install invocation (contains the one-time credential)"
                       text={out.install_invocation}
                       testid="edr-deployment-invocation" />
          </div>
          <div className="basis" style={{ marginTop: 8 }}>
            {out.credential_contract}
          </div>
          <div style={{ marginTop: 10 }}>
            <div className="section-title" style={{ marginBottom: 6 }}>
              What happens next
            </div>
            <div className="steps">
              {(out.next_steps || []).map((s, i) => (
                <div className="step" key={i} data-state="idle">
                  <div className="n">STEP {i + 1}</div>
                  <div className="t">{s}</div>
                </div>))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function EdrDownloadsPage() {
  const nav = useNavigate();
  const [data, setData] = useState(null);
  const [groups, setGroups] = useState([]);
  const [deployments, setDeployments] = useState(null);
  const [selected, setSelected] = useState(null);
  const [err, setErr] = useState(null);

  const load = useCallback(() => {
    setErr(null);
    Promise.all([listConnectorReleases(), listGroups(), listDeployments()])
      .then(([r, g, d]) => {
        setData(r); setGroups(g.groups || []); setDeployments(d);
      })
      .catch((e) => setErr(apiErrorText(e, "release catalog unavailable")));
  }, []);

  useEffect(load, [load]);

  const releases = data?.releases || [];

  return (
    <NivXForgeConsole activeTab="downloads">
      <div className="ops-head">
        <div>
          <span className="eyebrow">Management</span>
          <h1 className="ttl">Connector Downloads</h1>
          <div className="sub">
            The NivXForge Connector is a <strong>released product
            artifact</strong>. It is built once per release and the same bytes
            install on every device. Selecting a Version and a Group generates
            deployment context around that artifact — it never recompiles the
            connector.
          </div>
        </div>
        <div className="spacer" />
        <div className="ops-actions">
          <button className="btn" onClick={load}
                  data-testid="edr-downloads-refresh">
            <RefreshCw size={11} /> Refresh
          </button>
          <button className="btn" data-testid="edr-downloads-to-computers"
                  onClick={() => nav("/edr/computers")}>
            <ShieldCheck size={11} /> Computers
          </button>
          <button className="btn" data-testid="edr-downloads-to-policies"
                  onClick={() => nav("/edr/policies")}>
            Policies
          </button>
          <button className="btn mint" data-testid="edr-downloads-add-device"
                  onClick={() => nav("/edr/computers/add")}>
            <KeyRound size={11} /> Add device
          </button>
        </div>
      </div>

      {err ? <Refusal title="Release catalog unavailable" body={err}
                      testid="edr-downloads-refusal" /> : null}
      {!data && !err ? <Skeleton rows={7} testid="edr-downloads-loading" />
        : null}

      {data ? (
        <>
          <div className="kpi-rail" data-testid="edr-downloads-kpis">
            <Kpi label="Published releases" value={data.published} tone="mint"
                 testid="edr-kpi-published" />
            <Kpi label="Releases in catalog" value={data.count}
                 testid="edr-kpi-releases" />
            <Kpi label="Groups" value={groups.length}
                 testid="edr-kpi-downloads-groups" />
            <Kpi label="Deployments created" value={deployments?.count ?? 0}
                 testid="edr-kpi-deployments" />
          </div>

          <div className="panel" style={{ padding: "11px 13px",
                                          marginBottom: 14 }}
               data-testid="edr-connector-workflow">
            <div className="section-title" style={{ marginBottom: 7 }}>
              <Terminal size={10} style={{ verticalAlign: -1, marginRight: 5 }} />
              Administrator workflow
            </div>
            <div className="steps">
              {(data.admin_workflow || []).map((s, i) => (
                <div className="step" key={i} data-state="idle">
                  <div className="n">STEP {i + 1}</div>
                  <div className="t">{s}</div>
                </div>))}
            </div>
            <div className="basis" style={{ marginTop: 8 }}
                 data-testid="edr-distribution-contract">
              {data.distribution_contract}
            </div>
          </div>

          {selected ? (
            <DeploymentBuilder release={selected} groups={groups}
                               onCreated={load}
                               onCancel={() => setSelected(null)} />
          ) : null}

          <div className="pkg-grid" data-testid="edr-release-grid">
            {releases.map((r) => (
              <Release release={r} key={r.release_id}
                       selected={selected?.release_id === r.release_id}
                       onSelect={setSelected} />))}
          </div>

          {deployments?.count ? (
            <div style={{ marginTop: 18 }}>
              <div className="section-title" style={{ marginBottom: 6 }}>
                Deployments
              </div>
              <OpsTable
                testid="edr-deployments-table"
                rows={deployments.deployments}
                rowKey={(r) => r.deployment_id}
                columns={[
                  { key: "created_at", label: "Created", width: 96,
                    render: (r) => <Ago iso={r.created_at} /> },
                  { key: "label", label: "Label",
                    render: (r) => r.label || <NA label="NONE" /> },
                  { key: "connector_version", label: "Connector", width: 96,
                    cls: "mono" },
                  { key: "group_name", label: "Group", width: 160 },
                  { key: "policy_name", label: "Policy", width: 180,
                    render: (r) => (r.policy_name
                      ? `${r.policy_name} · v${r.policy_version}`
                      : <NA label="POLICY UNASSIGNED" />) },
                  { key: "artifact_identity", label: "Artifact identity",
                    cls: "mono",
                    render: (r) => (
                      <span title={r.artifact_identity}>
                        {String(r.artifact_identity || "").slice(0, 24)}…
                      </span>) },
                  { key: "rebuilt_connector", label: "Rebuilt", width: 80,
                    render: () => <StateChip token="NO" tone="ok" /> },
                ]} />
              <div className="basis" style={{ marginTop: 8 }}>
                {deployments.note}
              </div>
            </div>
          ) : null}
        </>
      ) : null}
    </NivXForgeConsole>
  );
}
