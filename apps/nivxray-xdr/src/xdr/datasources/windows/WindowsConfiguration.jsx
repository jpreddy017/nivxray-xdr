/**
 * Windows · Configuration.
 *
 * Configuration is presented as MANAGED OBJECTS, not a key/value dump.
 *
 * Two honesty rules the previous key/value table blurred:
 *   · a collection profile is only listed when a real delivery asserted it
 *     (observed profiles come from device telemetry, never invented), and
 *   · the declared channel contract is the platform's DECLARATION — it
 *     says what is supported, never what is happening.
 */
import React, { useState } from "react";
import { NxDataTable, NxFlyout, NxKeyFact, NxFacts, NxMetricStrip, NxRaw,
         NxSection, NxState, NxTabs, NxTechnical, NxTokenList,
         measured } from "@/xdr/nx";

const TABS = [
  { key: "profiles", label: "Collection profiles" },
  { key: "channels", label: "Channel contract" },
  { key: "unsupported", label: "Declared unsupported" },
];

/** Profiles are DERIVED from what devices actually asserted. */
function observedProfiles(devices = [], channels = []) {
  const out = new Map();
  for (const d of devices) {
    for (const p of d.profiles || []) {
      if (!out.has(p)) {
        out.set(p, { profile: p, devices: [], versions: new Set(),
                     channels: new Set(), last_telemetry: null });
      }
      const row = out.get(p);
      row.devices.push(d.evidence_origin);
      for (const v of d.profile_versions || []) row.versions.add(v);
      for (const c of d.channels_observed || []) row.channels.add(c);
      if (d.last_telemetry_at
          && (!row.last_telemetry || d.last_telemetry_at > row.last_telemetry)) {
        row.last_telemetry = d.last_telemetry_at;
      }
    }
  }
  for (const c of channels) {
    for (const p of c.profiles || []) {
      if (out.has(p)) out.get(p).channels.add(c.channel);
    }
  }
  return [...out.values()].map((r) => ({
    ...r,
    versions: [...r.versions],
    channels: [...r.channels],
  }));
}

function ProfilePane({ row, onClose }) {
  if (!row) return null;
  return (
    <NxFlyout open title={row.profile} eyebrow="Collection profile"
              onClose={onClose} width={620} testid="wx-profile-pane">
      <NxSection title="Assignment"
                 note="A profile is listed because a delivery asserted it.
                       Assignment is therefore OBSERVED, not declared by this
                       console.">
        <NxFacts>
          <NxKeyFact label="Assigned devices (observed)"
                     value={<NxTokenList values={row.devices} limit={12} />} />
          <NxKeyFact label="Profile version(s)"
                     value={<NxTokenList values={row.versions} limit={6} />}
                     reason={row.versions.length ? null
                       : "no delivery declared a profile version"} />
          <NxKeyFact label="Channels observed under this profile"
                     value={<NxTokenList values={row.channels} limit={12} />} />
          <NxKeyFact label="Last telemetry" value={row.last_telemetry} mono
                     reason={row.last_telemetry ? null
                       : "no delivery observed for any device on this profile"} />
        </NxFacts>
      </NxSection>
      <NxTechnical>
        <NxRaw>{JSON.stringify(row, null, 2)}</NxRaw>
      </NxTechnical>
    </NxFlyout>
  );
}

export default function WindowsConfiguration({ config, devices = [],
                                               channels = [], loading,
                                               error, onRefresh }) {
  const [tab, setTab] = useState("profiles");
  const [profile, setProfile] = useState(null);
  const c = config || {};
  const profiles = observedProfiles(devices, channels);

  return (
    <div className="wx-stack" data-testid="wx-configuration">
      <NxMetricStrip testid="wx-config-metrics" items={[
        { label: "Declared channels", value: (c.channels || []).length },
        { label: "Declared unsupported", value: (c.unsupported || []).length },
        { label: "Profiles observed", value: profiles.length },
        { label: "Freshness window", value: c.freshness_minutes,
          sub: "minutes" },
        { label: "Analysis window", value: c.window_hours, sub: "hours" },
      ]} />

      <NxTabs tabs={TABS} active={tab} onChange={setTab}
              testid="wx-config-tabs" />

      {tab === "profiles" && (
        <NxSection variant="card" title="Collection profiles"
                   note="Versioned acquisition profiles as observed in real
                         deliveries. Editing a profile is a collector-side
                         administrative act and is not offered here until the
                         management API is proven end to end."
                   testid="wx-config-profiles">
          <NxDataTable rows={profiles} loading={loading} error={error}
                       onRefresh={onRefresh} rowKey={(r) => r.profile}
                       onRowClick={setProfile} searchable={false}
                       emptyTitle="No collection profile has been observed"
                       emptyHint="A profile appears once a delivery declares
                                  it — the console does not list profiles it
                                  has never seen in evidence"
                       testid="wx-profiles-table"
                       columns={[
            { key: "profile", header: "Profile", width: "220px",
              render: (r) => <strong className="nx-mono">{r.profile}</strong> },
            { key: "devices", header: "Assigned devices", width: "140px",
              align: "right", value: (r) => r.devices.length,
              render: (r) => r.devices.length },
            { key: "channels", header: "Channels", width: "120px",
              align: "right", value: (r) => r.channels.length,
              render: (r) => r.channels.length },
            { key: "version", header: "Version", width: "160px",
              value: (r) => r.versions.join(","),
              render: (r) => (r.versions.length
                ? <NxTokenList values={r.versions} limit={2} />
                : <span className="nx-absent">—</span>) },
            { key: "last", header: "Last telemetry", width: "190px",
              value: (r) => r.last_telemetry || "",
              render: (r) => (r.last_telemetry
                ? <span className="nx-mono">{r.last_telemetry}</span>
                : <span className="nx-absent">—</span>) },
            { key: "status", header: "Status", width: "150px",
              value: (r) => (r.last_telemetry ? "RECEIVING" : "NOT_OBSERVED"),
              render: (r) => <NxState
                value={r.last_telemetry ? "RECEIVING" : "NOT_OBSERVED"} /> },
          ]} />
        </NxSection>
      )}

      {tab === "channels" && (
        <NxSection variant="card" title="Declared channel contract"
                   note={`The platform's declaration of what it can acquire and
                          understand. Freshness window
                          ${measured(c.freshness_minutes)} minutes · analysis
                          window ${measured(c.window_hours)} hours.`}
                   testid="wx-config-channels">
          <NxDataTable rows={c.channels || []} loading={loading}
                       rowKey={(r) => r.channel}
                       searchPlaceholder="Search channel, source, DSM"
                       emptyTitle="No channel is declared"
                       testid="wx-config-channels-table"
                       columns={[
            { key: "channel", header: "Channel", width: "260px",
              render: (r) => <span className="nx-mono">{r.channel}</span> },
            { key: "declared_source", header: "Declared source", width: "190px",
              render: (r) => (r.declared_source
                ? <NxTokenList values={[r.declared_source]} />
                : <span className="nx-absent">—</span>) },
            { key: "dsm_id", header: "DSM", width: "170px",
              render: (r) => (r.dsm_id
                ? <NxTokenList values={[r.dsm_id]} />
                : <span className="nx-absent">no DSM parses this channel yet</span>) },
            { key: "parsing", header: "Declared parsing", width: "160px",
              render: (r) => <NxState value={r.parsing} /> },
            { key: "normalization", header: "Declared normalization",
              width: "180px",
              render: (r) => <NxState value={r.normalization} /> },
            { key: "provides", header: "Evidence provided",
              value: (r) => (r.provides || []).join(","),
              render: (r) => <NxTokenList values={r.provides} limit={4} /> },
          ]} />
        </NxSection>
      )}

      {tab === "unsupported" && (
        <NxSection variant="card" title="Declared unsupported"
                   note="Stated openly: these channels are not acquired or not
                         understood, and the reason is given. An unsupported
                         channel is never shown as quiet."
                   testid="wx-config-unsupported">
          <NxDataTable rows={c.unsupported || []} loading={loading}
                       rowKey={(r) => r.channel} searchable={false}
                       emptyTitle="Every declared channel is supported"
                       testid="wx-config-unsupported-table"
                       columns={[
            { key: "channel", header: "Channel", width: "280px",
              render: (r) => <span className="nx-mono">{r.channel}</span> },
            { key: "state", header: "State", width: "150px",
              render: () => <NxState value="UNSUPPORTED" /> },
            { key: "reason", header: "Reason",
              render: (r) => r.reason },
          ]} />
        </NxSection>
      )}

      <ProfilePane row={profile} onClose={() => setProfile(null)} />
    </div>
  );
}
