/**
 * Data Sources → Windows · the administrator's Windows telemetry console.
 *
 * Overview | Devices | Channels | Collectors | Coverage | Health | Configuration
 *
 * There is deliberately NO composite health verdict on this page. A tenant
 * can be receiving every channel and be able to detect almost none of it,
 * and one green light would hide exactly that. The server refuses to
 * publish such a verdict and this surface refuses to invent one.
 */
import React, { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import XdrShell from "@/xdr/XdrShell";
import { NxKpi, NxPageShell, NxSurface, NxTabs } from "@/xdr/nx";
import WindowsChannels from "./WindowsChannels";
import WindowsDevices from "./WindowsDevices";
import { Fact, Section, StateChip } from "./WindowsPrimitives";
import {
  getWindowsChannels, getWindowsCollectors, getWindowsConfiguration,
  getWindowsDevices, getWindowsOverview, measured,
} from "./windowsApi";
import "./windows.css";

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "devices", label: "Devices" },
  { key: "channels", label: "Channels" },
  { key: "collectors", label: "Collectors" },
  { key: "coverage", label: "Coverage" },
  { key: "health", label: "Health" },
  { key: "configuration", label: "Configuration" },
];

const StateCounts = ({ counts, testid }) => (
  <div className="wx-tags" data-testid={testid}>
    {Object.entries(counts || {})
      .filter(([, n]) => n > 0)
      .map(([state, n]) => (
        <span key={state}><StateChip value={state} /> <strong>{n}</strong></span>
      ))}
  </div>
);

export default function WindowsPage() {
  const { tab } = useParams();
  const navigate = useNavigate();
  const active = TABS.some((t) => t.key === tab) ? tab : "overview";

  const [s, setS] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const reload = useCallback(() => {
    setLoading(true);
    Promise.all([
      getWindowsOverview().catch((e) => ({ _error: e.message })),
      getWindowsChannels().catch((e) => ({ _error: e.message })),
      getWindowsDevices().catch((e) => ({ _error: e.message })),
      getWindowsCollectors().catch((e) => ({ _error: e.message })),
      getWindowsConfiguration().catch((e) => ({ _error: e.message })),
    ]).then(([overview, channels, devices, collectors, config]) => {
      setS({ overview, channels, devices, collectors, config });
      setError(overview?._error || channels?._error || null);
    }).finally(() => setLoading(false));
  }, []);
  useEffect(reload, [reload]);

  const ov = s.overview || {};
  const channels = s.channels?.channels || [];
  const devices = s.devices?.devices || [];
  const collectors = s.collectors?.collectors || [];

  const toEvents = (query) =>
    navigate(`/xdr/events?${new URLSearchParams(query).toString()}`);

  return (
    <XdrShell>
      <NxPageShell
        eyebrow="Data Sources"
        title="Windows"
        description="Per-channel acquisition, understanding and detection truth — five independent dimensions, no composite health verdict"
        testid="wx-page">
        <NxTabs tabs={TABS} active={active}
                onChange={(k) => navigate(`/xdr/data-sources/windows/${k}`)}
                testid="wx-tabs" />

        {error && <p className="wx-attn" data-testid="wx-error">{error}</p>}

        {active === "overview" && (
          <div className="wx-wrap" data-testid="wx-overview">
            <NxSurface>
              <div className="wx-facts">
                <NxKpi label="Channels declared" value={measured(ov.channels_declared)} />
                <NxKpi label="Devices" value={measured(ov.devices)} />
                <NxKpi label="Collectors" value={measured(ov.collectors)} />
                <NxKpi label="Detections fired" value={measured(ov.detections_fired)} />
              </div>
            </NxSurface>
            <Section title="Collection"><StateCounts counts={ov.collection} testid="wx-ov-collection" /></Section>
            <Section title="Parsing"><StateCounts counts={ov.parsing} testid="wx-ov-parsing" /></Section>
            <Section title="Normalization"><StateCounts counts={ov.normalization} testid="wx-ov-normalization" /></Section>
            <Section title="Detection capability"
                     note="Capability is computed from deployed detection content and the evidence each channel provides. It does not depend on anything having fired.">
              <StateCounts counts={ov.detection_capability} testid="wx-ov-capability" />
            </Section>
            <Section title="Composite health" note={ov.composite_health_reason}>
              <StateChip value={ov.composite_health} />
            </Section>
            <Section title="Real Windows endpoint proof"
                     note={ov.real_endpoint_proof?.reason}
                     testid="wx-ov-proof">
              <StateChip value={ov.real_endpoint_proof?.state} />
            </Section>
            {ov.attention?.length > 0 && (
              <Section title="Attention" testid="wx-ov-attention">
                <table className="wx-kv">
                  <tbody>
                    {ov.attention.map((a) => (
                      <tr key={a.channel}>
                        <td>{a.channel}</td>
                        <td className="wx-attn">{a.items.join(" · ")}</td>
                      </tr>))}
                  </tbody>
                </table>
              </Section>
            )}
          </div>
        )}

        {active === "devices" && (
          <WindowsDevices devices={devices} loading={loading} error={s.devices?._error}
                          onRefresh={reload}
                          onPivotEvents={(host) => toEvents({ host })} />
        )}

        {active === "channels" && (
          <WindowsChannels channels={channels} loading={loading}
                           error={s.channels?._error} onRefresh={reload}
                           onPivotEvents={(channel) => toEvents({ channel })} />
        )}

        {active === "collectors" && (
          <div className="wx-wrap" data-testid="wx-collectors">
            <Section title="Collectors" note={s.collectors?.authorization_note}>
              <table className="wx-kv">
                <tbody>
                  {collectors.map((c) => (
                    <tr key={c.collector_id || c.name}>
                      <td>{c.name || c.collector_id}</td>
                      <td>
                        <StateChip value={c.state || "NOT AVAILABLE"} />{" "}
                        {c.is_windows_collector
                          ? <span className="wx-tag">{c.windows_authorized_sources.join(", ")}</span>
                          : <span className="wx-dim">no Windows source authorized</span>}
                      </td>
                    </tr>))}
                  {collectors.length === 0 && (
                    <tr><td colSpan={2} className="wx-dim">
                      no collector is enrolled in this tenant</td></tr>)}
                </tbody>
              </table>
            </Section>
          </div>
        )}

        {active === "coverage" && (
          <div className="wx-wrap" data-testid="wx-coverage">
            <Section title="Acquired → Understood → Detectable"
                     note="A compact presentation of the authoritative states. Each stage carries the facts it stands on; it can never manufacture a successful stage.">
              <table className="wx-kv">
                <tbody>
                  {channels.map((c) => (
                    <tr key={c.channel}>
                      <td>{c.label}</td>
                      <td>
                        {(c.summary_stages || []).map((st) => (
                          <span key={st.stage} title={st.detail}>
                            <StateChip value={st.reached ? st.state : `${st.stage}: ${st.state}`} />{" "}
                          </span>))}
                      </td>
                    </tr>))}
                </tbody>
              </table>
            </Section>
          </div>
        )}

        {active === "health" && (
          <div className="wx-wrap" data-testid="wx-health">
            <Section title="Collection health"
                     note="Arrival, gaps and measured processing outcomes. A stopped stream is a gap in this platform's visibility — never proof the endpoint is quiet.">
              <table className="wx-kv">
                <tbody>
                  {channels.map((c) => (
                    <tr key={c.channel}>
                      <td>{c.label}</td>
                      <td>
                        <StateChip value={c.collection.state} />{" "}
                        <span className="wx-dim">{c.collection.reason}</span>
                      </td>
                    </tr>))}
                </tbody>
              </table>
            </Section>
          </div>
        )}

        {active === "configuration" && (
          <div className="wx-wrap" data-testid="wx-configuration">
            <Section title="Channel contract"
                     note={`Freshness window ${measured(s.config?.freshness_minutes)} minutes · analysis window ${measured(s.config?.window_hours)} hours`}>
              <table className="wx-kv">
                <tbody>
                  {(s.config?.channels || []).map((c) => (
                    <tr key={c.channel}>
                      <td>{c.channel}</td>
                      <td>
                        declared source <span className="wx-tag">{c.declared_source}</span>{" "}
                        DSM <span className="wx-tag">{c.dsm_id || "none"}</span>{" "}
                        <StateChip value={c.parsing} /> <StateChip value={c.normalization} />
                      </td>
                    </tr>))}
                </tbody>
              </table>
            </Section>
            <Section title="Declared unsupported">
              {(s.config?.unsupported || []).map((u) => (
                <Fact key={u.channel} label={u.channel} value={u.reason} />))}
            </Section>
          </div>
        )}
      </NxPageShell>
    </XdrShell>
  );
}
