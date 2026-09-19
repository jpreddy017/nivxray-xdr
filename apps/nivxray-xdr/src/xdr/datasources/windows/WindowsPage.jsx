/**
 * Data Sources → Windows · the administrator's Windows telemetry console.
 *
 * Overview | Devices | Channels | Collectors | Coverage | Health | Configuration
 *
 * Composed entirely from `@/xdr/nx`. The page-local `wx-*` design system
 * is gone: one design language, one table, one flyout, one status grammar.
 *
 * There is deliberately NO composite health verdict on this page. A tenant
 * can be receiving every channel and be able to detect almost none of it,
 * and one green light would hide exactly that. The server refuses to
 * publish such a verdict and this surface refuses to invent one.
 */
import React, { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { PlugZap, Radar } from "lucide-react";
import XdrShell from "@/xdr/XdrShell";
import { NxButton, NxPageShell, NxSection, NxTabs,
         NxVendorIcon } from "@/xdr/nx";
import WindowsChannels from "./WindowsChannels";
import WindowsCollectors from "./WindowsCollectors";
import WindowsConfiguration from "./WindowsConfiguration";
import WindowsCoverage from "./WindowsCoverage";
import WindowsDevices from "./WindowsDevices";
import WindowsOverview from "./WindowsOverview";
import WindowsHealth from "./WindowsHealth";
import { SelectCustomerNotice } from "./WindowsPrimitives";
import {
  getWindowsChannels, getWindowsCollectors, getWindowsConfiguration,
  getWindowsDevices, getWindowsOverview, isTenantRequired,
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

export default function WindowsPage() {
  const { tab } = useParams();
  const navigate = useNavigate();
  const active = TABS.some((t) => t.key === tab) ? tab : "overview";

  const [s, setS] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [focusChannel, setFocusChannel] = useState(null);
  const [focusDevice, setFocusDevice] = useState(null);

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

  const channels = s.channels?.channels || [];
  const devices = s.devices?.devices || [];
  const collectors = s.collectors?.collectors || [];

  const go = (key) => navigate(`/xdr/data-sources/windows/${key}`);
  const toEvents = (query) =>
    navigate(`/xdr/events?${new URLSearchParams(query).toString()}`);

  const openChannel = (channel) => { setFocusChannel(channel); go("channels"); };
  const openDevice = (origin) => { setFocusDevice(origin); go("devices"); };

  return (
    <XdrShell>
      <NxPageShell
        eyebrow="Data Sources"
        title="Windows"
        description="Windows Event Log acquisition, understanding and detection
                     truth — five independent dimensions, no composite health
                     verdict"
        meta={<NxVendorIcon id="microsoft/windows" name="Microsoft Windows"
                            withLabel size={18} />}
        action={
          <>
            <NxButton variant="primary" testid="wx-add-device"
                      onClick={() => navigate("/xdr/admin/collectors")}>
              <PlugZap size={13} /> Add Windows device
            </NxButton>
            <NxButton testid="wx-verify-ingestion"
                      onClick={() => toEvents({ source: "windows-eventlog" })}>
              <Radar size={13} /> Verify ingestion
            </NxButton>
            <NxButton testid="wx-manage-profiles"
                      onClick={() => go("configuration")}>
              Manage profiles
            </NxButton>
          </>
        }
        testid="wx-page">
        <NxTabs tabs={TABS} active={active} onChange={go} testid="wx-tabs" />

        {error && (isTenantRequired(error)
          ? <SelectCustomerNotice />
          : <NxSection variant="card" title="This view could not load"
                       testid="wx-error">
              <p className="nx-sec-note">{error}</p>
            </NxSection>)}

        {active === "overview" && (
          <WindowsOverview overview={s.overview} channels={channels}
                           devices={devices} loading={loading}
                           onOpenChannel={openChannel}
                           onOpenDevice={openDevice} />
        )}

        {active === "devices" && (
          <WindowsDevices devices={devices} loading={loading}
                          error={s.devices?._error} onRefresh={reload}
                          initialOrigin={focusDevice}
                          onPivotEvents={(host) => toEvents({ host })} />
        )}

        {active === "channels" && (
          <WindowsChannels channels={channels} loading={loading}
                           error={s.channels?._error} onRefresh={reload}
                           initialChannel={focusChannel}
                           onPivotEvents={(channel) => toEvents({ channel })} />
        )}

        {active === "collectors" && (
          <WindowsCollectors collectors={collectors}
                             note={s.collectors?.authorization_note}
                             loading={loading} error={s.collectors?._error}
                             onRefresh={reload} />
        )}

        {active === "coverage" && <WindowsCoverage />}

        {active === "health" && (
          <WindowsHealth channels={channels} loading={loading}
                         error={s.channels?._error} onRefresh={reload}
                         onPivotEvents={(channel) => toEvents({ channel })} />
        )}

        {active === "configuration" && (
          <WindowsConfiguration config={s.config} devices={devices}
                                channels={channels} loading={loading}
                                error={s.config?._error} onRefresh={reload} />
        )}
      </NxPageShell>
    </XdrShell>
  );
}
