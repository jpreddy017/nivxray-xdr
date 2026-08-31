/**
 * PlatformOverviewBody · Phase A.2 · Visual Maturity benchmark.
 *
 * The Administration/Overview page rebuilt as a mature enterprise
 * control-plane cockpit.  Composes the Nx primitives (HeroHeader,
 * Donut, AreaSpark, HBar) over authoritative NivXRay endpoints:
 *
 *   GET /api/admin/stats                    · six KPIs + LOLBAS
 *   GET /api/admin/ioc/composition          · IOC breakdown
 *   GET /api/admin/data-sources/summary     · data-source health
 *   GET /api/admin/detection/summary        · detection coverage
 *   GET /api/platform/metrics               · pipeline health
 *   GET /api/platform/timeseries?limit=30   · operations trend
 *
 * Anti-fabrication contract: trend deltas are computed ONLY from
 * real snapshots; when history is unavailable, an honest empty
 * state renders instead of an invented percentage.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Users, Share2, Globe, Zap, Boxes, ShieldCheck,
  Activity, CheckCircle2, AlertTriangle, Info, ArrowRight,
} from "lucide-react";

import { NxHeroHeader, NxDonut, NxAreaSpark, NxHBar } from "@/xdr/nx";
import api from "@/lib/api";
import PipelineStrip from "@/xdr/admin/PipelineStrip";
import "./platformOverview.css";


/* ── Fetch helpers ────────────────────────────────────────────── */

async function safe(promise, fallback = null) {
  try {
    const { data } = await promise;
    return data;
  } catch (_) {
    return fallback;
  }
}

/* ── Time formatting ──────────────────────────────────────────── */

function fmtTimestamp(iso) {
  if (!iso) return null;
  const s = String(iso);
  return s.length >= 16 ? s.slice(0, 16).replace("T", " ") + " UTC" : s;
}
function relativeShort(iso) {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return null;
  const sec = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (sec < 60)    return `${sec}s ago`;
  if (sec < 3600)  return `${Math.floor(sec/60)} min ago`;
  if (sec < 86400) return `${Math.floor(sec/3600)} h ago`;
  return `${Math.floor(sec/86400)} d ago`;
}


/* ── Trend delta computation ──────────────────────────────────── */

/**
 * Returns a delta ({ pct, direction }) or `null` when we honestly
 * cannot compute one (fewer than 2 snapshots ≥ 7 days apart).
 */
function trendDelta(items, key) {
  if (!Array.isArray(items) || items.length < 2) return null;
  const latest = items[items.length - 1];
  const cutoff = Date.now() - 7 * 86400_000;
  // find the oldest sample within the window; fall back to first.
  const older = items.find(s =>
      s.computed_at && Date.parse(s.computed_at) >= cutoff)
      || items[0];
  const lv = Number(latest?.[key] ?? NaN);
  const ov = Number(older?.[key] ?? NaN);
  if (!Number.isFinite(lv) || !Number.isFinite(ov) || ov === 0) return null;
  const pct = ((lv - ov) / ov) * 100;
  return { pct: Math.round(pct * 10) / 10, direction: pct >= 0 ? "up" : "down" };
}


/* ── Component ─────────────────────────────────────────────────── */

export default function PlatformOverviewBody() {
  const [loading, setLoading] = useState(true);
  const [stats,   setStats]   = useState(null);
  const [ioc,     setIoc]     = useState(null);
  const [sources, setSources] = useState(null);
  const [det,     setDet]     = useState(null);
  const [health,  setHealth]  = useState(null);
  const [series,  setSeries]  = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const [s, i, ds, dt, ph, ts] = await Promise.all([
        safe(api.get("/admin/stats")),
        safe(api.get("/admin/ioc/composition")),
        safe(api.get("/admin/data-sources/summary")),
        safe(api.get("/admin/detection/summary")),
        safe(api.get("/platform/metrics")),
        safe(api.get("/platform/timeseries?limit=30")),
      ]);
      if (cancelled) return;
      setStats(s); setIoc(i); setSources(ds); setDet(dt);
      setHealth(ph); setSeries(ts);
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, []);

  const operationsPoints = useMemo(() => {
    const items = series?.items || [];
    return items
      .filter(x => Number.isFinite(Number(x?.pipeline_health?.total_cases)))
      .map(x => ({
        y:     Number(x.pipeline_health.total_cases) || 0,
        label: (x.date_bucket || x.computed_at || "").slice(5, 10),
      }));
  }, [series]);

  const iocDelta = useMemo(
    () => trendDelta(series?.items || [], "nvkc.total_samples"),
    [series]);
  const opsDelta = useMemo(
    () => trendDelta((series?.items || []).map(s => ({
      ...s, ops_total: s.pipeline_health?.total_cases,
    })), "ops_total"),
    [series]);

  const healthStatus = useMemo(() => derivePlatformHealth(health), [health]);
  const insights     = useMemo(
    () => deriveInsights(stats, sources, det, iocDelta),
    [stats, sources, det, iocDelta]);

  return (
    <div className="platform-overview" data-testid="xdr-platform-overview">
      {/* Hero */}
      <NxHeroHeader
        eyebrow="Administration"
        title="Platform Overview"
        description="Monitor platform health, data coverage, detection capability and configuration in one place."
        action={<HealthChip status={healthStatus} health={health} />}
        provenance={null}
      />

      {/* KPI strip */}
      <KpiStrip
        stats={stats}
        loading={loading}
        iocDelta={iocDelta}
        opsDelta={opsDelta}
        detTotal={det?.total}
      />

      {/* Ingestion pipeline · authoritative counts per stage */}
      <PipelineStrip testid="overview-pipeline" />

      {/* Main analytical row */}
      <div className="po-row po-row-main">
        <SectionCard
          title="IOC Composition"
          subtitle="Breakdown by indicator type"
          footer={<LinkOut to="/xdr/intelligence/ioc" label="View IOC Intelligence" />}
        >
          <IocCompositionBlock loading={loading} data={ioc} />
        </SectionCard>

        <SectionCard
          title="Operations Over Time"
          subtitle="Investigation operations over the last 30 days"
          footer={<LinkOut to="/xdr/incidents" label="View Operations" />}
        >
          <OperationsBlock
            loading={loading}
            points={operationsPoints}
            delta={opsDelta}
          />
        </SectionCard>

        <SectionCard
          title="LOLBAS Intelligence"
          subtitle="Living Off The Land Binaries and Scripts"
          footer={<LinkOut to="/xdr/admin/content-pack-lolbas"
                             label="View LOLBAS" />}
        >
          <LolbasBlock loading={loading} lolbas={stats?.lolbas} />
        </SectionCard>
      </div>

      {/* Operational detail row */}
      <div className="po-row po-row-bottom">
        <SectionCard
          title="Data Sources Health"
          subtitle="Status of configured data inputs"
          footer={<LinkOut to="/xdr/admin/data-sources-native"
                             label="Manage Data Sources" />}
          span={2}
        >
          <DataSourcesBlock loading={loading} data={sources} />
        </SectionCard>

        <SectionCard
          title="Detection Content Summary"
          subtitle="Overview of detection content by category"
          footer={<LinkOut to="/xdr/admin/detection-content"
                             label="Manage Detection Registry" />}
          span={2}
        >
          <DetectionBlock loading={loading} data={det} />
        </SectionCard>

        <SectionCard
          title="Administrator Insights"
          subtitle="Attention items derived from real state"
          footer={<LinkOut to="/xdr/admin/audit-log" label="View Audit Log" />}
        >
          <InsightsBlock loading={loading} insights={insights} />
        </SectionCard>
      </div>

      <footer className="po-honest">
        NivXRay is evidence-first and deterministic. Counts are sourced
        from authoritative registries and refreshed on schedule.
      </footer>
    </div>
  );
}


/* ═══════════════ Sub-components ══════════════════════════════════ */

function SectionCard({ title, subtitle, footer, children, span }) {
  return (
    <section className={`po-card ${span ? `po-span-${span}` : ""}`}
                 data-testid={`po-card-${slug(title)}`}>
      <header className="po-card-head">
        <h3 className="po-card-title">{title}</h3>
        {subtitle && <p className="po-card-sub">{subtitle}</p>}
      </header>
      <div className="po-card-body">{children}</div>
      {footer && <footer className="po-card-foot">{footer}</footer>}
    </section>
  );
}

function LinkOut({ to, label }) {
  return (
    <Link to={to} className="po-linkout"
             data-testid={`po-linkout-${slug(label)}`}>
      {label} <ArrowRight size={12} />
    </Link>
  );
}

function HealthChip({ status, health }) {
  const cls = status.level;
  const label = status.label;
  const checked = relativeShort(health?.computed_at) || null;
  return (
    <div className={`po-health po-health-${cls}`}
            data-testid="po-health-chip">
      <span className="po-health-dot" />
      <div className="po-health-txt">
        <div className="po-health-label">{label}</div>
        {checked && (
          <div className="po-health-when">Last checked {checked}</div>
        )}
      </div>
      <Activity size={16} className="po-health-icon" aria-hidden="true" />
    </div>
  );
}

/* ── KPI strip ─────────────────────────────────────────────────── */

function KpiStrip({ stats, loading, iocDelta, opsDelta, detTotal }) {
  const items = [
    { key: "users", icon: Users, label: "Total Users",
      value: stats?.total_users, sub: "Active platform users" },
    { key: "shares", icon: Share2, label: "Total Shares",
      value: stats?.total_shares, sub: "Shared workspaces" },
    { key: "iocs", icon: Globe, label: "Total IOCs",
      value: stats?.total_iocs, sub: "Indicators of Compromise",
      delta: iocDelta },
    { key: "ops", icon: Zap, label: "Total Operations",
      value: stats?.total_operations, sub: "Investigation operations",
      delta: opsDelta },
    { key: "osint", icon: Boxes, label: "Configured OSINT",
      value: stats?.configured_osint_services, sub: "OSINT sources connected" },
    { key: "rules", icon: ShieldCheck, label: "Detection Rules",
      value: detTotal,
      sub: "Registered detection content" },
  ];
  return (
    <div className="po-kpi-strip" data-testid="po-kpi-strip">
      {items.map(it => (
        <KpiTile key={it.key} {...it} loading={loading} />
      ))}
    </div>
  );
}

function KpiTile({ icon: Icon, label, value, sub, delta, loading }) {
  const shown = value == null
    ? "—"
    : typeof value === "number"
      ? value.toLocaleString()
      : value;
  return (
    <div className="po-kpi" data-testid={`po-kpi-${slug(label)}`}>
      <div className="po-kpi-icon" aria-hidden="true">
        <Icon size={16} />
      </div>
      <div className="po-kpi-body">
        <div className="po-kpi-value">
          {loading ? <span className="po-skel po-skel-num" /> : shown}
        </div>
        <div className="po-kpi-label">{label}</div>
        <div className="po-kpi-sub">{sub}</div>
        {delta && (
          <div className={`po-kpi-delta po-kpi-delta-${delta.direction}`}>
            {delta.direction === "up" ? "↑" : "↓"} {Math.abs(delta.pct)}% vs last 7 days
          </div>
        )}
      </div>
    </div>
  );
}

/* ── IOC Composition ───────────────────────────────────────────── */

function IocCompositionBlock({ loading, data }) {
  if (loading) return <SkelBlock height={180} />;
  if (!data || !data.total) return <HonestEmpty text="No IOC data available." />;

  const items = (data.items || []).map((it, i) => ({
    ...it,
    tone: ["purple", "blue", "teal", "amber", "faint"][i % 5],
  }));

  return (
    <div className="po-ioc" data-testid="po-ioc-composition">
      <div className="po-ioc-chart">
        <NxDonut
          items={items}
          total={data.total}
          size={180}
          thickness={26}
          centerLabel={
            <>
              <div className="po-ioc-center-value">{fmtNum(data.total)}</div>
              <div className="po-ioc-center-label">Total IOCs</div>
            </>
          }
        />
      </div>
      <ul className="po-ioc-legend">
        {items.map(it => (
          <li key={it.key} data-testid={`po-ioc-legend-${it.key}`}>
            <span className={`po-ioc-dot po-ioc-dot-${it.tone}`} />
            <span className="po-ioc-legend-label">{it.label}</span>
            <span className="po-ioc-legend-value">{fmtNum(it.count)}</span>
            <span className="po-ioc-legend-pct">({it.pct}%)</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ── Operations trend ──────────────────────────────────────────── */

function OperationsBlock({ loading, points, delta }) {
  if (loading) return <SkelBlock height={180} />;
  if (!points || points.length < 2) {
    return <HonestEmpty
        title="Historical trend not yet available"
        text="Operations trend will appear here once daily platform snapshots accumulate. This is the honest state, not an error." />;
  }
  return (
    <div className="po-ops" data-testid="po-ops-trend">
      <NxAreaSpark points={points} height={200} />
      {delta && (
        <div className={`po-ops-delta po-ops-delta-${delta.direction}`}>
          {delta.direction === "up" ? "↑" : "↓"} {Math.abs(delta.pct)}%
          <span className="po-ops-delta-sub">vs last 7 days</span>
        </div>
      )}
    </div>
  );
}

/* ── LOLBAS ────────────────────────────────────────────────────── */

function LolbasBlock({ loading, lolbas }) {
  if (loading) return <SkelBlock height={180} />;
  if (!lolbas) return <HonestEmpty text="LOLBAS content pack not available." />;
  const items = [
    { key: "active",   label: "Active",   value: lolbas.active_count   ?? 0, tone: "purple" },
    { key: "sources",  label: "Sources",  value: lolbas.source_count   ?? 0, tone: "blue" },
    { key: "defaults", label: "Defaults", value: lolbas.defaults_count ?? 0, tone: "teal" },
  ];
  const lastUpdated = fmtTimestamp(lolbas.last_update);
  return (
    <div className="po-lolbas" data-testid="po-lolbas">
      <NxHBar items={items} />
      {lastUpdated && (
        <div className="po-lolbas-meta">
          <span className="po-lolbas-meta-label">Last updated</span>
          <span className="po-lolbas-meta-value">{lastUpdated}</span>
        </div>
      )}
    </div>
  );
}

/* ── Data sources ──────────────────────────────────────────────── */

function DataSourcesBlock({ loading, data }) {
  if (loading) return <SkelBlock height={140} />;
  if (!data || !data.total) return <HonestEmpty text="No data sources configured." />;
  return (
    <table className="po-table" data-testid="po-data-sources-table">
      <thead>
        <tr>
          <th>Source Type</th>
          <th className="num">Configured</th>
          <th className="num">Connected</th>
          <th>Health</th>
          <th>Last Received</th>
        </tr>
      </thead>
      <tbody>
        {(data.groups || []).map(g => {
          const health = healthOf(g);
          return (
            <tr key={g.key} data-testid={`po-ds-row-${g.key}`}>
              <td>{g.label}</td>
              <td className="num">{g.configured}</td>
              <td className="num">{g.connected}</td>
              <td>
                <span className={`po-pill po-pill-${health.tone}`}>
                  {health.label}
                </span>
              </td>
              <td className="mono">
                {g.last_telemetry_at
                  ? (relativeShort(g.last_telemetry_at) || "—")
                  : "—"}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function healthOf(g) {
  if (g.configured === 0)                 return { tone: "faint",   label: "None" };
  if (g.connected  === g.configured)      return { tone: "benign",  label: "Healthy" };
  if (g.connected  > 0)                   return { tone: "amber",   label: "Partial" };
  return                                        { tone: "amber",   label: "No telemetry" };
}

/* ── Detection summary ─────────────────────────────────────────── */

function DetectionBlock({ loading, data }) {
  if (loading) return <SkelBlock height={140} />;
  if (!data || !data.total) return <HonestEmpty text="No detection content registered." />;
  const max = Math.max(1, ...data.categories.map(c => c.total));
  return (
    <table className="po-table" data-testid="po-detection-table">
      <thead>
        <tr>
          <th>Category</th>
          <th className="bar-col">Distribution</th>
          <th className="num">Total</th>
          <th className="num">Active</th>
          <th className="num">Disabled</th>
        </tr>
      </thead>
      <tbody>
        {data.categories.map((c, i) => (
          <tr key={c.key} data-testid={`po-det-row-${c.key}`}>
            <td>{c.label}</td>
            <td className="bar-col">
              <span className="po-inline-bar">
                <span
                  className="po-inline-bar-fill"
                  style={{
                    width: `${(c.total / max) * 100}%`,
                    background: BAR_COLOURS[i % BAR_COLOURS.length],
                  }}
                />
              </span>
            </td>
            <td className="num">{c.total}</td>
            <td className="num">{c.active}</td>
            <td className="num">{c.disabled}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const BAR_COLOURS = ["#6D4EE0", "#2563EB", "#0D9488", "#F59E0B", "#9CA3AF", "#DC2626"];

/* ── Insights ──────────────────────────────────────────────────── */

function deriveInsights(stats, sources, det, iocDelta) {
  const out = [];

  if (stats && sources && det) {
    const healthyDs = (sources.groups || [])
      .every(g => g.connected === g.configured);
    if (healthyDs && det.active > 0) {
      out.push({ tone: "benign", icon: CheckCircle2,
        title: "Platform is healthy",
        body:  "All critical services operational." });
    }
  }

  if (sources) {
    const bad = (sources.groups || [])
      .filter(g => g.configured > 0 && g.connected === 0);
    if (bad.length > 0) {
      out.push({ tone: "amber", icon: AlertTriangle,
        title: `${bad.length} data source group${bad.length > 1 ? "s" : ""} need review`,
        body:  `${bad.map(g => g.label).join(", ")} — no telemetry received yet.` });
    }
  }

  if (det && det.disabled > 0) {
    out.push({ tone: "amber", icon: AlertTriangle,
      title: `${det.disabled} rule${det.disabled > 1 ? "s" : ""} disabled`,
      body:  "Review and enable if needed." });
  }

  if (iocDelta && iocDelta.direction === "up" && iocDelta.pct >= 5) {
    out.push({ tone: "info", icon: Info,
      title: "IOC coverage growing",
      body:  `↑ ${iocDelta.pct}% over the last 7 days.` });
  }

  if (out.length === 0) {
    out.push({ tone: "info", icon: Info,
      title: "No attention items",
      body:  "Every operational check is currently within tolerance." });
  }

  return out;
}

function InsightsBlock({ loading, insights }) {
  if (loading) return <SkelBlock height={140} />;
  return (
    <ul className="po-insights" data-testid="po-insights">
      {insights.map((it, i) => (
        <li key={i} className={`po-insight po-insight-${it.tone}`}
                data-testid={`po-insight-${i}`}>
          <span className="po-insight-icon" aria-hidden="true">
            <it.icon size={14} />
          </span>
          <div>
            <div className="po-insight-title">{it.title}</div>
            <div className="po-insight-body">{it.body}</div>
          </div>
        </li>
      ))}
    </ul>
  );
}


/* ── Small utilities ───────────────────────────────────────────── */

function derivePlatformHealth(health) {
  if (!health) return { level: "unknown", label: "Unknown" };
  const ok = health?.pipeline_health?.decode_success_rate;
  if (typeof ok === "number") {
    if (ok >= 0.95) return { level: "operational", label: "Operational" };
    if (ok >= 0.75) return { level: "degraded",    label: "Degraded" };
    return                { level: "critical",    label: "Critical" };
  }
  return { level: "operational", label: "Operational" };
}

function HonestEmpty({ title, text }) {
  return (
    <div className="po-empty" data-testid="po-empty">
      {title && <div className="po-empty-title">{title}</div>}
      <div className="po-empty-body">{text}</div>
    </div>
  );
}

function SkelBlock({ height }) {
  return <div className="po-skel po-skel-block" style={{ height }} />;
}

function fmtNum(n) {
  const v = Number(n) || 0;
  return v.toLocaleString();
}

function slug(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}
