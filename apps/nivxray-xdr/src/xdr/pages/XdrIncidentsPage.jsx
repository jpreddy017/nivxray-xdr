/**
 * XdrIncidentsPage · `/xdr/incidents`
 *
 * Full queue view.  Honours `?mine=1` (My Queue) and `?q=` (search
 * prefill) so the sidebar deep-links keep working.
 */
import React, { useEffect, useState, useMemo, useCallback } from "react";
import { useSearchParams } from "react-router-dom";

import { useAuth } from "@/lib/auth";
import { listIncidents } from "@/lib/incidentsApi";
import XdrShell      from "@/xdr/XdrShell";
import IncidentQueue from "@/xdr/components/IncidentQueue";

export default function XdrIncidentsPage() {
  const { user } = useAuth();
  const [params] = useSearchParams();
  const mine = params.get("mine") === "1";
  const initialQ = params.get("q") || "";

  const [rows, setRows]     = useState([]);
  const [loading, setL]     = useState(true);
  const [error, setError]   = useState(null);
  const [q, setQ]           = useState(initialQ);
  const [stateFilter, setS] = useState("all");

  const load = useCallback(async () => {
    setL(true); setError(null);
    try {
      const res = await listIncidents({ limit: 500 });
      setRows(res.incidents || []);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load incidents.");
    } finally { setL(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const visible = useMemo(() => {
    if (!mine) return rows;
    return rows.filter((r) => r.assignee && r.assignee === user?.email);
  }, [rows, mine, user?.email]);

  return (
    <XdrShell activeTop="dashboards">
      <h1 className="page-h1">{mine ? "My Queue" : "Incidents"}</h1>
      <div className="page-sub">
        {mine
          ? "Incidents currently assigned to you."
          : "Every open incident across all tenants scoped to your account."}
      </div>

      {loading && <div className="x-empty">LOADING…</div>}
      {!loading && error && (
        <div className="x-empty" style={{ color: "#ff9494" }}>{String(error)}</div>
      )}
      {!loading && !error && (
        <IncidentQueue
          rows={visible}
          q={q} onQChange={setQ}
          stateFilter={stateFilter} onStateChange={setS}
          title={mine ? "My Assigned Incidents" : "All Incidents"}
        />
      )}
    </XdrShell>
  );
}
