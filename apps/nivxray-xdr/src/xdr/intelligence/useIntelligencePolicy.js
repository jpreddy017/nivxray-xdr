/**
 * Intelligence policy STATE AUTHORITY.
 *
 * Extracted from the former 543-line `IntelligenceControlPanel` so one UI
 * composition is no longer forced to serve three different jobs. The hook
 * owns loading, mutation, inheritance and history; the three presentation
 * components own only their layout.
 *
 * RBAC and scope are enforced SERVER-SIDE. This hook renders whatever the
 * server says and surfaces a denial verbatim — it never decides authority.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import api from "@/lib/api";
import { activeTenant } from "@/lib/tenant";
import { modeOf } from "./intelligenceModel";

function errText(e) {
  const d = e?.response?.data?.detail ?? e?.detail ?? e;
  if (d == null) return "Request failed.";
  if (typeof d === "string") return d;
  if (typeof d === "object") {
    return d.reason || d.message || d.detail || d.code
      || (e?.message ?? JSON.stringify(d));
  }
  return String(d);
}

export default function useIntelligencePolicy({
  scope = "global",
  incidentId = null,
} = {}) {
  const [policy, setPolicy] = useState(null);
  const [effective, setEffective] = useState(null);
  const [globalPolicy, setGlobalPolicy] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState(null);

  const scopeKind = scope === "incident" ? "incident" : "global";
  const scopeId = scope === "incident" ? incidentId : "global";

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    // A0.5 · the intelligence policy is tenant-scoped. With no customer
    // resolved the server correctly answers TENANT_REQUIRED, so we state
    // that instead of firing a request that can only be denied.
    if (!activeTenant()) {
      setHealth(null);
      setPolicy(null);
      setEffective(null);
      setError("No customer selected · there is no default tenant");
      setLoading(false);
      return;
    }
    try {
      const h = await api.get("/intelligence/health");
      setHealth(h.data);
      if (scope === "global") {
        const p = await api.get("/intelligence/policy/global");
        setPolicy(p.data);
        setGlobalPolicy(p.data);
        setEffective(null);
      } else {
        const [ov, ef] = await Promise.all([
          api.get(`/intelligence/policy/incident/${incidentId}`),
          api.get(`/intelligence/policy/incident/${incidentId}/effective`),
        ]);
        setPolicy(ov.data);
        setEffective(ef.data.effective);
        setGlobalPolicy(ef.data.global);
      }
    } catch (e) {
      setError(errText(e));
    } finally {
      setLoading(false);
    }
  }, [scope, incidentId]);

  useEffect(() => {
    if (scope === "incident" && !incidentId) return;
    load();
  }, [load, scope, incidentId]);

  const values = useMemo(() => {
    const src = scope === "global" ? policy : effective;
    if (!src) return null;
    return {
      online_ai: src.online_ai || "on",
      online_llm: src.online_llm || "on",
    };
  }, [policy, effective, scope]);

  const mode = useMemo(() => modeOf(values), [values]);

  const ceiling = useMemo(() => ({
    online_ai: (globalPolicy?.online_ai ?? "on") === "on",
    online_llm: (globalPolicy?.online_llm ?? "on") === "on",
  }), [globalPolicy]);

  const inherited = scope === "incident"
    && policy?.online_ai == null && policy?.online_llm == null;

  const save = useCallback(async (nextValues, reason) => {
    setSaving(true);
    setError(null);
    try {
      const url = scope === "global"
        ? "/intelligence/policy/global"
        : `/intelligence/policy/incident/${incidentId}`;
      const { data } = await api.put(url, {
        ...nextValues,
        reason: reason || undefined,
      });
      setPolicy(data);
      if (scope === "global") {
        setGlobalPolicy(data);
      } else {
        const ef = await api.get(
          `/intelligence/policy/incident/${incidentId}/effective`);
        setEffective(ef.data.effective);
        setGlobalPolicy(ef.data.global);
      }
      return { ok: true };
    } catch (e) {
      const denied = e?.response?.data?.detail?.code === "ACCESS_DENIED";
      const msg = denied
        ? "You do not have permission to change this policy."
        : errText(e);
      setError(msg);
      return { ok: false, error: msg };
    } finally {
      setSaving(false);
    }
  }, [scope, incidentId]);

  const clearOverride = useCallback(async (reason) => {
    if (scope !== "incident") return { ok: false };
    setSaving(true);
    setError(null);
    try {
      await api.delete(`/intelligence/policy/incident/${incidentId}`
        + `?reason=${encodeURIComponent(reason || "cleared")}`);
      await load();
      return { ok: true };
    } catch (e) {
      const msg = errText(e);
      setError(msg);
      return { ok: false, error: msg };
    } finally {
      setSaving(false);
    }
  }, [scope, incidentId, load]);

  const loadHistory = useCallback(async () => {
    try {
      const { data } = await api.get(
        `/intelligence/policy/${scopeKind}/${scopeId}/history`);
      setHistory(data.history || []);
    } catch (e) {
      setError(errText(e));
      setHistory([]);
    }
  }, [scopeKind, scopeId]);

  return {
    policy, effective, globalPolicy, health, values, mode, ceiling,
    inherited, loading, saving, error, history,
    reload: load, save, clearOverride, loadHistory,
  };
}
