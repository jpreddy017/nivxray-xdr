/**
 * Navigation bridge · WorkspacePage → L4 Analyst Workspace (PR-4).
 *
 * ARB-scoped: navigation only. Creates an Investigation case from the
 * current decode/investigate result and routes to /investigate/{case_id}.
 * No layout changes to the source workspace.
 *
 * Idempotency: case_id is deterministic (see bundleAdapter.deriveCaseId).
 * A 409 on POST means the case already exists — we treat that as
 * "already investigated" and route straight to it.
 */
import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "@/lib/api";
import { buildInvestigationBundle } from "./bundleAdapter";

/** Toggle disabled by default until we have *any* usable decode signal. */
function hasUsableResult({ output, decodeResp, verdictCard, investigation }) {
  if (output && output.length > 0) return true;
  if (decodeResp && decodeResp.output) return true;
  if (verdictCard && Object.keys(verdictCard).length > 0) return true;
  if (investigation) {
    const inv = investigation;
    if (
      (inv.iocs && inv.iocs.length) ||
      (inv.capabilities && inv.capabilities.length) ||
      (inv.mitre && inv.mitre.length)
    ) {
      return true;
    }
  }
  return false;
}

export default function OpenInvestigationButton(props) {
  const { input, output, decodeResp, verdictCard, investigation } = props;
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const enabled = useMemo(
    () => hasUsableResult({ output, decodeResp, verdictCard, investigation }),
    [output, decodeResp, verdictCard, investigation],
  );

  const openInvestigation = async () => {
    if (!enabled || busy) return;
    setBusy(true);
    setErr("");
    try {
      const bundle = buildInvestigationBundle({
        input,
        decodeResp,
        verdictCard,
        investigation,
        output,
      });
      try {
        await api.post("/investigation", { bundle, mode: "investigation" });
      } catch (e) {
        // 409 = case already exists (same artifact hash) — that's fine,
        // we route to it. Any other failure surfaces.
        if (e?.response?.status !== 409) throw e;
      }
      navigate(`/investigate/${bundle.case_id}`);
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "bridge_failed");
      setBusy(false);
    }
  };

  return (
    <div
      data-testid="bridge-open-investigation"
      className="flex items-center gap-3 flex-wrap"
    >
      <button
        type="button"
        onClick={openInvestigation}
        disabled={!enabled || busy}
        data-testid="bridge-open-investigation-btn"
        className={`nvx-btn ${enabled ? "primary" : ""}`}
        title={
          enabled
            ? "Open this artefact in the SOC Investigation Workspace"
            : "Run Decode or Auto Investigate first"
        }
      >
        {busy ? "OPENING…" : "OPEN INVESTIGATION WORKSPACE →"}
      </button>
      {err ? (
        <span
          data-testid="bridge-open-investigation-error"
          className="mono"
          style={{ color: "var(--high, #e06c75)", fontSize: 11 }}
        >
          ✗ {err}
        </span>
      ) : null}
    </div>
  );
}
