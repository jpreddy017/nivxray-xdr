import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { getComputers } from "@/nivxforge/onboardingApi";
import FileEvidence from "@/nivxforge/files/FileEvidence";
import { activeTenant, TENANT_BOUND_EVENT } from "@/lib/tenant";

function FilesBody() {
  const [params, setParams] = useSearchParams();
  const endpoint = params.get("device") || "";
  const [computers, setComputers] = useState([]), [error, setError] = useState("");
  const [tenant, setTenant] = useState(activeTenant);
  useEffect(() => {
    const changed = () => { setComputers([]); setTenant(activeTenant()); };
    window.addEventListener(TENANT_BOUND_EVENT, changed);
    return () => window.removeEventListener(TENANT_BOUND_EVENT, changed);
  }, []);
  useEffect(() => {
    let live = true;
    setError("");
    getComputers().then((d) => { if (live) setComputers(d.computers || []); })
      .catch(() => { if (live) setError("Computer list unavailable. Open Files from Computers instead."); });
    return () => { live = false; };
  }, [tenant]);
  return <>
    <h1 className="page-h1">Files</h1>
    <label>Computer <select value={endpoint} onChange={(e) => {
      const next = new URLSearchParams(params);
      if (e.target.value) next.set("device", e.target.value); else next.delete("device");
      setParams(next);
    }}><option value="">Select a computer</option>
      {endpoint && !computers.some((c) => c.endpoint_id === endpoint) ? <option value={endpoint}>{endpoint}</option> : null}
      {computers.map((c) => <option key={c.endpoint_id} value={c.endpoint_id}>{c.hostname || c.endpoint_id}</option>)}
    </select></label>
    {error ? <p role="alert">{error}</p> : null}
    {endpoint ? <FileEvidence key={`${tenant}:${endpoint}`} endpointId={endpoint} /> : <p>Select a computer to investigate its recorded file observations.</p>}
  </>;
}

export default function EdrFilesPage() {
  return <NivXForgeConsole activeTab="files"><FilesBody /></NivXForgeConsole>;
}

