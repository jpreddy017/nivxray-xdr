import React from "react";
import api from "@/lib/api";
import { activeTenant } from "@/lib/tenant";
import ForensicsAnalyzer from "./ForensicsAnalyzer";

const ANALYSIS_PATHS = new Set([
  "/api/edr/forensics/command-analysis",
  "/api/edr/forensics/ioc-reputation",
]);

async function request(path, { method, body, signal }) {
  if (!ANALYSIS_PATHS.has(path) || method !== "POST") {
    throw new Error("Unsupported Forensics request");
  }
  const { data } = await api.post(path.slice(4), body, { signal });
  return data;
}

export default function ForensicsAnalyzerSection() {
  const tenantId = activeTenant();
  if (!tenantId) return <p>Select a customer to analyze commands.</p>;
  return <ForensicsAnalyzer key={tenantId} request={request} tenantId={tenantId} />;
}
