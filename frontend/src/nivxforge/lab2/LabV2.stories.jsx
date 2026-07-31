/**
 * Storybook stories for LabV2 · the full Investigation Workspace.
 * Each story runs the same LabV2 rendered by the app — no fixtures
 * needed because the workspace ships with the coherent PowerShell
 * case internally (prompt §4 mandate).
 */
import React from "react";
import LabV2 from "./LabV2";

export default {
  title: "Lab 2.0/Workspace/LabV2",
  component: LabV2,
  parameters: { layout: "fullscreen" },
};

export const Default = () => <LabV2 />;
export const Analyzing = () => <LabV2 isAnalyzing />;
export const WithError = () => (
  <LabV2 analyzeError="Backend unreachable · retry when host resolves." />
);
