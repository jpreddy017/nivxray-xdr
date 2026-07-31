/**
 * Storybook stories for LabV2 · full Investigation Workspace.
 * Uses the projector to build a demo-case view; no fixtures needed.
 */
import React from "react";
import LabV2 from "./LabV2";
import { projectCIO } from "./labv2.projector";

const { view } = projectCIO(null); // demo case

export default {
  title: "Lab 2.0/Workspace/LabV2",
  component: LabV2,
  parameters: { layout: "fullscreen" },
};

export const Default = () => <LabV2 view={view} sourceIsDemo />;
export const Analyzing = () => <LabV2 view={view} sourceIsDemo isAnalyzing />;
export const WithError = () => (
  <LabV2
    view={view}
    sourceIsDemo
    analyzeError="Backend unreachable · retry when host resolves."
  />
);
