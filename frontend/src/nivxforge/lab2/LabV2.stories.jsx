import React from "react";
import LabV2 from "./LabV2";
import { buildDemoView } from "./labv2.projector";

const view = buildDemoView();

export default {
  title: "Lab 2.0/Workspace/LabV2",
  component: LabV2,
  parameters: { layout: "fullscreen" },
};

export const Default = () => <LabV2 view={view} />;
export const Analyzing = () => <LabV2 view={view} isAnalyzing />;
export const WithError = () => (
  <LabV2 view={view} analyzeError="Backend unreachable · retry when host resolves." />
);
