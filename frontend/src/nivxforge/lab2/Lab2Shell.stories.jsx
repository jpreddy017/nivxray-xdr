/**
 * Storybook stories for Lab2Shell.
 *
 * States covered:
 *   1. Empty — no CIO wired
 *   2. Populated — real CIO with verdict
 *   3. Nav collapsed — dockedPanels.left = false
 *   4. Context collapsed — dockedPanels.right = false
 *
 * All stories run inside `<Lab2Provider>` because the shell depends
 * on workspace-state context (docked panels, palette, theme).
 */
import React from "react";
import Lab2Shell from "./Lab2Shell";
import { Lab2Provider, useDockedPanels } from "./Lab2Provider";

const populatedCIO = {
  schema_version: "0.1",
  cio_id: "cio_demo_001",
  created_at: new Date().toISOString(),
  source: { surface: "storybook", endpoint: null, correlation_id: null },
  input_text: "powershell -w hidden -enc SQBFAFgA...",
  evidence_graph: { nodes: [], edges: [] },
  reasoning_steps: [],
  timeline: [],
  summary: {},
  verdict: {
    label: "Malicious",
    confidence: 0.94,
    confidence_pct: 94,
    reason: "Base64-encoded PowerShell downloader observed with Invoke-Expression stager.",
    contributors: [
      { node_id: "N-002", kind: "ioc", weight: 8, confidence: 0.9, category: "url", label: "hxxp://c2.example[.]net/agent.ps1" },
      { node_id: "N-003", kind: "behaviour", weight: 7, confidence: 0.88, category: "execution", label: "Encoded PowerShell stager" },
    ],
    not_counted: [],
    engine: "unified-verdict-engine",
  },
};

function ShellHarness({ initialCIO, collapseLeft, collapseRight }) {
  // A tiny inline collapser so stories can showcase docked-panel state.
  const CollapseController = () => {
    const { dockedPanels, togglePanel } = useDockedPanels();
    React.useEffect(() => {
      if (collapseLeft && dockedPanels.left) togglePanel("left");
      if (collapseRight && dockedPanels.right) togglePanel("right");
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);
    return null;
  };
  return (
    <Lab2Provider initialCIO={initialCIO}>
      <CollapseController />
      <Lab2Shell caseLabel={initialCIO ? initialCIO.cio_id : "no active case"} />
    </Lab2Provider>
  );
}

export default {
  title: "Lab 2.0/Shell/Lab2Shell",
  component: Lab2Shell,
  parameters: {
    layout: "fullscreen",
  },
};

export const Empty = () => <ShellHarness initialCIO={null} />;

export const Populated = () => <ShellHarness initialCIO={populatedCIO} />;

export const LeftNavCollapsed = () => (
  <ShellHarness initialCIO={populatedCIO} collapseLeft />
);

export const ContextPanelCollapsed = () => (
  <ShellHarness initialCIO={populatedCIO} collapseRight />
);
