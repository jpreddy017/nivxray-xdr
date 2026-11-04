/**
 * VerdictRibbon Storybook stories.
 *
 * ADR-0019 · Every component tier 3-6 ships stories BEFORE completion.
 * When Storybook is installed (`yarn add -D @storybook/react` etc.),
 * this file is discovered automatically. Until then, it serves as
 * living documentation of every rendered state.
 */
import React from "react";
import { CIOProvider } from "../hooks/useCIO";
import { VerdictRibbon } from "./VerdictRibbon";

export default {
  title: "Lab2/Panels/VerdictRibbon",
  component: VerdictRibbon,
  parameters: {
    docs: {
      description: {
        component:
          "Reference implementation per ADR-0019. Renders the unified " +
          "verdict engine's output. Consumes only `useVerdict()`.",
      },
    },
  },
};

// ─── Fixtures ────────────────────────────────────────────────────

const fixture = (verdict) => ({
  schema_version: "0.1",
  cio_id: "CIO-storybook",
  created_at: "2026-02-28T10:00:00Z",
  source: { surface: "storybook" },
  input_text: "",
  input_kind: "text",
  decode_chain: [],
  evidence_graph: { nodes: [], edges: [] },
  reasoning_steps: [],
  confidence: verdict?.confidence ?? 0,
  verdict,
  timeline: [],
  summary: {},
  recommendations: [],
  reports: {},
  metadata: {},
});

const withCIO = (verdict) => (Story) => (
  <div className="lab2" style={{ padding: 24, background: "var(--bg-canvas)", minHeight: 200 }}>
    <CIOProvider value={fixture(verdict)}>
      <Story />
    </CIOProvider>
  </div>
);

// ─── Stories (every state a component can be in) ─────────────────

export const Malicious = {
  decorators: [withCIO({
    label: "Malicious",
    confidence: 0.94, confidence_pct: 94,
    reason: "Top contributor: LOLBIN · regsvr32 (weight=10, confidence=0.9). Total contributing nodes: 6.",
    contributors: [], not_counted: [],
    engine: "unified-verdict-engine-v1",
  })],
};

export const Suspicious = {
  decorators: [withCIO({
    label: "Suspicious",
    confidence: 0.72, confidence_pct: 72,
    reason: "Top contributor: Encoded PowerShell (weight=6, confidence=0.85). Total contributing nodes: 3.",
    contributors: [], not_counted: [],
    engine: "unified-verdict-engine-v1",
  })],
};

export const RuntimeDependent = {
  decorators: [withCIO({
    label: "Runtime Dependent",
    confidence: 0.50, confidence_pct: 50,
    reason: "Payload decoded but no dominant driver — sandbox to disambiguate.",
    contributors: [], not_counted: [],
    engine: "unified-verdict-engine-v1",
  })],
};

export const Informational = {
  decorators: [withCIO({
    label: "Informational",
    confidence: 0.05, confidence_pct: 5,
    reason: "Only vendor-infrastructure observed — no artefact IOCs.",
    contributors: [], not_counted: [],
    engine: "unified-verdict-engine-v1",
  })],
};

export const Undetermined = {
  decorators: [withCIO({
    label: "Undetermined",
    confidence: 0.0, confidence_pct: 0,
    reason: "Insufficient evidence to reach a verdict.",
    contributors: [], not_counted: [],
    engine: "unified-verdict-engine-v1",
  })],
};

export const EmptyState = { decorators: [withCIO(null)] };

export const ErrorState = {
  decorators: [withCIO({
    label: "",
    confidence: null, confidence_pct: null,
    reason: "", contributors: [], not_counted: [],
    engine: "",
  })],
};
