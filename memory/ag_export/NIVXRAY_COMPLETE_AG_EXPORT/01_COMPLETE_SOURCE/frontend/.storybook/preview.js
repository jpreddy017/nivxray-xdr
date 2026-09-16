/**
 * Storybook preview — every story is auto-wrapped in the `.lab2`
 * container so semantic tokens (ADR-0018) resolve identically to
 * the production feature-flagged path.
 */
import React from "react";
import "../src/nivxforge/design/tokens.css";

/** @type { import('@storybook/react').Preview } */
const preview = {
  parameters: {
    layout: "padded",
    backgrounds: {
      default: "lab2-canvas",
      values: [
        { name: "lab2-canvas", value: "hsl(220 18% 8%)" },
        { name: "workspace-legacy", value: "#020617" },
        { name: "light", value: "#ffffff" },
      ],
    },
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
  },
  decorators: [
    (Story) =>
      React.createElement(
        "div",
        {
          className: "lab2",
          style: {
            background: "var(--bg-canvas)",
            padding: "var(--space-6)",
            minHeight: "100vh",
            color: "var(--fg-primary)",
            fontFamily: "var(--font-sans)",
          },
        },
        React.createElement(Story)
      ),
  ],
};

export default preview;
