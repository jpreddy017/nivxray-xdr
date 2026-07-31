/**
 * Storybook 8 config for NivXRay · Lab 2.0 component library.
 *
 * Stories live alongside components in `src/nivxforge/**` (Lab 2.0
 * surface only). Legacy Workspace components are NOT included so
 * the story catalogue stays focused on the new evidence-driven
 * component system.
 */
const path = require("path");

/** @type { import('@storybook/react-webpack5').StorybookConfig } */
const config = {
  stories: [
    "../src/nivxforge/**/*.stories.@(js|jsx|ts|tsx|mdx)",
  ],
  addons: [
    "@storybook/addon-essentials",
    "@storybook/addon-interactions",
    "@storybook/addon-a11y",
    "@storybook/preset-create-react-app",
  ],
  framework: {
    name: "@storybook/react-webpack5",
    options: {},
  },
  staticDirs: ["../public"],
  webpackFinal: async (webpackConfig) => {
    webpackConfig.resolve = webpackConfig.resolve || {};
    webpackConfig.resolve.alias = {
      ...(webpackConfig.resolve.alias || {}),
      "@": path.resolve(__dirname, "../src"),
    };
    return webpackConfig;
  },
  docs: {
    autodocs: "tag",
  },
};

module.exports = config;
