import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// NivXRay XDR — standalone build config.
//
// Boundary rules (owner-locked 2026-08-29):
//   • This package MUST NOT import from /app/frontend/src — the `@`
//     alias below only resolves to the local `src/` directory.
//   • The build output is a self-contained static bundle that runs at
//     its own origin (deployed as its own Emergent project).
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    base: "/",
    // Classic JSX runtime — the moved source uses <React.Fragment>
    // and React.createElement via lucide/react-router extensions.  The
    // classic runtime keeps `React` in scope automatically and matches
    // the CRA-based semantics the moved code was originally authored
    // against, so no source rewrite is required.
    plugins: [react({ jsxRuntime: "classic" })],
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "src"),
      },
    },
    define: {
      // Existing XDR/nivxforge code reads process.env.REACT_APP_BACKEND_URL
      // (CRA convention).  Expose the standalone-app equivalent so no
      // moved file needs edits.
      "process.env.REACT_APP_BACKEND_URL": JSON.stringify(
        env.REACT_APP_NIVXRAY_API_URL || env.REACT_APP_BACKEND_URL || "",
      ),
      // Origin of the SEPARATELY deployed NivXMachines Workspace
      // frontend (AutoInvestigate / Decoder / Analyze / Lab). It is a
      // different origin by owner decision, so this app can only open
      // it in a new tab — never route to it. Empty means "not
      // configured", and the console then renders the launcher disabled
      // instead of linking nowhere.
      // Origins of the SEPARATELY deployed sibling products. Empty means
      // "this deployment serves it at the same origin" (preview, and any
      // combined deployment), so cross-product pivots stay in-app. Both
      // REACT_APP_* and VITE_* spellings are accepted so a deployment can
      // use either convention. PUBLIC configuration only — a build
      // variable is readable in the browser bundle and must never hold a
      // credential.
      "process.env.REACT_APP_XDR_URL": JSON.stringify(
        env.REACT_APP_XDR_URL || env.VITE_XDR_URL || "",
      ),
      "process.env.REACT_APP_EDR_URL": JSON.stringify(
        env.REACT_APP_EDR_URL || env.VITE_EDR_URL || "",
      ),
      "process.env.REACT_APP_WORKSPACE_URL": JSON.stringify(
        env.REACT_APP_WORKSPACE_URL || env.VITE_WORKSPACE_URL || "",
      ),
    },
    build: {
      outDir: "dist",
      emptyOutDir: true,
      sourcemap: false,
      rollupOptions: {
        output: {
          entryFileNames: "assets/[name]-[hash].js",
          chunkFileNames: "assets/[name]-[hash].js",
          assetFileNames: "assets/[name]-[hash][extname]",
        },
      },
    },
    server: {
      port: 3100,
      strictPort: false,
      host: "0.0.0.0",
      allowedHosts: true,
    },
    preview: {
      port: 3100,
      strictPort: false,
      host: "0.0.0.0",
      allowedHosts: true,
    },
  };
});
