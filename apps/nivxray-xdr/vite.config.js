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
      strictPort: true,
    },
    preview: {
      port: 3100,
      strictPort: true,
      host: "0.0.0.0",
    },
  };
});
