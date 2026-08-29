import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// NivXRay XDR — standalone build config.
//
// Boundary rules (owner-locked 2026-08-29):
//   • This package MUST NOT import from /app/frontend/src — the `@`
//     alias below only resolves to the local `src/` directory.
//   • The build output is a self-contained static bundle rooted at
//     `/xdr/`.  For preview, the existing NivXRay frontend server
//     mounts this bundle at `/xdr/*` as static files.  The two
//     frontends never share a bundle, a router, or a runtime state.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    base: "/xdr/",
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "src"),
      },
    },
    define: {
      // Existing XDR/nivxforge code reads process.env.REACT_APP_BACKEND_URL
      // (CRA convention).  We expose the standalone-app equivalent so no
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
          // Deterministic file names so the base-app's static hosting
          // works with a single ingress rule.
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
  };
});
