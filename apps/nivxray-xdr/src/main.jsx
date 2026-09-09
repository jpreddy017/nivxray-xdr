/**
 * NivXRay XDR standalone entry point.
 *
 * Independent from `/app/frontend`.  Consumes existing NivXRay APIs
 * over HTTP.  Renders under `/xdr/*` on the preview host.
 */
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import App from "./App.jsx";
import { AuthProvider } from "@/lib/auth";
import { BRAND } from "@/productScope";
import "./styles/globals.css";

// index.html ships a single static <title>, so a scoped deployment must
// correct it at boot — otherwise the EDR host shows "NivXRay XDR" in the tab.
document.title = BRAND.documentTitle;

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
);
