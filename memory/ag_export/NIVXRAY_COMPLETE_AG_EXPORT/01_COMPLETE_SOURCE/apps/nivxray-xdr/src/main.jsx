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
import "./styles/globals.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
);
