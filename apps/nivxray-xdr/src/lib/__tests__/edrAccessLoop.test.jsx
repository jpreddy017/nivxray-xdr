/**
 * EDR access loop · "pick a customer" is not "you are forbidden".
 *
 * `/edr` alternated between the dashboard and "You are not authorized for this
 * page". The route itself maps to no page capability — `consolePermissions()`
 * and `routePermissions()` both return `undefined` for `/edr`, so nothing in
 * the guard can deny it. The denial came from the transport: ANY 403 latched
 * `invalidateSecurity("denied", path)`, and with no customer selected the
 * first tenant-scoped read answers 403 TENANT_REQUIRED. "Recheck access"
 * cleared the latch, the page mounted, the read fired again, and the latch
 * came back.
 *
 * These tests fix the distinction in place, and the ones asserting that a real
 * refusal still latches are as important as the ones asserting the loop is
 * gone.
 */
import React from "react";
import axios from "axios";
import { renderToStaticMarkup } from "react-dom/server";
import { StaticRouter } from "react-router-dom/server";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { secureRequests, secureFetchJson, isTenantSelectionRefusal,
         refusalCode } from "../secureRequests";
import { invalidateSecurity, securitySnapshot } from "../securityState";
import { Protected } from "@/App";

const access = vi.hoisted(() => ({ loading: false, answer: true }));
vi.mock("@/xdr/access/AccessProvider", () => ({
  useAccess: () => ({ loading: access.loading,
                      canAny: () => access.answer, refresh: vi.fn() }),
  AccessProvider: ({ children }) => children,
}));
vi.mock("@/lib/auth", () => ({
  useAuth: () => ({ user: { email: "operator@synthetic" }, loading: false }),
}));
vi.mock("@/xdr/XdrShell", () => ({ default: ({ children }) => children }));
vi.mock("@/nivxforge/NivXForgeConsole", () => ({
  default: ({ children }) => children,
}));

let loaded;
function Dashboard() { loaded(); return <div>EDR dashboard</div>; }
const render = (path) => renderToStaticMarkup(
  <StaticRouter location={path}><Protected><Dashboard /></Protected></StaticRouter>);

/** The server's own refusal shapes (see backend session_context.ScopeDenied). */
const TENANT_REQUIRED = { code: "TENANT_REQUIRED", basis: "MULTIPLE_AUTHORIZED_TENANTS",
  reason: "principal is authorized for several tenants and named none; there is no default tenant",
  requested_tenant: null, fail_closed: true };
const TENANT_NOT_RESOLVED = { code: "TENANT_NOT_RESOLVED", basis: "NOT_AUTHORIZED",
  reason: "principal holds no tenant scope", fail_closed: true };
const UNHELD = { code: "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL",
  reason: "this principal does not hold the named tenant" };
const ACCESS_DENIED = { code: "ACCESS_DENIED", reason: "principal not authorized" };

const refuse = (status, detail) => axios.create({
  adapter: async (config) => {
    throw Object.assign(new Error("synthetic refusal"),
      { config, response: { status, data: detail === undefined ? {} : { detail } } });
  },
});

beforeEach(() => {
  const values = new Map([["nvx_token", "synthetic-session"]]);
  const storage = { getItem: (k) => values.get(k) || null,
                    setItem: (k, v) => values.set(k, v),
                    removeItem: (k) => values.delete(k) };
  globalThis.window = Object.assign(new EventTarget(),
    { localStorage: storage, location: { pathname: "/edr" } });
  globalThis.localStorage = storage;
  loaded = vi.fn();
  access.loading = false;
  access.answer = true;
  invalidateSecurity("scope");
});
afterEach(() => {
  invalidateSecurity("scope");
  vi.unstubAllGlobals();
  delete globalThis.window;
  delete globalThis.localStorage;
});

describe("transport classification", () => {
  it.each([
    ["TENANT_REQUIRED", TENANT_REQUIRED],
    ["TENANT_NOT_RESOLVED", TENANT_NOT_RESOLVED],
  ])("%s does not latch a page denial and does not bump the epoch", async (_n, detail) => {
    const before = securitySnapshot();
    const client = refuse(403, detail);
    secureRequests(client);
    await expect(client.get("/edr/telemetry/freshness")).rejects.toThrow("synthetic refusal");
    expect(securitySnapshot().epoch).toBe(before.epoch);
    expect(securitySnapshot().reason).toBe(before.reason);
    expect(securitySnapshot().deniedPath).toBeNull();
  });

  it.each([
    ["ACCESS_DENIED", ACCESS_DENIED],
    ["TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL", UNHELD],
    ["an unstructured refusal", undefined],
    ["a string detail", "Forbidden"],
  ])("%s still latches the denial (fail closed)", async (_n, detail) => {
    const before = securitySnapshot().epoch;
    const client = refuse(403, detail);
    secureRequests(client);
    await expect(client.get("/edr/endpoints")).rejects.toThrow("synthetic refusal");
    expect(securitySnapshot().epoch).toBeGreaterThan(before);
    expect(securitySnapshot().reason).toBe("denied");
    expect(securitySnapshot().deniedPath).toBe("/edr");
  });

  it("401 still ends the session and clears the token", async () => {
    const client = refuse(401, { code: "TOKEN_EXPIRED" });
    secureRequests(client);
    await expect(client.get("/edr/endpoints")).rejects.toThrow("synthetic refusal");
    expect(securitySnapshot().reason).toBe("expired");
    expect(localStorage.getItem("nvx_token")).toBeNull();
  });

  it("a customer-independent read in flight survives a tenant-selection refusal", async () => {
    let capabilitiesConfig;
    const client = axios.create({
      adapter: async (config) => {
        if (config.url.includes("capabilities")) {
          capabilitiesConfig = config;
          return { data: { capabilities: [] }, status: 200, config };
        }
        throw Object.assign(new Error("synthetic refusal"),
          { config, response: { status: 403, data: { detail: TENANT_REQUIRED } } });
      },
    });
    secureRequests(client);
    const capabilities = client.get("/edr/wave0/capabilities");
    await expect(client.get("/edr/telemetry/freshness")).rejects.toThrow("synthetic refusal");
    await expect(capabilities).resolves.toMatchObject({ status: 200 });
    expect(capabilitiesConfig.signal.aborted).toBe(false);
  });

  it("secureFetchJson classifies the same way", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: false, status: 403, json: async () => ({ detail: TENANT_REQUIRED }) }));
    const before = securitySnapshot().epoch;
    await expect(secureFetchJson("/api/edr/telemetry/freshness")).rejects.toThrow();
    expect(securitySnapshot().epoch).toBe(before);
    expect(securitySnapshot().reason).not.toBe("denied");
  });

  it("the classifier reads the server's code, never prose", () => {
    expect(refusalCode(TENANT_REQUIRED)).toBe("TENANT_REQUIRED");
    expect(refusalCode("Forbidden")).toBeNull();
    expect(refusalCode(undefined)).toBeNull();
    expect(isTenantSelectionRefusal(TENANT_REQUIRED)).toBe(true);
    expect(isTenantSelectionRefusal(UNHELD)).toBe(false);
    expect(isTenantSelectionRefusal({ reason: "tenant required" })).toBe(false);
  });
});

describe("the /edr route itself", () => {
  it("renders the dashboard when no customer is selected instead of looping", async () => {
    const client = refuse(403, TENANT_REQUIRED);
    secureRequests(client);
    await expect(client.get("/edr/telemetry/freshness")).rejects.toThrow();
    const html = render("/edr");
    expect(html).toContain("EDR dashboard");
    expect(html).not.toContain("route-denied");
    expect(loaded).toHaveBeenCalledOnce();
  });

  it("a genuine refusal on this path still refuses the page", async () => {
    const client = refuse(403, ACCESS_DENIED);
    secureRequests(client);
    await expect(client.get("/edr/endpoints")).rejects.toThrow();
    const html = render("/edr");
    expect(html).toContain("route-denied");
    expect(loaded).not.toHaveBeenCalled();
  });

  it("unresolved authorization shows loading, never the dashboard", () => {
    access.loading = true;
    const html = render("/xdr/incidents");
    expect(html).toContain("route-loading");
    expect(html).not.toContain("EDR dashboard");
    expect(loaded).not.toHaveBeenCalled();
  });

  it("a denial latched for another path does not block this one", async () => {
    invalidateSecurity("denied", "/edr/computers");
    const html = render("/edr");
    expect(html).toContain("EDR dashboard");
  });
});
