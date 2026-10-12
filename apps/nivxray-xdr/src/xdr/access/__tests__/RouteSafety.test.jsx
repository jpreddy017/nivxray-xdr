import React from "react";
import { createMemoryHistory } from "@remix-run/router";
import { renderToStaticMarkup } from "react-dom/server";
import { StaticRouter } from "react-router-dom/server";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { Protected } from "@/App";
import { permissionState, routePermissions, ADMIN_PERMISSIONS } from "../routePermissions";
import { invalidateSecurity } from "@/lib/securityState";
import { readInvestigationCases } from "@/xdr/pages/XdrInvestigationsListPage";
import api from "@/lib/api";
const access = vi.hoisted(() => ({ loading: false, answer: true, grants: null }));
vi.mock("../AccessProvider", () => ({ useAccess: () => ({ loading: access.loading, canAny: (list) => access.grants ? list.some((p) => access.grants.includes(p)) : access.answer, refresh: vi.fn() }) }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ user: { email: "synthetic" }, loading: false }) }));
vi.mock("@/lib/api", () => ({ default: { get: vi.fn() } }));
vi.mock("@/xdr/XdrShell", () => ({ default: ({ children }) => children }));
let loaded;
function Sensitive() { loaded(); return <div>Synthetic record</div>; }
const render = (path) => renderToStaticMarkup(<StaticRouter location={path}><Protected><Sensitive /></Protected></StaticRouter>);
beforeEach(() => { access.loading = false; access.answer = true; access.grants = null; loaded = vi.fn(); vi.resetAllMocks(); invalidateSecurity("scope"); });
it("authorized direct route renders while denied route never mounts the loader", () => {
  expect(render("/xdr/admin/secrets")).toContain("Synthetic record");
  expect(loaded).toHaveBeenCalledOnce(); loaded.mockClear(); access.answer = false;
  expect(render("/xdr/admin/secrets")).toContain("route-denied"); expect(loaded).not.toHaveBeenCalled();
});
it.each([null, "loading"])("unknown/loading authorization %s does not mount sensitive content", (answer) => {
  access.answer = answer === "loading" ? true : answer; access.loading = answer === "loading";
  expect(render("/xdr/incidents/A-1")).not.toContain("Synthetic record"); expect(loaded).not.toHaveBeenCalled();
});
it("memory history back/forward rechecks destination permission without changing URLs", () => {
  const history = createMemoryHistory({ initialEntries: ["/xdr/admin/secrets", "/xdr/incidents/A-1"], initialIndex: 1 });
  const check = () => {
    access.answer = !history.location.pathname.includes("secrets");
    expect(render(history.location.pathname).includes("Synthetic record")).toBe(access.answer);
  };
  check(); history.go(-1); check(); history.go(1); check();
  expect(history.location.pathname).toBe("/xdr/incidents/A-1");
  expect(loaded).toHaveBeenCalledTimes(2);
});
it("a 403 discards the active destination until context changes", () => {
  invalidateSecurity("denied", "/xdr/admin/secrets");
  expect(render("/xdr/admin/secrets")).toContain("route-denied"); expect(loaded).not.toHaveBeenCalled();
  invalidateSecurity("scope"); expect(render("/xdr/admin/secrets")).toContain("Synthetic record");
});
it("unmapped admin capabilities fail closed without removing routes", () => {
  expect(Object.keys(ADMIN_PERMISSIONS)).toHaveLength(28);
  expect(render("/xdr/admin/edr-enrollment")).toContain("route-unavailable"); expect(loaded).not.toHaveBeenCalled();
  expect(routePermissions("/edr/response")).toBeUndefined();
});
it("page mapping uses resource permissions, never role names", () => {
  expect(routePermissions("/xdr/admin/secrets")).toEqual(["secrets.read"]);
  expect(routePermissions("/xdr/admin/api-keys")).toEqual(["api_keys.read"]);
  expect(routePermissions("/xdr/clients")).toEqual(["tenants.read"]);
  expect(permissionState({ loading: false, canAny: () => null }, ["incidents.read"])).toBe("unavailable");
});
it.each([401, 403])("denied investigation authority %s cannot fall back to incidents", async (status) => {
  api.get.mockRejectedValueOnce({ response: { status } });
  await expect(readInvestigationCases()).rejects.toEqual({ response: { status } });
  expect(api.get).toHaveBeenCalledOnce(); expect(api.get).toHaveBeenCalledWith("/v2/cases", { signal: undefined });
});
it("cancelled investigation cannot start a fallback request", async () => {
  api.get.mockRejectedValueOnce({ code: "ERR_CANCELED" });
  await expect(readInvestigationCases()).rejects.toEqual({ code: "ERR_CANCELED" });
  expect(api.get).toHaveBeenCalledOnce();
});
it("documented absent-route compatibility fallback still works", async () => {
  api.get.mockRejectedValueOnce({ response: { status: 404, data: { detail: "Not Found" } } });
  api.get.mockResolvedValueOnce({ data: { incidents: [{ id: "A-1", name: "Synthetic incident" }] } });
  expect((await readInvestigationCases())[0].id).toBe("A-1"); expect(api.get).toHaveBeenCalledTimes(2);
});

it("tenant-local permissions cannot authorize a different selected customer", async () => {
  const { effectivePermission } = await vi.importActual("../AccessProvider");
  const state = { available: true, data: { tenant: "A", permissions: ["secrets.read"], cross_tenant: false } };
  expect(effectivePermission(state, "secrets.read", "A")).toBe(true);
  expect(effectivePermission(state, "secrets.read", "B")).toBeNull();
  expect(effectivePermission({ available: false }, "secrets.read", "A")).toBeNull();
  expect(effectivePermission(state, "api_keys.read", "A")).toBe(false);
});

it("a resource grant alone cannot enter the separate administration console", () => {
  access.grants = ["secrets.read", "console.soc.access"];
  expect(render("/xdr/admin/secrets")).toContain("route-denied"); expect(loaded).not.toHaveBeenCalled();
  access.grants.push("console.admin.access");
  expect(render("/xdr/admin/secrets")).toContain("Synthetic record");
});
