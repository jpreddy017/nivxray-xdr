import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import axios from "axios";
import { secureRequests, secureFetchJson } from "../secureRequests";
import { installSecurityEvents, invalidateSecurity, securitySnapshot, subscribeSecurity } from "../securityState";
import { applyCustomerSelection } from "../customerSelection";
import { createRequestFence } from "../requestFence";
import { activeTenant, setActiveTenant, resetServerTenant, bindServerTenant } from "../tenant";
let cleanup;
beforeEach(() => {
  const values = new Map([["nvx_token", "synthetic-session"]]);
  const storage = { getItem: (k) => values.get(k) || null, setItem: (k,v) => values.set(k,v), removeItem: (k) => values.delete(k) };
  globalThis.window = Object.assign(new EventTarget(), { localStorage: storage, location: { pathname: "/xdr/incidents" } });
  globalThis.localStorage = storage;
  globalThis.CustomEvent = class extends Event { constructor(name, options) { super(name); this.detail = options?.detail; } };
  resetServerTenant(); cleanup = installSecurityEvents(window); invalidateSecurity("scope");
});
afterEach(() => { cleanup(); invalidateSecurity("scope"); resetServerTenant(); vi.unstubAllGlobals(); delete globalThis.window; delete globalThis.localStorage; });
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => { resolve=a; reject=b; }); return { promise, resolve, reject }; };
it("same-window A/B changes notify and discard prior context", () => {
  const notify = vi.fn(); const off = subscribeSecurity(notify);
  setActiveTenant("A"); const epoch = securitySnapshot().epoch; setActiveTenant("B");
  expect(activeTenant()).toBe("B"); expect(securitySnapshot().epoch).toBe(epoch+1); expect(notify).toHaveBeenCalledTimes(2); off();
});
it("incident server binding cannot be changed by the customer selector", () => {
  bindServerTenant("A", { switchable: false }); const epoch = securitySnapshot().epoch;
  setActiveTenant("B"); expect(activeTenant()).toBe("A"); expect(securitySnapshot().epoch).toBe(epoch);
});
it("cross-tab storage changes invalidate the current view", () => {
  const epoch = securitySnapshot().epoch; const event = new Event("storage"); event.key="nvx_tenant"; window.dispatchEvent(event);
  expect(securitySnapshot().epoch).toBe(epoch+1);
});
it("a pending A response cannot publish after B even if transport ignores cancellation", async () => {
  setActiveTenant("A"); const old = deferred(); const started = deferred(); let captured;
  const client=axios.create({ adapter: config => { captured=config; started.resolve(); return old.promise; } }); secureRequests(client);
  const request=client.get("/synthetic"); const assertion=expect(request).rejects.toMatchObject({ code:"ERR_CANCELED" });
  await started.promise; setActiveTenant("B"); expect(captured.signal.aborted).toBe(true);
  old.resolve({data:{id:"A-private"},status:200,config:captured}); await assertion;
});
it("rapid A/B/A requests retain only the latest context", async () => {
  const client=axios.create({adapter: async config => { invalidateSecurity("scope"); return {data:"old",status:200,config}; }}); secureRequests(client);
  await expect(client.get("/synthetic")).rejects.toMatchObject({code:"ERR_CANCELED"});
});
it.each([401,403])("%s invalidates sensitive view state and pending requests", async (status) => {
  const epoch=securitySnapshot().epoch;
  const client=axios.create({adapter: async config => { throw Object.assign(new Error("synthetic refusal"), {config,response:{status}}); }}); secureRequests(client);
  await expect(client.get("/synthetic")).rejects.toThrow("synthetic refusal");
  expect(securitySnapshot().epoch).toBeGreaterThan(epoch);
  expect(securitySnapshot().reason).toBe(status===401?"expired":"denied");
  if(status===401) expect(localStorage.getItem("nvx_token")).toBeNull();
});
it("an obsolete A denial cannot invalidate the current B view", async () => {
  const old=deferred(); const started=deferred(); let config;
  const client=axios.create({adapter:c=>{ config=c; started.resolve(); return old.promise; }}); secureRequests(client);
  const request=client.get("/synthetic"); const assertion=expect(request).rejects.toMatchObject({code:"ERR_CANCELED"});
  await started.promise; setActiveTenant("B"); const epoch=securitySnapshot().epoch;
  old.reject({config,response:{status:403}}); await assertion; expect(securitySnapshot().epoch).toBe(epoch);
});

it("latest customer selection wins even when the older response arrives first", () => {
  const fence = createRequestFence(); const older = fence.begin(); const latest = fence.begin();
  expect(fence.current(older)).toBe(false); expect(fence.current(latest)).toBe(true);
  fence.cancel(); expect(fence.current(latest)).toBe(false);
});

it("fetch responses fence delayed body parsing across a tenant switch", async () => {
  const body = deferred(); const started = deferred();
  vi.stubGlobal("fetch", async () => { started.resolve(); return { ok: true, json: () => body.promise }; });
  const request = secureFetchJson("/synthetic"); const assertion = expect(request).rejects.toMatchObject({ code: "ERR_CANCELED" });
  await started.promise; setActiveTenant("B"); body.resolve({ id: "A-private" }); await assertion;
});

it("denied customer selections cannot alter the current context", () => {
  setActiveTenant("A"); const epoch = securitySnapshot().epoch;
  expect(() => applyCustomerSelection({ authorized: false, tenant_ids: ["B"] }, "B")).toThrow("not authorized");
  expect(activeTenant()).toBe("A"); expect(securitySnapshot().epoch).toBe(epoch);
});
it("an authorized selector cannot relabel an incident-locked customer", () => {
  bindServerTenant("A", { switchable: false });
  expect(() => applyCustomerSelection({ authorized: true, tenant_ids: ["B"] }, "B")).toThrow("locked");
  expect(activeTenant()).toBe("A");
});
it("a server-authorized selection updates the applied customer", () => {
  expect(applyCustomerSelection({ authorized: true, tenant_ids: ["B"] }, "B")).toBe("B");
  expect(activeTenant()).toBe("B");
});
