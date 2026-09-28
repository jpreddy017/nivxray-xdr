/**
 * P0-FIX-4A · the single-customer EDR console must not ask the user to
 * pick the only customer it could ever be, and the browser must not be
 * the thing that decides which customer that is.
 *
 * Pure unit suite: `lib/tenant.js` and `nivxforge/tenantContext.js` only,
 * with a stubbed `window`. No network, no DOM renderer, no credential.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  CONTROL_CONTEXT_ONLY, CONTROL_SWITCHABLE, CONTROL_UNRESOLVED,
  customerControlFor, customerLabel, serverCustomer,
} from "../../nivxforge/tenantContext";
import {
  activeTenant, bindServerTenant, resetServerTenant, serverBoundTenant,
  setActiveTenant, tenantIsSwitchable,
} from "../tenant";

const OWN = "acme-corp";
const FOREIGN = "contoso-corp";

function stubWindow(search = "", stored = null) {
  const store = new Map();
  if (stored) store.set("nvx_tenant", stored);
  globalThis.window = {
    location: { search },
    localStorage: {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
    },
  };
  return store;
}

const SESS_SINGLE = {
  principal: { email: "analyst@acme.test", role: "l2_investigator" },
  tenant_scope: { authorized: true, all_tenants: false, tenant_ids: [OWN] },
  customers: [{ customer: OWN, display_name: "ACME Corporation" }],
  active_customer: { value: OWN, basis: "SINGLE_AUTHORIZED_TENANT" },
};
const SESS_MULTI = {
  tenant_scope: { authorized: true, all_tenants: false,
                  tenant_ids: [OWN, FOREIGN] },
  customers: [{ customer: OWN }, { customer: FOREIGN }],
  active_customer: { value: null, basis: "MULTIPLE_AUTHORIZED_TENANTS" },
};
const SESS_CROSS = {
  tenant_scope: { authorized: true, all_tenants: true, tenant_ids: [] },
  customers: [{ customer: OWN }, { customer: FOREIGN }],
  active_customer: { value: null,
                     basis: "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER" },
};

beforeEach(() => { resetServerTenant(); stubWindow(); });
afterEach(() => { resetServerTenant(); delete globalThis.window; });

describe("h · which customer control may be rendered", () => {
  it("h01 · a single-authorized-tenant principal gets CONTEXT ONLY", () => {
    expect(customerControlFor(SESS_SINGLE)).toBe(CONTROL_CONTEXT_ONLY);
    expect(serverCustomer(SESS_SINGLE)).toBe(OWN);
    expect(customerLabel(SESS_SINGLE)).toBe("ACME Corporation");
  });

  it("h02 · only the server's switchable bases get the picker", () => {
    expect(customerControlFor(SESS_MULTI)).toBe(CONTROL_SWITCHABLE);
    expect(customerControlFor(SESS_CROSS)).toBe(CONTROL_SWITCHABLE);
  });

  it("h03 · an unresolved or unauthorized context renders no picker", () => {
    expect(customerControlFor(null)).toBe(CONTROL_UNRESOLVED);
    expect(customerControlFor({})).toBe(CONTROL_UNRESOLVED);
    expect(customerControlFor({ active_customer: { basis: "NOT_AUTHORIZED" } }))
      .toBe(CONTROL_UNRESOLVED);
  });

  it("h04 · authority is never inferred from a role name", () => {
    const admin = { principal: { role: "platform_admin" },
                    active_customer: { value: OWN,
                                       basis: "SINGLE_AUTHORIZED_TENANT" } };
    expect(customerControlFor(admin)).toBe(CONTROL_CONTEXT_ONLY);
    const analyst = { principal: { role: "l1_analyst" },
                      active_customer: { value: null,
                                         basis: "MULTIPLE_AUTHORIZED_TENANTS" } };
    expect(customerControlFor(analyst)).toBe(CONTROL_SWITCHABLE);
  });
});

describe("h · the server binding outranks the browser", () => {
  it("h05 · the bound principal uses the server's customer", () => {
    bindServerTenant(OWN, { switchable: false });
    expect(serverBoundTenant()).toBe(OWN);
    expect(tenantIsSwitchable()).toBe(false);
    expect(activeTenant()).toBe(OWN);
  });

  it("h06 · a foreign ?tenant= never reaches the tenant header", () => {
    // `?tenant=` was REMOVED from the resolution order: it cannot be the
    // acting tenant even before the server binding arrives.
    stubWindow(`?tenant=${FOREIGN}`);
    expect(activeTenant()).toBeNull();
    bindServerTenant(OWN, { switchable: false });
    expect(activeTenant()).toBe(OWN);
  });

  it("h07 · a stale/foreign nvx_tenant cannot become authoritative", () => {
    const store = stubWindow("", FOREIGN);
    bindServerTenant(OWN, { switchable: false });
    expect(activeTenant()).toBe(OWN);
    expect(store.get("nvx_tenant")).toBe(OWN);     // hostile value replaced
  });

  it("h08 · both hostile inputs together still lose", () => {
    stubWindow(`?tenant=${FOREIGN}&device=x`, FOREIGN);
    bindServerTenant(OWN, { switchable: false });
    expect(activeTenant()).toBe(OWN);
  });

  it("h09 · a bound principal cannot re-point itself", () => {
    stubWindow();
    bindServerTenant(OWN, { switchable: false });
    setActiveTenant(FOREIGN);
    expect(activeTenant()).toBe(OWN);
  });

  it("h10 · a switchable principal keeps its explicit selection", () => {
    stubWindow(`?tenant=${FOREIGN}`);
    bindServerTenant(null, { switchable: true });
    expect(tenantIsSwitchable()).toBe(true);
    expect(activeTenant()).toBeNull();            // the URL alone is not it
    setActiveTenant(FOREIGN);                     // the console may adopt it
    expect(activeTenant()).toBe(FOREIGN);
    stubWindow("", OWN);
    expect(activeTenant()).toBe(OWN);
  });

  it("h11 · no customer is ever invented", () => {
    stubWindow();
    expect(activeTenant()).toBeNull();
    bindServerTenant("", { switchable: false });
    expect(serverBoundTenant()).toBeNull();
    expect(activeTenant()).toBeNull();
    expect(serverCustomer({ active_customer: { value: null } })).toBeNull();
  });

  it("h12a · the binding is announced once, so late readers correct", () => {
    const seen = [];
    globalThis.window.dispatchEvent = (e) => seen.push(e?.detail);
    globalThis.CustomEvent = class { constructor(t, o) {
      this.type = t; this.detail = o?.detail; } };
    bindServerTenant(OWN, { switchable: false });
    bindServerTenant(OWN, { switchable: false });      // idempotent
    expect(seen).toEqual([OWN]);
  });

  it("h12 · the header name is unchanged, so no call site is bypassed",
     async () => {
       const { TENANT_HEADER } = await import("../tenant");
       expect(TENANT_HEADER).toBe("X-Tenant-Id");
     });
});
