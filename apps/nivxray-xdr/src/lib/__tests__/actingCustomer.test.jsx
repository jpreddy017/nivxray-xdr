// @vitest-environment jsdom
//
// The acting customer is a STATE, and "not resolved yet" is not the same fact
// as "no customer selected". Conflating them is what made a tenant-scoped read
// fire with no X-Tenant-Id and then render the server's correct
// TENANT_REQUIRED refusal as a backend failure.
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  CUSTOMER_NONE, CUSTOMER_PENDING, CUSTOMER_READY, CUSTOMER_SEALED,
  useActingCustomer,
} from "../actingCustomer";
import {
  bindServerTenant, resetServerTenant, sealTenantAuthority, setActiveTenant,
} from "../tenant";

const OWN = "acme-corp";

beforeEach(() => { resetServerTenant(); window.localStorage.clear(); });
afterEach(() => { resetServerTenant(); window.localStorage.clear(); });

describe("the acting customer distinguishes four states", () => {
  it("is PENDING before the server's authority answered", () => {
    const { result } = renderHook(() => useActingCustomer());
    expect(result.current.state).toBe(CUSTOMER_PENDING);
    expect(result.current.tenant).toBeNull();
  });

  it("becomes READY when the server binds a customer, even after mount", () => {
    const { result } = renderHook(() => useActingCustomer());
    expect(result.current.state).toBe(CUSTOMER_PENDING);
    act(() => { bindServerTenant(OWN, { switchable: false }); });
    expect(result.current.state).toBe(CUSTOMER_READY);
    expect(result.current.tenant).toBe(OWN);
  });

  it("is NONE for a switchable principal that selected nothing", () => {
    const { result } = renderHook(() => useActingCustomer());
    act(() => { bindServerTenant(null, { switchable: true }); });
    expect(result.current.state).toBe(CUSTOMER_NONE);
    expect(result.current.tenant).toBeNull();
  });

  it("is SEALED when the authority could not be established", () => {
    const { result } = renderHook(() => useActingCustomer());
    act(() => { sealTenantAuthority(); });
    expect(result.current.state).toBe(CUSTOMER_SEALED);
    expect(result.current.tenant).toBeNull();
  });

  it("reports the new customer after a switch", () => {
    bindServerTenant(null, { switchable: true });
    setActiveTenant(OWN);
    const { result } = renderHook(() => useActingCustomer());
    expect(result.current.tenant).toBe(OWN);
    act(() => {
      setActiveTenant("contoso-corp");
      window.dispatchEvent(new CustomEvent("nvx-tenant-bound",
                                          { detail: "contoso-corp" }));
    });
    expect(result.current.state).toBe(CUSTOMER_READY);
    expect(result.current.tenant).toBe("contoso-corp");
  });

  it("re-reads the binding a console made before the hook mounted", () => {
    bindServerTenant(OWN, { switchable: false });
    const { result } = renderHook(() => useActingCustomer());
    expect(result.current.state).toBe(CUSTOMER_READY);
  });
});
