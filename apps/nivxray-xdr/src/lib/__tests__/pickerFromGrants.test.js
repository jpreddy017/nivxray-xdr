/**
 * P0-FIX-6B-2 · PICKER FROM GRANTS — the customer switcher is an
 * AUTHORIZATION surface, not a directory.
 *
 * The menu used to be filled from `GET /api/xdr/tenants` (the whole tenant
 * registry, gated only by `tenants.read`), so a principal could be offered —
 * and learn the existence of — every customer on the platform. These tests
 * pin the new contract: the list comes from
 * `session-context.authorized_customers`, selection goes through the audited
 * `POST /api/edr/session/active-tenant`, and no browser value can add a
 * customer.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  authorityScope, authorizedCustomers, CONTROL_CONTEXT_ONLY,
  CONTROL_SWITCHABLE, CONTROL_UNRESOLVED, contentGateFor, customerControlFor,
  customerLabel, GATE_FAILED, GATE_RENDER, isPlatformPrincipal, serverCustomer,
} from "@/nivxforge/tenantContext";

const PICKER_FILE = readFileSync(
  new URL("../../nivxforge/components/CustomerPicker.jsx", import.meta.url),
  "utf8");
//: executable source only — the file's header comment explains the sources it
//: deliberately no longer reads, and must not be mistaken for reading them.
const PICKER = PICKER_FILE.slice(PICKER_FILE.indexOf("import React"));

const SINGLE = {
  principal: { email: "analyst@customer-a.test", role: "analyst" },
  tenant_scope: { authorized: true, authority_scope: "CUSTOMER",
                  all_tenants: false, tenant_ids: ["customer-a"] },
  customers: [{ customer: "customer-a", display_name: "Customer A" }],
  authorized_customers: [{ customer: "customer-a",
                           display_name: "Customer A", kind: "CUSTOMER" }],
  active_customer: { value: "customer-a", basis: "SINGLE_AUTHORIZED_TENANT" },
};

const MULTI = {
  principal: { email: "soc@mssp.test", role: "soc_manager" },
  tenant_scope: { authorized: true, authority_scope: "CUSTOMER",
                  all_tenants: false,
                  tenant_ids: ["customer-a", "customer-b"] },
  customers: [{ customer: "customer-a", display_name: "Customer A" }],
  authorized_customers: [
    { customer: "customer-a", display_name: "Customer A", kind: "CUSTOMER" },
    { customer: "customer-b", display_name: "Customer B", kind: "CUSTOMER" },
  ],
  active_customer: { value: null, basis: "MULTIPLE_AUTHORIZED_TENANTS" },
};

const PLATFORM = {
  principal: { email: "admin@nivxray.com", role: "admin" },
  tenant_scope: { authorized: true, authority_scope: "PLATFORM",
                  all_tenants: true, tenant_ids: ["default", "nivx-live"] },
  customers: [{ customer: "default", display_name: "Preview Runtime" }],
  authorized_customers: [
    { customer: "default", display_name: "Preview Runtime",
      kind: "LEGACY_ADOPTED" },
    { customer: "nivx-live", display_name: "Preview Live Sources",
      kind: "LEGACY_ADOPTED" },
  ],
  active_customer: { value: null,
                     basis: "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER" },
};

// ── A · one authorized customer: no choice to offer ───────────────
describe("A · CUSTOMER with exactly one grant", () => {
  it("renders context only — never SELECT CUSTOMER", () => {
    expect(customerControlFor(SINGLE)).toBe(CONTROL_CONTEXT_ONLY);
    expect(serverCustomer(SINGLE)).toBe("customer-a");
    expect(customerLabel(SINGLE)).toBe("Customer A");
    expect(contentGateFor("ready", customerControlFor(SINGLE)))
      .toBe(GATE_RENDER);
  });
});

// ── B/C · multiple grants: only the authorized customers ──────────
describe("B/C · CUSTOMER with several grants", () => {
  it("offers a switcher containing ONLY the server-authorized set", () => {
    expect(customerControlFor(MULTI)).toBe(CONTROL_SWITCHABLE);
    expect(authorizedCustomers(MULTI).map((c) => c.customer))
      .toEqual(["customer-a", "customer-b"]);
  });

  it("cannot offer a customer the server did not authorize", () => {
    expect(authorizedCustomers(MULTI).map((c) => c.customer))
      .not.toContain("customer-c");
    // the evidence-derived `customers` list is NOT the offer list
    expect(authorizedCustomers(MULTI).length)
      .toBeGreaterThan(MULTI.customers.length);
  });

  it("offers nothing when the server authorized nothing", () => {
    expect(authorizedCustomers({ tenant_scope: { authorized: true },
                                 authorized_customers: [] })).toEqual([]);
    expect(authorizedCustomers({})).toEqual([]);
    expect(authorizedCustomers({ authorized_customers: [{ customer: " " }] }))
      .toEqual([]);
  });
});

// ── D/E · the browser cannot add a customer ───────────────────────
describe("D/E · hostile query string and stale storage", () => {
  it("the picker reads no browser-controlled source", () => {
    expect(PICKER).not.toMatch(/localStorage/);
    expect(PICKER).not.toMatch(/location\.search|URLSearchParams|\?tenant=/);
    expect(PICKER).not.toMatch(/"default"|'default'/);
  });

  it("the picker never reads the tenant registry", () => {
    expect(PICKER).not.toMatch(/xdr\/tenants/);
    expect(PICKER).not.toMatch(/api\.get\(/);
  });

  it("the offered list is a prop derived from session-context only", () => {
    expect(PICKER).toMatch(/customers = \[\]/);
    expect(PICKER).toMatch(/customers \|\| \[\]/);
  });

  it("role names play no part in the client decision", () => {
    for (const role of ["admin", "soc_manager", "mssp_operator",
                        "platform_admin"]) {
      expect(PICKER).not.toContain(role);
    }
    expect(authorityScope({ principal: { role: "admin" },
                            tenant_scope: { authorized: true } }))
      .toBe("CUSTOMER");
  });
});

// ── F/G · selection is a SERVER action ────────────────────────────
describe("F/G · selecting a customer", () => {
  it("calls the audited switch endpoint before persisting anything", () => {
    expect(PICKER).toMatch(/api\.post\(\s*"\/edr\/session\/active-tenant"/);
    const post = PICKER.indexOf("active-tenant");
    const persist = PICKER.indexOf("setActiveTenant(id)");
    expect(post).toBeGreaterThan(-1);
    expect(persist).toBeGreaterThan(post);          // server first, then local
  });

  it("a refused selection changes no active customer", () => {
    const refusal = PICKER.slice(PICKER.indexOf("catch (e)"));
    expect(refusal).not.toMatch(/setActiveTenant/);
    expect(refusal).toMatch(/nvf-customer-refusal|setErr/);
  });
});

// ── H/I · PLATFORM Super Admin ────────────────────────────────────
describe("H/I · PLATFORM principal", () => {
  it("is recognised only from the explicit server designation", () => {
    expect(isPlatformPrincipal(PLATFORM)).toBe(true);
    expect(isPlatformPrincipal(MULTI)).toBe(false);
    expect(isPlatformPrincipal(SINGLE)).toBe(false);
    expect(isPlatformPrincipal({ tenant_scope: { all_tenants: true } }))
      .toBe(false);                                 // breadth ≠ designation
  });

  it("stays in PLATFORM context when no customer is selected", () => {
    expect(customerControlFor(PLATFORM)).toBe(CONTROL_SWITCHABLE);
    expect(serverCustomer(PLATFORM)).toBeNull();    // no silent "default"
    expect(customerLabel(PLATFORM)).toBeNull();
  });

  it("offers only the authoritative customers the server listed", () => {
    expect(authorizedCustomers(PLATFORM).map((c) => c.customer))
      .toEqual(["default", "nivx-live"]);
  });

  it("labels the platform context explicitly", () => {
    expect(PICKER).toMatch(/nvf-platform-badge/);
    expect(PICKER).toMatch(/PLATFORM AUTHORITY/);
  });
});

// ── J · fail closed (Fix 4A/4B preserved) ─────────────────────────
describe("J · authority-resolution failure", () => {
  it("renders no tenant-bound content and says why", () => {
    expect(contentGateFor("error", CONTROL_SWITCHABLE)).toBe(GATE_FAILED);
    expect(contentGateFor("ready", CONTROL_UNRESOLVED)).toBe(GATE_FAILED);
    expect(customerControlFor({ active_customer: { basis: "NOT_AUTHORIZED" } }))
      .toBe(CONTROL_UNRESOLVED);
    expect(customerControlFor(null)).toBe(CONTROL_UNRESOLVED);
  });
});
