import { expect, it } from "vitest";
import { PRODUCT_SCOPE, HOME_PATH, BRAND, isForeignPath, productOfPath } from "@/productScope";
// Exercise the real module under both scoped configs and the unchanged combined preview.
const expected = process.env.NIVX_TEST_PRODUCT || "";
it("scoped build identifies its own product and landing route", () => {
  expect(PRODUCT_SCOPE).toBe(expected);
  expect(HOME_PATH).toBe(`/${PRODUCT_SCOPE || "xdr"}`);
  expect(BRAND.label).toBe(PRODUCT_SCOPE === "edr" ? "NivXForge EDR" : "NivXRay XDR");
});
it("scope rejects the other product while preserving shared login", () => {
  const other = PRODUCT_SCOPE === "xdr" ? "edr" : "xdr";
  expect(isForeignPath(`/${other}/investigation`)).toBe(expected !== "");
  expect(isForeignPath(`/${PRODUCT_SCOPE}/investigation`)).toBe(false);
  expect(isForeignPath("/login")).toBe(false);
  expect(productOfPath("/login")).toBeNull();
});
