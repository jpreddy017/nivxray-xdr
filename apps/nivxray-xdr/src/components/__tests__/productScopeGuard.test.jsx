// @vitest-environment jsdom
//
// The scope guard must REFUSE the other product without stranding the analyst.
// `vercel.json` carries a host redirect for `/` only, so a foreign path such as
// /xdr/incidents reloads onto this same EDR artifact and stops at the notice —
// with no way back into EDR it is a dead end.
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import ProductScopeGuard from "../ProductScopeGuard";

vi.mock("@/productScope", () => ({
  PRODUCT_SCOPE: "edr",
  HOME_PATH: "/edr",
  isForeignPath: (p) => p.startsWith("/xdr"),
  productOfPath: (p) => (p.startsWith("/xdr") ? "xdr" : "edr"),
}));

afterEach(cleanup);

const at = (path) => render(
  <MemoryRouter initialEntries={[path]}>
    <Routes>
      <Route path="*" element={
        <ProductScopeGuard><div data-testid="product-content" /></ProductScopeGuard>
      } />
    </Routes>
  </MemoryRouter>);

describe("the scope guard refuses the other product without stranding", () => {
  it("renders the product on its own paths", () => {
    at("/edr/computers");
    expect(screen.getByTestId("product-content")).toBeTruthy();
    expect(screen.queryByTestId("wrong-product-host")).toBeNull();
  });

  it("refuses a foreign path and loads nothing from the other product", () => {
    at("/xdr/incidents");
    expect(screen.getByTestId("wrong-product-host")).toBeTruthy();
    expect(screen.queryByTestId("product-content")).toBeNull();
    expect(screen.getByTestId("wrong-product-host").textContent)
      .toMatch(/Nothing was loaded from the other product/);
  });

  it("offers a way back into THIS product", () => {
    at("/xdr/incidents?customer=p0f-collector-auth-proof");
    const back = screen.getByTestId("wrong-product-host-back");
    expect(back.getAttribute("href")).toBe("/edr");
    expect(back.textContent).toMatch(/Back to NivXRay EDR/);
  });
});
