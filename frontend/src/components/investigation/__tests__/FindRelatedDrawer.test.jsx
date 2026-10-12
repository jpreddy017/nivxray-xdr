import React, { act } from "react";
import { createRoot } from "react-dom/client";
import api from "@/lib/api";
import FindRelatedDrawer from "../FindRelatedDrawer";

jest.mock("@/lib/api", () => ({ __esModule: true, default: { post: jest.fn() } }), { virtual: true });
jest.mock("@/components/investigation/CorrelationSuggestionCard", () => () => null, { virtual: true });

let root, container;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  api.post.mockReset().mockResolvedValue({ data: { suggestions: [], count: 0 } });
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
});
const render = async (caseId) => {
  await act(async () => root.render(<FindRelatedDrawer caseId={caseId} onClose={() => {}} />));
};

test("loads once per case despite unrelated rerenders", async () => {
  await render("synthetic-A");
  await render("synthetic-A");
  expect(api.post).toHaveBeenCalledTimes(1);
  await render("synthetic-B");
  expect(api.post).toHaveBeenCalledTimes(2);
  expect(api.post).toHaveBeenLastCalledWith("/correlations/find-related", {
    case_id: "synthetic-B", limit: 25, refresh: false,
  });
});
test("explicit refresh still requests a fresh scan", async () => {
  await render("synthetic-A");
  await act(async () => container.querySelector('[data-testid="find-related-refresh"]').click());
  expect(api.post).toHaveBeenLastCalledWith("/correlations/find-related", {
    case_id: "synthetic-A", limit: 25, refresh: true,
  });
});
