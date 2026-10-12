import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { useIdlePersist } from "../useIdlePersist";

function Probe({ storageKey = "test.scope-a", snapshot, bulkFields = [] }) {
  useIdlePersist(storageKey, snapshot, { bulkFields });
  return null;
}

let root, container;
beforeEach(() => {
  jest.useFakeTimers();
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear();
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
  jest.useRealTimers();
});
const render = (props) => act(() => root.render(<Probe {...props} />));
const tick = (ms) => act(() => jest.advanceTimersByTime(ms));

test("unrelated inline-object renders preserve the pending debounce", () => {
  render({ snapshot: { input: "one" } });
  tick(600);
  render({ snapshot: { input: "one" } });
  tick(202);
  expect(JSON.parse(localStorage.getItem("test.scope-a"))).toEqual({ input: "one" });
});
test("changed data restarts the debounce and persists only the latest snapshot", () => {
  render({ snapshot: { input: "old" } });
  tick(600);
  render({ snapshot: { input: "new" } });
  tick(202);
  expect(localStorage.getItem("test.scope-a")).toBeNull();
  tick(600);
  expect(JSON.parse(localStorage.getItem("test.scope-a"))).toEqual({ input: "new" });
});
test("changing the storage key cancels the old scope's pending write", () => {
  render({ snapshot: { input: "A" } });
  tick(800); // idle callback is pending
  render({ storageKey: "test.scope-b", snapshot: { input: "B" } });
  tick(802);
  expect(localStorage.getItem("test.scope-a")).toBeNull();
  expect(JSON.parse(localStorage.getItem("test.scope-b"))).toEqual({ input: "B" });
});
test("unmount cancels deferred work", () => {
  render({ snapshot: { input: "secret" } });
  tick(800);
  act(() => root.render(null));
  tick(802);
  expect(localStorage.length).toBe(0);
});
test("StrictMode effect replay still schedules persistence", () => {
  act(() => root.render(<React.StrictMode><Probe snapshot={{ input: "one" }} /></React.StrictMode>));
  tick(802);
  expect(JSON.parse(localStorage.getItem("test.scope-a"))).toEqual({ input: "one" });
});
test("bulk-field changes retain the size guard and do not serialize on render", () => {
  const stringify = jest.spyOn(JSON, "stringify");
  render({ snapshot: { input: "a".repeat(200001) } });
  expect(stringify).not.toHaveBeenCalled();
  render({ snapshot: { input: "a".repeat(200001) }, bulkFields: ["input"] });
  tick(802);
  expect(JSON.parse(localStorage.getItem("test.scope-a"))).toEqual({ input: null, _dropped_for_size: true });
  stringify.mockRestore();
});
