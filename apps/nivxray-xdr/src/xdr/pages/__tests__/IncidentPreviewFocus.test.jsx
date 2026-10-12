import { describe, expect, it, vi } from "vitest";
import { manageFlyoutFocus } from "../../nx/NxFlyout";
describe("Incident preview keyboard lifecycle", () => {
  it("focuses the dialog, traps Tab in both directions, closes on Escape and restores the invoking control", () => {
    const doc = { activeElement: null, addEventListener: vi.fn(), removeEventListener: vi.fn() };
    const control = () => ({ isConnected: true, focus: vi.fn(function () { doc.activeElement = this; }) });
    const original = control(), first = control(), last = control();
    doc.activeElement = original;
    vi.stubGlobal("document", doc);
    const close = vi.fn();
    const cleanup = manageFlyoutFocus({ querySelectorAll: () => [first, last] }, close);
    expect(first.focus).toHaveBeenCalledOnce();
    const handler = doc.addEventListener.mock.calls[0][1];
    doc.activeElement = last;
    const forward = { key: "Tab", preventDefault: vi.fn() };
    handler(forward); expect(forward.preventDefault).toHaveBeenCalledOnce(); expect(doc.activeElement).toBe(first);
    const backward = { key: "Tab", shiftKey: true, preventDefault: vi.fn() };
    handler(backward); expect(doc.activeElement).toBe(last);
    handler({ key: "Escape", preventDefault: vi.fn() }); expect(close).toHaveBeenCalledOnce();
    cleanup(); expect(original.focus).toHaveBeenCalledOnce(); expect(doc.removeEventListener).toHaveBeenCalledWith("keydown", handler);
    vi.unstubAllGlobals();
  });
});
