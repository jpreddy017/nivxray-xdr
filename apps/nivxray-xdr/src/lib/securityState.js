/** Presentation invalidation only; the backend remains the authority. */
let snapshot = { epoch: 0, reason: null, deniedPath: null };
const listeners = new Set();
const pending = new Set();
export const securitySnapshot = () => snapshot;
export const subscribeSecurity = (fn) => { listeners.add(fn); return () => listeners.delete(fn); };
export function invalidateSecurity(reason = "scope", deniedPath = null) {
  snapshot = { epoch: snapshot.epoch + 1, reason, deniedPath };
  for (const cancel of [...pending]) cancel();
  for (const listener of [...listeners]) listener();
}
export function trackRequest(cancel) {
  pending.add(cancel);
  return () => pending.delete(cancel);
}
export function installSecurityEvents(target = globalThis.window) {
  if (!target) return () => {};
  const scope = () => invalidateSecurity("scope");
  const session = () => invalidateSecurity("session");
  const storage = (e) => {
    if (e.key === "nvx_tenant") scope();
    if (e.key === "nvx_token" || e.key === "nvx_email" || e.key === null) session();
  };
  target.addEventListener("nvx-tenant-bound", scope);
  target.addEventListener("nvx-session-changed", session);
  target.addEventListener("storage", storage);
  return () => {
    target.removeEventListener("nvx-tenant-bound", scope);
    target.removeEventListener("nvx-session-changed", session);
    target.removeEventListener("storage", storage);
  };
}
export function sessionChanged() {
  // Login/logout can happen in this window; storage fires only in other tabs.
  globalThis.window?.dispatchEvent(new Event("nvx-session-changed"));
}
