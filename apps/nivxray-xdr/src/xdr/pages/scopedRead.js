import { securitySnapshot, subscribeSecurity } from "@/lib/securityState";

// Fence component state as well as transport: a canceled transport may still resolve.
export function startScopedRead(read, publish) {
  const controller = new AbortController();
  const epoch = securitySnapshot().epoch;
  let active = true;
  const current = () => active && !controller.signal.aborted && securitySnapshot().epoch === epoch;
  const stop = () => { active = false; controller.abort(); };
  const unsubscribe = subscribeSecurity(stop);
  const done = (async () => {
    try {
      const data = await read(controller.signal);
      if (current()) publish({ data, error: null, loading: false });
    } catch (error) {
      if (current()) publish({ data: null, error, loading: false });
    }
  })();
  return { done, cancel: () => { stop(); unsubscribe(); } };
}
