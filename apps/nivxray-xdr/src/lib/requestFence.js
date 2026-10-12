/** Latest selection wins; leaving its context invalidates pending selections. */
export function createRequestFence() {
  let generation = 0;
  return {
    begin: () => ++generation,
    current: (ticket) => ticket === generation,
    cancel: () => { ++generation; },
  };
}
