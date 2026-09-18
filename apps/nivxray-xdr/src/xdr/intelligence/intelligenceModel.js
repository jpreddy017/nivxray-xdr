/**
 * Intelligence policy MODEL — the shared authority for every surface.
 *
 * One truth, three presentations (dashboard status · incident context ·
 * administration editor). Nothing here renders; nothing here invents.
 *
 * The four facts stay distinct internally, exactly as the backend keeps
 * them, and are translated into analyst language only at the edge:
 *
 *   POLICY        what an administrator has permitted   (online_ai/online_llm)
 *   PROVISIONING  whether a runtime actually exists     (health.*.health)
 *   AVAILABILITY  whether it can answer right now
 *   EFFECTIVE     what applies at this scope after inheritance
 */

export const MODES = [
  {
    id: "standard",
    label: "Standard",
    hint: "Online AI and the cloud LLM are both permitted.",
    values: { online_ai: "on", online_llm: "on" },
  },
  {
    id: "online_ai_only",
    label: "Online AI",
    hint: "Online AI permitted · cloud LLM disabled.",
    values: { online_ai: "on", online_llm: "off" },
  },
  {
    id: "offline_only",
    label: "Offline only",
    hint: "No data leaves this scope.",
    values: { online_ai: "off", online_llm: "off" },
  },
];

export const MODE_BY_ID = Object.fromEntries(MODES.map((m) => [m.id, m]));

/** The effective mode for a resolved `{online_ai, online_llm}` pair. */
export function modeOf(values) {
  if (!values) return null;
  if (values.online_ai === "off") return MODE_BY_ID.offline_only;
  if (values.online_llm === "off") return MODE_BY_ID.online_ai_only;
  return MODE_BY_ID.standard;
}

/** Runtime status in analyst language — never a raw provisioning enum. */
export function statusRows({ values, health }) {
  const grade = (h) => {
    if (!h) return { text: "Not reported", tone: "faint" };
    if (h === "ready") return { text: "Ready", tone: "ok" };
    return { text: "Not provisioned", tone: "warn" };
  };
  const onlineAi = values?.online_ai === "on";
  const onlineLlm = values?.online_llm === "on";
  return [
    {
      key: "online-ai",
      label: "Online AI",
      text: onlineAi ? "Permitted" : "Off",
      tone: onlineAi ? "ok" : "off",
    },
    {
      key: "online-llm",
      label: "Cloud LLM",
      text: !onlineAi ? "Off" : (onlineLlm ? "Permitted" : "Off"),
      tone: onlineAi && onlineLlm ? "ok" : "off",
      note: !onlineAi ? "requires Online AI" : undefined,
    },
    {
      key: "offline-intelligence",
      label: "Offline intelligence",
      ...grade(health?.offline_ai?.health),
    },
    {
      key: "narration",
      label: "NivXRay narration",
      text: "Available",
      tone: "ok",
      note: "guaranteed baseline",
    },
  ];
}

/** Compact one-line summary used by the dashboard and incident surfaces. */
export function summarize({ values, health }) {
  const mode = modeOf(values);
  const offline = health?.offline_ai?.health === "ready";
  return {
    mode,
    modeLabel: mode ? mode.label : "Not resolved",
    narration: "Available",
    offlineReady: offline,
    offlineLabel: offline ? "Ready" : "Not provisioned",
  };
}
