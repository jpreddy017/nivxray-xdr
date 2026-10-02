// Run: node --test frontend/src/v2/investigation/*.node-test.mjs  (no install needed)
import test from "node:test";
import assert from "node:assert/strict";
import { buildActivityView, TI_SCHEMA } from "./activityView.mjs";

const N = (extra) => ({ schema_version: TI_SCHEMA, ioc_type: "IPV4", observable: "203.0.113.50",
  lookup_at: "2026-09-05T09:02:41.000Z", cache_state: "MISS", freshness: "FRESH", provenance: { source_client: "C" }, ...extra });
const ti = (rows) => buildActivityView({ frame_iid: "n", ts: "2026-09-05T09:02:41Z", lane: "network",
  remote_ip: "203.0.113.50", investigation: { ti: rows } }).sections.find((s) => s.key === "threat_intel");

test("normalized TI rows are consumed; degradation is stated, never benign", () => {
  const s = ti([N({ provider: "abuseipdb", state: "UNAVAILABLE", failure_reason: "NOT_CONFIGURED" }),
                N({ provider: "talos", state: "NO_HIT" }),
                N({ provider: "otx", state: "STALE", stale_state: "UNKNOWN", cache_state: "HIT_STALE" })]);
  assert.deepEqual(s.items.map((r) => r.state), ["UNAVAILABLE", "NO_HIT", "STALE"]);
  assert.equal(s.items[0].detail, "NOT_CONFIGURED");
  assert.equal(s.items[2].stale_state, "UNKNOWN");
  assert.ok(s.statements.some((x) => /no reputation conclusion/.test(x)));
  assert.ok(s.items.every((r) => r.state !== "BENIGN"));
});

test("BENIGN needs an affirmative known-good basis under the normalized contract", () => {
  assert.equal(ti([N({ provider: "x", state: "BENIGN" })]).items[0].state, "UNKNOWN");
  assert.equal(ti([N({ provider: "local_ioc", state: "BENIGN",
    provenance: { source_client: "H", basis: "PROVIDER_ASSERTED_KNOWN_GOOD" } })]).items[0].state, "BENIGN");
});
