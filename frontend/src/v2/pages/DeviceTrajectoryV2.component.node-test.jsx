// DT component tests (react-dom/server). Built by the ignored harness (/app/.e3ui-harness/webpack.test.config.js)
// because the clone has no installed node_modules; run with node's built-in test runner.
import test from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { AttackChainSidebar, EvidencePane, StatusBar, TimeRangeBox } from "./DeviceTrajectoryV2";
import { trajectoryVerdict, ABSENCE } from "../investigation/activityView.mjs";
import CAUSAL from "../../../../backend/tests/edr_investigation/fixtures/dt_causal_frames.json";

const SEP = { start: Date.parse("2026-09-05T09:00:00Z"), end: Date.parse("2026-09-05T09:03:20Z") };
const MATCH = { rule_id: "E3-SEQ-1", rule_version: 1, outcome: "MATCH", mitre: ["T1059.001"],
  contributing_frame_ids: ["tf_p"], evidence_refs: ["cev_p"] };
const HIST = [
  { version: 1, at: "2026-09-05T09:01:40Z", trigger: "INITIAL", assessment: "UNKNOWN" },
  { version: 2, at: "2026-09-05T11:41:00Z", trigger: "INTEL_CHANGE", assessment: "MALICIOUS", supersedes: 1 }];
const LONG = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdaterSynWithAVeryLongValueName";
const frame = (extra) => ({ frame_iid: "tf_p", ts: "2026-09-05T09:00:40Z", lane: "process", action: "process_create",
  label: "powershell.exe spawned by WINWORD.EXE", entity: { iid: "proc_P" }, parent: { iid: "proc_W" },
  canonical_evidence_id: "cev_p", mitre: ["T1059.001"], ...extra });
const ev = (f) => ({ id: f.frame_iid, ts: Date.parse(f.ts), kind: "execute", verdict: trajectoryVerdict(f),
  label: f.label, mitre: f.mitre || [], meta: f, source: true });
const pane = (f, frames = []) => renderToStaticMarkup(
  <EvidencePane event={ev(f)} tab="evidence" onTab={() => {}} frames={frames} />);
const box = (props) => renderToStaticMarkup(
  <TimeRangeBox stages={[]} caseBounds={SEP} setViewport={() => {}} {...props} />);

test("navigator dates derive from case context (September fixture)", () => {
  const html = box({ eventTs: [SEP.start, SEP.end] });
  assert.match(html, /data-state="AVAILABLE"/);
  assert.match(html, /data-iso="2026-09-05"/);
  assert.match(html, /data-testid="case-span-label">Sep 5</);
  assert.match(html, />09:00:00</);
  assert.match(html, /<polyline/);
});

test("Jun/Jul dates cannot appear for September fixtures", () => {
  const html = box({});
  assert.doesNotMatch(html, /Jun|Jul/);
  assert.doesNotMatch(html, />24:00</);
});

test("unknown time context is shown truthfully, with no fallback dates", () => {
  const html = box({ boundsKnown: false });
  assert.match(html, /data-testid="date-strip-unknown"/);
  assert.match(html, /Time range UNKNOWN/);
  assert.doesNotMatch(html, /day-chip-|<polyline/);
});

test("a MATCH does not become MALICIOUS (pane, chain, status bar)", () => {
  const f = frame({ investigation: { behavior: [MATCH] } });
  const html = pane(f);
  assert.match(html, /data-testid="evidence-verdict-badge"[^>]*>DETECTED</);
  assert.doesNotMatch(html, /ASSESSED MALICIOUS/);
  const stages = [{ tactic: "EXECUTION", techniques: ["T1059.001"], frames: [f], detected: true, malicious: false }];
  const chain = renderToStaticMarkup(<AttackChainSidebar stages={stages} selectedIdx={null} onSelect={() => {}} />);
  assert.match(chain, /1 stages · 1 detected · 0 assessed malicious/);
  assert.match(chain, /data-assessed-malicious="false"/);
  const bar = renderToStaticMarkup(<StatusBar rows={[]} events={[]} selectedStageIdx={null}
    detectedCount={1} compromiseCount={0} />);
  assert.match(bar, /1 detected · 0 assessed malicious/);
});

test("a real MALICIOUS assessment still renders MALICIOUS", () => {
  const f = frame({ lane: "file", mitre: [], investigation: { history: HIST } });
  assert.match(pane(f), /data-testid="evidence-verdict-badge"[^>]*>ASSESSED MALICIOUS</);
  const stages = [{ tactic: "OTHER", techniques: [], frames: [f], detected: false, malicious: true }];
  const chain = renderToStaticMarkup(<AttackChainSidebar stages={stages} selectedIdx={null} onSelect={() => {}} />);
  assert.match(chain, /0 detected · 1 assessed malicious/);
});

test("truncated labels expose their full value", () => {
  const f = frame({ lane: "registry", label: LONG });
  const stages = [{ tactic: "OTHER", techniques: [], frames: [f], detected: false, malicious: false }];
  const chain = renderToStaticMarkup(<AttackChainSidebar stages={stages} selectedIdx={null} onSelect={() => {}} />);
  assert.ok(chain.includes(`title="${LONG.replace(/\\/g, "\\")}"`));
  assert.match(chain, /class="[^"]*truncate[^"]*"/);
  assert.ok(pane(f).includes(`data-testid="evidence-title"`) && pane(f).includes(`title="${LONG}"`));
});

test("regression: absence statement, NOT_WIRED actions and Activity Details sync", () => {
  const html = pane(frame({}));
  assert.ok(html.includes(ABSENCE));
  assert.match(html, /data-testid="action-block-sha-not-wired"/);
  assert.match(html, /data-testid="action-allowlist-not-wired"/);
  assert.match(html, /data-testid="activity-details-sections"/);
  assert.match(html, /data-testid="ad-section-causal_context"/);
});

test("causal context panel renders all groups; correlated/unknown stay distinct", () => {
  const frames = CAUSAL.map((f) => ({ ...f, investigation: { synthetic: true } }));
  const html = pane(frames.find((f) => f.frame_iid === "c_u"), frames);
  for (const g of ["observed", "preceded_by", "caused_by", "produced", "correlated", "unknown", "evidence"])
    assert.match(html, new RegExp(`data-testid="causal-group-${g}"`));
  assert.match(html, /data-state="PROVEN_CAUSAL"/);
  assert.match(html, /data-state="UNKNOWN"/);
  assert.match(html, /PID equality never establishes identity/);
  assert.match(html, /No evidence-supported cause recorded; none is inferred\./);
});
