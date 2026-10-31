"""Apply the deep-link completeness change to the BRANCH copy of TrajectoryPage.jsx.

The /app workspace copy of this file is OLDER than the branch head: the branch already carries
later frontend work (older-page abort handling, cursor-advance guard, OUTSIDE_PAGE state).
Committing the workspace copy would silently revert that work, so the committed blob is built
from the branch copy plus exactly this repair.
"""
import sys

SRC = "/app/_preservation/upstream/TrajectoryPage.parent.jsx"
OUT = "/app/_preservation/upstream/TrajectoryPage.commit.jsx"

EDITS = [
    # 1 · shared, testable mapping
    ('import { hasTechnique } from "./attack";\n',
     'import { hasTechnique } from "./attack";\n'
     'import { deepLinkFromError, deepLinkFromFocus, LOOKUP_AMBIGUOUS, LOOKUP_INCOMPLETE,\n'
     '         selectedFor } from "./deeplink";\n'),

    # 2 · selection is an exact identity match or nothing
    ('  const sel = wanted ? model.items.find((it) => it.ev.event_iid === wanted) || null : null;\n',
     '  const sel = selectedFor(model.items, wanted);\n'),

    # 3 · the four outcomes stay distinct; an unfinished search is never "not found"
    ('''    api.get(`${url}/focus`, { params: { event_iid: wanted }, signal: ac.signal }).then(({ data: f }) => {
      if (!active) return;
      if (f.state !== "FOCUS_RESOLVED") {
        const incomplete = /UNAVAILABLE|INCOMPLETE/.test(f.state || "");
        setDeep({ state: incomplete ? "UNAVAILABLE" : "NOT_FOUND", id: wanted, scope: url,
          note: incomplete ? "The observation could not be located because the evidence read failed or the search was incomplete. This does not establish that it is absent." : f.missing_link || f.reason }); return;
      }
      if (!f.focus?.window || !Number.isFinite(Date.parse(f.focus.window.time_start)) || !Number.isFinite(Date.parse(f.focus.window.time_end))) throw new Error("Focus window unavailable");
      setDeep({ state: "OUTSIDE_PAGE", id: wanted, scope: url });
      upd({ t0: Date.parse(f.focus.window.time_start), t1: Date.parse(f.focus.window.time_end) }, true);
    }).catch(() => { if (active) setDeep({ state: "UNAVAILABLE", id: wanted, scope: url, note: "The observation lookup failed. Retry to locate it; absence has not been established." }); });
''',
     '''    api.get(`${url}/focus`, { params: { event_iid: wanted }, signal: ac.signal }).then(({ data: f }) => {
      if (!active) return;
      // An UNFINISHED lookup keeps its own state: it is never rendered as "not found", and no
      // row is selected in its place. An AMBIGUOUS identifier is offered, never narrowed here.
      const d = deepLinkFromFocus(f, { id: wanted, scope: url, attempt: focusRetry });
      setDeep(d);
      if (d.state === "OUTSIDE_PAGE") upd({ t0: d.window.t0, t1: d.window.t1 }, true);
    }).catch(() => { if (active) setDeep(deepLinkFromError(wanted, { scope: url, attempt: focusRetry })); });
'''),

    # 4 · the detection pivot must not report an unfinished lookup as an unresolvable event
    ('''      try { const { data: f } = await api.get(`${url}/focus`, { params: { observation_id: d.observation_id } }); id = f?.focus?.event_iid; ms = ms || Date.parse(f?.focus?.observed_at || ""); }
''',
     '''      try { const { data: f } = await api.get(`${url}/focus`, { params: { observation_id: d.observation_id } });
        if (f?.state === LOOKUP_INCOMPLETE || f?.state === LOOKUP_AMBIGUOUS) {
          setLoading(false);
          setDeep(deepLinkFromFocus(f, { id: d.observation_id, scope: url, attempt: focusRetry }));
          return;
        }
        id = f?.focus?.event_iid; ms = ms || Date.parse(f?.focus?.observed_at || ""); }
'''),

    # 5 · "Lookup incomplete" and "Identifier is ambiguous" are their own, actionable states
    ('''        {deep && !["FOCUSED"].includes(deep.state) && <div data-testid="v3-deeplink-state" style={{ fontSize: 13, color: deep.state === "NOT_FOUND" ? C.amber : C.muted, marginBottom: 8 }}>
          {["NOT_FOUND", "UNAVAILABLE"].includes(deep.state) ? (deep.note || `Observation ${deep.id} was not found in retained evidence for this device.`)
            : deep.state === "OUTSIDE_PAGE" ? "Observation located in retained evidence. Its time range is selected; load older events if it is outside the loaded page." : `Locating observation ${deep.id} in history…`}
          {deep.state === "UNAVAILABLE" && <button className="v3-link" data-testid="v3-focus-retry" onClick={() => { setDeep(null); setFocusRetry((v) => v + 1); }}>Retry observation lookup</button>}
          {deep.state === "OUTSIDE_PAGE" && older.cursor && <button className="v3-link" disabled={loading} onClick={loadOlder}>Load older events</button>}</div>}
''',
     '''        {deep && !["FOCUSED"].includes(deep.state) && (
          ["INCOMPLETE", "AMBIGUOUS"].includes(deep.state) ? (
            <div role="status" data-testid="v3-deeplink-state" data-deeplink-state={deep.state}
              style={{ fontSize: 13, color: C.text, marginBottom: 8, padding: "8px 12px", border: `1px solid ${C.amber}`, borderRadius: 8 }}>
              <strong data-testid="v3-deeplink-headline">{deep.state === "AMBIGUOUS" ? "Identifier is ambiguous" : "Lookup incomplete"}</strong>
              <div data-testid="v3-deeplink-note" style={{ color: C.muted, marginTop: 4 }}>
                {deep.state === "AMBIGUOUS"
                  ? (deep.note || `Observation ${deep.id} was exported by an older build and names more than one observation. Choose the intended one — nothing is selected automatically.`)
                  : (deep.note || `The search for observation ${deep.id} did not finish, so it is neither found nor shown to be absent. Nothing is selected in its place.`)}
                {deep.searched ? ` (${deep.searched} observations compared)` : ""}
              </div>
              {deep.state === "AMBIGUOUS" && deep.candidates?.length > 0 && (
                <ul data-testid="v3-deeplink-candidates" style={{ margin: "8px 0 0", paddingLeft: 18 }}>
                  {deep.candidates.map((c) => (
                    <li key={c.event_id}>
                      <button className="v3-link" data-testid={`v3-deeplink-candidate-${c.event_id}`} style={{ fontSize: 13 }}
                        onClick={() => { setDeep(null); upd({ event: c.event_iid || c.event_id }); }}>{c.event_id}</button>
                    </li>
                  ))}
                </ul>
              )}
              <div style={{ marginTop: 8, display: "flex", gap: 12 }}>
                {deep.retryable !== false && <button className="v3-btn" data-testid="v3-deeplink-retry" onClick={() => { setDeep(null); setFocusRetry((v) => v + 1); }}>Retry lookup</button>}
                <button className="v3-btn" data-testid="v3-deeplink-narrow" onClick={() => { setDeep(null); upd({ event: null }); say("Deep link cleared. Narrow the time range, then open the link again to search a smaller span."); }}>Narrow the search</button>
              </div>
            </div>
          ) : (
            <div data-testid="v3-deeplink-state" data-deeplink-state={deep.state} style={{ fontSize: 13, color: deep.state === "NOT_FOUND" ? C.amber : C.muted, marginBottom: 8 }}>
              {deep.state === "NOT_FOUND" ? (deep.note || `Observation ${deep.id} was not found in retained evidence for this device.`)
                : deep.state === "OUTSIDE_PAGE" ? "Observation located in retained evidence. Its time range is selected; load older events if it is outside the loaded page." : `Locating observation ${deep.id} in history…`}
              {deep.state === "OUTSIDE_PAGE" && older.cursor && <button className="v3-link" disabled={loading} onClick={loadOlder}>Load older events</button>}</div>
          ))}
'''),
]

src = open(SRC, encoding="utf-8").read()
for i, (old, new) in enumerate(EDITS, 1):
    if src.count(old) != 1:
        print(f"edit {i}: anchor matched {src.count(old)} times — refusing")
        sys.exit(2)
    src = src.replace(old, new)
open(OUT, "w", encoding="utf-8").write(src)
print(f"wrote {OUT} ({len(src.splitlines())} lines)")
