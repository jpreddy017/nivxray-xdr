# NivXRay · Analyst Observation Form
_Structured qualitative feedback form for M2.75 Analyst Dogfooding. Use one form per analyst per session. Do not coach the analyst; observe and record._

---

## Session Meta

| Field                          | Value |
|--------------------------------|-------|
| Session ID                     |       |
| Date                           |       |
| Duration                       |       |
| Analyst pseudonym              |       |
| Years of DFIR experience       |       |
| Familiar with Cisco Secure Endpoint? | Y / N |
| Familiar with any XDR? (Splunk / QRadar / Sentinel / etc.) | list |
| Case used                      | e.g. `case_dfir_bumblebee_akira_2026` |
| NivXRay build hash             |       |

---

## Task Walkthrough

For each task: **let the analyst find their own path.** Do not intervene unless they explicitly ask for help. Log every observation verbatim; do not paraphrase confusion into "user found it slightly hard".

### Task 1 · Find the parent process of the first malicious execution

- **Path taken (verbatim clicks / keys / scrolls):**
- **Time to completion (or DNF):**
- **Confusion moments (quote if possible):**
- **Did they say the answer with confidence?** (Y / N / hesitant)

### Task 2 · Locate the first malicious execution timestamp

- **Path taken:**
- **Time to completion:**
- **Confusion moments:**
- **Confidence:**

### Task 3 · Trace all spawned child processes

- **Path taken:**
- **Time to completion:**
- **Confusion moments:**
- **Confidence:**
- **Missed any children? which:**

### Task 4 · Follow every registry-key modification in the incident window

- **Path taken:**
- **Time to completion:**
- **Confusion moments:**
- **Confidence:**

### Task 5 · Inspect all outbound network connections from suspicious binaries

- **Path taken:**
- **Time to completion:**
- **Confusion moments:**
- **Confidence:**

### Task 6 · Review detections and MITRE attribution

- **Path taken:**
- **Time to completion:**
- **Confusion moments:**
- **Confidence:**

---

## Structured Heuristic Questions

Ask after all six tasks. Answers on a 1–5 Likert scale (1 = strongly disagree, 5 = strongly agree), plus a one-sentence why.

| # | Question | Score (1–5) | Why |
|---|---|:---:|-----|
| Q1 | I could find the initial execution quickly. | | |
| Q2 | I could trace process ancestry naturally without hunting for hidden UI. | | |
| Q3 | The currently selected entity was obvious at all times. | | |
| Q4 | I could distinguish historical events from the currently-relevant context. | | |
| Q5 | I never lost my place in the timeline while panning or zooming. | | |
| Q6 | Panning and zooming behaved the way I expected from other pro tools. | | |
| Q7 | The right panel exposed the information I expected without hunting. | | |
| Q8 | Selecting an event made the surrounding evidence chain (parent, siblings, related network / registry activity) obvious. | | |
| Q9 | I could recover to a "known good" view after a mistake (Escape, Fit, undo). | | |
| Q10 | The investigation flow was obvious without any training. | | |

Aggregate score = median of the 10 questions. **Gate: aggregate ≥ 4.0 across ≥ 60% of analysts** for the milestone to close.

---

## Free-Form Feedback

### What worked well (verbatim quotes if possible)

- 

### What did not work (verbatim)

- 

### If you could change ONE thing right now, what would it be?

- 

### Would you rather use NivXRay or the tool you currently use for this task? Why?

- 

---

## Observer-only fields (do NOT ask the analyst)

- **Number of unrequested help queries** (`"where do I click?"`, `"is this the right thing?"`):
- **Number of times they backed out and restarted:**
- **Number of visible frustration signals** (sighs, throw-hand-up, verbal exasperation):
- **Any workflow steps they SKIPPED entirely** (e.g. never opened the minimap, never used the day scrubber):
- **Time-to-first-click** on canvas after loading:
- **Scroll direction confusion?** (Y / N):
- **Any browser back-button attempts?** (a sign they don't know how to escape a selection):

---

## Post-Session Summary (fill within 30 min of session)

**Three friction items to escalate to the M3 backlog:**

1. 
2. 
3. 

**One thing that pleasantly surprised the analyst:**

- 

**Would this analyst adopt NivXRay if it were their tool tomorrow?** (Y / Maybe / N)

- Reason:

---

## Aggregation Rule (across sessions)

Any friction item observed by **≥ 2 analysts** is automatically promoted to the top of the M3 backlog before general perf work begins. This is the gate defined in `CANVAS_ENGINE_ARCHITECTURE.md` §20 · M2.75.
