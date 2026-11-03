# Forensic Snapshots · the collection gap, traced before touching the sensor

Date 2026-11-03 · traced at `b061f74e` · **no sensor change made, no route added,
no mock surface shipped.**

You asked to trace the existing sensor and backend collection path first and, if
the capability is missing, to name the exact gap before changing the sensor. It
is missing. Here is precisely where it stops.

## 1 · The sensor has no collection action at all

`agents/nivxforge-linux/nivxforge_sensor.py`

- `CAPABILITIES["response_actions"] = ["KILL_PROCESS"]`, plus privilege-gated
  `ISOLATE_ENDPOINT` / `RELEASE_ISOLATION`.
- `_execute_command()` handles exactly those three and returns
  `FAILED · unknown action <X>` for anything else. A snapshot command sent today
  would be refused by the endpoint, correctly.
- There is no process/file/network **inventory on demand**: `collect_processes`,
  `collect_network` and `collect_files` run on the sensor's own poll cycle and
  emit incrementally (first observation only), so they cannot answer "what is on
  this machine right now".
- Nearest existing primitive: `nivxforge_content_acquisition.py` can read and
  digest a file at a path with an acquisition record. It is endpoint-side,
  capability-gated, and invoked only during FILE events — it is not
  server-commandable.

## 2 · The command plane cannot express the request

`backend/edr_plane/response.py`

```python
ACTIONS = ("KILL_PROCESS", "ISOLATE_ENDPOINT", "RELEASE_ISOLATION")
```

`backend/routers/edr_response.py` validates `body.action in resp.ACTIONS`, so a
`TAKE_FORENSIC_SNAPSHOT` cannot be issued, queued or claimed.

## 3 · There is no job or artifact store, and no transport for bytes

- No snapshot job collection, no results collection, no routes.
- The only sensor→platform channel is `POST /api/edr/agent/telemetry`, one JSON
  line per event. There is **no artifact upload path**, so even a successful
  collection has nowhere to put bytes.
- The platform's own registry already grades this honestly:
  `backend.service.forensic_snapshot` → `TELEMETRY_MISSING`, Wave 7;
  `backend.service.file_fetch` → `CONTROL_DRIVER_MISSING`;
  `experience.forensics_ui` → `NOT_IMPLEMENTED` (`/edr/forensics` is a reserved
  page, not a mock).

## 4 · What a real snapshot therefore needs, in order

1. **Sensor**: a `COLLECT_SNAPSHOT` action with a declared manifest (processes,
   listening sockets, watched-directory inventory, users, cron/systemd units),
   each section reporting `OBSERVED` or a named gap — no section may be inferred.
2. **Command plane**: the action added to `ACTIONS`, with authorisation and the
   existing claim → execute → verify lifecycle.
3. **Store**: a job record (requester, target, requested_at, captured_at,
   status) and a results record, both customer-partitioned, so a **completed
   collection with zero results** is distinguishable from **failed** and from
   **timed out**.
4. **Transport**: a bounded artifact channel, or an explicit decision that v1
   returns metadata only.
5. **UI**: Dashboard → Forensic Snapshots (customer-scoped history) and
   Computers → device → Actions → Take forensic snapshot (device preselected).

Steps 1–4 change the sensor and the response plane, which is why this document
stops here rather than shipping a surface that could only have been a mock.

## 5 · What can be built now without the sensor

The two entry points, wired to a real (initially empty) job store, with the
device action declaring the exact missing capability at request time — the same
pattern the sensor already uses for isolation on a host without `CAP_NET_ADMIN`.
That is honest and useful, and it is the recommended next step, but it does not
produce a snapshot.
