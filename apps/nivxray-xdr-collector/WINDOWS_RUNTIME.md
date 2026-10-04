# NivXForge EDR · supported Windows runtime (G1/S5)

The native Windows Event Log adapter acquires through `EvtSubscribe`, so the
interpreter it runs on is part of the product contract, not a local detail.
This file is that contract. It is short on purpose: every line is something
a proof or a production deployment is allowed to rely on.

## Supported interpreter

| | |
| --- | --- |
| **Supported** | CPython **3.14**, standard (GIL) build, **x64**, installed from python.org or an equivalent non-Store distribution. Verified against 3.14.5. |
| **Dependencies** | `requirements-windows.txt` — `pywin32==312` (pinned). Wheel resolved: `pywin32-312-cp314-cp314-win_amd64.whl`. |
| **Also supported** | CPython 3.13 / 3.12 x64 standard builds. `pywin32==312` publishes cp313 / cp312 wheels. |
| **NOT supported** | The **Microsoft Store `python.exe` execution alias**. It is not an interpreter, it ships no `pip`, and the fact that the path exists proves nothing. It must never be selected. |
| **NOT supported** | The **free-threaded** interpreter (`cp314t`). pywin32 publishes no wheel for it and does not intend to; using it would mean building pywin32 from source with Visual Studio, which is not a supported NivXForge runtime. |
| **NOT supported** | 32-bit (`win32`) interpreters on a 64-bit host. |

`py.exe` is a launcher, not a runtime. It is used **once**, to create the
virtual environment; after that every command names
`<venv>\Scripts\python.exe` by absolute path so the alias can never be
picked up by accident.

## Establishing the runtime (no silent fallbacks)

```
py -3.14 -m ensurepip --upgrade
py -3.14 -m venv C:\nivx\.venv
C:\nivx\.venv\Scripts\python.exe -m pip install -r requirements-windows.txt
C:\nivx\.venv\Scripts\python.exe -c "import win32evtlog; print(win32evtlog)"
```

If any step fails, **STOP and report it**. A different interpreter version is
never installed automatically to route around a dependency failure: that
would silently change the runtime the proof is about. Changing the supported
runtime is a decision, and this file is where it is recorded.

## Fail-closed capability gate

`WindowsEventLogConnector.acquisition_capability()` probes the native
binding, and `CollectorRuntime._start_windows_eventlog()` refuses to start
the connector when the host **is** Windows and the binding is unavailable:

| Code | Meaning | Start behaviour |
| --- | --- | --- |
| `NATIVE_BINDING_BOUND` | `win32evtlog` imported and exposes the `Evt*` API | starts |
| `NATIVE_BINDING_UNAVAILABLE` | pywin32 missing, or imported without the Event Log API | **refused** on Windows: `ok: false`, `reason: native_binding_unavailable`, health `ERROR` |
| `PLATFORM_NOT_WINDOWS` | not a Windows host | starts, and every channel reports `UNSUPPORTED_PLATFORM` — never an empty success |
| `BINDING_NOT_PROBED` | a reader was injected (test double / future backend) and makes no claim | starts |

Before this gate a Windows host with no pywin32 reported a CONNECTED
connector that acquired zero events forever. Zero events and no capability
are different facts, and only one of them is a healthy collector.

## Persistent state

`XDR_STATE_DIR` always wins. Unset, the default is platform-resolved by
`framework/state_paths.py`:

| Platform | Default |
| --- | --- |
| Windows | `C:\ProgramData\NivXForge\state` |
| POSIX | `/var/lib/nivxray` |

Windows never falls back to the POSIX path. The outbox and the Windows
channel bookmarks share `${XDR_STATE_DIR}\outbox.db` deliberately — one
fsync domain, so a delivery record and the acquisition position it justifies
cannot disagree after a crash.
