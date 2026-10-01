"""G1 · the EvtSubscribe invocation contract (real-Windows defect, ERROR 87).

What happened on the real endpoint: every channel — Sysmon, Security,
PowerShell/Operational — failed identically with
`(87, 'EvtSubscribe', 'The parameter is incorrect.')`, while the whole
`Evt*` API was present and the read-only pre-flight had already proved
those channels exist and are readable. Three identical failures on three
unrelated channels is not three permission problems; it is one wrong call.

Two defects in that one call:

1. `EvtSubscribe` requires EXACTLY ONE delivery mechanism — a signal event
   handle (pull) or a callback (push). We passed neither, which Windows
   answers with ERROR_INVALID_PARAMETER (87) regardless of channel.
2. The bookmark was passed positionally into `Context`. The tail is
   `(Context, Query, Session, Bookmark)`, so resuming would have subscribed
   `StartAfterBookmark` with no bookmark — wrong, and silently so.

These tests pin the CALL SHAPE, which is the thing that broke. They cannot
prove Windows accepts it; that is the endpoint's Stage 9/10 probe.

TEST/SYNTHETIC — `win32evtlog`, `win32event` and `pywintypes` are injected
fakes. No Windows host is involved.
"""
from __future__ import annotations

import sys
import types

import pytest

from framework.windows_eventlog import NativeEvtReader

SYSMON = "Microsoft-Windows-Sysmon/Operational"


class _Err(Exception):
    def __init__(self, winerror, func="EvtNext", msg="x"):
        super().__init__(winerror, func, msg)
        self.winerror = winerror


class _FakeEvtlog(types.ModuleType):
    EvtSubscribeStartAtOldestRecord = 2
    EvtSubscribeStartAfterBookmark = 3
    EvtRenderEventXml = 1
    EvtRenderBookmark = 2

    def __init__(self, *, batches=None, raise_on_next=None):
        super().__init__("win32evtlog")
        self.calls = []
        self.updated = []
        self._batches = list(batches or [])
        self._raise = raise_on_next

    def EvtCreateBookmark(self, xml):
        self.calls.append(("EvtCreateBookmark", xml))
        return f"BOOKMARK_OBJ({xml})"

    def EvtSubscribe(self, channel, flags, *args, **kwargs):
        self.calls.append(("EvtSubscribe", channel, flags, args, kwargs))
        return "SUBSCRIPTION"

    def EvtNext(self, handle, count, timeout, flags):
        self.calls.append(("EvtNext", handle, count, timeout, flags))
        if self._raise is not None:
            raise _Err(self._raise)
        return self._batches.pop(0) if self._batches else []

    def EvtRender(self, obj, kind):
        if kind == self.EvtRenderBookmark:
            return "<BookmarkList/>"
        return f"<Event>{obj}</Event>"

    def EvtUpdateBookmark(self, bookmark, ev):
        self.updated.append((bookmark, ev))


class _FakeEvent(types.ModuleType):
    def __init__(self):
        super().__init__("win32event")
        self.created = 0

    def CreateEvent(self, sa, manual_reset, initial_state, name):
        self.created += 1
        self.args = (sa, manual_reset, initial_state, name)
        return "SIGNAL_HANDLE"


def _install(monkeypatch, evtlog):
    ev = _FakeEvent()
    pwt = types.ModuleType("pywintypes")
    pwt.error = _Err
    monkeypatch.setitem(sys.modules, "win32evtlog", evtlog)
    monkeypatch.setitem(sys.modules, "win32event", ev)
    monkeypatch.setitem(sys.modules, "pywintypes", pwt)
    return ev


def _subscribe_call(evtlog):
    return next(c for c in evtlog.calls if c[0] == "EvtSubscribe")


# ── 1 · the exact ERROR 87 shape can never be issued again ───────────
def test_subscribe_always_supplies_exactly_one_delivery_mechanism(monkeypatch):
    evtlog = _FakeEvtlog(batches=[["e1"]])
    ev = _install(monkeypatch, evtlog)
    NativeEvtReader().read(SYSMON, bookmark_xml=None, xpath=None, limit=1)
    _, _, _, args, kwargs = _subscribe_call(evtlog)
    assert ev.created == 1, "a real signal event handle must be created"
    assert kwargs["SignalEvent"] == "SIGNAL_HANDLE"
    assert kwargs["Callback"] is None
    # THE regression: neither mechanism supplied is ERROR_INVALID_PARAMETER
    # (87) on every channel.
    assert not (kwargs["SignalEvent"] is None and kwargs["Callback"] is None)
    assert args == (), "no positional tail: Context/Query/Session/Bookmark " \
                       "must be named"


def test_signal_event_is_manual_reset_and_initially_unsignalled(monkeypatch):
    evtlog = _FakeEvtlog(batches=[["e1"]])
    ev = _install(monkeypatch, evtlog)
    NativeEvtReader().read(SYSMON, bookmark_xml=None, xpath=None, limit=1)
    sa, manual_reset, initial_state, name = ev.args
    assert sa is None and manual_reset is True
    assert initial_state is False and name is None


# ── 2 · the bookmark goes to Bookmark, never to Context ──────────────
def test_fresh_read_starts_at_oldest_with_no_bookmark(monkeypatch):
    evtlog = _FakeEvtlog(batches=[["e1"]])
    _install(monkeypatch, evtlog)
    NativeEvtReader().read(SYSMON, bookmark_xml=None, xpath=None, limit=1)
    _, channel, flags, _args, kwargs = _subscribe_call(evtlog)
    assert channel == SYSMON
    assert flags == _FakeEvtlog.EvtSubscribeStartAtOldestRecord
    assert kwargs["Bookmark"] is None


def test_resume_passes_the_bookmark_object_as_Bookmark(monkeypatch):
    evtlog = _FakeEvtlog(batches=[["e1"]])
    _install(monkeypatch, evtlog)
    NativeEvtReader().read(SYSMON, bookmark_xml="<BookmarkList/>",
                           xpath=None, limit=1)
    _, _, flags, _args, kwargs = _subscribe_call(evtlog)
    assert flags == _FakeEvtlog.EvtSubscribeStartAfterBookmark
    assert kwargs["Bookmark"] == "BOOKMARK_OBJ(<BookmarkList/>)"
    assert "Context" not in kwargs, "the bookmark must not travel as Context"


def test_start_after_bookmark_never_without_a_bookmark(monkeypatch):
    """StartAfterBookmark + no bookmark is itself ERROR 87."""
    for xml in (None, "<BookmarkList/>"):
        evtlog = _FakeEvtlog(batches=[[]])
        _install(monkeypatch, evtlog)
        NativeEvtReader().read(SYSMON, bookmark_xml=xml, xpath=None, limit=1)
        _, _, flags, _a, kwargs = _subscribe_call(evtlog)
        if flags == _FakeEvtlog.EvtSubscribeStartAfterBookmark:
            assert kwargs["Bookmark"] is not None


# ── 3 · the XPath window is passed as the Query ──────────────────────
def test_xpath_is_passed_as_Query(monkeypatch):
    evtlog = _FakeEvtlog(batches=[["e1"]])
    _install(monkeypatch, evtlog)
    xp = "*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]"
    NativeEvtReader().read(SYSMON, bookmark_xml=None, xpath=xp, limit=1)
    assert _subscribe_call(evtlog)[4]["Query"] == xp


# ── 4 · reads terminate: finite timeout, exhaustion is not an error ──
def test_evtnext_timeout_is_finite(monkeypatch):
    evtlog = _FakeEvtlog(batches=[[]])
    _install(monkeypatch, evtlog)
    NativeEvtReader().read(SYSMON, bookmark_xml=None, xpath=None, limit=5)
    nxt = next(c for c in evtlog.calls if c[0] == "EvtNext")
    assert nxt[3] != -1, "INFINITE would stall the collector on a quiet channel"
    assert 0 < nxt[3] <= 5000


@pytest.mark.parametrize("winerror", [259, 1460])
def test_no_more_items_and_wait_timeout_end_the_read_cleanly(monkeypatch,
                                                             winerror):
    evtlog = _FakeEvtlog(raise_on_next=winerror)
    _install(monkeypatch, evtlog)
    res = NativeEvtReader().read(SYSMON, bookmark_xml=None, xpath=None,
                                 limit=10)
    assert res["state"] == "READ_OK"
    assert res["records"] == []
    assert res["bookmark_xml"] == "<BookmarkList/>"


def test_a_real_evtnext_failure_still_propagates(monkeypatch):
    evtlog = _FakeEvtlog(raise_on_next=87)
    _install(monkeypatch, evtlog)
    with pytest.raises(Exception) as e:
        NativeEvtReader().read(SYSMON, bookmark_xml=None, xpath=None, limit=1)
    assert getattr(e.value, "winerror", None) == 87


def test_records_are_returned_verbatim_and_bookmark_advances(monkeypatch):
    evtlog = _FakeEvtlog(batches=[["e1", "e2"], []])
    _install(monkeypatch, evtlog)
    res = NativeEvtReader().read(SYSMON, bookmark_xml=None, xpath=None,
                                 limit=5)
    assert res["records"] == ["<Event>e1</Event>", "<Event>e2</Event>"]
    assert [e for _b, e in evtlog.updated] == ["e1", "e2"]


# ── 5 · capability now covers the pull mechanism ─────────────────────
def test_binding_status_requires_win32event(monkeypatch):
    evtlog = _FakeEvtlog()
    for n in ("EvtSubscribe", "EvtCreateBookmark", "EvtNext", "EvtRender",
              "EvtUpdateBookmark"):
        assert hasattr(evtlog, n)
    monkeypatch.setitem(sys.modules, "win32evtlog", evtlog)
    monkeypatch.setitem(sys.modules, "win32event",
                        types.ModuleType("win32event"))   # no CreateEvent
    st = NativeEvtReader().binding_status()
    assert st["bound"] is False
    assert "win32event.CreateEvent" in st["reason"]


def test_binding_status_bound_when_both_modules_are_complete(monkeypatch):
    evtlog = _FakeEvtlog()
    _install(monkeypatch, evtlog)
    st = NativeEvtReader().binding_status()
    assert st["bound"] is True
    assert st["code"] == "NATIVE_BINDING_BOUND"
