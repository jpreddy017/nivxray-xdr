"""G1/B1+B2 · the Windows connector must be DEPLOYABLE by the service.

Two defects this locks down, both found while preparing the G1 endpoint proof:

B1  `main.py` (boot rehydrate) and `routes/connectors.py` (create) construct
    every connector as `cls(tenant_id=…, config=…, identity=rec.id)`. The
    REST/webhook/syslog adapters accept that; this one did not, so it raised
    TypeError — swallowed at boot — and the Windows connector silently never
    started.

B2  `collector_id` defaulted to a random `collector-<uuid>`. It anchors BOTH
    the envelope identity the authoritative ingest boundary matches against
    its enrolled collector AND the bookmark scope
    `(tenant, collector_id, channel)`. A value that changes every process
    start means ingest cannot recognise the collector and acquisition can
    never resume. An undeclared identity now fails closed instead.
"""
import pytest

from framework.windows_eventlog import WindowsEventLogConnector

TENANT = "ten_g1_proof"
CONNECTOR_REC_ID = "windows-eventlog::rec0001"
COLLECTOR = "col_g1proof0001"


class _Reader:
    def read(self, channel, *, bookmark_xml, xpath, limit):
        return {"records": [], "bookmark_xml": bookmark_xml,
                "state": "READ_OK", "reason": None}


def _cfg(**kw):
    return {"channels": ["Microsoft-Windows-Sysmon/Operational"], **kw}


def test_service_construction_contract_is_accepted(monkeypatch, tmp_path):
    """Exactly how `main.py:79` and `routes/connectors.py:173` build it."""
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path))
    inst = WindowsEventLogConnector(
        tenant_id=TENANT, config=_cfg(collector_id=COLLECTOR),
        identity=CONNECTOR_REC_ID)
    assert inst.identity == CONNECTOR_REC_ID
    assert inst.checkpoint.connector_id == CONNECTOR_REC_ID
    assert inst.collector_id == COLLECTOR


def test_collector_id_comes_from_connector_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("NIVX_COLLECTOR_ID", "col_env_fallback")
    inst = WindowsEventLogConnector(TENANT, _cfg(collector_id=COLLECTOR),
                                    CONNECTOR_REC_ID, reader=_Reader())
    # configuration is authoritative over the environment fallback
    assert inst.collector_id == COLLECTOR


def test_environment_is_the_explicit_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("NIVX_COLLECTOR_ID", "col_env_fallback")
    inst = WindowsEventLogConnector(TENANT, _cfg(), CONNECTOR_REC_ID,
                                    reader=_Reader())
    assert inst.collector_id == "col_env_fallback"


def test_undeclared_collector_identity_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("NIVX_COLLECTOR_ID", raising=False)
    with pytest.raises(ValueError) as e:
        WindowsEventLogConnector(TENANT, _cfg(), CONNECTOR_REC_ID,
                                 reader=_Reader())
    assert "collector_id" in str(e.value)


def test_no_random_collector_identity_is_ever_generated(tmp_path, monkeypatch):
    """Two processes, same declaration → same identity, so the bookmark
    scope survives a restart."""
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path))
    a = WindowsEventLogConnector(TENANT, _cfg(collector_id=COLLECTOR),
                                 CONNECTOR_REC_ID, reader=_Reader())
    b = WindowsEventLogConnector(TENANT, _cfg(collector_id=COLLECTOR),
                                 CONNECTOR_REC_ID, reader=_Reader())
    assert a.collector_id == b.collector_id == COLLECTOR
    assert "collector-" not in a.collector_id


def test_bookmark_scope_is_stable_across_a_restart(tmp_path, monkeypatch):
    """Write a bookmark in one instance, resume it in a fresh one."""
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path))
    channel = "Microsoft-Windows-Sysmon/Operational"
    first = WindowsEventLogConnector(TENANT, _cfg(collector_id=COLLECTOR),
                                     CONNECTOR_REC_ID, reader=_Reader())
    first.bookmarks.record_read(
        tenant_id=TENANT, collector_id=first.collector_id, channel=channel,
        bookmark_xml="<BookmarkList>restart</BookmarkList>", record_ids=[7],
        profile_id=first.profile.profile_id,
        profile_version=first.profile.version, error=None)
    first.bookmarks.commit_delivered(
        tenant_id=TENANT, collector_id=first.collector_id, channel=channel,
        bookmark_xml="<BookmarkList>restart</BookmarkList>")

    second = WindowsEventLogConnector(TENANT, _cfg(collector_id=COLLECTOR),
                                      CONNECTOR_REC_ID, reader=_Reader())
    resume = second.bookmarks.resume_for(TENANT, second.collector_id, channel)
    assert resume.get("bookmark_xml") == "<BookmarkList>restart</BookmarkList>"
