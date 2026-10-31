"""D14 · tenant authority — adversarial.

    authenticated delivery tenant -> authoritative tenant -> normalizer

A tenant named in the payload is a claim by whoever sent it. This suite
attacks that boundary at the only place it can still be attacked — the
normalizer contract itself, since D13's shaping already withholds the field
on the ingest path — and holds every applicable DSM to the same answer:

    authenticated = B, payload = A   ->  canonical tenant = B
    tenant A canonical evidence      ->  zero
    the A claim                      ->  UNTRUSTED_SOURCE_CLAIM, used=False
    authenticated missing / blank    ->  REJECT, no canonical event

and, because the tenant is identity material in D10, that an untrusted
claim cannot move a canonical `event_id`.

EVIDENCE LABELLING — TEST/SYNTHETIC. Nothing live, nothing production.
"""
from __future__ import annotations

import inspect

import pytest

from detection_content.xdr_pipeline import DSM_REGISTRY
from services import tenant_authority as ta

AUD = "1757452888.555:9002"
AUTH = "t-owner-b"
CLAIMED = "t-victim-a"

#: every DSM whose normalizer takes a tenant, with a sample the real parser
#: accepts. `snort-eve` is excluded deliberately: its normalizer takes no
#: tenant argument at all (flagged in the D13 report), so there is no
#: contract here to attack.
SAMPLES = {
    "linux-auditd": {
        "message": (f'type=SYSCALL msg=audit({AUD}): arch=c000003e '
                    f'syscall=59 uid=0 euid=0 comm="bash" '
                    f'exe="/usr/bin/bash" key="exec"'),
        "collector_id": "col-d14"},
    "windows-security-evd": {
        "EventID": 4624, "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security", "Computer": "WIN-DC-01",
        "TimeCreated": "2026-06-01T10:00:00+00:00",
        "EventData": {"TargetUserName": "svc_backup", "LogonType": "3",
                      "IpAddress": "10.0.0.9"}},
    "aws-cloudtrail": {
        "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
        "eventTime": "2026-06-01T10:00:00Z", "awsRegion": "us-east-1",
        "eventID": "ct-d14", "sourceIPAddress": "203.0.113.7",
        "userIdentity": {"type": "IAMUser", "userName": "dev1",
                         "accountId": "111122223333"}},
    "microsoft-sysmon": {
        "EventID": 1, "provider": "Microsoft-Windows-Sysmon",
        "Computer": "WIN-WS-07", "User": "CORP\\dev1",
        "UtcTime": "2026-06-01T10:00:00+00:00",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd /c whoami", "ProcessId": "4321"},
    "cef-leef": {
        "line": ("CEF:0|NivX|Firewall|1.0|100|Blocked|5|src=10.0.0.4 "
                 "dst=198.51.100.2 devTime=1780308000000")},
    "nivxforge-linux-sensor": {
        "activity": "PROCESS", "operation": "OBSERVED",
        "collection_method": "proc_scan", "endpoint_id": "dev_d14",
        "hostname": "linux-d14", "pid": 4242,
        "start_time": "2026-06-01T10:00:00+00:00",
        "observed_at": "2026-06-01T10:00:05+00:00",
        "image_path": "/usr/bin/bash"},
}


def _dsms():
    return {d.id: d for d in DSM_REGISTRY._dsms}


def normalize(dsm_id: str, event: dict, *, tenant=AUTH):
    dsm = _dsms()[dsm_id]
    parsed = dsm.select_parser().parse(dict(event))
    return dsm.select_normalizer().normalize(
        parsed, dsm.id, "col-d14", "int-d14", "trace-d14", tenant_id=tenant)


def poison(dsm_id: str, *, tenant_key="tenant_id") -> dict:
    """The same event, with a tenant the payload has no right to name."""
    return dict(SAMPLES[dsm_id], **{tenant_key: CLAIMED})


def claim_of(canonical: dict) -> dict | None:
    return (canonical.get("additional_fields") or {}).get("tenant_claim")


# ── every applicable DSM takes the same answer ───────────────────────
@pytest.mark.parametrize("dsm_id", sorted(SAMPLES))
def test_the_authenticated_tenant_wins_over_a_payload_claim(dsm_id):
    c = normalize(dsm_id, poison(dsm_id))
    assert c["tenant_id"] == AUTH, (dsm_id, c["tenant_id"])
    assert c["tenant_id"] != CLAIMED


@pytest.mark.parametrize("dsm_id", sorted(SAMPLES))
def test_the_claim_survives_only_as_an_untrusted_claim(dsm_id):
    claim = claim_of(normalize(dsm_id, poison(dsm_id)))
    assert claim is not None, f"{dsm_id}: the claim was dropped, not recorded"
    assert claim["state"] == ta.UNTRUSTED_SOURCE_CLAIM
    assert claim["claimed_tenant_id"] == CLAIMED
    assert claim["used"] is False
    assert claim["agrees_with_authenticated"] is False
    assert claim["claim_source"]


@pytest.mark.parametrize("dsm_id", sorted(SAMPLES))
def test_a_clean_event_records_no_claim_at_all(dsm_id):
    assert claim_of(normalize(dsm_id, SAMPLES[dsm_id])) is None


@pytest.mark.parametrize("dsm_id", sorted(SAMPLES))
@pytest.mark.parametrize("bad", [None, "", "   ", "\t\n"])
def test_a_missing_authenticated_tenant_is_refused_not_defaulted(dsm_id, bad):
    with pytest.raises(ValueError, match="NO tenant fallback"):
        normalize(dsm_id, SAMPLES[dsm_id], tenant=bad)


@pytest.mark.parametrize("dsm_id", sorted(SAMPLES))
@pytest.mark.parametrize("bad", [None, "", "  "])
def test_a_payload_claim_cannot_rescue_a_missing_authenticated_tenant(
        dsm_id, bad):
    with pytest.raises(ValueError, match="NO tenant fallback"):
        normalize(dsm_id, poison(dsm_id), tenant=bad)


@pytest.mark.parametrize("dsm_id", sorted(SAMPLES))
def test_no_normalizer_still_carries_a_default_tenant_in_its_signature(dsm_id):
    """The defect class this gate closes: a signature default that lets a
    caller establish tenant authority by saying nothing."""
    sig = inspect.signature(_dsms()[dsm_id].select_normalizer().normalize)
    default = sig.parameters["tenant_id"].default
    assert default in (None, inspect.Parameter.empty), (dsm_id, default)
    assert default != "default"


def test_no_registered_dsm_anywhere_defaults_its_tenant():
    for dsm_id, dsm in _dsms().items():
        sig = inspect.signature(dsm.select_normalizer().normalize)
        p = sig.parameters.get("tenant_id")
        if p is None:
            continue            # snort — no tenant contract at all
        assert p.default in (None, inspect.Parameter.empty), dsm_id


# ── untrusted tenant material must not reach canonical identity (D10) ─
def test_a_payload_claim_cannot_move_the_deterministic_event_id():
    clean = normalize("linux-auditd", SAMPLES["linux-auditd"])
    poisoned = normalize("linux-auditd", poison("linux-auditd"))
    assert poisoned["event_id"] == clean["event_id"]
    assert poisoned["additional_fields"]["event_id_basis"] == \
        clean["additional_fields"]["event_id_basis"]


def test_a_real_change_of_authenticated_tenant_still_changes_identity():
    """The D10 contract: identity is tenant-scoped. A LEGITIMATE tenant
    change must move it — only an untrusted claim must not."""
    b = normalize("linux-auditd", SAMPLES["linux-auditd"], tenant=AUTH)
    c = normalize("linux-auditd", SAMPLES["linux-auditd"], tenant="t-owner-c")
    assert b["event_id"] != c["event_id"]


def test_the_claimed_tenant_never_appears_as_the_owner_anywhere():
    for dsm_id in SAMPLES:
        c = normalize(dsm_id, poison(dsm_id))
        assert c.get("tenant_id") == AUTH, dsm_id
        # the ONLY place the claimed value may appear is inside the claim
        # record and the preserved raw evidence — never as an owner field
        for key, value in c.items():
            if key in ("additional_fields", "raw_ref"):
                continue
            assert CLAIMED not in str(value), (dsm_id, key)


# ── the helper itself ────────────────────────────────────────────────
def test_the_helper_refuses_every_shape_of_absent_tenant():
    for bad in (None, "", "   ", "\n", 0, False):
        with pytest.raises(ta.TenantAuthorityError):
            ta.resolve(bad, ("t-a", "raw.tenant_id"))


def test_nivx_own_assembled_tenant_is_never_labelled_a_claim():
    """A NivX-assembled LINE event carries OUR tenant at the top level and
    the collector payload nested. Echoing ours back as an "untrusted claim"
    would be a dishonest label, so only the payload's value counts."""
    assembled = {"tenant_id": AUTH, "line": "x",
                 "raw": {"line": "x", "tenant_id": CLAIMED}}
    claims = ta.payload_claims(assembled)
    assert [c[0] for c in claims] == [CLAIMED]
    assert "collector envelope" in claims[0][1]

    clean = {"tenant_id": AUTH, "line": "x", "raw": {"line": "x"}}
    assert ta.payload_claims(clean) == ()


def test_a_withheld_document_claim_is_still_reported():
    doc_event = {"EventID": 1, "_nivx": {
        "tenant_id": AUTH,
        "source_fields_withheld": {"tenant_id": CLAIMED}}}
    claims = ta.payload_claims(doc_event)
    assert [c[0] for c in claims] == [CLAIMED]
    assert "withheld at the ingest boundary" in claims[0][1]


def test_the_helper_reports_the_first_claim_in_declared_order():
    tenant, claim = ta.resolve(AUTH, (None, "raw.tenant_id"),
                               ("t-second", "parsed.tenant_id"))
    assert tenant == AUTH
    assert claim["claim_source"] == "parsed.tenant_id"
    assert claim["claimed_tenant_id"] == "t-second"


def test_an_agreeing_claim_is_still_recorded_as_a_claim():
    _, claim = ta.resolve(AUTH, (AUTH, "raw.tenant_id"))
    assert claim["agrees_with_authenticated"] is True
    assert claim["used"] is False


def test_whitespace_is_stripped_from_the_authenticated_tenant_only():
    tenant, claim = ta.resolve(f"  {AUTH}  ", (f"  {CLAIMED}  ", "raw"))
    assert tenant == AUTH
    assert claim["claimed_tenant_id"] == CLAIMED
