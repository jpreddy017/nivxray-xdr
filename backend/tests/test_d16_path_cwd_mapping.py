"""D16 · auditd PATH / CWD -> canonical file & directory evidence.

auditd has always delivered this and NivX has always thrown it away:

    type=CWD  msg=audit(…): cwd="/home/deploy"
    type=PATH msg=audit(…): item=0 name="/usr/bin/bash"      nametype=NORMAL
    type=PATH msg=audit(…): item=1 name="scripts/payload.sh" nametype=CREATE
    type=PATH msg=audit(…): item=2 name="scripts"            nametype=PARENT

Before D16 the canonical `file` entity was empty for every auditd event, so
no rule could cite a file path the source had actually observed.

Three refusals are held here, because they are what make the mapping
trustworthy:

  * a path is NEVER invented — a relative name with no observed CWD stays
    unresolved and says why;
  * PATH records are NEVER collapsed — each `item` is its own entry, in item
    order, with the record that produced it;
  * auditd does not say whether a NORMAL path is a file or a directory, so
    the object kind stays NOT_OBSERVED; only `nametype=PARENT` is a
    directory.

EVIDENCE LABELLING — TEST/SYNTHETIC throughout. Nothing live, nothing
production.
"""
from __future__ import annotations

import pytest

from detection_content.telemetry.auditd_stitcher import plan_stitch
from detection_content.telemetry.linux_auditd_dsm import (
    LinuxAuditdDSM, LinuxAuditdNormalizer, LinuxAuditdParser)

TEN = "t-d16"
COL = "col-d16"
AUD = "1757452888.111:5101"

SYSCALL = (f'node=web-prod-04 type=SYSCALL msg=audit({AUD}): arch=c000003e '
           f'syscall=59 success=yes exit=0 uid=0 euid=0 auid=1000 pid=4242 '
           f'ppid=4200 comm="bash" exe="/usr/bin/bash" key="exec"')
EXECVE = (f'type=EXECVE msg=audit({AUD}): argc=3 a0="/bin/bash" a1="-c" '
          f'a2="cat /etc/shadow"')
CWD = f'type=CWD msg=audit({AUD}): cwd="/home/deploy"'
PATH0 = (f'type=PATH msg=audit({AUD}): item=0 name="/usr/bin/bash" '
         f'inode=1234 dev=fd:01 mode=0100755 ouid=0 ogid=0 nametype=NORMAL')
PATH1 = (f'type=PATH msg=audit({AUD}): item=1 name="scripts/payload.sh" '
         f'inode=999 mode=0100644 ouid=1000 ogid=1000 nametype=CREATE')
PATH2 = f'type=PATH msg=audit({AUD}): item=2 name="scripts" nametype=PARENT'
PATH_NULL = (f'type=PATH msg=audit({AUD}): item=3 name="(null)" '
             f'nametype=UNKNOWN')


def normalize(lines, tenant=TEN):
    """Stitch the way the real ingest path stitches, then normalize."""
    plan = plan_stitch(lines, [tenant] * len(lines), [COL] * len(lines))
    primary = next(i for i, role in plan["roles"].items()
                   if role == "PRIMARY")
    st = plan["stitched"][primary]
    raw = {**st, "line": st["_primary_line"], "message": st["_primary_line"],
           "tenant_id": tenant}
    parsed = LinuxAuditdParser().parse(raw)
    return LinuxAuditdNormalizer().normalize(
        parsed, "linux-auditd", COL, "int-d16", "trace-d16",
        tenant_id=tenant)


def mapping(out):
    return out["additional_fields"]["path_mapping"]


FULL = [SYSCALL, EXECVE, CWD, PATH0, PATH1, PATH2]


# ══ 1 · the working directory ═════════════════════════════════════
def test_the_cwd_record_becomes_the_working_directory():
    wd = mapping(normalize(FULL))["working_directory"]
    assert wd["path"] == "/home/deploy"
    assert wd["state"] == "OBSERVED"
    assert wd["source"] == "auditd:CWD cwd="
    assert wd["source_record"] == "CWD"


def test_a_missing_cwd_is_not_observed_and_is_never_slash():
    wd = mapping(normalize([SYSCALL, EXECVE, PATH0]))["working_directory"]
    assert wd["path"] is None
    assert wd["state"] == "NOT_OBSERVED"
    assert "unknown, not '/'" in wd["reason"]


def test_the_working_directory_is_also_published_beside_the_mapping():
    out = normalize(FULL)
    assert out["additional_fields"]["working_directory"]["path"] \
        == "/home/deploy"


# ══ 2 · every PATH record survives as its own item ════════════════
def test_every_path_record_is_kept_as_its_own_item_in_item_order():
    m = mapping(normalize(FULL))
    assert m["path_records_observed"] == 3
    assert [e["item"] for e in m["path_items"]] == [0, 1, 2]
    assert [e["path"] for e in m["path_items"]] == [
        "/usr/bin/bash", "scripts/payload.sh", "scripts"]


def test_later_path_records_are_read_from_their_own_verbatim_record():
    # The stitcher merges only the FIRST record of each type, so item 1 and
    # item 2 exist only because they are re-read from their own lines.
    m = mapping(normalize(FULL))
    for entry, expected in zip(m["path_items"], (PATH0, PATH1, PATH2)):
        assert entry["record_ref"]["record_type"] == "PATH"
        assert entry["record_ref"]["line"] == expected
        assert entry["record_ref"]["audit_id"] == AUD


def test_several_paths_are_never_merged_into_one():
    m = mapping(normalize(FULL))
    paths = [e["absolute_path"] for e in m["path_items"]]
    assert len(set(paths)) == 3
    assert "never merged" in m["collapse_note"]


def test_path_attributes_are_carried_verbatim():
    item0 = mapping(normalize(FULL))["path_items"][0]
    assert item0["inode"] == "1234"
    assert item0["dev"] == "fd:01"
    assert item0["mode"] == "0100755"
    assert item0["ouid"] == "0"


# ══ 3 · no path is ever invented ══════════════════════════════════
def test_an_absolute_name_is_taken_verbatim():
    item0 = mapping(normalize(FULL))["path_items"][0]
    assert item0["absolute_path"] == "/usr/bin/bash"
    assert item0["absolute_path_basis"] == "VERBATIM_ABSOLUTE"
    assert item0["absolute_path_state"] == "OBSERVED"


def test_a_relative_name_with_an_observed_cwd_is_derived_and_says_so():
    item1 = mapping(normalize(FULL))["path_items"][1]
    assert item1["absolute_path"] == "/home/deploy/scripts/payload.sh"
    assert item1["absolute_path_basis"] == "DERIVED_FROM_OBSERVED_CWD"
    assert item1["absolute_path_state"] == "DERIVED"
    assert item1["absolute_path_resolved_from"] == {
        "cwd": "/home/deploy", "relative_name": "scripts/payload.sh"}


def test_a_relative_name_without_a_cwd_stays_unresolved():
    item = mapping(normalize([SYSCALL, EXECVE, PATH1]))["path_items"][0]
    assert item["path"] == "scripts/payload.sh"
    assert item["absolute_path"] is None
    assert item["absolute_path_state"] == "NOT_RESOLVABLE"
    assert "NOT guessed" in item["absolute_path_not_resolvable_reason"]


def test_an_unusable_path_name_is_reported_not_substituted():
    m = mapping(normalize([SYSCALL, EXECVE, CWD, PATH_NULL]))
    assert m["unusable_path_records"] == 1
    entry = m["path_items"][0]
    assert entry["path"] is None
    assert entry["path_state"] == "NOT_OBSERVED"
    assert "never substituted" in entry["path_not_observed_reason"]
    # and it never becomes the canonical file
    assert m["primary_file_basis"] is None


# ══ 4 · the canonical file entity ═════════════════════════════════
def test_the_primary_file_is_the_lowest_non_parent_item():
    out = normalize(FULL)
    assert out["file"]["path"] == "/usr/bin/bash"
    assert out["file"]["name"] == "bash"
    m = mapping(out)
    assert m["primary_file_basis"] == "LOWEST_PATH_ITEM_EXCLUDING_PARENT"
    assert m["file_path_item"] == 0
    assert m["file_path_state"] == "OBSERVED"
    assert m["file_path_record_ref"]["line"] == PATH0


def test_a_parent_path_is_a_directory_and_never_the_canonical_file():
    out = normalize([SYSCALL, EXECVE, CWD, PATH2])
    m = mapping(out)
    assert m["directory_paths"] == ["/home/deploy/scripts"]
    assert out["file"]["path"] == ""
    assert "never delivered a usable non-parent path" in \
        m["primary_file_reason"] or "no PATH record" in \
        m["primary_file_reason"]


def test_an_event_with_no_path_record_keeps_an_empty_file_entity():
    out = normalize([SYSCALL, EXECVE])
    assert out["file"]["path"] == ""
    m = mapping(out)
    assert m["path_records_observed"] == 0
    assert m["primary_file_reason"] == \
        "this audit event delivered no PATH record"


def test_the_action_is_mapped_only_when_auditd_states_it():
    items = mapping(normalize(FULL))["path_items"]
    normal, created, parent = items
    assert normal["action"] is None
    assert normal["action_state"] == "NOT_OBSERVED"
    assert created["action"] == "create"
    assert created["action_basis"] == "auditd:PATH nametype=CREATE"
    assert parent["action"] is None


def test_the_object_kind_is_only_claimed_for_a_parent_directory():
    items = mapping(normalize(FULL))["path_items"]
    assert items[0]["kind"] == "PATH_OBJECT"
    assert items[0]["kind_state"] == "OBJECT_KIND_NOT_OBSERVED"
    assert items[2]["kind"] == "DIRECTORY"
    assert items[2]["kind_state"] == "OBSERVED"


def test_a_delete_nametype_maps_to_the_delete_action():
    line = (f'type=PATH msg=audit({AUD}): item=0 name="/tmp/evidence.log" '
            f'nametype=DELETE')
    out = normalize([SYSCALL, line])
    assert out["file"]["action"] == "delete"
    assert out["file"]["path"] == "/tmp/evidence.log"


# ══ 5 · detection rules can now cite it ═══════════════════════════
def test_a_rule_reading_file_path_sees_the_observed_path():
    out = normalize(FULL)
    # the same nested read a library rule performs
    assert out.get("file", {}).get("path") == "/usr/bin/bash"


# ══ 6 · standalone CWD / PATH records are auditd, not garbage ═════
@pytest.mark.parametrize("line", [CWD, PATH0])
def test_the_dsm_claims_standalone_cwd_and_path_records(line):
    assert LinuxAuditdDSM().supports({"message": line, "line": line})


def test_a_standalone_path_record_is_labelled_as_a_fragment():
    parsed = LinuxAuditdParser().parse({"message": PATH0, "line": PATH0,
                                        "tenant_id": TEN})
    out = LinuxAuditdNormalizer().normalize(
        parsed, "linux-auditd", COL, "int-d16", "trace-d16", tenant_id=TEN)
    assert out["event_type"] == "auditd_path_record"
    extra = out["additional_fields"]
    assert extra["fragment_state"] == "STANDALONE_RECORD_NO_PROCESS_CONTEXT"
    assert extra["identity_state"] == "NOT_OBSERVED"
    assert out["file"]["path"] == "/usr/bin/bash"
    assert extra["path_mapping"]["path_records_observed"] == 1


def test_a_standalone_cwd_record_carries_the_working_directory():
    parsed = LinuxAuditdParser().parse({"message": CWD, "line": CWD,
                                        "tenant_id": TEN})
    out = LinuxAuditdNormalizer().normalize(
        parsed, "linux-auditd", COL, "int-d16", "trace-d16", tenant_id=TEN)
    assert out["event_type"] == "auditd_cwd_record"
    wd = out["additional_fields"]["working_directory"]
    assert wd["path"] == "/home/deploy" and wd["state"] == "OBSERVED"


def test_a_standalone_record_keeps_its_own_deterministic_identity():
    def _one(line):
        parsed = LinuxAuditdParser().parse({"message": line, "line": line,
                                            "tenant_id": TEN})
        return LinuxAuditdNormalizer().normalize(
            parsed, "linux-auditd", COL, "int-d16", "trace-d16",
            tenant_id=TEN)["event_id"]

    # same record twice -> ONE identity; different record types of the same
    # audit event -> different identities (D10 preserved)
    assert _one(PATH0) == _one(PATH0)
    assert _one(PATH0) != _one(CWD)
    assert _one(PATH0) != _one(SYSCALL)


# ══ 7 · nothing else regressed ════════════════════════════════════
def test_the_stitched_execution_evidence_is_unchanged():
    out = normalize(FULL)
    assert out["event_type"] == "process_execution"
    assert out["process"]["command_line"] == "/bin/bash -c cat /etc/shadow"
    assert out["process"]["pid"] == 4242
    assert out["identity"]["is_privileged"] is True
    assert out["host"]["hostname"] == "web-prod-04"
    extra = out["additional_fields"]
    assert extra["stitched"] is True
    assert extra["stitch_record_types"] == ["CWD", "EXECVE", "PATH",
                                            "SYSCALL"]
    assert extra["stitch_completeness"] == "COMPLETE"


def test_the_path_mapping_never_reaches_canonical_identity():
    # The same execution with and without PATH/CWD records is still ONE
    # canonical event: paths are evidence, not identity material.
    assert normalize(FULL)["event_id"] == \
        normalize([SYSCALL, EXECVE])["event_id"]


def test_tenant_authority_still_owns_the_evidence():
    out = normalize(FULL, tenant="t-d16-owner")
    assert out["tenant_id"] == "t-d16-owner"
