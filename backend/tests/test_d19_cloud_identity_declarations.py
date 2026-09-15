"""D19 · declaration batch 2 — cloud & identity lanes, on evidence that
actually exists.

The D17 contract gate was meant to find undeclared rules. Pointed at the
cloud/identity lane it found something worse: these rules were not merely
undeclared, they read fields NivX has never produced —

    cloud.policy              (nowhere in the evidence model)
    preauth_type              (in the 4768 record, not in the model)
    principal_kind            (nowhere)
    network.destination_ip    (a spelling that exists nowhere; the field is
                               network.dest_ip)

On real telemetry they could not fire at all. Declaring them as written
would have produced citations pointing at nothing, which is exactly the
failure D8 was built to prevent.

So D19 fixed the evidence first — the smallest genuine prerequisites:

    AuthEntity.preauth_type          <- Windows 4768 PreAuthType
    CloudContext.principal_type      <- CloudTrail userIdentity.type
    CloudContext.request_parameters  <- CloudTrail requestParameters

then pointed the predicates at the canonical fields (keeping every raw-shape
key, so nothing that worked before stops working), and only then declared.

Two rules stay on the ledger because NivX has NO source for them at all:
DET-PS-004 (M365/Graph audit) and DET-PE-002 (AD CS 4886/4887).

EVIDENCE LABELLING — TEST/SYNTHETIC throughout.
"""
from __future__ import annotations

import pytest

from detection_content.library import REGISTRY
from detection_content.library import declaration_contract as dc
from detection_content.library.models import apply_operator
from detection_content.library.registry import RUNTIME_DETECTION_RULES
from detection_content.library.rules_enterprise import _D19_BATCH_2
from detection_content.telemetry.aws_cloudtrail_dsm import (
    AWSCloudTrailNormalizer, AWSCloudTrailParser)
from detection_content.telemetry.windows_security_dsm import (
    WindowsSecurityNormalizer, WindowsSecurityParser)

TEN = "t-d19"
COL = "col-d19"
BATCH = sorted(_D19_BATCH_2)
RULES = {r.rule_id: r for r in RUNTIME_DETECTION_RULES}


def cloudtrail(**over):
    doc = {"eventName": "PutUserPolicy", "eventSource": "iam.amazonaws.com",
           "eventTime": "2026-06-01T10:00:00Z", "awsRegion": "us-east-1",
           "eventID": "ct-d19-1", "sourceIPAddress": "203.0.113.7",
           "userIdentity": {"type": "IAMUser", "userName": "dev1",
                            "accountId": "111122223333",
                            "arn": "arn:aws:iam::111122223333:user/dev1"},
           "requestParameters": {
               "userName": "dev1",
               "policyDocument": '{"Statement":[{"Effect":"Allow",'
                                 '"Action":"*","Resource":"*"}]}'}}
    doc.update(over)
    parsed = AWSCloudTrailParser().parse(doc)
    return AWSCloudTrailNormalizer().normalize(
        parsed, "aws-cloudtrail", COL, "int-d19", "trace-d19",
        tenant_id=TEN)


def windows(eid, **data):
    parsed = WindowsSecurityParser().parse({
        "EventID": eid,
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security", "Computer": "WIN-DC-19",
        "TimeCreated": "2026-06-01T10:00:00+00:00",
        "EventData": data})
    return WindowsSecurityNormalizer().normalize(
        parsed, "windows-security-evd", COL, "int-d19", "trace-d19",
        tenant_id=TEN)


def fire(out, event_id):
    return {m["rule_id"]: m for m in
            REGISTRY.evaluate_event({**out, "event_id": event_id})}


# ══ 1 · the evidence prerequisites are real, and sourced ══════════
def test_the_new_fields_exist_in_the_canonical_model():
    for path in ("authentication.preauth_type", "cloud.principal_type",
                 "cloud.request_parameters"):
        assert path in dc.CANONICAL_FIELDS, path


def test_windows_4768_now_publishes_the_preauth_type_it_always_carried():
    out = windows(4768, TargetUserName="svc_sql", TargetDomainName="CORP",
                  ServiceName="krbtgt", Status="0x0", PreAuthType="0")
    assert out["authentication"]["preauth_type"] == "0"
    # and it is never defaulted when the record does not carry it
    silent = windows(4768, TargetUserName="svc_sql", Status="0x0")
    assert silent["authentication"]["preauth_type"] == ""


def test_cloudtrail_now_publishes_principal_type_and_request_parameters():
    out = cloudtrail()
    assert out["cloud"]["principal_type"] == "IAMUser"
    assert out["cloud"]["request_parameters"]["userName"] == "dev1"
    # verbatim — the provider's own vocabulary is not translated
    assert cloudtrail(userIdentity={"type": "AWSService",
                                    "accountId": "1"})["cloud"][
        "principal_type"] == "AWSService"


def test_absent_request_parameters_are_an_empty_document_not_invented():
    out = cloudtrail(requestParameters=None)
    assert out["cloud"]["request_parameters"] == {}
    assert "DET-PE-003" not in fire(out, "d19-empty-params")


def test_the_serialized_operator_searches_the_document_as_text():
    assert apply_operator("serialized_contains_any_ci",
                          {"policyDocument": '{"Action":"*"}'}, ['"*"'])
    assert not apply_operator("serialized_contains_any_ci",
                              {"policyDocument": '{"Action":"s3:Get"}'},
                              ['"*"'])
    for empty in (None, "", {}, []):
        assert apply_operator("serialized_contains_any_ci", empty,
                              ["x"]) is False


# ══ 2 · the five rules now fire on CANONICAL evidence ═════════════
def test_a_wildcard_iam_policy_write_is_detected_and_cited():
    matches = fire(cloudtrail(), "d19-iam")
    assert "DET-PE-003" in matches, sorted(matches)
    citation = matches["DET-PE-003"]["citation"]
    assert citation["citation_completeness"] == "CITED"
    assert {c["canonical_field"] for c in citation["matched_conditions"]} == \
        {"cloud.action", "cloud.request_parameters"}


def test_a_least_privilege_policy_write_is_not_detected():
    benign = cloudtrail(requestParameters={
        "userName": "dev1",
        "policyDocument": '{"Statement":[{"Effect":"Allow",'
                          '"Action":"s3:GetObject"}]}'})
    assert "DET-PE-003" not in fire(benign, "d19-iam-benign")


def test_kerberoasting_is_detected_from_canonical_authentication_evidence():
    out = windows(4769, TargetUserName="svc_sql",
                  ServiceName="MSSQLSvc/sql.corp", TicketOptions="0x40810000",
                  TicketEncryptionType="0x17", Status="0x0",
                  IpAddress="10.0.0.9")
    assert out["source_event_id"] == "4769"
    assert out["authentication"]["ticket_encryption"] == "0x17"
    matches = fire(out, "d19-kerberoast")
    assert "DET-CR-004" in matches, sorted(matches)
    fields = {c["canonical_field"]
              for c in matches["DET-CR-004"]["citation"]["matched_conditions"]}
    assert fields == {"source_event_id", "authentication.ticket_encryption",
                      "authentication.service_name"}


def test_an_aes_ticket_and_a_machine_spn_are_not_kerberoasting():
    aes = windows(4769, ServiceName="MSSQLSvc/sql.corp",
                  TicketEncryptionType="0x12", Status="0x0")
    machine = windows(4769, ServiceName="DC01$",
                      TicketEncryptionType="0x17", Status="0x0")
    assert "DET-CR-004" not in fire(aes, "d19-aes")
    assert "DET-CR-004" not in fire(machine, "d19-machine")


def test_asrep_roasting_is_detected_from_the_preauth_type():
    out = windows(4768, TargetUserName="svc_legacy", ServiceName="krbtgt",
                  Status="0x0", PreAuthType="0")
    matches = fire(out, "d19-asrep")
    assert "DET-CR-005" in matches, sorted(matches)
    fields = {c["canonical_field"]
              for c in matches["DET-CR-005"]["citation"]["matched_conditions"]}
    assert fields == {"source_event_id", "authentication.preauth_type"}


def test_normal_preauthentication_is_not_asrep_roasting():
    out = windows(4768, TargetUserName="user1", Status="0x0",
                  PreAuthType="2")
    assert "DET-CR-005" not in fire(out, "d19-preauth-ok")


def test_imds_credential_theft_reads_the_canonical_destination_field():
    out = {"event_type": "network_connect",
           "network": {"dest_ip": "169.254.169.254"},
           "process": {"command_line":
                       "curl http://169.254.169.254/latest/meta-data/iam/"
                       "security-credentials/role1"},
           "command_line": "curl http://169.254.169.254/latest/meta-data/"
                           "iam/security-credentials/role1"}
    matches = fire(out, "d19-imds")
    assert "DET-CR-006" in matches, sorted(matches)
    fields = {c["canonical_field"]
              for c in matches["DET-CR-006"]["citation"]["matched_conditions"]}
    assert fields == {"network.dest_ip", "process.command_line"}


def test_a_non_human_principal_creating_credentials_is_detected():
    out = cloudtrail(eventName="CreateAccessKey",
                     userIdentity={"type": "AWSService",
                                   "accountId": "111122223333"},
                     requestParameters={"userName": "svc-deploy"})
    matches = fire(out, "d19-nhi")
    assert "DET-EM-001" in matches, sorted(matches)
    fields = {c["canonical_field"]
              for c in matches["DET-EM-001"]["citation"]["matched_conditions"]}
    assert fields == {"cloud.principal_type", "cloud.action"}


def test_a_non_human_principal_reading_a_secret_is_not_key_abuse():
    out = cloudtrail(eventName="GetSecretValue",
                     userIdentity={"type": "AWSService",
                                   "accountId": "111122223333"},
                     requestParameters={})
    assert "DET-EM-001" not in fire(out, "d19-nhi-benign")


# ══ 3 · the declarations themselves ═══════════════════════════════
@pytest.mark.parametrize("rule_id", BATCH)
def test_each_batch_rule_is_declared_and_explains_its_fixtures(rule_id):
    rule = RULES[rule_id]
    assert rule.conditions
    assert rule.rule_version == "2"
    proof = dc.citation_proof(rule)
    assert proof["positive_fixtures"] >= 1, proof
    assert proof["cited_fixtures"] >= 1, proof


@pytest.mark.parametrize("rule_id", BATCH)
def test_every_declared_field_is_a_real_canonical_path(rule_id):
    for c in RULES[rule_id].conditions:
        assert c.canonical_field in dc.CANONICAL_FIELDS, c.canonical_field
        assert c.note


@pytest.mark.parametrize("rule_id", BATCH)
def test_declaring_did_not_change_any_fixture_verdict(rule_id):
    rule = RULES[rule_id]
    for fixture in rule.fixtures:
        assert rule.evaluate(fixture.event) is fixture.should_match, \
            (rule_id, fixture.name)


def test_the_original_raw_shape_fixtures_still_pass():
    # the pre-D19 hand-shaped fixtures are KEPT, so the older ingest shapes
    # a collector might still send keep working
    for rule_id in BATCH:
        names = [f.name for f in RULES[rule_id].fixtures]
        assert "positive" in names and "negative" in names, (rule_id, names)


def test_coverage_moved_and_the_ledger_only_shrank():
    report = dc.report(RUNTIME_DETECTION_RULES)
    assert len(report["declared"]) == 27
    assert set(report["undeclared"]) == set(dc.DECLARATION_DEBT)
    assert report["contract_problems"] == []
    assert report["declared_but_unexplained"] == []
    for rule_id in BATCH:
        assert rule_id not in dc.DECLARATION_DEBT


# ══ 4 · what D19 refused to declare, and why ══════════════════════
@pytest.mark.parametrize("rule_id,source", [
    ("DET-PS-004", "M365 / Graph audit telemetry"),
    ("DET-PE-002", "AD CS 4886/4887 telemetry"),
])
def test_a_rule_with_no_source_at_all_stays_on_the_ledger(rule_id, source):
    assert rule_id in dc.DECLARATION_DEBT
    assert RULES[rule_id].conditions == []
    gap = " ".join(dc.TELEMETRY_GAPS[rule_id])
    assert "no DSM" in gap
    citation = RULES[rule_id].cite({})
    assert citation["declaration_state"] == "NOT_DECLARED"
    assert citation["evaluated_conditions"] == []


def test_the_closed_gaps_record_how_each_one_was_closed():
    for rule_id in BATCH:
        assert rule_id in dc.CLOSED_TELEMETRY_GAPS, rule_id
        assert dc.CLOSED_TELEMETRY_GAPS[rule_id]


def test_no_fabricated_support_was_added_for_the_two_blocked_rules():
    # nothing invented a certificate or inbox-rule field to make them pass
    for field in ("certificate.template", "certificate.san",
                  "cloud.rule_name", "cloud.policy", "principal_kind",
                  "network.destination_ip"):
        assert field not in dc.CANONICAL_FIELDS, field
