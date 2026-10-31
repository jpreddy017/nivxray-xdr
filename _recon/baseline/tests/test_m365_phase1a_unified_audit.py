"""Microsoft security telemetry · Phase 1a — the evidence plane.

This is a telemetry DOMAIN, not a rule parser. What is tested:

  * the Office 365 Management Activity **common schema** is interpreted for
    all three subscribed content types (Exchange, AzureActiveDirectory,
    General) by ONE DSM;
  * `CreationTime` is the activity basis, and `contentCreated` — blob
    availability — is never allowed to stand in for it (D11/D12);
  * `OrganizationId` is preserved as the PROVIDER's tenant, and the
    authenticated delivery remains the only authority on the NivX tenant
    (D14);
  * Microsoft's own vocabulary survives: `Operation`, `Workload`,
    `RecordType`, `ResultStatus`, `UserType`, `Parameters`. Numeric codes
    resolve to the names Microsoft publishes; an undocumented code is
    reported as the code, never guessed;
  * nothing is fabricated: a record without an actor, IP, status or
    timestamp produces empty fields, not invented ones;
  * DET-PS-004 is declared only because the evidence it cites now exists,
    and ordinary Microsoft administration does not match it.

EVIDENCE LABELLING — TEST/SYNTHETIC records in Microsoft's documented
shape. No Microsoft tenant is contacted here.
"""
from __future__ import annotations

import pytest

from detection_content.library import declaration_contract as dc
from detection_content.library.registry import RUNTIME_DETECTION_RULES
from detection_content.telemetry.m365_unified_audit_dsm import (
    M365UnifiedAuditDSM, M365UnifiedAuditNormalizer, M365UnifiedAuditParser,
    M365UnifiedAuditParserError)
from detection_content.telemetry.registry import TELEMETRY_DSM_REGISTRY
from services import source_routing

TEN = "t-m365-phase1a"
COL = "col-m365"
ORG = "11111111-2222-3333-4444-555555555555"
RULES = {r.rule_id: r for r in RUNTIME_DETECTION_RULES}


def exchange_inbox_rule(params, *, op="New-InboxRule", **over):
    doc = {
        "Id": "ex-1", "RecordType": 1, "CreationTime": "2026-06-02T09:15:00",
        "Operation": op, "OrganizationId": ORG, "UserType": 2,
        "UserKey": "user1@corp.example", "Workload": "Exchange",
        "ResultStatus": "True", "ObjectId": "user1@corp.example",
        "UserId": "user1@corp.example", "ClientIP": "203.0.113.40",
        "ExternalAccess": False, "OrganizationName": "corp.example",
        "OriginatingServer": "EXCH01 (15.20.0000.000)",
        "Parameters": params,
    }
    doc.update(over)
    return doc


def entra_role_add(**over):
    doc = {
        "Id": "aad-1", "RecordType": 8, "CreationTime": "2026-06-02T09:20:00",
        "Operation": "Add member to role.", "OrganizationId": ORG,
        "UserType": 0, "UserKey": "admin@corp.example",
        "Workload": "AzureActiveDirectory", "ResultStatus": "Success",
        "ObjectId": "Directory", "UserId": "admin@corp.example",
        "ActorIpAddress": "198.51.100.22",
        "ApplicationId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "Actor": [{"ID": "admin@corp.example", "Type": 5}],
        "Target": [{"ID": "victim@corp.example", "Type": 5}],
        "ModifiedProperties": [{"Name": "Role.DisplayName",
                                "NewValue": "Global Administrator",
                                "OldValue": ""}],
    }
    doc.update(over)
    return doc


def general_record(**over):
    doc = {
        "Id": "gen-1", "RecordType": 18, "CreationTime": "2026-06-02T09:25:00",
        "Operation": "Set-AntiPhishPolicy", "OrganizationId": ORG,
        "UserType": 3, "UserKey": "secadmin@corp.example",
        "Workload": "SecurityComplianceCenter", "ResultStatus": "True",
        "UserId": "secadmin@corp.example",
        "Parameters": [{"Name": "Identity", "Value": "Default"},
                       {"Name": "Enabled", "Value": "False"}],
    }
    doc.update(over)
    return doc


def canonical(doc, tenant=TEN):
    parsed = M365UnifiedAuditParser().parse(doc)
    return M365UnifiedAuditNormalizer().normalize(
        parsed, "m365-unified-audit", COL, "m365-int", "trace-m365",
        tenant_id=tenant)


# ── the source is declarable and routes to exactly one DSM ────────
def test_declared_source_selects_the_m365_dsm_only():
    assert source_routing.SOURCE_CATALOG["m365-unified-audit"] == \
        "m365-unified-audit"
    for alias in ("m365", "o365", "office365", "microsoft-365",
                  "m365-management-activity",
                  "office365-management-activity"):
        assert source_routing.canonical_source(alias) == "m365-unified-audit"


def test_the_dsm_is_registered_and_loaded():
    dsm = TELEMETRY_DSM_REGISTRY.get("m365-unified-audit")
    assert dsm is not None and dsm.vendor == "Microsoft"
    assert not [f for f in TELEMETRY_DSM_REGISTRY.load_failures()
                if f.get("dsm_id") == "m365-unified-audit"]


def test_routing_is_fail_closed_for_a_non_microsoft_payload():
    decision, dsm = source_routing.route(
        declared="m365-unified-audit",
        authorized=["m365-unified-audit"],
        raw_event={"eventName": "PutUserPolicy",
                   "eventSource": "iam.amazonaws.com"},
        registry=TELEMETRY_DSM_REGISTRY)
    assert dsm is None
    assert decision["mismatch_reason"] == "SOURCE_FORMAT_MISMATCH"


# ── one DSM, three content types ──────────────────────────────────
@pytest.mark.parametrize("doc,workload,record_type", [
    (exchange_inbox_rule([{"Name": "Name", "Value": "r"}]), "Exchange",
     "ExchangeAdmin"),
    (entra_role_add(), "AzureActiveDirectory", "AzureActiveDirectory"),
    (general_record(), "SecurityComplianceCenter",
     "SecurityComplianceCenterEOPCmdlet"),
])
def test_all_three_content_types_produce_evidence(doc, workload, record_type):
    ev = canonical(doc)
    assert ev["source_vendor"] == "Microsoft"
    assert ev["event_type"] == "cloud_audit"
    assert ev["cloud"]["workload"] == workload
    assert ev["cloud"]["record_type"] == record_type
    assert ev["cloud"]["action"] == doc["Operation"]
    assert ev["source_event_id"] == doc["Id"]


def test_the_dsm_supports_only_management_activity_records():
    dsm = M365UnifiedAuditDSM()
    assert dsm.supports(entra_role_add())
    assert not dsm.supports({"eventName": "x", "eventSource": "y"})
    assert not dsm.supports({"EventID": 4688, "channel": "Security"})
    # Operation without a record type is not a Management Activity record
    assert not dsm.supports({"Operation": "New-InboxRule"})


def test_a_record_missing_the_common_schema_is_refused_not_guessed():
    with pytest.raises(M365UnifiedAuditParserError) as e:
        M365UnifiedAuditParser().parse({"Id": "x", "CreationTime": "now"})
    assert e.value.code == "MISSING_M365_AUDIT_MARKERS"
    with pytest.raises(M365UnifiedAuditParserError) as e2:
        M365UnifiedAuditParser().parse({"RecordType": 1,
                                        "Operation": "New-InboxRule"})
    assert e2.value.code == "MISSING_M365_TENANT_BINDING"


# ── D11/D12 · activity time vs blob availability ──────────────────
def test_creation_time_is_the_activity_basis():
    ev = canonical(entra_role_add())
    stamp = ev["provenance"]["timestamps"]["activity_occurred_at"]
    assert stamp["status"] == "AVAILABLE"
    assert stamp["source"] == "m365:CreationTime"
    assert ev["event_time"].startswith("2026-06-02T09:20:00")


def test_blob_availability_never_becomes_activity_time():
    doc = entra_role_add()
    doc["_nivx"] = {"m365_acquisition": {
        "contentId": "c-1", "contentType": "Audit.AzureActiveDirectory",
        "contentCreated": "2026-06-02T11:00:00Z",
        "contentExpiration": "2026-06-09T11:00:00Z"}}
    ev = canonical(doc)
    acq = ev["additional_fields"]["m365_acquisition"]
    assert acq["content_created"] == "2026-06-02T11:00:00Z"
    assert "not when the activity happened" in acq["basis"]
    # the activity instant is still the user's action, not the blob's
    assert ev["event_time"].startswith("2026-06-02T09:20:00")
    assert ev["provenance"]["timestamps"]["activity_occurred_at"]["source"] \
        == "m365:CreationTime"


def test_a_record_without_creation_time_stays_honestly_unobserved():
    doc = entra_role_add()
    doc.pop("CreationTime")
    ev = canonical(doc)
    stamp = ev["provenance"]["timestamps"]["activity_occurred_at"]
    assert stamp["status"] != "AVAILABLE"
    assert "contentCreated is blob availability" in (stamp.get("reason") or "")


def test_the_management_activity_api_has_no_sensor_observation():
    ev = canonical(entra_role_add())
    obs = ev["provenance"]["timestamps"]["sensor_observed_at"]
    assert obs["status"] != "AVAILABLE"


# ── D14 · provider tenant is not the NivX tenant ──────────────────
def test_organization_id_is_the_provider_tenant_not_the_nivx_tenant():
    ev = canonical(entra_role_add())
    assert ev["tenant_id"] == TEN
    assert ev["cloud"]["provider_tenant_id"] == ORG
    assert ev["additional_fields"]["provider_tenant_id"] == ORG
    assert "NOT the NivX tenant" in \
        ev["additional_fields"]["provider_tenant_id_basis"]


def test_a_payload_named_tenant_is_recorded_and_never_believed():
    doc = entra_role_add()
    doc["_nivx"] = {"source_fields_withheld": {"tenant_id": "attacker-tenant"}}
    ev = canonical(doc)
    assert ev["tenant_id"] == TEN
    assert "attacker-tenant" in str(ev["additional_fields"]["tenant_claim"])


# ── provider vocabulary survives ──────────────────────────────────
def test_microsoft_enum_codes_resolve_to_microsoft_names():
    assert canonical(entra_role_add())["cloud"]["record_type"] == \
        "AzureActiveDirectory"
    assert canonical(entra_role_add(UserType=6))["cloud"]["principal_type"] \
        == "ServicePrincipal"


def test_an_undocumented_code_is_reported_not_guessed():
    ev = canonical(entra_role_add(RecordType=9999, UserType=77))
    assert ev["cloud"]["record_type"] == "RecordType:9999"
    assert ev["cloud"]["principal_type"] == "UserType:77"
    assert ev["additional_fields"]["record_type_code"] == 9999


def test_exchange_parameters_are_flattened_and_kept_verbatim():
    params = [{"Name": "Name", "Value": "ext-archive"},
              {"Name": "ForwardTo", "Value": "attacker@evil.example"}]
    ev = canonical(exchange_inbox_rule(params))
    assert ev["cloud"]["request_parameters"]["ForwardTo"] == \
        "attacker@evil.example"
    assert ev["additional_fields"]["parameters_verbatim"] == params


def test_result_status_is_preserved_and_absence_is_not_success():
    assert canonical(general_record())["cloud"]["result_status"] == "True"
    doc = general_record()
    doc.pop("ResultStatus")
    assert canonical(doc)["cloud"]["result_status"] == ""


def test_admin_and_non_human_principals_come_from_microsofts_user_type():
    assert canonical(exchange_inbox_rule([]))["identity"]["is_privileged"]
    sp = canonical(entra_role_add(UserType=6))
    assert sp["identity"]["is_privileged"] is False
    assert sp["identity"]["service_principal_id"] == sp["cloud"][
        "application_id"]


# ── correlation identifiers preserved, never invented (STEP 4) ────
def test_correlation_identifiers_are_preserved_where_recorded():
    ev = canonical(exchange_inbox_rule(
        [{"Name": "Name", "Value": "r"}], SessionId="sess-9",
        MailboxOwnerUPN="victim@corp.example",
        ClientInfoString="Client=OWA;Action=ViaProxy"))
    assert ev["identity"]["username"] == "user1@corp.example"
    assert ev["network"]["src_ip"] == "203.0.113.40"
    assert ev["cloud"]["session_id"] == "sess-9"
    assert "victim@corp.example" in ev["cloud"]["resource_ids"]
    assert ev["cloud"]["user_agent"].startswith("Client=OWA")


def test_missing_identifiers_stay_empty_rather_than_being_invented():
    doc = general_record()          # no ClientIP, no SessionId, no ObjectId
    ev = canonical(doc)
    assert ev["network"]["src_ip"] == ""
    assert ev["cloud"]["session_id"] == ""
    assert ev["cloud"]["resource_ids"] == []
    assert ev["cloud"]["application_id"] == ""


def test_the_dsm_declares_what_it_cannot_evidence():
    cap = M365UnifiedAuditDSM().capability
    joined = " ".join(cap["does_not_provide"]).lower()
    assert "device id" in joined
    assert "dlp" in joined
    assert any("contentcreated" in c.lower() for c in cap["caveats"])


# ── detection SECOND, on evidence that exists ─────────────────────
def test_det_ps_004_is_declared_and_off_the_debt_ledger():
    rule = RULES["DET-PS-004"]
    assert rule.conditions, "DET-PS-004 must declare the fields it evaluates"
    assert "DET-PS-004" not in dc.DECLARATION_DEBT
    assert "DET-PS-004" not in dc.TELEMETRY_GAPS
    assert not dc.validate_rule(rule)
    assert {c.canonical_field for c in rule.conditions} == {
        "cloud.action", "cloud.request_parameters"}


def test_det_ps_004_fires_on_real_m365_evidence_and_cites_it():
    ev = canonical(exchange_inbox_rule(
        [{"Name": "Name", "Value": "ext-archive"},
         {"Name": "ForwardTo", "Value": "attacker@evil.example"}]))
    rule = RULES["DET-PS-004"]
    assert rule.evaluate(ev) is True
    citation = rule.cite(ev, evidence_ref=ev["event_id"])
    fields = {c["canonical_field"]
              for c in citation.get("matched_conditions") or []}
    assert fields == {"cloud.action", "cloud.request_parameters"}


@pytest.mark.parametrize("params,op", [
    ([{"Name": "Name", "Value": "triage"},
      {"Name": "MoveToFolder", "Value": "Archive"}], "New-InboxRule"),
    ([{"Name": "Identity", "Value": "user1@corp.example"}], "Set-Mailbox"),
    ([], "Get-InboxRule"),
])
def test_ordinary_microsoft_administration_does_not_match(params, op):
    ev = canonical(exchange_inbox_rule(params, op=op))
    assert RULES["DET-PS-004"].evaluate(ev) is False


def test_entra_and_general_records_do_not_match_an_exchange_rule():
    assert RULES["DET-PS-004"].evaluate(canonical(entra_role_add())) is False
    assert RULES["DET-PS-004"].evaluate(canonical(general_record())) is False


def test_the_predicate_coverage_limit_is_recorded_not_silently_fixed():
    # The rule advertises EXTERNAL forwarding; the predicate cannot yet tell
    # internal from external. That is a standing finding, and the evidence
    # needed to close it is preserved on the event.
    assert "DET-PS-004" in dc.PREDICATE_COVERAGE_FINDINGS
    ev = canonical(exchange_inbox_rule(
        [{"Name": "ForwardTo", "Value": "colleague@corp.example"}]))
    assert RULES["DET-PS-004"].evaluate(ev) is True     # honest: it matches
    assert ev["additional_fields"]["external_access"] is False
    assert ev["cloud"]["request_parameters"]["ForwardTo"] == \
        "colleague@corp.example"


def test_declaration_coverage_grew_without_new_contract_problems():
    report = dc.report(list(RUNTIME_DETECTION_RULES))
    assert report["contract_problems"] == []
    assert report["declared_but_unexplained"] == []
    declared, total = report["declaration_coverage"].split("/")
    assert int(declared) == 28 and int(total) == 37
