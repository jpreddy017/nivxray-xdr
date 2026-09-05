"""
NivXRay XDR — AWS CloudTrail DSM, Parser & Normalizer.
Provides native support for AWS CloudTrail audit logs:
- Management and Data events (IAM, STS, EC2, S3, KMS)
- User identity resolution (IAMUser, AssumedRole, Root, ServicePrincipal)
- Request parameters, affected resources, source IP, and User-Agent extraction.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    CanonicalTelemetryEvent,
    CloudContext,
    HostEntity,
    IdentityEntity,
    NetworkEntity,
    ProvenanceEnvelope,
)


class AWSCloudTrailParserError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


class AWSCloudTrailParser:
    id = "aws-cloudtrail-parser"

    def parse(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(ev, dict):
            raise AWSCloudTrailParserError("INVALID_EVENT", "Event is not a JSON/dict object")

        # Unwrap if event has a "detail" wrapper (e.g. EventBridge CloudTrail format)
        data = ev.get("detail") if isinstance(ev.get("detail"), dict) else ev

        event_name = data.get("eventName")
        event_source = data.get("eventSource")
        if not event_name and not event_source:
            raise AWSCloudTrailParserError("MISSING_CLOUDTRAIL_MARKERS", "Event lacks eventName or eventSource")

        return {
            "parser_id": self.id,
            "raw": ev,
            "data": data,
        }


class AWSCloudTrailNormalizer:
    id = "aws-cloudtrail-normalizer"

    def normalize(
        self,
        parsed: Dict[str, Any],
        dsm_id: str,
        collector_id: str,
        integration_id: str,
        trace_id: str,
        tenant_id: Optional[str] = "default",
    ) -> Dict[str, Any]:
        raw = parsed["raw"]
        if tenant_id is None or (isinstance(tenant_id, str) and not tenant_id.strip()):
            raise ValueError("tenant_id is required: NO tenant fallback permitted")
        resolved_tenant = (raw if isinstance(raw, dict) else {}).get("tenant_id") or parsed.get("tenant_id") or tenant_id
        if not resolved_tenant or not str(resolved_tenant).strip():
            raise ValueError("tenant_id is required: NO tenant fallback permitted")
        resolved_tenant = str(resolved_tenant).strip()

        data = parsed["data"]
        now_iso = datetime.now(timezone.utc).isoformat()

        event_name = str(data.get("eventName") or "")
        event_source = str(data.get("eventSource") or "")
        aws_region = str(data.get("awsRegion") or "")
        event_time = str(data.get("eventTime") or now_iso)
        event_id = str(data.get("eventID") or uuid.uuid4())

        # Extract UserIdentity
        user_identity = data.get("userIdentity") or {}
        ident_type = str(user_identity.get("type") or "")
        user_arn = str(user_identity.get("arn") or "")
        user_name = str(user_identity.get("userName") or user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName") or "")
        account_id = str(user_identity.get("accountId") or data.get("recipientAccountId") or "")
        principal_id = str(user_identity.get("principalId") or user_arn or user_name)

        is_priv = (
            ident_type == "Root"
            or "admin" in user_name.lower()
            or "admin" in user_arn.lower()
        )

        identity = IdentityEntity(
            principal_id=principal_id or user_name or "",
            username=user_name,
            domain=account_id,
            is_privileged=is_priv,
            service_principal_id=user_arn if ident_type == "ServicePrincipal" else "",
        )

        # Extract Network context
        src_ip = str(data.get("sourceIPAddress") or "")
        network = NetworkEntity()
        if src_ip and not src_ip.endswith(".amazonaws.com"):
            network = NetworkEntity(
                src_ip=src_ip,
                direction="inbound",
            )

        # Extract Resources
        resources = data.get("resources") or []
        resource_ids: List[str] = []
        for r in resources:
            if isinstance(r, dict):
                r_arn = r.get("ARN") or r.get("accountId") or r.get("resourceName")
                if r_arn:
                    resource_ids.append(str(r_arn))

        cloud = CloudContext(
            provider="aws",
            account_id=account_id,
            region=aws_region,
            service=event_source.replace(".amazonaws.com", ""),
            action=event_name,
            principal_arn=user_arn,
            resource_ids=resource_ids,
            user_agent=str(data.get("userAgent") or ""),
        )

        host = HostEntity(
            hostname=f"aws-account-{account_id}" if account_id else "aws-cloud",
            host_id=account_id,
            os_family="cloud",
        )

        provenance = ProvenanceEnvelope(
            trace_id=trace_id,
            collector_id=collector_id,
            integration_id=integration_id,
            dsm_id=dsm_id,
            parser_id=AWSCloudTrailParser.id,
            normalizer_id=self.id,
            ingest_time=now_iso,
        )

        canonical = CanonicalTelemetryEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=resolved_tenant,
            source_vendor="AWS",
            source_product="CloudTrail",
            source_event_id=event_id,
            event_type="cloud_audit",
            event_time=event_time,
            ingest_time=now_iso,
            host=host,
            identity=identity,
            network=network,
            cloud=cloud,
            raw_ref=raw,
            provenance=provenance,
            additional_fields={
                "event_source": event_source,
                "event_name": event_name,
                "request_parameters": data.get("requestParameters") or {},
                "response_elements": data.get("responseElements") or {},
            },
        )
        return canonical.to_dict()


class AWSCloudTrailDSM:
    id = "aws-cloudtrail"
    vendor = "AWS"
    product = "AWS CloudTrail"
    version = "1"
    source_type = "CLOUD_AUDIT"

    def supports(self, ev: Dict[str, Any]) -> bool:
        if not isinstance(ev, dict):
            return False
        # Direct event keys
        if "eventName" in ev and "eventSource" in ev:
            return True
        # EventBridge format
        detail = ev.get("detail")
        if isinstance(detail, dict) and "eventName" in detail and "eventSource" in detail:
            return True
        return False

    def select_parser(self) -> AWSCloudTrailParser:
        return AWSCloudTrailParser()

    def select_normalizer(self) -> AWSCloudTrailNormalizer:
        return AWSCloudTrailNormalizer()

    def identity(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "source_type": self.source_type,
        }
