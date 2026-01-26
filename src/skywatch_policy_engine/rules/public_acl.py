from __future__ import annotations

from typing import Any, Mapping

from ..errors import RuleInvalidSchema, RuleSkippedMissingData
from ..interfaces import FindingSpec
from ..types import (
    Evidence,
    EvidenceObservation,
    Remediation,
    ResourceSnapshot,
    ResourceType,
    Severity,
)
from .common import is_public_grantee_uri


class PublicAclRule:
    rule_id = "S3_PUBLIC_ACL"
    rule_version = "1.0.0"
    default_severity = Severity.HIGH

    def supports(self, resource_type: ResourceType) -> bool:
        return resource_type == ResourceType.S3_BUCKET

    def evaluate(
        self, snapshot: ResourceSnapshot, *, params: Mapping[str, Any] | None = None
    ) -> list[FindingSpec]:
        grants = snapshot.metadata.get("acl_grants")
        if grants is None:
            raise RuleSkippedMissingData(self.rule_id, ["metadata.acl_grants"])
        if not isinstance(grants, list):
            raise RuleInvalidSchema(self.rule_id, "metadata.acl_grants must be a list")

        offending: list[Mapping[str, Any]] = []
        for g in grants:
            if not isinstance(g, Mapping):
                continue
            uri = g.get("grantee_uri")
            perm = str(g.get("permission", "")).upper()
            if is_public_grantee_uri(uri) and (
                "READ" in perm or "FULL_CONTROL" in perm or "WRITE" in perm
            ):
                offending.append(g)

        if not offending:
            return []

        return [
            FindingSpec(
                finding_key="public_acl",
                title="S3 bucket is publicly accessible via ACL",
                description="The bucket ACL grants public group access (AllUsers/AuthenticatedUsers).",
                evidence=Evidence(
                    summary="Public ACL grants detected.",
                    observations=[
                        EvidenceObservation(path="metadata.acl_grants", value=offending),
                    ],
                ),
                remediation=Remediation(
                    summary="Remove public ACL grants and enable Public Access Block.",
                    steps=[
                        "Remove ACL grants to AllUsers and AuthenticatedUsers.",
                        "Enable S3 Block Public Access settings for the bucket/account.",
                    ],
                    references=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                    ],
                ),
            )
        ]
