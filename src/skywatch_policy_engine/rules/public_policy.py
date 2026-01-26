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
from .common import normalize_to_list


class PublicPolicyRule:
    rule_id = "S3_PUBLIC_POLICY"
    rule_version = "1.0.0"
    default_severity = Severity.HIGH

    def supports(self, resource_type: ResourceType) -> bool:
        return resource_type == ResourceType.S3_BUCKET

    def evaluate(
        self, snapshot: ResourceSnapshot, *, params: Mapping[str, Any] | None = None
    ) -> list[FindingSpec]:
        policy = snapshot.metadata.get("bucket_policy")
        if policy is None:
            raise RuleSkippedMissingData(self.rule_id, ["metadata.bucket_policy"])
        if not isinstance(policy, Mapping):
            raise RuleInvalidSchema(self.rule_id, "metadata.bucket_policy must be an object")

        statements = policy.get("statements")
        if statements is None:
            raise RuleSkippedMissingData(self.rule_id, ["metadata.bucket_policy.statements"])
        if not isinstance(statements, list):
            raise RuleInvalidSchema(
                self.rule_id, "metadata.bucket_policy.statements must be a list"
            )

        public_statements: list[Mapping[str, Any]] = []
        for st in statements:
            if not isinstance(st, Mapping):
                continue
            if str(st.get("effect", "")).lower() != "allow":
                continue
            principal = st.get("principal")
            if not _is_wildcard_principal(principal):
                continue
            actions = normalize_to_list(st.get("action"))
            if not any(isinstance(a, str) and a.lower().startswith("s3:") for a in actions):
                continue
            public_statements.append(st)

        if not public_statements:
            return []

        pab = snapshot.metadata.get("public_access_block")
        restrict_public_buckets = None
        if isinstance(pab, Mapping):
            restrict_public_buckets = pab.get("restrict_public_buckets")

        severity = Severity.CRITICAL if restrict_public_buckets is False else None

        return [
            FindingSpec(
                finding_key="public_policy",
                title="S3 bucket policy allows public access",
                description="The bucket policy contains Allow statements with wildcard principals.",
                severity=severity,
                evidence=Evidence(
                    summary="Public policy statements detected.",
                    observations=[
                        EvidenceObservation(
                            path="metadata.bucket_policy.statements", value=public_statements
                        ),
                        EvidenceObservation(
                            path="metadata.public_access_block.restrict_public_buckets",
                            value=restrict_public_buckets,
                        ),
                    ],
                ),
                remediation=Remediation(
                    summary="Restrict bucket policy to trusted principals only.",
                    steps=[
                        "Remove wildcard principals from Allow statements.",
                        "Use least-privilege IAM principals (roles/users) and conditions.",
                        "Enable/verify S3 Block Public Access settings (especially RestrictPublicBuckets).",
                    ],
                    references=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html",
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                    ],
                ),
            )
        ]


def _is_wildcard_principal(principal: Any) -> bool:
    # Supports common normalized shapes.
    if principal == "*" or principal == {"AWS": "*"}:
        return True
    if isinstance(principal, str) and principal.strip() == "*":
        return True
    if isinstance(principal, Mapping) and principal.get("AWS") == "*":
        return True
    return False
