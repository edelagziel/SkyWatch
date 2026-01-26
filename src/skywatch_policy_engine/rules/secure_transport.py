from __future__ import annotations

from typing import Any, Mapping

from ..interfaces import FindingSpec
from ..types import (
    Evidence,
    EvidenceObservation,
    Remediation,
    ResourceSnapshot,
    ResourceType,
    Severity,
)


class SecureTransportRule:
    rule_id = "S3_TLS_NOT_ENFORCED"
    rule_version = "1.0.0"
    default_severity = Severity.MEDIUM

    def supports(self, resource_type: ResourceType) -> bool:
        return resource_type == ResourceType.S3_BUCKET

    def evaluate(
        self, snapshot: ResourceSnapshot, *, params: Mapping[str, Any] | None = None
    ) -> list[FindingSpec]:
        transport = snapshot.metadata.get("transport")
        requires_tls = None
        if isinstance(transport, Mapping):
            requires_tls = transport.get("requires_tls")

        # Per LLD, missing is treated as insecure for TLS enforcement.
        if requires_tls is True:
            return []

        return [
            FindingSpec(
                finding_key="tls_not_enforced",
                title="S3 bucket policy does not enforce TLS-only access",
                description="The bucket does not appear to require TLS (HTTPS) for access.",
                evidence=Evidence(
                    summary="TLS is not enforced or the indicator is missing.",
                    observations=[
                        EvidenceObservation(
                            path="metadata.transport.requires_tls", value=requires_tls
                        ),
                    ],
                ),
                remediation=Remediation(
                    summary="Enforce TLS-only access to the bucket.",
                    steps=[
                        "Add a bucket policy statement that denies requests where aws:SecureTransport is false.",
                        "Validate clients access the bucket using HTTPS endpoints.",
                    ],
                    references=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html#example-bucket-policies-use-secure-transport",
                    ],
                ),
            )
        ]
