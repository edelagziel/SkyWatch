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


class EncryptionEnabledRule:
    rule_id = "S3_ENCRYPTION_DISABLED"
    rule_version = "1.0.0"
    default_severity = Severity.HIGH

    def supports(self, resource_type: ResourceType) -> bool:
        return resource_type == ResourceType.S3_BUCKET

    def evaluate(
        self, snapshot: ResourceSnapshot, *, params: Mapping[str, Any] | None = None
    ) -> list[FindingSpec]:
        encryption = snapshot.metadata.get("encryption")
        enabled = None
        if isinstance(encryption, Mapping):
            enabled = encryption.get("enabled")
        # Per LLD baseline, missing encryption config is treated as insecure.
        if enabled is True:
            return []

        obs = []
        if isinstance(encryption, Mapping) and "enabled" in encryption:
            obs.append(
                EvidenceObservation(
                    path="metadata.encryption.enabled", value=encryption.get("enabled")
                )
            )
        else:
            obs.append(EvidenceObservation(path="metadata.encryption", value=encryption))

        return [
            FindingSpec(
                finding_key="encryption_disabled",
                title="S3 bucket encryption at rest is not enabled",
                description="The bucket is missing encryption-at-rest configuration (SSE-S3 or SSE-KMS).",
                evidence=Evidence(
                    summary="Bucket encryption is disabled or missing.",
                    observations=obs,
                ),
                remediation=Remediation(
                    summary="Enable default encryption on the bucket.",
                    steps=[
                        "Enable SSE-S3 or SSE-KMS default encryption for the bucket.",
                        "Optionally enforce encryption via a bucket policy to deny unencrypted uploads.",
                    ],
                    references=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
                    ],
                ),
            )
        ]
