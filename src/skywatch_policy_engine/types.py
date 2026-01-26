from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


class Provider(str, Enum):
    AWS = "AWS"
    AZURE = "Azure"
    GCP = "GCP"


class ResourceType(str, Enum):
    S3_BUCKET = "S3_BUCKET"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    SUPPRESSED = "SUPPRESSED"


class EvaluationErrorCode(str, Enum):
    UNKNOWN_RULE = "UNKNOWN_RULE"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    SKIPPED_MISSING_DATA = "SKIPPED_MISSING_DATA"
    RULE_EXCEPTION = "RULE_EXCEPTION"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    """
    Provider-agnostic, normalized representation of a cloud resource state.

    This is the primary input to the Policy Engine. The metadata field contains
    normalized keys that are consistent across providers (e.g., for S3: encryption,
    public_access_block, acl_grants, bucket_policy, transport).

    Attributes:
        snapshot_id: Unique identifier for this snapshot (typically UUID).
        account_id: Cloud account ID where the resource resides.
        provider: Cloud provider (AWS, Azure, GCP).
        resource_type: Type of resource (e.g., S3_BUCKET).
        resource_id: Resource identifier (e.g., bucket name or ARN).
        captured_at: Timestamp when the snapshot was captured.
        metadata: Normalized configuration metadata. Structure depends on resource_type.
    """

    snapshot_id: str
    account_id: str
    provider: Provider
    resource_type: ResourceType
    resource_id: str
    captured_at: datetime
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuleConfig:
    rule_id: str
    enabled: bool = True
    severity_override: Severity | None = None
    params: Mapping[str, Any] | None = None
    suppressed: bool = False


@dataclass(frozen=True, slots=True)
class EvidenceObservation:
    path: str
    value: Any


@dataclass(frozen=True, slots=True)
class Evidence:
    summary: str
    observations: list[EvidenceObservation] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Remediation:
    summary: str
    steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Finding:
    """
    A security finding (vulnerability) detected by a policy rule.

    Findings represent actionable security issues with evidence and remediation
    guidance. They are deterministic: the same snapshot and rule configuration
    will always produce the same finding (same finding_id via UUIDv5).

    Attributes:
        finding_id: Deterministic UUID (UUIDv5) derived from snapshot_id, rule_id, finding_key.
        account_id: Cloud account ID where the resource resides.
        resource_type: Type of resource (e.g., S3_BUCKET).
        resource_id: Resource identifier (e.g., bucket name).
        rule_id: Identifier of the rule that generated this finding.
        rule_version: Version of the rule that generated this finding.
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW).
        status: Finding status (OPEN or SUPPRESSED).
        title: Short title describing the finding.
        description: Detailed description of the security issue.
        evidence: Evidence supporting the finding (observations, paths, values).
        remediation: Remediation guidance (steps, references).
        detected_at: Timestamp when the finding was detected.
    """

    finding_id: str
    account_id: str
    resource_type: ResourceType
    resource_id: str
    rule_id: str
    rule_version: str
    severity: Severity
    status: FindingStatus
    title: str
    description: str
    evidence: Evidence
    remediation: Remediation
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class EvaluationError:
    rule_id: str
    error_code: EvaluationErrorCode
    message: str
    snapshot_id: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class EvaluationStats:
    rules_evaluated: int
    rules_failed: int
    duration_ms: int


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    findings: list[Finding]
    stats: EvaluationStats
    errors: list[EvaluationError] = field(default_factory=list)


# A stable, deterministic namespace for finding IDs.
FINDING_ID_NAMESPACE = uuid.UUID("3d014e3a-8a03-4dd8-9f5d-6b7b5a03b0d2")
