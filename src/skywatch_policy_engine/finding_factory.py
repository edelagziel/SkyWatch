from __future__ import annotations

import uuid
from dataclasses import dataclass

from .context import EvaluationContext
from .interfaces import FindingSpec
from .types import (
    FINDING_ID_NAMESPACE,
    Evidence,
    Finding,
    FindingStatus,
    Remediation,
    ResourceSnapshot,
    Severity,
)


@dataclass(frozen=True, slots=True)
class FindingFactory:
    """
    Creates consistent findings with deterministic IDs and standardized formatting.

    This factory ensures that findings are created with:
    - Deterministic UUIDs (UUIDv5) based on snapshot_id, rule_id, and finding_key
    - Consistent timestamps (from evaluation context)
    - Proper status (OPEN or SUPPRESSED based on rule config)

    The determinism ensures that re-evaluating the same snapshot with the same
    rules will produce findings with identical IDs, enabling deduplication and
    change detection.

    Note on determinism:
    - finding_id is UUIDv5 derived from (snapshot_id, rule_id, finding_key)
    - detected_at defaults to ctx.evaluated_at (typically snapshot.captured_at)
    - Same inputs always produce the same finding_id

    Example:
        >>> factory = FindingFactory()
        >>> finding = factory.create(
        ...     snapshot=snapshot,
        ...     ctx=ctx,
        ...     rule_id="S3_ENCRYPTION_DISABLED",
        ...     rule_version="1.0.0",
        ...     severity=Severity.HIGH,
        ...     status=FindingStatus.OPEN,
        ...     spec=finding_spec,
        ... )
    """

    def create(
        self,
        *,
        snapshot: ResourceSnapshot,
        ctx: EvaluationContext,
        rule_id: str,
        rule_version: str,
        severity: Severity,
        status: FindingStatus,
        spec: FindingSpec,
    ) -> Finding:
        fid = _stable_finding_id(
            snapshot_id=snapshot.snapshot_id, rule_id=rule_id, finding_key=spec.finding_key
        )
        return Finding(
            finding_id=str(fid),
            account_id=snapshot.account_id,
            resource_type=snapshot.resource_type,
            resource_id=snapshot.resource_id,
            rule_id=rule_id,
            rule_version=rule_version,
            severity=severity,
            status=status,
            title=spec.title,
            description=spec.description,
            evidence=_ensure_evidence(spec.evidence),
            remediation=_ensure_remediation(spec.remediation),
            detected_at=ctx.evaluated_at,
        )


def _stable_finding_id(*, snapshot_id: str, rule_id: str, finding_key: str) -> uuid.UUID:
    name = f"{snapshot_id}|{rule_id}|{finding_key}"
    return uuid.uuid5(FINDING_ID_NAMESPACE, name)


def _ensure_evidence(e: Evidence) -> Evidence:
    # hook for normalization if needed later
    return e


def _ensure_remediation(r: Remediation) -> Remediation:
    return r
