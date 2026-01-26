from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, runtime_checkable

from .types import Evidence, Remediation, ResourceSnapshot, ResourceType, Severity


@dataclass(frozen=True, slots=True)
class FindingSpec:
    """
    Rule-produced finding skeleton.

    The engine/factory will enrich this into a full Finding (IDs, timestamps, status, etc.).
    finding_key should be stable for deterministic finding_id generation.
    """

    finding_key: str
    title: str
    description: str
    evidence: Evidence
    remediation: Remediation
    severity: Severity | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)


@runtime_checkable
class PolicyRule(Protocol):
    rule_id: str
    rule_version: str
    default_severity: Severity

    def supports(self, resource_type: ResourceType) -> bool:  # optional skip
        return True

    def evaluate(
        self, snapshot: ResourceSnapshot, *, params: Mapping[str, Any] | None = None
    ) -> list[FindingSpec]:
        ...
