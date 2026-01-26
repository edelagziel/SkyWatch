from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .types import Provider, ResourceType


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    correlation_id: str
    evaluated_at: datetime
    account_id: str
    provider: Provider
    resource_type: ResourceType
    resource_id: str
