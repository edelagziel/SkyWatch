from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .serialization import rule_configs_from_dict
from .types import ResourceType, RuleConfig


class PolicyRepository:
    def get_enabled_rules(
        self, *, resource_type: ResourceType, account_id: str
    ) -> list[RuleConfig]:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class StaticPolicyRepository(PolicyRepository):
    rules: tuple[RuleConfig, ...]

    def get_enabled_rules(
        self, *, resource_type: ResourceType, account_id: str
    ) -> list[RuleConfig]:
        # For MVP we ignore resource_type/account_id scoping; caller provides the right set.
        return [r for r in self.rules if r.enabled]


@dataclass(frozen=True, slots=True)
class JsonPolicyRepository(PolicyRepository):
    path: Path

    def get_enabled_rules(
        self, *, resource_type: ResourceType, account_id: str
    ) -> list[RuleConfig]:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        rules = rule_configs_from_dict(data)
        return [r for r in rules if r.enabled]


def ensure_repository(rules: Iterable[RuleConfig] | PolicyRepository) -> PolicyRepository:
    if isinstance(rules, PolicyRepository):
        return rules
    return StaticPolicyRepository(tuple(rules))
