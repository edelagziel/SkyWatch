from __future__ import annotations

from dataclasses import dataclass, field

from .errors import UnknownRuleError
from .interfaces import PolicyRule


@dataclass(slots=True)
class RuleRegistry:
    """
    Registry mapping rule IDs to rule implementations.

    The registry allows dynamic registration of policy rules and provides
    lookup by rule_id. This enables the Open/Closed Principle: new rules
    can be added without modifying the engine.

    Attributes:
        _rules: Internal dictionary mapping rule_id -> PolicyRule instance.

    Example:
        >>> registry = RuleRegistry()
        >>> registry.register(EncryptionEnabledRule())
        >>> rule = registry.get("S3_ENCRYPTION_DISABLED")
    """

    _rules: dict[str, PolicyRule] = field(default_factory=dict)

    def register(self, rule: PolicyRule) -> None:
        """
        Register a policy rule in the registry.

        Args:
            rule: Policy rule instance to register. Must have a `rule_id` attribute.

        Note:
            If a rule with the same rule_id already exists, it will be overwritten.
        """
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> PolicyRule:
        """
        Retrieve a rule by its ID.

        Args:
            rule_id: Identifier of the rule to retrieve.

        Returns:
            PolicyRule instance for the given rule_id.

        Raises:
            UnknownRuleError: If no rule with the given rule_id is registered.
        """
        try:
            return self._rules[rule_id]
        except KeyError as e:
            raise UnknownRuleError(rule_id) from e
