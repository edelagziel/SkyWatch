from __future__ import annotations

from .registry import RuleRegistry
from .rules import EncryptionEnabledRule, PublicAclRule, PublicPolicyRule, SecureTransportRule


def default_registry() -> RuleRegistry:
    reg = RuleRegistry()
    reg.register(EncryptionEnabledRule())
    reg.register(PublicAclRule())
    reg.register(PublicPolicyRule())
    reg.register(SecureTransportRule())
    return reg
