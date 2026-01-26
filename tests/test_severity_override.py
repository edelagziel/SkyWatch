import unittest
from datetime import datetime, timezone

from skywatch_policy_engine.builtins import default_registry
from skywatch_policy_engine.engine import PolicyEngine
from skywatch_policy_engine.repository import StaticPolicyRepository
from skywatch_policy_engine.types import (
    Provider,
    ResourceSnapshot,
    ResourceType,
    RuleConfig,
    Severity,
)


class TestSeverityOverride(unittest.TestCase):
    def test_severity_override_applied(self):
        """Should apply severity override from rule config"""
        engine = PolicyEngine(
            repository=StaticPolicyRepository(
                tuple(
                    [
                        RuleConfig(
                            rule_id="S3_ENCRYPTION_DISABLED",
                            enabled=True,
                            severity_override=Severity.CRITICAL,  # Override HIGH to CRITICAL
                        )
                    ]
                )
            ),
            registry=default_registry(),
        )
        snapshot = ResourceSnapshot(
            snapshot_id="test-1",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-1",
            captured_at=datetime.now(timezone.utc),
            metadata={"encryption": {"enabled": False}},
        )
        result = engine.evaluate(snapshot)
        # Find the encryption finding
        encryption_findings = [
            f for f in result.findings if f.rule_id == "S3_ENCRYPTION_DISABLED"
        ]
        self.assertEqual(len(encryption_findings), 1)
        # Should be CRITICAL due to override, not HIGH (default)
        self.assertEqual(encryption_findings[0].severity, Severity.CRITICAL)

    def test_default_severity_when_no_override(self):
        """Should use default severity when no override is set"""
        engine = PolicyEngine(
            repository=StaticPolicyRepository(
                tuple([RuleConfig(rule_id="S3_ENCRYPTION_DISABLED", enabled=True)])
            ),
            registry=default_registry(),
        )
        snapshot = ResourceSnapshot(
            snapshot_id="test-2",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-2",
            captured_at=datetime.now(timezone.utc),
            metadata={"encryption": {"enabled": False}},
        )
        result = engine.evaluate(snapshot)
        encryption_findings = [
            f for f in result.findings if f.rule_id == "S3_ENCRYPTION_DISABLED"
        ]
        self.assertEqual(len(encryption_findings), 1)
        # Should be HIGH (default for EncryptionEnabledRule)
        self.assertEqual(encryption_findings[0].severity, Severity.HIGH)
