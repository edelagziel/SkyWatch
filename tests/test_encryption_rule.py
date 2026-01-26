import unittest
from datetime import datetime, timezone

from skywatch_policy_engine.rules.encryption import EncryptionEnabledRule
from skywatch_policy_engine.types import (
    Provider,
    ResourceSnapshot,
    ResourceType,
    Severity,
)


class TestEncryptionRule(unittest.TestCase):
    def setUp(self):
        self.rule = EncryptionEnabledRule()

    def test_encryption_enabled_no_finding(self):
        """Should not emit finding when encryption is enabled"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-1",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-1",
            captured_at=datetime.now(timezone.utc),
            metadata={"encryption": {"enabled": True}},
        )
        findings = self.rule.evaluate(snapshot)
        self.assertEqual(len(findings), 0)

    def test_encryption_disabled_emits_finding(self):
        """Should emit finding when encryption is disabled"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-2",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-2",
            captured_at=datetime.now(timezone.utc),
            metadata={"encryption": {"enabled": False}},
        )
        findings = self.rule.evaluate(snapshot)
        self.assertEqual(len(findings), 1)
        # FindingSpec doesn't have severity set (it's None by default, set later by engine)
        self.assertEqual(
            findings[0].title, "S3 bucket encryption at rest is not enabled"
        )
        self.assertEqual(findings[0].finding_key, "encryption_disabled")
        self.assertIn("encryption", findings[0].evidence.observations[0].path.lower())

    def test_encryption_missing_emits_finding(self):
        """Should emit finding when encryption config is missing"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-3",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-3",
            captured_at=datetime.now(timezone.utc),
            metadata={},  # No encryption key
        )
        findings = self.rule.evaluate(snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_key, "encryption_disabled")

    def test_encryption_none_value_emits_finding(self):
        """Should emit finding when encryption is None"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-4",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-4",
            captured_at=datetime.now(timezone.utc),
            metadata={"encryption": None},
        )
        findings = self.rule.evaluate(snapshot)
        self.assertEqual(len(findings), 1)

    def test_supports_s3_bucket(self):
        """Should support S3_BUCKET resource type"""
        self.assertTrue(self.rule.supports(ResourceType.S3_BUCKET))
