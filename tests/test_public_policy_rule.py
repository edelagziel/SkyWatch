import unittest
from datetime import datetime, timezone

from skywatch_policy_engine.errors import RuleInvalidSchema, RuleSkippedMissingData
from skywatch_policy_engine.rules.public_policy import PublicPolicyRule
from skywatch_policy_engine.types import (
    Provider,
    ResourceSnapshot,
    ResourceType,
    Severity,
)


class TestPublicPolicyRule(unittest.TestCase):
    def setUp(self):
        self.rule = PublicPolicyRule()

    def test_no_public_policy_no_finding(self):
        """Should not emit finding when no public policy statements exist"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-1",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-1",
            captured_at=datetime.now(timezone.utc),
            metadata={
                "bucket_policy": {
                    "statements": [
                        {
                            "effect": "Allow",
                            "principal": "arn:aws:iam::123456789012:user/test",
                            "action": ["s3:GetObject"],
                        }
                    ]
                }
            },
        )
        findings = self.rule.evaluate(snapshot)
        self.assertEqual(len(findings), 0)

    def test_public_policy_wildcard_emits_finding(self):
        """Should emit finding when policy has wildcard principal"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-2",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-2",
            captured_at=datetime.now(timezone.utc),
            metadata={
                "bucket_policy": {
                    "statements": [
                        {
                            "effect": "Allow",
                            "principal": "*",
                            "action": ["s3:GetObject"],
                            "resource": ["arn:aws:s3:::bucket-2/*"],
                        }
                    ]
                }
            },
        )
        findings = self.rule.evaluate(snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_key, "public_policy")
        self.assertEqual(
            findings[0].title, "S3 bucket policy allows public access"
        )

    def test_public_policy_with_restrict_public_buckets_false_critical(self):
        """Should emit CRITICAL finding when restrict_public_buckets is False"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-3",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-3",
            captured_at=datetime.now(timezone.utc),
            metadata={
                "bucket_policy": {
                    "statements": [
                        {
                            "effect": "Allow",
                            "principal": "*",
                            "action": ["s3:GetObject"],
                        }
                    ]
                },
                "public_access_block": {"restrict_public_buckets": False},
            },
        )
        findings = self.rule.evaluate(snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_missing_bucket_policy_raises_error(self):
        """Should raise RuleSkippedMissingData when bucket_policy is missing"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-4",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-4",
            captured_at=datetime.now(timezone.utc),
            metadata={},  # No bucket_policy
        )
        with self.assertRaises(RuleSkippedMissingData) as cm:
            self.rule.evaluate(snapshot)
        self.assertIn("bucket_policy", str(cm.exception))

    def test_deny_statement_ignored(self):
        """Should ignore Deny statements"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-5",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-5",
            captured_at=datetime.now(timezone.utc),
            metadata={
                "bucket_policy": {
                    "statements": [
                        {
                            "effect": "Deny",
                            "principal": "*",
                            "action": ["s3:GetObject"],
                        }
                    ]
                }
            },
        )
        findings = self.rule.evaluate(snapshot)
        self.assertEqual(len(findings), 0)
