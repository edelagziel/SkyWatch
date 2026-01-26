import unittest
from datetime import datetime, timezone

from skywatch_policy_engine.errors import RuleInvalidSchema, RuleSkippedMissingData
from skywatch_policy_engine.rules.public_acl import PublicAclRule
from skywatch_policy_engine.types import (
    Provider,
    ResourceSnapshot,
    ResourceType,
    Severity,
)


class TestPublicAclRule(unittest.TestCase):
    def setUp(self):
        self.rule = PublicAclRule()

    def test_no_public_acl_no_finding(self):
        """Should not emit finding when no public ACL grants exist"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-1",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-1",
            captured_at=datetime.now(timezone.utc),
            metadata={
                "acl_grants": [
                    {
                        "grantee_type": "USER",
                        "grantee_uri": "arn:aws:iam::123456789012:user/test",
                        "permission": "READ",
                    }
                ]
            },
        )
        findings = self.rule.evaluate(snapshot)
        self.assertEqual(len(findings), 0)

    def test_public_acl_allusers_emits_finding(self):
        """Should emit finding when AllUsers has READ permission"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-2",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-2",
            captured_at=datetime.now(timezone.utc),
            metadata={
                "acl_grants": [
                    {
                        "grantee_type": "GROUP",
                        "grantee_uri": "http://acs.amazonaws.com/groups/global/AllUsers",
                        "permission": "READ",
                    }
                ]
            },
        )
        findings = self.rule.evaluate(snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_key, "public_acl")
        self.assertEqual(findings[0].title, "S3 bucket is publicly accessible via ACL")

    def test_public_acl_authenticated_users_emits_finding(self):
        """Should emit finding when AuthenticatedUsers has permission"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-3",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-3",
            captured_at=datetime.now(timezone.utc),
            metadata={
                "acl_grants": [
                    {
                        "grantee_type": "GROUP",
                        "grantee_uri": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                        "permission": "FULL_CONTROL",
                    }
                ]
            },
        )
        findings = self.rule.evaluate(snapshot)
        self.assertEqual(len(findings), 1)

    def test_missing_acl_grants_raises_error(self):
        """Should raise RuleSkippedMissingData when acl_grants is missing"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-4",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-4",
            captured_at=datetime.now(timezone.utc),
            metadata={},  # No acl_grants
        )
        with self.assertRaises(RuleSkippedMissingData) as cm:
            self.rule.evaluate(snapshot)
        self.assertIn("acl_grants", str(cm.exception))

    def test_invalid_acl_grants_type_raises_error(self):
        """Should raise RuleInvalidSchema when acl_grants is not a list"""
        snapshot = ResourceSnapshot(
            snapshot_id="test-5",
            account_id="123456789012",
            provider=Provider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            resource_id="bucket-5",
            captured_at=datetime.now(timezone.utc),
            metadata={"acl_grants": "not-a-list"},
        )
        with self.assertRaises(RuleInvalidSchema) as cm:
            self.rule.evaluate(snapshot)
        self.assertIn("must be a list", str(cm.exception))
