import json
import unittest
from pathlib import Path

from skywatch_policy_engine.builtins import default_registry
from skywatch_policy_engine.engine import PolicyEngine
from skywatch_policy_engine.repository import StaticPolicyRepository
from skywatch_policy_engine.serialization import rule_configs_from_dict, snapshot_from_dict
 
 
class TestPolicyEngineMVP(unittest.TestCase):
     def test_examples_snapshot_generates_findings(self) -> None:
         root = Path(__file__).resolve().parents[1]
         snap = json.loads((root / "examples" / "s3_snapshot_public_unencrypted.json").read_text(encoding="utf-8"))
         pol = json.loads((root / "examples" / "policies.json").read_text(encoding="utf-8"))
 
         snapshot = snapshot_from_dict(snap)
         rules = rule_configs_from_dict(pol)
 
         engine = PolicyEngine(repository=StaticPolicyRepository(tuple(rules)), registry=default_registry())
         result = engine.evaluate(snapshot)
 
         rule_ids = sorted({f.rule_id for f in result.findings})
         self.assertEqual(rule_ids, ["S3_ENCRYPTION_DISABLED", "S3_PUBLIC_ACL", "S3_PUBLIC_POLICY", "S3_TLS_NOT_ENFORCED"])
         self.assertEqual(len(result.findings), 4)
 
 
if __name__ == "__main__":
     unittest.main()
