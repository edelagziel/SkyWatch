from __future__ import annotations


class SkyWatchPolicyEngineError(Exception):
    pass


class UnknownRuleError(SkyWatchPolicyEngineError):
    def __init__(self, rule_id: str):
        super().__init__(f"Unknown rule_id: {rule_id}")
        self.rule_id = rule_id


class RuleSkippedMissingData(SkyWatchPolicyEngineError):
    def __init__(self, rule_id: str, missing_paths: list[str]):
        super().__init__(f"Rule {rule_id} skipped: missing required data: {missing_paths}")
        self.rule_id = rule_id
        self.missing_paths = missing_paths


class RuleInvalidSchema(SkyWatchPolicyEngineError):
    def __init__(self, rule_id: str, message: str):
        super().__init__(f"Rule {rule_id} invalid schema: {message}")
        self.rule_id = rule_id
