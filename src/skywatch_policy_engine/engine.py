from __future__ import annotations

import time
from dataclasses import dataclass

from .context import EvaluationContext
from .errors import RuleInvalidSchema, RuleSkippedMissingData, UnknownRuleError
from .finding_factory import FindingFactory
from .guard import NormalizationGuard
from .interfaces import PolicyRule
from .repository import PolicyRepository
from .types import (
    EvaluationError,
    EvaluationErrorCode,
    EvaluationResult,
    EvaluationStats,
    FindingStatus,
    ResourceSnapshot,
    RuleConfig,
    Severity,
    utc_now,
)


@dataclass(frozen=True, slots=True)
class PolicyEngine:
    """
    Orchestrates evaluation of a ResourceSnapshot against enabled policy rules.

    The engine is deterministic: given the same snapshot and rule configuration,
    it will always produce the same results. It implements fail-soft error handling,
    meaning that errors in one rule do not stop evaluation of other rules.

    Attributes:
        repository: Provides enabled rules for a given resource type and account.
        registry: Maps rule IDs to rule implementations. Must have a `get(rule_id)` method.
        finding_factory: Creates consistent findings with IDs and timestamps.

    Example:
        >>> from skywatch_policy_engine.builtins import default_registry
        >>> from skywatch_policy_engine.repository import StaticPolicyRepository
        >>> engine = PolicyEngine(
        ...     repository=StaticPolicyRepository(rules),
        ...     registry=default_registry(),
        ... )
        >>> result = engine.evaluate(snapshot)
        >>> print(f"Found {len(result.findings)} findings")
    """

    repository: PolicyRepository
    registry: object  # RuleRegistry-like: has get(rule_id)->PolicyRule
    finding_factory: FindingFactory = FindingFactory()

    def evaluate(self, snapshot: ResourceSnapshot) -> EvaluationResult:
        """
        Evaluate a resource snapshot against enabled policy rules.

        Performs validation of required snapshot fields using NormalizationGuard
        before evaluation, then runs all enabled rules and collects findings.

        Args:
            snapshot: Normalized resource snapshot to evaluate. Must contain
                required fields: account_id, resource_id, resource_type.

        Returns:
            EvaluationResult containing:
                - findings: List of security findings (vulnerabilities)
                - stats: Evaluation statistics (rules evaluated, failed, duration)
                - errors: Non-fatal errors encountered during evaluation

        Note:
            All errors are captured in the result rather than raised as exceptions.
            This ensures fail-soft behavior where one rule's failure doesn't stop
            evaluation of other rules.

        Example:
            >>> snapshot = ResourceSnapshot(
            ...     snapshot_id="...",
            ...     account_id="123456789012",
            ...     provider=Provider.AWS,
            ...     resource_type=ResourceType.S3_BUCKET,
            ...     resource_id="my-bucket",
            ...     captured_at=utc_now(),
            ...     metadata={"encryption": {"enabled": False}},
            ... )
            >>> result = engine.evaluate(snapshot)
            >>> for finding in result.findings:
            ...     print(f"{finding.rule_id}: {finding.severity}")
        """
        started = time.perf_counter()
        errors: list[EvaluationError] = []
        findings = []
        rules_evaluated = 0
        rules_failed = 0

        # Validate required snapshot fields using NormalizationGuard (per LLD)
        snapshot_dict = {
            "account_id": snapshot.account_id,
            "resource_id": snapshot.resource_id,
            "resource_type": snapshot.resource_type.value,
        }
        guard_result = NormalizationGuard.require(
            snapshot_dict, paths=["account_id", "resource_id", "resource_type"]
        )

        if guard_result.missing_paths:
            # Return early with validation error
            duration_ms = int((time.perf_counter() - started) * 1000)
            return EvaluationResult(
                findings=[],
                stats=EvaluationStats(
                    rules_evaluated=0, rules_failed=0, duration_ms=duration_ms
                ),
                errors=[
                    EvaluationError(
                        rule_id="__validation__",
                        error_code=EvaluationErrorCode.INVALID_SCHEMA,
                        message=f"Missing required snapshot fields: {', '.join(guard_result.missing_paths)}",
                        snapshot_id=snapshot.snapshot_id,
                        occurred_at=utc_now(),
                    )
                ],
            )

        ctx = EvaluationContext(
            correlation_id=snapshot.snapshot_id,
            evaluated_at=snapshot.captured_at or utc_now(),
            account_id=snapshot.account_id,
            provider=snapshot.provider,
            resource_type=snapshot.resource_type,
            resource_id=snapshot.resource_id,
        )

        rule_configs = self.repository.get_enabled_rules(
            resource_type=snapshot.resource_type, account_id=snapshot.account_id
        )

        for cfg in rule_configs:
            rules_evaluated += 1
            try:
                rule: PolicyRule = self.registry.get(cfg.rule_id)
            except UnknownRuleError as e:
                rules_failed += 1
                errors.append(
                    EvaluationError(
                        rule_id=cfg.rule_id,
                        error_code=EvaluationErrorCode.UNKNOWN_RULE,
                        message=str(e),
                        snapshot_id=snapshot.snapshot_id,
                        occurred_at=utc_now(),
                    )
                )
                continue

            if hasattr(rule, "supports") and not rule.supports(snapshot.resource_type):
                continue

            try:
                specs = rule.evaluate(snapshot, params=cfg.params)
            except RuleSkippedMissingData as e:
                errors.append(
                    EvaluationError(
                        rule_id=cfg.rule_id,
                        error_code=EvaluationErrorCode.SKIPPED_MISSING_DATA,
                        message=str(e),
                        snapshot_id=snapshot.snapshot_id,
                        occurred_at=utc_now(),
                    )
                )
                continue
            except RuleInvalidSchema as e:
                rules_failed += 1
                errors.append(
                    EvaluationError(
                        rule_id=cfg.rule_id,
                        error_code=EvaluationErrorCode.INVALID_SCHEMA,
                        message=str(e),
                        snapshot_id=snapshot.snapshot_id,
                        occurred_at=utc_now(),
                    )
                )
                continue
            except Exception as e:  # fail-soft
                rules_failed += 1
                errors.append(
                    EvaluationError(
                        rule_id=cfg.rule_id,
                        error_code=EvaluationErrorCode.RULE_EXCEPTION,
                        message=f"{type(e).__name__}: {e}",
                        snapshot_id=snapshot.snapshot_id,
                        occurred_at=utc_now(),
                    )
                )
                continue

            status = FindingStatus.SUPPRESSED if cfg.suppressed else FindingStatus.OPEN

            for spec in specs:
                sev = _resolve_severity(rule=rule, cfg=cfg, spec_severity=spec.severity)
                findings.append(
                    self.finding_factory.create(
                        snapshot=snapshot,
                        ctx=ctx,
                        rule_id=rule.rule_id,
                        rule_version=rule.rule_version,
                        severity=sev,
                        status=status,
                        spec=spec,
                    )
                )

        duration_ms = int((time.perf_counter() - started) * 1000)
        stats = EvaluationStats(
            rules_evaluated=rules_evaluated,
            rules_failed=rules_failed,
            duration_ms=duration_ms,
        )
        return EvaluationResult(findings=findings, stats=stats, errors=errors)


def _resolve_severity(
    *, rule: PolicyRule, cfg: RuleConfig, spec_severity: Severity | None
) -> Severity:
    """
    Resolve the final severity for a finding.

    Priority order:
    1. Rule config severity override (if set)
    2. Finding spec severity (if set by rule)
    3. Rule default severity

    Args:
        rule: The policy rule that generated the finding.
        cfg: Rule configuration (may contain severity override).
        spec_severity: Severity specified by the rule in FindingSpec.

    Returns:
        Final severity to use for the finding.
    """
    if cfg.severity_override is not None:
        return cfg.severity_override
    if spec_severity is not None:
        return spec_severity
    return rule.default_severity
