from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from .types import (
    Evidence,
    EvaluationError,
    EvaluationResult,
    Finding,
    Provider,
    Remediation,
    ResourceSnapshot,
    ResourceType,
    RuleConfig,
    Severity,
)


def _dt_from_iso(s: str) -> datetime:
    # Accept both Z and explicit offsets.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def snapshot_from_dict(d: Mapping[str, Any]) -> ResourceSnapshot:
    return ResourceSnapshot(
        snapshot_id=str(d["snapshot_id"]),
        account_id=str(d["account_id"]),
        provider=Provider(d["provider"]),
        resource_type=ResourceType(d["resource_type"]),
        resource_id=str(d["resource_id"]),
        captured_at=_dt_from_iso(str(d["captured_at"])),
        metadata=d.get("metadata") or {},
    )


def rule_configs_from_dict(d: Mapping[str, Any]) -> list[RuleConfig]:
    rules = d.get("rules") or []
    out: list[RuleConfig] = []
    for r in rules:
        sev = r.get("severity_override")
        out.append(
            RuleConfig(
                rule_id=str(r["rule_id"]),
                enabled=bool(r.get("enabled", True)),
                severity_override=Severity(sev) if sev is not None else None,
                params=r.get("params"),
                suppressed=bool(r.get("suppressed", False)),
            )
        )
    return out


def _dt_to_iso(dt: datetime) -> str:
    return dt.isoformat()


def evaluation_result_to_dict(r: EvaluationResult) -> dict[str, Any]:
    return {
        "findings": [finding_to_dict(f) for f in r.findings],
        "stats": {
            "rules_evaluated": r.stats.rules_evaluated,
            "rules_failed": r.stats.rules_failed,
            "duration_ms": r.stats.duration_ms,
        },
        "errors": [evaluation_error_to_dict(e) for e in r.errors],
    }


def finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "finding_id": f.finding_id,
        "account_id": f.account_id,
        "resource_type": f.resource_type.value,
        "resource_id": f.resource_id,
        "rule_id": f.rule_id,
        "rule_version": f.rule_version,
        "severity": f.severity.value,
        "status": f.status.value,
        "title": f.title,
        "description": f.description,
        "evidence": evidence_to_dict(f.evidence),
        "remediation": remediation_to_dict(f.remediation),
        "detected_at": _dt_to_iso(f.detected_at),
    }


def evidence_to_dict(e: Evidence) -> dict[str, Any]:
    return {
        "summary": e.summary,
        "observations": [{"path": o.path, "value": o.value} for o in e.observations],
    }


def remediation_to_dict(r: Remediation) -> dict[str, Any]:
    return {
        "summary": r.summary,
        "steps": list(r.steps),
        "references": list(r.references),
    }


def evaluation_error_to_dict(e: EvaluationError) -> dict[str, Any]:
    return {
        "rule_id": e.rule_id,
        "error_code": e.error_code.value,
        "message": e.message,
        "snapshot_id": e.snapshot_id,
        "occurred_at": _dt_to_iso(e.occurred_at),
    }
