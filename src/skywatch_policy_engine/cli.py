from __future__ import annotations

import argparse
import json
from pathlib import Path

from .builtins import default_registry
from .engine import PolicyEngine
from .repository import StaticPolicyRepository
from .serialization import evaluation_result_to_dict, rule_configs_from_dict, snapshot_from_dict
from .types import EvaluationResult


def _format_result_text(result: EvaluationResult) -> str:
    """Format evaluation result as human-readable text."""
    lines: list[str] = []
    sep = "─" * 60
    lines.append("")
    lines.append("  SkyWatch Policy Evaluation")
    lines.append(sep)
    s = result.stats
    lines.append(f"  Rules evaluated: {s.rules_evaluated}  |  Rules with errors: {s.rules_failed}  |  Duration: {s.duration_ms} ms")
    lines.append(f"  Findings: {len(result.findings)}  |  Errors: {len(result.errors)}")
    lines.append("")

    if result.errors:
        lines.append("  Errors")
        lines.append("  " + "─" * 40)
        for e in result.errors:
            lines.append(f"    [{e.rule_id}] {e.error_code.value}: {e.message}")
        lines.append("")

    if not result.findings:
        lines.append("  No findings.")
        lines.append("")
        return "\n".join(lines)

    lines.append("  Findings")
    lines.append("  " + "─" * 40)
    for i, f in enumerate(result.findings, 1):
        lines.append("")
        lines.append(f"  [{i}] {f.title}")
        lines.append(f"      Rule: {f.rule_id}  |  Severity: {f.severity.value}  |  Resource: {f.resource_id}")
        lines.append(f"      {f.description}")
        lines.append(f"      Evidence: {f.evidence.summary}")
        if f.remediation.steps:
            lines.append("      Remediation:")
            for step in f.remediation.steps:
                lines.append(f"        • {step}")
        if f.remediation.references:
            lines.append("      References:")
            for ref in f.remediation.references:
                lines.append(f"        {ref}")
        lines.append("")

    lines.append(sep)
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="skywatch-eval",
        description="Evaluate a normalized ResourceSnapshot using SkyWatch policy rules.",
    )
    p.add_argument(
        "--snapshot",
        required=True,
        type=Path,
        help="Path to snapshot JSON (normalized ResourceSnapshot).",
    )
    p.add_argument(
        "--policies",
        required=True,
        type=Path,
        help="Path to policies JSON (enabled rules, overrides, suppression).",
    )
    p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format: text (readable summary) or json. Default: text.",
    )
    p.add_argument("--pretty", action="store_true", help="Pretty-print output JSON (only with --format json).")
    args = p.parse_args(argv)

    snapshot_data = json.loads(args.snapshot.read_text(encoding="utf-8"))
    policies_data = json.loads(args.policies.read_text(encoding="utf-8"))

    snapshot = snapshot_from_dict(snapshot_data)
    rule_configs = rule_configs_from_dict(policies_data)

    engine = PolicyEngine(
        repository=StaticPolicyRepository(tuple(rule_configs)),
        registry=default_registry(),
    )

    result = engine.evaluate(snapshot)

    if args.format == "text":
        print(_format_result_text(result))
    else:
        out = evaluation_result_to_dict(result)
        if args.pretty:
            print(json.dumps(out, indent=2, ensure_ascii=False, sort_keys=True))
        else:
            print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
