from __future__ import annotations

import argparse
import json
from pathlib import Path

from .builtins import default_registry
from .engine import PolicyEngine
from .repository import StaticPolicyRepository
from .serialization import evaluation_result_to_dict, rule_configs_from_dict, snapshot_from_dict


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
    p.add_argument("--pretty", action="store_true", help="Pretty-print output JSON.")
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
    out = evaluation_result_to_dict(result)

    if args.pretty:
        print(json.dumps(out, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
