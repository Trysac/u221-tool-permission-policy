"""Command-line interface for evaluating a policy."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import PolicyError, load_policy_json


def main(argv: list[str] | None = None) -> int:
    """Run the CLI.

    Args:
        argv: Optional argument vector; defaults to ``sys.argv[1:]``.

    Returns:
        Exit code: 0 for allow, 1 for deny or ask, 2 for usage/invalid policy.
    """
    parser = argparse.ArgumentParser(
        prog="python -m tool_permission_policy",
        description="Evaluate a tool call against a permission policy",
    )
    parser.add_argument("--policy", required=True, help="Path to policy JSON file")
    parser.add_argument("--tool", required=True, help="Tool name")
    parser.add_argument("--args", required=True, help="JSON object of tool arguments")
    parser.add_argument("--context", default="{}", help="JSON object of context strings")

    try:
        ns = parser.parse_args(argv)
    except SystemExit:
        return 2

    # Load policy file
    try:
        with open(ns.policy, "rb") as f:
            policy_text = f.read()
        policy = load_policy_json(policy_text)
    except (PolicyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Parse JSON arguments
    try:
        args_data = json.loads(ns.args)
        if not isinstance(args_data, dict):
            raise ValueError("--args must be a JSON object")
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"error: invalid --args: {exc}", file=sys.stderr)
        return 2

    try:
        context_data = json.loads(ns.context)
        if not isinstance(context_data, dict):
            raise ValueError("--context must be a JSON object")
        if not all(isinstance(v, str) for v in context_data.values()):
            raise ValueError("--context values must be strings")
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"error: invalid --context: {exc}", file=sys.stderr)
        return 2

    # Evaluate
    try:
        decision = policy.decide(ns.tool, args_data, context_data)
    except Exception as exc:
        print(f"error: evaluation failed: {exc}", file=sys.stderr)
        return 2

    decision_dict: dict[str, Any] = {
        "effect": decision.effect,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
    }
    print(json.dumps(decision_dict, sort_keys=True))

    return 0 if decision.effect == "allow" else 1


if __name__ == "__main__":
    sys.exit(main())
