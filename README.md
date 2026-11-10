# trysac-tool-permission-policy

[![PyPI version](https://badge.fury.io/py/trysac-tool-permission-policy.svg)](https://badge.fury.io/py/trysac-tool-permission-policy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Versions](https://img.shields.io/pypi/pyversions/trysac-tool-permission-policy.svg)](https://pypi.org/project/trysac-tool-permission-policy/)

`tool_permission_policy` evaluates a JSON policy for agent tool calls. A policy has a default effect, rules with tool name globs, optional `when` context conditions and optional argument constraints. Missing or mistyped arguments fail closed on deny rules. Deny rules override allow and ask rules.

## Installation

```bash
pip install trysac-tool-permission-policy
```

## Usage

```python
from tool_permission_policy import load_policy_json

policy = load_policy_json(open("policy.json", "rb").read())
decision = policy.decide("fs.read", {"path": "/workspace/a.py"}, {"env": "dev"})
print(decision.effect, decision.rule_id, decision.reason)
```

Policy file example:

```json
{
  "version": 1,
  "default": "deny",
  "rules": [
    {
      "id": "workspace-read",
      "effect": "allow",
      "tools": ["fs.read"],
      "when": {"env": ["dev"]},
      "args": {"path": {"prefix": ["/workspace/"]}}
    }
  ]
}
```

CLI:

```bash
python -m tool_permission_policy --policy policy.json --tool fs.read \
  --args '{"path": "/workspace/a"}' --context '{}'
```

Exit codes: `0` = allow, `1` = deny or ask, `2` = usage, invalid arguments or invalid policy.

## Public API

- `load_policy(data: Mapping[str, Any]) -> Policy` validates a parsed policy mapping.
- `load_policy_json(text: str | bytes, *, max_bytes: int = 1_048_576) -> Policy` parses and validates JSON; `max_bytes` limits input size.
- `Policy.decide(tool: str, args: Mapping[str, Any], context: Mapping[str, str] | None = None, *, on_event: Callable[[dict[str, object]], None] | None = None) -> Decision` evaluates one call.
- `Decision(effect: Literal['allow', 'ask', 'deny'], rule_id: str | None, reason: Literal['matched', 'missing_argument', 'no_matching_rule'])` is frozen.
- `PolicyError(code: Literal['invalid_policy', 'too_large'], message: str)` is raised for invalid policy data or size limit violations.
- `on_event` receives `{'event': 'decision', 'tool': tool, 'effect': effect, 'rule_id': rule_id}` without argument values or context.

Limits: at most 1000 rules, 100 tool globs per rule, a regex `pattern` of at most 200 characters, and JSON nesting depth of at most 16. `load_policy_json` rejects input larger than `max_bytes` (default 1 MiB).

## Why not a tool allowlist or a general RBAC engine

A tool-name allowlist cannot express path prefixes, URL hosts, numeric maximums or value allowlists, and it fails open when an argument is missing. A general RBAC engine models roles and identities; roles and identity management are out of scope for this library. This utility evaluates argument-level constraints and applies fail-closed deny semantics for agent tool calls.

## Threat model

See [docs/SECURITY.md](docs/SECURITY.md).

## Development

The package has no runtime dependencies and imports only the standard library. Tests live in `tests/test_tool_permission_policy.py`.
