# Architecture

`tool_permission_policy` is a small library with no runtime dependencies. The core modules are:

- `tool_permission_policy/__init__.py`: policy loading, validation, and evaluation.
- `tool_permission_policy/__main__.py`: command-line interface.

## Policy representation

A policy is an immutable object (`Policy`) containing a tuple of `_Rule` objects. Each `_Rule` stores its id, effect, tool globs, `when` conditions, and a mapping of argument constraints. Constraints are validated at load time and stored as `_Constraint` instances, with regex patterns compiled once.

## Evaluation algorithm

For a tool call, the policy iterates rules in order:

1. Skip rules whose tool glob does not match or whose `when` conditions do not hold.
2. Evaluate each argument constraint, yielding `True`, `False`, or `Unknown` (missing or wrong-typed argument).
3. For `deny` rules: match if no constraint is `False`; if any is `Unknown`, set reason to `missing_argument`. The first matching deny rule is returned immediately.
4. For `allow` and `ask` rules: match only if all constraints are `True`. The first matching `ask` and first matching `allow` are remembered.
5. After all rules: return the first `ask` if any, else the first `allow`, else the policy default with `rule_id=None` and `reason='no_matching_rule'`.

## CLI

The CLI loads a policy file, parses JSON arguments and context, evaluates the tool call, prints the decision as a JSON object with sorted keys, and exits with code 0 for allow, 1 for deny or ask, and 2 for any error.
