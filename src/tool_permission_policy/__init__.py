"""Declarative allow, ask and deny policies for agent tool calls.

Evaluates a JSON policy with tool name globs, argument constraints and
context conditions. Deny rules override allow and ask, and missing or
mistyped arguments fail closed on deny rules.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import math
import posixpath
import re
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

__all__ = [
    "Decision",
    "Policy",
    "PolicyError",
    "__version__",
    "load_policy",
    "load_policy_json",
]

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

EffectLiteral = Literal["allow", "ask", "deny"]
ReasonLiteral = Literal["matched", "missing_argument", "no_matching_rule"]
ErrorCodeLiteral = Literal["invalid_policy", "too_large"]

_MAX_RULES = 1000
_MAX_GLOBS_PER_RULE = 100
_MAX_PATTERN_LENGTH = 200
_MAX_DEPTH = 16
_DEFAULT_MAX_BYTES = 1_048_576


class PolicyError(Exception):
    """Raised for invalid policy data or size limit violations."""

    def __init__(self, code: ErrorCodeLiteral, message: str) -> None:
        super().__init__(message)
        self.code: ErrorCodeLiteral = code
        self.message = message


@dataclass(frozen=True)
class Decision:
    """Result of evaluating a policy."""

    effect: EffectLiteral
    rule_id: str | None
    reason: ReasonLiteral


@dataclass(frozen=True)
class _Constraint:
    kind: str
    value: Any


@dataclass(frozen=True)
class _Rule:
    id: str
    effect: EffectLiteral
    tools: tuple[str, ...]
    when: Mapping[str, tuple[str, ...]]
    constraints: Mapping[str, _Constraint]


class Policy:
    """An immutable policy loaded from a mapping."""

    def __init__(
        self,
        default: EffectLiteral,
        rules: tuple[_Rule, ...],
    ) -> None:
        self._default = default
        self._rules = rules

    def decide(
        self,
        tool: str,
        args: Mapping[str, Any],
        context: Mapping[str, str] | None = None,
        *,
        on_event: Callable[[dict[str, object]], None] | None = None,
    ) -> Decision:
        """Evaluate the policy for a tool call.

        Args:
            tool: The tool name to match against rule globs.
            args: The call arguments, keyed by name.
            context: Optional context key/value pairs for ``when`` conditions.
            on_event: Optional callback receiving a decision event dict.

        Returns:
            A :class:`Decision` with the effect, matched rule id and reason.
        """
        ctx = context or {}
        first_allow: _Rule | None = None
        first_ask: _Rule | None = None

        for rule in self._rules:
            if not self._rule_applies(rule, tool, ctx):
                continue

            constraint_results = [
                self._eval_constraint(rule.constraints[name], args.get(name))
                for name in rule.constraints
            ]

            if rule.effect == "deny":
                if all(res is not False for res in constraint_results):
                    reason: ReasonLiteral = (
                        "missing_argument"
                        if any(res is None for res in constraint_results)
                        else "matched"
                    )
                    decision = Decision(rule.effect, rule.id, reason)
                    if on_event:
                        on_event(
                            {
                                "event": "decision",
                                "tool": tool,
                                "effect": decision.effect,
                                "rule_id": decision.rule_id,
                            }
                        )
                    return decision
            elif rule.effect == "ask":
                if all(res is True for res in constraint_results) and first_ask is None:
                    first_ask = rule
            else:  # allow
                if all(res is True for res in constraint_results) and first_allow is None:
                    first_allow = rule

        matched_rule: _Rule | None = first_ask if first_ask else first_allow
        if matched_rule:
            decision = Decision(matched_rule.effect, matched_rule.id, "matched")
        else:
            decision = Decision(self._default, None, "no_matching_rule")

        if on_event:
            on_event(
                {
                    "event": "decision",
                    "tool": tool,
                    "effect": decision.effect,
                    "rule_id": decision.rule_id,
                }
            )
        return decision

    @staticmethod
    def _rule_applies(rule: _Rule, tool: str, context: Mapping[str, str]) -> bool:
        if not any(fnmatch.fnmatchcase(tool, pattern) for pattern in rule.tools):
            return False
        for key, allowed_values in rule.when.items():
            if key not in context:
                return False
            if context[key] not in allowed_values:
                return False
        return True

    @staticmethod
    def _eval_constraint(constraint: _Constraint, arg: Any) -> bool | None:
        """Evaluate a single constraint, returning True, False or None (Unknown)."""
        if arg is None:
            return None
        kind = constraint.kind
        value = constraint.value

        if kind == "one_of":
            if not isinstance(arg, (str, int, float, bool, type(None))):
                return None
            return any(type(arg) is type(candidate) and arg == candidate for candidate in value)

        if kind == "prefix":
            if not isinstance(arg, str):
                return None
            if "\x00" in arg or "\\" in arg:
                return False
            normalized = posixpath.normpath(arg)
            for prefix in value:
                if normalized == prefix[:-1] or normalized.startswith(prefix):
                    return True
            return False

        if kind == "max":
            if not isinstance(arg, (int, float)) or isinstance(arg, bool):
                return None
            if isinstance(arg, float) and not math.isfinite(arg):
                return None
            return bool(arg <= value)

        if kind == "host":
            if not isinstance(arg, str):
                return None
            try:
                parsed = urllib.parse.urlsplit(arg)
            except ValueError:
                return False
            if parsed.scheme not in ("http", "https"):
                return False
            if parsed.username is not None or parsed.password is not None:
                return False
            hostname = parsed.hostname
            if hostname is None:
                return False
            return hostname.lower() in value

        if kind == "pattern":
            if not isinstance(arg, str):
                return None
            return value.fullmatch(arg) is not None

        # Should never happen if validation is correct
        return None


def _validate_effect(value: Any, path: str) -> EffectLiteral:
    if not isinstance(value, str) or value not in ("allow", "ask", "deny"):
        raise PolicyError("invalid_policy", f"{path}: effect must be 'allow', 'ask' or 'deny'")
    return value  # type: ignore[return-value]


def _validate_constraint(
    name: str,
    spec: Any,
    path: str,
) -> _Constraint:
    if name == "one_of":
        if not isinstance(spec, list) or len(spec) == 0:
            raise PolicyError("invalid_policy", f"{path}: one_of requires a non-empty list")
        for item in spec:
            if not isinstance(item, (str, int, float, bool, type(None))):
                raise PolicyError("invalid_policy", f"{path}: one_of items must be JSON scalars")
        return _Constraint("one_of", spec)

    if name == "prefix":
        if not isinstance(spec, list) or len(spec) == 0:
            raise PolicyError("invalid_policy", f"{path}: prefix requires a non-empty list")
        for prefix in spec:
            if not isinstance(prefix, str):
                raise PolicyError("invalid_policy", f"{path}: prefix items must be strings")
            if not prefix.startswith("/") or not prefix.endswith("/"):
                raise PolicyError("invalid_policy", f"{path}: prefix must start and end with '/")
            if "\x00" in prefix or "\\" in prefix:
                raise PolicyError(
                    "invalid_policy", f"{path}: prefix must not contain NUL or backslash"
                )
        return _Constraint("prefix", spec)

    if name == "max":
        if not isinstance(spec, (int, float)) or isinstance(spec, bool):
            raise PolicyError("invalid_policy", f"{path}: max must be an int or float")
        if isinstance(spec, float) and not math.isfinite(spec):
            raise PolicyError("invalid_policy", f"{path}: max must be finite")
        return _Constraint("max", spec)

    if name == "host":
        if not isinstance(spec, list) or len(spec) == 0:
            raise PolicyError("invalid_policy", f"{path}: host requires a non-empty list")
        for host in spec:
            if not isinstance(host, str) or host == "":
                raise PolicyError("invalid_policy", f"{path}: host items must be non-empty strings")
            if host != host.lower():
                raise PolicyError("invalid_policy", f"{path}: host must be lowercase")
        return _Constraint("host", spec)

    if name == "pattern":
        if not isinstance(spec, str):
            raise PolicyError("invalid_policy", f"{path}: pattern must be a string")
        if len(spec) > _MAX_PATTERN_LENGTH:
            raise PolicyError(
                "invalid_policy", f"{path}: pattern exceeds {_MAX_PATTERN_LENGTH} characters"
            )
        try:
            compiled = re.compile(spec)
        except re.error as exc:
            raise PolicyError("invalid_policy", f"{path}: invalid regex: {exc}") from exc
        return _Constraint("pattern", compiled)

    raise PolicyError("invalid_policy", f"{path}: unknown constraint {name}")


def _check_depth(value: Any, depth: int = 1) -> None:
    """Ensure the parsed policy does not exceed the maximum JSON nesting depth."""
    if depth > _MAX_DEPTH:
        raise PolicyError("invalid_policy", f"policy JSON exceeds maximum depth {_MAX_DEPTH}")
    if isinstance(value, Mapping):
        for item in value.values():
            _check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, depth + 1)


def load_policy(data: Mapping[str, Any]) -> Policy:
    """Load and validate a policy from a mapping.

    Args:
        data: The policy as a parsed JSON object (or any mapping).

    Returns:
        A validated :class:`Policy`.

    Raises:
        PolicyError: if the policy is invalid.
    """
    if not isinstance(data, Mapping):
        raise PolicyError("invalid_policy", "policy must be an object")

    _check_depth(data)

    # version
    version = data.get("version")
    if version != 1:
        raise PolicyError("invalid_policy", "version must be 1")

    # default
    default = data.get("default")
    if not isinstance(default, str) or default not in ("allow", "ask", "deny"):
        raise PolicyError("invalid_policy", "default must be 'allow', 'ask' or 'deny'")

    # rules
    rules_data = data.get("rules")
    if not isinstance(rules_data, list):
        raise PolicyError("invalid_policy", "rules must be a list")
    if len(rules_data) > _MAX_RULES:
        raise PolicyError("invalid_policy", f"too many rules (max {_MAX_RULES})")

    rules: list[_Rule] = []
    seen_ids: set[str] = set()

    for idx, rule_data in enumerate(rules_data):
        rule_path = f"rules[{idx}]"
        if not isinstance(rule_data, Mapping):
            raise PolicyError("invalid_policy", f"{rule_path}: rule must be an object")

        rule_id = rule_data.get("id")
        if not isinstance(rule_id, str) or not (1 <= len(rule_id) <= 64):
            raise PolicyError(
                "invalid_policy", f"{rule_path}: id must be a string of 1-64 characters"
            )
        if rule_id in seen_ids:
            raise PolicyError("invalid_policy", f"{rule_path}: duplicate rule id {rule_id!r}")
        seen_ids.add(rule_id)

        effect = _validate_effect(rule_data.get("effect"), rule_path)

        tools_data = rule_data.get("tools")
        if not isinstance(tools_data, list) or len(tools_data) == 0:
            raise PolicyError("invalid_policy", f"{rule_path}: tools must be a non-empty list")
        if len(tools_data) > _MAX_GLOBS_PER_RULE:
            raise PolicyError(
                "invalid_policy",
                f"{rule_path}: too many globs (max {_MAX_GLOBS_PER_RULE})",
            )
        tools: list[str] = []
        for glob_idx, glob in enumerate(tools_data):
            if not isinstance(glob, str) or glob == "":
                raise PolicyError(
                    "invalid_policy", f"{rule_path}.tools[{glob_idx}] must be a non-empty string"
                )
            tools.append(glob)

        when_data = rule_data.get("when", {})
        if not isinstance(when_data, Mapping):
            raise PolicyError("invalid_policy", f"{rule_path}: when must be an object")
        when: dict[str, tuple[str, ...]] = {}
        for key, allowed_values in when_data.items():
            if not isinstance(key, str):
                raise PolicyError("invalid_policy", f"{rule_path}.when: keys must be strings")
            if not isinstance(allowed_values, list):
                raise PolicyError("invalid_policy", f"{rule_path}.when.{key}: must be a list")
            values_tuple: list[str] = []
            for val in allowed_values:
                if not isinstance(val, str):
                    raise PolicyError(
                        "invalid_policy", f"{rule_path}.when.{key}: items must be strings"
                    )
                values_tuple.append(val)
            when[key] = tuple(values_tuple)

        args_data = rule_data.get("args", {})
        if not isinstance(args_data, Mapping):
            raise PolicyError("invalid_policy", f"{rule_path}: args must be an object")
        constraints: dict[str, _Constraint] = {}
        for arg_name, constraint_dict in args_data.items():
            if not isinstance(arg_name, str):
                raise PolicyError(
                    "invalid_policy", f"{rule_path}.args: argument names must be strings"
                )
            if not isinstance(constraint_dict, Mapping):
                raise PolicyError(
                    "invalid_policy", f"{rule_path}.args.{arg_name}: must be an object"
                )
            if len(constraint_dict) != 1:
                raise PolicyError(
                    "invalid_policy",
                    f"{rule_path}.args.{arg_name}: exactly one constraint required",
                )
            constraint_name, constraint_spec = next(iter(constraint_dict.items()))
            if not isinstance(constraint_name, str):
                raise PolicyError(
                    "invalid_policy",
                    f"{rule_path}.args.{arg_name}: constraint name must be a string",
                )
            constraints[arg_name] = _validate_constraint(
                constraint_name,
                constraint_spec,
                f"{rule_path}.args.{arg_name}",
            )

        rules.append(
            _Rule(
                id=rule_id,
                effect=effect,
                tools=tuple(tools),
                when=when,
                constraints=constraints,
            )
        )

    return Policy(default=default, rules=tuple(rules))  # type: ignore[arg-type]


def load_policy_json(
    text: str | bytes,
    *,
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> Policy:
    """Parse and load a policy from a JSON string or bytes.

    Args:
        text: JSON text or bytes.
        max_bytes: Maximum size of the input in bytes.

    Returns:
        A validated :class:`Policy`.

    Raises:
        PolicyError: if the JSON is invalid, too large, or the policy is invalid.
    """
    if isinstance(text, bytes):
        if len(text) > max_bytes:
            raise PolicyError("too_large", f"policy JSON exceeds {max_bytes} bytes")
        try:
            text_str = text.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError("invalid_policy", "policy JSON is not valid UTF-8") from exc
    elif isinstance(text, str):
        encoded = text.encode("utf-8")
        if len(encoded) > max_bytes:
            raise PolicyError("too_large", f"policy JSON exceeds {max_bytes} bytes")
        text_str = text
    else:
        raise PolicyError("invalid_policy", "policy text must be str or bytes")

    try:
        data = json.loads(text_str)
    except json.JSONDecodeError as exc:
        raise PolicyError("invalid_policy", "policy JSON is malformed") from exc
    except RecursionError as exc:
        raise PolicyError("invalid_policy", "policy JSON is nested too deeply") from exc

    return load_policy(data)
