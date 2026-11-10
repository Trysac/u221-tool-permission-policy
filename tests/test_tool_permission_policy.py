"""Tests for tool_permission_policy."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tool_permission_policy import (
    Decision,
    Policy,
    PolicyError,
    __version__,
    load_policy,
    load_policy_json,
)


def test_version() -> None:
    assert isinstance(__version__, str)
    assert __version__ != ""


def test_load_policy_minimal() -> None:
    policy = load_policy({"version": 1, "default": "deny", "rules": []})
    assert isinstance(policy, Policy)
    assert policy.decide("anything", {}, {}) == Decision("deny", None, "no_matching_rule")


def test_load_policy_json_accepts_bytes() -> None:
    data = b'{"version": 1, "default": "allow", "rules": []}'
    policy = load_policy_json(data)
    assert policy.decide("tool", {}, {}) == Decision("allow", None, "no_matching_rule")


def test_load_policy_json_size_limit() -> None:
    # max_bytes default 1_048_576; create a policy exactly at limit
    json_text = '{"version": 1, "default": "deny", "rules": []}'
    filler = " " * (1_048_576 - len(json_text.encode("utf-8")))
    policy_text = json_text + filler
    assert len(policy_text.encode("utf-8")) == 1_048_576
    policy = load_policy_json(policy_text, max_bytes=1_048_576)
    assert policy is not None

    # one byte over
    with pytest.raises(PolicyError) as exc_info:
        load_policy_json(policy_text + " ", max_bytes=1_048_576)
    assert exc_info.value.code == "too_large"


def test_load_policy_json_malformed() -> None:
    with pytest.raises(PolicyError) as exc_info:
        load_policy_json(b"not json")
    assert exc_info.value.code == "invalid_policy"


def test_load_policy_invalid_version() -> None:
    with pytest.raises(PolicyError) as exc_info:
        load_policy({"version": 2, "default": "deny", "rules": []})
    assert exc_info.value.code == "invalid_policy"


def test_load_policy_invalid_default() -> None:
    with pytest.raises(PolicyError) as exc_info:
        load_policy({"version": 1, "default": "maybe", "rules": []})
    assert exc_info.value.code == "invalid_policy"


def test_load_policy_unknown_constraint() -> None:
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "r1",
                "effect": "allow",
                "tools": ["fs.*"],
                "args": {"path": {"startswith": "/workspace/"}},
            }
        ],
    }
    with pytest.raises(PolicyError) as exc_info:
        load_policy(policy_data)
    assert exc_info.value.code == "invalid_policy"
    assert "rules[0].args.path" in exc_info.value.message
    assert "unknown constraint startswith" in exc_info.value.message


def test_load_policy_unknown_constraint_exact_message() -> None:
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "r1",
                "effect": "allow",
                "tools": ["fs.*"],
                "args": {"path": {"startswith": "/workspace/"}},
            }
        ],
    }
    with pytest.raises(PolicyError) as exc_info:
        load_policy(policy_data)
    assert exc_info.value.message == "rules[0].args.path: unknown constraint startswith"


def test_load_policy_duplicate_rule_id() -> None:
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {"id": "dup", "effect": "allow", "tools": ["*"], "args": {}},
            {"id": "dup", "effect": "deny", "tools": ["*"], "args": {}},
        ],
    }
    with pytest.raises(PolicyError) as exc_info:
        load_policy(policy_data)
    assert exc_info.value.code == "invalid_policy"


def test_load_policy_invalid_effect() -> None:
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [{"id": "r1", "effect": "maybe", "tools": ["*"], "args": {}}],
    }
    with pytest.raises(PolicyError) as exc_info:
        load_policy(policy_data)
    assert exc_info.value.code == "invalid_policy"


def test_load_policy_too_many_rules() -> None:
    rules = [{"id": f"r{i}", "effect": "allow", "tools": ["*"], "args": {}} for i in range(1001)]
    with pytest.raises(PolicyError) as exc_info:
        load_policy({"version": 1, "default": "deny", "rules": rules})
    assert exc_info.value.code == "invalid_policy"


def test_load_policy_too_many_globs() -> None:
    globs = [f"glob{i}" for i in range(101)]
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [{"id": "r1", "effect": "allow", "tools": globs, "args": {}}],
    }
    with pytest.raises(PolicyError) as exc_info:
        load_policy(policy_data)
    assert exc_info.value.code == "invalid_policy"


def test_load_policy_pattern_too_long() -> None:
    long_pattern = "a" * 201
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "r1",
                "effect": "deny",
                "tools": ["*"],
                "args": {"path": {"pattern": long_pattern}},
            }
        ],
    }
    with pytest.raises(PolicyError) as exc_info:
        load_policy(policy_data)
    assert exc_info.value.code == "invalid_policy"


def test_load_policy_invalid_regex() -> None:
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "r1",
                "effect": "deny",
                "tools": ["*"],
                "args": {"path": {"pattern": "(["}},
            }
        ],
    }
    with pytest.raises(PolicyError) as exc_info:
        load_policy(policy_data)
    assert exc_info.value.code == "invalid_policy"


def test_load_policy_multiple_constraints_on_arg() -> None:
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "r1",
                "effect": "allow",
                "tools": ["*"],
                "args": {"x": {"max": 10, "one_of": [1, 2]}},
            }
        ],
    }
    with pytest.raises(PolicyError) as exc_info:
        load_policy(policy_data)
    assert exc_info.value.code == "invalid_policy"


# --- Acceptance scenario 1 ---
def _policy_acceptance() -> Policy:
    data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "r1",
                "effect": "allow",
                "tools": ["fs.read"],
                "args": {"path": {"prefix": ["/workspace/"]}},
            },
            {
                "id": "r2",
                "effect": "deny",
                "tools": ["fs.*"],
                "args": {"path": {"pattern": ".*[.]env"}},
            },
            {
                "id": "r3",
                "effect": "ask",
                "tools": ["http.post"],
                "args": {"url": {"host": ["api.example.com"]}},
            },
        ],
    }
    return load_policy(data)


def test_acceptance_allow_rule_matches() -> None:
    policy = _policy_acceptance()
    decision = policy.decide("fs.read", {"path": "/workspace/src/a.py"}, {})
    assert decision == Decision("allow", "r1", "matched")


def test_acceptance_path_traversal_normalized() -> None:
    policy = _policy_acceptance()
    decision = policy.decide("fs.read", {"path": "/workspace/../etc/passwd"}, {})
    assert decision == Decision("deny", None, "no_matching_rule")


def test_acceptance_deny_overrides_allow() -> None:
    policy = _policy_acceptance()
    decision = policy.decide("fs.read", {"path": "/workspace/.env"}, {})
    assert decision.effect == "deny"
    assert decision.rule_id == "r2"
    assert decision.reason == "matched"

    decision_missing = policy.decide("fs.read", {}, {})
    assert decision_missing.effect == "deny"
    assert decision_missing.rule_id == "r2"
    assert decision_missing.reason == "missing_argument"


def test_acceptance_host_constraint() -> None:
    policy = _policy_acceptance()
    decision1 = policy.decide("http.post", {"url": "https://api.example.com/v1"}, {})
    assert decision1 == Decision("ask", "r3", "matched")

    decision2 = policy.decide("http.post", {"url": "http://API.EXAMPLE.COM"}, {})
    assert decision2 == Decision("ask", "r3", "matched")

    decision3 = policy.decide("http.post", {"url": "https://api.example.com.evil.io/"}, {})
    assert decision3 == Decision("deny", None, "no_matching_rule")

    decision4 = policy.decide("http.post", {"url": "https://user@api.example.com/"}, {})
    assert decision4 == Decision("deny", None, "no_matching_rule")


def test_acceptance_when_condition() -> None:
    policy = load_policy(
        {
            "version": 1,
            "default": "deny",
            "rules": [
                {
                    "id": "r1",
                    "effect": "allow",
                    "tools": ["fs.read"],
                    "when": {"env": ["dev"]},
                    "args": {"path": {"prefix": ["/workspace/"]}},
                }
            ],
        }
    )
    # context present and matching
    assert policy.decide("fs.read", {"path": "/workspace/a"}, {"env": "dev"}) == Decision(
        "allow", "r1", "matched"
    )
    # context missing
    decision = policy.decide("fs.read", {"path": "/workspace/a"}, {})
    assert decision == Decision("deny", None, "no_matching_rule")
    # context wrong
    decision = policy.decide("fs.read", {"path": "/workspace/a"}, {"env": "prod"})
    assert decision == Decision("deny", None, "no_matching_rule")


def test_acceptance_max_constraint() -> None:
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "r1",
                "effect": "allow",
                "tools": ["*"],
                "args": {"n": {"max": 100}},
            }
        ],
    }
    policy = load_policy(policy_data)
    assert policy.decide("tool", {"n": 100}, {}) == Decision("allow", "r1", "matched")
    assert policy.decide("tool", {"n": 100.5}, {}) == Decision("deny", None, "no_matching_rule")
    assert policy.decide("tool", {"n": True}, {}) == Decision("deny", None, "no_matching_rule")


def test_on_event_callback() -> None:
    policy = _policy_acceptance()
    events: list[dict[str, object]] = []
    decision = policy.decide(
        "fs.read",
        {"path": "/workspace/a"},
        {},
        on_event=events.append,
    )
    assert decision.effect == "allow"
    assert len(events) == 1
    event = events[0]
    assert event["event"] == "decision"
    assert event["tool"] == "fs.read"
    assert event["effect"] == "allow"
    assert event["rule_id"] == "r1"
    assert "args" not in event
    assert "context" not in event


def test_main_cli_allow(capsys: pytest.CaptureFixture[str], tmp_path: Any) -> None:
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "r1",
                "effect": "allow",
                "tools": ["fs.read"],
                "args": {"path": {"prefix": ["/workspace/"]}},
            }
        ],
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy_data))

    from tool_permission_policy.__main__ import main

    args_json = json.dumps({"path": "/workspace/a"})
    rc = main(
        [
            "--policy",
            str(policy_path),
            "--tool",
            "fs.read",
            "--args",
            args_json,
            "--context",
            "{}",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 0
    decision = json.loads(captured.out.strip())
    assert decision["effect"] == "allow"
    assert decision["rule_id"] == "r1"
    assert decision["reason"] == "matched"


def test_main_cli_policy_path_literal(
    capsys: pytest.CaptureFixture[str], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_data = {"version": 1, "default": "allow", "rules": []}
    (tmp_path / "p.json").write_text(json.dumps(policy_data))
    monkeypatch.chdir(tmp_path)

    from tool_permission_policy.__main__ import main

    rc = main(
        [
            "--policy",
            "p.json",
            "--tool",
            "fs.read",
            "--args",
            '{"path": "/workspace/a"}',
        ]
    )
    captured = capsys.readouterr()
    assert rc == 0
    decision = json.loads(captured.out.strip())
    assert decision["effect"] == "allow"
    assert decision["rule_id"] is None
    assert decision["reason"] == "no_matching_rule"


def test_main_cli_deny(capsys: pytest.CaptureFixture[str], tmp_path: Any) -> None:
    policy_data = {"version": 1, "default": "deny", "rules": []}
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy_data))

    from tool_permission_policy.__main__ import main

    rc = main(
        [
            "--policy",
            str(policy_path),
            "--tool",
            "anything",
            "--args",
            "{}",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 1
    decision = json.loads(captured.out.strip())
    assert decision["effect"] == "deny"
    assert decision["rule_id"] is None
    assert decision["reason"] == "no_matching_rule"


def test_main_cli_invalid_policy(capsys: pytest.CaptureFixture[str], tmp_path: Any) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("not json")

    from tool_permission_policy.__main__ import main

    rc = main(
        [
            "--policy",
            str(policy_path),
            "--tool",
            "anything",
            "--args",
            "{}",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 2
    assert "error" in captured.err


def test_main_cli_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    from tool_permission_policy.__main__ import main

    rc = main([])
    captured = capsys.readouterr()
    assert rc == 2
    assert "usage" in captured.err.lower()


def test_main_cli_invalid_args_json(capsys: pytest.CaptureFixture[str], tmp_path: Any) -> None:
    policy_data = {"version": 1, "default": "deny", "rules": []}
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy_data))

    from tool_permission_policy.__main__ import main

    rc = main(
        [
            "--policy",
            str(policy_path),
            "--tool",
            "anything",
            "--args",
            "not json",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 2
    assert "invalid --args" in captured.err


def test_main_cli_invalid_context_json(capsys: pytest.CaptureFixture[str], tmp_path: Any) -> None:
    policy_data = {"version": 1, "default": "deny", "rules": []}
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy_data))

    from tool_permission_policy.__main__ import main

    rc = main(
        [
            "--policy",
            str(policy_path),
            "--tool",
            "anything",
            "--args",
            "{}",
            "--context",
            "not json",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 2
    assert "invalid --context" in captured.err


def test_max_constraint_unknown_on_bool() -> None:
    # bool is not allowed for max, so argument should be Unknown -> deny rule matches with missing_argument
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "r1",
                "effect": "deny",
                "tools": ["*"],
                "args": {"n": {"max": 10}},
            }
        ],
    }
    policy = load_policy(policy_data)
    decision = policy.decide("tool", {"n": True}, {})
    assert decision.effect == "deny"
    assert decision.rule_id == "r1"
    assert decision.reason == "missing_argument"


def test_one_of_type_sensitivity() -> None:
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "r1",
                "effect": "allow",
                "tools": ["*"],
                "args": {"x": {"one_of": [1, "1"]}},
            }
        ],
    }
    policy = load_policy(policy_data)
    # int 1 matches int 1
    assert policy.decide("tool", {"x": 1}, {}) == Decision("allow", "r1", "matched")
    # bool True not match int 1
    assert policy.decide("tool", {"x": True}, {}) == Decision("deny", None, "no_matching_rule")
    # str "1" matches str "1"
    assert policy.decide("tool", {"x": "1"}, {}) == Decision("allow", "r1", "matched")


def test_prefix_nul_and_backslash() -> None:
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "r1",
                "effect": "allow",
                "tools": ["*"],
                "args": {"path": {"prefix": ["/safe/"]}},
            }
        ],
    }
    policy = load_policy(policy_data)
    # NUL in path -> False -> allow rule not match
    decision = policy.decide("tool", {"path": "/safe/\x00evil"}, {})
    assert decision == Decision("deny", None, "no_matching_rule")
    # backslash -> False
    decision = policy.decide("tool", {"path": "/safe/\\evil"}, {})
    assert decision == Decision("deny", None, "no_matching_rule")


def test_host_port_ignored() -> None:
    policy_data = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "r1",
                "effect": "allow",
                "tools": ["*"],
                "args": {"url": {"host": ["example.com"]}},
            }
        ],
    }
    policy = load_policy(policy_data)
    assert policy.decide("tool", {"url": "https://example.com:8443/path"}, {}) == Decision(
        "allow", "r1", "matched"
    )


def test_edge_default_ask_no_matching_rule() -> None:
    policy = load_policy({"version": 1, "default": "ask", "rules": []})
    assert policy.decide("unknown.tool", {}, {}) == Decision("ask", None, "no_matching_rule")


def test_edge_two_deny_rules_first_wins() -> None:
    policy = load_policy(
        {
            "version": 1,
            "default": "allow",
            "rules": [
                {"id": "r1", "effect": "deny", "tools": ["fs.*"]},
                {"id": "r2", "effect": "deny", "tools": ["fs.read"]},
            ],
        }
    )
    decision = policy.decide("fs.read", {}, {})
    assert decision.effect == "deny"
    assert decision.rule_id == "r1"


def test_edge_allow_rule_without_constraints_empty_args() -> None:
    policy = load_policy(
        {
            "version": 1,
            "default": "deny",
            "rules": [{"id": "r1", "effect": "allow", "tools": ["fs.read"]}],
        }
    )
    assert policy.decide("fs.read", {}, {}) == Decision("allow", "r1", "matched")


def test_load_policy_exceeds_max_depth() -> None:
    value: Any = []
    for _ in range(20):
        value = [value]
    data = {"version": 1, "default": "deny", "rules": [], "extra": value}
    with pytest.raises(PolicyError) as exc_info:
        load_policy(data)
    assert exc_info.value.code == "invalid_policy"


def test_load_policy_json_recursion_rejected() -> None:
    with pytest.raises(PolicyError) as exc_info:
        load_policy_json("[" * 500_000)
    assert exc_info.value.code == "invalid_policy"


def test_max_constraint_large_int_argument() -> None:
    policy = load_policy(
        {
            "version": 1,
            "default": "deny",
            "rules": [{"id": "r1", "effect": "allow", "tools": ["*"], "args": {"n": {"max": 100}}}],
        }
    )
    assert policy.decide("tool", {"n": 10**400}, {}) == Decision("deny", None, "no_matching_rule")


def test_load_policy_max_large_int() -> None:
    policy = load_policy(
        {
            "version": 1,
            "default": "deny",
            "rules": [
                {
                    "id": "r1",
                    "effect": "allow",
                    "tools": ["*"],
                    "args": {"n": {"max": 10**400}},
                }
            ],
        }
    )
    assert policy.decide("tool", {"n": 10**401}, {}) == Decision("deny", None, "no_matching_rule")
    assert policy.decide("tool", {"n": 5}, {}) == Decision("allow", "r1", "matched")
