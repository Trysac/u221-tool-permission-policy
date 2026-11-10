# Testing

## Running

Run the checked-in test module with pytest:

```sh
pytest tests/test_tool_permission_policy.py
```

## Policy

`tests/test_tool_permission_policy.py` is the checked-in test module. It contains unit tests covering:

- `test_version`: the module exposes `__version__` as a string.
- `test_load_policy_minimal`: a minimal policy loads and evaluates a decision.
- `test_load_policy_json_accepts_bytes`: `load_policy_json` accepts bytes input.
- `test_load_policy_json_size_limit`: `max_bytes` rejects oversized input with `PolicyError` code `too_large` and accepts the exact limit.
- `test_load_policy_json_malformed`: malformed JSON raises `PolicyError` code `invalid_policy`.
- `test_load_policy_invalid_version`: an invalid policy version raises `PolicyError` code `invalid_policy`.
- `test_load_policy_invalid_default`: an invalid default effect raises `PolicyError` code `invalid_policy`.
- `test_load_policy_unknown_constraint`: an unknown argument constraint raises `PolicyError` with a message containing the constraint path and name.

## Tiers

The repository listing contains a single test module. No separate local/CI tiers, conformance test files or shared fixtures are present in the listing.

## Layout

`tests/test_tool_permission_policy.py` mirrors the public package module `tool_permission_policy`.
