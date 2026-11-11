# Project record

## Objective

Declarative allow, ask and deny policies for agent tool calls: tool name globs, argument constraints on paths, hosts, values and numbers, context conditions and fail-closed deny.

## Scope

In scope:

- The public API in `tool_permission_policy`: `load_policy`, `load_policy_json`, `Policy.decide`, `Decision` and `PolicyError`.
- JSON policies with `version`, `default`, `rules`, tool name globs, `when` context conditions and argument constraints (`one_of`, `prefix`, `max`, `host`, `pattern`).
- Deny-overrides evaluation, fail-closed handling of missing or mistyped arguments on deny rules, and the command-line interface in `tool_permission_policy/__main__.py`.

Out of scope:

- Roles and identity management.
- Persistence of decisions.
- Human approval flows.

## Timeline

No timeline entries are recorded in the specification.

## Effort metrics

Measured values only; a value that has not been measured stays pending measurement.

| Metric | Value |
|---|---|
| Tokens (input / output) | 799358 / 60172 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.0906 |

## Factory run u221 (measured from API usage)

| Date (UTC) | Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|---|
| 2026-11-10 | generation | deepseek-v4-pro | yes | 1864 | 19204 | 0 | 3200 | 0.0393 |
| 2026-11-10 | fix-1 | deepseek-flash | no | 12578 | 1256 | 0 | 67840 | 0.0028 |
| 2026-11-10 | fix-2 | deepseek-flash | no | 9305 | 1373 | 0 | 27904 | 0.0023 |
| 2026-11-10 | audit | deepseek-flash | no | 31278 | 20942 | 0 | 364800 | 0.0184 |
| 2026-11-10 | fix-3 | deepseek-flash | no | 19778 | 5786 | 0 | 167808 | 0.0069 |
| 2026-11-10 | docs | deepseek-flash | no | 92747 | 11611 | 0 | 256 | 0.0209 |

Total: $0.0906. Prices: deepseek line, as measured by its adapter. Providers serve the current version of each model id, so the date tells which version answered; versions, launch stages and price sources per line are in the factory's model register (docs/MODELS.md).
