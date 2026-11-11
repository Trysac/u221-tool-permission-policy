# Security model

`tool_permission_policy` evaluates declarative policies for agent tool calls. This document describes the threat model and what the library does and does not defend against.

## Defended

- Path traversal: the `prefix` constraint applies `posixpath.normpath` to the argument. A path like `/workspace/../etc/passwd` normalizes to `/etc/passwd` and does not match a prefix of `/workspace/`. Arguments containing NUL or backslash are rejected for `prefix`.
- Host suffix and userinfo tricks: the `host` constraint uses `urllib.parse.urlsplit` and checks the hostname against lowercase host entries. Only `http` and `https` schemes are accepted, userinfo is rejected, and `api.example.com.evil.io` or `user@api.example.com` do not match `api.example.com`.
- Missing or mistyped arguments on deny rules: deny rules match when no constraint is `False`. A missing or wrong-typed argument is `Unknown` and counts as matching for a deny rule, with reason `missing_argument`. An attacker cannot bypass a deny rule by omitting an argument.
- Bool smuggled as a number: a boolean is not accepted by `max`, and type-sensitive equality in `one_of` prevents `true` from matching `1`.

## Not defended

- Symlinks: the policy engine does not resolve symlinks on the real filesystem. A path that appears to be inside an allowed prefix may point outside it. Callers should resolve paths before passing them to `decide` if the underlying tool could follow symlinks.
- DNS rebinding: the `host` constraint checks the hostname string, but DNS resolution could change later. Use an IP allowlist or proxy if that matters.
- Semantic misuse: an allowed tool may still be used in unintended ways within its constraints. The policy engine is not a sandbox.

## Policy validation limits

- Maximum 1000 rules per policy.
- Maximum 100 tool globs per rule.
- Maximum regex pattern length of 200 characters.
- Maximum JSON nesting depth of 16; deeper documents are rejected with `PolicyError('invalid_policy')` instead of crashing the parser.
- `load_policy_json` rejects input larger than 1 MiB by default; `max_bytes` can set another limit.
