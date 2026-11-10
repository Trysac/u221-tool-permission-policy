# Argument-level tool call policy engine

Status: accepted (generated, pending human review)

## Context

Agent tool calls need safeguards beyond tool name allowlists. We need path, host, numeric and value constraints with fail-closed deny semantics.

## Decision

Implement a declarative policy language evaluated by a pure Python library, using standard library modules (fnmatch, posixpath, re, urllib.parse). Deny rules override allow/ask and treat missing arguments as Unknown, causing deny to match with reason missing_argument.

## Consequences

The library is dependency-free and straightforward to audit. Policy evaluation is deterministic. The fail-closed deny behavior prevents bypasses that omit arguments, but callers must handle symlink resolution and DNS rebinding themselves.
