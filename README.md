# tool-permission-policy

[![PyPI version](https://img.shields.io/pypi/v/trysac-tool-permission-policy)](https://pypi.org/project/trysac-tool-permission-policy/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-tool-permission-policy)](LICENSE)
[![CI](https://github.com/Trysac/u221-tool-permission-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u221-tool-permission-policy/actions/workflows/ci.yml)

Declarative allow, ask and deny policies for agent tool calls: tool name globs, argument constraints on paths, hosts, values and numbers, context conditions and fail-closed deny

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-tool-permission-policy
# or
uv add trysac-tool-permission-policy
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import tool_permission_policy

# normalize() trims surrounding whitespace and lower-cases the text.
print(tool_permission_policy.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    tool_permission_policy.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
