# Stack

## Used

| Tool | Why |
|---|---|
| Python >= 3.10 | Supports the annotations used in the package, including `str | None` and `list[str]`. |
| Python standard library | The implementation imports only standard-library modules: `fnmatch`, `posixpath`, `re`, `urllib.parse`, `json`, `argparse`, `logging`, `dataclasses` and `typing`. |
| pytest | Test runner indicated by the checked-in test cache for `tests/test_tool_permission_policy.py`. |

## Discarded

| Tool | Why not |
|---|---|
| Third-party runtime dependencies | The package declares none and the implementation uses only the standard library. |
