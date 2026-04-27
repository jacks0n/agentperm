# Contributing

Thanks for considering a contribution. The bridge is small and focused on purpose — please read [docs/architecture.md](docs/architecture.md) before proposing larger changes.

## Dev setup

Requires Python 3.12+.

```sh
git clone https://github.com/jacks0n/llm-agent-bridge.git
cd llm-agent-bridge
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

Or with `pip`:

```sh
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality gates

All three must pass before a PR merges:

```sh
pytest -q                       # full test suite (~50 ms)
ruff check .                    # lint
basedpyright src tests          # strict type check
```

Or run them in one go:

```sh
pytest -q && ruff check . && basedpyright src tests
```

## Code conventions

- **No `Any`.** JSON values are typed as `JsonValue`; bashlex / tomlkit are narrowed at the boundary.
- **Domain types are immutable** (`@dataclass(frozen=True)`).
- **Sum types use isinstance dispatch**, not enums-with-payload — see `Request`, `Rule`.
- **Adapter contract** lives in `AgentAdapter`. New agents add a class implementing `install`, `parse_event`, `write_verdict`, optionally `import_native_rules`.
- **Tests round-trip parse/serialize.** `tests/test_parser.py`, `tests/test_policy.py`, `tests/test_adapters.py` are the authoritative behavior spec.

## Adding a new agent

1. Read [docs/adapters.md](docs/adapters.md) — the contract and the existing four adapters.
2. Add an `AgentName` variant.
3. Subclass `AgentAdapter`, implement `install` / `parse_event` / `write_verdict` / `import_native_rules`.
4. Register in `ADAPTERS`.
5. Add round-trip tests in `tests/test_adapters.py`.

## Adding a new rule kind

1. Subclass `Rule` with the matching method appropriate to its target type (segment, tool name, etc.).
2. Extend `parse_rule` to recognize the new form (string or dict).
3. Extend `Policy._match_bash` / `_decide_tool` if the rule applies to a new request kind.
4. Extend `serialize` so it round-trips through the policy file.
5. Add a parse-and-match test in `tests/test_policy.py`.

## PR checklist

- [ ] Tests added / updated for the change
- [ ] `pytest -q` passes
- [ ] `ruff check .` passes
- [ ] `basedpyright src tests` passes
- [ ] Public API change → docs updated (`docs/`, `README.md`)
- [ ] Behavior change → `CHANGELOG.md` entry under `## [Unreleased]`

## Issue reports

Please include the trace log for any "still prompting" / "incorrectly allowed" reports — see [docs/troubleshooting.md](docs/troubleshooting.md#reporting-a-bug).
