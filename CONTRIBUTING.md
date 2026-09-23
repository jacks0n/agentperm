# Contributing

Thanks for considering a contribution. agentperm is small and focused on purpose — please read [docs/architecture.md](docs/architecture.md) before proposing larger changes.

## Dev setup

Requires Python 3.12+.

```sh
git clone https://github.com/jacks0n/agentperm.git
cd agentperm
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

Or with `pip`:

```sh
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality gates

Run the standard gates before a PR merges:

```sh
just check
```

This runs Ruff, strict basedpyright, Vulture dead-code detection, Pylint duplicate-code and
700-line module limits, and pytest. These are standard tools, not custom checking scripts.
Source and tests must be fully typed: no Any, unknown-type exemptions, or type-ignore comments.

## Code conventions

- **No `Any`.** JSON values are typed as `JsonValue`; JSON, TOML and parser inputs are narrowed at boundaries.
- **Small semantic modules.** Keep each file at most 700 lines. `domain/model.py` owns value objects;
  `domain/evaluation.py` owns policy decisions. Parsers and agent adapters remain outside that boundary.
- **Domain types are immutable** (`@dataclass(frozen=True)`).
- **Sum types use isinstance dispatch**, not enums-with-payload — see `Request`, `Rule`.
- **Adapter contract** lives in `AgentAdapter`. New agents add a class implementing `install`, `parse_event`, `write_verdict`, optionally `import_native_rules`.
- **Tests round-trip parse/serialize.** Parser, policy, installation and native-protocol tests are
  grouped by scenario in `tests/`. A passing suite does not replace real native-agent acceptance.

## Adding a new agent

1. Read [docs/adapters.md](docs/adapters.md) — the contract and the existing four adapters.
2. Add an `AgentName` variant.
3. Subclass `AgentAdapter`, implement `install` / `parse_event` / `write_verdict` / `import_native_rules`.
4. Register in `ADAPTERS`.
5. Add round-trip tests alongside `tests/test_adapter_decisions.py` and `tests/test_hook_contracts.py`.

## Adding a new rule kind

1. Subclass `Rule` with the matching method appropriate to its target type (segment, tool name, etc.).
2. Extend `parse_rule` to recognize the new form (string or dict).
3. Extend `Policy._match_bash` / `_decide_tool` if the rule applies to a new request kind.
4. Extend `serialize` so it round-trips through the policy file.
5. Add a parse-and-match test alongside `tests/test_rule_matching.py` and `tests/test_policy_decisions.py`.

## PR checklist

- [ ] Tests added / updated for the change
- [ ] `just check` passes (including types, dead/duplicate code and file-size limits)
- [ ] Applicable native workflows manually verified; arrange focus-changing tests with the user
- [ ] Public API change → docs updated (`docs/`, `README.md`)
- [ ] Behavior change → `CHANGELOG.md` entry under `## [Unreleased]`

## Releasing

Releases are published to PyPI by `.github/workflows/publish.yml` using PyPI Trusted Publishing. The
PyPI project must have a trusted publisher configured with these values:

- Owner: `jacks0n`
- Repository: `agentperm`
- Workflow: `publish.yml`
- Environment: `pypi`

The Python, uv, and just versions in `mise.toml` are the authoritative development and CI toolchain.
Run `mise install` once, then use the `justfile` recipes for local checks and builds.

Set the release version in `pyproject.toml` and `uv.lock`, move the changelog entries into a matching
versioned section, and merge those changes to `main`. After branch CI passes, create an annotated tag
whose name is `v` followed by that exact project version, then push it:

```sh
git tag -a v0.4.0 -m "agentperm 0.4.0"
git push origin v0.4.0
```

The tag push starts the release workflow. It rejects a tag that does not match `pyproject.toml` or a
missing changelog section, runs `just ci`, builds the distributions once, publishes them to PyPI
with Trusted Publishing, and then creates the GitHub Release with those files attached. Only stable
`vMAJOR.MINOR.PATCH` tags trigger a release.

## Issue reports

Please include the trace log for any "still prompting" / "incorrectly allowed" reports — see [docs/troubleshooting.md](docs/troubleshooting.md#filing-a-bug).
