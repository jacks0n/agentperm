# agentperm

**One permission policy for every coding agent. Parsed like a shell, not matched like a string.**

agentperm is a pre-tool hook for [Claude Code](https://docs.anthropic.com/en/docs/claude-code),
[Codex CLI](https://github.com/openai/codex), [OpenCode](https://opencode.ai),
[Gemini CLI](https://github.com/google-gemini/gemini-cli), and [Kiro](https://kiro.dev). Before a
command runs, it parses the whole shell program, judges every piece against one local policy file,
and returns **allow / ask / deny**. You approve *intent* once; you stop re-approving `git status`
because a flag moved, it entered a pipe, or a different agent asked.

[![PyPI](https://img.shields.io/pypi/v/agentperm)](https://pypi.org/project/agentperm/)
[![Python](https://img.shields.io/pypi/pyversions/agentperm)](https://pypi.org/project/agentperm/)
[![CI](https://github.com/jacks0n/agentperm/actions/workflows/ci.yml/badge.svg)](https://github.com/jacks0n/agentperm/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jacks0n/agentperm/blob/main/LICENSE)

## Everything it does, on one screen

```jsonc
// ~/.agent-permissions.jsonc
{
  "version": 1,
  "permissions": {
    "deny": [
      "Shell(git push --force)",
      {"Write(src/generated/**)": {"reason": "Generated — run `just generate`."}},
      {"SQL(no-file-io)": {"dialect": "postgres", "functions": {"any": ["pg_read_file"]}}}
    ],
    "ask": ["Shell(aws ec2 terminate-*)"],
    "allow": [
      "Shell(git values(-C) {status,diff,log} only(-C, --short, --stat))",
      "Shell(aws values(--profile) ec2 describe-* only(--profile))",
      "Shell(jq only(-r))",
      "Shell(echo *)",
      "Shell(psql values(-d) sqlvalues(<SQL:ro>, -c))",
      "Shell(psql values(-d) stdin(<SQL:ro>))",
      {"SQL(ro)": {"dialect": "postgres", "effects": {"only": ["read"]}}},
      "Python(readonly)",
      "Python(query_db(<SQL:ro>))",
      "Write(src/**)"
    ]
  }
}
```

Agent tries to run:

```sh
aws ec2 describe-vpcs --profile=dev 2>/dev/null | jq -r .Vpcs[].VpcId &&
git -C . diff --stat &&
echo "SELECT count(*) FROM users" | psql -d app
```

agentperm sees:

```text
aws ec2 describe-vpcs --profile=dev   allow  Shell(aws values(--profile) ec2 describe-* only(--profile))
  2>/dev/null                         allow  redirect to /dev/null is harmless
jq -r .Vpcs[].VpcId                   allow  Shell(jq only(-r))
git -C . diff --stat                  allow  Shell(git values(-C) {status,diff,log} only(-C, --short, --stat))
echo "SELECT count(*) FROM users"     allow  Shell(echo *)
psql -d app                           allow  Shell(psql values(-d) stdin(<SQL:ro>))  ← stdin is SQL; read-only
──────────────────────────────────────────────
allow — no prompt
```

Same policy, other attempts. The strictest segment decides: `deny > ask > allow > no-opinion`.

```text
allow       git -C . status --short                              flags reorder freely; only(…) admits --short
allow       bash -lc 'git diff --stat | jq -r .'                 wrapper unwrapped; inner pipe split and matched
no-opinion  aws ec2 describe-vpcs --endpoint-url http://x        unreviewed flag → no match → your agent prompts
allow       python -c "print(open('x.json').read())"             Python AST is read-only
ask         python -c "import shutil; shutil.rmtree('x')"        Python AST finds a mutation
allow       psql -d app -c 'SELECT id FROM users'                SQL parsed; effects = {read}
ask         echo 'DELETE FROM users' | psql -d app               stdin SQL parsed; DELETE is not a read
deny        psql -d app -c "SELECT pg_read_file('/etc/passwd')"  function deny beats the read-only allow
allow       python -c "query_db('SELECT id FROM users')"         literal SQL through a declared Python helper
ask         python -c "query_db(sql)"                            query text is not static
deny        git status && git push --force                       one denied segment denies the chain
ask         git status | ./deploy.sh                             one unknown segment prompts for the chain
ask         git diff --stat > out.txt                            redirect writes a file; allowlist paths if you want
deny        Write src/generated/client.py                        "Generated — run `just generate`."
```

The last line is one capability for every host: Claude `Edit`/`Write`/`NotebookEdit`, Codex
`apply_patch`, OpenCode `edit`, Gemini `replace`, and Kiro `fs_write` are all `Write`, so a create,
an overwrite, and an in-place edit are one decision. Real parsers, not regex: tree-sitter-bash for
shell, Python's `ast` for inline Python, SQLGlot for SQL. Anything agentperm cannot statically
understand is never allowed — it asks, or defers to your agent's own prompt.
`agentperm why "<command>"` prints this breakdown for any command without running it.

https://github.com/user-attachments/assets/9abcd24d-147c-4323-a1c3-970544e0d86a

[GIF fallback](https://raw.githubusercontent.com/jacks0n/agentperm/main/docs/media/demo.gif)

## Install

```sh
uv tool install agentperm          # or: pipx install agentperm
agentperm install --dry-run        # preview every hook file it would touch, then:
agentperm install                  # hook into every supported agent it finds
agentperm init                     # conservative starter policy → ~/.agent-permissions.jsonc
agentperm why "git status | head"  # check a decision without running anything
```

Python 3.12+, macOS or Linux. Native agent settings stay in place; agentperm adds a decision in
front of them. `agentperm uninstall` removes only what `install` wrote. Full walkthrough:
[Getting started](docs/getting-started.md).

## Why not native allowlists?

| | Native allowlists · string/regex hooks | agentperm |
|---|---|---|
| Unit of matching | one opaque command string | every segment of a parsed shell program |
| `git -C . status`, `--region=x`, `-la` vs `-al` | a new rule each time | one rule: `values(…)`, `only(…)`, `{a,b}`, `*` |
| Pipes, `&&`, `bash -c`, `$(…)`, heredocs | defeated by the first `\|` | decomposed; strictest segment wins |
| Python, SQL, file edits | strings | AST, SQL effect classification, semantic `Write` |
| Five agents | five formats to keep in sync | one file, wired through each agent's native hooks |
| "Why was I prompted?" | guess | `agentperm why`, per-rule `reason`, opt-in JSONL traces |

Sandboxes are a different tool: they contain what runs, agentperm decides what runs. Use both.

## How policies compose

- `~/.agent-permissions.jsonc` merges with every `.agent-permissions.jsonc` from `/` down to the
  command's working directory.
- **Deny anywhere is a floor.** For Ask and Allow the nearest matching policy wins, so a project can
  allow something your global policy asks about — but never un-deny anything.
- Any policy file can `include` explicit paths or globs; fragments merge into that same layer.
- Directory policies are not trust-gated. Review a cloned repo's `.agent-permissions.jsonc` the same
  way you review its `.envrc`.

## Rules cheat sheet

| Form | Meaning |
|---|---|
| `{status,log,diff}` | one of these command-path tokens |
| `describe-*` | glob within one token |
| `values(--region)` | `--region` consumes the following token |
| `only(--region, --profile)` | reject every other flag |
| `!--force` | reject this flag |
| `!-*` | reject every flag |
| `!...` | reject trailing operands |
| `<SQL:name>` · `stdin(<SQL>)` · `sqlvalues(<SQL>, -c)` | parse SQL from an operand, stdin, or option values |
| `<EXEC>` · `<SHELL>` | evaluate a wrapper's nested command or nested shell source |
| `Python(readonly)` · `Python(f(<SQL>))` | AST-check inline Python; capture SQL passed to a helper |
| `Write(src/**)` · `Read(**)` | scoped file capabilities shared by every agent — `Write` covers create, overwrite, edit, and patch |
| `shell.redirection` | `>/dev/null` and `2>&1` pass; `> file` asks unless the path is allowlisted |

`agentperm validate` after editing. Exact grammar: [Shell pattern DSL](docs/pattern-dsl.md) ·
[Semantic SQL policies](docs/sql-policy.md) · [Policy reference](docs/policy-reference.md).

## Agents

Claude Code · Codex CLI · OpenCode · Gemini CLI · Kiro. Same engine, same policy; hook stages and
what each host can express differ (Gemini and Kiro cannot surface an interactive Ask distinct from
Deny). Install directly or via Rulesync; import existing native rules. Exact coverage per agent:
[capability matrix](docs/capabilities.md).

## Not a sandbox

agentperm is a **permission intent layer**. It sees only tool calls the host routes through hooks,
matches argv shape rather than proving program behaviour, and does not isolate processes, files, or
network. A host's bypass mode bypasses agentperm too. Traces are diagnostic, off by default, and
unredacted. Threat model, bypass surfaces, and failure behaviour: [SECURITY.md](SECURITY.md).

## Zellij pane bypass

The bundled [Zellij plugin](zellij-plugin/) adds a per-pane "skip prompts" toggle: Ask and
no-opinion become Allow for that pane only, Deny still holds — far narrower than a host-wide
"dangerously skip permissions" mode.

## Documentation

- [Getting started](docs/getting-started.md) — install, initialize, verify.
- [Capability matrix](docs/capabilities.md) — exact behaviour per agent.
- [Policy reference](docs/policy-reference.md) — schema, semantic tools, hierarchy, includes, redirects.
- [Shell pattern DSL](docs/pattern-dsl.md) · [Semantic SQL policies](docs/sql-policy.md) — matching grammars.
- [CLI reference](docs/cli.md) — commands, hook installation, traces, exit behaviour.
- [Troubleshooting](docs/troubleshooting.md) — symptom-led fixes.
- [Architecture](docs/architecture.md) · [Adapter notes](docs/adapters.md) — contributor internals.
- [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## License

MIT
