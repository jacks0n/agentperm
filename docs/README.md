# agentperm documentation

Use this page to find the shortest path to the answer you need. The README explains why agentperm
exists; these docs separate tasks, exact behavior, and maintainer internals so each fact has one
authoritative home.

## I want to…

| Goal | Start here |
|---|---|
| Install agentperm and remove my first prompt | [Getting started](getting-started.md) |
| See what each supported agent can enforce | [Capability matrix](capabilities.md) |
| Write or organize a policy | [Policy reference](policy-reference.md) |
| Match flags, permutations, pipes, and wrappers | [Shell pattern DSL](pattern-dsl.md) |
| Allow SQL by dialect, effect, relation, or function | [Semantic SQL policies](sql-policy.md) |
| Understand a decision or inspect a trace | [`why`](cli.md#why) and [diagnostic traces](cli.md#diagnostic-traces) |
| Fix prompting, hook, policy, or parsing problems | [Troubleshooting](troubleshooting.md) |
| Assess the security boundary | [Security model](../SECURITY.md) |
| Understand or extend the implementation | [Architecture](architecture.md), then [adapter notes](adapters.md) |

## Reading layers

- **Evaluate and try:** [project README](../README.md) and [getting started](getting-started.md).
- **Operate:** [CLI reference](cli.md), [capability matrix](capabilities.md), and
  [troubleshooting](troubleshooting.md).
- **Specify:** [policy reference](policy-reference.md), [Shell pattern DSL](pattern-dsl.md), and
  [Semantic SQL policies](sql-policy.md).
- **Maintain:** [architecture](architecture.md), [adapter notes](adapters.md), and
  [contributing](../CONTRIBUTING.md).

## Terminology

| Term | Meaning |
|---|---|
| **policy** | The merged global and directory `.agent-permissions.jsonc` files used for a request. |
| **rule** | One allow, ask, or deny entry, including shell, Python, SQL, and named/scoped tool rules. |
| **segment** | One executable command extracted from shell source. `a | b && c` has three. |
| **request** | A shell operation, semantic tool operation, compound operation, or rejected operation produced by an adapter. |
| **verdict** | `allow`, `ask`, `deny`, or `no-opinion`, plus a rationale. |

## Documentation contract

Guides optimize for completing a task; references define exact behavior. When a guide and reference
appear to disagree, treat that as a documentation bug. Implementation tests and the Unreleased
changelog are checked during documentation updates so shipped behavior stays authoritative.
