# Semantic SQL policies

SQL rules classify captured query text; they do not discover database clients, environment
variables, option grammars, wrappers, or Python helpers. Policy authors describe those ordinary
command shapes with `Shell(...)` and Python call shapes with `Python(...)`, then place an SQL capture
where query text occurs.

## SQL rules

SQL policies are ordinary permission rules, so `deny` wins over `ask`, which wins over `allow`:

```jsonc
{
  "permissions": {
    "allow": [{
      "SQL(reporting)": {
        "dialect": "postgres",
        "format": "plain",
        "effects": {"only": ["read"]},
        "relations": {"all": ["reporting.*", "process.*"]},
        "functions": {"all": ["builtin:*", "process.safe_reporting_function"]}
      }
    }],
    "deny": [{
      "SQL(blocked-function)": {
        "dialect": "postgres",
        "functions": {"any": ["process.dangerous_extension_function"]}
      }
    }]
  }
}
```

Supported dialects are `oracle`, `postgres`, `mysql`, and `sqlite`. Supported document formats are
`plain`, `sqlplus`, `psql`, `mysql`, and `sqlite`. A document format removes a small allowlist of
presentation-only client directives before parsing. Shell escapes, file loading, output spooling,
client extension loading, and unrecognized meta-commands fail closed.

Each optional selector contains exactly one mode:

- `any`: at least one discovered value must match a pattern.
- `all`: every discovered value must match; an empty set passes.
- `only`: every value must match and the analyzer must not report an unknown effect.

Patterns use shell-style `*` and `?`. Relations are syntactic SQL relation references—tables, views,
and synonyms cannot be distinguished without a database catalogue. They are exposed as
`dialect:catalog.schema.name`; patterns may omit the `dialect:` prefix. Parser-recognized functions
use `builtin:name`; other calls use `dialect:schema.name`. A non-builtin function must be covered by
the rule's `functions` selector, so an effects-only read rule cannot silently allow a stored function.

Effects accumulate over the complete AST, including CTEs and nested queries: `read`, `data-write`,
`schema-write`, `session-change`, `transaction-control`, `lock`, `external-io`, `code-execution`, and
`unknown`. Thus `SELECT ... FOR UPDATE`, `SELECT ... INTO`, and a `DELETE` inside a CTE do not match
`effects: {only: ["read"]}`. Unsupported syntax, SQLGlot `Command` fallbacks, dynamic query text, and
documents over the analysis boundary require approval.

PostgreSQL `EXPLAIN` is unwrapped when its option list and single inner statement are static. The
inner statement supplies the effects, relations, and functions, so `EXPLAIN ANALYZE SELECT` remains
a read while `EXPLAIN ANALYZE DELETE` remains a data write. Unknown options and opaque inner
statements require approval.

## Shell captures

SQL stays inside normal `Shell(...)` rules:

```jsonc
"Shell(dbcli <SQL:reporting>)"
"Shell(dbcli stdin(<SQL:reporting>))"
"Shell(dbcli values(--host,--port) sqlvalues(<SQL:reporting>,-q,--query))"
```

- `<SQL>` captures one positional operand and considers every SQL rule.
- `<SQL:name>` captures one positional operand and selects non-deny SQL rules named `name`.
- `stdin(...)` analyzes statically available stdin from a literal heredoc or a restricted literal
  `echo`/`printf '%s\n' ...` pipe.
- `sqlvalues(<SQL...>,flags...)` declares arbitrary value-bearing flags. At least one listed flag must
  occur, and every occurrence is parsed independently. Separate, attached, repeated, short, and long
  forms are supported.
- `values(...)` continues to declare every non-SQL option that consumes a value. No option names or
  arities are built into SQL support.

Bare `<SQL>` makes the capture reusable across configured dialect rules. A named capture narrows only
Ask/Allow candidates; every matching SQL Deny remains active.

Connection setup remains ordinary shell policy. Leading `NAME=value` assignments are already handled
by shell syntax, regardless of the variable name. A preceding command such as `source` is a separate
segment and needs its own rule if it should be allowed:

```jsonc
"Shell(source *)"
"Shell(dbcli values(-h,-p,-U,-d) sqlvalues(<SQL:reporting>,-c))"
```

The same rule works with arbitrary executable paths, variable names, hosts, users, databases, and
option values because none of those are SQL-domain concepts.

## Wrappers

Two generic semantic captures cover wrappers that the built-in shell parser cannot unwrap:

```jsonc
"Shell(wrapper <EXEC>)"
"Shell(remote ... shell <SHELL> -l -c)"
```

`<EXEC>` evaluates the remaining normalized operands as a nested executable invocation. `<SHELL>`
parses one literal operand as nested shell source. Inner commands still need their own rules, and a
nested SQL client can use the same SQL capture rules. Wrapper names and argv layout are policy-defined.

## Python captures

Inline Python call targets and SQL argument locations are also declared as rules:

```jsonc
"Python(query_db(<SQL:reporting>))"
"Python(project.database.inspect(sql=<SQL:reporting>))"
"Python(*.execute(<SQL>))"
```

Targets are statically resolved using the existing inline-Python analyzer and may contain `*`.
The positional or keyword argument must be a literal string or a local name directly bound to one.
Other Python effects are still analyzed; dynamic targets and dynamic SQL require approval. Nothing in
agentperm assumes a particular database library or helper name.

Both `python - <<'PY'` and Python's equivalent implicit-stdin form are supported:

```sh
python <<'PY'
query_db("select meter_id from process.meter order by meter_id")
PY
```

Quoting the heredoc delimiter is recommended. An unquoted heredoc is accepted only when its body has
no shell expansion markers; dynamic input requires approval.

## Trust boundary

SQLGlot provides broad dialect parsing, not proof of database behavior. Agentperm walks the complete
returned AST, rejects opaque fallbacks, and makes stored-function permission explicit, but it cannot
know database grants, triggers, function bodies, view definitions, row-level security, or runtime SQL
assembled by application code. SQL rules are conservative intent classification, not a SQL sandbox.
