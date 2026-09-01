"""Semantic SQL rules and generic shell/Python capture integration."""

from __future__ import annotations

import pytest

from agentperm import (
    Decision,
    Policy,
    ShellRequest,
    SqlDialect,
    SqlDocumentFormat,
    SqlRequest,
    Verdict,
    parse_pipeline,
    parse_policy_text,
    parse_rule,
)
from agentperm.domain import PythonSqlPattern, ShellPattern
from agentperm.sql.domain import CapturedSql, SqlCaptureKind, SqlEffect, SqlOrigin
from agentperm.sql.parser import SqlParseError, parse_sql


def _policy(*, allow: str, ask: str = "", deny: str = "") -> Policy:
    return parse_policy_text(
        f"""
        {{
          permissions: {{
            allow: {allow},
            ask: {ask or "[]"},
            deny: {deny or "[]"},
          }}
        }}
        """,
        "test policy",
    ).policy


def _decide(policy: Policy, command: str) -> Verdict:
    return policy.decide(ShellRequest(parse_pipeline(command)))


def test_sql_rule_round_trips_domain_configuration() -> None:
    rule = parse_rule(
        {
            "SQL(reporting)": {
                "dialect": "postgres",
                "effects": {"only": ["read"]},
                "relations": {"all": ["reporting.*"]},
                "functions": {"all": ["builtin:*"]},
            }
        }
    )
    assert rule is not None
    assert rule.serialize() == {
        "SQL(reporting)": {
            "dialect": "postgres",
            "format": "plain",
            "effects": {"only": ["read"]},
            "relations": {"all": ["reporting.*"]},
            "functions": {"all": ["builtin:*"]},
        }
    }


def test_nested_write_and_lock_accumulate_effects() -> None:
    nested_write = parse_sql(
        "with changed as (delete from audit.events returning *) select * from changed",
        dialect=SqlDialect.Postgres,
        document_format=SqlDocumentFormat.Plain,
    )
    locking_read = parse_sql(
        "select * from audit.events for update",
        dialect=SqlDialect.Postgres,
        document_format=SqlDocumentFormat.Plain,
    )
    assert nested_write.effects == frozenset({SqlEffect.Read, SqlEffect.DataWrite})
    assert locking_read.effects == frozenset({SqlEffect.Read, SqlEffect.Lock})


@pytest.mark.parametrize(
    ("dialect", "query"),
    [
        (SqlDialect.Oracle, "select meter_id from process.meter order by meter_id fetch first 20 rows only"),
        (SqlDialect.Postgres, "select meter_id from process.meter union select meter_id from archive.meter"),
        (SqlDialect.MySql, "select meter_id from process.meter order by meter_id limit 20"),
        (SqlDialect.Sqlite, "select meter_id from meter order by meter_id limit 20"),
    ],
)
def test_queries_parse_across_supported_dialects(dialect: SqlDialect, query: str) -> None:
    facts = parse_sql(query, dialect, SqlDocumentFormat.Plain)
    assert facts.effects == frozenset({SqlEffect.Read})


def test_cte_aliases_are_excluded_without_hiding_same_named_physical_tables() -> None:
    facts = parse_sql(
        "with x as (select * from reporting.meter) select * from x; select * from x",
        SqlDialect.Postgres,
        SqlDocumentFormat.Plain,
    )
    assert {relation.name for relation in facts.relations} == {"postgres:reporting.meter", "postgres:x"}


def test_shell_sql_option_values_validate_every_occurrence() -> None:
    policy = _policy(
        allow="""[
          {"SQL(reporting)": {dialect: "postgres", effects: {only: ["read"]}}},
          "Shell(dbcli values(--host, --port) sqlvalues(<SQL:reporting>,-q,--query))"
        ]""",
    )
    allowed = _decide(
        policy,
        "dbcli --host db.internal -q 'select * from reporting.meters' "
        "--query='with x as (select 1) select * from x'",
    )
    denied_by_semantics = _decide(
        policy,
        "dbcli -q 'select * from reporting.meters' --query 'delete from reporting.meters'",
    )
    assert allowed.decision is Decision.Allow
    assert denied_by_semantics.decision is Decision.Ask


def test_bare_sql_capture_uses_all_rules_and_global_deny_wins() -> None:
    policy = _policy(
        allow="""[
          {"SQL(generic-read)": {dialect: "postgres", effects: {only: ["read"]}}},
          "Shell(dbcli sqlvalues(<SQL>,-q))"
        ]""",
        deny="""[
          {"SQL(blocked-function)": {
            dialect: "postgres",
            functions: {any: ["dangerous_extension_function"]}
          }}
        ]""",
    )
    assert _decide(policy, "dbcli -q 'select count(*) from reporting.meters'").decision is Decision.Allow
    assert _decide(policy, "dbcli -q 'select dangerous_extension_function()'").decision is Decision.Deny


def test_relation_deny_is_independent_of_read_allow() -> None:
    policy = _policy(
        allow="""[
          {"SQL(reporting)": {dialect: "postgres", effects: {only: ["read"]}}},
          "Shell(dbcli sqlvalues(<SQL:reporting>,-q))"
        ]""",
        deny="""[{
          "SQL(sensitive-relation)": {
            dialect: "postgres", relations: {any: ["private.*"]}
          }
        }]""",
    )
    assert _decide(policy, "dbcli -q 'select * from reporting.meter'").decision is Decision.Allow
    assert _decide(policy, "dbcli -q 'select * from private.secret'").decision is Decision.Deny


def test_sql_request_can_be_evaluated_directly_by_policy() -> None:
    policy = _policy(
        allow='[{"SQL(reporting)": {dialect: "sqlite", effects: {only: ["read"]}}}]',
    )
    request = SqlRequest(
        CapturedSql(
            "select * from meter",
            "reporting",
            SqlOrigin(SqlCaptureKind.Argument, "test"),
        )
    )
    assert policy.decide(request).decision is Decision.Allow


def test_named_sql_capture_still_applies_every_deny_rule() -> None:
    policy = _policy(
        allow="""[
          {"SQL(reporting)": {
            dialect: "oracle",
            effects: {only: ["read"]},
            functions: {all: ["builtin:*", "process.safe_reporting_function"]}
          }},
          "Shell(dbcli sqlvalues(<SQL:reporting>,-q))"
        ]""",
        deny="""[
          {"SQL(blocked-function)": {
            dialect: "oracle",
            functions: {any: ["process.dangerous_extension_function"]}
          }}
        ]""",
    )
    safe = "select process.safe_reporting_function(meter_id) from process.meter"
    unsafe = "select process.dangerous_extension_function() from process.meter"
    assert _decide(policy, f'dbcli -q "{safe}"').decision is Decision.Allow
    assert _decide(policy, f'dbcli -q "{unsafe}"').decision is Decision.Deny


def test_unknown_named_profile_cannot_bypass_sql_deny() -> None:
    policy = _policy(
        allow='["Shell(dbcli sqlvalues(<SQL:missing>,-q))"]',
        deny="""[{
          "SQL(blocked-function)": {
            dialect: "postgres", functions: {any: ["dangerous_extension_function"]}
          }
        }]""",
    )
    command = "dbcli -q 'select dangerous_extension_function()'"
    assert _decide(policy, command).decision is Decision.Deny


def test_literal_pipe_supplies_stdin_without_client_knowledge() -> None:
    policy = _policy(
        allow="""[
          {"SQL(reporting)": {dialect: "postgres", effects: {only: ["read"]}}},
          "Shell(dbcli stdin(<SQL:reporting>))"
        ]""",
    )
    assert _decide(policy, "echo 'select * from reporting.meters' | dbcli").decision is Decision.Allow
    assert _decide(policy, "echo 'drop table reporting.meters' | dbcli").decision is Decision.Ask


def test_dynamic_shell_sql_does_not_become_static_capture() -> None:
    policy = _policy(
        allow="""[
          {"SQL(reporting)": {dialect: "postgres", effects: {only: ["read"]}}},
          "Shell(dbcli sqlvalues(<SQL:reporting>,-q))",
          "Shell(other stdin(<SQL:reporting>))"
        ]""",
    )
    assert _decide(policy, 'dbcli -q "$QUERY"').decision is Decision.NoOpinion
    assert _decide(policy, 'echo "$QUERY" | other').decision is Decision.Ask
    assert _decide(policy, "dbcli -q 'select * from meter where id = $1'").decision is Decision.Allow


def test_sqlplus_document_ignores_only_known_client_directives() -> None:
    policy = _policy(
        allow="""[
          {"SQL(oracle-report)": {
            dialect: "oracle", format: "sqlplus", effects: {only: ["read"]}
          }},
          "Shell(dbcli stdin(<SQL:oracle-report>))"
        ]""",
    )
    command = (
        "printf '%s\\n' 'set pagesize 100' 'column nmi_id format a12' "
        "'select nmi_id from process.meter;' 'exit' | dbcli"
    )
    assert _decide(policy, command).decision is Decision.Allow


def test_effectful_client_directive_fails_closed() -> None:
    policy = _policy(
        allow="""[
          {"SQL(oracle-report)": {
            dialect: "oracle", format: "sqlplus", effects: {only: ["read"]}
          }},
          "Shell(dbcli stdin(<SQL:oracle-report>))"
        ]""",
    )
    command = "printf '%s\\n' 'host arbitrary-command' 'select 1 from dual;' | dbcli"
    assert _decide(policy, command).decision is Decision.Ask


def test_nested_shell_capture_handles_generic_remote_wrapper() -> None:
    policy = _policy(
        allow="""[
          {"SQL(reporting)": {dialect: "postgres", effects: {only: ["read"]}}},
          "Shell(wrapper ... shell <SHELL> -l -c)",
          "Shell(dbcli sqlvalues(<SQL:reporting>,-q))"
        ]""",
    )
    command = "wrapper target shell -lc \"dbcli -q 'select * from reporting.meters'\""
    assert _decide(policy, command).decision is Decision.Allow


def test_policy_describes_docker_sqlplus_without_production_special_cases() -> None:
    policy = _policy(
        allow="""[
          {"SQL(oracle-report)": {
            dialect: "oracle", format: "sqlplus", effects: {only: ["read"]}
          }},
          "Shell(docker exec ... bash <SHELL> -l -c)",
          "Shell(sqlplus stdin(<SQL:oracle-report>))"
        ]""",
    )
    inner = (
        "printf '%s\\n' 'set pagesize 100 feedback off linesize 260 trimspool on' "
        "'column nmi_id format a12' "
        "'select n.nmi_id from process.meter n order by n.nmi_id;' 'exit' "
        "| sqlplus -s process/example@DATABASE"
    )
    escaped = inner.replace('"', '\\"')
    command = f'docker exec arbitrary-container bash -lc "{escaped}"'
    assert _decide(policy, command).decision is Decision.Allow


def test_nested_exec_capture_applies_rules_to_wrapped_argv() -> None:
    policy = _policy(
        allow='["Shell(wrapper <EXEC>)", "Shell(inspector !-*)"]',
    )
    assert _decide(policy, "wrapper inspector file.txt").decision is Decision.Allow


def test_nested_exec_preserves_inner_flags_for_denies() -> None:
    policy = _policy(
        allow='["Shell(wrapper <EXEC>)"]',
        deny='["Shell(rm -r -f)"]',
    )
    assert _decide(policy, "wrapper rm -rf /tmp/example").decision is Decision.Deny


def test_python_call_capture_is_target_and_argument_driven() -> None:
    policy = _policy(
        allow="""[
          {"SQL(reporting)": {dialect: "postgres", effects: {only: ["read"]}}},
          "Python(project.database.inspect(sql=<SQL:reporting>))"
        ]""",
    )
    read = "python -c \"project.database.inspect(sql='select * from reporting.meters')\""
    write = "python -c \"project.database.inspect(sql='update reporting.meters set active=false')\""
    dynamic = "python -c \"project.database.inspect(sql=get_query())\""
    assert _decide(policy, read).decision is Decision.Allow
    assert _decide(policy, write).decision is Decision.Ask
    assert _decide(policy, dynamic).decision is Decision.Ask


def test_python_wildcard_target_and_static_local_string() -> None:
    pattern = parse_rule("Python(*.execute(<SQL:reporting>))")
    assert isinstance(pattern, PythonSqlPattern)
    policy = _policy(
        allow="""[
          {"SQL(reporting)": {dialect: "sqlite", effects: {only: ["read"]}}},
          "Python(*.execute(<SQL:reporting>))"
        ]""",
    )
    command = "python -c \"query='select * from meter'; cursor.execute(query)\""
    assert _decide(policy, command).decision is Decision.Allow


def test_python_capture_rule_does_not_allow_unrelated_python() -> None:
    policy = _policy(
        allow="""[
          {"SQL(reporting)": {dialect: "sqlite", effects: {only: ["read"]}}},
          "Python(query_db(<SQL:reporting>))"
        ]""",
    )
    assert _decide(policy, "python -c 'print(1)'").decision is Decision.NoOpinion


def test_python_ask_and_deny_capture_decisions_are_active() -> None:
    ask_policy = _policy(
        allow='[{"SQL(reporting)": {dialect: "sqlite", effects: {only: ["read"]}}}]',
        ask='["Python(query_db(<SQL:reporting>))"]',
    )
    deny_policy = _policy(
        allow='[{"SQL(reporting)": {dialect: "sqlite", effects: {only: ["read"]}}}]',
        deny='["Python(query_db(<SQL:reporting>))"]',
    )
    command = "python -c \"query_db('select * from meter')\""
    assert _decide(ask_policy, command).decision is Decision.Ask
    assert _decide(deny_policy, command).decision is Decision.Deny


def test_connection_environment_and_non_sql_options_stay_generic() -> None:
    policy = _policy(
        allow="""[
          {"SQL(reporting)": {dialect: "postgres", effects: {only: ["read"]}}},
          "Shell(source *)",
          "Shell(dbcli values(-h,-p,-U,-d,-v,-P) sqlvalues(<SQL:reporting>,-c))"
        ]""",
    )
    first = (
        "with summary as (select meter_id,count(*) channels from process.channel group by meter_id) "
        "select meter_id,channels from summary order by meter_id"
    )
    second = "select meter_id from process.meter order by meter_id fetch first 20 rows only"
    command = (
        "source /project/config.env && CONNECTION_SECRET=\"$SECRET\" /custom/bin/dbcli -X "
        "-h \"$HOST\" -p \"$PORT\" -U \"$USER\" -d \"$DATABASE\" "
        f"-v STOP=1 -P pager=off -c \"{first}\" -c \"{second}\""
    )
    assert _decide(policy, command).decision is Decision.Allow


def test_postgres_explain_classifies_the_inner_statement() -> None:
    policy = _policy(
        allow="""[
          {"SQL(reporting)": {
            dialect: "postgres", effects: {only: ["read", "session-change"]}
          }},
          "Shell(dbcli sqlvalues(<SQL:reporting>,-q))"
        ]""",
    )
    read = (
        "set statement_timeout='20s'; "
        "explain (analyze, buffers, summary) select * from reporting.meters"
    )
    assert _decide(policy, f'dbcli -q "{read}"').decision is Decision.Allow
    assert _decide(policy, "dbcli -q 'explain delete from reporting.meters'").decision is Decision.Ask
    facts = parse_sql(
        "explain analyze delete from reporting.meters",
        SqlDialect.Postgres,
        SqlDocumentFormat.Plain,
    )
    assert facts.effects == frozenset({SqlEffect.DataWrite})


def test_unsupported_postgres_explain_option_fails_closed() -> None:
    with pytest.raises(SqlParseError, match="unsupported option"):
        parse_sql(
            "explain (analyze, arbitrary) select * from reporting.meters",
            SqlDialect.Postgres,
            SqlDocumentFormat.Plain,
        )


def test_shell_capture_parser_is_generic() -> None:
    rule = parse_rule("Shell(arbitrary sqlvalues(<SQL:profile>,-x,--text) stdin(<SQL>))")
    assert isinstance(rule, ShellPattern)
    assert rule.sql_value_captures == (("profile", ("-x", "--text")),)
    assert rule.captures_stdin_sql
