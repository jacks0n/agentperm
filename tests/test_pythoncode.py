"""Inline Python AST policy tests."""

from __future__ import annotations

import pytest

from agentperm import (
    BashCommand,
    Decision,
    Policy,
    PolicyError,
    PythonCallPolicy,
    PythonReadonly,
    Rule,
    ShellRequest,
    Verdict,
    parse_pipeline,
    parse_policy_text,
    parse_rule,
)


def _decide(
    command: str,
    *,
    calls: PythonCallPolicy | None = None,
    extra_allow: tuple[Rule, ...] = (),
) -> Verdict:
    policy = Policy(allow=(PythonReadonly(), *extra_allow), python_calls=calls or PythonCallPolicy())
    return policy.decide(ShellRequest(parse_pipeline(command)))


def test_python_readonly_rule_parses_and_serializes() -> None:
    rule = parse_rule("Python(readonly)")
    assert isinstance(rule, PythonReadonly)
    assert rule.serialize() == "Python(readonly)"


def test_python_readonly_rule_is_allow_only() -> None:
    with pytest.raises(PolicyError, match=r"only valid in permissions\.allow"):
        Policy(ask=(PythonReadonly(),))


@pytest.mark.parametrize(
    "command",
    (
        'python -c "import agentperm; print(len(agentperm.__all__))"',
        'PYTHONPATH=src python -c "import agentperm; print(type(agentperm), vars(agentperm))"',
        '.venv/bin/python -c "from agentperm import Policy; print(Policy)"',
        'python3 -c "import inspect; print(inspect.signature(len))"',
        'uv run python -c "from agentperm.adapters.kiro import _kiro_command_rule; '
        "print(_kiro_command_rule('git status'))\"",
    ),
)
def test_readonly_diagnostic_commands_allow(command: str) -> None:
    assert _decide(command).decision is Decision.Allow


def test_readonly_project_call_and_introspection_heredoc_allows() -> None:
    command = """uv run python - <<'PY'
from lib.adapters.common.calendar import get_calendar, VENUE_ASX
c = get_calendar(VENUE_ASX)
print(type(c), vars(c) if hasattr(c, '__dict__') else 'no dict')
print([x for x in dir(c) if 'zone' in x.lower() or 'time' in x.lower()])
PY
"""
    assert _decide(command).decision is Decision.Allow


def test_sql_capture_unwraps_static_sqlalchemy_text() -> None:
    policy = parse_policy_text(
        """
        {
          permissions: {
            allow: [
              {"SQL(read-only)": {dialect: "postgres", effects: {only: ["read"]}}},
              "Python(*.execute(<SQL:read-only>))"
            ]
          }
        }
        """,
        "test policy",
    ).policy
    command = """python - <<'PY'
from sqlalchemy import text
sql = "select count(*) from app.records"
with engine.connect() as connection:
    print(connection.execute(text(sql)).one())
PY
"""
    assert policy.decide(ShellRequest(parse_pipeline(command))).decision is Decision.Allow


def test_sql_capture_resolves_bounded_local_string_builders() -> None:
    policy = parse_policy_text(
        """
        {
          permissions: {
            allow: [
              {"SQL(read-only)": {dialect: "postgres", effects: {only: ["read"]}}},
              "Python(*.execute(<SQL:read-only>))"
            ]
          }
        }
        """,
        "test policy",
    ).policy
    command = """python - <<'PY'
from sqlalchemy import text
for mode in ('primary', 'archive'):
    def relation(name):
        return ('ONLY app.' + name) if mode == 'primary' else ('app.' + name + '_current')
    def active(alias):
        return f"{alias}.active = true"
    sql = f"select count(*) from {relation('records')} m where {active('m')}"
    print(connection.execute(text(sql)).one())
PY
"""
    assert policy.decide(ShellRequest(parse_pipeline(command))).decision is Decision.Allow


def test_sql_capture_checks_every_local_string_builder_result() -> None:
    policy = parse_policy_text(
        """
        {
          permissions: {
            allow: [
              {"SQL(read-only)": {dialect: "postgres", effects: {only: ["read"]}}},
              "Python(*.execute(<SQL:read-only>))"
            ]
          }
        }
        """,
        "test policy",
    ).policy
    command = """python - <<'PY'
from sqlalchemy import text
def query():
    return "select * from app.records" if inspect_only else "delete from app.records"
connection.execute(text(query()))
PY
"""
    assert policy.decide(ShellRequest(parse_pipeline(command))).decision is Decision.Ask


def test_function_local_string_does_not_make_outer_dynamic_sql_static() -> None:
    policy = parse_policy_text(
        """
        {
          permissions: {
            allow: [
              {"SQL(read-only)": {dialect: "postgres", effects: {only: ["read"]}}},
              "Python(*.execute(<SQL:read-only>))"
            ]
          }
        }
        """,
        "test policy",
    ).policy
    command = """python - <<'PY'
from sqlalchemy import text
sql = get_query()
def unrelated():
    sql = "select * from app.records"
connection.execute(text(sql))
PY
"""
    assert policy.decide(ShellRequest(parse_pipeline(command))).decision is Decision.Ask


@pytest.mark.parametrize(
    ("queries", "expected"),
    (
        (("select * from app.records", "select count(*) from app.records"), Decision.Allow),
        (("select * from app.records", "delete from app.records"), Decision.Ask),
    ),
)
def test_sql_capture_checks_every_bounded_loop_value(queries: tuple[str, ...], expected: Decision) -> None:
    policy = parse_policy_text(
        """
        {
          permissions: {
            allow: [
              {"SQL(read-only)": {dialect: "postgres", effects: {only: ["read"]}}},
              "Python(*.execute(<SQL:read-only>))"
            ]
          }
        }
        """,
        "test policy",
    ).policy
    source_values = ", ".join(repr(query) for query in queries)
    command = f"""python - <<'PY'
from sqlalchemy import text
for sql in ({source_values}):
    connection.execute(text(sql))
PY
"""
    assert policy.decide(ShellRequest(parse_pipeline(command))).decision is expected


def test_readonly_file_search_with_exception_handling_allows() -> None:
    command = """python - <<'PY'
from pathlib import Path
for p in Path('.venv').rglob('*'):
    if p.is_file() and p.suffix in {'.json', '.js', '.py', '.md'}:
        try:
            text = p.read_text(errors='ignore')
        except OSError:
            continue
        if 'reportExplicitAny' in text or 'max-module-lines' in text:
            print(p)
PY
"""
    assert _decide(command).decision is Decision.Allow


def test_multiline_python_c_import_list_allows() -> None:
    command = """python -c "
from agentperm import (
    AgentAdapter, AgentName, BashCommand, Policy
)
print('All old public names still importable from agentperm')
" 2>&1"""
    assert _decide(command).decision is Decision.Allow


@pytest.mark.parametrize(
    ("source", "reason"),
    (
        ("open('out', 'w')", "writing"),
        ("from pathlib import Path\nPath('out').write_text('x')", "pathlib.Path.write_text"),
        ("import os as operating\noperating.remove('out')", "os.remove"),
        ("from os import remove as r\nr('out')", "os.remove"),
        ("import subprocess\nsubprocess.run(['touch', 'out'])", "subprocess.run"),
        ("importlib.import_module('os').system('id')", "system"),
        ("lib.popen('cmd')", "popen"),
        ("client.delete_item(Key={'id': 1})", "client.delete_item"),
        ("obj.value = 1", "Attribute mutation"),
        ("items[0] = 1", "Subscript mutation"),
        ("(factory())()", "dynamic Python call"),
    ),
)
def test_known_mutation_or_unknown_call_asks(source: str, reason: str) -> None:
    command_source = source.replace("\n", "; ")
    verdict = _decide(f'python -c "{command_source}"')
    assert verdict.decision is Decision.Ask
    assert reason in verdict.rationale


def test_assignment_alias_not_called_is_allowed() -> None:
    command = 'python -c "import os; f = os.remove; print(f)"'
    assert _decide(command).decision is Decision.Allow


@pytest.mark.parametrize(
    ("source", "reason"),
    (
        ("import subprocess; r = subprocess.run; r(['rm', '-rf', '/'])", "subprocess.run"),
        ("import os; f = os.remove; f('important')", "os.remove"),
        ("from os import remove; r = remove; r('file')", "os.remove"),
        ("import shutil; d = shutil.rmtree; d('/tmp/x')", "shutil.rmtree"),
    ),
)
def test_assignment_rebinding_tracked_for_calls(source: str, reason: str) -> None:
    verdict = _decide(f'python -c "{source}"')
    assert verdict.decision is Decision.Ask
    assert reason in verdict.rationale


def test_assignment_rebinding_respects_deny_policy() -> None:
    calls = PythonCallPolicy(deny=frozenset({"project.forbidden"}))
    source = "from project import forbidden; f = forbidden; f()"
    verdict = _decide(f'python -c "{source}"', calls=calls)
    assert verdict.decision is Decision.Deny
    assert "project.forbidden" in verdict.rationale


def test_python_call_allow_overrides_builtin_mutation_catalogue() -> None:
    calls = PythonCallPolicy(allow=frozenset({"os.remove"}))
    assert _decide("python -c \"from os import remove; remove('out')\"", calls=calls).decision is Decision.Allow


def test_python_call_ask_overrides_ordinary_call_default() -> None:
    calls = PythonCallPolicy(ask=frozenset({"project.inspect"}))
    verdict = _decide('python -c "from project import inspect; inspect()"', calls=calls)
    assert verdict.decision is Decision.Ask
    assert "requires approval by policy" in verdict.rationale


def test_python_call_deny_returns_deny() -> None:
    calls = PythonCallPolicy(deny=frozenset({"project.forbidden"}))
    verdict = _decide('python -c "from project import forbidden; forbidden()"', calls=calls)
    assert verdict.decision is Decision.Deny


def test_python_call_policy_deny_beats_allow_for_same_target() -> None:
    calls = PythonCallPolicy(
        deny=frozenset({"project.operation"}),
        allow=frozenset({"project.operation"}),
    )
    assert _decide('python -c "from project import operation; operation()"', calls=calls).decision is Decision.Deny


def test_python_guard_beats_broad_shell_allow() -> None:
    verdict = _decide(
        "python -c \"open('out', 'w')\"",
        extra_allow=(BashCommand(("python",)),),
    )
    assert verdict.decision is Decision.Ask


def test_python_m_and_script_execution_remain_outside_inline_guard() -> None:
    assert _decide("python -m pytest").decision is Decision.NoOpinion
    assert _decide("python script.py").decision is Decision.NoOpinion


def test_python_stdin_without_literal_heredoc_asks() -> None:
    assert _decide("python -").decision is Decision.Ask


def test_dynamic_unquoted_heredoc_asks() -> None:
    command = """python - <<PY
print('$VALUE')
PY
"""
    verdict = _decide(command)
    assert verdict.decision is Decision.Ask
    assert "shell expansion" in verdict.rationale


def test_malformed_inline_python_asks() -> None:
    verdict = _decide("python -c 'def nope('")
    assert verdict.decision is Decision.Ask
    assert "not parseable" in verdict.rationale
