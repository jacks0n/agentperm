"""`agentperm validate` — catching what the tolerant runtime loader lets slide."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentperm import main, validate_policy_text
from agentperm.policy import DEFAULT_TEMPLATES, load_template, render_templates


def _messages(text: str, severity: str | None = None) -> list[str]:
    return [f.message for f in validate_policy_text(text) if severity is None or f.severity == severity]


def test_clean_policy_has_no_findings() -> None:
    text = '{"version": 1, "permissions": {"allow": ["Shell(git status)"], "deny": ["Shell(sudo)"]}}'
    assert validate_policy_text(text) == []


def test_bundled_templates_validate_clean() -> None:
    text = render_templates([load_template(name) for name in DEFAULT_TEMPLATES])
    assert validate_policy_text(text) == []


def test_invalid_jsonc_is_an_error() -> None:
    assert any("invalid JSON/JSONC" in m for m in _messages('{"version": 1', "error"))


def test_silently_dropped_entries_are_errors() -> None:
    text = '{"permissions": {"allow": ["", 42]}}'
    errors = _messages(text, "error")
    assert any("allow[0]" in m and "silently ignored" in m for m in errors)
    assert any("allow[1]" in m for m in errors)


def test_malformed_shell_rule_reports_position() -> None:
    text = '{"permissions": {"deny": ["Shell(sudo)", "Shell(rm -rf"]}}'
    errors = _messages(text, "error")
    assert any("deny[1]" in m and "missing closing parenthesis" in m for m in errors)


def test_unknown_keys_warn() -> None:
    text = '{"version": 1, "permisions": {}, "permissions": {"denied": []}}'
    warnings = _messages(text, "warning")
    assert any("'permisions'" in m for m in warnings)
    assert any("'denied'" in m for m in warnings)


def test_include_accepts_paths_and_globs() -> None:
    assert validate_policy_text('{"include": ["parts/core.jsonc", "parts/*.jsonc"]}') == []


@pytest.mark.parametrize("include", ['"parts/*.jsonc"', "{}", '["", 42]'])
def test_invalid_include_shape_is_an_error(include: str) -> None:
    assert any("include" in message for message in _messages(f'{{"include": {include}}}', "error"))


def test_bad_redirect_decision_is_an_error() -> None:
    text = '{"shell": {"redirection": {"stdoutToFile": "allw"}}}'
    assert any("allow/ask/deny" in m for m in _messages(text, "error"))


def test_bad_allow_path_is_an_error() -> None:
    text = '{"shell": {"redirection": {"allowPaths": ["/tmp", ""]}}}'
    assert any("allowPaths[1]" in m for m in _messages(text, "error"))


def test_bad_python_calls_are_errors() -> None:
    text = '{"python": {"calls": {"allow": ["os.getcwd", ""], "deny": "nope"}}}'
    errors = _messages(text, "error")
    assert any("python.calls.allow" in m for m in errors)
    assert any("python.calls.deny" in m for m in errors)


@pytest.mark.parametrize(
    "entry",
    [
        '{"Edit(generated/**)": {"reason": ""}}',
        '{"Write(generated/**)": {"reason": 42}}',
        '{"rule": "Read(secrets/**)", "reason": null}',
        '{"tool": "Bash", "command": "sed", "when": {"hasOption": "-i"}, "reason": "   "}',
    ],
)
def test_invalid_rule_reason_is_an_error_without_making_rule_unparseable(entry: str) -> None:
    errors = _messages(f'{{"permissions": {{"deny": [{entry}]}}}}', "error")
    assert any("'reason' must be a non-empty string" in message for message in errors)
    assert not any("unparseable rule" in message for message in errors)


def test_valid_rule_reason_has_no_finding() -> None:
    text = '{"permissions": {"deny": [{"Write(generated/**)": {"reason": "Generated file"}}]}}'
    assert validate_policy_text(text) == []


@pytest.mark.parametrize(
    ("entry", "hint"),
    [
        ('"Edit"', 'use "Write"'),
        ('"Edit(generated/**)"', 'use "Write(generated/**)"'),
        ('{"Edit(generated/**)": {"reason": "Generated"}}', 'use "Write(generated/**)"'),
        ('"Glob"', 'use "Read"'),
        ('"Grep(src/**)"', 'use "Read(src/**)"'),
        ('"LS"', 'use "Read"'),
        ('"read_file"', 'use "Read"'),
        ('"webfetch"', 'use "WebFetch"'),
        ('"Search"', "known tools: AWS, Code, Knowledge, Read, Skill, WebFetch, WebSearch, Write"),
        ('"Task"', "known tools:"),
        ('"Nope*"', "known tools:"),
        ('"mcp__coderift__outline"', 'use "MCP(coderift.outline)"'),
        ('"Shel(git status)"', "did you mean Shell(...)"),
    ],
)
def test_rule_naming_no_agentperm_tool_is_an_error(entry: str, hint: str) -> None:
    text = f'{{"permissions": {{"deny": [{entry}]}}}}'
    errors = _messages(text, "error")
    assert any("matches no tool" in m and hint in m for m in errors), errors


@pytest.mark.parametrize(
    "entry",
    ['"Read"', '"Read(src/**)"', '"Write(generated/**)"', '"WebFetch(domain:github.com)"', '"Web*"', '"*"'],
)
def test_rule_naming_a_capability_is_clean(entry: str) -> None:
    assert validate_policy_text(f'{{"permissions": {{"allow": [{entry}]}}}}') == []


def test_multi_key_rule_as_key_object_is_an_error() -> None:
    text = """{
        "permissions": {
            "allow": [{
                "Shell(git status)": {"reason": "Inspect the worktree."},
                "comment": "This sibling must not be silently ignored."
            }]
        }
    }"""

    errors = _messages(text, "error")

    assert len(errors) == 1
    assert "unparseable rule" in errors[0]


# --- the validate command -------------------------------------------------


def test_cli_validate_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = tmp_path / "good.jsonc"
    good.write_text('{"version": 1, "permissions": {"allow": ["Read"]}}')
    bad = tmp_path / "bad.jsonc"
    bad.write_text('{"permissions": {"allow": [""]}}')

    assert main(["validate", str(good)]) == 0
    assert "ok" in capsys.readouterr().out
    assert main(["validate", str(good), str(bad)]) == 1
    out = capsys.readouterr().out
    assert "error:" in out


def test_cli_validate_warnings_alone_exit_zero(tmp_path: Path) -> None:
    warned = tmp_path / "warned.jsonc"
    warned.write_text('{"version": 1, "extra": true, "permissions": {"allow": ["Read"]}}')
    assert main(["validate", str(warned)]) == 0


def test_cli_validate_rejects_a_native_tool_name(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    native = tmp_path / "native.jsonc"
    native.write_text('{"version": 1, "permissions": {"allow": ["Edit(src/**)"]}}')
    assert main(["validate", str(native)]) == 1
    out = capsys.readouterr().out
    assert "error:" in out
    assert '"Write(src/**)"' in out


def test_cli_validate_explicit_root_follows_includes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    included = tmp_path / "included.jsonc"
    included.write_text('{"permissions":{"allow":[""]}}')
    root = tmp_path / "root.jsonc"
    root.write_text('{"include":["included*.jsonc"]}')

    assert main(["validate", str(root)]) == 1
    out = capsys.readouterr().out
    assert str(included) in out
    assert "silently ignored" in out


def test_cli_validate_reports_unmatched_include_glob(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "root.jsonc"
    root.write_text('{"include":["missing/*.jsonc"]}')

    assert main(["validate", str(root)]) == 1
    assert "matched no files" in capsys.readouterr().out


def test_cli_validate_defaults_to_discovered_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.chdir(workdir)

    assert main(["validate"]) == 0
    assert "no policy files found" in capsys.readouterr().out

    (home / ".agent-permissions.jsonc").write_text('{"permissions": {"allow": [""]}}')
    (workdir / ".agent-permissions.jsonc").write_text('{"version": 1, "permissions": {"allow": ["Read"]}}')
    assert main(["validate"]) == 1
    out = capsys.readouterr().out
    assert str(home / ".agent-permissions.jsonc") in out
    assert "ok" in out  # the clean workdir file still reports
