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


def test_mistyped_shell_prefix_warns() -> None:
    text = '{"permissions": {"allow": ["Shel(git status)"]}}'
    warnings = _messages(text, "warning")
    assert any("did you mean Shell" in m for m in warnings)


def test_unknown_keys_warn() -> None:
    text = '{"version": 1, "permisions": {}, "permissions": {"denied": []}}'
    warnings = _messages(text, "warning")
    assert any("'permisions'" in m for m in warnings)
    assert any("'denied'" in m for m in warnings)


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
    warned.write_text('{"version": 1, "permissions": {"allow": ["Shel(git status)"]}}')
    assert main(["validate", str(warned)]) == 0


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
