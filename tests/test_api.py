"""Versioned JSON API contract tests."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentperm import POLICY_FILENAME, main
from agentperm.domain import JsonObject
from tests.json_support import array_at, decode_object, text_at


def _call_api(
    request: JsonObject,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, JsonObject]:
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(request)))
    status = main(["api"])
    captured = capsys.readouterr()
    assert captured.err == ""
    return status, decode_object(captured.out)


def _write_policy(path: Path, permissions: str, *, include: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    document: JsonObject = {"version": 1, "permissions": {"allow": [permissions]}}
    if include is not None:
        document["include"] = [include]
    path.write_text(json.dumps(document))


def test_api_info_describes_the_supported_contract(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    status, response = _call_api(
        {"protocol_version": 1, "operation": "info"}, monkeypatch, capsys
    )

    assert status == 0
    assert response["protocol_version"] == 1
    assert response["ok"] is True
    result = response["result"]
    assert isinstance(result, dict)
    assert result["operations"] == [
        "info",
        "explain",
        "sources",
        "rule.describe",
        "policy.plan",
        "policy.apply",
        "policy.undo",
    ]
    assert isinstance(result["agentperm_version"], str)


def test_api_explain_returns_typed_verdict_segments_and_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "home"
    cwd = tmp_path / "repo"
    fragment = home / ".agent-permissions.d" / "git.jsonc"
    home.mkdir()
    cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    _write_policy(fragment, "Shell(git {status,diff})")
    (home / POLICY_FILENAME).write_text(json.dumps({"version": 1, "include": [str(fragment)]}))

    status, response = _call_api(
        {
            "protocol_version": 1,
            "operation": "explain",
            "cwd": str(cwd),
            "command": "git status && git diff",
        },
        monkeypatch,
        capsys,
    )

    assert status == 0
    result = response["result"]
    assert isinstance(result, dict)
    assert result["decision"] == "allow"
    assert isinstance(result["rationale"], str)
    assert result["segments"] == [
        {"command": "git status", "decision": "allow", "rationale": "allow by rule 'Shell(git {status,diff})'"},
        {"command": "git diff", "decision": "allow", "rationale": "allow by rule 'Shell(git {status,diff})'"},
    ]
    sources = result["sources"]
    assert isinstance(sources, list)
    assert [source["path"] for source in sources if isinstance(source, dict)] == [
        str(fragment),
        str(home / POLICY_FILENAME),
    ]
    assert all(isinstance(source.get("id"), str) for source in sources if isinstance(source, dict))


def test_api_explain_identifies_redirection_only_file_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "home"
    cwd = tmp_path / "repo"
    home.mkdir()
    cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))

    status, response = _call_api(
        {
            "protocol_version": 1,
            "operation": "explain",
            "cwd": str(cwd),
            "command": 'printf "%s" "$(</tmp/result)"',
        },
        monkeypatch,
        capsys,
    )

    assert status == 0
    result = response["result"]
    assert isinstance(result, dict)
    assert result["decision"] == "ask"
    assert result["segments"] == [
        {"command": "printf %s", "decision": "allow", "rationale": "inert shell builtin"},
        {
            "command": "</tmp/result",
            "decision": "no-opinion",
            "rationale": "commandless input redirection",
        },
    ]


def test_api_explain_uses_shell_cwd_policy_and_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "home"
    cwd = tmp_path / "caller"
    target = tmp_path / "protected" / "secret" / "key"
    home.mkdir()
    cwd.mkdir()
    target.parent.mkdir(parents=True)
    target.write_text("secret")
    monkeypatch.setenv("HOME", str(home))
    _write_policy(cwd / POLICY_FILENAME, "Shell(cat)")
    protected_policy = tmp_path / "protected" / POLICY_FILENAME
    protected_policy.write_text(
        json.dumps({"version": 1, "permissions": {"deny": ["Read(secret/**)"]}})
    )

    status, response = _call_api(
        {
            "protocol_version": 1,
            "operation": "explain",
            "cwd": str(cwd),
            "command": f"cat {target}",
        },
        monkeypatch,
        capsys,
    )

    assert status == 0
    result = response["result"]
    assert isinstance(result, dict)
    assert result["decision"] == "allow"
    assert [text_at(segment, "decision") for segment in array_at(result, "segments")] == ["allow"]
    assert str(protected_policy) not in [
        text_at(source, "path") for source in array_at(result, "sources")
    ]


def test_api_sources_preserves_policy_layers_and_include_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "home"
    cwd = tmp_path / "repo" / "src"
    fragment = home / ".agent-permissions.d" / "base.jsonc"
    project = tmp_path / "repo" / POLICY_FILENAME
    home.mkdir()
    cwd.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    _write_policy(fragment, "Read")
    (home / POLICY_FILENAME).write_text(json.dumps({"version": 1, "include": [str(fragment)]}))
    _write_policy(project, "Shell(git status)")

    request: JsonObject = {
        "protocol_version": 1,
        "operation": "sources",
        "cwd": str(cwd),
    }
    status, first = _call_api(request, monkeypatch, capsys)
    _, second = _call_api(request, monkeypatch, capsys)

    assert status == 0
    result = first["result"]
    assert isinstance(result, dict)
    layers = result["layers"]
    assert isinstance(layers, list)
    assert [
        [text_at(source, "path") for source in array_at(layer, "sources")]
        for layer in layers
    ] == [
        [str(fragment), str(home / POLICY_FILENAME)],
        [str(project)],
    ]
    assert [text_at(layer, "root", "path") for layer in layers] == [
        str(home / POLICY_FILENAME),
        str(project),
    ]
    assert all(text_at(layer, "root", "id").startswith("policy-source-v1-") for layer in layers)
    assert first == second
    targets = result["targets"]
    assert isinstance(targets, list)
    assert any(
        isinstance(target, dict) and target["path"] == str(home / POLICY_FILENAME)
        for target in targets
    )


def test_api_policy_plan_apply_and_undo_use_opaque_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    home.mkdir()
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTPERM_PLAN_DIR", str(tmp_path / "plans"))
    _, sources = _call_api(
        {"protocol_version": 1, "operation": "sources", "cwd": str(repo)},
        monkeypatch,
        capsys,
    )
    source_result = sources["result"]
    assert isinstance(source_result, dict)
    targets = source_result["targets"]
    assert isinstance(targets, list)
    project = next(
        target for target in targets if isinstance(target, dict) and target["scope"] == "project"
    )

    status, planned = _call_api(
        {
            "protocol_version": 1,
            "operation": "policy.plan",
            "contexts": [str(repo)],
            "files": [
                {
                    "target_id": project["id"],
                    "edits": [
                        {
                            "action": "add",
                            "decision": "allow",
                            "rule": {
                                "SQL(read-only)": {
                                    "dialect": "sqlite",
                                    "effects": {"only": ["read"]},
                                }
                            },
                        }
                    ],
                }
            ],
        },
        monkeypatch,
        capsys,
    )
    assert status == 0
    plan_result = planned["result"]
    assert isinstance(plan_result, dict)
    assert not (repo / POLICY_FILENAME).exists()

    status, applied = _call_api(
        {
            "protocol_version": 1,
            "operation": "policy.apply",
            "plan_id": plan_result["plan_id"],
        },
        monkeypatch,
        capsys,
    )
    assert status == 0
    assert (repo / POLICY_FILENAME).exists()
    applied_result = applied["result"]
    assert isinstance(applied_result, dict)

    status, _ = _call_api(
        {
            "protocol_version": 1,
            "operation": "policy.undo",
            "plan_id": applied_result["undo_id"],
        },
        monkeypatch,
        capsys,
    )
    assert status == 0
    assert not (repo / POLICY_FILENAME).exists()


def test_api_rule_describe_accepts_native_structured_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    value: JsonObject = {
        "SQL(read-only)": {"dialect": "sqlite", "effects": {"only": ["read"]}}
    }

    status, response = _call_api(
        {"protocol_version": 1, "operation": "rule.describe", "value": value},
        monkeypatch,
        capsys,
    )

    assert status == 0
    result = response["result"]
    assert isinstance(result, dict)
    canonical = result["canonical_value"]
    assert isinstance(canonical, dict)
    assert canonical["SQL(read-only)"] == {
        "dialect": "sqlite",
        "effects": {"only": ["read"]},
        "format": "plain",
    }
    assert result["kind"] == "sql"
    assert result["semantic_effect"] == "read_only"
    assert result["valid_decisions"] == ["allow", "ask", "deny"]


def test_api_rule_describe_reports_unparseable_values_as_policy_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    status, response = _call_api(
        {"protocol_version": 1, "operation": "rule.describe", "value": {"not": "a rule"}},
        monkeypatch,
        capsys,
    )

    assert status == 1
    error = response["error"]
    assert isinstance(error, dict)
    assert error["code"] == "policy_error"
    assert isinstance(error["message"], str)
    assert error["message"]


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("not json", "invalid_json"),
        ("[]", "invalid_request"),
        ('{"protocol_version":2,"operation":"info"}', "unsupported_protocol_version"),
        ('{"protocol_version":1,"operation":"missing"}', "unknown_operation"),
        ('{"protocol_version":1,"operation":"explain","cwd":1,"command":"pwd"}', "invalid_request"),
        ('{"protocol_version":1,"operation":"info"} {}', "invalid_json"),
        ('{"protocol_version":1,"operation":"explain","cwd":"/tmp","command":"\\ud800"}', "invalid_request"),
        (f'{{"protocol_version":1,"operation":"info","extra":{("9" * 5000)}}}', "invalid_json"),
    ],
)
def test_api_errors_always_use_the_versioned_json_envelope(
    raw: str,
    code: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(raw))

    assert main(["api"]) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    response = decode_object(captured.out)
    assert response["protocol_version"] == 1
    assert response["ok"] is False
    error = response["error"]
    assert isinstance(error, dict)
    assert error["code"] == code
    assert isinstance(error["message"], str)


def test_api_reports_policy_load_errors_without_leaking_a_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "home"
    cwd = tmp_path / "repo"
    home.mkdir()
    cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    (home / POLICY_FILENAME).write_text('{"include":["missing/*.jsonc"]}')

    status, response = _call_api(
        {"protocol_version": 1, "operation": "sources", "cwd": str(cwd)},
        monkeypatch,
        capsys,
    )

    assert status == 1
    error = response["error"]
    assert isinstance(error, dict)
    assert error["code"] == "policy_error"
    assert "matched no files" in str(error["message"])
