from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import agentperm.policy_api as policy_api
from agentperm import POLICY_FILENAME
from agentperm.domain import JsonValue
from agentperm.errors import PolicyError
from agentperm.json_boundary import decode_jsonc
from agentperm.policy_api import (
    apply_policy_plan,
    create_policy_plan,
    discover_policy_targets,
    undo_policy_plan,
)


def _repository(path: Path) -> None:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)


def _project_target(repo: Path) -> str:
    targets = discover_policy_targets([repo])
    return next(target.id for target in targets if target.scope == "project")


def _plan_files(target_id: str, rule: JsonValue) -> JsonValue:
    return [
        {
            "target_id": target_id,
            "edits": [{"action": "add", "decision": "allow", "rule": rule}],
        }
    ]


def test_plan_apply_and_undo_preserve_json5_and_use_exact_reviewed_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    plans = tmp_path / "plans"
    home.mkdir()
    _repository(repo)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTPERM_PLAN_DIR", str(plans))
    policy = repo / POLICY_FILENAME
    original = "{\n  // keep me\n  permissions: {allow: ['Read',],},\n}\n"
    policy.write_text(original)

    plan = create_policy_plan([repo], _plan_files(_project_target(repo), "Python(readonly)"))

    assert policy.read_text() == original
    files = plan["files"]
    assert isinstance(files, list)
    planned = files[0]
    assert isinstance(planned, dict)
    assert '"Python(readonly)"' in str(planned["diff"])
    result = apply_policy_plan(str(plan["plan_id"]))
    applied = policy.read_text()
    assert "// keep me" in applied
    assert decode_jsonc(applied) == {
        "permissions": {"allow": ["Read", "Python(readonly)"]}
    }

    undo_policy_plan(str(result["undo_id"]))

    assert policy.read_text() == original


def test_plan_accepts_native_structured_rule_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    home.mkdir()
    _repository(repo)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTPERM_PLAN_DIR", str(tmp_path / "plans"))
    rule = {"SQL(read-only)": {"dialect": "sqlite", "effects": {"only": ["read"]}}}

    plan = create_policy_plan([repo], _plan_files(_project_target(repo), rule))
    result = apply_policy_plan(str(plan["plan_id"]))

    policy = decode_jsonc((repo / POLICY_FILENAME).read_text())
    assert isinstance(policy, dict)
    permissions = policy["permissions"]
    assert isinstance(permissions, dict)
    allow = permissions["allow"]
    assert isinstance(allow, list)
    assert allow[0] == {
        "SQL(read-only)": {
            "dialect": "sqlite",
            "effects": {"only": ["read"]},
            "format": "plain",
        }
    }
    undo_policy_plan(str(result["undo_id"]))
    assert not (repo / POLICY_FILENAME).exists()


def test_apply_fails_closed_when_policy_changed_after_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    home.mkdir()
    _repository(repo)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTPERM_PLAN_DIR", str(tmp_path / "plans"))
    policy = repo / POLICY_FILENAME
    policy.write_text('{"version":1,"permissions":{"allow":[]}}\n')
    plan = create_policy_plan([repo], _plan_files(_project_target(repo), "Read"))
    changed = '{"version":1,"permissions":{"allow":["Write"]}}\n'
    policy.write_text(changed)

    with pytest.raises(PolicyError, match="changed after review"):
        apply_policy_plan(str(plan["plan_id"]))

    assert policy.read_text() == changed


def test_plan_rejects_unknown_target_and_unsupported_policy_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    home.mkdir()
    _repository(repo)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTPERM_PLAN_DIR", str(tmp_path / "plans"))

    with pytest.raises(PolicyError, match="not editable"):
        create_policy_plan([repo], _plan_files("invented", "Read"))

    (repo / POLICY_FILENAME).write_text(json.dumps({"version": 999, "permissions": {}}))
    with pytest.raises(PolicyError, match="unsupported version"):
        create_policy_plan([repo], _plan_files(_project_target(repo), "Read"))


def test_used_apply_and_undo_plans_cannot_be_replayed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    home.mkdir()
    _repository(repo)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTPERM_PLAN_DIR", str(tmp_path / "plans"))
    plan = create_policy_plan([repo], _plan_files(_project_target(repo), "Read"))
    plan_id = str(plan["plan_id"])
    applied = apply_policy_plan(plan_id)

    with pytest.raises(PolicyError, match="not found"):
        apply_policy_plan(plan_id)
    undo_id = str(applied["undo_id"])
    undo_policy_plan(undo_id)
    with pytest.raises(PolicyError, match="not found"):
        undo_policy_plan(undo_id)


def test_crlf_policy_round_trips_as_exact_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    home.mkdir()
    _repository(repo)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTPERM_PLAN_DIR", str(tmp_path / "plans"))
    policy = repo / POLICY_FILENAME
    original = b'{\r\n  "version": 1,\r\n  "permissions": {"allow": []}\r\n}\r\n'
    policy.write_bytes(original)

    plan = create_policy_plan([repo], _plan_files(_project_target(repo), "Read"))
    applied = apply_policy_plan(str(plan["plan_id"]))

    assert b"\r\n" in policy.read_bytes()
    assert b"\n" not in policy.read_bytes().replace(b"\r\n", b"")
    undo_policy_plan(str(applied["undo_id"]))
    assert policy.read_bytes() == original


def test_apply_does_not_mutate_policy_if_undo_plan_cannot_be_persisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    home.mkdir()
    _repository(repo)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTPERM_PLAN_DIR", str(tmp_path / "plans"))
    policy = repo / POLICY_FILENAME
    original = b'{"version":1,"permissions":{"allow":[]}}\n'
    policy.write_bytes(original)
    plan = create_policy_plan([repo], _plan_files(_project_target(repo), "Read"))

    def fail_to_persist(_: object) -> None:
        raise OSError("cache full")

    monkeypatch.setattr(policy_api, "_write_plan", fail_to_persist)
    with pytest.raises(OSError, match="cache full"):
        apply_policy_plan(str(plan["plan_id"]))

    assert policy.read_bytes() == original


def test_creating_a_plan_removes_expired_plan_documents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    plans = tmp_path / "plans"
    home.mkdir()
    plans.mkdir()
    _repository(repo)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTPERM_PLAN_DIR", str(plans))
    expired = plans / "expired.json"
    expired.write_text('{"plan_version":1,"expires_at":0}')

    create_policy_plan([repo], _plan_files(_project_target(repo), "Read"))

    assert not expired.exists()


def test_consumed_plan_cleanup_failure_does_not_hide_apply_or_undo_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    home.mkdir()
    _repository(repo)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTPERM_PLAN_DIR", str(tmp_path / "plans"))
    plan = create_policy_plan([repo], _plan_files(_project_target(repo), "Read"))

    def fail_cleanup(_: str) -> None:
        raise OSError("cleanup denied")

    monkeypatch.setattr(policy_api, "_delete_plan", fail_cleanup)
    applied = apply_policy_plan(str(plan["plan_id"]))
    assert (repo / POLICY_FILENAME).exists()

    result = undo_policy_plan(str(applied["undo_id"]))
    assert result == {"restored_files": 1}
    assert not (repo / POLICY_FILENAME).exists()


def test_shared_include_target_retains_every_consumer_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    first = tmp_path / "first"
    second = tmp_path / "second"
    fragment = tmp_path / "shared.jsonc"
    home.mkdir()
    _repository(first)
    _repository(second)
    monkeypatch.setenv("HOME", str(home))
    fragment.write_text('{"version":1,"permissions":{"allow":[]}}')
    root = json.dumps({"version": 1, "include": [str(fragment)]})
    (first / POLICY_FILENAME).write_text(root)
    (second / POLICY_FILENAME).write_text(root)

    targets = discover_policy_targets([first, second])
    shared = next(target for target in targets if target.path == fragment)

    assert shared.scope == "project"
    assert set(shared.contexts) == {first.resolve(), second.resolve()}
