"""Policy decision tests — strictness, aggregation, rule matching, bypass coercion."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentperm import (
    Decision,
    JsonObject,
    NamedTool,
    Policy,
    PolicyFile,
    ToolRequest,
    Verdict,
    parse_rule,
    save_policy_file,
)
from tests.json_support import decode_object, json_at

# --- Edit(...) is a deprecated alias for Write(...) ------------------------


@pytest.mark.parametrize(
    ("raw", "specifier", "rationale"),
    [
        ("Edit", None, ""),
        ("Edit(*)", None, ""),
        ("Edit(generated/**)", "generated/**", ""),
        ({"Edit(generated/**)": {"reason": "Regenerate."}}, "generated/**", "Regenerate."),
        ({"rule": "Edit(generated/**)", "reason": "Regenerate."}, "generated/**", "Regenerate."),
    ],
)
def test_edit_rule_is_a_deprecated_alias_for_write(
    raw: str | JsonObject, specifier: str | None, rationale: str
) -> None:
    rule = parse_rule(raw)
    assert isinstance(rule, NamedTool)
    assert rule.name == "Write"
    assert rule.specifier == specifier
    assert rule.rationale == rationale
    canonical = "Write" if specifier is None else f"Write({specifier})"
    assert rule == parse_rule(canonical)
    # The alias is never written back: import/init/save all emit the canonical spelling.
    assert rule.serialize() == (canonical if not rationale else {canonical: {"reason": rationale}})


def test_tool_name_alias_is_exact_and_case_sensitive() -> None:
    assert parse_rule("edit") == NamedTool("edit")
    assert parse_rule("Edit*") == NamedTool("Edit*")
    assert parse_rule("NotebookEdit(**/*.ipynb)") == NamedTool("NotebookEdit", "**/*.ipynb")


def test_edit_and_write_rules_dedupe_after_alias() -> None:
    edit = parse_rule({"Edit(generated/**)": {"reason": "first"}})
    write = parse_rule({"Write(generated/**)": {"reason": "second"}})
    assert edit is not None and write is not None
    merged = Policy(deny=(edit,)).merged_with(Policy(deny=(write,)))
    assert merged.deny == (edit,)
    assert merged.deny[0].rationale == "first"


def test_edit_only_deny_governs_every_write_to_its_scope() -> None:
    # The original bug: an Edit-only deny let a native overwrite through as no-opinion.
    rule = parse_rule({"Edit(generated/**)": {"reason": "Generated — run the generator."}})
    assert rule is not None
    verdict = Policy(deny=(rule,)).decide(ToolRequest("Write", (("file_path", "generated/client.py"),)))
    assert verdict == Verdict(Decision.Deny, "Generated — run the generator.")


def test_save_policy_file_collapses_aliased_duplicates(tmp_path: Path) -> None:
    path = tmp_path / ".agent-permissions.jsonc"
    edit = parse_rule({"Edit(generated/**)": {"reason": "first"}})
    write = parse_rule({"Write(generated/**)": {"reason": "second"}})
    assert edit is not None and write is not None
    save_policy_file(path, PolicyFile(policy=Policy(deny=(edit, write))))

    saved = decode_object(path.read_text())
    assert json_at(saved, "permissions", "deny") == [{"Write(generated/**)": {"reason": "first"}}]
