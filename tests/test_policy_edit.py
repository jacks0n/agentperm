from __future__ import annotations

import pytest

from agentperm.json_boundary import decode_jsonc
from agentperm.policy_edit import (
    AddPermissionRule,
    PolicyEditError,
    RemovePermissionRule,
    ReplacePermissionRule,
    add_permission_rule,
    edit_permission_rules,
    permission_rule_entries,
    remove_permission_rule,
    replace_permission_rule,
)


def test_add_preserves_existing_json5_and_appends_to_a_trailing_comma_array() -> None:
    source = """{
  // This spelling and whitespace must remain byte-for-byte intact.
  version: 1,
  'permissions': {
    allow: [
      'Bash(git status)', // existing rule
    ],
  },
}
"""

    updated = add_permission_rule(source, "allow", "Python(readonly)")

    assert updated == """{
  // This spelling and whitespace must remain byte-for-byte intact.
  version: 1,
  'permissions': {
    allow: [
      'Bash(git status)', // existing rule
      "Python(readonly)"
    ],
  },
}
"""


def test_add_structured_rule_uses_authoritative_canonical_form() -> None:
    source = '{permissions:{allow:["Bash(git status)"]}}'
    rule = {
        "when": {"hasOption": "--porcelain"},
        "command": "git",
        "tool": "Bash",
        "reason": "machine readable status",
    }

    updated = add_permission_rule(source, "allow", rule)

    assert updated == (
        '{permissions:{allow:["Bash(git status)", '
        '{"command":["git"],"reason":"machine readable status","tool":"Bash",'
        '"when":{"hasOption":["--porcelain"]}}]}}'
    )


def test_add_is_a_semantic_noop_despite_json5_formatting() -> None:
    source = """{
  permissions: {
    allow: [{
      tool: 'Bash',
      command: ['git'],
      when: {hasOption: ['--porcelain'],},
    }],
  },
}
"""
    same_rule = {"command": ["git"], "tool": "Bash", "when": {"hasOption": ["--porcelain"]}}

    assert add_permission_rule(source, "allow", same_rule) == source


def test_add_builds_missing_permissions_without_rewriting_the_document() -> None:
    source = """{
  version: 1, // retained
}
"""

    updated = add_permission_rule(source, "deny", "Write")

    assert updated == """{
  version: 1, // retained
  "permissions": {
    "deny": [
      "Write"
    ]
  }
}
"""


def test_add_builds_missing_decision_beside_existing_commented_member() -> None:
    source = """{
  permissions: {
    allow: [], /* retained */
  },
}
"""

    updated = add_permission_rule(source, "ask", "Write")

    assert updated == """{
  permissions: {
    allow: [], /* retained */
    "ask": [
      "Write"
    ]
  },
}
"""


def test_replace_changes_only_the_value_span() -> None:
    source = """{
  permissions: {
    allow: [
      // rationale lives outside the rule and must survive
      {tool: 'Bash', command: ['git'], when: {hasOption: ['--porcelain']}}, // keep
      'Read',
    ],
  },
}
"""
    old = {"tool": "Bash", "command": ["git"], "when": {"hasOption": ["--porcelain"]}}

    updated = replace_permission_rule(source, "allow", old, "Python(readonly)")

    assert updated == """{
  permissions: {
    allow: [
      // rationale lives outside the rule and must survive
      "Python(readonly)", // keep
      'Read',
    ],
  },
}
"""


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        (
            "First",
            """{
  permissions: {allow: [
    // first comment
     // after first
    'Middle',
    'Last' // last comment
  ]},
}
""",
        ),
        (
            "Middle",
            """{
  permissions: {allow: [
    // first comment
    'First', // after first
    
    'Last' // last comment
  ]},
}
""",
        ),
        (
            "Last",
            """{
  permissions: {allow: [
    // first comment
    'First', // after first
    'Middle'
     // last comment
  ]},
}
""",
        ),
    ],
)
def test_remove_preserves_comments_and_only_deletes_value_and_separator(target: str, expected: str) -> None:
    source = """{
  permissions: {allow: [
    // first comment
    'First', // after first
    'Middle',
    'Last' // last comment
  ]},
}
"""

    updated = remove_permission_rule(source, "allow", target)

    assert updated == expected
    decode_jsonc(updated)


def test_remove_only_item_with_trailing_comma_leaves_valid_array_and_comments() -> None:
    source = "{permissions:{allow:[/* before */ 'Read' /* after */,]}}"

    updated = remove_permission_rule(source, "allow", "Read")

    assert updated == "{permissions:{allow:[/* before */  /* after */]}}"
    decode_jsonc(updated)


def test_entries_decode_nested_rules_and_report_exact_spans() -> None:
    source = """{
  permissions: {
    allow: [
      'Read',
      {tool:'Bash', command:['git'], when:{hasOption:['--porcelain',],},},
    ],
    deny: ['Write'],
  },
}
"""

    entries = permission_rule_entries(source)

    assert [(entry.decision, entry.index, entry.value) for entry in entries] == [
        ("allow", 0, "Read"),
        (
            "allow",
            1,
            {"tool": "Bash", "command": ["git"], "when": {"hasOption": ["--porcelain"]}},
        ),
        ("deny", 0, "Write"),
    ]
    assert [decode_jsonc(source[entry.start : entry.end]) for entry in entries] == [
        entry.value for entry in entries
    ]


@pytest.mark.parametrize(
    "source",
    [
        "{permissions:{allow:[]}, permissions:{deny:[]}}",
        "{permissions:{allow:[{tool:'Bash', tool:'Read'}]}}",
        "{permissions:{allow:[], allow:[]}}",
    ],
)
def test_every_duplicate_object_key_is_rejected(source: str) -> None:
    with pytest.raises(PolicyEditError, match="duplicate object key"):
        permission_rule_entries(source)


def test_duplicate_matching_rules_make_every_targeted_edit_ambiguous() -> None:
    source = "{permissions:{allow:['Read', \"Read\"]}}"

    with pytest.raises(PolicyEditError, match="duplicate matching rules"):
        add_permission_rule(source, "allow", "Read")
    with pytest.raises(PolicyEditError, match="found 2"):
        replace_permission_rule(source, "allow", "Read", "Write")
    with pytest.raises(PolicyEditError, match="found 2"):
        remove_permission_rule(source, "allow", "Read")


def test_replace_refuses_to_create_a_semantic_duplicate() -> None:
    source = "{permissions:{allow:['Read', 'Write']}}"

    with pytest.raises(PolicyEditError, match="replacement rule already exists"):
        replace_permission_rule(source, "allow", "Read", "Write")


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("[]", "policy document must be an object"),
        ("{permissions:[]}", "permissions must be an object"),
        ("{permissions:{allow:{}}}", "permissions.allow must be an array"),
    ],
)
def test_ambiguous_policy_shapes_are_rejected(source: str, message: str) -> None:
    with pytest.raises(PolicyEditError, match=message):
        add_permission_rule(source, "allow", "Read")


def test_edit_rejects_a_malformed_unrelated_decision_array() -> None:
    source = "{permissions:{allow:[], deny:{}}}"

    with pytest.raises(PolicyEditError, match=r"permissions.deny must be an array"):
        add_permission_rule(source, "allow", "Read")


def test_invalid_new_rule_is_rejected_before_any_edit() -> None:
    source = "{permissions:{allow:[]}}"

    with pytest.raises(PolicyEditError, match="unparseable permission rule"):
        add_permission_rule(source, "allow", [])


def test_batch_edits_are_applied_in_order() -> None:
    source = "{permissions:{allow:['Read'], deny:[]}}"

    updated = edit_permission_rules(
        source,
        [
            ReplacePermissionRule("allow", "Read", "Python(readonly)"),
            AddPermissionRule("allow", "Read"),
            RemovePermissionRule("allow", "Python(readonly)"),
        ],
    )

    assert decode_jsonc(updated) == {"permissions": {"allow": ["Read"], "deny": []}}


def test_inserted_lines_follow_existing_crlf_without_normalising_untouched_bytes() -> None:
    source = "{\r\n  permissions: {\r\n    allow: [],\r\n  },\r\n}\r\n"

    updated = add_permission_rule(source, "deny", "Write")

    assert updated == (
        "{\r\n  permissions: {\r\n    allow: [],\r\n"
        '    "deny": [\r\n      "Write"\r\n    ]\r\n'
        "  },\r\n}\r\n"
    )


def test_comment_markers_and_delimiters_inside_strings_do_not_confuse_spans() -> None:
    source = "{note:'// not a comment ] }', permissions:{allow:['Read/*still text*/']}}"

    updated = replace_permission_rule(source, "allow", "Read/*still text*/", "Read")

    assert updated == "{note:'// not a comment ] }', permissions:{allow:[\"Read\"]}}"
