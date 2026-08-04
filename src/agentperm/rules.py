"""Rule parsing: string/dict → Rule objects."""

from __future__ import annotations

import re

from .domain import BashCommand, BashOption, JsonObject, JsonValue, NamedTool, PythonReadonly, Rule, ShellPattern
from .errors import PolicyError


def parse_rule(raw: JsonValue) -> Rule | None:
    if isinstance(raw, str):
        return _parse_string_rule(raw)
    if isinstance(raw, dict):
        return _parse_dict_rule(raw)
    return None


def _parse_string_rule(text: str) -> Rule | None:
    text = text.strip()
    if text == "Python(readonly)":
        return PythonReadonly()
    if text.startswith("Python("):
        raise PolicyError(f"unsupported Python rule: {text!r}")
    if text.startswith("Shell("):
        if not text.endswith(")"):
            raise PolicyError(f"malformed Shell rule (missing closing parenthesis): {text!r}")
        inner = text[6:-1]
        if not inner:
            raise PolicyError("empty Shell() pattern")
        from .shellpattern import parse_shell_pattern
        return parse_shell_pattern(inner)
    bash_wildcard = re.fullmatch(r"Bash\((.+):\*\)", text)
    if bash_wildcard:
        return BashCommand(tuple(bash_wildcard.group(1).split()), trailing_wildcard=True)
    bash_exact = re.fullmatch(r"Bash\((.+)\)", text)
    if bash_exact:
        return BashCommand(tuple(bash_exact.group(1).split()), trailing_wildcard=False)
    named = re.fullmatch(r"(.+?)\((.*)\)", text)
    if named:
        name = named.group(1)
        spec = named.group(2)
        if name == "Bash" and spec in ("", "*"):
            raise PolicyError(
                f"{text!r} is silently dead — shell commands are matched by "
                f"Bash(cmd:*) or Shell(...) rules, not a bare tool name"
            )
        return NamedTool(name, None if spec in ("", "*") else spec)
    if text == "Bash":
        raise PolicyError(
            "bare 'Bash' is silently dead — shell commands are matched by "
            "Bash(cmd:*) or Shell(...) rules, not a bare tool name"
        )
    if text:
        return NamedTool(text)
    return None


def _parse_allow_paths(data: JsonObject) -> tuple[str, ...]:
    raw = data.get("allowPaths")
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PolicyError("'allowPaths' must be an array of path strings")
    paths: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item:
            raise PolicyError(f"'allowPaths' member must be a non-empty string, got {item!r}")
        paths.append(item)
    return tuple(paths)


def _parse_shell_dict_rule(rule_str: str, data: JsonObject) -> ShellPattern:
    from dataclasses import replace

    pattern = _parse_string_rule(rule_str)
    if not isinstance(pattern, ShellPattern):
        raise PolicyError(f"invalid Shell rule: {rule_str!r}")

    values_raw = data.get("values")
    allow_paths = _parse_allow_paths(data)

    extra_frozen = frozenset[str]()
    if values_raw is not None:
        if not isinstance(values_raw, list):
            raise PolicyError("'values' must be an array of flag names")

        from .shellpattern import is_flag, validate_flag_name

        extra: set[str] = set()
        for v in values_raw:
            if not isinstance(v, str):
                raise PolicyError(f"'values' member must be a string, got {type(v).__name__}")
            if not is_flag(v):
                raise PolicyError(f"non-flag member {v!r} in 'values'")
            validate_flag_name(v, 0)
            extra.add(v)
        extra_frozen = frozenset(extra)

    if not extra_frozen and not allow_paths:
        return pattern
    return replace(
        pattern,
        value_flags=pattern.value_flags | extra_frozen,
        extra_values=extra_frozen,
        allow_paths=allow_paths,
    )


def _parse_dict_rule(data: JsonObject) -> Rule | None:
    # Legacy {"rule": "Shell(...)", ...} form
    rule_str = data.get("rule")
    if isinstance(rule_str, str) and rule_str.strip().startswith("Shell("):
        return _parse_shell_dict_rule(rule_str, data)

    # New rule-as-key form: {"Shell(...)": {"allowPaths": [...], "values": [...]}}
    if "rule" not in data and "tool" not in data:
        for key, value in data.items():
            key_stripped = key.strip()
            if key_stripped.startswith(("Shell(", "Bash(")):
                if not isinstance(value, dict):
                    raise PolicyError(f"rule-as-key value must be an object, got {type(value).__name__}")
                return _parse_shell_dict_rule(key_stripped, value)

    if data.get("tool") != "Bash":
        return None
    commands_raw = data.get("command")
    if isinstance(commands_raw, str):
        commands = [commands_raw]
    elif isinstance(commands_raw, list):
        commands = [c for c in commands_raw if isinstance(c, str)]
    else:
        return None
    if not commands:
        return None
    when = data.get("when")
    if not isinstance(when, dict):
        return None
    options_raw = when.get("hasOption")
    if isinstance(options_raw, str):
        options = [options_raw]
    elif isinstance(options_raw, list):
        options = [o for o in options_raw if isinstance(o, str)]
    else:
        return None
    if not options:
        return None
    reason = data.get("reason")
    return BashOption(
        commands=frozenset(commands),
        options=frozenset(options),
        rationale=reason if isinstance(reason, str) else "",
    )
