"""agentperm's tool capabilities and the native tools each agent exposes for them.

A policy names capabilities (``Read``, ``Write``, …), never a host's own tool names.
Every adapter resolves a native tool call through this table, so one rule governs
the same operation on every agent, whatever the host calls it or however old it is.
A native tool that is not listed reaches the policy under its own name, which no
valid rule names, so the host's own permission flow decides it.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum, StrEnum, auto
from pathlib import Path

from .model import AgentName, Pipeline, ShellRequest, ToolArguments, ToolRequest, tool_arguments, tool_path_arguments


class Capability(StrEnum):
    Read = "Read"
    Write = "Write"
    WebFetch = "WebFetch"
    WebSearch = "WebSearch"
    Skill = "Skill"
    AWS = "AWS"
    Code = "Code"
    Knowledge = "Knowledge"


class Target(Enum):
    """How a tool's input identifies what it touches."""

    Paths = auto()  # its path fields are the files it reads or writes
    Listing = auto()  # it lists the entries of the directory in its path field
    Search = auto()  # it reads everything under its root (path field, else the working directory)
    Glob = auto()  # it matches its pattern fields beneath its root


@dataclass(frozen=True)
class NativeTool:
    capability: Capability
    target: Target = Target.Paths
    # Host-specific fields naming a target, beyond the generic path fields.
    path_keys: tuple[str, ...] = ()
    pattern_keys: tuple[str, ...] = ("pattern",)


_READ = NativeTool(Capability.Read)
_WRITE = NativeTool(Capability.Write)
_LIST = NativeTool(Capability.Read, Target.Listing, ("dir_path",))
_SEARCH = NativeTool(Capability.Read, Target.Search, ("dir_path",))
_GLOB = NativeTool(Capability.Read, Target.Glob, ("dir_path",))
_WEB_FETCH = NativeTool(Capability.WebFetch)
_WEB_SEARCH = NativeTool(Capability.WebSearch)
_SKILL = NativeTool(Capability.Skill)
_AWS = NativeTool(Capability.AWS)

# Current and legacy names. Names shared by two agents must map identically, so
# guessing the wrong agent from a payload can never change a decision.
NATIVE_TOOLS: dict[AgentName, dict[str, NativeTool]] = {
    AgentName.Claude: {
        "Read": _READ,
        "NotebookRead": _READ,
        "Glob": _GLOB,
        "Grep": _SEARCH,
        "LS": _LIST,
        "Write": _WRITE,
        "Edit": _WRITE,
        "MultiEdit": _WRITE,
        "NotebookEdit": _WRITE,
        "WebFetch": _WEB_FETCH,
        "WebSearch": _WEB_SEARCH,
        "Skill": _SKILL,
    },
    AgentName.Codex: {
        # Codex reads through its shell; these are its image viewer and the
        # file tools it shipped before 0.117 (read_file, grep_files) and 0.129 (list_dir).
        "view_image": _READ,
        "read_file": _READ,
        "list_dir": _LIST,
        "grep_files": _SEARCH,
    },
    AgentName.Gemini: {
        "read_file": _READ,
        "read_many_files": NativeTool(Capability.Read, Target.Glob, pattern_keys=("include", "paths")),
        "list_directory": _LIST,
        "glob": _GLOB,
        "grep_search": _SEARCH,
        "search_file_content": _SEARCH,
        "write_file": _WRITE,
        "replace": _WRITE,
        "web_fetch": _WEB_FETCH,
        "google_web_search": _WEB_SEARCH,
        "activate_skill": _SKILL,
    },
    AgentName.Opencode: {
        "read": _READ,
        "list": _LIST,
        "glob": _GLOB,
        "grep": _SEARCH,
        "edit": _WRITE,
        "write": _WRITE,
        "multiedit": _WRITE,
        "webfetch": _WEB_FETCH,
        "websearch": _WEB_SEARCH,
        "skill": _SKILL,
    },
    AgentName.Kiro: {
        # CLI names, then their legacy and IDE spellings.
        "read": NativeTool(Capability.Read, path_keys=("image_paths",)),
        "fs_read": NativeTool(Capability.Read, path_keys=("image_paths",)),
        "fsRead": _READ,
        "write": _WRITE,
        "fs_write": _WRITE,
        "fsWrite": _WRITE,
        "glob": _GLOB,
        "grep": _SEARCH,
        "web_fetch": _WEB_FETCH,
        "webFetch": _WEB_FETCH,
        "web_search": _WEB_SEARCH,
        "webSearch": _WEB_SEARCH,
        "remote_web_search": _WEB_SEARCH,
        "aws": _AWS,
        "use_aws": _AWS,
        "useAws": _AWS,
        "code": NativeTool(Capability.Code),
        "knowledge": NativeTool(Capability.Knowledge),
        "read_file": _READ,
        "readFile": _READ,
        "read_files": _READ,
        "readMultipleFiles": _READ,
        "read_code": _READ,
        "readCode": _READ,
        "list_directory": _LIST,
        "listDirectory": _LIST,
        "file_search": _SEARCH,
        "fileSearch": _SEARCH,
        "grep_search": _SEARCH,
        "grepSearch": _SEARCH,
        "fs_append": _WRITE,
        "fsAppend": _WRITE,
        "str_replace": _WRITE,
        "strReplace": _WRITE,
        "edit_code": _WRITE,
        "editCode": _WRITE,
        "semantic_rename": _WRITE,
        "smart_relocate": _WRITE,
        "delete_file": NativeTool(Capability.Write, path_keys=("targetFile",)),
        "deleteFile": NativeTool(Capability.Write, path_keys=("targetFile",)),
    },
}

SHELL_TOOLS: dict[AgentName, frozenset[str]] = {
    AgentName.Claude: frozenset({"Bash"}),
    AgentName.Codex: frozenset({"Bash"}),
    AgentName.Gemini: frozenset({"run_shell_command"}),
    AgentName.Opencode: frozenset({"bash"}),
    AgentName.Kiro: frozenset(
        {"shell", "execute_bash", "execute_cmd", "executeBash", "executeCmd", "run_command", "runCommand"}
    ),
}
POWERSHELL_TOOLS: dict[AgentName, frozenset[str]] = {
    AgentName.Claude: frozenset({"PowerShell"}),
    AgentName.Kiro: frozenset({"execute_pwsh", "executePwsh"}),
}


def agent_tool_names(agent: AgentName) -> frozenset[str]:
    """Every native tool name agentperm recognises for ``agent``."""
    return (
        frozenset(NATIVE_TOOLS.get(agent, {}))
        | SHELL_TOOLS.get(agent, frozenset())
        | POWERSHELL_TOOLS.get(agent, frozenset())
    )


def native_tool(agent: AgentName, name: str) -> NativeTool | None:
    return NATIVE_TOOLS.get(agent, {}).get(name)


def native_capability(name: str) -> Capability | None:
    """The capability any agent's native tool ``name`` resolves to (for policy hints)."""
    for tools in NATIVE_TOOLS.values():
        if name in tools:
            return tools[name].capability
    return None


def powershell_request(cwd: Path | None) -> ShellRequest:
    return ShellRequest(
        Pipeline((), parseable=False, unparseable_reason="PowerShell commands are not analysed"), cwd=cwd
    )


def tool_request(agent: AgentName, name: str, tool_input: object, cwd: Path | None) -> ToolRequest:
    """Resolve a native tool call to its capability and the paths it targets."""
    arguments = tool_arguments(tool_input)
    tool = native_tool(agent, name)
    if tool is None:
        return ToolRequest(name, arguments, cwd=cwd)
    extra = tuple(("path", value) for key, value in arguments if key in tool.path_keys)
    if tool.target is Target.Paths:
        return ToolRequest(tool.capability, arguments + extra, cwd=cwd)

    path_fields = tool_path_arguments(arguments)
    roots = [value for key, value in path_fields if key not in tool.pattern_keys] + [value for _, value in extra]
    patterns = [value for key, value in arguments if key in tool.pattern_keys]
    others = tuple(argument for argument in arguments if argument not in path_fields)
    if tool.target is Target.Listing:
        targets = [f"{root}/*" for root in roots]
    elif tool.target is Target.Glob and patterns:
        root = roots[0] if roots else "."
        targets = [pattern if os.path.isabs(pattern) else f"{root}/{pattern}" for pattern in patterns]
    else:
        targets = [root if _is_file(root, cwd) else f"{root}/**" for root in roots or ["."]]
    # ``**`` in a target becomes two segments so a single-segment scope (``src/*``)
    # can never cover a recursive target.
    return ToolRequest(tool.capability, others + _path_arguments(targets), cwd=cwd)


def _path_arguments(targets: list[str]) -> ToolArguments:
    return tuple(("path", re.sub(r"\*\*", "*/*", target)) for target in targets)


def _is_file(root: str, cwd: Path | None) -> bool:
    path = Path(root).expanduser()
    if not path.is_absolute() and cwd is not None:
        path = cwd / path
    return path.is_file()
