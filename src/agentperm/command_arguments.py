"""Typed argparse destination schema for the command-line boundary."""

from argparse import Namespace
from dataclasses import dataclass, field


@dataclass
class CommandArguments(Namespace):
    command: str = ""
    mode: str = "auto"
    dry_run: bool = False
    templates: list[str] = field(default_factory=list)
    init_local: bool = False
    init_output: str | None = None
    list_templates: bool = False
    paths: list[str] = field(default_factory=list)
    shell_command: str = ""
    agent: str = ""
    event: str = ""
    passthrough: list[str] | None = None
    edit_local: bool = False
