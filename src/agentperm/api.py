"""Versioned JSON API for local agentperm clients."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TextIO

from .domain import JsonObject, JsonValue
from .errors import PolicyError
from .explanation import explain_shell_command
from .json_boundary import decode_json
from .policy import PolicyLayer, policy_layers
from .policy_api import (
    apply_policy_plan,
    create_policy_plan,
    discover_policy_targets,
    policy_source_id,
    undo_policy_plan,
)
from .rule_description import describe_rule

PROTOCOL_VERSION = 1
_OPERATIONS = (
    "info",
    "explain",
    "sources",
    "rule.describe",
    "policy.plan",
    "policy.apply",
    "policy.undo",
)


@dataclass(frozen=True)
class ApiRequestError(Exception):
    code: str
    message: str


def run_api(stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Read one request and write one response, with no non-JSON stdout."""
    input_stream = stdin or sys.stdin
    output_stream = stdout or sys.stdout
    try:
        value = decode_json(input_stream.read())
    except json.JSONDecodeError as error:
        return _write_error(output_stream, "invalid_json", f"request is not valid JSON: {error.msg}")
    except (ValueError, RecursionError):
        return _write_error(output_stream, "invalid_json", "request is not valid JSON")

    try:
        if not isinstance(value, dict):
            raise ApiRequestError("invalid_request", "request must be a JSON object")
        result = _dispatch(value)
    except ApiRequestError as error:
        return _write_error(output_stream, error.code, error.message)
    except UnicodeError:
        return _write_error(output_stream, "invalid_request", "request contains invalid Unicode")
    except PolicyError as error:
        return _write_error(output_stream, "policy_error", str(error))
    except OSError as error:
        return _write_error(output_stream, "io_error", str(error))
    except Exception:
        # This process boundary must never strand GUI clients with non-JSON output.
        return _write_error(output_stream, "internal_error", "agentperm could not complete the request")

    _write(output_stream, {"protocol_version": PROTOCOL_VERSION, "ok": True, "result": result})
    return 0


def _dispatch(request: JsonObject) -> JsonObject:
    protocol_version = request.get("protocol_version")
    if type(protocol_version) is not int:  # bool is an int subclass
        raise ApiRequestError("invalid_request", "protocol_version must be an integer")
    if protocol_version != PROTOCOL_VERSION:
        raise ApiRequestError(
            "unsupported_protocol_version",
            f"protocol_version {protocol_version} is unsupported; expected {PROTOCOL_VERSION}",
        )

    operation = request.get("operation")
    if not isinstance(operation, str):
        raise ApiRequestError("invalid_request", "operation must be a string")
    if operation not in _OPERATIONS:
        raise ApiRequestError("unknown_operation", f"unknown operation: {operation}")

    allowed_fields = {"protocol_version", "operation"}
    if operation in ("explain", "sources"):
        allowed_fields.add("cwd")
    if operation == "explain":
        allowed_fields.add("command")
    if operation == "rule.describe":
        allowed_fields.add("value")
    if operation == "policy.plan":
        allowed_fields.update(("contexts", "files"))
    if operation in ("policy.apply", "policy.undo"):
        allowed_fields.add("plan_id")
    unexpected = sorted(request.keys() - allowed_fields)
    if unexpected:
        raise ApiRequestError("invalid_request", f"unexpected request fields: {', '.join(unexpected)}")

    if operation == "info":
        return _info()
    if operation == "rule.describe":
        if "value" not in request:
            raise ApiRequestError("invalid_request", "value is required")
        return describe_rule(request["value"]).to_json()
    if operation == "policy.plan":
        if "files" not in request:
            raise ApiRequestError("invalid_request", "files is required")
        return create_policy_plan(_contexts(request.get("contexts")), request["files"])
    if operation == "policy.apply":
        return apply_policy_plan(_non_empty_string(request.get("plan_id"), "plan_id"))
    if operation == "policy.undo":
        return undo_policy_plan(_non_empty_string(request.get("plan_id"), "plan_id"))
    cwd = _directory(request.get("cwd"))
    if operation == "sources":
        return _sources(cwd)
    return _explain(cwd, _non_empty_string(request.get("command"), "command"))


def _info() -> JsonObject:
    try:
        agentperm_version = version("agentperm")
    except PackageNotFoundError:
        agentperm_version = "0+unknown"
    return {
        "agentperm_version": agentperm_version,
        "operations": list(_OPERATIONS),
    }


def _sources(cwd: Path) -> JsonObject:
    return {
        "cwd": str(cwd),
        "layers": [_serialize_layer(layer) for layer in policy_layers(cwd=cwd)],
        "targets": [target.to_json() for target in discover_policy_targets([cwd])],
    }


def _explain(cwd: Path, command: str) -> JsonObject:
    explanation = explain_shell_command(command, cwd)
    segments: list[JsonValue] = [
        {
            "command": segment.command,
            "decision": segment.decision.value,
            "rationale": segment.rationale,
        }
        for segment in explanation.segments
    ]
    return {
        "cwd": str(cwd),
        "decision": explanation.decision.value,
        "rationale": explanation.rationale,
        "segments": segments,
        "sources": [_source_reference(source) for source in explanation.sources],
    }


def _serialize_layer(layer: PolicyLayer) -> JsonObject:
    return {
        "root": _source_reference(layer.root),
        "sources": [_source_reference(source) for source in layer.sources],
    }


def _source_reference(path: Path) -> JsonObject:
    absolute = path.expanduser().absolute()
    return {"id": policy_source_id(absolute), "path": str(absolute)}


def _contexts(value: JsonValue | None) -> list[Path]:
    if not isinstance(value, list) or not value:
        raise ApiRequestError("invalid_request", "contexts must be a non-empty array")
    contexts: list[Path] = []
    for item in value:
        contexts.append(_directory(item))
    return contexts


def _directory(value: JsonValue | None) -> Path:
    supplied = _non_empty_string(value, "cwd")
    path = Path(supplied).expanduser().absolute()
    if not path.is_dir():
        raise ApiRequestError("invalid_request", f"cwd is not a directory: {supplied}")
    return path.resolve()


def _non_empty_string(value: JsonValue | None, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ApiRequestError("invalid_request", f"{field} must be a non-empty string")
    return value


def _write_error(stdout: TextIO, code: str, message: str) -> int:
    _write(
        stdout,
        {
            "protocol_version": PROTOCOL_VERSION,
            "ok": False,
            "error": {"code": code, "message": message},
        },
    )
    return 1


def _write(stdout: TextIO, response: JsonObject) -> None:
    json.dump(response, stdout, separators=(",", ":"))
    stdout.write("\n")
