"""Shallow AST effect analysis for inline Python commands.

This deliberately models ordinary, non-adversarial diagnostic snippets. It is
not a Python sandbox or an inter-procedural proof system: calls are considered
read-only unless a user rule or the built-in mutation catalogue says otherwise.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from .domain import Decision, PythonCallPolicy, Segment, Verdict

_MAX_SOURCE_BYTES = 100_000
_MAX_AST_NODES = 10_000
_PYTHON_NAME = re.compile(r"python(?:3(?:\.\d+)?)?")
_SAFE_INTERPRETER_FLAGS = frozenset({"-B", "-E", "-I", "-O", "-OO", "-P", "-q", "-s", "-S", "-u", "-v", "-x"})

_UNSAFE_EXACT = frozenset({
    "builtins.eval", "builtins.exec", "builtins.compile", "builtins.__import__",
    "builtins.setattr", "builtins.delattr", "builtins.breakpoint",
    "os.remove", "os.unlink", "os.rename", "os.renames", "os.replace",
    "os.mkdir", "os.makedirs", "os.rmdir", "os.removedirs", "os.chmod",
    "os.chown", "os.link", "os.symlink", "os.truncate", "os.putenv",
    "os.unsetenv", "os.system", "os.popen", "os.fork", "os.kill",
    "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree",
    "shutil.move", "shutil.rmtree", "shutil.make_archive", "shutil.unpack_archive",
    "tempfile.NamedTemporaryFile", "tempfile.TemporaryDirectory",
    "tempfile.mkstemp", "tempfile.mkdtemp", "sqlite3.connect",
})
_UNSAFE_PREFIXES = (
    "subprocess.", "multiprocessing.", "socket.",
    "os.exec", "os.spawn", "os.posix_spawn",
)
_UNSAFE_TERMINALS = frozenset({
    "write", "writelines", "write_text", "write_bytes", "touch", "unlink",
    "remove", "rename", "replace", "mkdir", "rmdir", "chmod", "chown",
    "symlink_to", "hardlink_to", "truncate", "save", "delete", "commit",
    "rollback", "execute", "executemany", "executescript", "send", "sendall",
    "post", "put", "patch", "system", "popen",
})
_UNSAFE_TERMINAL_PREFIXES = (
    "add_", "create_", "delete_", "mkdir_", "move_", "patch_", "post_",
    "put_", "remove_", "rename_", "replace_", "save_", "set_", "start_",
    "stop_", "terminate_", "truncate_", "unlink_", "update_", "write_",
)
_BUILTIN_NAMES = frozenset({
    "__import__", "abs", "all", "any", "ascii", "bin", "bool", "breakpoint",
    "bytearray", "bytes", "callable", "chr", "classmethod", "compile", "complex",
    "delattr", "dict", "dir", "divmod", "enumerate", "eval", "exec", "filter",
    "float", "format", "frozenset", "getattr", "globals", "hasattr", "hash",
    "help", "hex", "id", "input", "int", "isinstance", "issubclass", "iter",
    "len", "list", "locals", "map", "max", "memoryview", "min", "next", "object",
    "oct", "open", "ord", "pow", "print", "property", "range", "repr", "reversed",
    "round", "set", "setattr", "slice", "sorted", "staticmethod", "str", "sum",
    "super", "tuple", "type", "vars", "zip",
})

_ALLOWED_STATEMENTS = (
    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Return, ast.Delete,
    ast.Assign, ast.TypeAlias, ast.AugAssign, ast.AnnAssign, ast.For, ast.AsyncFor,
    ast.While, ast.If, ast.With, ast.AsyncWith, ast.Match, ast.Raise, ast.Try,
    ast.TryStar, ast.Assert, ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
    ast.Expr, ast.Pass, ast.Break, ast.Continue,
)
_ALLOWED_EXPRESSIONS = (
    ast.BoolOp, ast.NamedExpr, ast.BinOp, ast.UnaryOp, ast.Lambda, ast.IfExp,
    ast.Dict, ast.Set, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
    ast.Await, ast.Yield, ast.YieldFrom, ast.Compare, ast.Call, ast.FormattedValue,
    ast.JoinedStr, ast.Constant, ast.Attribute, ast.Subscript, ast.Starred, ast.Name,
    ast.List, ast.Tuple, ast.Slice,
)
_ALLOWED_HELPERS = (
    ast.arguments, ast.arg, ast.keyword, ast.alias, ast.withitem, ast.comprehension,
    ast.match_case, ast.pattern, ast.TypeIgnore, ast.operator, ast.unaryop, ast.boolop,
    ast.cmpop, ast.expr_context,
)


@dataclass(frozen=True)
class _InlineSource:
    source: str | None
    problem: str = ""


def analyze_python_segment(segment: Segment, calls: PythonCallPolicy) -> Verdict | None:
    """Return a verdict for inline Python, or ``None`` for unrelated command shapes."""
    extracted = _extract_inline_source(segment)
    if extracted is None:
        return None
    if extracted.source is None:
        return Verdict(Decision.Ask, extracted.problem or "inline Python source is not statically available")
    source = extracted.source
    if len(source.encode()) > _MAX_SOURCE_BYTES:
        return Verdict(Decision.Ask, f"inline Python exceeds {_MAX_SOURCE_BYTES} byte analysis limit")
    try:
        tree = ast.parse(source, mode="exec")
    except (SyntaxError, ValueError) as error:
        return Verdict(Decision.Ask, f"inline Python is not parseable: {error}")
    analyzer = _Analyzer(calls)
    analyzer.visit(tree)
    return analyzer.verdict


def _extract_inline_source(segment: Segment) -> _InlineSource | None:
    if not segment.argv:
        return None
    argv = segment.argv
    command = argv[0].rsplit("/", 1)[-1]
    if _PYTHON_NAME.fullmatch(command):
        args = argv[1:]
    elif command == "uv" and len(argv) >= 3 and argv[1] == "run" \
            and _PYTHON_NAME.fullmatch(argv[2].rsplit("/", 1)[-1]):
        args = argv[3:]
    else:
        return None

    if "-c" in args:
        index = args.index("-c")
        if any(arg not in _SAFE_INTERPRETER_FLAGS for arg in args[:index]):
            return _InlineSource(None, "unsupported Python interpreter options before -c")
        if index + 1 >= len(args):
            return _InlineSource(None, "python -c is missing its source argument")
        return _InlineSource(args[index + 1])

    if "-" in args:
        index = args.index("-")
        if any(arg not in _SAFE_INTERPRETER_FLAGS for arg in args[:index]):
            return _InlineSource(None, "unsupported Python interpreter options before stdin")
        if segment.stdin_source is None:
            return _InlineSource(None, "python stdin is not a literal heredoc")
        if segment.stdin_dynamic:
            return _InlineSource(None, "python heredoc contains shell expansion")
        return _InlineSource(segment.stdin_source)
    return None


class _Analyzer(ast.NodeVisitor):
    def __init__(self, calls: PythonCallPolicy) -> None:
        self.calls = calls
        self.aliases: dict[str, str] = {}
        self.node_count = 0
        self.verdict = Verdict(Decision.Allow, "inline Python AST is read-only")

    def visit(self, node: ast.AST) -> None:
        self.node_count += 1
        if self.node_count > _MAX_AST_NODES:
            self._record(Decision.Ask, f"inline Python exceeds {_MAX_AST_NODES} node analysis limit")
            return
        if not self._allowed(node):
            self._record(Decision.Ask, f"unsupported Python AST node {type(node).__name__}")
            return
        super().visit(node)

    @staticmethod
    def _allowed(node: ast.AST) -> bool:
        return isinstance(node, (ast.Module, *_ALLOWED_STATEMENTS, *_ALLOWED_EXPRESSIONS, *_ALLOWED_HELPERS))

    def _record(self, decision: Decision, rationale: str) -> None:
        strictness = {Decision.Allow: 1, Decision.Ask: 2, Decision.Deny: 3}
        if strictness[decision] > strictness[self.verdict.decision]:
            self.verdict = Verdict(decision, rationale)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[bound] = alias.name if alias.asname else bound

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None or any(alias.name == "*" for alias in node.names):
            self._record(Decision.Ask, "relative or wildcard import cannot be resolved shallowly")
            return
        prefix = "." * node.level + node.module
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = f"{prefix}.{alias.name}"

    def visit_Global(self, node: ast.Global) -> None:
        self._record(Decision.Ask, "global assignment scope is not read-only")

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self._record(Decision.Ask, "nonlocal assignment scope is not read-only")

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_target(target)
            self._track_name_alias(target, node.value)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._check_target(node.target)
        self.visit(node.annotation)
        if node.value is not None:
            self._track_name_alias(node.target, node.value)
            self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._check_target(node.target)
        self.visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._check_target(node.target)
        self._track_name_alias(node.target, node.value)
        self.visit(node.value)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self._check_target(target)

    def _check_target(self, target: ast.expr) -> None:
        if isinstance(target, ast.Name):
            return
        if isinstance(target, ast.Starred):
            self._check_target(target.value)
            return
        if isinstance(target, ast.List | ast.Tuple):
            for item in target.elts:
                self._check_target(item)
            return
        self._record(Decision.Ask, f"Python {type(target).__name__} mutation is not read-only")
        self.visit(target)

    def _track_name_alias(self, target: ast.expr, value: ast.expr) -> None:
        if isinstance(target, ast.Name):
            resolved = self._call_target(value)
            if resolved is not None:
                self.aliases[target.id] = resolved

    def visit_For(self, node: ast.For) -> None:
        self._visit_for(node.target, node.iter, node.body, node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_for(node.target, node.iter, node.body, node.orelse)

    def _visit_for(
        self,
        target: ast.expr,
        iterator: ast.expr,
        body: list[ast.stmt],
        orelse: list[ast.stmt],
    ) -> None:
        self._check_target(target)
        self.visit(iterator)
        for child in (*body, *orelse):
            self.visit(child)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self._check_target(node.target)
        self.visit(node.iter)
        for condition in node.ifs:
            self.visit(condition)

    def visit_Call(self, node: ast.Call) -> None:
        target = self._call_target(node.func)
        if target is None:
            self._record(Decision.Ask, "dynamic Python call target cannot be classified")
        else:
            configured = self.calls.decision_for(target)
            if configured is Decision.Deny:
                self._record(Decision.Deny, f"Python call denied by policy: {target}")
            elif configured is Decision.Ask:
                self._record(Decision.Ask, f"Python call requires approval by policy: {target}")
            elif configured is not Decision.Allow:
                problem = self._builtin_call_problem(node, target)
                if problem:
                    self._record(Decision.Ask, problem)
        self.visit(node.func)
        for argument in node.args:
            self.visit(argument)
        for keyword in node.keywords:
            self.visit(keyword.value)

    def _call_target(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self.aliases:
                return self.aliases[node.id]
            return f"builtins.{node.id}" if node.id in _BUILTIN_NAMES else node.id
        if isinstance(node, ast.Attribute):
            base = self._value_target(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def _value_target(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name | ast.Attribute):
            return self._call_target(node)
        if isinstance(node, ast.Call):
            return self._call_target(node.func)
        return None

    def _builtin_call_problem(self, node: ast.Call, target: str) -> str | None:
        if target in {"builtins.open", "io.open", "pathlib.Path.open"} or target.endswith(".Path.open"):
            mode_index = 1 if target in {"builtins.open", "io.open"} else 0
            mode: ast.expr | None = node.args[mode_index] if len(node.args) > mode_index else None
            mode = next((kw.value for kw in node.keywords if kw.arg == "mode"), mode)
            if mode is None:
                return None
            if not isinstance(mode, ast.Constant) or not isinstance(mode.value, str):
                return f"Python open mode is dynamic: {target}"
            if any(flag in mode.value for flag in "wax+"):
                return f"Python call opens a file for writing: {target}({mode.value!r})"
            return None
        if target in _UNSAFE_EXACT or target.startswith(_UNSAFE_PREFIXES):
            return f"Python call may mutate external state: {target}"
        terminal = target.rsplit(".", 1)[-1]
        if terminal in _UNSAFE_TERMINALS or terminal.startswith(_UNSAFE_TERMINAL_PREFIXES):
            return f"Python call may mutate external state: {target}"
        return None
