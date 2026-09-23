"""Resolve bounded static SQL sources from Python expressions."""

from __future__ import annotations

import ast
from collections.abc import Callable
from itertools import product

from .python_adapters import PYTHON_SQL_CALL_ADAPTERS

_MAX_STATIC_STRING_ALTERNATIVES = 64


class PythonSqlSourceResolver:
    """Track local string construction without taking on general Python evaluation."""

    def __init__(self, call_target: Callable[[ast.expr], str | None]) -> None:
        self._call_target = call_target
        self._constants: dict[str, tuple[str, ...]] = {}
        self._functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}

    def track_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._functions[node.name] = node

    def track_assignment(self, target: ast.expr, value: ast.expr) -> None:
        if not isinstance(target, ast.Name):
            return
        strings = self._literal_strings(value)
        if strings is None:
            self._constants.pop(target.id, None)
        else:
            self._constants[target.id] = strings

    def track_iteration(self, target: ast.expr, iterator: ast.expr) -> None:
        """Bind a simple loop target to every statically bounded string value."""

        if not isinstance(target, ast.Name):
            return
        elements = iterator.elts if isinstance(iterator, ast.List | ast.Set | ast.Tuple) else (iterator,)
        values: list[str] = []
        for element in elements:
            resolved = self._literal_strings(element)
            if resolved is None:
                self._constants.pop(target.id, None)
                return
            values.extend(resolved)
        bounded = self._bounded_unique(values)
        if bounded is None:
            self._constants.pop(target.id, None)
        else:
            self._constants[target.id] = bounded

    def resolve(self, node: ast.expr | None) -> tuple[str, ...] | None:
        if isinstance(node, ast.Call):
            target = self._call_target(node.func)
            for adapter in PYTHON_SQL_CALL_ADAPTERS:
                if unwrapped := adapter.unwrap(node, target):
                    node = unwrapped
                    break
        return self._literal_strings(node)

    def _literal_strings(
        self,
        node: ast.expr | None,
        bindings: dict[str, tuple[str, ...]] | None = None,
        stack: frozenset[str] = frozenset(),
    ) -> tuple[str, ...] | None:
        bindings = bindings or {}
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return (node.value,)
        if isinstance(node, ast.Name):
            return bindings.get(node.id, self._constants.get(node.id))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._literal_strings(node.left, bindings, stack)
            right = self._literal_strings(node.right, bindings, stack)
            return self._combine_strings(left, right)
        if isinstance(node, ast.IfExp):
            body = self._literal_strings(node.body, bindings, stack)
            orelse = self._literal_strings(node.orelse, bindings, stack)
            if body is None or orelse is None:
                return None
            return self._bounded_unique((*body, *orelse))
        if isinstance(node, ast.JoinedStr):
            alternatives: tuple[str, ...] = ("",)
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts = (value.value,)
                elif isinstance(value, ast.FormattedValue) and value.conversion == -1 and value.format_spec is None:
                    parts = self._literal_strings(value.value, bindings, stack)
                else:
                    return None
                combined = self._combine_strings(alternatives, parts)
                if combined is None:
                    return None
                alternatives = combined
            return alternatives
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            return self._local_function_results(node, bindings, stack)
        return None

    def _local_function_results(
        self,
        node: ast.Call,
        bindings: dict[str, tuple[str, ...]],
        stack: frozenset[str],
    ) -> tuple[str, ...] | None:
        if not isinstance(node.func, ast.Name):
            return None
        function = self._functions.get(node.func.id)
        if function is None or node.func.id in stack or node.keywords:
            return None
        positional = function.args.posonlyargs + function.args.args
        if len(node.args) != len(positional) or function.args.vararg or function.args.kwarg:
            return None
        resolved_args = tuple(self._literal_strings(argument, bindings, stack) for argument in node.args)
        if any(value is None for value in resolved_args):
            return None
        local_bindings = dict(bindings)
        for parameter, values in zip(positional, resolved_args, strict=True):
            if values is None:
                return None
            local_bindings[parameter.arg] = values
        returns = tuple(
            child
            for statement in function.body
            for child in ast.walk(statement)
            if isinstance(child, ast.Return) and child.value is not None
        )
        if not returns:
            return None
        results: list[str] = []
        next_stack = stack | {node.func.id}
        for returned in returns:
            values = self._literal_strings(returned.value, local_bindings, next_stack)
            if values is None:
                return None
            results.extend(values)
        return self._bounded_unique(results)

    @staticmethod
    def _bounded_unique(values: tuple[str, ...] | list[str]) -> tuple[str, ...] | None:
        unique = tuple(dict.fromkeys(values))
        return unique if len(unique) <= _MAX_STATIC_STRING_ALTERNATIVES else None

    def _combine_strings(
        self,
        left: tuple[str, ...] | None,
        right: tuple[str, ...] | None,
    ) -> tuple[str, ...] | None:
        if left is None or right is None or len(left) * len(right) > _MAX_STATIC_STRING_ALTERNATIVES:
            return None
        return self._bounded_unique([first + second for first, second in product(left, right)])
