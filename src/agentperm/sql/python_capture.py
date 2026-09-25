"""Resolve bounded static SQL sources from Python expressions."""

from __future__ import annotations

import ast
from collections.abc import Callable, Sequence
from itertools import product

from ..config import MAX_STATIC_STRING_ALTERNATIVES
from .python_adapters import PYTHON_SQL_CALL_ADAPTERS

type StringValues = tuple[str, ...]
type MappingValues = tuple[StringValues | None, StringValues | None]
type ResolverState = tuple[dict[str, StringValues], dict[str, MappingValues]]


class PythonSqlSourceResolver:
    """Track local string construction without taking on general Python evaluation."""

    def __init__(self, call_target: Callable[[ast.expr], str | None]) -> None:
        self._call_target = call_target
        self._constants: dict[str, StringValues] = {}
        self._mappings: dict[str, MappingValues] = {}
        self._functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}

    def track_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._functions[node.name] = node

    def track_assignment(self, target: ast.expr, value: ast.expr) -> None:
        if not isinstance(target, ast.Name):
            return
        strings = self.resolve(value)
        if strings is None:
            self._constants.pop(target.id, None)
        else:
            self._constants[target.id] = strings
        mapping = self._literal_mapping(value)
        if mapping is None:
            self._mappings.pop(target.id, None)
        else:
            self._mappings[target.id] = mapping

    def track_iteration(self, target: ast.expr, iterator: ast.expr) -> None:
        """Bind a simple loop target to every statically bounded string value."""

        mapping = self._mapping_iteration(iterator)
        if mapping is not None and isinstance(target, ast.Tuple) and len(target.elts) == 2:
            for item, mapped_values in zip(target.elts, mapping, strict=True):
                if isinstance(item, ast.Name):
                    if mapped_values is None:
                        self._constants.pop(item.id, None)
                    else:
                        self._constants[item.id] = mapped_values
            return
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

    def snapshot(self) -> ResolverState:
        return dict(self._constants), dict(self._mappings)

    def restore(self, state: ResolverState) -> None:
        constants, mappings = state
        self._constants = dict(constants)
        self._mappings = dict(mappings)

    def merge(self, states: tuple[ResolverState, ...]) -> None:
        constant_names: set[str] = set(states[0][0])
        mapping_names: set[str] = set(states[0][1])
        for constants, mappings in states[1:]:
            constant_names.intersection_update(constants)
            mapping_names.intersection_update(mappings)
        merged_constants: dict[str, tuple[str, ...]] = {}
        for name in constant_names:
            values = self._bounded_unique([value for constants, _ in states for value in constants[name]])
            if values is not None:
                merged_constants[name] = values
        merged_mappings: dict[str, MappingValues] = {}
        for name in mapping_names:
            key_groups = tuple(mappings[name][0] for _, mappings in states)
            value_groups = tuple(mappings[name][1] for _, mappings in states)
            keys = (
                self._bounded_unique([key for group in key_groups if group is not None for key in group])
                if all(group is not None for group in key_groups)
                else None
            )
            values = (
                self._bounded_unique([value for group in value_groups if group is not None for value in group])
                if all(group is not None for group in value_groups)
                else None
            )
            if keys is not None or values is not None:
                merged_mappings[name] = (keys, values)
        self._constants = merged_constants
        self._mappings = merged_mappings

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
        if isinstance(node, ast.Call):
            generated = self._joined_range_strings(node, bindings, stack)
            if generated is not None:
                return generated
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            return self._local_function_results(node, bindings, stack)
        return None

    def _joined_range_strings(
        self,
        node: ast.Call,
        bindings: dict[str, tuple[str, ...]],
        stack: frozenset[str],
    ) -> tuple[str, ...] | None:
        """Model a fixed-shape string joined over integer ``range`` values.

        Two representative items retain both the generated item and separator
        in the SQL presented to the parser. Arbitrary iterables remain dynamic.
        """
        if (
            not isinstance(node.func, ast.Attribute)
            or node.func.attr != "join"
            or len(node.args) != 1
            or node.keywords
            or not isinstance(node.args[0], ast.GeneratorExp | ast.ListComp)
        ):
            return None
        comprehension = node.args[0]
        if len(comprehension.generators) != 1:
            return None
        generator = comprehension.generators[0]
        if (
            generator.is_async
            or generator.ifs
            or not isinstance(generator.target, ast.Name)
            or not isinstance(generator.iter, ast.Call)
            or self._call_target(generator.iter.func) != "builtins.range"
        ):
            return None
        separators = self._literal_strings(node.func.value, bindings, stack)
        if separators is None:
            return None
        samples: list[tuple[str, ...]] = []
        for value in ("0", "1"):
            sample_bindings = dict(bindings)
            sample_bindings[generator.target.id] = (value,)
            sample = self._literal_strings(comprehension.elt, sample_bindings, stack)
            if sample is None:
                return None
            samples.append(sample)
        return self._bounded_unique(
            [separator.join((first, second)) for separator, first, second in product(separators, *samples)]
        )

    def _literal_mapping(self, node: ast.expr) -> MappingValues | None:
        if not isinstance(node, ast.Dict) or any(key is None for key in node.keys):
            return None
        keys: list[str] = []
        values: list[str] = []
        keys_static = True
        values_static = True
        for key, value in zip(node.keys, node.values, strict=True):
            resolved_keys = self._literal_strings(key)
            resolved_values = self._literal_strings(value)
            keys_static &= resolved_keys is not None
            values_static &= resolved_values is not None
            keys.extend(resolved_keys or ())
            values.extend(resolved_values or ())
        bounded_keys = self._bounded_unique(keys) if keys_static else None
        bounded_values = self._bounded_unique(values) if values_static else None
        return None if bounded_keys is None and bounded_values is None else (bounded_keys, bounded_values)

    def _mapping_iteration(self, node: ast.expr) -> MappingValues | None:
        if (
            not isinstance(node, ast.Call)
            or node.args
            or node.keywords
            or not isinstance(node.func, ast.Attribute)
            or node.func.attr != "items"
            or not isinstance(node.func.value, ast.Name)
        ):
            return None
        return self._mappings.get(node.func.value.id)

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
        return_values = tuple(
            child.value
            for statement in function.body
            for child in ast.walk(statement)
            if isinstance(child, ast.Return) and child.value is not None
        )
        if not return_values:
            return None
        output_names: set[str] = set()
        for value in return_values:
            output_names.update(self._output_names(value))
        resolved_args = tuple(self._literal_strings(argument, bindings, stack) for argument in node.args)
        local_bindings = dict(bindings)
        for parameter, values in zip(positional, resolved_args, strict=True):
            if values is None:
                if parameter.arg in output_names:
                    return None
            else:
                local_bindings[parameter.arg] = values
        results: list[str] = []
        next_stack = stack | {node.func.id}
        for value in return_values:
            values = self._literal_strings(value, local_bindings, next_stack)
            if values is None:
                return None
            results.extend(values)
        return self._bounded_unique(results)

    def _output_names(self, node: ast.AST) -> set[str]:
        if isinstance(node, ast.Name):
            return {node.id}
        if isinstance(node, ast.IfExp):
            return self._output_names(node.body) | self._output_names(node.orelse)
        names: set[str] = set()
        for child in ast.iter_child_nodes(node):
            names.update(self._output_names(child))
        return names

    @staticmethod
    def _bounded_unique(values: Sequence[str]) -> tuple[str, ...] | None:
        unique = tuple(dict.fromkeys(values))
        return unique if len(unique) <= MAX_STATIC_STRING_ALTERNATIVES else None

    def _combine_strings(
        self,
        left: tuple[str, ...] | None,
        right: tuple[str, ...] | None,
    ) -> tuple[str, ...] | None:
        if left is None or right is None or len(left) * len(right) > MAX_STATIC_STRING_ALTERNATIVES:
            return None
        return self._bounded_unique([first + second for first, second in product(left, right)])
