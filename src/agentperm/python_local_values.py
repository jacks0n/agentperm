"""Provenance tracking for mutations of freshly allocated Python containers."""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class LocalValue:
    """A fresh built-in container and, when known, its item shape."""

    kind: str
    item: LocalValue | None = None


@dataclass
class LocalValueTracker:
    """Distinguish process-local container updates from external mutations."""

    call_target: Callable[[ast.expr], str | None]
    values: dict[str, LocalValue] = field(default_factory=dict)

    def track_assignment(self, target: ast.expr, value: ast.expr) -> None:
        if not isinstance(target, ast.Name):
            return
        inferred = self._infer(value)
        if inferred is None:
            self.values.pop(target.id, None)
        else:
            self.values[target.id] = inferred

    def track_iteration(self, target: ast.expr, iterator: ast.expr) -> None:
        if not isinstance(target, ast.Name):
            return
        container = self._infer(iterator)
        if container is None or container.item is None:
            self.values.pop(target.id, None)
        else:
            self.values[target.id] = container.item

    def owns_subscript(self, target: ast.Subscript) -> bool:
        value = self.values.get(target.value.id) if isinstance(target.value, ast.Name) else None
        return value is not None and value.kind in {"dict", "list"}

    @staticmethod
    def owns_attribute(target: ast.Attribute) -> bool:
        """Recognize local client settings that cannot mutate remote state."""
        return target.attr in {"call_timeout"}

    def _infer(self, node: ast.expr) -> LocalValue | None:
        if isinstance(node, ast.Name):
            return self.values.get(node.id)
        if isinstance(node, ast.Dict | ast.DictComp):
            return LocalValue("dict")
        if isinstance(node, ast.List):
            items = tuple(filter(None, (self._infer(item) for item in node.elts)))
            item = items[0] if items and all(candidate == items[0] for candidate in items) else None
            return LocalValue("list", item)
        if isinstance(node, ast.ListComp):
            return LocalValue("list", self._infer(node.elt))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr) and (
            self._infer(node.left) == LocalValue("dict") or isinstance(node.left, ast.Dict)
        ):
            return LocalValue("dict")
        if isinstance(node, ast.Call):
            target = self.call_target(node.func)
            if target == "builtins.dict":
                return LocalValue("dict")
            if target == "builtins.list":
                return LocalValue("list")
        return None
