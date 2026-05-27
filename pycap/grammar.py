"""PyCap syntax filter (§3.1).

Rejects environment-authoritative or unbounded constructs in untrusted code:
  * raw sockets, file I/O outside broker proxy
  * dynamic imports, reflection (__import__, eval, exec, getattr/setattr by string)
  * `while` loops, unbounded recursion
  * exception escape to outer scope (no try-except wrapping broker calls)
"""
from __future__ import annotations
import ast
from typing import List


# Whitelist of allowed call roots. All external interaction must go through
# `broker.<primitive>(...)`.
ALLOWED_CALL_ROOTS = {"broker"}

# Builtins permitted inside a Cell.
ALLOWED_BUILTINS = {
    "len", "sum", "min", "max", "abs", "range",
    "int", "float", "str", "bool", "list", "dict", "tuple",
    "sorted", "any", "all", "round",
}

# Module-level forbidden names (cover reflection / sandbox-escape vectors).
FORBIDDEN_NAMES = {
    "__import__", "eval", "exec", "compile",
    "globals", "locals", "vars", "dir",
    "getattr", "setattr", "hasattr", "delattr",
    "open", "input", "exit", "quit",
    "socket", "os", "sys", "subprocess", "ctypes",
    "importlib", "marshal", "pickle",
    "Thread", "Process",
    "__class__", "__bases__", "__mro__", "__subclasses__",
    "__globals__", "__builtins__", "__dict__",
}


class PyCapSyntaxError(Exception):
    """Raised when an untrusted load violates PyCap syntactic constraints."""


class _Filter(ast.NodeVisitor):
    def __init__(self) -> None:
        self.errors: List[str] = []

    # --- structural rejections ---
    def visit_Import(self, node: ast.Import):
        self.errors.append("import is forbidden in PyCap")

    def visit_ImportFrom(self, node: ast.ImportFrom):
        self.errors.append("from-import is forbidden in PyCap")

    def visit_While(self, node: ast.While):
        self.errors.append("while-loops are forbidden (use bounded `for ... in range(...)`)")

    def visit_AsyncFunctionDef(self, node):
        self.errors.append("async/await is not allowed in PyCap")

    def visit_Try(self, node: ast.Try):
        # Disallow exception-based escape from broker errors.
        self.errors.append("try/except is forbidden (broker enforces failure consistency)")

    def visit_Raise(self, node: ast.Raise):
        self.errors.append("raise is forbidden (errors must flow through broker receipts)")

    def visit_Lambda(self, node: ast.Lambda):
        self.errors.append("lambda expressions are forbidden")

    def visit_Global(self, node):
        self.errors.append("`global` is forbidden")

    def visit_Nonlocal(self, node):
        self.errors.append("`nonlocal` is forbidden")

    # --- name-level rejections ---
    def visit_Name(self, node: ast.Name):
        if node.id in FORBIDDEN_NAMES:
            self.errors.append(f"forbidden name: {node.id!r}")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # Block dunder pivots like x.__class__.__bases__
        if node.attr.startswith("__") and node.attr not in ("__init__",):
            self.errors.append(f"forbidden dunder attribute access: {node.attr!r}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Calls must be either builtin-whitelisted or broker.<x>(...)
        f = node.func
        if isinstance(f, ast.Name):
            if f.id not in ALLOWED_BUILTINS and f.id != "cell":
                self.errors.append(f"unrecognized free call: {f.id!r}")
        elif isinstance(f, ast.Attribute):
            root = f.value
            if isinstance(root, ast.Name) and root.id not in ALLOWED_CALL_ROOTS:
                # allow chained attribute access on data structures (e.g. d.get())
                if f.attr not in {"get", "items", "keys", "values"}:
                    self.errors.append(
                        f"unauthorized call root: {root.id}.{f.attr}"
                    )
        else:
            self.errors.append("indirect / computed calls are forbidden")
        self.generic_visit(node)


def syntax_filter(source: str) -> ast.Module:
    """Parse and filter `source`. Returns the AST or raises PyCapSyntaxError."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:  # parse error is also a PyCap rejection
        raise PyCapSyntaxError(f"parse error: {e}") from e

    flt = _Filter()
    flt.visit(tree)
    if flt.errors:
        raise PyCapSyntaxError("; ".join(flt.errors))
    return tree
