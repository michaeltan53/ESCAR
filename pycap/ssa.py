"""Lower a PyCap AST into a control-flow-bounded SSA IR with phi nodes.

The IR is intentionally tiny — it only needs enough fidelity to drive the
abstract interpreter in `verifier.abstract_interp` (label tracking, broker
call detection, branch joins). It is NOT a general Python compiler.

Each broker call is assigned a unique `origin_id`, used downstream in the
manifest's effect envelope.
"""
from __future__ import annotations
import ast
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SSAInstr:
    op: str                   # "assign", "binop", "call", "if", "phi", "return"
    dst: Optional[str]
    args: Tuple[Any, ...] = ()
    meta: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:  # readable in test failures
        return f"<{self.op} {self.dst}={self.args}>"


@dataclass
class PhiNode:
    dst: str
    sources: List[Tuple[str, str]]   # (branch_label, var_name)


@dataclass
class SSAModule:
    cells: List["SSACell"]


@dataclass
class SSACell:
    name: str
    params: List[str]
    body: List[SSAInstr]
    ir_hash: str

    @property
    def short_hash(self) -> str:
        return self.ir_hash[:12]


class SSABuilder(ast.NodeVisitor):
    """Builds a flat sequence of SSAInstrs for a single `def cell(...)`.

    Branches are *flattened* into linear instructions plus phi joins, using
    a counter to mint fresh SSA names. Loops are required to be `for x in
    range(N)` with a *literal* bound (else we reject by raising).
    """

    def __init__(self) -> None:
        self._fresh = 0
        self._origin = 0
        self.body: List[SSAInstr] = []
        # variable name -> latest SSA name in scope
        self.env: Dict[str, str] = {}

    # ---------------- helpers ----------------
    def _new(self, hint: str = "t") -> str:
        self._fresh += 1
        return f"%{hint}{self._fresh}"

    def _origin_id(self) -> int:
        self._origin += 1
        return self._origin

    def _emit(self, instr: SSAInstr) -> None:
        self.body.append(instr)

    # ---------------- expressions ----------------
    def expr(self, node: ast.AST) -> str:
        if isinstance(node, ast.Constant):
            r = self._new("c")
            self._emit(SSAInstr("const", r, (node.value,)))
            return r
        if isinstance(node, ast.Name):
            return self.env.get(node.id, node.id)
        if isinstance(node, ast.BinOp):
            l, rr = self.expr(node.left), self.expr(node.right)
            r = self._new("bin")
            self._emit(SSAInstr("binop", r, (type(node.op).__name__, l, rr)))
            return r
        if isinstance(node, ast.Compare):
            l = self.expr(node.left)
            cur = l
            for op, comp in zip(node.ops, node.comparators):
                rhs = self.expr(comp)
                r = self._new("cmp")
                self._emit(SSAInstr("cmp", r, (type(op).__name__, cur, rhs)))
                cur = r
            return cur
        if isinstance(node, ast.BoolOp):
            vals = [self.expr(v) for v in node.values]
            r = self._new("bool")
            self._emit(SSAInstr("boolop", r, (type(node.op).__name__, *vals)))
            return r
        if isinstance(node, ast.UnaryOp):
            v = self.expr(node.operand)
            r = self._new("una")
            self._emit(SSAInstr("unaryop", r, (type(node.op).__name__, v)))
            return r
        if isinstance(node, ast.IfExp):
            test = self.expr(node.test)
            t = self.expr(node.body)
            e = self.expr(node.orelse)
            r = self._new("sel")
            self._emit(SSAInstr("select", r, (test, t, e)))
            return r
        if isinstance(node, ast.Subscript):
            base = self.expr(node.value)
            idx = self.expr(node.slice if isinstance(node.slice, ast.AST) else node.slice.value)
            r = self._new("sub")
            self._emit(SSAInstr("subscript", r, (base, idx)))
            return r
        if isinstance(node, ast.Slice):
            lo = self.expr(node.lower) if node.lower else "_none"
            hi = self.expr(node.upper) if node.upper else "_none"
            r = self._new("slc")
            self._emit(SSAInstr("slice", r, (lo, hi)))
            return r
        if isinstance(node, ast.Call):
            # identify broker.<primitive>(...) calls
            args = [self.expr(a) for a in node.args]
            kwargs = {kw.arg: self.expr(kw.value) for kw in node.keywords}
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id == "broker":
                prim = node.func.attr
                r = self._new("call")
                self._emit(SSAInstr(
                    "broker_call", r,
                    (prim, tuple(args), tuple(sorted(kwargs.items()))),
                    meta={"origin_id": self._origin_id()},
                ))
                return r
            # plain builtin call
            if isinstance(node.func, ast.Name):
                r = self._new("call")
                self._emit(SSAInstr("call", r, (node.func.id, tuple(args), tuple(sorted(kwargs.items())))))
                return r
            # method on data (e.g. dict.get)
            if isinstance(node.func, ast.Attribute):
                base = self.expr(node.func.value)
                r = self._new("mcall")
                self._emit(SSAInstr("method_call", r, (base, node.func.attr, tuple(args))))
                return r
        if isinstance(node, ast.List):
            elts = [self.expr(e) for e in node.elts]
            r = self._new("lst")
            self._emit(SSAInstr("mklist", r, tuple(elts)))
            return r
        if isinstance(node, ast.Dict):
            keys = [self.expr(k) for k in node.keys]
            vals = [self.expr(v) for v in node.values]
            r = self._new("dct")
            self._emit(SSAInstr("mkdict", r, (tuple(keys), tuple(vals))))
            return r
        if isinstance(node, ast.Tuple):
            elts = [self.expr(e) for e in node.elts]
            r = self._new("tup")
            self._emit(SSAInstr("mktup", r, tuple(elts)))
            return r
        raise RuntimeError(f"unsupported expression: {ast.dump(node)}")

    # ---------------- statements ----------------
    def stmt(self, node: ast.AST) -> None:
        if isinstance(node, ast.Assign):
            v = self.expr(node.value)
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    nm = self._new(tgt.id)
                    self._emit(SSAInstr("assign", nm, (v,)))
                    self.env[tgt.id] = nm
                elif isinstance(tgt, ast.Subscript):
                    base = self.expr(tgt.value)
                    idx = self.expr(tgt.slice if isinstance(tgt.slice, ast.AST) else tgt.slice.value)
                    self._emit(SSAInstr("store_subscript", None, (base, idx, v)))
        elif isinstance(node, ast.Expr):
            self.expr(node.value)
        elif isinstance(node, ast.AugAssign):
            tgt = node.target
            if isinstance(tgt, ast.Name):
                lhs = self.env.get(tgt.id, tgt.id)
                rhs = self.expr(node.value)
                r = self._new("aug")
                self._emit(SSAInstr("binop", r, (type(node.op).__name__, lhs, rhs)))
                self.env[tgt.id] = r
        elif isinstance(node, ast.If):
            cond = self.expr(node.test)
            self._emit(SSAInstr("branch_in", None, (cond,)))
            # snapshot env before each branch
            env_before = dict(self.env)
            then_changes: Dict[str, str] = {}
            else_changes: Dict[str, str] = {}
            # then
            for s in node.body:
                self.stmt(s)
            for k, v in self.env.items():
                if env_before.get(k) != v:
                    then_changes[k] = v
            # reset env, take else
            self.env = dict(env_before)
            for s in node.orelse:
                self.stmt(s)
            for k, v in self.env.items():
                if env_before.get(k) != v:
                    else_changes[k] = v
            # phi-merge
            self._emit(SSAInstr("branch_out", None, ()))
            merged = dict(env_before)
            for var in set(then_changes) | set(else_changes):
                t_src = then_changes.get(var, env_before.get(var, var))
                e_src = else_changes.get(var, env_before.get(var, var))
                phi_name = self._new(f"phi_{var}")
                self._emit(SSAInstr("phi", phi_name, (t_src, e_src), meta={"var": var}))
                merged[var] = phi_name
            self.env = merged
        elif isinstance(node, ast.For):
            # Only `for x in range(<literal>)` is allowed.
            if not (isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name)
                    and node.iter.func.id == "range"):
                raise RuntimeError("for-loops must iterate over range(<literal>)")
            args = node.iter.args
            if len(args) != 1 or not isinstance(args[0], ast.Constant) or not isinstance(args[0].value, int):
                raise RuntimeError("for-range bound must be a single integer literal")
            bound = args[0].value
            if bound > 1024:
                raise RuntimeError("for-range bound exceeds gas budget (>1024)")
            self._emit(SSAInstr("loop_in", None, (bound,)))
            for s in node.body:
                self.stmt(s)
            self._emit(SSAInstr("loop_out", None, ()))
        elif isinstance(node, ast.Return):
            v = self.expr(node.value) if node.value else "_none"
            self._emit(SSAInstr("return", None, (v,)))
        elif isinstance(node, ast.Pass):
            pass
        else:
            raise RuntimeError(f"unsupported statement: {ast.dump(node)}")

    # ---------------- entry point ----------------
    def build(self, tree: ast.Module) -> SSAModule:
        cells: List[SSACell] = []
        for top in tree.body:
            if isinstance(top, ast.FunctionDef) and top.name == "cell":
                self.body, self.env = [], {}
                # parameter SSA names
                params = [a.arg for a in top.args.args]
                for p in params:
                    self.env[p] = p
                for s in top.body:
                    self.stmt(s)
                ir_repr = repr(self.body)
                ir_hash = hashlib.sha256(ir_repr.encode()).hexdigest()
                cells.append(SSACell(name=top.name, params=params, body=list(self.body),
                                     ir_hash=ir_hash))
        if not cells:
            raise RuntimeError("no `def cell(...)` found in PyCap module")
        return SSAModule(cells=cells)
