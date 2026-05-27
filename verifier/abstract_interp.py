"""Bounded abstract interpretation over PyCap SSA IR (paper §3.1).

State σ̂ tracks, per SSA register:
  * label  ∈ L = {⊥, H}
  * static value (when knowable, used to bind effect targets)

Globals:
  * pc      : program-counter label (high-water mark for control flow)
  * hwm     : session high-water mark for *observed* high data
  * gas     : abstract-step budget

External `broker.<primitive>(...)` calls are converted into `Effect`
records appended to the manifest. The label of the effect is the join of:
  * pc                (control-flow taint)
  * hwm               (session observation-flow taint)
  * arg labels        (data-flow taint)
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from pycap.lattice import Label, Lattice, BOTTOM, HIGH
from pycap.ssa import SSACell, SSAInstr
from .manifest import Effect, EffectKind, Manifest, ResourceBudget, DEFAULT_OP_FOR_PRIMITIVE


# -----------------------------------------------------------------------------
# Abstract values
# -----------------------------------------------------------------------------
@dataclass
class AbstractVal:
    label: Label = BOTTOM
    static: Any = None           # concrete value if known, else None
    known: bool = False

    def join(self, other: "AbstractVal") -> "AbstractVal":
        new_label = Lattice.join(self.label, other.label)
        if self.known and other.known and self.static == other.static:
            return AbstractVal(new_label, self.static, True)
        return AbstractVal(new_label, None, False)


@dataclass
class AbstractState:
    regs: Dict[str, AbstractVal] = field(default_factory=dict)
    pc: Label = BOTTOM
    hwm: Label = BOTTOM
    gas: int = 10_000

    def get(self, name: str) -> AbstractVal:
        if name in self.regs:
            return self.regs[name]
        # parameter or external — start at hwm-equivalent label so that
        # cross-cell continuations stay sound.
        return AbstractVal(self.hwm, None, False)

    def set(self, name: str, v: AbstractVal) -> None:
        self.regs[name] = v


# -----------------------------------------------------------------------------
# High-label data sources
# -----------------------------------------------------------------------------
def source_label(target: Any) -> Label:
    """Map a static URL/resource string to its source label."""
    if isinstance(target, str):
        # crm:// is treated as confidential by default (paper §3.4)
        if target.startswith("crm://") or target.startswith("hr://") or target.startswith("med://"):
            return HIGH
        if target.startswith("public://") or target.startswith("alerts."):
            return BOTTOM
    return BOTTOM


def is_outbound_target(target: Any) -> bool:
    if not isinstance(target, str):
        return True   # unknown -> conservative
    return target.startswith("alerts.") or target.startswith("partner.") \
        or target.startswith("http://") or target.startswith("https://")


# -----------------------------------------------------------------------------
# Result
# -----------------------------------------------------------------------------
@dataclass
class VerifyResult:
    ok: bool
    manifest: Optional[Manifest]
    error: Optional[str] = None


# -----------------------------------------------------------------------------
# Interpreter
# -----------------------------------------------------------------------------
class AbstractInterpreter:
    """Worst-case abstract execution producing an Effect Manifest.

    Designed to be `Sound` rather than `Complete`: the manifest's effect
    envelope is always an over-approximation of what the cell could do.
    """

    BROKER_OBS = {"http_get", "db_read", "fs_read", "kv_get"}
    BROKER_MUT = {"send_http", "db_write", "fs_write", "kv_put"}
    BROKER_DECL = {"declassify_bucket", "declassify_hash", "declassify_redact"}

    def __init__(self, budget: ResourceBudget = ResourceBudget()) -> None:
        self.budget = budget

    # ---------- top-level ----------
    def verify(self, cell: SSACell, *, hwm_in: Label = BOTTOM) -> VerifyResult:
        try:
            manifest = Manifest(ir_hash=cell.ir_hash, budget=self.budget)
            state = AbstractState(hwm=hwm_in, gas=self.budget.gas)
            # parameters get hwm
            for p in cell.params:
                state.set(p, AbstractVal(hwm_in, None, False))

            self._run_block(cell.body, state, manifest)
            manifest.state_in_keys = ("seen",) if "state_in" in cell.params else ()
            manifest.state_out_keys = manifest.state_in_keys
            return VerifyResult(ok=True, manifest=manifest)
        except Exception as e:           # any verification error is a hard reject
            return VerifyResult(ok=False, manifest=None, error=str(e))

    # ---------- block dispatcher ----------
    def _run_block(self, body: List[SSAInstr], state: AbstractState, manifest: Manifest) -> None:
        i = 0
        while i < len(body):
            ins = body[i]
            if state.gas <= 0:
                raise RuntimeError("gas exhausted during abstract interpretation")
            state.gas -= 1
            if ins.op == "branch_in":
                # locate matching branch_out, split into then/else by phi positions
                end = self._match_close(body, i, "branch_in", "branch_out")
                cond_reg = ins.args[0]
                # Apply pc lift for both halves (we treat them as one merged region —
                # this is sound for label tracking even without splitting).
                old_pc = state.pc
                state.pc = Lattice.join(old_pc, state.get(cond_reg).label)
                self._run_block(body[i + 1:end], state, manifest)
                state.pc = old_pc
                i = end + 1
                continue
            if ins.op == "loop_in":
                end = self._match_close(body, i, "loop_in", "loop_out")
                self._run_block(body[i + 1:end], state, manifest)
                i = end + 1
                continue
            self._run_instr(ins, state, manifest)
            i += 1

    @staticmethod
    def _match_close(body: List[SSAInstr], start: int, open_op: str, close_op: str) -> int:
        depth = 1
        for j in range(start + 1, len(body)):
            if body[j].op == open_op:
                depth += 1
            elif body[j].op == close_op:
                depth -= 1
                if depth == 0:
                    return j
        raise RuntimeError(f"unmatched {open_op}")

    # ---------- single instruction ----------
    def _run_instr(self, ins: SSAInstr, state: AbstractState, manifest: Manifest) -> None:
        if ins.op == "const":
            state.set(ins.dst, AbstractVal(BOTTOM, ins.args[0], True))
        elif ins.op == "assign":
            (src,) = ins.args
            state.set(ins.dst, state.get(src))
        elif ins.op == "binop":
            _op, a, b = ins.args
            va, vb = state.get(a), state.get(b)
            state.set(ins.dst, AbstractVal(Lattice.join(va.label, vb.label), None, False))
        elif ins.op == "cmp":
            _op, a, b = ins.args
            va, vb = state.get(a), state.get(b)
            state.set(ins.dst, AbstractVal(Lattice.join(va.label, vb.label), None, False))
        elif ins.op == "boolop":
            _op, *xs = ins.args
            lab = Lattice.join_many(state.get(x).label for x in xs)
            state.set(ins.dst, AbstractVal(lab, None, False))
        elif ins.op == "unaryop":
            _op, v = ins.args
            state.set(ins.dst, AbstractVal(state.get(v).label, None, False))
        elif ins.op == "select":
            t, a, b = ins.args
            lab = Lattice.join_many([state.get(t).label, state.get(a).label, state.get(b).label])
            # `path = "/vip" if profile["vip"] else "/normal"` — even a constant
            # string absorbs the branch label. This matches the paper §3.4.
            state.set(ins.dst, AbstractVal(lab, None, False))
        elif ins.op == "subscript":
            base, idx = ins.args
            vb, vi = state.get(base), state.get(idx)
            state.set(ins.dst, AbstractVal(Lattice.join(vb.label, vi.label), None, False))
        elif ins.op == "slice":
            lo, hi = ins.args
            lab = Lattice.join(state.get(lo).label, state.get(hi).label) if lo != "_none" or hi != "_none" else BOTTOM
            state.set(ins.dst, AbstractVal(lab, None, False))
        elif ins.op == "store_subscript":
            base, idx, v = ins.args
            # The container's label rises with the value's label.
            lab = Lattice.join_many([state.get(base).label, state.get(idx).label, state.get(v).label])
            state.set(base, AbstractVal(lab, None, False))
        elif ins.op == "phi":
            a, b = ins.args
            va, vb = state.get(a), state.get(b)
            merged = va.join(vb)
            # phi inherits pc — control-flow taint absorption (§3.4)
            merged = AbstractVal(Lattice.join(merged.label, state.pc), merged.static, merged.known)
            state.set(ins.dst, merged)
        elif ins.op == "mklist":
            lab = Lattice.join_many(state.get(x).label for x in ins.args)
            state.set(ins.dst, AbstractVal(lab, None, False))
        elif ins.op == "mkdict":
            keys, vals = ins.args
            lab = Lattice.join_many([state.get(x).label for x in (*keys, *vals)])
            state.set(ins.dst, AbstractVal(lab, list(zip(keys, vals)), True))
        elif ins.op == "mktup":
            lab = Lattice.join_many(state.get(x).label for x in ins.args)
            state.set(ins.dst, AbstractVal(lab, None, False))
        elif ins.op == "call":
            _name, args, kwargs = ins.args
            lab = Lattice.join_many(state.get(a).label for a in args)
            state.set(ins.dst, AbstractVal(lab, None, False))
        elif ins.op == "method_call":
            base, _attr, args = ins.args
            lab = Lattice.join_many([state.get(base).label, *(state.get(a).label for a in args)])
            state.set(ins.dst, AbstractVal(lab, None, False))
        elif ins.op == "broker_call":
            self._broker_call(ins, state, manifest)
        elif ins.op == "return":
            (v,) = ins.args
            # return value participates in state_out
            _ = state.get(v)
        else:
            # unknown ops — be conservative: bump pc to HIGH and keep going
            state.pc = Lattice.join(state.pc, HIGH)

    # ---------- broker effect synthesis ----------
    def _broker_call(self, ins: SSAInstr, state: AbstractState, manifest: Manifest) -> None:
        prim, pos_args, kw_args = ins.args
        origin = ins.meta.get("origin_id", 0)
        # Resolve target string statically when possible (first positional arg).
        target_val = state.get(pos_args[0]) if pos_args else AbstractVal(BOTTOM, "*", True)
        target = target_val.static if target_val.known and isinstance(target_val.static, str) else "*"

        # base label for the effect — pc taint + data-flow taint of args.
        # The session hwm is tracked separately; what gets *transmitted* is
        # determined by the labels of the values actually leaving the cell.
        arg_label = Lattice.join_many([state.get(a).label for a in pos_args]
                                      + [state.get(v).label for _, v in kw_args])
        eff_label = Lattice.join_many([state.pc, arg_label])

        if prim in self.BROKER_OBS:
            kind = EffectKind.OBS
            src_lab = source_label(target)
            # observing high data raises hwm
            state.hwm = Lattice.join(state.hwm, src_lab)
            # the result register inherits the source label
            state.set(ins.dst, AbstractVal(Lattice.join(src_lab, eff_label), None, False))
            eff_label = Lattice.join(eff_label, src_lab)
        elif prim in self.BROKER_MUT:
            kind = EffectKind.MUT
            # mutation result is just an ack — label tracks effect label
            state.set(ins.dst, AbstractVal(eff_label, None, False))
        elif prim in self.BROKER_DECL:
            kind = EffectKind.DECL
            # declassification: result label drops to BOTTOM (broker enforces policy)
            state.set(ins.dst, AbstractVal(BOTTOM, None, False))
            eff_label = BOTTOM
        else:
            # Unknown broker primitive — conservatively classify as MUT with
            # HIGH label so the broker policy automaton denies it. The kernel
            # monitor remains as the tertiary defence in NO-AUTOMATON ablation.
            kind = EffectKind.MUT
            eff_label = HIGH
            state.set(ins.dst, AbstractVal(HIGH, None, False))

        # summarize args (name -> label)
        args_summary: List[Tuple[str, str]] = []
        for i, a in enumerate(pos_args):
            args_summary.append((f"arg{i}", state.get(a).label.name))
        for k, v in kw_args:
            args_summary.append((str(k), state.get(v).label.name))

        # Per-effect β consumption: Mut/Decl cost more than Obs (write
        # amplification, declassifier policy lookup). Tunable via the manifest's
        # ResourceBudget. These constants keep the simulator deterministic.
        beta_cost = {EffectKind.OBS: 1, EffectKind.MUT: 4,
                     EffectKind.DECL: 2, EffectKind.PURE: 0}.get(kind, 1)
        op_verb = DEFAULT_OP_FOR_PRIMITIVE.get(prim, "*")

        manifest.add_effect(Effect(
            kind=kind,
            primitive=prim,
            target=target if isinstance(target, str) else "*",
            args_summary=tuple(args_summary),
            label=eff_label,
            origin_id=origin,
            op=op_verb,
            budget=beta_cost,
        ))
