"""Global safety policy A_P modelled as a finite automaton.

States represent discrete admission phases (paper §3.2). Transitions are
triggered only on discrete `Effect` submissions — there are no continuous-
state assumptions, so multi-cell workflows cannot race the automaton.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Optional, Set, Tuple

from pycap.lattice import Label, BOTTOM, HIGH, Lattice
from verifier.manifest import Effect, EffectKind


# Destination allowlist — paper §3.4 specifies that alerts.partner.com is the
# authorized partner endpoint. Anything else is denied.
ALLOWED_MUT_DESTINATIONS: frozenset = frozenset({"alerts.partner.com"})


@dataclass(frozen=True)
class AutomatonState:
    name: str
    accepting: bool = False


@dataclass
class Transition:
    src: AutomatonState
    pred: Callable[[Effect], bool]
    dst: AutomatonState
    note: str = ""


@dataclass
class PolicyAutomaton:
    """A_P = (Q, Σ, δ, q_0, F)."""
    states: Dict[str, AutomatonState]
    transitions: List[Transition]
    initial: AutomatonState
    accepting: FrozenSet[AutomatonState]

    def step(self, current: AutomatonState, eff: Effect) -> Optional[AutomatonState]:
        for t in self.transitions:
            if t.src == current and t.pred(eff):
                return t.dst
        return None

    def accepts(self, current: AutomatonState) -> bool:
        return current in self.accepting


# ---------------- default policy ----------------
def default_automaton() -> PolicyAutomaton:
    """Default safety language: any number of OBS, then DECL?, then MUT.

    Rules:
      * Any OBS effect is allowed (state stays in `obs`).
      * MUT is allowed only when global label-ceiling for that effect is BOT.
      * DECL is allowed only when target is in registry (broker checks).
      * After a successful MUT, automaton remains accepting (idempotent).
    """
    s_init = AutomatonState("init", accepting=True)
    s_obs = AutomatonState("obs", accepting=True)
    s_mut = AutomatonState("mut", accepting=True)

    states = {s.name: s for s in [s_init, s_obs, s_mut]}

    def is_obs(e: Effect) -> bool:
        return e.kind == EffectKind.OBS

    def is_mut_admissible(e: Effect) -> bool:
        # MUT must (1) be label-BOT and (2) target an allowed destination.
        return (e.kind == EffectKind.MUT
                and Lattice.leq(e.label, BOTTOM)
                and e.target in ALLOWED_MUT_DESTINATIONS)

    def is_decl(e: Effect) -> bool:
        return e.kind == EffectKind.DECL

    def is_pure(e: Effect) -> bool:
        return e.kind == EffectKind.PURE

    transitions: List[Transition] = []
    for s in [s_init, s_obs, s_mut]:
        transitions.append(Transition(s, is_obs, s_obs, "obs allowed"))
        transitions.append(Transition(s, is_decl, s, "declassification allowed"))
        transitions.append(Transition(s, is_pure, s, "pure noop"))
        transitions.append(Transition(s, is_mut_admissible, s_mut, "low-mut admitted"))
        # All other effects produce no transition — broker emits a DENY
        # but the automaton stays in its current state (failure consistency,
        # paper §3.3: "回滚仅作用于局部暂态").

    return PolicyAutomaton(
        states=states,
        transitions=transitions,
        initial=s_init,
        accepting=frozenset({s_init, s_obs, s_mut}),
    )
