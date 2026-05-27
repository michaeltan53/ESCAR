"""Effect Manifest M_t = ⟨Ê_t, ℓ_t*, β_t*, h(IR_t)⟩ (paper §2.2, §3.1).

Each effect carries the tuple e = ⟨kind, dst, op, args, ℓ, β⟩:
  * kind : Obs | Mut | Decl  (pure also retained for internal noops)
  * dst  : destination resource (URL / table / file path)
  * op   : operation semantics (verb-level, e.g. GET / POST / READ / WRITE)
  * args : argument summary (name → label)
  * ℓ    : information-flow label upper bound
  * β    : per-effect resource-budget consumption
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Tuple
from pycap.lattice import Label, BOTTOM, Lattice


class EffectKind(str, Enum):
    PURE = "Pure"
    OBS = "Obs"      # read-only observation
    MUT = "Mut"      # external mutation
    DECL = "Decl"    # declassification


# Per-primitive default operation verb. The verifier writes this into Effect.op
# so policy-layer rules can match on operation semantics rather than primitive
# string alone (paper §2.2).
DEFAULT_OP_FOR_PRIMITIVE: Dict[str, str] = {
    "http_get":            "GET",
    "send_http":           "POST",
    "kv_get":              "READ",
    "kv_put":              "WRITE",
    "db_read":             "READ",
    "db_write":            "WRITE",
    "fs_read":             "READ",
    "fs_write":            "WRITE",
    "declassify_bucket":   "DECLASSIFY",
    "declassify_hash":     "DECLASSIFY",
    "declassify_redact":   "DECLASSIFY",
    "raw_socket":          "CONNECT",
    "tcp_connect":         "CONNECT",
}


@dataclass(frozen=True)
class Effect:
    kind: EffectKind
    primitive: str                 # e.g. "send_http", "http_get", "declassify_bucket"
    target: str                    # destination URL / resource id (or "*" if uncertain)
    args_summary: Tuple[Tuple[str, str], ...]   # name -> "BOT"/"H"
    label: Label                   # ℓ_eff for this effect
    origin_id: int = 0
    op: str = "*"                  # operation verb (paper §2.2 — `op` field of e)
    budget: int = 1                # β: per-effect budget consumption (paper §2.2)


@dataclass(frozen=True)
class ResourceBudget:
    gas: int = 10_000              # abstract-instruction budget
    wall_ms: int = 5_000           # max wall-time
    out_bytes: int = 64 * 1024     # max network output


@dataclass
class Manifest:
    """Static contract attached to a Cell. Fully serializable."""
    ir_hash: str
    effects: List[Effect] = field(default_factory=list)
    label_ceiling: Label = BOTTOM    # global ℓ_eff upper bound across all effects
    budget: ResourceBudget = field(default_factory=ResourceBudget)
    state_in_keys: Tuple[str, ...] = ()
    state_out_keys: Tuple[str, ...] = ()

    # ---------- summarization ----------
    def add_effect(self, eff: Effect) -> None:
        self.effects.append(eff)
        self.label_ceiling = Lattice.join(self.label_ceiling, eff.label)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ir_hash": self.ir_hash,
            "label_ceiling": self.label_ceiling.name,
            "budget": dict(gas=self.budget.gas, wall_ms=self.budget.wall_ms,
                           out_bytes=self.budget.out_bytes),
            "effects": [
                dict(kind=e.kind.value, primitive=e.primitive, op=e.op, target=e.target,
                     args=list(e.args_summary), label=e.label.name,
                     beta=e.budget, origin=e.origin_id)
                for e in self.effects
            ],
            "state_in_keys": list(self.state_in_keys),
            "state_out_keys": list(self.state_out_keys),
        }

    @property
    def total_beta(self) -> int:
        """β_t* — sum of per-effect budget consumption (paper §2.2)."""
        return sum(e.budget for e in self.effects)
