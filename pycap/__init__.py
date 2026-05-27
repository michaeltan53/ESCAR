"""PyCap: restricted Python sublanguage for ESCar/PcaW.

Strips environment authority. Forces all external interaction through the
broker proxy primitives. Disallows reflection, dynamic import, raw sockets,
unbounded loops.
"""
from .lattice import Label, Lattice, BOTTOM, HIGH
from .grammar import PyCapSyntaxError, syntax_filter
from .ssa import SSABuilder, SSAModule, SSAInstr, PhiNode

__all__ = [
    "Label", "Lattice", "BOTTOM", "HIGH",
    "PyCapSyntaxError", "syntax_filter",
    "SSABuilder", "SSAModule", "SSAInstr", "PhiNode",
]
