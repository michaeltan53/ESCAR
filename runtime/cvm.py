"""Resident CVM: long-lived process that runs the verifier and broker.

The CVM bootstraps once and accepts long-lived RPC-style cell submissions.
Per the paper §4.1, validator cost is amortized via a content-addressed
manifest cache.
"""
from __future__ import annotations
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from broker.broker import Broker
from kernel.enforcement import KernelMonitor, SyscallDenied
from pycap.grammar import PyCapSyntaxError, syntax_filter
from pycap.lattice import Label, BOTTOM, HIGH, Lattice
from pycap.ssa import SSABuilder
from verifier.abstract_interp import AbstractInterpreter
from verifier.manifest import Manifest

from .cell import CellSubmission
from .worker import Worker, WorkerPool


@dataclass
class ExecResult:
    accepted: bool
    state: str               # "OK" | "SYNTAX_REJECT" | "VERIFY_REJECT"
                              # | "BROKER_DENY" | "KERNEL_DENY" | "EXEC_ERROR"
    reason: str = ""
    manifest: Optional[Manifest] = None
    state_out: Dict[str, Any] = field(default_factory=dict)
    audit_chain_head: str = ""
    blocked_by: str = ""     # which layer blocked: V_t / Broker / Kernel
    elapsed_ms: float = 0.0


class CVM:
    """Long-lived confidential VM hosting the broker + verifier."""

    def __init__(self,
                 *,
                 broker: Optional[Broker] = None,
                 verifier: Optional[AbstractInterpreter] = None,
                 enable_static: bool = True,
                 enable_runtime: bool = True,    # broker policy automaton
                 enable_kernel: bool = True,     # seccomp/BPF default-deny
                 enable_capability: bool = True, # capability token check
                 enable_envelope: bool = True,   # manifest envelope check
                 enable_ifc: bool = True,        # high-water-mark IFC tracking
                 ) -> None:
        self.broker = broker or Broker(enable_envelope_check=enable_envelope,
                                       enable_capability=enable_capability,
                                       enable_kernel_fallback=enable_kernel)
        # Map enable_runtime -> automaton on/off.
        self.broker.enable_automaton = enable_runtime
        self.verifier = verifier or AbstractInterpreter()
        self.workers = WorkerPool(self.broker)
        self.enable_static = enable_static
        self.enable_runtime = enable_runtime
        self.enable_kernel = enable_kernel
        self.enable_ifc = enable_ifc
        self._manifest_cache: Dict[str, Manifest] = {}
        # Source-content cache: maps SHA-256(source) → manifest. On a hit we
        # skip parse + SSA build + abstract interpretation (paper §4.1).
        self._source_cache: Dict[str, Manifest] = {}
        self._session_hwm: Label = BOTTOM

    # ------------------------------------------------------------------
    def submit_cell(self, sub: CellSubmission) -> ExecResult:
        t0 = time.perf_counter()

        # Content-addressed cache hit — skip parse + SSA + verify.
        src_key = hashlib.sha256(sub.source.encode()).hexdigest()
        cached_manifest = self._source_cache.get(src_key) if self.enable_static and self.enable_ifc else None
        tree = None

        if cached_manifest is None:
            # 1) Syntax filter (PyCap)
            if self.enable_static:
                try:
                    tree = syntax_filter(sub.source)
                except PyCapSyntaxError as e:
                    return ExecResult(False, "SYNTAX_REJECT", str(e),
                                      audit_chain_head=self.broker.audit.head,
                                      blocked_by="V_t",
                                      elapsed_ms=(time.perf_counter() - t0) * 1000)
            else:
                import ast as _ast
                try:
                    tree = _ast.parse(sub.source)
                except SyntaxError as e:
                    return ExecResult(False, "SYNTAX_REJECT", str(e),
                                      blocked_by="parser",
                                      elapsed_ms=(time.perf_counter() - t0) * 1000)

        # 2) SSA + abstract interpretation
        manifest: Optional[Manifest] = cached_manifest
        if cached_manifest is not None:
            pass     # source-cache hit
        elif self.enable_static and self.enable_ifc:
            try:
                module = SSABuilder().build(tree)
            except Exception as e:
                return ExecResult(False, "VERIFY_REJECT", f"SSA build failed: {e}",
                                  audit_chain_head=self.broker.audit.head,
                                  blocked_by="V_t",
                                  elapsed_ms=(time.perf_counter() - t0) * 1000)
            cell = module.cells[0]
            cached = self._manifest_cache.get(cell.ir_hash)
            if cached is not None:
                manifest = cached
            else:
                vr = self.verifier.verify(cell, hwm_in=self._session_hwm)
                if not vr.ok or vr.manifest is None:
                    return ExecResult(False, "VERIFY_REJECT", vr.error or "unknown",
                                      audit_chain_head=self.broker.audit.head,
                                      blocked_by="V_t",
                                      elapsed_ms=(time.perf_counter() - t0) * 1000)
                manifest = vr.manifest
                self._manifest_cache[cell.ir_hash] = manifest
            self._source_cache[src_key] = manifest
        else:
            # NO-IFC ablation: build a permissive manifest with BOT labels.
            # Without IFC, the system has no taint to track, so every effect
            # is treated as low — implicit-flow leaks succeed.
            from verifier.manifest import Effect, EffectKind
            manifest = Manifest(ir_hash="permissive")
            for prim in ("http_get", "send_http", "kv_get", "declassify_bucket",
                         "declassify_hash", "declassify_redact", "db_read", "db_write"):
                kind = (EffectKind.OBS if prim in {"http_get", "kv_get", "db_read"} else
                        EffectKind.DECL if prim.startswith("declassify_") else
                        EffectKind.MUT)
                manifest.effects.append(Effect(kind=kind, primitive=prim, target="*",
                                                args_summary=(), label=BOTTOM))
            manifest.label_ceiling = BOTTOM

        # 3) Execute under worker, broker mediates externals
        worker = self.workers.acquire()
        chain_baseline = len(self.broker.audit.receipts)
        try:
            state_out = worker.execute(sub.source, manifest, sub.state_in)
        except SyscallDenied as e:
            return ExecResult(False, "KERNEL_DENY", str(e),
                              manifest=manifest,
                              audit_chain_head=self.broker.audit.head,
                              blocked_by="Kernel",
                              elapsed_ms=(time.perf_counter() - t0) * 1000)
        except Exception as e:
            return ExecResult(False, "EXEC_ERROR", repr(e),
                              manifest=manifest,
                              audit_chain_head=self.broker.audit.head,
                              elapsed_ms=(time.perf_counter() - t0) * 1000)

        # Inspect only receipts produced by this cell.
        cell_receipts = self.broker.audit.receipts[chain_baseline:]
        denied = [r for r in cell_receipts if r.decision == "DENY"]
        if denied:
            return ExecResult(False, "BROKER_DENY",
                              denied[-1].note or "policy denial",
                              manifest=manifest,
                              audit_chain_head=self.broker.audit.head,
                              blocked_by="Broker",
                              elapsed_ms=(time.perf_counter() - t0) * 1000)

        # update session HWM monotonically
        self._session_hwm = Lattice.join(self._session_hwm, manifest.label_ceiling)
        return ExecResult(True, "OK", "ok", manifest=manifest, state_out=state_out,
                          audit_chain_head=self.broker.audit.head,
                          elapsed_ms=(time.perf_counter() - t0) * 1000)

    def reset_session(self) -> None:
        self.broker.reset_session()
        self._session_hwm = BOTTOM
