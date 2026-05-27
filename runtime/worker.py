"""Worker pool: ephemeral processes that execute admitted effects.

Workers do not hold any environment authority — every external effect is
proxied through the Broker. This is enforced by:
  * the PyCap syntax filter (rejects raw socket/import/etc.)
  * the kernel monitor (default-deny on sensitive syscalls)
  * the simulated runtime (this file): the only way to call out is via
    `RuntimeBrokerProxy`, which forwards to the trusted broker.

After each cell, the worker is reset (clean template) — `state_out` is the
only continuity carrier between cells (paper §3.1, §4.1).
"""
from __future__ import annotations
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# Optional simulated network I/O cost. Off by default — on Windows the
# sleep granularity (~15 ms) distorts microbenchmarks. Set ESCAR_IO_MS to
# any positive value (e.g. 5 on Linux) to model deployment latencies.
_SIM_IO_MS = float(os.environ.get("ESCAR_IO_MS", "0"))

from kernel.enforcement import KernelMonitor, SyscallDenied
from verifier.manifest import Effect, EffectKind
from pycap.lattice import BOTTOM, HIGH, Label, Lattice
from broker.broker import Broker, AdmitResult
from broker.capability import CapabilityToken
from verifier.manifest import Manifest


# ---------------- mock external services ------------------
class _MockServices:
    """Tiny in-memory stand-in for crm://, kv://, http://."""

    def __init__(self) -> None:
        self.kv = {"seen": 0}
        self.crm = {
            "u-1": {"vip": True,  "recent": [50, 100, 250, 60], "name": "Alice"},
            "u-2": {"vip": False, "recent": [10, 20, 5, 8],     "name": "Bob"},
        }
        self.outbox: List[Dict[str, Any]] = []

    def crm_get(self, target: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if _SIM_IO_MS:
            time.sleep(_SIM_IO_MS / 1000)
        uid = payload.get("uid", "u-1")
        return dict(self.crm.get(uid, {"vip": False, "recent": []}))

    def http_post(self, target: str, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        if _SIM_IO_MS:
            time.sleep(_SIM_IO_MS / 1000)
        rec = dict(target=target, path=path, body=body, ts=time.time())
        self.outbox.append(rec)
        return {"ok": True}


@dataclass
class RuntimeBrokerProxy:
    """Side that the executing cell sees as `broker`."""
    broker: Broker
    manifest: Manifest
    services: _MockServices
    kernel: KernelMonitor

    pending_token: Optional[CapabilityToken] = None
    receipts: List[Any] = field(default_factory=list)
    last_error: Optional[str] = None

    # ---------------- helpers ----------------
    def _effect(self, kind: EffectKind, primitive: str, target: str, args: Dict[str, str],
                label: Label, origin_id: int = 0) -> Effect:
        return Effect(kind=kind, primitive=primitive, target=target,
                      args_summary=tuple(args.items()), label=label, origin_id=origin_id)

    def _submit(self, eff: Effect) -> AdmitResult:
        # acquire a capability token bound to current chain head — only when
        # capability enforcement is on (the broker silently admits without
        # token verification when the knob is off, used by ablation/baselines).
        token = (self.broker.issue_token(self.manifest)
                  if self.broker.enable_capability else None)
        result = self.broker.submit(manifest=self.manifest, effect=eff, token=token)
        self.receipts.append(result.receipt)
        if not result.ok:
            self.last_error = result.reason
        return result

    # ---------------- broker primitives ----------------
    def _lookup_label(self, primitive: str, target: str, kind: EffectKind) -> Label:
        exact: Optional[Any] = None
        wildcard: Optional[Any] = None
        for declared in self.manifest.effects:
            if declared.primitive == primitive and declared.kind == kind:
                if declared.target == target:
                    exact = declared
                    break
                if declared.target == "*":
                    wildcard = declared
        chosen = exact if exact is not None else wildcard
        return chosen.label if chosen is not None else BOTTOM

    def http_get(self, target: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        label = self._lookup_label("http_get", target, EffectKind.OBS)
        eff = self._effect(EffectKind.OBS, "http_get", target,
                           {"uid": "BOT"}, label=label)
        r = self._submit(eff)
        if not r.ok:
            return {}
        return self.services.crm_get(target, payload)

    def send_http(self, target: str, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        label = self._lookup_label("send_http", target, EffectKind.MUT)
        eff = self._effect(EffectKind.MUT, "send_http", target,
                           {"path": "BOT", "body": label.name}, label=label)
        r = self._submit(eff)
        if not r.ok:
            return {"ok": False, "reason": r.reason}
        return self.services.http_post(target, path, body)

    def kv_get(self, key: str) -> Any:
        eff = self._effect(EffectKind.OBS, "kv_get", key, {}, label=BOTTOM)
        self._submit(eff)
        return self.services.kv.get(key)

    def declassify_bucket(self, value: Any, bins=(0, 300, 600), purpose: str = "alert") -> str:
        eff = self._effect(EffectKind.DECL, "declassify_bucket", purpose,
                           {"bins": "BOT"}, label=BOTTOM)
        r = self._submit(eff)
        if not r.ok:
            return ""
        return self.broker.declassifiers.get("declassify_bucket").fn(value, bins=bins, purpose=purpose)

    def declassify_hash(self, value: Any, purpose: str = "audit") -> str:
        eff = self._effect(EffectKind.DECL, "declassify_hash", purpose,
                           {}, label=BOTTOM)
        r = self._submit(eff)
        if not r.ok:
            return ""
        return self.broker.declassifiers.get("declassify_hash").fn(value, purpose=purpose)

    def declassify_redact(self, value: Any, keep: int = 2, purpose: str = "logging") -> str:
        eff = self._effect(EffectKind.DECL, "declassify_redact", purpose,
                           {"keep": "BOT"}, label=BOTTOM)
        r = self._submit(eff)
        if not r.ok:
            return ""
        return self.broker.declassifiers.get("declassify_redact").fn(value, keep=keep, purpose=purpose)

    # ---- masquerading primitives caught by the kernel monitor ----
    def raw_socket(self, host: str, port: int) -> Any:
        # This is *not* a real broker primitive. A malicious cell that calls
        # it should be blocked at the kernel layer (default-deny).
        if self.broker.enable_kernel_fallback:
            self.kernel.call("raw_socket")
        # If kernel enforcement is off, fall through and "succeed" — i.e.,
        # the simulated escape would have happened in production.
        return {"escaped": True, "host": host, "port": port}

    def tcp_connect(self, host: str, port: int) -> Any:
        if self.broker.enable_kernel_fallback:
            self.kernel.call("tcp_connect")
        return {"escaped": True}


# ---------------------------------------------------------------------------
class Worker:
    """Single-shot worker. Built to be reset between cells."""

    def __init__(self, broker: Broker, services: Optional[_MockServices] = None,
                 kernel: Optional[KernelMonitor] = None) -> None:
        self.broker = broker
        self.services = services or _MockServices()
        self.kernel = kernel or KernelMonitor.default()

    def execute(self, source: str, manifest: Manifest, state_in: Dict[str, Any]) -> Dict[str, Any]:
        proxy = RuntimeBrokerProxy(self.broker, manifest, self.services, self.kernel)

        # exec the source in a strictly minimal namespace
        safe_builtins = {
            "len": len, "sum": sum, "min": min, "max": max, "abs": abs, "range": range,
            "int": int, "float": float, "str": str, "bool": bool,
            "list": list, "dict": dict, "tuple": tuple,
            "sorted": sorted, "any": any, "all": all, "round": round, "True": True,
            "False": False, "None": None,
        }
        ns: Dict[str, Any] = {"broker": proxy, "__builtins__": safe_builtins}
        exec(compile(source, "<cell>", "exec"), ns, ns)
        if "cell" not in ns:
            raise RuntimeError("source did not define cell()")
        # The cell signature in PcaW is `cell(uid, state_in)` per §3.4. We
        # inject from state_in["uid"] when present, else "u-1".
        uid = state_in.get("uid", "u-1")
        out = ns["cell"](uid, dict(state_in)) or {}
        return dict(out)


@dataclass
class WorkerPool:
    """Long-running CVM, ephemeral workers."""
    broker: Broker

    def acquire(self) -> Worker:
        return Worker(self.broker)
