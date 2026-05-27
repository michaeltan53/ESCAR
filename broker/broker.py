"""Trusted Broker: the only component permitted to submit external effects.

For every effect submission it checks (paper §3.2):
  (1) the effect is declared in the static manifest (envelope check);
  (2) the policy automaton accepts the effect from the current state;
  (3) the capability token is bound to (IR hash, manifest, h_{t-1}).

On admit:  generates a receipt, advances the chain, advances the automaton.
On deny:   appends an Error Manifest receipt — the chain advances either way.
"""
from __future__ import annotations
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from pycap.lattice import BOTTOM, Lattice
from verifier.manifest import Effect, EffectKind, Manifest

from .audit import AuditLog, ErrorManifest, Receipt
from .automaton import AutomatonState, PolicyAutomaton, default_automaton
from .capability import CapabilityToken, sign_token, verify_token
from .declassifier import DeclassifierRegistry, default_registry


@dataclass
class AdmitResult:
    ok: bool
    receipt: Optional[Receipt]
    reason: str = ""


def _manifest_digest(manifest: Manifest) -> str:
    blob = json.dumps(manifest.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


class Broker:
    """The single point of authority for outbound effects.

    Lives in the CVM. In this prototype the CVM boundary is logical: the
    broker holds the only HMAC key and the only handle to the audit log.
    """

    def __init__(self,
                 *,
                 automaton: Optional[PolicyAutomaton] = None,
                 declassifiers: Optional[DeclassifierRegistry] = None,
                 sign_key: Optional[bytes] = None,
                 enable_envelope_check: bool = True,
                 enable_automaton: bool = True,
                 enable_capability: bool = True,
                 enable_kernel_fallback: bool = True,
                 ) -> None:
        self.automaton = automaton or default_automaton()
        self.declassifiers = declassifiers or default_registry()
        self.sign_key = sign_key or os.urandom(32)
        self.audit = AuditLog()
        self.state: AutomatonState = self.automaton.initial
        # ablation knobs
        self.enable_envelope_check = enable_envelope_check
        self.enable_automaton = enable_automaton
        self.enable_capability = enable_capability
        self.enable_kernel_fallback = enable_kernel_fallback
        self._issued_tokens: Dict[str, CapabilityToken] = {}

    # ------------------------------------------------------------------
    def issue_token(self, manifest: Manifest) -> CapabilityToken:
        """Bind a capability token to (IR hash, manifest, h_{t-1})."""
        token = sign_token(ir_hash=manifest.ir_hash,
                           manifest=manifest.to_dict(),
                           prev_chain=self.audit.head,
                           key=self.sign_key)
        self._issued_tokens[token.nonce] = token
        return token

    # ------------------------------------------------------------------
    def submit(self, *, manifest: Manifest, effect: Effect,
               token: Optional[CapabilityToken]) -> AdmitResult:
        # 1) Envelope: effect must be declared in manifest.
        if self.enable_envelope_check and not self._effect_in_envelope(effect, manifest):
            err = ErrorManifest(
                reason="envelope_violation",
                automaton_state=self.state.name,
                refused_effect=dict(kind=effect.kind.value, primitive=effect.primitive,
                                    target=effect.target, label=effect.label.name),
            )
            r = self.audit.append_error(ir_hash=manifest.ir_hash,
                                        manifest_digest=_manifest_digest(manifest), err=err)
            return AdmitResult(False, r, "effect outside manifest envelope")

        # 2) Capability token.
        if self.enable_capability:
            if token is None:
                err = ErrorManifest(reason="missing_capability",
                                     automaton_state=self.state.name,
                                     refused_effect=dict(kind=effect.kind.value,
                                                         primitive=effect.primitive,
                                                         target=effect.target,
                                                         label=effect.label.name))
                r = self.audit.append_error(ir_hash=manifest.ir_hash,
                                            manifest_digest=_manifest_digest(manifest), err=err)
                return AdmitResult(False, r, "no capability token")
            if not verify_token(token, manifest.to_dict(), token.prev_chain, self.sign_key):
                err = ErrorManifest(reason="invalid_token",
                                     automaton_state=self.state.name,
                                     refused_effect=dict(kind=effect.kind.value,
                                                         primitive=effect.primitive,
                                                         target=effect.target,
                                                         label=effect.label.name))
                r = self.audit.append_error(ir_hash=manifest.ir_hash,
                                            manifest_digest=_manifest_digest(manifest), err=err)
                return AdmitResult(False, r, "capability token verification failed")
            # anti-replay: token must reference the *current* head
            if token.prev_chain != self.audit.head:
                err = ErrorManifest(reason="stale_token_prev_chain",
                                     automaton_state=self.state.name,
                                     refused_effect=dict(kind=effect.kind.value,
                                                         primitive=effect.primitive,
                                                         target=effect.target,
                                                         label=effect.label.name))
                r = self.audit.append_error(ir_hash=manifest.ir_hash,
                                            manifest_digest=_manifest_digest(manifest), err=err)
                return AdmitResult(False, r, "stale token prev-chain (replay attempt)")

        # 3) Policy automaton.
        if self.enable_automaton:
            nxt = self.automaton.step(self.state, effect)
            if nxt is None or not self.automaton.accepts(nxt):
                err = ErrorManifest(reason="policy_block",
                                     automaton_state=self.state.name,
                                     refused_effect=dict(kind=effect.kind.value,
                                                         primitive=effect.primitive,
                                                         target=effect.target,
                                                         label=effect.label.name))
                r = self.audit.append_error(ir_hash=manifest.ir_hash,
                                            manifest_digest=_manifest_digest(manifest), err=err)
                return AdmitResult(False, r, f"policy denied at state {self.state.name}")
            self.state = nxt

        # 4) Declassification routing.
        if effect.kind == EffectKind.DECL:
            if not self.declassifiers.has(effect.primitive):
                err = ErrorManifest(reason="unregistered_declassifier",
                                     automaton_state=self.state.name,
                                     refused_effect=dict(kind=effect.kind.value,
                                                         primitive=effect.primitive,
                                                         target=effect.target,
                                                         label=effect.label.name))
                r = self.audit.append_error(ir_hash=manifest.ir_hash,
                                            manifest_digest=_manifest_digest(manifest), err=err)
                return AdmitResult(False, r, "declassifier not in registry")

        # 5) Admit.
        receipt = self.audit.append(ir_hash=manifest.ir_hash,
                                    manifest_digest=_manifest_digest(manifest),
                                    effect=effect, decision="ADMIT")
        return AdmitResult(True, receipt, "ok")

    # ------------------------------------------------------------------
    @staticmethod
    def _effect_in_envelope(eff: Effect, manifest: Manifest) -> bool:
        for declared in manifest.effects:
            if declared.kind == eff.kind \
                    and declared.primitive == eff.primitive \
                    and (declared.target == "*" or declared.target == eff.target) \
                    and Lattice.leq(eff.label, declared.label):
                return True
        return False

    # ------------------------------------------------------------------
    def reset_session(self) -> None:
        """Reset automaton state but keep audit chain."""
        self.state = self.automaton.initial
