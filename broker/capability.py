"""Capability tokens κ_t = ⟨h(IR_t), M_t, prefix_hash, nonce, expiry⟩
(paper §3.2). The MAC binds:

  * h(IR_t)     — anchors the token to a specific compiled load
  * manifest    — so an effect outside the envelope is rejected
  * prefix_hash — the head of the audit chain (anti-replay / cross-session)
  * nonce       — fresh per token (anti-TOCTOU)
  * expiry      — wall-clock deadline (anti-stale-token)
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict


# Default token TTL in seconds (paper §3.2 — `expiry` field). Bounded so even
# a leaked token cannot be replayed long after issuance.
DEFAULT_TOKEN_TTL_S = 60.0


@dataclass(frozen=True)
class CapabilityToken:
    ir_hash: str
    manifest_digest: str
    prev_chain: str
    nonce: str
    issued_at: float
    expiry: float           # absolute wall-clock deadline (paper §3.2)
    mac: str

    def serialize(self) -> Dict[str, Any]:
        return dict(ir_hash=self.ir_hash, manifest_digest=self.manifest_digest,
                    prev_chain=self.prev_chain, nonce=self.nonce,
                    issued_at=self.issued_at, expiry=self.expiry, mac=self.mac)


def _digest(payload: Dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def sign_token(*, ir_hash: str, manifest: Dict[str, Any], prev_chain: str, key: bytes,
               ttl_s: float = DEFAULT_TOKEN_TTL_S) -> CapabilityToken:
    nonce = os.urandom(8).hex()
    issued_at = time.time()
    expiry = issued_at + ttl_s
    md = _digest(manifest)
    body = f"{ir_hash}|{md}|{prev_chain}|{nonce}|{issued_at}|{expiry}".encode()
    mac = hmac.new(key, body, hashlib.sha256).hexdigest()
    return CapabilityToken(ir_hash=ir_hash, manifest_digest=md, prev_chain=prev_chain,
                            nonce=nonce, issued_at=issued_at, expiry=expiry, mac=mac)


def verify_token(token: CapabilityToken, manifest: Dict[str, Any], expected_prev_chain: str,
                 key: bytes, *, now: float | None = None) -> bool:
    md = _digest(manifest)
    if token.manifest_digest != md or token.prev_chain != expected_prev_chain:
        return False
    if (now or time.time()) > token.expiry:
        return False    # expired
    body = f"{token.ir_hash}|{token.manifest_digest}|{token.prev_chain}|{token.nonce}|{token.issued_at}|{token.expiry}".encode()
    expect = hmac.new(key, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, token.mac)
