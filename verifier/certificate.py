"""Lightweight certificate cert_t accompanying every Manifest.

In the real CVM deployment this is HMAC-signed by an attestation-bound key. Here
we use HMAC-SHA256 with a session key to retain cryptographic shape — what
matters for the experiments is non-forgeability across components.
"""
from __future__ import annotations
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class Certificate:
    payload_digest: str
    mac: str
    issuer: str = "V_t"


def _digest(payload: Dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def sign_certificate(payload: Dict[str, Any], key: bytes, issuer: str = "V_t") -> Certificate:
    d = _digest(payload)
    mac = hmac.new(key, d.encode(), hashlib.sha256).hexdigest()
    return Certificate(payload_digest=d, mac=mac, issuer=issuer)


def verify_certificate(payload: Dict[str, Any], cert: Certificate, key: bytes) -> bool:
    if _digest(payload) != cert.payload_digest:
        return False
    expect = hmac.new(key, cert.payload_digest.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, cert.mac)
