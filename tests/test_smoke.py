"""Smoke tests: each safety invariant from §3.5 of the paper is exercised
once. Run with:    python -m unittest tests.test_smoke
"""
import time
import unittest

from runtime.cvm import CVM
from runtime.cell import CellSubmission
from baselines.systems import PcaWFull
from attacks.families import (
    explicit_exfil, implicit_flow, rebinding, env_escape, failure_desync, benign,
)
from pycap.grammar import syntax_filter, PyCapSyntaxError
from broker.capability import sign_token, verify_token
from verifier.manifest import Manifest, Effect, EffectKind, DEFAULT_OP_FOR_PRIMITIVE
from pycap.lattice import BOTTOM


class TestPyCap(unittest.TestCase):
    def test_pycap_blocks_socket_import(self):
        with self.assertRaises(PyCapSyntaxError):
            syntax_filter("import socket\nsocket.socket()")

    def test_pycap_accepts_clean_cell(self):
        src = '''
def cell(uid, state_in):
    return state_in
'''
        syntax_filter(src)


class TestPaperExample(unittest.TestCase):
    """Reproduces §3.4: the implicit-leak path is blocked, the declassified
    path is admitted."""
    def setUp(self):
        self.cvm = CVM()

    def test_implicit_leak_blocked(self):
        self.cvm.reset_session()
        src = '''
def cell(uid, state_in):
    profile = broker.http_get("crm://user", {"uid": uid})
    avg = sum(profile["recent"][:3]) // 3
    path = "/vip" if profile["vip"] else "/normal"
    broker.send_http("alerts.partner.com", path, {"uid": uid, "avg": avg})
    return {"seen": state_in["seen"] + 1}
'''
        res = self.cvm.submit_cell(CellSubmission(src, {"uid": "u-1", "seen": 0}))
        self.assertFalse(res.accepted)
        self.assertEqual(res.blocked_by, "Broker")

    def test_declassified_path_admitted(self):
        self.cvm.reset_session()
        src = '''
def cell(uid, state_in):
    profile = broker.http_get("crm://user", {"uid": uid})
    avg = sum(profile["recent"][:3]) // 3
    risk_bin = broker.declassify_bucket(avg, bins=[0,300,600], purpose="alert")
    broker.send_http("alerts.partner.com", "/risk", {"risk_bin": risk_bin})
    return {"seen": state_in["seen"] + 1}
'''
        res = self.cvm.submit_cell(CellSubmission(src, {"uid": "u-1", "seen": 0}))
        self.assertTrue(res.accepted, msg=f"unexpected: {res.state} {res.reason}")


class TestSafetyInvariants(unittest.TestCase):
    """§3.3 safety invariants: enforcement-admission, composition-compliance,
    failure-consistency."""

    def test_enforcement_admission_no_phantom_mutation(self):
        sys_ = PcaWFull()
        cases = explicit_exfil(seed=11, n=20)
        admitted = 0
        for c in cases:
            sys_.cvm.reset_session()
            if sys_.decide(c) == "ALLOW":
                admitted += 1
        self.assertEqual(admitted, 0)

    def test_composition_compliance_blocks_implicit_flow(self):
        sys_ = PcaWFull()
        cases = implicit_flow(seed=12, n=20)
        admitted = 0
        for c in cases:
            sys_.cvm.reset_session()
            if sys_.decide(c) == "ALLOW":
                admitted += 1
        self.assertEqual(admitted, 0)

    def test_failure_consistency_audit_chain_intact(self):
        sys_ = PcaWFull()
        cases = failure_desync(seed=13, n=10)
        for c in cases:
            sys_.cvm.reset_session()
            sys_.decide(c)
        # audit chain integrity (sequential prev_chain link) must hold
        rec = sys_.cvm.broker.audit.receipts
        self.assertGreater(len(rec), 0)
        for i in range(1, len(rec)):
            self.assertEqual(rec[i].prev_chain, rec[i-1].chain)


class TestAttackFamilies(unittest.TestCase):
    def test_each_family_blocked(self):
        sys_ = PcaWFull()
        for fn in [explicit_exfil, implicit_flow, rebinding, env_escape,
                   failure_desync]:
            for case in fn(seed=21, n=5):
                sys_.cvm.reset_session()
                self.assertEqual(sys_.decide(case), "BLOCK",
                                  msg=f"{fn.__name__} not blocked: {case.note}")

    def test_benign_admitted_majority(self):
        sys_ = PcaWFull()
        ok = 0
        cases = benign(seed=31, n=40)
        for c in cases:
            sys_.cvm.reset_session()
            if sys_.decide(c) == "ALLOW":
                ok += 1
        # benign majority should pass; ~10% raw-leak variants are correctly blocked
        self.assertGreater(ok / len(cases), 0.7)


class TestEffectTuple(unittest.TestCase):
    """Verify the new Effect tuple fields (paper §2.2)."""

    def test_effect_carries_op_and_beta(self):
        cvm = CVM()
        src = '''
def cell(uid, state_in):
    broker.send_http("alerts.partner.com", "/heartbeat", {"n": 1})
    return state_in
'''
        cvm.submit_cell(CellSubmission(src, {"uid": "u-1", "seen": 0}))
        manifest = next(iter(cvm._source_cache.values()))
        send = next(e for e in manifest.effects if e.primitive == "send_http")
        self.assertEqual(send.op, DEFAULT_OP_FOR_PRIMITIVE["send_http"])
        self.assertGreater(send.budget, 0)
        self.assertGreater(manifest.total_beta, 0)


class TestCapabilityExpiry(unittest.TestCase):
    """Token must be rejected after its expiry (paper §3.2 — `expiry` field)."""

    def test_expired_token_rejected(self):
        manifest = Manifest(ir_hash="ir-test")
        manifest.add_effect(Effect(EffectKind.MUT, "send_http", "alerts.partner.com",
                                    args_summary=(), label=BOTTOM,
                                    op="POST", budget=4))
        key = b"k" * 32
        token = sign_token(ir_hash="ir-test", manifest=manifest.to_dict(),
                            prev_chain="0" * 64, key=key, ttl_s=0.0001)
        self.assertTrue(verify_token(token, manifest.to_dict(), "0" * 64, key,
                                      now=token.issued_at))
        # past expiry
        self.assertFalse(verify_token(token, manifest.to_dict(), "0" * 64, key,
                                       now=token.expiry + 1))


if __name__ == "__main__":
    unittest.main()
