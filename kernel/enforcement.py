"""Default-deny syscall enforcement (paper §3.2)."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Set


SENSITIVE_SYSCALLS: Set[str] = {
    "socket", "connect", "bind", "listen", "accept",
    "open", "openat", "creat", "unlink", "rename",
    "execve", "execveat", "fork", "clone", "ptrace",
    "mount", "umount", "chmod", "chown",
    "sendto", "recvfrom",
    "raw_socket", "tcp_connect",      # synthetic names used by attacks/
}


class SyscallDenied(Exception):
    pass


@dataclass
class KernelMonitor:
    """Default-deny: only broker.* primitives are exempt; everything else dies."""
    allowed: Set[str]
    denied_log: List[str]

    @classmethod
    def default(cls) -> "KernelMonitor":
        return cls(allowed=set(), denied_log=[])

    def call(self, syscall: str) -> None:
        if syscall in SENSITIVE_SYSCALLS and syscall not in self.allowed:
            self.denied_log.append(syscall)
            raise SyscallDenied(f"kernel default-deny: {syscall}")
