"""SSH access controller.

SSH itself stays enabled in DSM (so scheduled jobs keep working). The gate
controls who may reach the SSH port with a small iptables chain of its own:

    INPUT -> NASGATE
    NASGATE:  -s <trusted host> -p tcp --dport 22  RETURN   (one per host)
              -p tcp --dport 22                     DROP

While the gate is open the chain is empty, so anyone may connect. While it is
closed only the trusted hosts (for example the Home Assistant machine that
pulls backups) get through.

Requirements: container runs with network_mode host and cap NET_ADMIN.
The rules live in the host kernel, so they also survive a container restart.
If DSM's own firewall is turned on it manages separate chains; a DSM
"apply" may drop our jump rule, which fails open (SSH reachable), never
locks anyone out. The gate re-adds its rules on every open/close.
"""

from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess

from ..config import Settings
from . import ControllerStatus

log = logging.getLogger("nasgate.ssh")

CHAIN = "NASGATE"


class SSHError(Exception):
    pass


def _find_iptables() -> str:
    """Prefer the legacy (xtables) binary: Synology kernels have no nf_tables."""
    for name in ("iptables-legacy", "iptables"):
        exe = shutil.which(name)
        if exe:
            return exe
    raise SSHError("iptables binary not found in the container image")


def _ipt(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    exe = _find_iptables()
    cp = subprocess.run([exe, "-w", "5", *args], capture_output=True, text=True)
    if check and cp.returncode != 0:
        raise SSHError(f"iptables {' '.join(args)}: {cp.stderr.strip() or cp.stdout.strip()}")
    return cp


def _valid_host(h: str) -> str:
    """Accept an IP or CIDR; reject anything else so it never reaches a shell."""
    try:
        return str(ipaddress.ip_network(h, strict=False))
    except ValueError as e:
        raise SSHError(f"Trusted host '{h}' is not a valid IP or CIDR") from e


class SSHController:
    id = "ssh"

    def __init__(self, settings: Settings, runner=_ipt):
        self.settings = settings
        self._ipt = runner

    # -- chain plumbing ------------------------------------------------------
    def _ensure_chain(self) -> None:
        if self._ipt("-L", CHAIN, "-n", check=False).returncode != 0:
            self._ipt("-N", CHAIN)
        # Jump from INPUT, first position, exactly once.
        if self._ipt("-C", "INPUT", "-j", CHAIN, check=False).returncode != 0:
            self._ipt("-I", "INPUT", "1", "-j", CHAIN)

    def _flush(self) -> None:
        if self._ipt("-L", CHAIN, "-n", check=False).returncode == 0:
            self._ipt("-F", CHAIN)

    def remove(self) -> None:
        """Remove every trace of the gate from iptables (used by uninstall)."""
        self._ipt("-D", "INPUT", "-j", CHAIN, check=False)
        self._ipt("-F", CHAIN, check=False)
        self._ipt("-X", CHAIN, check=False)

    # -- controller API ------------------------------------------------------
    def apply(self, open_: bool) -> None:
        port = str(int(self.settings.ssh_port))
        self._ensure_chain()
        self._flush()
        if open_:
            log.info("SSH open to everyone")
            return
        for host in self.settings.ssh_trusted_hosts:
            net = _valid_host(host)
            self._ipt("-A", CHAIN, "-s", net, "-p", "tcp", "--dport", port, "-j", "RETURN")
        self._ipt("-A", CHAIN, "-p", "tcp", "--dport", port, "-j", "DROP")
        log.info("SSH closed; trusted hosts: %s", ", ".join(self.settings.ssh_trusted_hosts) or "none")

    def status(self) -> ControllerStatus:
        try:
            cp = self._ipt("-S", CHAIN, check=False)
        except SSHError as e:
            return ControllerStatus(self.id, "error", str(e))
        if cp.returncode != 0:
            return ControllerStatus(self.id, "open", "no gate rules installed")
        rules = [l for l in cp.stdout.splitlines() if l.startswith("-A")]
        if not any(" -j DROP" in r for r in rules):
            return ControllerStatus(self.id, "open", "")
        jump = self._ipt("-C", "INPUT", "-j", CHAIN, check=False).returncode == 0
        if not jump:
            return ControllerStatus(self.id, "open", "gate chain exists but INPUT jump is missing")
        trusted = [r.split("-s ")[1].split()[0] for r in rules if " -s " in r]
        return ControllerStatus(self.id, "closed", "trusted: " + (", ".join(trusted) or "none"))
