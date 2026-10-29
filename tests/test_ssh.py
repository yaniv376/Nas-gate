import subprocess

import pytest

from nasgate.config import Settings
from nasgate.controllers.ssh import CHAIN, SSHController, SSHError


class FakeIpt:
    """Simulates just enough of iptables to check the rule logic."""
    def __init__(self):
        self.chain = None; self.jump = False; self.calls = []
    def __call__(self, *args, check=True):
        self.calls.append(args)
        rc, out = 0, ""
        a = args
        if a[0] == "-L":
            rc = 0 if self.chain is not None else 1
        elif a[0] == "-N":
            self.chain = []
        elif a[0] == "-C":
            rc = 0 if self.jump else 1
        elif a[0] == "-I":
            self.jump = True
        elif a[0] == "-F":
            self.chain = []
        elif a[0] == "-A":
            self.chain.append("-A " + " ".join(a[1:]))
        elif a[0] == "-S":
            rc = 0 if self.chain is not None else 1
            out = "\n".join([f"-N {CHAIN}"] + (self.chain or []))
        if check and rc != 0:
            raise SSHError("fail")
        return subprocess.CompletedProcess(a, rc, out, "")


def test_closed_allows_only_trusted_hosts():
    s = Settings(ssh_port=22, ssh_trusted_hosts=["192.168.4.20", "10.0.0.0/24"])
    ipt = FakeIpt(); ctl = SSHController(s, runner=ipt)
    ctl.apply(False)
    assert ipt.jump
    assert ipt.chain == [
        f"-A {CHAIN} -s 192.168.4.20/32 -p tcp --dport 22 -j RETURN",
        f"-A {CHAIN} -s 10.0.0.0/24 -p tcp --dport 22 -j RETURN",
        f"-A {CHAIN} -p tcp --dport 22 -j DROP",
    ]
    st = ctl.status()
    assert st.live == "closed" and "192.168.4.20/32" in st.detail


def test_open_flushes_rules():
    s = Settings(ssh_trusted_hosts=["192.168.4.20"])
    ipt = FakeIpt(); ctl = SSHController(s, runner=ipt)
    ctl.apply(False); ctl.apply(True)
    assert ipt.chain == [] and ctl.status().live == "open"


def test_bad_host_rejected():
    s = Settings(ssh_trusted_hosts=["not an ip; rm -rf /"])
    ctl = SSHController(s, runner=FakeIpt())
    with pytest.raises(SSHError):
        ctl.apply(False)
