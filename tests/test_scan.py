import importlib

import pytest

from nasgate.config import Settings
from nasgate.dsm import DSMError


class FakeDSM:
    """Answers DSM API calls from a dict keyed by (api, method)."""
    def __init__(self, answers):
        self.answers = answers; self.calls = []
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def request(self, api, method, version=None, **params):
        self.calls.append((api, method, params))
        key = (api, method)
        if key not in self.answers:
            raise DSMError(f"DSM error 102: {api}")
        return dict(self.answers[key])
    def quickconnect_get(self):
        return self.request("SYNO.Core.QuickConnect", "get")


GOOD = {
    ("SYNO.Core.Upgrade.Server", "check"): {"update": {"available": False}},
    ("SYNO.Core.Terminal", "get"): {"enable_ssh": True, "enable_telnet": False, "ssh_port": 22},
    ("SYNO.Core.Security.AutoBlock", "get"): {"enable": True, "attempts": 10, "within_mins": 5},
    ("SYNO.Core.Security.Firewall", "get"): {"enable_firewall": True},
    ("SYNO.Core.Web.DSM", "get"): {"enable_https_redirect": True, "enable_hsts": True},
    ("SYNO.Core.FileServ.SMB", "get"): {"enable_samba": True, "smb_min_protocol": "SMB2"},
    ("SYNO.Core.User", "list"): {"users": [{"name": "admin", "expired": "now"}, {"name": "me", "expired": "normal"}]},
    ("SYNO.Core.OTP.EnforcePolicy", "get"): {"otp_enforce_option": "admin"},
    ("SYNO.Core.SecurityScan.Status", "system_get"): {"items": [{"title": "x", "status": "safe"}]},
    ("SYNO.Core.QuickConnect", "get"): {"enabled": False},
    ("SYNO.Docker.Container", "list"): {"containers": [{"name": "seerr", "image": "ghcr.io/seerr-team/seerr:latest", "status": "running"}]},
}


@pytest.fixture
def scanmod(tmp_path, monkeypatch):
    monkeypatch.setenv("NASGATE_DATA_DIR", str(tmp_path))
    from nasgate import config, scan
    importlib.reload(config); importlib.reload(scan)
    return scan


def write_proc(tmp_path, listen_ports_v4=(), listen_ports_v6=()):
    d = tmp_path / "net"; d.mkdir()
    def rows(ports, wide):
        out = ["  sl  local_address rem_address   st"]
        for i, p in enumerate(ports):
            addr = ("0" * (32 if wide else 8)) + f":{p:04X}"
            out.append(f"   {i}: {addr} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 0")
        # a non-wildcard listener must not count
        out.append(f"  99: {'0100007F' if not wide else '0' * 31 + '1'}:22B8 00000000:0000 0A 0 0 0 0 0 0 0 1 0")
        return "\n".join(out) + "\n"
    (d / "tcp").write_text(rows(listen_ports_v4, False))
    (d / "tcp6").write_text(rows(listen_ports_v6, True))
    return str(d)


def test_clean_nas_scores_high(scanmod, tmp_path):
    proc = write_proc(tmp_path, [22, 5001])
    r = scanmod.run_scan(Settings(dsm_user="u", dsm_password="p"), False, proc_dir=proc,
                         client_factory=lambda: FakeDSM(GOOD))
    assert r.errors == []
    assert r.score >= 95
    ids = {f["id"] for f in r.findings}
    assert "listening" in ids and "port_22" not in ids       # ssh is info, not flagged
    assert scanmod.load().score == r.score                     # persisted


def test_weak_nas_flags_everything(scanmod, tmp_path):
    bad = dict(GOOD)
    bad[("SYNO.Core.Terminal", "get")] = {"enable_ssh": True, "enable_telnet": True, "ssh_port": 22}
    bad[("SYNO.Core.Security.AutoBlock", "get")] = {"enable": False}
    bad[("SYNO.Core.FileServ.SMB", "get")] = {"enable_samba": True, "smb_min_protocol": "SMB1"}
    bad[("SYNO.Core.User", "list")] = {"users": [{"name": "admin", "expired": "normal"}, {"name": "guest", "expired": "normal"}]}
    bad[("SYNO.Core.OTP.EnforcePolicy", "get")] = {"otp_enforce_option": "none"}
    bad[("SYNO.Core.QuickConnect", "get")] = {"enabled": True}
    bad[("SYNO.Core.Security.Firewall", "get")] = {"enable_firewall": False}
    del bad[("SYNO.Core.SecurityScan.Status", "system_get")]    # API missing on this model
    proc = write_proc(tmp_path, [23, 21, 9000], [445])
    r = scanmod.run_scan(Settings(dsm_user="u", dsm_password="p"), False, proc_dir=proc,
                         client_factory=lambda: FakeDSM(bad))
    by_id = {f["id"]: f for f in r.findings}
    assert by_id["telnet"]["severity"] == "critical" and by_id["telnet"]["fix"] == "disable_telnet"
    assert by_id["admin_account"]["severity"] == "critical"
    assert by_id["quickconnect"]["fix"] == "close_gate"
    assert by_id["port_23"]["severity"] == "critical" and by_id["port_9000"]["severity"] == "medium"
    assert by_id["advisor_unchecked"]["severity"] == "low"
    assert r.findings[0]["severity"] == "critical"            # sorted worst first
    assert r.score < 20
    assert any("advisor" in e for e in r.errors)


def test_dsm_unreachable_still_scans_ports(scanmod, tmp_path):
    proc = write_proc(tmp_path, [22])
    def boom():
        raise DSMError("no login")
    r = scanmod.run_scan(Settings(dsm_user="u", dsm_password="p"), False, proc_dir=proc, client_factory=boom)
    ids = {f["id"] for f in r.findings}
    assert "dsm_unreachable" in ids and "listening" in ids


def test_fix_merges_current_settings(scanmod):
    dsm = FakeDSM({("SYNO.Core.Terminal", "get"): {"enable_ssh": True, "enable_telnet": True, "ssh_port": 2222},
                   ("SYNO.Core.Terminal", "set"): {}})
    out = scanmod.apply_fix(Settings(dsm_user="u", dsm_password="p"), "disable_telnet", client_factory=lambda: dsm)
    set_call = [c for c in dsm.calls if c[1] == "set"][0]
    assert set_call[2] == {"enable_ssh": "true", "enable_telnet": "false", "ssh_port": 2222}
    assert out["ok"]
    with pytest.raises(KeyError):
        scanmod.apply_fix(Settings(), "format_disk", client_factory=lambda: dsm)


def test_image_repo_normalisation(scanmod):
    assert scanmod._image_repo("lscr.io/linuxserver/foo:1.2") == "linuxserver/foo"
    assert scanmod._image_repo("fallenbagel/jellyseerr:latest") == "fallenbagel/jellyseerr"
    assert scanmod._image_repo("nginx") == "library/nginx"
    assert scanmod._image_repo("ghcr.io/seerr-team/seerr@sha256:abc") == "seerr-team/seerr"
    assert scanmod._image_repo("myregistry:5000/team/app:v1") == "myregistry:5000/team/app"


def test_deprecated_container_flagged(scanmod, tmp_path):
    answers = dict(GOOD)
    answers[("SYNO.Docker.Container", "list")] = {"containers": [
        {"name": "fallenbagel-jellyseerr-1", "image": "fallenbagel/jellyseerr:latest", "status": "running"},
        {"name": "seerr", "image": "ghcr.io/seerr-team/seerr:latest", "status": "running"},
        {"name": "old-wt", "image": "containrrr/watchtower", "status": "exited"},
    ]}
    proc = write_proc(tmp_path, [22])
    r = scanmod.run_scan(Settings(dsm_user="u", dsm_password="p"), False, proc_dir=proc,
                         client_factory=lambda: FakeDSM(answers))
    by_id = {f["id"]: f for f in r.findings}
    assert by_id["image_fallenbagel_jellyseerr"]["severity"] == "medium"
    assert "seerr-team/seerr" in by_id["image_fallenbagel_jellyseerr"]["detail"]
    assert by_id["image_containrrr_watchtower"]["severity"] == "low"      # stopped container
    assert "image_seerr-team_seerr" not in by_id
    assert "seerr" in by_id["containers"]["detail"]


def test_containers_unchecked_without_permission(scanmod, tmp_path):
    answers = dict(GOOD); del answers[("SYNO.Docker.Container", "list")]
    proc = write_proc(tmp_path, [22])
    r = scanmod.run_scan(Settings(dsm_user="u", dsm_password="p"), False, proc_dir=proc,
                         client_factory=lambda: FakeDSM(answers))
    ids = {f["id"] for f in r.findings}
    assert "containers_unchecked" in ids and not any(i.startswith("image_") for i in ids)


def test_otp_is_low_when_lan_only(scanmod, tmp_path):
    answers = dict(GOOD)
    answers[("SYNO.Core.OTP.EnforcePolicy", "get")] = {"otp_enforce_option": "none"}
    proc = write_proc(tmp_path, [22])
    s = Settings(dsm_user="u", dsm_password="p", manage_quickconnect=True)
    r = scanmod.run_scan(s, False, proc_dir=proc, client_factory=lambda: FakeDSM(answers))
    otp = next(f for f in r.findings if f["id"] == "otp")
    assert otp["severity"] == "low" and otp["advice_key"] == "a_otp_lan"
    # gate open => QuickConnect reachable => back to high
    r = scanmod.run_scan(s, True, proc_dir=proc, client_factory=lambda: FakeDSM(answers))
    assert next(f for f in r.findings if f["id"] == "otp")["severity"] == "high"
    # firewall off => high
    answers[("SYNO.Core.Security.Firewall", "get")] = {"enable_firewall": False}
    r = scanmod.run_scan(s, False, proc_dir=proc, client_factory=lambda: FakeDSM(answers))
    assert next(f for f in r.findings if f["id"] == "otp")["severity"] == "high"


def test_firewall_on_demotes_exposed_ports(scanmod, tmp_path):
    # NFS, NetBIOS and Portainer bound to every interface, but the DSM firewall
    # is on: these are reminders (low), not holes, and barely cost points.
    proc = write_proc(tmp_path, [22, 139, 2049, 9000])
    r = scanmod.run_scan(Settings(dsm_user="u", dsm_password="p"), False, proc_dir=proc,
                         client_factory=lambda: FakeDSM(GOOD))
    by_id = {f["id"]: f for f in r.findings}
    for pid in ("port_139", "port_2049", "port_9000"):
        assert by_id[pid]["severity"] == "low" and by_id[pid]["advice_key"] == "a_port_fw"
    assert r.score >= 90
