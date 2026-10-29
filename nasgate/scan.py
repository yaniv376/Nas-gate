"""Security scan: looks at the NAS and reports weaknesses with advice.

The scan only reports. Every one-click fix is a separate, explicit call
(`apply_fix`) that the user triggers after reading the finding, and only
the fixes that cannot lock anyone out are offered.

Two sources:
  * the DSM Web API (needs the gate's DSM user), one small call per check;
  * the host network namespace (the container runs with network_mode host),
    read from /proc/net/tcp*, to list services listening on every interface.

Every check is wrapped so one failing API never aborts the scan; a check
that cannot run becomes a low "could not check" finding.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import config
from .dsm import DSMClient, DSMError

log = logging.getLogger("nasgate.scan")

SCAN_FILE = config.DATA_DIR / "scan.json"

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}

# Ports that are worth a word when they listen on every interface.
KNOWN_PORTS = {
    21: ("ftp", "high"), 22: ("ssh", "info"), 23: ("telnet", "critical"),
    80: ("http", "info"), 139: ("netbios", "medium"), 161: ("snmp", "medium"),
    443: ("https", "info"), 445: ("smb", "info"), 548: ("afp", "low"),
    873: ("rsync", "medium"), 2049: ("nfs", "medium"), 3306: ("mysql", "high"),
    3389: ("rdp", "high"), 5000: ("dsm-http", "low"), 5001: ("dsm-https", "info"),
    5432: ("postgres", "high"), 6379: ("redis", "high"), 8080: ("http-alt", "low"),
    8787: ("nas-gate", "info"), 9000: ("portainer", "medium"), 27017: ("mongodb", "high"),
}


@dataclass
class Finding:
    id: str
    severity: str            # critical / high / medium / low / info / ok
    title_key: str           # i18n key for the title
    detail: str = ""         # raw facts (ports, versions...), not translated
    advice_key: str = ""     # i18n key for the advice
    fix: str | None = None   # id of a one-click fix, if one is safe to offer
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    started_at: float
    finished_at: float
    score: int
    findings: list[dict]
    counts: dict[str, int]
    errors: list[str]

    def summary(self) -> dict:
        return {"finished_at": self.finished_at, "score": self.score, "counts": self.counts,
                "findings": len(self.findings)}


# ----------------------------------------------------------------------------
# DSM checks. Each takes the client and returns a list of findings.
# ----------------------------------------------------------------------------

def _bool(v: Any) -> bool:
    if isinstance(v, str):
        return v.lower() == "true"
    return bool(v)


def check_dsm_update(dsm: DSMClient) -> list[Finding]:
    data = dsm.request("SYNO.Core.Upgrade.Server", "check")
    upd = data.get("update") or data
    available = _bool(upd.get("available", False))
    version = upd.get("version") or upd.get("version_string") or ""
    if available:
        return [Finding("dsm_update", "high", "f_dsm_update", version, "a_dsm_update")]
    return [Finding("dsm_update", "ok", "f_dsm_uptodate")]


def check_terminal(dsm: DSMClient) -> list[Finding]:
    t = dsm.request("SYNO.Core.Terminal", "get")
    out = []
    if _bool(t.get("enable_telnet")):
        out.append(Finding("telnet", "critical", "f_telnet", "", "a_telnet", fix="disable_telnet"))
    else:
        out.append(Finding("telnet", "ok", "f_telnet_off"))
    port = int(t.get("ssh_port", 22) or 22)
    if _bool(t.get("enable_ssh")):
        sev = "low" if port == 22 else "info"
        out.append(Finding("ssh_port", sev, "f_ssh_on", str(port), "a_ssh_port"))
    return out


def check_autoblock(dsm: DSMClient) -> list[Finding]:
    a = dsm.request("SYNO.Core.Security.AutoBlock", "get")
    if _bool(a.get("enable")):
        return [Finding("autoblock", "ok", "f_autoblock_on",
                        f"{a.get('attempts')} / {a.get('within_mins')} min")]
    return [Finding("autoblock", "high", "f_autoblock_off", "", "a_autoblock", fix="enable_autoblock")]


def check_firewall(dsm: DSMClient) -> list[Finding]:
    f = dsm.request("SYNO.Core.Security.Firewall", "get")
    if _bool(f.get("enable_firewall")):
        return [Finding("firewall", "ok", "f_firewall_on")]
    return [Finding("firewall", "medium", "f_firewall_off", "", "a_firewall")]


def check_https(dsm: DSMClient) -> list[Finding]:
    w = dsm.request("SYNO.Core.Web.DSM", "get")
    out = []
    if not _bool(w.get("enable_https_redirect")):
        out.append(Finding("https_redirect", "medium", "f_https_redirect_off", "", "a_https_redirect",
                           fix="enable_https_redirect"))
    else:
        out.append(Finding("https_redirect", "ok", "f_https_redirect_on"))
    if not _bool(w.get("enable_hsts")):
        out.append(Finding("hsts", "low", "f_hsts_off", "", "a_hsts", fix="enable_hsts"))
    return out


def check_smb(dsm: DSMClient) -> list[Finding]:
    s = dsm.request("SYNO.Core.FileServ.SMB", "get")
    if not _bool(s.get("enable_samba", True)):
        return [Finding("smb1", "ok", "f_smb_off")]
    raw = s.get("smb_min_protocol", "")
    minp = str(raw).upper()
    label = {"1": "SMB1", "2": "SMB2", "3": "SMB3"}.get(minp, minp)
    if minp in ("SMB1", "NT1", "1"):
        return [Finding("smb1", "high", "f_smb1", label, "a_smb1", fix="smb_min_smb2")]
    return [Finding("smb1", "ok", "f_smb_min", label)]


def check_admin_account(dsm: DSMClient) -> list[Finding]:
    u = dsm.request("SYNO.Core.User", "list", offset=0, limit=-1,
                    additional=json.dumps(["expired"]))
    users = u.get("users") or []
    out = []
    for user in users:
        if user.get("name") == "admin":
            disabled = str(user.get("expired", "")).lower() == "now"
            if disabled:
                out.append(Finding("admin_account", "ok", "f_admin_disabled"))
            else:
                out.append(Finding("admin_account", "critical", "f_admin_enabled", "", "a_admin"))
    if "guest" in {x.get("name") for x in users}:
        g = next(x for x in users if x.get("name") == "guest")
        if str(g.get("expired", "")).lower() != "now":
            out.append(Finding("guest_account", "high", "f_guest_enabled", "", "a_guest"))
    out.append(Finding("user_count", "info", "f_user_count", str(len(users))))
    return out


def check_otp(dsm: DSMClient) -> list[Finding]:
    o = dsm.request("SYNO.Core.OTP.EnforcePolicy", "get")
    opt = str(o.get("otp_enforce_option", "none")).lower()
    if opt == "none":
        return [Finding("otp", "high", "f_otp_none", "", "a_otp")]
    return [Finding("otp", "ok", "f_otp_on", opt)]


def check_quickconnect(dsm: DSMClient, gate_open: bool) -> list[Finding]:
    q = dsm.quickconnect_get()
    enabled = _bool(q.get("enabled", False))
    if enabled and not gate_open:
        return [Finding("quickconnect", "high", "f_qc_on_closed", "", "a_qc", fix="close_gate")]
    return [Finding("quickconnect", "ok", "f_qc_ok", "on" if enabled else "off")]


def check_security_advisor(dsm: DSMClient) -> list[Finding]:
    """Pull DSM's own Security Advisor results when the API exposes them."""
    st = dsm.request("SYNO.Core.SecurityScan.Status", "system_get")
    items = st.get("items") or st.get("list") or st.get("results") or []
    if isinstance(items, dict):
        items = [v if isinstance(v, dict) else {"title": k, "status": v} for k, v in items.items()]
    items = [i if isinstance(i, dict) else {"title": str(i)} for i in items]
    bad = [i for i in items if str(i.get("status", i.get("result", i.get("severity", "")))).lower()
           in ("fail", "failed", "warning", "danger", "critical", "warn")]
    last = st.get("lastScanTime") or st.get("last_scan_time")
    if not items:
        return [Finding("advisor", "low", "f_advisor_never", "", "a_advisor")]
    if bad:
        names = ", ".join(str(i.get("title") or i.get("name") or i.get("id")) for i in bad[:8])
        return [Finding("advisor", "medium", "f_advisor_issues", names, "a_advisor")]
    return [Finding("advisor", "ok", "f_advisor_clean", str(last or ""))]


DSM_CHECKS: list[tuple[str, Callable[..., list[Finding]]]] = [
    ("dsm_update", check_dsm_update),
    ("terminal", check_terminal),
    ("autoblock", check_autoblock),
    ("firewall", check_firewall),
    ("https", check_https),
    ("smb", check_smb),
    ("accounts", check_admin_account),
    ("otp", check_otp),
    ("advisor", check_security_advisor),
]


# ----------------------------------------------------------------------------
# Local checks (host network namespace)
# ----------------------------------------------------------------------------

def listening_ports(proc_dir: str = "/proc/net") -> list[tuple[int, str]]:
    """Ports in LISTEN state bound to every interface, as (port, 'v4'|'v6')."""
    out: set[tuple[int, str]] = set()
    for name, fam in (("tcp", "v4"), ("tcp6", "v6")):
        path = Path(proc_dir) / name
        if not path.exists():
            continue
        for line in path.read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":   # 0A = LISTEN
                continue
            addr, port_hex = parts[1].rsplit(":", 1)
            wildcard = addr.strip("0") == "" or addr == "0000000000000000FFFF00000000000000"
            if wildcard:
                out.add((int(port_hex, 16), fam))
    return sorted(out)


def check_listening(ports: list[tuple[int, str]]) -> list[Finding]:
    seen: dict[int, str] = {}
    for port, fam in ports:
        seen.setdefault(port, fam)
    out = []
    flagged = []
    for port in sorted(seen):
        name, sev = KNOWN_PORTS.get(port, (f"port {port}", "info"))
        if sev in ("critical", "high", "medium"):
            flagged.append(Finding(f"port_{port}", sev, "f_port_exposed", f"{port} ({name})", "a_port"))
    out.append(Finding("listening", "info", "f_listening",
                       ", ".join(str(p) for p in sorted(seen)) or "none"))
    return out + flagged


# ----------------------------------------------------------------------------
# Runner
# ----------------------------------------------------------------------------

def run_scan(settings: config.Settings, gate_open: bool, proc_dir: str = "/proc/net",
             client_factory: Callable[[], DSMClient] | None = None) -> ScanResult:
    started = time.time()
    findings: list[Finding] = []
    errors: list[str] = []

    def factory() -> DSMClient:
        if not settings.dsm_user or not settings.dsm_password:
            raise DSMError("DSM user and password are not set")
        return DSMClient(settings.dsm_url, settings.dsm_user, settings.dsm_password,
                         settings.dsm_verify_tls)

    make = client_factory or factory
    try:
        with make() as dsm:
            for name, fn in DSM_CHECKS:
                try:
                    findings.extend(fn(dsm))
                except Exception as e:  # noqa: BLE001
                    errors.append(f"{name}: {e}")
                    findings.append(Finding(f"{name}_unchecked", "low", "f_unchecked", f"{name}: {e}"))
            try:
                findings.extend(check_quickconnect(dsm, gate_open))
            except Exception as e:  # noqa: BLE001
                errors.append(f"quickconnect: {e}")
    except Exception as e:  # noqa: BLE001
        errors.append(f"dsm: {e}")
        findings.append(Finding("dsm_unreachable", "high", "f_dsm_unreachable", str(e), "a_dsm_unreachable"))

    try:
        findings.extend(check_listening(listening_ports(proc_dir)))
    except Exception as e:  # noqa: BLE001
        errors.append(f"listening: {e}")

    penalty = 0
    for f in findings:
        w = SEVERITY_WEIGHT.get(f.severity, 0)
        if f.id.startswith("port_"):
            w = min(w, 4)            # a LAN-only service is a hint, not a hole
        penalty += w
    score = max(0, 100 - penalty)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "ok": 5}
    findings.sort(key=lambda f: order.get(f.severity, 9))
    result = ScanResult(started, time.time(), score, [asdict(f) for f in findings], counts, errors)
    save(result)
    return result


def save(result: ScanResult) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = SCAN_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(result), indent=1, ensure_ascii=False))
    os.chmod(tmp, 0o600)
    tmp.replace(SCAN_FILE)


def load() -> ScanResult | None:
    if not SCAN_FILE.exists():
        return None
    try:
        d = json.loads(SCAN_FILE.read_text())
        return ScanResult(**d)
    except (ValueError, TypeError):
        return None


# ----------------------------------------------------------------------------
# One-click fixes: safe, reversible DSM settings only.
# ----------------------------------------------------------------------------

FIXES: dict[str, dict[str, Any]] = {
    "disable_telnet": {"api": "SYNO.Core.Terminal", "method": "set", "params": {"enable_telnet": "false"},
                       "merge_from": ("SYNO.Core.Terminal", "get")},
    "enable_autoblock": {"api": "SYNO.Core.Security.AutoBlock", "method": "set",
                         "params": {"enable": "true", "attempts": 10, "within_mins": 5,
                                    "enable_expire": "false"},
                         "merge_from": ("SYNO.Core.Security.AutoBlock", "get")},
    "enable_https_redirect": {"api": "SYNO.Core.Web.DSM", "method": "set",
                              "params": {"enable_https_redirect": "true"},
                              "merge_from": ("SYNO.Core.Web.DSM", "get")},
    "enable_hsts": {"api": "SYNO.Core.Web.DSM", "method": "set", "params": {"enable_hsts": "true"},
                    "merge_from": ("SYNO.Core.Web.DSM", "get")},
    "smb_min_smb2": {"api": "SYNO.Core.FileServ.SMB", "method": "set",
                     "params": {"smb_min_protocol": "SMB2"},
                     "merge_from": ("SYNO.Core.FileServ.SMB", "get")},
}


def apply_fix(settings: config.Settings, fix_id: str,
              client_factory: Callable[[], DSMClient] | None = None) -> dict:
    """Apply one fix. DSM 'set' methods usually need the whole settings block,
    so the current values are read first and only the fix's keys change."""
    spec = FIXES.get(fix_id)
    if not spec:
        raise KeyError(fix_id)

    def factory() -> DSMClient:
        return DSMClient(settings.dsm_url, settings.dsm_user, settings.dsm_password,
                         settings.dsm_verify_tls)

    with (client_factory or factory)() as dsm:
        params: dict[str, Any] = {}
        api_get, m_get = spec["merge_from"]
        current = dsm.request(api_get, m_get)
        for k, v in current.items():
            if isinstance(v, bool):
                params[k] = "true" if v else "false"
            elif isinstance(v, (int, float, str)):
                params[k] = v
            else:
                params[k] = json.dumps(v)
        fix_params = dict(spec["params"])
        if fix_id == "smb_min_smb2" and str(current.get("smb_min_protocol", "")).isdigit():
            fix_params["smb_min_protocol"] = "2"
        params.update(fix_params)
        dsm.request(spec["api"], spec["method"], **params)
        after = dsm.request(api_get, m_get)
    return {"ok": True, "fix": fix_id, "after": {k: after.get(k) for k in spec["params"]}}


def report_text(result: ScanResult, lang: str = "en") -> str:
    """Plain-text report for copying or downloading."""
    from datetime import datetime
    from .i18n import t
    lines = [f"NAS Gate · {t(lang, 'scan')}",
             f"{t(lang, 'last_scan')}: {datetime.fromtimestamp(result.finished_at).strftime('%Y-%m-%d %H:%M')}",
             f"{t(lang, 'score')}: {result.score}/100", ""]
    for f in result.findings:
        sev = t(lang, f"sev_{f['severity']}")
        title = t(lang, f["title_key"])
        detail = f" ({f['detail']})" if f.get("detail") else ""
        lines.append(f"[{sev}] {title}{detail}")
        if f.get("advice_key"):
            lines.append(f"    {t(lang, f['advice_key'])}")
    if result.errors:
        lines += ["", "errors:"] + [f"  {e}" for e in result.errors]
    return "\n".join(lines) + "\n"
