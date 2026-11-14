"""Coleta de segurança básica: firewall, antivírus (Windows) e atualizações.

Somente leitura e sem privilégios de administrador. O que não puder ser lido
sem privilégios é reportado como indisponível.
"""
from __future__ import annotations

import re
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil

from ..utils import (IS_LINUX, IS_WINDOWS, read_registry_value, registry_key_exists,
                     run_command, run_powershell_json, safe_call)

HKLM = "HKEY_LOCAL_MACHINE"


# ------------------------------------------------------------------ parsers ---
def decode_av_state(state: int) -> dict:
    """Decodifica productState do Windows Security Center."""
    return {"enabled": ((state >> 12) & 0xF) == 1, "signatures_up_to_date": ((state >> 4) & 0xF) == 0}


def parse_apt_upgradable(text: str) -> tuple:
    """Retorna (total, de_segurança) a partir de ``apt list --upgradable``."""
    total = security = 0
    for line in text.splitlines():
        if "upgradable from" in line or "[upgradable" in line:
            total += 1
            if "-security" in line.split()[0]:
                security += 1
    return total, security


def _days_since(ts: float) -> int:
    return int((time.time() - ts) // 86400)


# ------------------------------------------------------------------ Windows ---
def _windows_firewall() -> dict:
    profiles = {}
    for label, reg in (("Domínio", "DomainProfile"), ("Privada", "StandardProfile"), ("Pública", "PublicProfile")):
        policy = read_registry_value(HKLM, rf"SOFTWARE\Policies\Microsoft\WindowsFirewall\{reg}", "EnableFirewall")
        local = read_registry_value(HKLM, rf"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{reg}", "EnableFirewall")
        val = policy if policy is not None else local
        profiles[label] = None if val is None else bool(val)
    source = "registro"
    if all(v is None for v in profiles.values()):
        raw = run_powershell_json(
            "Get-NetFirewallProfile | Select-Object @{n='Name';e={[string]$_.Name}},"
            "@{n='Enabled';e={[string]$_.Enabled}} | ConvertTo-Json -Compress", timeout=20)
        raw = raw if isinstance(raw, list) else [raw]
        names = {"Domain": "Domínio", "Private": "Privada", "Public": "Pública"}
        profiles = {names.get(r["Name"], r["Name"]): str(r["Enabled"]).lower() == "true" for r in raw}
        source = "PowerShell"
    service = safe_call(lambda: psutil.win_service_get("mpssvc").status())
    return {"tool": "Windows Defender Firewall", "profiles": profiles,
            "service_status": service, "source": source}


_AV_SCRIPT = r"""
$r=@{products=$null;defender=$null}
try{$r.products=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
  ForEach-Object{@{name=[string]$_.displayName;state=[int]$_.productState}})}catch{}
try{$m=Get-MpComputerStatus -ErrorAction Stop
 $r.defender=@{realtime=[bool]$m.RealTimeProtectionEnabled;signature_age_days=[int]$m.AntivirusSignatureAge;
 signature_updated=$m.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm')}}catch{}
$r|ConvertTo-Json -Depth 4 -Compress
"""


def _windows_antivirus() -> dict:
    raw = run_powershell_json(_AV_SCRIPT, timeout=30)
    products = raw.get("products")
    if products is not None:
        products = products if isinstance(products, list) else [products]
        products = [{"name": p["name"], **decode_av_state(int(p["state"]))} for p in products]
    return {"products": products, "defender": raw.get("defender")}


def _windows_updates() -> dict:
    out: dict = {"last_hotfix_id": None, "last_hotfix_date": None, "last_hotfix_age_days": None}
    script = ("Get-HotFix | Where-Object {$_.InstalledOn} | Sort-Object InstalledOn -Descending | "
              "Select-Object -First 1 | ForEach-Object { @{id=[string]$_.HotFixID;"
              "date=$_.InstalledOn.ToString('yyyy-MM-dd')} | ConvertTo-Json -Compress }")
    hf = run_powershell_json(script, timeout=60)
    out["last_hotfix_id"], out["last_hotfix_date"] = hf.get("id"), hf.get("date")
    out["last_hotfix_age_days"] = (datetime.now() - datetime.strptime(hf["date"], "%Y-%m-%d")).days
    return out


def _windows_update_extras() -> dict:
    wu = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"
    return {
        "last_check": read_registry_value(HKLM, wu + r"\Auto Update\Results\Detect", "LastSuccessTime"),
        "last_install": read_registry_value(HKLM, wu + r"\Auto Update\Results\Install", "LastSuccessTime"),
        "reboot_required": (registry_key_exists(HKLM, wu + r"\Auto Update\RebootRequired")
                            or registry_key_exists(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")),
    }


# -------------------------------------------------------------------- Linux ---
def _systemctl_active(unit: str) -> Optional[bool]:
    if not shutil.which("systemctl"):
        return None
    res = run_command(["systemctl", "is-active", unit], timeout=8)
    state = res.stdout.strip()
    if state == "active":
        return True
    return False if state in ("inactive", "failed", "unknown", "activating") else None


def _linux_firewall() -> dict:
    ufw_installed = Path("/etc/ufw/ufw.conf").exists() or bool(shutil.which("ufw"))
    if ufw_installed:
        enabled = None
        try:
            m = re.search(r"^ENABLED=(\w+)", Path("/etc/ufw/ufw.conf").read_text(), re.M)
            enabled = bool(m and m.group(1).lower() == "yes")
        except OSError:
            pass
        service = _systemctl_active("ufw")
        if service is True or enabled is True:
            active = True if (service is not False and enabled is not False) else False
        else:
            active = False if (service is False or enabled is False) else None
        return {"tool": "ufw", "active": active, "service_active": service, "config_enabled": enabled}
    if _systemctl_active("firewalld"):
        return {"tool": "firewalld", "active": True, "service_active": True, "config_enabled": None}
    return {"tool": None, "active": None, "service_active": None, "config_enabled": None}


def _linux_updates() -> dict:
    out: dict = {"manager": None, "upgradable": None, "security_upgradable": None,
                 "package_lists_age_days": None, "reboot_required": None}
    out["reboot_required"] = Path("/var/run/reboot-required").exists() or Path("/run/reboot-required").exists()
    if not shutil.which("apt"):
        raise RuntimeError("gerenciador apt não encontrado (distribuição não baseada em Debian/Ubuntu)")
    out["manager"] = "apt"
    for p in ("/var/lib/apt/periodic/update-success-stamp", "/var/cache/apt/pkgcache.bin", "/var/lib/apt/lists"):
        try:
            out["package_lists_age_days"] = _days_since(Path(p).stat().st_mtime)
            break
        except OSError:
            continue
    res = run_command(["apt", "list", "--upgradable"], timeout=45)
    if res.error:
        raise RuntimeError(res.error)
    out["upgradable"], out["security_upgradable"] = parse_apt_upgradable(res.stdout)
    return out


# -------------------------------------------------------------------- coleta --
def collect(ctx: dict) -> dict:
    warnings: list = []
    data: dict = {"firewall": None, "antivirus": None, "updates": None, "update_error": None}
    if IS_WINDOWS:
        data["firewall"] = safe_call(_windows_firewall, None, warnings, "firewall")
        data["antivirus"] = safe_call(_windows_antivirus, None, warnings, "antivírus")
        upd_warn: list = []
        upd = safe_call(_windows_updates, {}, upd_warn, "atualizações")
        extras = safe_call(_windows_update_extras, {}, warnings, "Windows Update")
        data["updates"] = {**upd, **extras}
        data["update_error"] = upd_warn[0] if upd_warn else None
        warnings += upd_warn
    elif IS_LINUX:
        data["firewall"] = safe_call(_linux_firewall, None, warnings, "firewall")
        upd_warn = []
        data["updates"] = safe_call(_linux_updates, None, upd_warn, "atualizações")
        data["update_error"] = upd_warn[0] if upd_warn else None
        if data["updates"] is None:
            data["updates"] = {"reboot_required": Path("/var/run/reboot-required").exists()}
        warnings += upd_warn
    data["_warnings"] = warnings
    return data
