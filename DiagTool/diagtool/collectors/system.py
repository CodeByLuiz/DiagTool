"""Coleta de informações do sistema: SO, CPU, hardware e tempo ligado."""
from __future__ import annotations

import getpass
import platform
import re
import socket
import time
from datetime import datetime
from pathlib import Path

import psutil

from ..utils import (IS_LINUX, IS_WINDOWS, read_registry_value, run_powershell,
                     safe_call)

HKLM = "HKEY_LOCAL_MACHINE"


def parse_os_release(text: str) -> dict:
    """Interpreta o conteúdo de /etc/os-release."""
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace").strip()


def _os_info() -> dict:
    if IS_WINDOWS:
        key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        product = read_registry_value(HKLM, key, "ProductName") or platform.system()
        build = int(read_registry_value(HKLM, key, "CurrentBuildNumber") or 0)
        ubr = read_registry_value(HKLM, key, "UBR")
        display = (read_registry_value(HKLM, key, "DisplayVersion")
                   or read_registry_value(HKLM, key, "ReleaseId") or "")
        if build >= 22000:  # o registro do Windows 11 ainda diz "Windows 10"
            product = product.replace("Windows 10", "Windows 11")
        return {"os_name": product, "os_version": display,
                "os_build": f"{build}.{ubr}" if ubr is not None else str(build),
                "os_build_number": build, "os_id": "windows",
                "os_version_id": str(build)}
    if IS_LINUX:
        info = parse_os_release(_read("/etc/os-release"))
        return {"os_name": info.get("PRETTY_NAME") or info.get("NAME") or "Linux",
                "os_version": info.get("VERSION") or info.get("VERSION_ID", ""),
                "os_build": platform.release(), "os_id": info.get("ID", "linux"),
                "os_version_id": info.get("VERSION_ID", ""),
                "os_codename": info.get("VERSION_CODENAME", "")}
    return {"os_name": platform.platform(), "os_version": platform.version(),
            "os_build": platform.release(), "os_id": platform.system().lower(),
            "os_version_id": platform.release()}


def _cpu_model() -> str:
    model = None
    if IS_WINDOWS:
        model = read_registry_value(
            HKLM, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString")
    elif IS_LINUX:
        fallback = None
        for line in _read("/proc/cpuinfo").splitlines():
            low = line.lower()
            if low.startswith("model name"):
                model = line.split(":", 1)[1]
                break
            if low.startswith(("hardware", "model")) and fallback is None:
                val = line.split(":", 1)[1].strip()
                if val and not val.isdigit():
                    fallback = val
        model = model or fallback
    return re.sub(r"\s+", " ", (model or platform.processor() or "Desconhecido")).strip()


def _cpu_info() -> dict:
    freq = safe_call(psutil.cpu_freq)
    return {
        "model": _cpu_model(),
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "frequency_mhz": round(freq.current) if freq and freq.current else None,
        "max_frequency_mhz": round(freq.max) if freq and freq.max else None,
        "usage_percent": psutil.cpu_percent(interval=1.0),
    }


def _hardware_info(warnings: list) -> dict:
    hw = {"manufacturer": None, "model": None, "bios_version": None, "serial_number": None}
    if IS_WINDOWS:
        key = r"HARDWARE\DESCRIPTION\System\BIOS"
        hw["manufacturer"] = read_registry_value(HKLM, key, "SystemManufacturer")
        hw["model"] = read_registry_value(HKLM, key, "SystemProductName")
        bios = read_registry_value(HKLM, key, "BIOSVersion")
        hw["bios_version"] = ", ".join(bios) if isinstance(bios, list) else bios
        res = run_powershell("(Get-CimInstance Win32_BIOS).SerialNumber", timeout=20)
        if res.ok and res.stdout.strip():
            hw["serial_number"] = res.stdout.strip()
    elif IS_LINUX:
        base = "/sys/class/dmi/id/"
        for field, fname in (("manufacturer", "sys_vendor"), ("model", "product_name"),
                             ("bios_version", "bios_version"), ("serial_number", "product_serial")):
            hw[field] = safe_call(_read, None, None, "", base + fname)  # serial exige root
    return hw


def collect(ctx: dict) -> dict:
    warnings: list = []
    data = {
        "hostname": safe_call(socket.gethostname, "desconhecido", warnings, "nome do computador"),
        "username": safe_call(getpass.getuser, "desconhecido", warnings, "usuário"),
        "os_family": "Windows" if IS_WINDOWS else "Linux" if IS_LINUX else platform.system(),
    }
    data.update(safe_call(_os_info, {"os_name": platform.platform()}, warnings, "sistema operacional"))
    machine = platform.machine()
    data["architecture"] = machine
    data["architecture_bits"] = 64 if machine.lower() in (
        "amd64", "x86_64", "arm64", "aarch64") else (32 if machine else None)
    data["cpu"] = safe_call(_cpu_info, {}, warnings, "processador")
    data["hardware"] = safe_call(_hardware_info, {}, warnings, "hardware", warnings)
    boot = safe_call(psutil.boot_time, None, warnings, "tempo de boot")
    if boot:
        data["boot_time"] = datetime.fromtimestamp(boot).isoformat(timespec="seconds")
        data["uptime_seconds"] = int(time.time() - boot)
    if hasattr(__import__("os"), "getloadavg"):
        data["load_average"] = safe_call(lambda: [round(x, 2) for x in __import__("os").getloadavg()])
    data["_warnings"] = warnings
    return data
