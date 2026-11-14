"""Coleta de volumes (capacidade/uso) e discos físicos (modelo, tipo, saúde)."""
from __future__ import annotations

import json
import os
import shutil

import psutil

from ..utils import (IS_LINUX, IS_WINDOWS, call_with_timeout, run_command,
                     run_powershell_json, safe_call, to_gb)

_SKIP_FSTYPES = {"squashfs", "tmpfs", "devtmpfs", "overlay", "iso9660", "udf", "ramfs", "proc", "sysfs"}
_SKIP_MOUNT_PREFIXES = ("/snap/", "/var/snap/", "/var/lib/snapd", "/run/", "/sys", "/proc", "/dev")


def _wanted(part) -> bool:
    opts = (part.opts or "").lower()
    if IS_WINDOWS:
        return "cdrom" not in opts and "remote" not in opts and bool(part.fstype)
    mp = part.mountpoint
    if part.fstype in _SKIP_FSTYPES or mp.startswith(_SKIP_MOUNT_PREFIXES):
        return False
    return True


def _volume(part) -> dict:
    u = call_with_timeout(psutil.disk_usage, 8, part.mountpoint)
    return {
        "device": part.device, "mountpoint": part.mountpoint, "fstype": part.fstype,
        "removable": "removable" in (part.opts or "").lower(),
        "total_bytes": u.total, "used_bytes": u.used, "free_bytes": u.free,
        "total_gb": to_gb(u.total), "used_gb": to_gb(u.used), "free_gb": to_gb(u.free),
        "percent_used": round(u.used / u.total * 100, 1) if u.total else 0.0,
    }


def _volumes(warnings: list) -> list:
    parts = [p for p in psutil.disk_partitions(all=False) if _wanted(p)]
    # Remove montagens duplicadas do mesmo dispositivo (btrfs, bind mounts)
    best: dict = {}
    for p in parts:
        cur = best.get(p.device)
        if cur is None or len(p.mountpoint) < len(cur.mountpoint):
            best[p.device] = p
    volumes = []
    for p in best.values():
        v = safe_call(_volume, None, warnings, f"volume {p.mountpoint}", p)
        if v:
            volumes.append(v)
    if not volumes:  # ambientes sem partições listáveis (ex.: contêineres)
        root = os.path.abspath(os.sep) if not IS_WINDOWS else os.environ.get("SystemDrive", "C:") + "\\"
        class _P: device, mountpoint, fstype, opts = "(raiz)", root, "", ""
        v = safe_call(_volume, None, warnings, "volume raiz", _P)
        if v:
            volumes.append(v)
    return volumes


def _physical_linux() -> list:
    if not shutil.which("lsblk"):
        raise RuntimeError("lsblk não encontrado")
    res = run_command(["lsblk", "-J", "-d", "-b", "-o", "NAME,MODEL,SIZE,ROTA,TYPE,TRAN"], timeout=10)
    if not res.ok:
        raise RuntimeError(res.error or res.stderr.strip()[:150])
    disks = []
    for d in json.loads(res.stdout).get("blockdevices", []):
        if d.get("type") != "disk":
            continue
        rota = d.get("rota")
        rotational = rota in (True, 1, "1", "true")
        name = d.get("name", "")
        if name.startswith(("zram", "ram", "loop", "sr")) or int(d.get("size") or 0) < 128 * 1024 ** 2:
            continue
        kind = "NVMe" if name.startswith("nvme") else ("HDD" if rotational else "SSD")
        disks.append({"name": name, "model": (d.get("model") or "").strip() or None,
                      "size_bytes": int(d.get("size") or 0), "size_gb": to_gb(int(d.get("size") or 0)),
                      "media_type": kind, "health": None})
    return disks


def _physical_windows() -> list:
    script = ("Get-PhysicalDisk | Select-Object FriendlyName,"
              "@{n='MediaType';e={[string]$_.MediaType}},"
              "@{n='Health';e={[string]$_.HealthStatus}},"
              "@{n='Size';e={[int64]$_.Size}} | ConvertTo-Json -Compress")
    raw = run_powershell_json(script, timeout=25)
    raw = raw if isinstance(raw, list) else [raw]
    return [{"name": d.get("FriendlyName"), "model": d.get("FriendlyName"),
             "size_bytes": d.get("Size"), "size_gb": to_gb(d.get("Size")),
             "media_type": d.get("MediaType"), "health": d.get("Health")} for d in raw]


def collect(ctx: dict) -> dict:
    warnings: list = []
    data = {"volumes": safe_call(_volumes, [], warnings, "volumes", warnings)}
    phys = None
    if IS_LINUX:
        phys = safe_call(_physical_linux, None, warnings, "discos físicos")
    elif IS_WINDOWS:
        phys = safe_call(_physical_windows, None, warnings, "discos físicos")
    data["physical_disks"] = phys  # None = não foi possível obter
    data["_warnings"] = warnings
    return data
