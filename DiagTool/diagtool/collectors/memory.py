"""Coleta de memória RAM, swap/arquivo de paginação e maiores consumidores."""
from __future__ import annotations

from collections import defaultdict

import psutil

from ..utils import safe_call, to_gb


def _top_processes(limit: int = 5) -> list:
    by_name: dict = defaultdict(lambda: [0, 0])
    for proc in psutil.process_iter(["name", "memory_info"]):
        try:
            info = proc.info
            mem = info.get("memory_info")
            if mem is None:
                continue
            entry = by_name[info.get("name") or "?"]
            entry[0] += mem.rss
            entry[1] += 1
        except (psutil.Error, OSError):
            continue
    ranked = sorted(by_name.items(), key=lambda kv: kv[1][0], reverse=True)[:limit]
    return [{"name": n, "memory_bytes": v[0], "memory_gb": to_gb(v[0]), "instances": v[1]}
            for n, v in ranked]


def collect(ctx: dict) -> dict:
    warnings: list = []
    vm = psutil.virtual_memory()
    used = vm.total - vm.available
    data = {
        "total_bytes": vm.total,
        "available_bytes": vm.available,
        "used_bytes": used,
        "total_gb": to_gb(vm.total),
        "available_gb": to_gb(vm.available),
        "used_gb": to_gb(used),
        "percent_used": round(used / vm.total * 100, 1) if vm.total else None,
    }
    sw = safe_call(psutil.swap_memory, None, warnings, "swap")
    data["swap"] = ({"total_bytes": sw.total, "used_bytes": sw.used,
                     "total_gb": to_gb(sw.total), "used_gb": to_gb(sw.used),
                     "percent_used": round(sw.percent, 1)} if sw else None)
    data["top_processes"] = safe_call(_top_processes, [], warnings, "processos")
    data["_warnings"] = warnings
    return data
