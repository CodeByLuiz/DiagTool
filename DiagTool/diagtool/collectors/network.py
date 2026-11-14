"""Coleta de configuração de rede: adaptadores, IP, gateway, DNS e proxy."""
from __future__ import annotations

import os
import re
import shutil
import socket
import struct
from pathlib import Path
from typing import Optional

import psutil

from ..utils import (IS_LINUX, IS_WINDOWS, is_ipv4, read_registry_value, run_command,
                     run_powershell_json, safe_call)

_VIRTUAL_PREFIXES = ("docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "tun", "tap", "wg",
                     "zt", "tailscale", "lxc", "lxd", "cni", "flannel", "podman", "vnet", "dummy", "ifb")
_VIRTUAL_WORDS = ("virtual", "vmware", "vethernet", "hyper-v", "vbox", "loopback", "bluetooth",
                  "tap-", "wsl", "npcap", "zerotier", "wireguard", "tailscale")
_IPV4_RE = r"\d{1,3}(?:\.\d{1,3}){3}"


# ------------------------------------------------------------------ parsers ---
def parse_proc_net_route(text: str) -> list:
    """Rotas padrão a partir de /proc/net/route."""
    routes = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 8 or f[1] != "00000000":
            continue
        flags = int(f[3], 16)
        if not flags & 0x2:  # RTF_GATEWAY
            continue
        gw = socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
        routes.append({"gateway": gw, "interface": f[0], "interface_ip": None, "metric": int(f[6])})
    return routes


def parse_windows_route_print(text: str) -> list:
    """Rotas padrão (0.0.0.0/0) a partir de ``route print -4`` (independe do idioma)."""
    routes = []
    rx = re.compile(rf"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+({_IPV4_RE})\s+({_IPV4_RE})\s+(\d+)")
    for line in text.splitlines():
        m = rx.match(line)
        if m:
            routes.append({"gateway": m.group(1), "interface": None,
                           "interface_ip": m.group(2), "metric": int(m.group(3))})
    return routes


def parse_resolv_conf(text: str) -> tuple:
    servers, search = [], []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            servers.append(parts[1].split("%")[0])
        elif len(parts) >= 2 and parts[0] in ("search", "domain"):
            search += parts[1:]
    return servers, search


def parse_resolvectl(text: str) -> list:
    """Servidores DNS a partir de ``resolvectl status``."""
    servers, active = [], False
    for line in text.splitlines():
        m = re.match(r"^\s*(?:Current )?DNS Servers?:\s*(.*)$", line)
        if m:
            active = True
            servers += [t.split("%")[0] for t in m.group(1).split()]
        elif active and re.fullmatch(r"\s+[0-9a-fA-F:.%\w]+\s*", line) and re.search(r"[.:]", line):
            servers.append(line.strip().split("%")[0])
        else:
            active = False
    return list(dict.fromkeys(servers))


def parse_ipconfig_dns(text: str) -> list:
    """Servidores DNS IPv4 a partir de ``ipconfig /all`` (qualquer idioma)."""
    servers, active = [], False
    for line in text.splitlines():
        if "DNS" in line.upper() and ":" in line:
            found = re.findall(_IPV4_RE, line)
            servers += found
            active = bool(found)
        elif active and re.fullmatch(rf"\s+{_IPV4_RE}\s*", line):
            servers.append(line.strip())
        else:
            active = False
    return list(dict.fromkeys(servers))


# ---------------------------------------------------------------- coletores ---
def _adapters() -> list:
    addrs, stats = psutil.net_if_addrs(), psutil.net_if_stats()
    out = []
    for name, entries in addrs.items():
        ipv4, ipv6, mac = [], [], None
        for a in entries:
            if a.family == socket.AF_INET:
                ipv4.append({"address": a.address, "netmask": a.netmask})
            elif a.family == socket.AF_INET6:
                ipv6.append(a.address.split("%")[0])
            elif a.family == psutil.AF_LINK:
                mac = a.address
        st = stats.get(name)
        low = name.lower()
        loopback = low == "lo" or "loopback" in low or any(i["address"].startswith("127.") for i in ipv4)
        virtual = low.startswith(_VIRTUAL_PREFIXES) or any(w in low for w in _VIRTUAL_WORDS)
        wifi = (any(w in low for w in ("wi-fi", "wifi", "wireless", "wlan", "sem fio"))
                or (IS_LINUX and (low.startswith("wl") or os.path.isdir(f"/sys/class/net/{name}/wireless"))))
        out.append({
            "name": name, "is_up": bool(st.isup) if st else False,
            "speed_mbps": st.speed if st and st.speed else None, "mtu": st.mtu if st else None,
            "mac": mac, "ipv4": ipv4, "ipv6": ipv6, "is_loopback": loopback,
            "is_virtual": virtual and not loopback,
            "type": "loopback" if loopback else "wifi" if wifi else "virtual" if virtual else "ethernet",
        })
    return out


def _default_routes() -> list:
    if IS_LINUX:
        return parse_proc_net_route(Path("/proc/net/route").read_text())
    if IS_WINDOWS:
        res = run_command(["route", "print", "-4"], timeout=15)
        if res.error:
            raise RuntimeError(res.error)
        return parse_windows_route_print(res.stdout)
    return []


def _linux_dns(warnings: list) -> tuple:
    servers, search = [], []
    conf = Path("/etc/resolv.conf")
    if conf.exists():
        servers, search = parse_resolv_conf(conf.read_text(errors="replace"))
    upstream = Path("/run/systemd/resolve/resolv.conf")
    if upstream.exists():
        up, up_search = parse_resolv_conf(upstream.read_text(errors="replace"))
        if up:
            servers, search = up, search or up_search
    if (not servers or all(s.startswith("127.") for s in servers)) and shutil.which("resolvectl"):
        res = run_command(["resolvectl", "status"], timeout=10)
        found = parse_resolvectl(res.stdout) if res.ok else []
        servers = found or servers
    if (not servers or all(s.startswith("127.") for s in servers)) and shutil.which("nmcli"):
        res = run_command(["nmcli", "-t", "-f", "IP4.DNS", "device", "show"], timeout=10)
        found = re.findall(r"IP4\.DNS\[\d+\]:(\S+)", res.stdout) if res.ok else []
        servers = found or servers
    return list(dict.fromkeys(servers)), search


def _windows_dns(warnings: list) -> tuple:
    try:
        raw = run_powershell_json(
            "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses} | "
            "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress", timeout=20)
        raw = raw if isinstance(raw, list) else [raw]
        servers = []
        for entry in raw:
            addrs = entry.get("ServerAddresses") or []
            servers += addrs if isinstance(addrs, list) else [addrs]
        return list(dict.fromkeys(servers)), []
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"DNS via PowerShell falhou ({exc}); usando ipconfig")
        res = run_command(["ipconfig", "/all"], timeout=20)
        return parse_ipconfig_dns(res.stdout), []


def _proxy() -> dict:
    if IS_WINDOWS:
        key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        enabled = read_registry_value("HKEY_CURRENT_USER", key, "ProxyEnable")
        return {"enabled": bool(enabled), "server": read_registry_value("HKEY_CURRENT_USER", key, "ProxyServer")}
    server = next((os.environ[v] for v in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY")
                   if os.environ.get(v)), None)
    return {"enabled": bool(server), "server": server}


def collect(ctx: dict) -> dict:
    warnings: list = []
    adapters = safe_call(_adapters, [], warnings, "adaptadores")
    routes = safe_call(_default_routes, [], warnings, "rota padrão")
    by_ip = {i["address"]: a["name"] for a in adapters for i in a["ipv4"]}
    up_names = {a["name"] for a in adapters if a["is_up"]}
    for r in routes:
        if r["interface"] is None:
            r["interface"] = by_ip.get(r["interface_ip"])
        if r["interface_ip"] is None:
            ad = next((a for a in adapters if a["name"] == r["interface"]), None)
            r["interface_ip"] = ad["ipv4"][0]["address"] if ad and ad["ipv4"] else None
    usable = sorted((r for r in routes if r["interface"] in up_names), key=lambda r: r["metric"])
    primary = usable[0] if usable else None

    if IS_LINUX:
        dns, search = safe_call(_linux_dns, ([], []), warnings, "DNS", warnings)
    elif IS_WINDOWS:
        dns, search = safe_call(_windows_dns, ([], []), warnings, "DNS", warnings)
    else:
        dns, search = [], []

    if primary is None:  # sem rota padrão: primeiro adaptador físico ativo com IPv4
        cand = next((a for a in adapters if a["is_up"] and a["ipv4"] and not a["is_loopback"]
                     and not a["is_virtual"]), None)
        primary_ip = cand["ipv4"][0]["address"] if cand else None
        primary_if = cand["name"] if cand else None
    else:
        primary_ip, primary_if = primary["interface_ip"], primary["interface"]

    return {
        "adapters": adapters,
        "default_routes": routes,
        "default_gateway": primary["gateway"] if primary else None,
        "primary_interface": primary_if,
        "primary_ipv4": primary_ip,
        "dns_servers": dns,
        "dns_search_domains": search,
        "proxy": safe_call(_proxy, {"enabled": False, "server": None}, warnings, "proxy"),
        "_warnings": warnings,
    }
