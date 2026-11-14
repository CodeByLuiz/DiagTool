"""Testes ativos de conectividade: ping, resolução DNS, consulta direta aos
servidores DNS configurados e conexão TCP/HTTPS.

Nenhum dado do computador é enviado: são apenas pacotes de teste padrão.
"""
from __future__ import annotations

import random
import re
import socket
import statistics
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from .. import config
from ..utils import IS_WINDOWS, call_with_timeout, is_ipv4, run_command


# ------------------------------------------------------------------- ping ----
def parse_ping_output(text: str, sent: int) -> dict:
    """Interpreta a saída do ping (Windows/Linux, qualquer idioma)."""
    times, received = [], 0
    for line in text.splitlines():
        if "ttl=" not in line.lower():
            continue
        received += 1
        m = re.search(r"([=<])\s*(\d+(?:[.,]\d+)?)\s*ms", line)
        if m:
            v = float(m.group(2).replace(",", "."))
            times.append(v / 2 if m.group(1) == "<" else v)
    received = min(received, sent)
    return {
        "sent": sent, "received": received,
        "loss_percent": round((sent - received) / sent * 100, 1) if sent else None,
        "min_ms": round(min(times), 1) if times else None,
        "avg_ms": round(statistics.mean(times), 1) if times else None,
        "max_ms": round(max(times), 1) if times else None,
    }


def tcp_probe(host: str, port: int, count: int = 3, timeout: float = 3.0) -> dict:
    """Mede latência de conexão TCP (alternativa quando o ICMP não está disponível)."""
    times = []
    for _ in range(count):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                times.append((time.perf_counter() - t0) * 1000)
        except OSError:
            pass
    return {
        "sent": count, "received": len(times),
        "loss_percent": round((count - len(times)) / count * 100, 1),
        "min_ms": round(min(times), 1) if times else None,
        "avg_ms": round(statistics.mean(times), 1) if times else None,
        "max_ms": round(max(times), 1) if times else None,
    }


def ping_host(target: dict) -> dict:
    host, count, tmo = target["host"], config.PING_COUNT, config.PING_TIMEOUT_S
    base = {"key": target["key"], "label": target["label"], "host": host}
    if IS_WINDOWS:
        args = ["ping", "-n", str(count), "-w", str(tmo * 1000), host]
    else:
        args = ["ping", "-n", "-c", str(count), "-W", str(tmo), host]
    res = run_command(args, timeout=count * (tmo + 1) + 5)
    blob = res.stdout + res.stderr
    unavailable = (res.error and not res.stdout) or (
        re.search(r"not permitted|permission denied|socktype|cap_net_raw", blob, re.I)
        and "ttl=" not in blob.lower())
    if unavailable:
        if target.get("tcp_port"):
            out = tcp_probe(host, target["tcp_port"])
            return {**base, "available": True, "method": f"tcp:{target['tcp_port']}",
                    "note": "ping indisponível; usado teste TCP", **out}
        return {**base, "available": False, "method": "icmp",
                "error": res.error or "ping não permitido neste sistema"}
    return {**base, "available": True, "method": "icmp", **parse_ping_output(res.stdout, count)}


# -------------------------------------------------------------------- DNS ----
def resolve_hostname(name: str, timeout: float = 5.0) -> dict:
    t0 = time.perf_counter()
    try:
        infos = call_with_timeout(socket.getaddrinfo, timeout, name, None, socket.AF_INET, socket.SOCK_STREAM)
        return {"hostname": name, "ok": True, "addresses": sorted({i[4][0] for i in infos})[:5],
                "time_ms": round((time.perf_counter() - t0) * 1000, 1), "error": None}
    except Exception as exc:  # noqa: BLE001
        return {"hostname": name, "ok": False, "addresses": [],
                "time_ms": round((time.perf_counter() - t0) * 1000, 1), "error": str(exc) or type(exc).__name__}


def build_dns_query(name: str, qid: int) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)  # tipo A, classe IN


def parse_dns_response(data: bytes, qid: int) -> dict:
    if len(data) < 12:
        raise ValueError("resposta DNS curta demais")
    rid, flags, _qd, an = struct.unpack(">HHHH", data[:8])
    return {"id_match": rid == qid, "rcode": flags & 0xF, "answers": an}


def query_dns_server(server: str, name: str, timeout: float = 3.0) -> dict:
    """Consulta direta (UDP/53) a um servidor DNS configurado."""
    qid = random.randint(0, 65535)
    t0 = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(build_dns_query(name, qid), (server, 53))
            data, _ = s.recvfrom(1024)
        r = parse_dns_response(data, qid)
        ok = r["id_match"] and r["rcode"] == 0 and r["answers"] > 0
        return {"server": server, "ok": ok, "rcode": r["rcode"], "answers": r["answers"],
                "time_ms": round((time.perf_counter() - t0) * 1000, 1),
                "error": None if ok else f"resposta DNS inválida (rcode={r['rcode']})"}
    except Exception as exc:  # noqa: BLE001
        return {"server": server, "ok": False, "rcode": None, "answers": 0, "time_ms": None,
                "error": "sem resposta (timeout)" if isinstance(exc, socket.timeout) else str(exc)}


def https_check(host: str, port: int = 443) -> dict:
    try:
        ip = call_with_timeout(socket.gethostbyname, 5, host)
    except Exception as exc:  # noqa: BLE001
        return {"host": host, "port": port, "ok": False, "time_ms": None, "error": f"DNS: {exc}"}
    r = tcp_probe(ip, port, count=2, timeout=4.0)
    return {"host": host, "port": port, "ok": r["received"] > 0, "time_ms": r["avg_ms"],
            "error": None if r["received"] else "conexão recusada ou bloqueada"}


# ----------------------------------------------------------------- coleta ----
def collect(ctx: dict) -> dict:
    warnings: list = []
    net = ctx.get("network") or {}
    gateway = net.get("default_gateway")
    dns_servers = [s for s in net.get("dns_servers", []) if is_ipv4(s)][:4]

    ping_targets = []
    if gateway:
        ping_targets.append({"key": "gateway", "label": f"Gateway ({gateway})", "host": gateway, "tcp_port": None})
    for i, (host, label, port) in enumerate(config.PING_INTERNET_TARGETS):
        ping_targets.append({"key": f"internet{i + 1}", "label": label, "host": host, "tcp_port": port})

    with ThreadPoolExecutor(max_workers=16) as pool:
        f_ping = [pool.submit(ping_host, t) for t in ping_targets]
        f_dns = [pool.submit(resolve_hostname, h) for h in config.DNS_TEST_HOSTNAMES]
        f_srv = [pool.submit(query_dns_server, s, config.DNS_SERVER_TEST_NAME) for s in dns_servers]
        f_https = [pool.submit(https_check, h) for h in config.HTTPS_TEST_HOSTS]
        pings = [f.result() for f in f_ping]
        dns_res = [f.result() for f in f_dns]
        dns_srv = [f.result() for f in f_srv]
        https = [f.result() for f in f_https]

    return {
        "gateway_tested": gateway,
        "pings": pings,
        "dns_resolution": dns_res,
        "dns_servers_test": dns_srv,
        "https_tests": https,
        "_warnings": warnings,
    }
