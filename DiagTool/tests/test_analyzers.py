"""Testes das regras de classificação, incluindo cenários Windows simulados."""
from diagtool.analyzers import connectivity, memory, network, security, storage, system
from diagtool.models import Status, worst


def st(findings, item_part):
    return next(f.status for f in findings if item_part in f.item)


def test_worst_rollup():
    assert worst([Status.NORMAL, Status.INDISPONIVEL]) is Status.NORMAL
    assert worst([Status.INDISPONIVEL]) is Status.INDISPONIVEL
    assert worst([Status.NORMAL, Status.PROBLEMA, Status.ALERTA]) is Status.PROBLEMA
    assert worst([]) is Status.INDISPONIVEL


def test_memory_levels_and_recommendations():
    base = {"total_gb": 16.0, "available_gb": 1.0, "top_processes": [{"name": "chrome"}], "swap": None}
    assert st(memory.analyze({**base, "percent_used": 50.0}, "Windows"), "RAM") is Status.NORMAL
    a = memory.analyze({**base, "percent_used": 85.0}, "Windows")
    assert st(a, "RAM") is Status.ALERTA
    p = memory.analyze({**base, "percent_used": 95.0}, "Linux")
    assert st(p, "RAM") is Status.PROBLEMA and any("chrome" in r for r in p[0].recommendations)
    assert memory.analyze({"percent_used": None}, "Linux")[0].status is Status.INDISPONIVEL


def test_storage_thresholds_and_health():
    vols = [{"mountpoint": "C:\\", "percent_used": 96.0, "free_gb": 5, "total_gb": 200},
            {"mountpoint": "D:\\", "percent_used": 88.0, "free_gb": 50, "total_gb": 400},
            {"mountpoint": "E:\\", "percent_used": 10.0, "free_gb": 90, "total_gb": 100}]
    phys = [{"name": "d0", "model": "SSD X", "health": "Unhealthy", "media_type": "SSD", "size_gb": 100}]
    f = storage.analyze({"volumes": vols, "physical_disks": phys}, "Windows")
    assert st(f, "C:") is Status.PROBLEMA and st(f, "D:") is Status.ALERTA and st(f, "E:") is Status.NORMAL
    assert st(f, "SSD X") is Status.PROBLEMA
    assert storage.analyze({"volumes": vols[:1], "physical_disks": None}, "Linux")[-1].status is Status.INDISPONIVEL


def test_system_windows10_is_flagged_and_uptime():
    d = {"os_name": "Windows 10 Pro", "os_build_number": 19045, "uptime_seconds": 70 * 86400,
         "cpu": {"usage_percent": 10}}
    f = system.analyze(d, "Windows")
    assert st(f, "Suporte") is Status.ALERTA and st(f, "Tempo ligado") is Status.PROBLEMA
    ok = system.analyze({"os_name": "Windows 11 Pro", "os_build_number": 26100, "uptime_seconds": 3600,
                         "cpu": {"usage_percent": 99}}, "Windows")
    assert st(ok, "Suporte") is Status.NORMAL and st(ok, "CPU") is Status.PROBLEMA


def test_system_linux_eol():
    old = system.analyze({"os_name": "Ubuntu 20.04", "os_id": "ubuntu", "os_version_id": "20.04",
                          "uptime_seconds": 10, "cpu": {"usage_percent": 1}}, "Linux")
    assert st(old, "Suporte") is Status.PROBLEMA
    mint = system.analyze({"os_name": "Linux Mint 22", "os_id": "linuxmint", "os_version_id": "22.1",
                           "uptime_seconds": 10, "cpu": {"usage_percent": 1}}, "Linux")
    assert st(mint, "Suporte") is Status.NORMAL


def _net(**kw):
    base = {"adapters": [{"name": "eth0", "is_up": True, "is_loopback": False, "is_virtual": False,
                          "type": "ethernet", "ipv4": [{"address": "192.168.0.5"}]}],
            "primary_ipv4": "192.168.0.5", "primary_interface": "eth0",
            "default_gateway": "192.168.0.1", "dns_servers": ["192.168.0.1"]}
    base.update(kw)
    return base


def test_network_rules():
    assert all(f.status is Status.NORMAL for f in network.analyze(_net(), "Linux"))
    f = network.analyze(_net(primary_ipv4="169.254.3.3", default_gateway=None, dns_servers=[]), "Windows")
    assert st(f, "IP") is Status.PROBLEMA and st(f, "Gateway") is Status.PROBLEMA and st(f, "DNS") is Status.PROBLEMA
    down = network.analyze(_net(adapters=[{"name": "eth0", "is_up": False, "is_loopback": False,
                                           "is_virtual": False, "type": "ethernet", "ipv4": []}]), "Linux")
    assert len(down) == 1 and down[0].status is Status.PROBLEMA and down[0].recommendations


def _ping(key, recv, avg=10.0, sent=4, **kw):
    return {"key": key, "label": key, "host": "x", "available": True, "method": "icmp", "sent": sent,
            "received": recv, "loss_percent": (sent - recv) / sent * 100, "min_ms": avg, "avg_ms": avg,
            "max_ms": avg, **kw}


def test_connectivity_icmp_blocked_but_internet_ok_is_only_alert():
    data = {"pings": [_ping("gateway", 0, None), _ping("internet1", 4)],
            "dns_resolution": [{"hostname": "a", "ok": True, "addresses": ["1.1.1.1"], "time_ms": 20}],
            "dns_servers_test": [], "https_tests": [{"host": "a", "port": 443, "ok": True, "time_ms": 30}]}
    f = connectivity.analyze(data, "Linux")
    assert st(f, "Internet") is Status.NORMAL and st(f, "gateway") is Status.ALERTA


def test_connectivity_total_outage_and_latency():
    out = connectivity.analyze({"pings": [_ping("gateway", 4), _ping("internet1", 0, None)],
                                "dns_resolution": [{"hostname": "a", "ok": False, "addresses": [], "time_ms": 5, "error": "x"}],
                                "dns_servers_test": [{"server": "1.1.1.1", "ok": False, "time_ms": None, "error": "t"}],
                                "https_tests": [{"host": "a", "port": 443, "ok": False, "time_ms": None, "error": "e"}]}, "Windows")
    assert st(out, "Acesso à Internet") is Status.PROBLEMA
    assert "roteador/modem" in out[0].recommendations[0]
    slow = connectivity.analyze({"pings": [_ping("internet1", 3, 350.0)], "dns_resolution": [],
                                 "dns_servers_test": [], "https_tests": [{"host": "a", "port": 443, "ok": True, "time_ms": 5}]}, "Linux")
    assert st(slow, "Ping") is Status.PROBLEMA
    na = connectivity.analyze({"pings": [{"key": "gateway", "label": "g", "available": False, "error": "e"}],
                               "dns_resolution": [], "dns_servers_test": [], "https_tests": []}, "Linux")
    assert st(na, "Ping") is Status.INDISPONIVEL


def test_security_windows_scenarios():
    data = {"firewall": {"tool": "WDF", "service_status": "running",
                         "profiles": {"Domínio": True, "Privada": False, "Pública": False}},
            "antivirus": {"products": [{"name": "Windows Defender", "enabled": True, "signatures_up_to_date": True}],
                          "defender": {"signature_age_days": 10, "signature_updated": "2026-11-04 10:00"}},
            "updates": {"last_hotfix_age_days": 100, "last_hotfix_id": "KB1", "last_hotfix_date": "2026-08-06",
                        "reboot_required": True}, "update_error": None}
    f = security.analyze(data, "Windows")
    assert st(f, "Privada") is Status.ALERTA and st(f, "Pública") is Status.PROBLEMA
    assert st(f, "Definições") is Status.ALERTA and st(f, "Atualizações do Windows") is Status.PROBLEMA
    assert st(f, "Reinício") is Status.ALERTA
    no_av = security.analyze({"firewall": None, "antivirus": {"products": []}, "updates": None,
                              "update_error": "falhou"}, "Windows")
    assert st(no_av, "Antivírus") is Status.PROBLEMA and st(no_av, "Firewall") is Status.INDISPONIVEL
    assert st(no_av, "Atualizações") is Status.INDISPONIVEL


def test_security_linux():
    f = security.analyze({"firewall": {"tool": "ufw", "active": False},
                          "updates": {"upgradable": 30, "security_upgradable": 25, "package_lists_age_days": 20,
                                      "reboot_required": False}, "update_error": None}, "Linux")
    assert st(f, "Firewall") is Status.ALERTA and st(f, "Atualizações de segurança") is Status.PROBLEMA
    assert st(f, "Lista de pacotes") is Status.ALERTA
