"""Testes dos interpretadores de saída de comandos (independentes do SO)."""
from diagtool.collectors import connectivity as c
from diagtool.collectors import network as n
from diagtool.collectors import security as s
from diagtool.collectors.system import parse_os_release
from diagtool.utils import (fmt_num, format_bytes, format_duration, is_ipv4,
                            parse_xdg_desktop_dir, sanitize_filename)


def test_ping_windows_en():
    t = ("Reply from 8.8.8.8: bytes=32 time=12ms TTL=118\nReply from 8.8.8.8: bytes=32 time<1ms TTL=118\n"
         "Request timed out.\nReply from 8.8.8.8: bytes=32 time=14ms TTL=118\n")
    r = c.parse_ping_output(t, 4)
    assert r["received"] == 3 and r["loss_percent"] == 25.0 and r["max_ms"] == 14.0 and r["min_ms"] == 0.5


def test_ping_windows_pt_and_unreachable():
    t = "Resposta de 8.8.8.8: bytes=32 tempo=20ms TTL=118\nResposta de 192.168.0.9: Host de destino inacessível.\n"
    r = c.parse_ping_output(t, 4)
    assert r["received"] == 1 and r["avg_ms"] == 20.0


def test_ping_linux_and_total_loss():
    t = "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=12.3 ms\n64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=13.1 ms\n"
    assert c.parse_ping_output(t, 2)["avg_ms"] == 12.7
    r = c.parse_ping_output("100% packet loss", 4)
    assert r["received"] == 0 and r["loss_percent"] == 100.0 and r["avg_ms"] is None


def test_dns_packet_roundtrip():
    q = c.build_dns_query("www.google.com", 4660)
    assert q[:2] == b"\x12\x34" and q.endswith(b"\x00\x01\x00\x01")
    ok = c.parse_dns_response(b"\x12\x34\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00", 4660)
    assert ok == {"id_match": True, "rcode": 0, "answers": 2}


def test_proc_net_route():
    txt = ("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
           "eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
           "eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")
    r = n.parse_proc_net_route(txt)
    assert r == [{"gateway": "192.168.0.1", "interface": "eth0", "interface_ip": None, "metric": 100}]


def test_windows_route_print_ignores_onlink_and_persistent():
    txt = ("Active Routes:\n  0.0.0.0  0.0.0.0  192.168.0.1  192.168.0.15  25\n"
           "  0.0.0.0  0.0.0.0  On-link  10.8.0.2  5\nPersistent Routes:\n  0.0.0.0  0.0.0.0  192.168.0.1  Default\n")
    r = n.parse_windows_route_print(txt)
    assert len(r) == 1 and r[0]["gateway"] == "192.168.0.1" and r[0]["interface_ip"] == "192.168.0.15"


def test_ipconfig_dns_pt():
    txt = ("   Sufixo DNS específico de conexão. . . : lan\n   Servidores DNS. . . . . . . . . . . . : 192.168.0.1\n"
           "                                       8.8.8.8\n   NetBIOS em TCP/IP . . . : Habilitado\n")
    assert n.parse_ipconfig_dns(txt) == ["192.168.0.1", "8.8.8.8"]


def test_resolv_and_resolvectl():
    servers, search = n.parse_resolv_conf("nameserver 127.0.0.53\nsearch lan example.com\n")
    assert servers == ["127.0.0.53"] and search == ["lan", "example.com"]
    st = "Link 2 (eth0)\n    Current DNS Server: 192.168.0.1\n           DNS Servers: 192.168.0.1 8.8.8.8\n DNS Domain: lan\n"
    assert n.parse_resolvectl(st) == ["192.168.0.1", "8.8.8.8"]


def test_apt_and_av():
    txt = ("Listing...\nlibc6/noble-updates 2.39 amd64 [upgradable from: 2.38]\n"
           "openssl/noble-security,noble-updates 3.0 amd64 [upgradable from: 2.9]\n")
    assert s.parse_apt_upgradable(txt) == (2, 1)
    assert s.decode_av_state(0x061100) == {"enabled": True, "signatures_up_to_date": True}
    assert s.decode_av_state(0x061110)["signatures_up_to_date"] is False
    assert s.decode_av_state(0x060000)["enabled"] is False


def test_os_release_and_xdg():
    d = parse_os_release('NAME="Linux Mint"\nID=linuxmint\nVERSION_ID="22"\n# c\n')
    assert d["ID"] == "linuxmint" and d["VERSION_ID"] == "22"
    assert parse_xdg_desktop_dir('XDG_DESKTOP_DIR="$HOME/Área de Trabalho"', "/home/ana") == "/home/ana/Área de Trabalho"


def test_formatting():
    assert format_bytes(1024 ** 3 * 16) == "16,0 GB"
    assert fmt_num(1234.5) == "1.234,5"
    assert format_duration(90061) == "1 dia 1h 1min"
    assert is_ipv4("192.168.0.1") and not is_ipv4("300.1.1.1") and not is_ipv4("fe80::1")
    assert sanitize_filename("PC/João 01") == "PC_Jo_o_01"
